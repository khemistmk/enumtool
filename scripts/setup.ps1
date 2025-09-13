param(
    [switch]$Force
)

Write-Host "[EnumTool] Setup starting..." -ForegroundColor Cyan

# 1) Ensure winget exists
if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Warning "winget not found. Please install the Windows Package Manager (winget) first: https://aka.ms/getwinget"
}

# 2) Install Tor Browser (for tor.exe)
$torApp = winget list --id TorProject.TorBrowser -e 2>$null | Out-String
if ($Force -or -not $torApp.Contains("TorProject.TorBrowser")) {
    Write-Host "Installing Tor Browser via winget..." -ForegroundColor Yellow
    winget install --id TorProject.TorBrowser -e --accept-source-agreements --accept-package-agreements
}

# 3) Locate tor.exe
function Find-TorExe {
    $candidates = @(
        "$Env:ProgramFiles\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe",
        "$Env:ProgramFiles(x86)\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe",
        "$Env:LocalAppData\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe"
    )
    foreach ($p in $candidates) {
        if (Test-Path $p) { return $p }
    }
    $cmd = Get-Command tor.exe -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) { return $cmd.Source }
    return $null
}

$torExe = Find-TorExe
if (-not $torExe) {
    Write-Warning "tor.exe not found after install. Launch Tor Browser once so files are created, or set TOR_EXE manually."
} else {
    Write-Host "Found tor.exe at $torExe" -ForegroundColor Green
    # Persist TOR_EXE for current user
    [Environment]::SetEnvironmentVariable('TOR_EXE', $torExe, 'User')
}

# 4) Create venv and install requirements
if (-not (Test-Path ".\.venv")) {
    Write-Host "Creating virtual environment (.venv)..." -ForegroundColor Yellow
    python -m venv .venv
}

$venvActivate = Join-Path (Resolve-Path ".\").Path ".venv\\Scripts\\Activate.ps1"
. $venvActivate

Write-Host "Installing Python dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt

# 5) Editable install
Write-Host "Installing enumtool in editable mode..." -ForegroundColor Yellow
pip install -e .

Write-Host "[EnumTool] Setup complete. Open a new terminal so TOR_EXE env var is loaded. To test anon: python -m enumtool example.com --anon" -ForegroundColor Cyan
