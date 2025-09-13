param(
    [switch]$Force,
    [switch]$TorOnly
)

Write-Host "[EnumTool] Setup starting..." -ForegroundColor Cyan

# 1) Ensure winget exists
if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Warning "winget not found. Please install the Windows Package Manager (winget) first: https://aka.ms/getwinget"
}

function Ensure-Python {
    # Check for python
    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCmd) {
        Write-Host 'Python not found. Attempting to install Python 3 via winget...' -ForegroundColor Yellow
        try {
            winget install -e --id Python.Python.3.11 --accept-source-agreements --accept-package-agreements
        } catch {
            try { winget install -e --id Python.Python.3 --accept-source-agreements --accept-package-agreements } catch { }
        }
        $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
        if (-not $pythonCmd) {
            Write-Warning 'Python still not found after install. Please install Python 3.x and re-run.'
            return $false
        }
    }
    try {
        python --version
    } catch { }
    # Ensure pip and upgrade it
    try { python -m ensurepip --upgrade } catch { }
    try { python -m pip install --upgrade pip setuptools wheel } catch { }
    return $true
}

function Test-PythonDeps {
    param()
    $code = @"
import sys
ok = True
mods = [
    ('dns', 'dnspython'),
    ('httpx', 'httpx'),
    ('jinja2', 'jinja2'),
    ('whois', 'python-whois'),
    ('bs4', 'beautifulsoup4'),
    ('requests', 'requests'),
    ('socks', 'PySocks'),
    ('stem', 'stem'),
]
for mod, pkg in mods:
    try:
        __import__(mod)
    except Exception as e:
        ok = False
        print(f"Missing or broken module {mod} (from {pkg}): {e}", file=sys.stderr)
print('DEPS_OK' if ok else 'DEPS_FAIL')
"@
    try {
        $tmp = [System.IO.Path]::GetTempFileName()
        $py = [System.IO.Path]::ChangeExtension($tmp, '.py')
        Set-Content -Path $py -Value $code -Encoding UTF8
        $out = & python $py 2>&1
        Remove-Item $py -Force -ErrorAction SilentlyContinue
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        if ($out -match 'DEPS_OK') { return $true }
        Write-Warning ($out | Out-String)
        return $false
    } catch {
        Write-Warning ("Failed to verify Python dependencies: " + $_.Exception.Message)
        return $false
    }
}

function Find-TorExe {
    param(
        [switch]$Deep
    )
    $candidates = @(
        (Join-Path $Env:ProgramFiles 'Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe'),
        (Join-Path ${Env:ProgramFiles(x86)} 'Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe'),
        (Join-Path $Env:LocalAppData 'Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe'),
    (Join-Path $Env:LocalAppData 'Programs\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe'),
    (Join-Path $Env:USERPROFILE 'Desktop\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe')
    )
    $candidates = $candidates | Where-Object { $_ -and ($_ -ne '') }
    foreach ($p in $candidates) { if (Test-Path $p) { return $p } }
    $cmd = Get-Command tor.exe -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) { return $cmd.Source }
    if ($Deep) {
        $roots = @()
        if ($Env:LocalAppData) { $roots += $Env:LocalAppData }
        if ($Env:ProgramFiles) { $roots += $Env:ProgramFiles }
        if (${Env:ProgramFiles(x86)}) { $roots += ${Env:ProgramFiles(x86)} }
        foreach ($r in $roots) {
            try {
                $hit = Get-ChildItem -Path $r -Recurse -Filter 'tor.exe' -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
                if ($hit) { return $hit }
            } catch { }
        }
    }
    return $null
}

function Find-TorExpertPaths {
    # Return common locations for tor.exe when installed as Expert Bundle (choco/scoop/manual)
    $paths = @(
        (Join-Path $Env:ProgramFiles 'tor\\tor.exe'),
        (Join-Path $Env:ProgramFiles 'Tor\\tor.exe'),
        (Join-Path $Env:ProgramFiles 'Tor Expert Bundle\\tor.exe'),
        (Join-Path $Env:LOCALAPPDATA 'Programs\\tor\\tor.exe'),
        (Join-Path $Env:ChocolateyInstall 'bin\\tor.exe'),
        'C:\\ProgramData\\chocolatey\\bin\\tor.exe'
    )
    return $paths | Where-Object { $_ -and (Test-Path $_) }
}

function Ensure-TorExpertInstalled {
    # If tor.exe already present (any where), skip installation
    if (Find-TorExe -Deep) { Write-Host 'Tor detected (tor.exe present); skipping install.' -ForegroundColor Green; return $true }
    if (Find-TorExpertPaths) { Write-Host 'Tor Expert Bundle detected; skipping install.' -ForegroundColor Green; return $true }

    # Prefer Chocolatey if available
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-Host 'Installing Tor via Chocolatey (tor daemon)...' -ForegroundColor Yellow
        choco install tor -y --no-progress
        if ($LASTEXITCODE -ne 0) { Write-Warning 'Chocolatey tor install failed.' }
    } elseif (Get-Command scoop -ErrorAction SilentlyContinue) {
        Write-Host 'Installing Tor via Scoop...' -ForegroundColor Yellow
        scoop install tor
        if ($LASTEXITCODE -ne 0) { Write-Warning 'Scoop tor install failed.' }
    } else {
        # Try winget expert bundle if available, otherwise prompt user
        $candidateIds = @('TorProject.Tor', 'TorProject.TorExpertBundle')
        $installed = $false
        foreach ($id in $candidateIds) {
            try {
                $info = winget show --id $id -e 2>$null | Out-String
                if ($info -and ($info.Length -gt 0)) {
                    Write-Host ("Installing Tor via winget ($id)...") -ForegroundColor Yellow
                    winget install --id $id -e --accept-source-agreements --accept-package-agreements
                    $installed = $true; break
                }
            } catch { }
        }
        if (-not $installed) {
            Write-Warning 'Could not locate Tor Expert Bundle in winget. If Chocolatey or Scoop are available, install tor using them; otherwise install tor manually from https://www.torproject.org/download/tor/.'
        }
    }
    return $true
}

# 2) Ensure Tor Expert Bundle is installed (skip if already present)
Ensure-TorExpertInstalled | Out-Null

# 3) Locate tor.exe and verify
$torExe = Find-TorExe
if (-not $torExe) { $torExe = Find-TorExe -Deep }
if (-not $torExe) {
    $paths = Find-TorExpertPaths
    if ($paths -and $paths.Count -gt 0) { $torExe = $paths[0] }
}

if ($torExe) {
    Write-Host ("Found tor.exe at " + $torExe) -ForegroundColor Green
    [Environment]::SetEnvironmentVariable('TOR_EXE', $torExe, 'User')
    $env:TOR_EXE = $torExe
    try {
        Write-Host 'Verifying tor binary...' -ForegroundColor Yellow
        & $torExe --version
    } catch {
        Write-Warning ("Failed to run tor --version: " + $_.Exception.Message)
    }
} else {
    Write-Warning 'tor.exe still not found. Install Tor Browser for current user, launch it once, or set TOR_EXE manually.'
}

# 4) Create venv and install requirements
if (-not $TorOnly) {
    if (-not (Ensure-Python)) { Write-Warning 'Skipping Python env setup due to missing Python.' }
}

if (-not $TorOnly -and -not (Test-Path ".\.venv")) {
    Write-Host "Creating virtual environment (.venv)..." -ForegroundColor Yellow
    python -m venv .venv
}

if (-not $TorOnly) {
    $venvActivate = Join-Path (Resolve-Path ".\").Path ".venv\\Scripts\\Activate.ps1"
    . $venvActivate

    Write-Host "Installing Python dependencies..." -ForegroundColor Yellow
    pip install -r requirements.txt

    # 5) Editable install
    Write-Host "Installing enumtool in editable mode..." -ForegroundColor Yellow
    pip install -e .
    # 6) Verify Python dependencies by importing key modules
    if (Test-PythonDeps) {
        Write-Host 'Python dependencies verified (DEPS_OK).' -ForegroundColor Green
    } else {
        Write-Warning 'Some Python dependencies may be missing or broken. See warnings above.'
    }
}

Write-Host "[EnumTool] Setup complete." -ForegroundColor Cyan
if ($env:TOR_EXE) {
    Write-Host ("TOR_EXE=" + $env:TOR_EXE) -ForegroundColor Green
    Write-Host "You can now run: python -m enumtool example.com --anon --active" -ForegroundColor Cyan
} else {
    Write-Host "TOR_EXE not set. If Tor Browser is installed for current user, try launching it once then re-run setup; or set TOR_EXE manually." -ForegroundColor Yellow
}
