#!/usr/bin/env bash
set -euo pipefail

echo "[EnumTool] Setup starting..."

# Detect platform
OS=$(uname -s || echo unknown)

ensure_python() {
  if command -v python3 >/dev/null 2>&1; then
    python3 --version || true
  else
    echo "Python 3 not found. Attempting to install..."
    case "$OS" in
      Linux)
        if command -v apt >/dev/null 2>&1; then
          sudo apt update && sudo apt install -y python3 python3-venv python3-pip
        elif command -v dnf >/dev/null 2>&1; then
          sudo dnf install -y python3 python3-virtualenv python3-pip
        elif command -v yum >/dev/null 2>&1; then
          sudo yum install -y python3 python3-virtualenv python3-pip
        elif command -v pacman >/dev/null 2>&1; then
          sudo pacman -Sy --noconfirm python python-pip
        else
          echo "Install Python 3 manually for your distro." >&2
        fi
        ;;
      Darwin)
        if command -v brew >/dev/null 2>&1; then
          brew install python
        else
          echo "Install Homebrew from https://brew.sh, then: brew install python" >&2
        fi
        ;;
    esac
  fi
}

ensure_tor() {
  install_tor=false
  if command -v tor >/dev/null 2>&1; then
    echo "tor already installed"
  else
    install_tor=true
  fi

  if $install_tor; then
    case "$OS" in
      Linux)
        if command -v apt >/dev/null 2>&1; then
          sudo apt update && sudo apt install -y tor
        elif command -v dnf >/dev/null 2>&1; then
          sudo dnf install -y tor
        elif command -v yum >/dev/null 2>&1; then
          sudo yum install -y tor
        elif command -v pacman >/dev/null 2>&1; then
          sudo pacman -Sy --noconfirm tor
        else
          echo "Package manager not detected. Please install 'tor' via your distro." >&2
        fi
        ;;
      Darwin)
        if command -v brew >/dev/null 2>&1; then
          brew install tor
        else
          echo "Homebrew not found. Install from https://brew.sh or install Tor manually." >&2
        fi
        ;;
      *)
        echo "Unsupported OS for this script. Install Tor manually." >&2
        ;;
    esac
  fi
}

ensure_python
ensure_tor

if $install_tor; then
  case "$OS" in
    Linux)
      if command -v apt >/dev/null 2>&1; then
        sudo apt update && sudo apt install -y tor
      elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y tor
      elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y tor
      elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -Sy --noconfirm tor
      else
        echo "Package manager not detected. Please install 'tor' via your distro." >&2
      fi
      ;;
    Darwin)
      if command -v brew >/dev/null 2>&1; then
        brew install tor
      else
        echo "Homebrew not found. Install from https://brew.sh or install Tor manually." >&2
      fi
      ;;
    *)
      echo "Unsupported OS for this script. Install Tor manually." >&2
      ;;
  esac
fi

# Locate tor binary
find_tor() {
  if command -v tor >/dev/null 2>&1; then
    command -v tor
    return 0
  fi
  for p in /usr/bin/tor /usr/local/bin/tor /opt/homebrew/bin/tor; do
    [ -x "$p" ] && echo "$p" && return 0
  done
  return 1
}

TOR_EXE=$(find_tor || true)
if [ -n "${TOR_EXE:-}" ]; then
  echo "Found tor at $TOR_EXE"
  # Persist in shell profile
  PROFILE="$HOME/.bashrc"
  [ -f "$HOME/.zshrc" ] && PROFILE="$HOME/.zshrc"
  if ! grep -q "export TOR_EXE=" "$PROFILE" 2>/dev/null; then
    echo "export TOR_EXE=\"$TOR_EXE\"" >> "$PROFILE"
    echo "Added TOR_EXE to $PROFILE (open a new shell to load)"
  fi
else
  echo "tor not found after install; set TOR_EXE manually." >&2
fi

# Create venv and install deps
python3 -m venv .venv || true
. .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
pip install -e .

# Verify Python dependencies by importing key modules
python - <<'PYEOF'
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
PYEOF

echo "[EnumTool] Setup complete. To test anon: python -m enumtool example.com --anon"
