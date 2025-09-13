#!/usr/bin/env bash
set -euo pipefail

echo "[EnumTool] Setup starting..."

# Detect platform
OS=$(uname -s || echo unknown)

# Install Tor
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
pip install -r requirements.txt
pip install -e .

echo "[EnumTool] Setup complete. To test anon: python -m enumtool example.com --anon"
