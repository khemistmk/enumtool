from __future__ import annotations

import os
import shutil
import socket
import tempfile
from pathlib import Path
from typing import Optional, Tuple

from stem.process import launch_tor_with_config  # type: ignore


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _locate_tor_exe() -> Optional[str]:
    # Priority: env var, PATH, common Windows Tor Browser locations
    env = os.environ.get("TOR_EXE")
    if env and Path(env).exists():
        return env
    # PATH
    path_exec = shutil.which("tor") or shutil.which("tor.exe")
    if path_exec:
        return path_exec
    # Common Tor paths (Windows, Linux, macOS)
    candidates = [
        # Windows Tor Expert Bundle and common installs
        r"C:\\Program Files\\tor\\tor.exe",
        r"C:\\Program Files\\Tor\\tor.exe",
        r"C:\\Program Files\\Tor Expert Bundle\\tor.exe",
        r"C:\\ProgramData\\chocolatey\\bin\\tor.exe",
        # Windows Tor Browser (fallback)
        r"C:\\Program Files\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe",
        r"C:\\Program Files (x86)\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe",
        r"C:\\Users\\%USERNAME%\\AppData\\Local\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe",
    r"C:\\Users\\%USERNAME%\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe",
        # Linux (daemon)
        "/usr/bin/tor",
        "/usr/local/bin/tor",
        "/usr/sbin/tor",
        "/snap/bin/tor",
        # macOS via Homebrew
        "/opt/homebrew/bin/tor",
        "/usr/local/bin/tor",
    ]
    for c in candidates:
        p = os.path.expandvars(c)
        if Path(p).exists():
            return p
    return None


class TorManager:
    def __init__(self) -> None:
        self.process = None
        self.socks_port: Optional[int] = None
        self.control_port: Optional[int] = None
        self.data_dir: Optional[Path] = None
        self.tor_exe: Optional[str] = None

    def start(self, progress: Optional[callable] = None, timeout: int = 60) -> Tuple[str, int]:
        exe = _locate_tor_exe()
        if not exe:
            raise RuntimeError("Tor executable not found. Set TOR_EXE or install Tor Browser.")
        self.tor_exe = exe
        self.socks_port = _find_free_port()
        self.control_port = _find_free_port()
        self.data_dir = Path(tempfile.mkdtemp(prefix="enumtool-tor-"))
        if progress:
            progress(f"Starting Tor (SOCKS {self.socks_port})…")
        # Launch Tor and wait for bootstrap
        config = {
            "SocksPort": str(self.socks_port),
            "ControlPort": str(self.control_port),
            "DataDirectory": str(self.data_dir),
            # Keep minimal
            "DNSPort": "0",
        }
        if os.name == "nt":
            # Stem cannot use timeout on Windows
            self.process = launch_tor_with_config(tor_cmd=exe, config=config)
        else:
            self.process = launch_tor_with_config(tor_cmd=exe, config=config, timeout=timeout)
        return ("127.0.0.1", self.socks_port)

    def stop(self) -> None:
        try:
            if self.process:
                self.process.terminate()
        except Exception:
            pass
        # Do not delete data dir to allow reuse between runs; it's temporary anyway