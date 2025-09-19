from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    from dotenv import load_dotenv  # type: ignore
except Exception:  # pragma: no cover
    load_dotenv = None  # type: ignore


def load_env(dotenv_path: Optional[Path] = None) -> None:
    """Load environment variables from .env in project root if available."""
    if load_dotenv is None:
        return
    if dotenv_path is None:
        dotenv_path = Path(__file__).resolve().parents[2] / ".env"
    try:
        load_dotenv(dotenv_path=dotenv_path, override=False)
    except Exception:
        pass


def get_api_key(name: str, default: Optional[str] = None) -> Optional[str]:
    return os.getenv(name, default)


@dataclass
class Settings:
    shodan_api_key: Optional[str] = None
    securitytrails_api_key: Optional[str] = None


def get_settings() -> Settings:
    load_env()
    return Settings(
    shodan_api_key=get_api_key("SHODAN_API_KEY"),
    securitytrails_api_key=get_api_key("SECURITYTRAILS_API_KEY"),
    )
