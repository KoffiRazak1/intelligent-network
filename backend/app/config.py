"""Chargement et validation des paramètres de l'application."""

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv


# config.py se trouve dans backend/app ; deux niveaux au-dessus se trouve le projet.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")


@dataclass(frozen=True)
class Settings:
    """Paramètres utilisés par le backend."""

    app_name: str
    app_env: str
    app_host: str
    app_port: int
    log_level: str
    capture_enabled: bool
    app_username: str
    app_password: str


@lru_cache
def get_settings() -> Settings:
    """Charge les paramètres une seule fois et vérifie leur format."""
    try:
        app_port = int(os.getenv("APP_PORT", "8000"))
    except ValueError as error:
        raise ValueError("APP_PORT doit être un nombre entier.") from error

    if not 1 <= app_port <= 65535:
        raise ValueError("APP_PORT doit être compris entre 1 et 65535.")

    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    allowed_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}

    if log_level not in allowed_levels:
        raise ValueError(
            "LOG_LEVEL doit être DEBUG, INFO, WARNING, ERROR ou CRITICAL."
        )

    capture_value = os.getenv("CAPTURE_ENABLED", "true").strip().lower()
    if capture_value not in {"true", "false", "1", "0", "yes", "no"}:
        raise ValueError("CAPTURE_ENABLED doit être true ou false.")
    capture_enabled = capture_value in {"true", "1", "yes"}

    app_env = os.getenv("APP_ENV", "development").strip().lower()
    app_username = os.getenv("APP_USERNAME", "")
    app_password = os.getenv("APP_PASSWORD", "")
    if app_env == "production" and (not app_username or not app_password):
        raise ValueError(
            "APP_USERNAME et APP_PASSWORD sont obligatoires en production."
        )

    return Settings(
        app_name=os.getenv(
            "APP_NAME",
            "Intelligent Network Packet Analyzer",
        ),
        app_env=app_env,
        app_host=os.getenv("APP_HOST", "127.0.0.1"),
        app_port=app_port,
        log_level=log_level,
        capture_enabled=capture_enabled,
        app_username=app_username,
        app_password=app_password,
    )
