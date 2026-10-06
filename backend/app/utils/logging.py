"""Configuration des journaux de l'application."""

import logging


def configure_logging(level: str = "INFO") -> None:
    """Configure les journaux dans la console."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        force=True,
    )


def get_logger(name: str) -> logging.Logger:
    """Retourne un journal associé au module appelant."""
    return logging.getLogger(name)