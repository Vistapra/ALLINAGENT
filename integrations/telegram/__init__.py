"""ALLINAGENT Telegram Control Center Onboarding & Command Specification Package."""

from __future__ import annotations

from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
COMMAND_CATALOG_PATH = PACKAGE_DIR / "command_catalog.json"
BUNDLED_PLUGIN_DIR = PACKAGE_DIR / "unified-company-control"

__all__ = [
    "PACKAGE_DIR",
    "COMMAND_CATALOG_PATH",
    "BUNDLED_PLUGIN_DIR",
]
