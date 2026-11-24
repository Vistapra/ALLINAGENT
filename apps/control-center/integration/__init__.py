"""Backward-compatible root alias package (`integration` -> `control_center`)."""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

_CONTAINER = str(Path(__file__).resolve().parents[1])
if _CONTAINER not in sys.path:
    sys.path.insert(0, _CONTAINER)

_cc = importlib.import_module("control_center")
__version__ = _cc.__version__
