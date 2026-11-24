"""Backward-compatible alias (`integration.paperclip_client` -> `control_center.paperclip_client`)."""
import importlib
import sys
from pathlib import Path

_c = str(Path(__file__).resolve().parents[1])
if _c not in sys.path:
    sys.path.insert(0, _c)

sys.modules[__name__] = importlib.import_module("control_center.paperclip_client")
