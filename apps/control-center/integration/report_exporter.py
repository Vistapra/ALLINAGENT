"""Backward-compatible alias (`integration.report_exporter` -> `control_center.report_exporter`)."""
import importlib
import sys
from pathlib import Path

_c = str(Path(__file__).resolve().parents[1])
if _c not in sys.path:
    sys.path.insert(0, _c)

_mod = importlib.import_module("control_center.report_exporter")
if __name__ == "__main__":
    raise SystemExit(_mod.main())
sys.modules[__name__] = _mod
