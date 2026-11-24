"""Backward-compatible alias (`integration.agent_skills_manager` -> `control_center.agent_skills_manager`)."""
import importlib
import sys
from pathlib import Path

_c = str(Path(__file__).resolve().parents[1])
if _c not in sys.path:
    sys.path.insert(0, _c)

_mod = importlib.import_module("control_center.agent_skills_manager")
if __name__ == "__main__":
    raise SystemExit(_mod.main())
sys.modules[__name__] = _mod
