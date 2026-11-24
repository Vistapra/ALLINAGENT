"""ALLINAGENT Cross-Platform Control Center Package.

Provides `control_center` as the canonical package and ensures backward-compatible
`integration.*` imports resolve to the exact same module instances via `sys.path`
and `sys.modules`.
"""
from __future__ import annotations

import sys
from pathlib import Path

__version__ = "1.0.0"

_PACKAGE_CONTAINER = str(Path(__file__).resolve().parents[1])
if _PACKAGE_CONTAINER not in sys.path:
    sys.path.insert(0, _PACKAGE_CONTAINER)
