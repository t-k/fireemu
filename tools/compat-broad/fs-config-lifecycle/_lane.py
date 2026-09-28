"""Register this directory as the `fs_config_lifecycle` package for scripts run by path.

The lane's modules import each other relatively, so a launcher or a descriptor loaded
by file path must first give the directory its package name. `conftest.py` does the
same for the tests; both register the identical module object.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

PACKAGE = "fs_config_lifecycle"


def ensure_package() -> None:
    if PACKAGE not in sys.modules:
        package = types.ModuleType(PACKAGE)
        package.__path__ = [str(Path(__file__).resolve().parent)]
        sys.modules[PACKAGE] = package
