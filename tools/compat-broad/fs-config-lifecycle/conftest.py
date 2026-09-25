"""Give this hyphenated fixture directory a collision-free import namespace."""

import sys
import types
from pathlib import Path

PACKAGE = "fs_config_lifecycle"
package = types.ModuleType(PACKAGE)
package.__path__ = [str(Path(__file__).parent)]
sys.modules.setdefault(PACKAGE, package)
