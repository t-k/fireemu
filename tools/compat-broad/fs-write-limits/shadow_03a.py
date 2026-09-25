"""Part A entrypoint for the FS-WRITE-LIMITS-03 artifact shadow.

The owned-artifact supervisor launches its child with a fixed argument list and
a sanitized environment, so the campaign part cannot travel as a flag or a
variable. It travels as the entrypoint instead. This module adds no behaviour of
its own and authorizes nothing.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from shadow_03 import main

if __name__ == "__main__":
    raise SystemExit(main([*sys.argv[1:], "--part", "A"]))
