"""Entry point of the fireemu Python runner: `python runner.py --source <dir> --codebase <name>`.

It is started by the fireemu daemon with the interpreter of the codebase's `venv` and speaks the
frame protocol on stdin and stdout (see `fireemu_runner/framing.py`).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fireemu_runner.main import run  # noqa: E402

if __name__ == "__main__":
    code = run(sys.argv[1:])
    sys.stdout.flush()
    sys.stderr.flush()
    # Handlers may have left non-daemon threads behind; the daemon already decided to stop us.
    os._exit(code)
