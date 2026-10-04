"""Launch a sandbox entry point with the reviewed uv interpreter, without fallback."""

import argparse
import subprocess
from pathlib import Path

from txn_sandbox_runtime import PYTHON_VERSION


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("record", "recover"))
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    entry = "txn_sandbox_cli.py" if args.command == "record" else "txn_sandbox_recovery.py"
    result = subprocess.run(
        ["uv", "run", "--python", PYTHON_VERSION, "python", str(Path(__file__).resolve().parent / entry), *args.arguments],
        check=False,
    )
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
