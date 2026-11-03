"""Test setup: the runner package is importable, and the fixture codebase has a project id."""

import os
import sys
from pathlib import Path

RUNNER_DIR = Path(__file__).resolve().parent.parent
FIXTURE = RUNNER_DIR.parent / "sdk-smoke-functions-python"

sys.path.insert(0, str(RUNNER_DIR))
os.environ.setdefault("GCLOUD_PROJECT", "demo-proj")
