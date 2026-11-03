"""Test setup: the runner package is importable, and the fixture codebase has a project id."""

import os
import sys
from pathlib import Path

RUNNER_DIR = Path(__file__).resolve().parent.parent


def _find_fixture() -> Path:
    # mutmut runs the tests from a copy of this directory (`mutants/`), one level deeper.
    for parent in RUNNER_DIR.parents:
        candidate = parent / "sdk-smoke-functions-python"
        if candidate.is_dir():
            return candidate
    raise RuntimeError("tools/sdk-smoke-functions-python not found above " + str(RUNNER_DIR))


FIXTURE = _find_fixture()

sys.path.insert(0, str(RUNNER_DIR))
os.environ.setdefault("GCLOUD_PROJECT", "demo-proj")
# The daemon exports this to every runner; the Storage default bucket is read from it.
os.environ.setdefault("FIREBASE_CONFIG", '{"storageBucket": "demo-proj.appspot.com"}')


import pytest  # noqa: E402


@pytest.fixture(scope="session")
def discovered():
    """The fixture codebase imported once by the SDK's own discovery (its `main.py` runs `initialize_app`)."""
    import firebase_admin

    # mutmut runs the suite several times in one process, so the app a previous session made may exist.
    if firebase_admin._DEFAULT_APP_NAME in firebase_admin._apps:
        firebase_admin.delete_app(firebase_admin.get_app())
    previous = os.getcwd()
    os.chdir(FIXTURE)
    try:
        from firebase_functions.private import serving

        yield serving.get_functions()
    finally:
        os.chdir(previous)
