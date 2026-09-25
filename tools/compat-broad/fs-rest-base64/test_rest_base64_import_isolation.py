"""Import-only regressions for the saved comparator; no production evidence is made.

Fresh Python/pytest processes exercise the actual Base64 test and the actual
limits comparator. Collection is tested separately from evidence-dependent test
execution: no historical matrix, credentials, native daemon or service is used.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
BROAD = HERE.parent
TEST_NAME = "test_rest_base64_comparator.py"


def _run(arguments, cwd):
    environment = dict(os.environ)
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    environment["PYTEST_ADDOPTS"] = ""
    return subprocess.run(
        [sys.executable, "-I", "-B", *arguments],
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


@pytest.mark.parametrize("order", ["base64-first", "limits-first", "foreign-cache"])
def test_base64_test_does_not_claim_or_replace_generic_comparator(order, tmp_path):
    result = _run(
        ["-c", r'''
import importlib.util
import sys
import types
from pathlib import Path

base64_path, limits_path, order = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
assert "comparator" not in sys.modules
sys.path.insert(0, str(limits_path))
if order == "limits-first":
    import comparator
elif order == "foreign-cache":
    sys.modules["comparator"] = types.ModuleType("unrelated-comparator-sentinel")
previous = sys.modules.get("comparator")
search_path = list(sys.path)
spec = importlib.util.spec_from_file_location("_base64_test_under_test", base64_path)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert sys.path == search_path, "Base64 test changed the process import search path"
assert sys.modules.get("comparator") is previous, "generic comparator cache changed"
assert module.CASE_ID == "firestore:errors/rest-shapes#write-bad-base64"
assert Path(module.compare_evidence.__code__.co_filename).resolve() == base64_path.with_name("comparator.py").resolve()
assert module.compare_evidence(None, None, None, expected_source_commit="a" * 40)["status"] == "indeterminate"
if order != "foreign-cache":
    # These are the symbols needed by the limits production/recompare imports
    # that failed after Base64 polluted sys.modules in the full CI invocation.
    from comparator import _validated, compare_rows
    assert Path(compare_rows.__code__.co_filename).resolve() == (limits_path / "comparator.py").resolve()
    assert callable(_validated)
''', str(HERE / TEST_NAME), str(BROAD / "fs-write-limits"), order],
        tmp_path,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("reverse", [False, True], ids=["base64-first", "limits-first"])
def test_actual_comparator_test_files_collect_together(reverse, tmp_path):
    # A small source tree isolates import collection from unrelated conftests.
    # Every source here is copied verbatim, not replaced with a dummy module.
    copied = tmp_path / "tools" / "compat-broad"
    source_files = {
        "fs-rest-base64": ["comparator.py", TEST_NAME],
        "fs-write-limits": ["compiler.py", "comparator.py", "test_comparator.py"],
    }
    for lane, names in source_files.items():
        directory = copied / lane
        directory.mkdir(parents=True)
        for name in names:
            shutil.copyfile(BROAD / lane / name, directory / name)
    config = tmp_path / "pytest.ini"
    config.write_text("[pytest]\n", encoding="utf-8")
    tests = [
        copied / "fs-rest-base64" / TEST_NAME,
        copied / "fs-write-limits" / "test_comparator.py",
    ]
    if reverse:
        tests.reverse()
    result = _run(
        ["-m", "pytest", "-c", str(config), "-p", "no:cacheprovider",
         "--import-mode=prepend", "--collect-only", "-q", *map(str, tests)],
        tmp_path,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "::test_exact_saved_error_matches_only_with_bound_current_receipt" in result.stdout
    assert "::test_complete_errors_are_observations_not_collection_failure" in result.stdout
    assert "import file mismatch" not in result.stdout + result.stderr


def test_old_test_basename_is_not_left_for_pytest_to_collect():
    assert (HERE / TEST_NAME).is_file()
    assert not (HERE / "test_comparator.py").exists()


def test_unchanged_comparator_cli_help_still_works(tmp_path):
    result = _run([str(HERE / "comparator.py"), "--help"], tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    for flag in ("--manifest", "--cases", "--expected-source-commit", "--matrix"):
        assert flag in result.stdout


def test_cli_missing_evidence_remains_indeterminate(tmp_path):
    import json

    missing = str(tmp_path / "does-not-exist.json")
    result = _run(
        [str(HERE / "comparator.py"), "--manifest", missing, "--cases", missing,
         "--matrix", missing, "--expected-source-commit", "a" * 40],
        tmp_path,
    )
    assert result.returncode == 2, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["status"] == "indeterminate"
    assert report["reason"] == "evidence-file-missing-or-malformed"
    assert report["productionExecuted"] is False
