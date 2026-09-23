"""Verification-branch carrier only: do not merge this directory.

Apply the exact proposed patch in a disposable local Git clone and exercise the
repository's real compiler/Gate/Ledger tests. No production credentials, remote
Git clone, workflow changes or mutation of the original checkout are involved.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PATCH_SHA256 = "3272fcce7f50c22535a916b799fc32016cfea9e1d0c783c98f5d2f7626138f97"
EXPECTED_FILES = {
    "limits_03_preflight.py": "7f37d2bef1204f02287be4b0fb4a747ef464b587db24c95555009b72e6a6cacc",
    "shadow_03.py": "09e7a1dc26567e591cbb8de6ee8ab15a75a267c43dc56825b76b7fb61d4f990c",
    "shadow_03a.py": "fad133caf73535688ce428e0abebe15c4c745045fb03a8236bf7d36a7b3d3d47",
    "test_limits_03_failed_apply_recovery.py": "990b62536f12b8f5fb1b429426174f1c866bd0775ce66845e1b7cb377a7646da",
}
COMPILER_TEST = '''from pathlib import Path
import sys
import pytest
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import compiler_03
import shadow_03

@pytest.mark.parametrize("part", ["A", "B", "ALL"])
def test_actual_compiler_wall_is_preserved(part):
    plan = compiler_03.compile_limits_plan("demo-firestore-probe", "(default)", "0" * 32, part)
    gate = plan["localGatePlan"]
    assert 0 < gate["recoverySeconds"] < gate["wallSeconds"] <= compiler_03.GATE_WALL_SECONDS_MAX
    assert shadow_03.shadow_execution_timeout(part) == gate["wallSeconds"] + 30
    if part == "ALL":
        assert shadow_03.shadow_execution_timeout(part) > 900
    for row in plan["requests"]:
        assert compiler_03.slot_seconds(row) in (3.0, 5.0, 12.0)
'''


def test_closure050_candidate_with_complete_repository(tmp_path, capsys):
    patch = HERE / "candidate.patch"
    assert hashlib.sha256(patch.read_bytes()).hexdigest() == PATCH_SHA256
    checkout = tmp_path / "candidate-checkout"
    cloned = subprocess.run(
        ["git", "clone", "--quiet", "--shared", "--no-hardlinks", str(ROOT), str(checkout)],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert cloned.returncode == 0, cloned.stderr
    source_commit = subprocess.check_output(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True
    ).strip()
    for arguments in (["apply", "--check", str(patch)], ["apply", str(patch)]):
        applied = subprocess.run(
            ["git", "-C", str(checkout), *arguments],
            capture_output=True, text=True, timeout=30, check=False,
        )
        assert applied.returncode == 0, applied.stderr
    lane = checkout / "tools/compat-broad/fs-write-limits"
    actual = {name: hashlib.sha256((lane / name).read_bytes()).hexdigest()
              for name in EXPECTED_FILES}
    assert actual == EXPECTED_FILES
    generated = lane / "test_closure050_actual_compiler.py"
    generated.write_text(COMPILER_TEST, encoding="utf-8")
    junit = tmp_path / "closure050-junit.xml"
    targets = [
        "test_limits_03_failed_apply_recovery.py",
        "test_limits_03_recording_gate.py",
        "test_limits_03_index_hosting.py",
        "test_limits_03_o8.py",
        generated.name,
    ]
    environment = dict(os.environ)
    for key in ("PYTHONPATH", "PYTEST_ADDOPTS", "PYTEST_CURRENT_TEST"):
        environment.pop(key, None)
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "--tb=short", "-p", "no:cacheprovider",
         "--junitxml", str(junit), *[str(lane / name) for name in targets]],
        cwd=checkout, env=environment, capture_output=True, text=True,
        timeout=1200, check=False,
    )
    suites = list(ET.parse(junit).getroot().iter("testsuite")) if junit.exists() else []
    totals = {key: sum(int(suite.get(key, "0")) for suite in suites)
              for key in ("tests", "failures", "errors", "skipped")}
    report = {
        "kind": "closure050-ci-candidate-v1", "sourceCommit": source_commit,
        "patchSha256": PATCH_SHA256, "candidateFiles": actual,
        "python": sys.version, "returncode": completed.returncode,
        "junit": totals, "fullRepositoryDependencies": True,
        "nativeFirestoreExecuted": False, "productionExecuted": False,
        "independentReview": False,
    }
    with capsys.disabled():
        print("\nCLOSURE050_CI_RESULT " + json.dumps(report, sort_keys=True), flush=True)
        print(completed.stdout[-100000:], flush=True)
        print(completed.stderr[-12000:], flush=True)
    assert completed.returncode == 0, completed.stdout[-100000:] + completed.stderr[-12000:]
    assert totals["tests"] > 12 and totals["failures"] == totals["errors"] == 0
