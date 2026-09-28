"""Bash evidence-gate contract; fake nextest output is NOT native test evidence."""

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

SCRIPTS = Path(__file__).resolve().parent


@pytest.fixture
def gate_run(tmp_path):
    repo = tmp_path / "repo"
    scripts = repo / "scripts"
    scripts.mkdir(parents=True)
    source = Path(os.environ.get("FIREEMU_GATE_UNDER_TEST", SCRIPTS / "local-regression-gate"))
    shutil.copy2(source, scripts / "local-regression-gate")
    shutil.copy2(SCRIPTS / "cargo-session", scripts / "cargo-session")
    subprocess.run(["git", "init", "-q", "-b", "fixture"], cwd=repo, check=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.name=Gate fixture", "-c", "user.email=fixture@example.invalid",
                    "commit", "-qm", "local gate fixture"], cwd=repo, check=True)
    shim = tmp_path / "bin"
    shim.mkdir()
    cargo = shim / "cargo"
    cargo.write_text('''#!/usr/bin/env bash
if [[ "$*" == "nextest --version" ]]; then
  [[ ${FIXTURE_MISSING:-0} == 0 ]] || exit 101
  echo 'cargo-nextest test-shim (not real Rust evidence)'
  exit 0
fi
printf '%s\\n' "$*" >> "$FIXTURE_CALLED"
printf '%s\\n' "$FIXTURE_SUMMARY"
exit "$FIXTURE_EXIT"
''')
    cargo.chmod(0o755)
    rustc = shim / "rustc"
    rustc.write_text("#!/usr/bin/env bash\necho 'rustc test-shim (not a compiler)'\n")
    rustc.chmod(0o755)
    report = tmp_path / "reports" / "report.json"
    called = tmp_path / "called"

    def run(summary="Summary [ 0.01s] 2 tests run: 2 passed, 1 skipped", *, code=0,
            report_path=None, args=(), missing=False, tee_failure=False, publish_fault=None):
        env = dict(os.environ)
        for key in ("CARGO_TARGET_DIR", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"):
            env.pop(key, None)
        env.update(PATH=str(shim) + os.pathsep + env["PATH"],
                   FIXTURE_SUMMARY=summary, FIXTURE_EXIT=str(code),
                   FIXTURE_CALLED=str(called), FIXTURE_MISSING="1" if missing else "0")
        if tee_failure:
            tee = shim / "tee"
            tee.write_text(f'#!/usr/bin/env bash\n{shutil.which("tee")} "$@"\nexit 1\n')
            tee.chmod(0o755)
        if publish_fault:
            link = shim / "ln"
            real_ln = shutil.which("ln")
            if publish_fault == "failure":
                link.write_text("#!/usr/bin/env bash\nexit 1\n")
            elif publish_fault == "directory-race":
                link.write_text(f'#!/usr/bin/env bash\nmkdir -- "${{@: -1}}"\nexec {real_ln} "$@"\n')
            elif publish_fault == "symlink-race":
                link.write_text(f'#!/usr/bin/env bash\nmkdir -- "${{@: -1}}.dir"\n{real_ln} -s -- "${{@: -1}}.dir" "${{@: -1}}"\nexec {real_ln} "$@"\n')
            link.chmod(0o755)
        path = report_path or report
        result = subprocess.run(["bash", str(scripts / "local-regression-gate"),
                                 "--session", "fixture", "--report", str(path),
                                 "--profile", "default", "--", *args],
                                cwd=repo, env=env, text=True, capture_output=True, timeout=10)
        return result, path, called
    return run


@pytest.mark.parametrize("summary,counts", [
    ("Summary [ 0.01s] 2 tests run: 2 passed, 1 skipped", (2, 2, 0, 1)),
    ("Summary [ 0.01s] 1 test run: 1 passed (1 slow)", (1, 1, 0, 0)),
    ("Summary [ 0.01s] 12 tests run: 12 passed (2 slow, 1 flaky), 8 skipped", (12, 12, 0, 8)),
])
def test_normal_summary_and_metadata(gate_run, summary, counts):
    result, path, called = gate_run(summary)
    assert result.returncode == 0, result.stderr
    report = json.loads(path.read_text())
    assert report["status"] == "passed"
    assert report["counts"] == dict(zip(("run", "passed", "failed", "skipped"), counts))
    assert report["exitStatus"] == result.returncode
    assert len(report["commit"]) == 40
    assert report["dirty"] is False
    assert "nextest run --profile default" in called.read_text()


@pytest.mark.parametrize("summary", [
    "Summary [ 0.01s] 2 tests run: 1 passed",
    "Summary [ 0.01s] 2 tests run: 0 passed, 2 timed out",
    "Summary [ 0.01s] 2 tests run: 3 passed",
    "Summary [ 0.01s] 2 tests run: no usable counters",
    "Summary [ 0.01s] 2 tests run: 1 passed, 1 leaky",
    "Summary [ 0.01s] 2 tests run: 2 passed, 1 failed",
    "Summary [ 0.01s] 999999999999999999999999999999999 tests run: 1 passed",
])
def test_inconsistent_or_unrecognized_counts_cannot_pass(gate_run, summary):
    result, path, _ = gate_run(summary)
    assert result.returncode != 0
    report = json.loads(path.read_text())
    assert report["status"] != "passed"
    assert report["exitStatus"] == result.returncode


@pytest.mark.parametrize("summary,code", [
    ("Summary [ 0.01s] 1 test run: 0 passed, 1 failed", 0),
    ("Summary [ 0.01s] 1 test run: 0 passed, 1 failed", 101),
    ("Summary [ 0.01s] 1 test run: 1 passed", 101),
    ("Summary [ 0.01s] 0 tests run: 0 passed, 7 skipped", 0),
    ("unrecognized output", 0),
])
def test_failed_empty_or_incomplete_run_has_matching_report_exit(gate_run, summary, code):
    result, path, _ = gate_run(summary, code=code)
    assert result.returncode != 0
    report = json.loads(path.read_text())
    assert report["status"] != "passed"
    assert report["exitStatus"] == result.returncode


def test_missing_nextest_is_not_a_pass(gate_run):
    result, path, called = gate_run(missing=True)
    assert result.returncode == 127
    report = json.loads(path.read_text())
    assert report["status"] == "missing-dependency"
    assert report["counts"]["run"] == 0
    assert report["exitStatus"] == result.returncode
    assert not called.exists()


@pytest.mark.parametrize("control", [*(chr(value) for value in range(1, 32)), '\\"', "日本語"])
def test_all_json_control_characters_in_arguments_are_escaped(gate_run, control):
    value = f"before{control}after"
    result, path, _ = gate_run(args=("--filter", value))
    assert result.returncode == 0, result.stderr
    report = json.loads(path.read_text())
    assert report["arguments"] == ["--filter", value]


def test_existing_receipt_is_not_overwritten_or_used_as_current_success(gate_run, tmp_path):
    path = tmp_path / "old.json"
    path.write_text('{"old": "do not replace"}\n')
    original = path.read_bytes()
    result, _, called = gate_run(report_path=path)
    assert result.returncode != 0
    assert path.read_bytes() == original
    assert not called.exists()


def test_report_symlink_cannot_clobber_its_target(gate_run, tmp_path):
    target = tmp_path / "original.txt"
    target.write_text("original")
    path = tmp_path / "linked.json"
    path.symlink_to(target)
    result, _, called = gate_run(report_path=path)
    assert result.returncode != 0
    assert target.read_text() == "original"
    assert path.is_symlink()
    assert not called.exists()


def test_missing_parent_creation_failure_cannot_return_success(gate_run, tmp_path):
    parent = tmp_path / "not-a-directory"
    parent.write_text("unchanged")
    result, _, _ = gate_run(report_path=parent / "result.json")
    assert result.returncode != 0
    assert parent.read_text() == "unchanged"


def test_log_writer_failure_cannot_return_success(gate_run):
    result, path, _ = gate_run(tee_failure=True)
    assert result.returncode != 0
    report = json.loads(path.read_text())
    assert report["status"] != "passed"
    assert report["exitStatus"] == result.returncode


@pytest.mark.parametrize("fault", ["failure", "directory-race", "symlink-race"])
def test_publication_failure_or_destination_race_never_passes(gate_run, fault):
    result, _, called = gate_run(publish_fault=fault)
    assert called.exists()
    assert result.returncode == 73


def test_failed_count_is_recorded_when_it_is_the_first_summary_term(gate_run):
    result, path, _ = gate_run("Summary [ 0.01s] 2 tests run: 2 failed", code=101)
    assert result.returncode == 101
    report = json.loads(path.read_text())
    assert report["counts"] == {"run": 2, "passed": 0, "failed": 2, "skipped": 0}


def test_concurrent_publishers_never_overwrite_the_first_receipt(gate_run):
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: gate_run(), range(2)))
    assert sorted(result.returncode for result, _, _ in results) == [0, 73]
    report = json.loads(results[0][1].read_text())
    assert report["status"] == "passed"
    assert report["exitStatus"] == 0
