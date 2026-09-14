"""Validate a historical session-v2 receipt without rebinding its source."""

import hashlib
import importlib.util
import re
import subprocess
import sys
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-inventory"))
from evidence_common import runtime_inputs_at_commit

_PUBLISHER_PATH = ROOT / "tools/publish-auth-session-v2.py"
_publisher_spec = importlib.util.spec_from_file_location(
    "session_v2_historical_publisher", _PUBLISHER_PATH
)
assert _publisher_spec and _publisher_spec.loader
_publisher = importlib.util.module_from_spec(_publisher_spec)
_publisher_spec.loader.exec_module(_publisher)
_ORIGINAL_VALIDATE = _publisher.validate

BUNDLE = _publisher.BUNDLE
PAGE = _publisher.PAGE
CASES = _publisher.CASES
SCOPE = _publisher.SCOPE
digest = _publisher.digest
comparison = _publisher.comparison
round_controls = _publisher.round_controls
inputs = _publisher.inputs


def _require(condition):
    if not condition:
        raise ValueError("Historical receipt binding is invalid")


@lru_cache(maxsize=4)
def _probe_inputs_at_commit(commit):
    _require(isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}", commit))
    try:
        names = subprocess.check_output(
            [
                "git",
                "ls-tree",
                "-r",
                "-z",
                "--name-only",
                commit,
                "--",
                "tools/auth-session-v2",
                "tools/compat-inventory",
            ],
            cwd=ROOT,
        ).decode().split("\0")
    except subprocess.CalledProcessError as error:
        raise ValueError("Recorded probe source commit is unavailable") from error
    directories = {
        Path("tools/auth-session-v2"),
        Path("tools/compat-inventory"),
    }
    names = sorted(
        name
        for name in names
        if name
        and Path(name).parent in directories
        and Path(name).suffix == ".py"
        and not Path(name).name.startswith("test_")
    )
    _require(bool(names))
    result = {}
    for name in names:
        try:
            content = subprocess.check_output(
                ["git", "show", f"{commit}:{name}"],
                cwd=ROOT,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError as error:
            raise ValueError("Recorded probe source closure is incomplete") from error
        result[name] = hashlib.sha256(content).hexdigest()
    return result


@lru_cache(maxsize=4)
def _runtime_inputs_at_commit(commit):
    return runtime_inputs_at_commit(commit, ROOT)


def _recorded_inputs(value):
    reports = (value.get("local"), value.get("production"))
    commits = {
        report.get("probeSourceCommit") if isinstance(report, dict) else None
        for report in reports
    }
    _require(len(commits) == 1)
    commit = commits.pop()
    return commit, _probe_inputs_at_commit(commit)


def validate_frozen(value):
    """Validate the immutable receipt against its recorded source snapshots."""
    commit, expected_probe_inputs = _recorded_inputs(value)
    _require(value.get("probeInputs") == expected_probe_inputs)
    local = value.get("local")
    _require(isinstance(local, dict))
    _require(local.get("build", {}).get("inputs") == _runtime_inputs_at_commit(commit))

    original_inputs = _publisher.inputs
    original_runtime_inputs = _publisher.runtime_inputs
    original_contract = _publisher.publication_contract_sha
    _publisher.inputs = lambda: value["probeInputs"]
    _publisher.runtime_inputs = lambda root: value["local"]["build"]["inputs"]
    _publisher.publication_contract_sha = lambda: value[
        "publicationContractSha256"
    ]
    try:
        _ORIGINAL_VALIDATE(value)
    finally:
        _publisher.inputs = original_inputs
        _publisher.runtime_inputs = original_runtime_inputs
        _publisher.publication_contract_sha = original_contract


def validate(value):
    """Validate a newly generated receipt against the current source tree."""
    _ORIGINAL_VALIDATE(value)


def render_frozen(value):
    """Render an immutable receipt without rebinding its source."""
    original = _publisher.validate
    _publisher.validate = validate_frozen
    try:
        return _publisher.render(value)
    finally:
        _publisher.validate = original


def render(value):
    """Render a current receipt with the original strict publisher."""
    return _publisher.render(value)
