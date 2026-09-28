"""Validate a historical session-v2 receipt without rebinding its source."""

import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/compat-inventory"))
from evidence_common import runtime_inputs_at_commit

_PUBLISHER_PATH = ROOT / "tools/publish-auth-session-v2.py"
_APPROVAL_PATH = ROOT / "tools/auth-session-v2-approval.py"
_APPROVAL_SOURCE_ANCHOR = "00ec446c34fba61090550de144f2281ac62a6d13"
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


@lru_cache(maxsize=8)
def _git_bytes(commit, name):
    _require(isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}", commit))
    try:
        return subprocess.check_output(
            ["git", "show", f"{commit}:{name}"],
            cwd=ROOT,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError as error:
        raise ValueError("Historical source file is unavailable") from error


@lru_cache(maxsize=4)
def _publication_contract_at_commit(commit):
    return hashlib.sha256(
        _git_bytes(commit, "tools/publish-auth-session-v2.py")
    ).hexdigest()


@lru_cache(maxsize=4)
def _source_review_digest_at_commit(commit):
    review = json.loads(
        _git_bytes(commit, "spec/compatibility/evidence/auth-session-v2/source-review.json")
    )
    _require(isinstance(review, dict))
    return digest(review)


@lru_cache(maxsize=1)
def _approval_source_digest():
    return hashlib.sha256(
        _git_bytes(_APPROVAL_SOURCE_ANCHOR, "tools/auth-session-v2-approval.py")
    ).hexdigest()


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
    runtime_commit = local.get("runtimeSourceCommit")
    _require(
        isinstance(runtime_commit, str)
        and re.fullmatch(r"[0-9a-f]{40}", runtime_commit)
    )
    _require(
        local.get("build", {}).get("inputs") == _runtime_inputs_at_commit(runtime_commit)
    )
    _require(
        value.get("publicationContractSha256")
        == _publication_contract_at_commit(commit)
    )
    _require(
        value.get("sourceReviewSha256") == _source_review_digest_at_commit(commit)
    )

    original_inputs = _publisher.inputs
    original_runtime_inputs = _publisher.runtime_inputs
    original_review = _publisher.REVIEW
    original_contract = _publisher.publication_contract_sha
    _publisher.inputs = lambda: value["probeInputs"]
    _publisher.runtime_inputs = lambda root: _runtime_inputs_at_commit(runtime_commit)
    _publisher.publication_contract_sha = lambda: _publication_contract_at_commit(commit)
    try:
        with tempfile.TemporaryDirectory(
            prefix="fireemu-auth-session-review-"
        ) as directory:
            historical_review = Path(directory) / "source-review.json"
            historical_review.write_bytes(
                _git_bytes(
                    commit,
                    "spec/compatibility/evidence/auth-session-v2/source-review.json",
                )
            )
            _publisher.REVIEW = historical_review
            _ORIGINAL_VALIDATE(value)
    finally:
        _publisher.inputs = original_inputs
        _publisher.runtime_inputs = original_runtime_inputs
        _publisher.REVIEW = original_review
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


def render_approval_frozen(approval, value):
    """Render the frozen approval using the source-bound receipt validator."""
    _require(
        hashlib.sha256(_APPROVAL_PATH.read_bytes()).hexdigest()
        == _approval_source_digest()
    )
    approval_spec = importlib.util.spec_from_file_location(
        "session_v2_historical_approval", _APPROVAL_PATH
    )
    _require(approval_spec is not None and approval_spec.loader is not None)
    approval_module = importlib.util.module_from_spec(approval_spec)
    approval_spec.loader.exec_module(approval_module)
    publisher = SimpleNamespace(
        BUNDLE=BUNDLE,
        CASES=CASES,
        comparison=comparison,
        digest=digest,
        round_controls=round_controls,
        validate=validate_frozen,
    )
    original_publisher = approval_module.publisher
    approval_module.publisher = publisher
    try:
        return approval_module.render(approval, value)
    finally:
        approval_module.publisher = original_publisher
