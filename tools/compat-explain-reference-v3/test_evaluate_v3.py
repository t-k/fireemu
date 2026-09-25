"""Coverage obligations for immutable, dual-collector Explain reevaluation."""

import copy
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

HERE = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location("reference_v3", HERE / "evaluate.py")
assert SPEC is not None
e = importlib.util.module_from_spec(SPEC)


def evaluator():
    assert SPEC is not None and SPEC.loader is not None
    assert (HERE / "evaluate.py").exists(), "v3 evaluator is not implemented"
    SPEC.loader.exec_module(e)
    return e


def sample() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    return {
        "method": "POST",
        "path": "/documents/items:runQuery",
        "body": {"structuredQuery": {"limit": 0}, "explainOptions": {"analyze": True}},
    }, [
        {
            "readTime": "2026-09-14T11:00:00Z",
            "explainMetrics": {
                "planSummary": {},
                "executionStats": {
                    "executionDuration": "0.123s",
                    "readOperations": "1",
                    "debugStats": {"documents_scanned": "0"},
                },
            },
        }
    ]


def test_duration_is_typed_and_defaults_scoped_without_mutation():
    e = evaluator()
    op, body = sample()
    before = copy.deepcopy(body)
    normalized, applied = e.canonical_body(op, 200, body)
    stats = normalized[0]["explainMetrics"]["executionStats"]
    assert stats["executionDuration"] == {
        "type": "google.protobuf.Duration",
        "nondeterministic": True,
    }
    assert stats["resultsReturned"] == "0"
    assert stats["readOperations"] == "1"
    assert len(applied["duration"]) == 1 and len(applied["defaults"]) == 2
    assert body == before


@pytest.mark.parametrize(
    "duration",
    [
        None,
        0,
        True,
        "",
        "-1s",
        "-0s",
        "NaNs",
        "1",
        "1.1234567890s",
        "315576000001s",
        "1e3s",
        "+1s",
        "1.s",
        " 1s",
        "missing",
    ],
)
def test_missing_or_invalid_duration_fails_closed(duration):
    e = evaluator()
    op, body = sample()
    stats = body[0]["explainMetrics"]["executionStats"]
    if duration == "missing":
        stats.pop("executionDuration")
    else:
        stats["executionDuration"] = duration
    with pytest.raises(ValueError, match="duration"):
        e.canonical_body(op, 200, body)


@pytest.mark.parametrize("duration", ["0s", "0.000000001s", "1.1s", "315576000000s"])
def test_valid_duration_boundaries(duration):
    e = evaluator()
    op, body = sample()
    body[0]["explainMetrics"]["executionStats"]["executionDuration"] = duration
    e.canonical_body(op, 200, body)


@pytest.mark.parametrize(
    "change",
    [
        "counter",
        "debug",
        "body",
        "status",
        "operation",
        "principal",
        "state",
        "cleanup",
    ],
)
def test_comparison_does_not_hide_other_differences(change):
    e = evaluator()
    op, body = sample()
    row = {
        "id": "explain/query/empty-analyze",
        "request": op,
        "status": 200,
        "body": body,
    }
    receipt: dict[str, Any] = {
        "nonce": "a" * 32,
        "receipt": {
            "rows": [row],
            "cleanup": [],
            "principalEvidence": {
                "principal": "administrator",
                "quotaProject": "project",
            },
        },
    }
    other = copy.deepcopy(receipt)
    if change in ("counter", "debug"):
        stats = other["receipt"]["rows"][0]["body"][0]["explainMetrics"][
            "executionStats"
        ]
        stats["readOperations" if change == "counter" else "debugStats"] = (
            "2" if change == "counter" else {"documents_scanned": "1"}
        )
    elif change in ("body", "state"):
        other["receipt"]["rows"][0]["body"][0]["extra"] = True
    elif change == "status":
        other["receipt"]["rows"][0]["status"] = 201
    elif change == "operation":
        other["receipt"]["rows"][0]["request"]["body"]["extra"] = True
    elif change == "principal":
        other["receipt"]["principalEvidence"]["principal"] = "user"
    elif change == "cleanup":
        other["receipt"]["cleanup"].append(row)
    if change in ("operation", "principal", "cleanup"):
        with pytest.raises(ValueError):
            e.compare_records(receipt, other, lambda v, n: v)
    else:
        assert (
            e.compare_records(receipt, other, lambda v, n: v)[0]["compatibility"]
            == "mismatch"
        )


@pytest.mark.parametrize(
    "change",
    [
        "production/result.json",
        "production/comparison.json",
        "production/execution-inputs.json",
        "originalLocal/result.json",
        "repairedLocal/result.json",
        "repairedLocal/artifact.json",
        "repairedLocal/process.json",
        "repairedLocal/worker/ownership.jsonl",
        "repairedLocal/manifest.json",
    ],
)
def test_directory_hashes_reject_tampering(tmp_path, change):
    e = evaluator()
    roots = {
        name: tmp_path / name
        for name in ["production", "originalLocal", "repairedLocal"]
    }
    for root in roots.values():
        root.mkdir()
    path = tmp_path / change
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("original")
    pinned = {key: e.tree_hashes(root) for key, root in roots.items()}
    path.write_text("tampered")
    with pytest.raises(ValueError, match="frozen"):
        e.validate_hashes(roots, pinned)


@pytest.fixture(scope="module")
def saved():
    e = evaluator()
    base = Path("/Users/tk/work/firebase-emulator")
    logs = base / "docs.local/logs/2026-09-14"
    roots = {
        "production": logs / "campaign-explain-production-109a9b45",
        "originalLocal": logs / "campaign-explain-shadow-109a9b45",
        "repairedLocal": logs / "campaign-explain-shadow-aad1a41d",
    }
    old = base / ".worktree/campaign-explain-reference-109a9b45"
    repaired = base / ".worktree/campaign-explain-reference-aad1a41d"
    if not all(p.exists() for p in [*roots.values(), old, repaired]):
        pytest.skip("private saved collection and exact collector checkouts required")
    return e, roots, old, repaired


def test_real_saved_collection_and_repaired_artifacts_pass(saved):
    e, roots, old, repaired = saved
    historical = e.run_validator("historical", old, roots)
    current = e.run_validator("repaired", repaired, roots)
    assert historical["originalComparison"]["compatibility"] == "indeterminate"
    assert historical["originalV2Compatibility"] == "mismatch"
    assert len(historical["originalV2Rows"]) == 12
    assert current["collectionComplete"] is True
    rows = e.run_validator("compare", old, roots)["rows"]
    assert len(rows) == 12
    assert all(row["compatibility"] == "match" for row in rows)


@pytest.mark.parametrize(
    "change",
    [
        "source",
        "observer",
        "manifest",
        "artifact",
        "process",
        "principal",
        "operation",
        "state",
        "cleanup",
    ],
)
def test_repaired_validator_rejects_receipt_tampering(saved, tmp_path, change):
    e, roots, _old, repaired = saved
    record = json.loads((roots["repairedLocal"] / "result.json").read_bytes())
    if change == "source":
        record["executionCommit"] = "0" * 40
    elif change == "observer":
        record["observerSha256"] = "0" * 64
    elif change == "manifest":
        record["manifestDigest"] = "0" * 64
    elif change == "artifact":
        record["runtime"]["artifactSha256"] = "0" * 64
    elif change == "process":
        record["runtime"]["ownedProcess"]["stopped"] = False
    elif change == "principal":
        record["receipt"]["principalEvidence"]["principal"] = "user"
    elif change == "operation":
        record["receipt"]["rows"][4]["request"]["body"]["extra"] = True
    elif change == "state":
        record["stateVerified"] = False
    elif change == "cleanup":
        record["cleanupComplete"] = False
    (tmp_path / "result.json").write_text(json.dumps(record))
    with pytest.raises(ValueError):
        e.run_validator("repaired", repaired, {**roots, "repairedLocal": tmp_path})


@pytest.fixture
def committed_source(tmp_path):
    import subprocess

    e = evaluator()
    for name in e.SOURCE_FILES:
        source = e.ROOT / name
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes() if source.exists() else b"{}\n")

    def git(*args):
        return (
            subprocess.check_output(
                ["git", *args], cwd=tmp_path, stderr=subprocess.PIPE
            )
            .decode()
            .strip()
        )

    git("init", "-q")
    git("config", "user.email", "test@example.invalid")
    git("config", "user.name", "Offline Test")
    git("add", ".")
    git("-c", "commit.gpgsign=false", "commit", "-qm", "source")
    anchor = {
        "kind": "query-explain-reference-evaluator-anchor-v3",
        "evaluatorSourceCommit": git("rev-parse", "HEAD"),
        "sourceFiles": {
            name: e.sha((tmp_path / name).read_bytes()) for name in e.SOURCE_FILES
        },
        "contractDigest": e.digest(e.contract()),
    }
    (tmp_path / e.ANCHOR).write_text(json.dumps(anchor))
    git("add", e.ANCHOR)
    git("-c", "commit.gpgsign=false", "commit", "-qm", "anchor")
    return e, tmp_path, git


def identity_process(root):
    import subprocess
    import sys

    program = "import importlib.util,sys; s=importlib.util.spec_from_file_location('v3',sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); print(m.source_identity())"
    return subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            program,
            str(root / "tools/compat-explain-reference-v3/evaluate.py"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def test_committed_source_identity_is_accepted(committed_source):
    _, root, _ = committed_source
    result = identity_process(root)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "change",
    [
        "source",
        "v2-source",
        "input-anchor",
        "uncommitted-anchor",
        "source-commit",
        "contract",
        "source-hash",
    ],
)
def test_evaluator_source_and_anchor_tampering_is_rejected(committed_source, change):
    e, root, git = committed_source
    if change in ("source", "v2-source", "input-anchor"):
        path = (
            root
            / {
                "source": e.SOURCE_FILES[0],
                "v2-source": "tools/compat-explain-reference/evaluate.py",
                "input-anchor": e.INPUTS,
            }[change]
        )
        path.write_bytes(path.read_bytes() + b"\n")
    else:
        path = root / e.ANCHOR
        anchor = json.loads(path.read_bytes())
        if change == "source-commit":
            anchor["evaluatorSourceCommit"] = "0" * 40
        elif change == "contract":
            anchor["contractDigest"] = "0" * 64
        elif change == "source-hash":
            anchor["sourceFiles"][e.SOURCE_FILES[0]] = "0" * 64
        else:
            anchor["uncommitted"] = True
        path.write_text(json.dumps(anchor))
        if change != "uncommitted-anchor":
            git("add", e.ANCHOR)
            git("-c", "commit.gpgsign=false", "commit", "-qm", "tampered anchor")
    assert identity_process(root).returncode != 0


def test_dependency_lock_and_manifest_are_in_source_closure():
    e = evaluator()
    assert {
        "tools/compat-inventory/pyproject.toml",
        "tools/compat-inventory/uv.lock",
    } <= set(e.SOURCE_FILES)


def test_plan_only_duration_is_not_projected():
    e = evaluator()
    operation, body = sample()
    operation["body"]["explainOptions"]["analyze"] = False
    projected, applied = e.canonical_body(operation, 200, body)
    assert projected == body
    assert applied == {"defaults": [], "duration": []}


@pytest.mark.parametrize("change", ["no-metrics", "no-stats", "duplicate-metrics"])
def test_analyze_requires_exactly_one_duration_parent(change):
    e = evaluator()
    operation, body = sample()
    if change == "no-metrics":
        body[0].pop("explainMetrics")
    elif change == "no-stats":
        body[0]["explainMetrics"].pop("executionStats")
    else:
        body.append(copy.deepcopy(body[0]))
    with pytest.raises(ValueError, match="duration"):
        e.canonical_body(operation, 200, body)


@pytest.fixture(scope="module")
def isolated_collector(saved, tmp_path_factory):
    import subprocess

    e, _roots, _old, repaired = saved
    target = tmp_path_factory.mktemp("collector") / "checkout"
    subprocess.run(
        ["git", "clone", "--shared", "--quiet", str(repaired), str(target)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "checkout", "--quiet", "--detach", e.REPAIRED_COMMIT],
        cwd=target,
        check=True,
        capture_output=True,
    )
    return target


def forge_cache(source, marker):
    import marshal
    import struct

    code = compile(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\nraise RuntimeError('FORGED_BYTECODE_EXECUTED')\n",
        str(source),
        "exec",
    )
    stat = source.stat()
    raw = (
        importlib.util.MAGIC_NUMBER
        + struct.pack(
            "<III", 0, int(stat.st_mtime) & 0xFFFFFFFF, stat.st_size & 0xFFFFFFFF
        )
        + marshal.dumps(code)
    )
    cache = Path(importlib.util.cache_from_source(str(source)))
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_bytes(raw)
    return cache


def prove_forged_cache_is_loadable(source, marker):
    import subprocess
    import sys

    program = "import importlib.util,sys; s=importlib.util.spec_from_file_location('forged',sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)"
    result = subprocess.run(
        [sys.executable, "-I", "-c", program, str(source)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert "FORGED_BYTECODE_EXECUTED" in result.stderr
    assert marker.read_text() == "executed"
    marker.unlink()


def test_initial_v2_import_ignores_forged_valid_cache(committed_source):
    import subprocess
    import sys

    _e, root, _git = committed_source
    marker = root / "forged-marker"
    source = root / "tools/compat-explain-reference/evaluate.py"
    forge_cache(source, marker)
    prove_forged_cache_is_loadable(source, marker)
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(root / "tools/compat-explain-reference-v3/evaluate.py"),
            "--help",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists()


@pytest.mark.parametrize(
    "module",
    [
        "compat-broad/campaign_explain.py",
        "compat-broad/shared_cases.py",
        "compat-broad/batch_contract.py",
        "compat-broad/broad.py",
        "compat-inventory/owned_runner.py",
        "compat-inventory/evidence_common.py",
    ],
)
def test_worker_ignores_forged_cache_and_still_rejects_invalid_receipt(
    saved, isolated_collector, tmp_path, module
):
    e, roots, _old, _repaired = saved
    marker = tmp_path / "forged-marker"
    source = isolated_collector / "tools" / module
    cache = forge_cache(source, marker)
    try:
        prove_forged_cache_is_loadable(source, marker)
        accepted = e.run_validator("repaired", isolated_collector, roots)
        assert accepted["collectionComplete"] is True
        record = json.loads((roots["repairedLocal"] / "result.json").read_bytes())
        record["cleanupComplete"] = False
        (tmp_path / "result.json").write_text(json.dumps(record))
        with pytest.raises(ValueError, match="cleanupComplete incomplete"):
            e.run_validator(
                "repaired", isolated_collector, {**roots, "repairedLocal": tmp_path}
            )
        assert not marker.exists()
    finally:
        cache.unlink()


def published_comparison():
    e = evaluator()
    summary_path = (
        e.ROOT / "spec/compatibility/broad-runs/query-explain-reference-summary-v3.json"
    )
    summary = json.loads(summary_path.read_bytes())
    directory = Path("/Users/tk/work/firebase-emulator/docs.local/logs/2026-09-14")
    for candidate in directory.glob("query-explain-reevaluation-v3-*.json"):
        if e.sha(candidate.read_bytes()) == summary["comparisonArtifactSha256"]:
            return e, candidate, summary_path
    pytest.skip("published comparison's private artifact unavailable")


def test_regenerates_published_summary_from_actual_comparison():
    e, comparison, summary = published_comparison()
    assert e.summary_bytes(comparison.read_bytes()) == summary.read_bytes()
    e.check_summary(comparison, summary)


@pytest.mark.parametrize("change", ["summary", "comparison"])
def test_summary_check_rejects_tampering(tmp_path, change):
    e, comparison, summary = published_comparison()
    copied_comparison = tmp_path / "comparison.json"
    copied_summary = tmp_path / "summary.json"
    copied_comparison.write_bytes(comparison.read_bytes())
    copied_summary.write_bytes(summary.read_bytes())
    target = copied_summary if change == "summary" else copied_comparison
    value = json.loads(target.read_bytes())
    value["rows"][0]["compatibility"] = "mismatch"
    target.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="summary"):
        e.check_summary(copied_comparison, copied_summary)


def test_public_summary_cli_regenerates_checks_and_refuses_tampering(committed_source):
    import subprocess
    import sys

    _e, root, _git = committed_source
    _e, comparison, published = published_comparison()
    output = root / "projected-summary.json"
    command = [
        sys.executable,
        "-I",
        str(root / "tools/compat-explain-reference-v3/evaluate.py"),
    ]
    projected = subprocess.run(
        [*command, "--project-summary", str(comparison), "--output", str(output)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert projected.returncode == 0, projected.stderr
    assert output.read_bytes() == published.read_bytes()
    check = [*command, "--check-summary", str(comparison), "--summary", str(output)]
    checked = subprocess.run(check, check=False, capture_output=True, text=True)
    assert checked.returncode == 0, checked.stderr
    assert json.loads(checked.stdout)["summaryValid"] is True
    output.write_bytes(output.read_bytes() + b"\n")
    assert subprocess.run(check, check=False, capture_output=True).returncode != 0
