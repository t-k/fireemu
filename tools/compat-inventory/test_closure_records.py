"""The records every closure cites must exist and must not change silently."""

import hashlib
import json
from itertools import product
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from hypothesis import given, settings, strategies as st

from closure_records import build_lock, check, closure_references, retired_suites


def write(root: Path, path: str, text: str) -> Path:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    return target


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


WORKFLOW = """jobs:
  compat-broad-tests:
    env:
      RETIRED_SUITES: |
        tools/compat-broad/fs-write-limits
        tools/compat-broad/auth-credential-tokens
"""


@pytest.fixture
def repo(tmp_path):
    record = '{"cases": [{"id": "batch-malformed-middle"}]}'
    write(tmp_path, "spec/compatibility/broad-runs/limits.json", record)
    write(
        tmp_path,
        "spec/compatibility/closure/evidence/X-comparison.json",
        '{"ok": true}',
    )
    write(tmp_path, "docs/compatibility/goals.md", "# goals")
    write(tmp_path, "tools/compat-broad/auth-account-federation/test_corpus.py", "")
    write(tmp_path, ".github/workflows/compatibility-inventory.yml", WORKFLOW)
    closure = {
        "conditions": [
            {
                "source": "spec/compatibility/broad-runs/limits.json#batch-malformed-middle",
                "evidence": {
                    "comparisonPath": "spec/compatibility/closure/evidence/X-comparison.json",
                    "comparisonSha256": sha('{"ok": true}'),
                    "federationCorpus": "tools/compat-broad/auth-account-federation/test_corpus.py: 63 passed",
                    "doc": "docs/compatibility/goals.md",
                    "note": "not a path: spec only in prose",
                },
            }
        ]
    }
    write(tmp_path, "spec/compatibility/closure/X.json", json.dumps(closure))
    lock = build_lock(tmp_path)
    write(tmp_path, "spec/compatibility/closure/record-digests.json", json.dumps(lock))
    return tmp_path


def test_references_are_found_with_fragments_and_result_suffixes(repo):
    refs = closure_references(repo)
    assert {ref.path for ref in refs} == {
        "spec/compatibility/broad-runs/limits.json",
        "spec/compatibility/closure/evidence/X-comparison.json",
        "tools/compat-broad/auth-account-federation/test_corpus.py",
        "docs/compatibility/goals.md",
    }
    assert any(ref.fragment == "batch-malformed-middle" for ref in refs)


def test_the_lock_pins_only_spec_and_conformance_records(repo):
    lock = build_lock(repo)
    assert set(lock["records"]) == {
        "spec/compatibility/broad-runs/limits.json",
        "spec/compatibility/closure/evidence/X-comparison.json",
    }
    assert check(repo) == []


def test_a_changed_or_missing_record_fails(repo):
    write(
        repo,
        "spec/compatibility/broad-runs/limits.json",
        '{"cases": [{"id": "batch-malformed-middle"}], "x": 1}',
    )
    assert any(
        "limits.json" in problem and "digest" in problem for problem in check(repo)
    )
    (repo / "docs/compatibility/goals.md").unlink()
    assert any(
        "goals.md" in problem and "missing" in problem for problem in check(repo)
    )


def test_a_missing_fragment_or_a_wrong_paired_digest_fails(repo):
    closure = json.loads((repo / "spec/compatibility/closure/X.json").read_text())
    closure["conditions"][0]["source"] = (
        "spec/compatibility/broad-runs/limits.json#nowhere"
    )
    closure["conditions"][0]["evidence"]["comparisonSha256"] = "0" * 64
    write(repo, "spec/compatibility/closure/X.json", json.dumps(closure))
    problems = check(repo)
    assert any("#nowhere" in problem for problem in problems)
    assert any("comparisonSha256" in problem for problem in problems)


def test_a_new_record_needs_a_lock_entry(repo):
    write(repo, "spec/compatibility/broad-runs/new.json", "{}")
    closure = json.loads((repo / "spec/compatibility/closure/X.json").read_text())
    closure["conditions"].append({"source": "spec/compatibility/broad-runs/new.json"})
    write(repo, "spec/compatibility/closure/X.json", json.dumps(closure))
    assert any(
        "new.json" in problem and "not pinned" in problem for problem in check(repo)
    )


def test_a_closure_may_not_cite_a_retired_suite(repo):
    assert retired_suites(repo) == [
        "tools/compat-broad/fs-write-limits",
        "tools/compat-broad/auth-credential-tokens",
    ]
    write(repo, "tools/compat-broad/fs-write-limits/test_x.py", "")
    closure = json.loads((repo / "spec/compatibility/closure/X.json").read_text())
    closure["conditions"].append(
        {"source": "tools/compat-broad/fs-write-limits/test_x.py: 3 passed"}
    )
    write(repo, "spec/compatibility/closure/X.json", json.dumps(closure))
    assert any("retired" in problem for problem in check(repo))


def test_markdown_fragments_are_heading_anchors(repo):
    write(
        repo,
        "docs/compatibility/goals.md",
        "# Goals\n\n## Feature group status\n\n### In-scope, application-facing contracts\n",
    )
    closure = json.loads((repo / "spec/compatibility/closure/X.json").read_text())
    closure["conditions"][0]["evidence"]["doc"] = (
        "docs/compatibility/goals.md#feature-group-status"
    )
    closure["conditions"].append(
        {"source": "docs/compatibility/goals.md#in-scope-application-facing-contracts"}
    )
    write(repo, "spec/compatibility/closure/X.json", json.dumps(closure))
    assert check(repo) == []
    closure["conditions"].append(
        {"source": "docs/compatibility/goals.md#missing-heading"}
    )
    write(repo, "spec/compatibility/closure/X.json", json.dumps(closure))
    problems = check(repo)
    assert problems == [
        "X.json: docs/compatibility/goals.md#missing-heading names no entry in the file"
    ]


def add_projection(repo):
    historical = "spec/compatibility/official-compatibility/history/e57a78e0/X.json"
    write(
        repo,
        historical,
        '{"conditions": [{"source": "tools/compat-broad/fs-write-limits/test_old.py"}]}',
    )
    write(repo, "tools/compat-broad/fs-write-limits/test_old.py", "")
    official = "spec/compatibility/official-compatibility/registry.json"
    write(
        repo,
        official,
        json.dumps(
            {
                "snapshots": [
                    {
                        "snapshotPath": historical,
                        "snapshotSha256": sha((repo / historical).read_text()),
                    }
                ]
            }
        ),
    )
    parent = "spec/compatibility/production-parent-registry.json"
    write(
        repo,
        parent,
        json.dumps(
            {
                "officialRegistryPath": official,
                "officialRegistrySha256": sha((repo / official).read_text()),
            }
        ),
    )
    return parent, official, historical


def test_projection_documents_are_discovered_without_increasing_closure_count(repo):
    parent, official, historical = add_projection(repo)
    refs = closure_references(repo)
    assert {parent, official, historical}.issubset({ref.path for ref in refs})
    previous = json.loads(
        (repo / "spec/compatibility/closure/record-digests.json").read_text()
    )["records"]
    updated = build_lock(repo)
    assert all(updated["records"][path] == digest for path, digest in previous.items())
    write(repo, "spec/compatibility/closure/record-digests.json", json.dumps(updated))
    assert check(repo) == []


def test_new_projection_inputs_need_pins_and_paired_real_digests(repo):
    _, official, _ = add_projection(repo)
    assert any(
        "production-parent-registry.json" in p and "not pinned" in p
        for p in check(repo)
    )
    doc = json.loads((repo / official).read_text())
    doc["snapshots"][0]["snapshotSha256"] = "0" * 64
    write(repo, official, json.dumps(doc))
    assert any("snapshotSha256 differs" in p for p in check(repo))


def test_partial_projection_and_missing_snapshot_fail(repo):
    _, official, historical = add_projection(repo)
    (repo / historical).unlink()
    assert any(historical in p and "missing" in p for p in check(repo))
    (repo / official).unlink()
    assert any("projection" in p and "missing" in p for p in check(repo))


def test_active_projection_still_refuses_retired_execution_references(repo):
    parent, _, _ = add_projection(repo)
    doc = json.loads((repo / parent).read_text())
    doc["activeEvidence"] = "tools/compat-broad/fs-write-limits/test_old.py"
    write(repo, parent, json.dumps(doc))
    assert any(
        "retired" in p and "production-parent-registry" in p for p in check(repo)
    )


def test_historical_references_keep_existence_and_digest_checks(repo):
    _, _, historical = add_projection(repo)
    target = "spec/compatibility/broad-runs/old-observation.json"
    write(repo, target, '{"recorded": true}')
    doc = json.loads((repo / historical).read_text())
    doc["observationPath"] = target
    doc["observationSha256"] = sha('{"recorded": true}')
    write(repo, historical, json.dumps(doc))
    write(
        repo,
        "spec/compatibility/closure/record-digests.json",
        json.dumps(build_lock(repo)),
    )
    write(repo, target, '{"recorded": false}')
    assert any("observationSha256 differs" in p for p in check(repo))
    (repo / target).unlink()
    assert any(target in p and "missing" in p for p in check(repo))


def test_projection_paired_digest_cannot_be_malformed(repo):
    _, official, _ = add_projection(repo)
    doc = json.loads((repo / official).read_text())
    doc["snapshots"][0]["snapshotSha256"] = "not-a-digest"
    write(repo, official, json.dumps(doc))
    assert any("snapshotSha256" in p and "invalid" in p for p in check(repo))


EXACT_TOOL_SOURCES = (
    "tools/compat-broad/fs-write-txn/fs_txn_compare_local.py",
    "tools/compat-broad/fs-write-txn/fs_txn_table_p13b.py",
)
UNPINNED_TOOL_NEIGHBORS = (
    "tools/compat-broad/fs-write-txn/fs_txn_compare_local.py.bak",
    "tools/compat-broad/fs-write-txn/fs_txn_table_p13b_extra.py",
    "tools/compat-broad/fs-write-txn/fs_txn_other.py",
    "tools/other/fs_txn_compare_local.py",
)
MODEL_PATHS = (
    "spec/compatibility/broad-runs/model.json",
    "conformance/model.mjs",
    *EXACT_TOOL_SOURCES,
    *UNPINNED_TOOL_NEIGHBORS,
)


def cite_source(repo, path, *, paired=False, historical=False):
    entry = (
        {"sourcePath": path, "sourceSha256": sha("original")}
        if paired
        else {"source": path}
    )
    if historical:
        write(
            repo,
            "spec/compatibility/official-compatibility/history/e57a78e0/tool.json",
            json.dumps({"conditions": [entry]}),
        )
    else:
        closure = json.loads((repo / "spec/compatibility/closure/X.json").read_text())
        closure["conditions"].append(entry)
        write(repo, "spec/compatibility/closure/X.json", json.dumps(closure))


def save_lock(repo):
    write(
        repo,
        "spec/compatibility/closure/record-digests.json",
        json.dumps(build_lock(repo)),
    )


@pytest.mark.parametrize("path", EXACT_TOOL_SOURCES)
def test_exact_tool_sources_are_pinned_when_cited(repo, path):
    write(repo, path, "original")
    cite_source(repo, path)
    assert build_lock(repo)["records"][path] == sha("original")
    save_lock(repo)
    assert check(repo) == []


@pytest.mark.parametrize("path", EXACT_TOOL_SOURCES)
def test_new_exact_tool_reference_requires_a_lock_entry(repo, path):
    write(repo, path, "original")
    cite_source(repo, path)
    assert any(path in problem and "not pinned" in problem for problem in check(repo))


@pytest.mark.parametrize("path", EXACT_TOOL_SOURCES)
def test_cited_exact_tool_source_hash_drift_is_rejected(repo, path):
    write(repo, path, "original")
    cite_source(repo, path)
    save_lock(repo)
    write(repo, path, "changed")
    assert any(
        path in problem and "digest differs" in problem for problem in check(repo)
    )


@pytest.mark.parametrize("path", EXACT_TOOL_SOURCES)
def test_exact_tool_paired_sha_remains_mandatory(repo, path):
    write(repo, path, "original")
    cite_source(repo, path, paired=True)
    save_lock(repo)
    write(repo, path, "changed")
    save_lock(repo)
    assert any(
        path in problem and "sourceSha256 differs" in problem for problem in check(repo)
    )


@pytest.mark.parametrize("path", EXACT_TOOL_SOURCES)
def test_missing_cited_exact_tool_remains_an_error(repo, path):
    cite_source(repo, path)
    assert path not in build_lock(repo)["records"]
    assert any(path in problem and "missing" in problem for problem in check(repo))


@pytest.mark.parametrize("path", EXACT_TOOL_SOURCES)
def test_uncited_exact_tool_is_not_pinned_and_stale_pin_is_rejected(repo, path):
    write(repo, path, "original")
    assert path not in build_lock(repo)["records"]
    lock_path = repo / "spec/compatibility/closure/record-digests.json"
    lock = json.loads(lock_path.read_text())
    lock["records"][path] = sha("original")
    lock_path.write_text(json.dumps(lock))
    assert any(
        path in problem
        and "is pinned in" in problem
        and "but no closure cites it" in problem
        for problem in check(repo)
    )


@pytest.mark.parametrize("path", UNPINNED_TOOL_NEIGHBORS)
def test_cited_tool_neighbors_do_not_expand_the_pin_family(repo, path):
    write(repo, path, "original")
    cite_source(repo, path)
    assert path not in build_lock(repo)["records"]
    assert check(repo) == []


@pytest.mark.parametrize("path", EXACT_TOOL_SOURCES)
@pytest.mark.parametrize("historical", [False, True], ids=["current", "historical"])
def test_exact_tool_retirement_distinguishes_current_and_historical_refs(
    repo, path, historical
):
    write(repo, path, "original")
    write(
        repo,
        ".github/workflows/compatibility-inventory.yml",
        WORKFLOW + "        tools/compat-broad/fs-write-txn\n",
    )
    cite_source(repo, path, paired=True, historical=historical)
    save_lock(repo)
    assert build_lock(repo)["records"][path] == sha("original")
    assert any("retired" in problem for problem in check(repo)) is not historical
    if historical:
        write(repo, path, "changed")
        problems = check(repo)
        assert any(
            path in problem and "digest differs" in problem for problem in problems
        )
        assert any(
            path in problem and "sourceSha256 differs" in problem
            for problem in problems
        )
        (repo / path).unlink()
        assert any(path in problem and "missing" in problem for problem in check(repo))


def test_bounded_reference_and_currency_model(tmp_path):
    """Exhaust all 256 combinations of path, citation, history, presence, drift, and paired SHA."""
    cases = product(MODEL_PATHS, *([[False, True]] * 5))
    for index, (path, cited, historical, present, changed, paired) in enumerate(cases):
        root = tmp_path / str(index)
        write(root, "spec/compatibility/closure/X.json", '{"conditions": []}')
        write(root, ".github/workflows/compatibility-inventory.yml", WORKFLOW)
        if present:
            write(root, path, "original")
        if cited:
            cite_source(root, path, paired=paired, historical=historical)
        eligible = path in EXACT_TOOL_SOURCES or path.startswith(
            ("spec/", "conformance/")
        )
        expected = {path: sha("original")} if cited and present and eligible else {}
        assert build_lock(root)["records"] == expected, (
            path,
            cited,
            historical,
            present,
            changed,
            paired,
        )
        save_lock(root)
        if present and changed:
            write(root, path, "changed")
        problems = check(root)
        missing = cited and not present
        drift = cited and present and changed and eligible
        mismatch = cited and present and changed and paired
        assert bool(problems) == (missing or drift or mismatch), (
            path,
            cited,
            historical,
            present,
            changed,
            paired,
            problems,
        )
        assert any("missing" in problem for problem in problems) == missing
        assert any("digest differs" in problem for problem in problems) == drift
        assert (
            any("sourceSha256 differs" in problem for problem in problems) == mismatch
        )
    assert index + 1 == 256


@settings(max_examples=80, derandomize=True, database=None, deadline=None)
@given(
    paths=st.lists(st.sampled_from(MODEL_PATHS), max_size=16),
    historical=st.booleans(),
    result_suffix=st.sampled_from(["", ": 2 passed", " evidence"]),
    content=st.text(alphabet="abc012\n", max_size=32),
)
def test_generated_citation_order_duplicates_and_suffixes_preserve_exact_pins(
    paths, historical, result_suffix, content
):
    with TemporaryDirectory(prefix="closure-record-property-") as directory:
        root = Path(directory)
        for path in MODEL_PATHS:
            write(root, path, content)
        write(root, ".github/workflows/compatibility-inventory.yml", WORKFLOW)
        write(root, "spec/compatibility/closure/X.json", '{"conditions": []}')
        document_path = (
            "spec/compatibility/official-compatibility/history/e57a78e0/tool.json"
            if historical
            else "spec/compatibility/closure/X.json"
        )

        def record_references(values):
            entries = [
                {
                    "nested": [
                        path + result_suffix,
                        {"note": "embedded citation " + path},
                    ]
                }
                for path in values
            ]
            write(root, document_path, json.dumps({"conditions": entries}))

        record_references(paths)
        expected = {
            path: sha(content)
            for path in set(paths)
            if path in EXACT_TOOL_SOURCES or path.startswith(("spec/", "conformance/"))
        }
        assert build_lock(root)["records"] == expected
        save_lock(root)
        assert check(root) == []
        record_references(list(reversed(paths)) + paths)
        assert build_lock(root)["records"] == expected
        assert check(root) == []
