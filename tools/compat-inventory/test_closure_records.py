"""The records every closure cites must exist and must not change silently."""

import hashlib
import json
from pathlib import Path

import pytest

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
    write(tmp_path, "spec/compatibility/closure/evidence/X-comparison.json", '{"ok": true}')
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
    write(repo, "spec/compatibility/broad-runs/limits.json", '{"cases": [{"id": "batch-malformed-middle"}], "x": 1}')
    assert any("limits.json" in problem and "digest" in problem for problem in check(repo))
    (repo / "docs/compatibility/goals.md").unlink()
    assert any("goals.md" in problem and "missing" in problem for problem in check(repo))


def test_a_missing_fragment_or_a_wrong_paired_digest_fails(repo):
    closure = json.loads((repo / "spec/compatibility/closure/X.json").read_text())
    closure["conditions"][0]["source"] = "spec/compatibility/broad-runs/limits.json#nowhere"
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
    assert any("new.json" in problem and "not pinned" in problem for problem in check(repo))


def test_a_closure_may_not_cite_a_retired_suite(repo):
    assert retired_suites(repo) == [
        "tools/compat-broad/fs-write-limits",
        "tools/compat-broad/auth-credential-tokens",
    ]
    write(repo, "tools/compat-broad/fs-write-limits/test_x.py", "")
    closure = json.loads((repo / "spec/compatibility/closure/X.json").read_text())
    closure["conditions"].append({"source": "tools/compat-broad/fs-write-limits/test_x.py: 3 passed"})
    write(repo, "spec/compatibility/closure/X.json", json.dumps(closure))
    assert any("retired" in problem for problem in check(repo))


def test_markdown_fragments_are_heading_anchors(repo):
    write(repo, "docs/compatibility/goals.md", "# Goals\n\n## Feature group status\n\n### In-scope, application-facing contracts\n")
    closure = json.loads((repo / "spec/compatibility/closure/X.json").read_text())
    closure["conditions"][0]["evidence"]["doc"] = "docs/compatibility/goals.md#feature-group-status"
    closure["conditions"].append({"source": "docs/compatibility/goals.md#in-scope-application-facing-contracts"})
    write(repo, "spec/compatibility/closure/X.json", json.dumps(closure))
    assert check(repo) == []
    closure["conditions"].append({"source": "docs/compatibility/goals.md#missing-heading"})
    write(repo, "spec/compatibility/closure/X.json", json.dumps(closure))
    problems = check(repo)
    assert problems == ["X.json: docs/compatibility/goals.md#missing-heading names no entry in the file"]
