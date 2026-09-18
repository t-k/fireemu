"""Publication hygiene: no personal absolute paths in the published trees.

This repository is published. Recording tools used to write ``str(ROOT)`` and
temporary directories verbatim into run receipts and readiness notes, which
leaks the operator's home directory name. Those receipts are now repo-relative
or use the ``<private>`` abbreviation, and this guard keeps them that way.

Files that cannot be rewritten are listed in ``ALLOWLIST`` with the reason.
"""

import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCANNED_TREES = ("spec", "docs", "tools", "conformance")

# Built from parts so this guard does not match itself.
_PREFIX_PARTS = (("Users",), ("home",), ("private", "tmp"), ("var", "folders"))
FORBIDDEN_PREFIXES = tuple("/" + "/".join(parts) + "/" for parts in _PREFIX_PARTS)

ALLOWLIST = {
    "tools/compat-explain-reference/test_evaluate.py": (
        "Digest-bound: its sha256 is pinned in "
        "spec/compatibility/broad-runs/query-explain-reference-evaluator-v2.json "
        "and listed in tools/compat-explain-reference/evaluate.py SOURCE_FILES. "
        "The anchor also replays the bytes out of a pinned source commit, so an "
        "edit requires re-running the evaluator against the private saved "
        "collection and republishing both the v2 and v3 anchors."
    ),
    "tools/compat-explain-reference-v3/test_evaluate_v3.py": (
        "Digest-bound: its sha256 is pinned in "
        "spec/compatibility/broad-runs/query-explain-reference-evaluator-v3.json "
        "and listed in tools/compat-explain-reference-v3/evaluate.py "
        "SOURCE_FILES, which also replays the bytes out of a pinned source "
        "commit. Same regeneration path as the v2 evaluator test."
    ),
    "tools/compat-broad/fs-listen-resume/test_o6_listen_sdk_local_shadow.py": (
        "The prefixes appear inside that lane's own assertions that its shadow "
        "evidence carries no absolute paths."
    ),
    "tools/compat-broad/fs-write-txn/test_txn_expiry_evidence.py": (
        "The prefixes appear inside that lane's own assertions that its "
        "transaction expiry evidence carries no absolute paths."
    ),
}


def scan_text(text):
    """Return (line number, prefix) for every forbidden prefix occurrence."""
    hits = []
    for number, line in enumerate(text.splitlines(), start=1):
        for prefix in FORBIDDEN_PREFIXES:
            if prefix in line:
                hits.append((number, prefix))
    return hits


def tracked_files():
    raw = subprocess.run(
        ["git", "ls-files", "-z", "--", *SCANNED_TREES],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    return [name for name in raw.decode().split("\0") if name]


def offending_lines(name):
    path = ROOT / name
    if path.is_symlink() or not path.is_file():
        return []
    return scan_text(path.read_bytes().decode("utf-8", errors="ignore"))


def test_published_trees_carry_no_personal_absolute_paths():
    unexpected = {
        name: hits
        for name in tracked_files()
        if name not in ALLOWLIST and (hits := offending_lines(name))
    }
    assert not unexpected, "personal absolute paths in published files: " + "; ".join(
        f"{name}:{number} contains {prefix}"
        for name, hits in sorted(unexpected.items())
        for number, prefix in hits
    )


@pytest.mark.parametrize("name", sorted(ALLOWLIST))
def test_allowlist_entry_is_still_needed(name):
    assert ALLOWLIST[name].strip(), "every allowlist entry needs a reason"
    assert (ROOT / name).is_file(), f"allowlisted file no longer exists: {name}"
    assert offending_lines(name), (
        f"{name} no longer contains a personal absolute path; remove it from ALLOWLIST"
    )


def test_allowlist_only_names_files_in_the_scanned_trees():
    for name in ALLOWLIST:
        assert name.split("/")[0] in SCANNED_TREES


@pytest.mark.parametrize("prefix", FORBIDDEN_PREFIXES)
def test_guard_detects_a_reintroduced_path(prefix):
    receipt = '{"command": ["' + prefix + 'someone/firebase-emulator/fireemu"]}'
    assert scan_text("fine\n" + receipt + "\nfine\n") == [(2, prefix)]


def test_guard_accepts_the_repo_relative_and_abbreviated_forms():
    accepted = (
        '{"command": ["docs.local/logs/2026-09-13/goals/fireemu"]}',
        '".worktree/compatibility-inventory/tools/compat-inventory/.venv/bin/python3"',
        "`<private>` below abbreviates the private log directory",
    )
    assert scan_text("\n".join(accepted)) == []
