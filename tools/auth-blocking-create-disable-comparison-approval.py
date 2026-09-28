"""Record the scoped human approval of the auth-blocking-create-disable-comparison record without altering it."""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "auth_blocking_create_disable_comparison_publisher",
    ROOT / "tools/publish-auth-blocking-create-disable-comparison.py",
)
assert spec and spec.loader
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
APPROVAL = (
    ROOT
    / "spec/compatibility/evidence/auth-blocking-create-disable/comparison-approval.json"
)
PAGE = ROOT / "docs/compatibility/auth-blocking-create-disable-comparison-approval.md"
SUBJECT = "8d21beb022a6afb5f1bb22aa9d164f9e6a16a469f6fa7379d1e3b5fcb4c8fd9e"
SOURCE_COMMIT = "bfe70d7f1bb8d95d1f4a49abfc2f3c09a4da0122"
SCOPE = "Row-by-row comparison of the approved production record of auth-blocking-create-disable revision 2 with one run of the same corpus on the owned local artifact: all ten semantic projections agree (creating sign-up refused, disabled record kept, second sign-up EMAIL_EXISTS, photo URL not persisted). Production used the recorded first-generation blocking function; the owned local run used the equivalent second-generation Identity fixture installed with npm ci from the committed lockfile, with the runner, fixture files, lockfile and artifact bound to committed content. Approved as a comparison of these cases on that artifact, profile and recorder; not a claim of Functions SDK generation parity or beyond these cases."
CASES = [
    "control-c-signup",
    "control-c-signup-readback",
    "control-c-signin",
    "target-t-signup",
    "target-t-token-lookup",
    "target-t-token-refresh",
    "target-t-record-readback",
    "target-t-signin",
    "target-t-second-signup",
    "control-c-final-signin",
]


def render(approval, receipt):
    expected = {
        "schemaVersion": 1,
        "subjectSha256": SUBJECT,
        "sourceCommit": SOURCE_COMMIT,
        "scope": SCOPE,
        "cases": CASES,
        "reviewer": "github:t-k (id:426779)",
        "reviewedAt": "2026-09-12",
        "decision": "approve",
    }
    if (
        publisher.digest(approval) != publisher.digest(expected)
        or publisher.digest(receipt) != SUBJECT
    ):
        raise ValueError(
            "Approval must match the exact human decision and complete subject"
        )
    publisher.validate(receipt)
    rows = {r["id"]: r for r in receipt["comparison"]}
    return "\n".join(
        [
            "# Blocking function on the creating request (revision 2), local comparison: scoped human approval",
            "",
            "Verified and approved within this limited scope. This is not a new production run and not a claim of complete Auth compatibility.",
            "",
            SCOPE,
            "",
            f"Subject: `{SUBJECT}`. Recomputed from the complete record; this approval cannot transfer to a changed subject.",
            "",
            f"Reviewed commit: `{approval['sourceCommit']}`. Reviewer: `{approval['reviewer']}`. Approval date: {approval['reviewedAt']}.",
            "",
            "This records the user's explicit decision, not a cryptographic signature or independent identity authentication.",
            "",
            "| Compared case | Same semantic projection |",
            "| --- | --- |",
            *[
                f"| {case} | {rows[case]['sameSemanticProjection']} |"
                for case in approval["cases"]
            ],
            "",
            "[Approval record](../../spec/compatibility/evidence/auth-blocking-create-disable/comparison-approval.json) · [Comparison record](../../spec/compatibility/evidence/auth-blocking-create-disable/local-comparison.json) · [Comparison page](auth-blocking-create-disable-comparison.md).",
            "",
            "The comparison page remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these cases. The private runs, earlier records in history, the source mappings and every earlier approval remain unchanged.",
            "",
        ]
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    page = render(
        json.loads(APPROVAL.read_bytes()), json.loads(publisher.BUNDLE.read_bytes())
    )
    if args.check:
        if PAGE.read_text() != page:
            raise ValueError("Generated approval page is stale")
    else:
        PAGE.write_text(page)
    print(
        "auth-blocking-create-disable-comparison approval checked; subject " + SUBJECT
    )
