"""Record the scoped human approval of the auth-disabled-admin-update-comparison record without altering it."""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "auth_disabled_admin_update_comparison_publisher",
    ROOT / "tools/publish-auth-disabled-admin-update-comparison.py",
)
assert spec and spec.loader
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
APPROVAL = (
    ROOT
    / "spec/compatibility/evidence/auth-disabled-admin-update/comparison-approval.json"
)
PAGE = ROOT / "docs/compatibility/auth-disabled-admin-update-comparison-approval.md"
SUBJECT = "87086b8343892b9bffd0a8e913b72658c6d277e2ea86d26dd88382b9acb8cc90"
SOURCE_COMMIT = "3cadafe7a42effb58b392897298e583a32e51792"
SCOPE = "Row-by-row comparison of the approved production record of auth-disabled-admin-update revision 1 with one run of the same corpus on the owned local artifact built from the tree at the recorded commit after the token rule was corrected: all ten semantic projections agree. Approved as a comparison of these ten cases on that artifact, profile and recorder; not a claim beyond them."
CASES = [
    "baseline-a-signin",
    "baseline-b-signin",
    "disabled-a-password-update",
    "disabled-a-update-token-lookup",
    "disabled-a-update-token-refresh",
    "disabled-a-photo-update",
    "disabled-a-signin",
    "disabled-b-signin",
    "reenabled-a-signin",
    "reenabled-b-signin",
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
            "# Administrative updates to a disabled account, local comparison: scoped human approval",
            "",
            "Verified and approved within this limited scope. This is not a new production run and not a claim of complete Auth compatibility.",
            "",
            SCOPE,
            "",
            f"Subject: `{SUBJECT}`. Recomputed from the complete record; this approval cannot transfer to a changed subject.",
            "",
            f"Reviewed commit: `{approval['sourceCommit']}`. Reviewer: `{approval['reviewer']}`. Approval date: {approval['reviewedAt']}.",
            "",
            "This records the user's explicit decision, not a cryptographic signature or independent identity authentication. The source mapping's execution approval stays not-granted: approving a recorded observation does not authorize new production operations.",
            "",
            "| Compared case | Same semantic projection |",
            "| --- | --- |",
            *[
                f"| {case} | {rows[case]['sameSemanticProjection']} |"
                for case in approval["cases"]
            ],
            "",
            "[Approval record](../../spec/compatibility/evidence/auth-disabled-admin-update/comparison-approval.json) · [Record](../../spec/compatibility/evidence/auth-disabled-admin-update/local-comparison.json) · [Candidate page](auth-disabled-admin-update-comparison.md).",
            "",
            "The candidate page remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these cases. The private run, earlier candidates in history, the source mapping and every earlier approval remain unchanged.",
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
    print("auth-disabled-admin-update-comparison approval checked; subject " + SUBJECT)
