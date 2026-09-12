"""Record the scoped human approval of the auth-refusal-precedence-comparison record without altering it."""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "auth_refusal_precedence_comparison_publisher",
    ROOT / "tools/publish-auth-refusal-precedence-comparison.py",
)
assert spec and spec.loader
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
APPROVAL = (
    ROOT
    / "spec/compatibility/evidence/auth-refusal-precedence/comparison-approval.json"
)
PAGE = ROOT / "docs/compatibility/auth-refusal-precedence-comparison-approval.md"
SUBJECT = "81b71859a84bb7aa08dc8312b1fbf59c94d62e6a1e3eb8d1c71609b2f4e5f2f1"
SOURCE_COMMIT = "c3a7973b31274311ac64835aec761e0bb2a4c1e9"
SCOPE = "Row-by-row comparison of the approved production record of auth-refusal-precedence revision 1 with one run of the same corpus on an owned local fireemu artifact built after the end-user accounts:update route was corrected to authenticate before authorizing administrator-only fields (strict profile, --only auth, no configuration change, codes read from the emulator inspection route; artifact, runtime inputs and recorder files all bound to commit c3a7973b). All nine semantic projections agree, including the tampered-token update now refused INVALID_ID_TOKEN. Approved as a comparison of these cases on that artifact, profile and recorder; not a production run, and not a claim that the local artifact matches on anything outside these nine cases or that the non-tampered session-failure orderings are production-observed."
CASES = [
    "baseline-a-fresh-finalize",
    "baseline-b-fresh-finalize",
    "invalid-token-admin-field-update",
    "disabled-a-wrong-code-finalize",
    "disabled-b-correct-code-finalize",
    "reenabled-a-held-finalize",
    "reenabled-b-held-finalize",
    "final-a-fresh-finalize",
    "final-b-fresh-finalize",
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
            "# Precedence of overlapping refusals, local comparison: scoped human approval",
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
            "[Approval record](../../spec/compatibility/evidence/auth-refusal-precedence/comparison-approval.json) \u00b7 [Comparison record](../../spec/compatibility/evidence/auth-refusal-precedence/local-comparison.json) \u00b7 [Comparison page](auth-refusal-precedence-comparison.md).",
            "",
            "The comparison page remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these nine cases. The private runs, the discarded run 1, the source mapping and every earlier approval remain unchanged.",
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
    print("auth-refusal-precedence-comparison approval checked; subject " + SUBJECT)
