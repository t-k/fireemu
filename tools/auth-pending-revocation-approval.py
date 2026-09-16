"""Record the scoped human approval of the pending-revocation observation without altering it."""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "pending_revocation_publisher", ROOT / "tools/publish-auth-pending-revocation.py"
)
assert spec and spec.loader
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
APPROVAL = ROOT / "spec/compatibility/evidence/auth-pending-revocation/approval.json"
PAGE = ROOT / "docs/compatibility/auth-pending-revocation-approval.md"
SUBJECT = "c6ce38ac6a05b969cdbbf516e77a1fc386e73cb221301d53f98c2c45029a0eb7"
SOURCE_COMMIT = "3a68ff3d94ce0b2f185fafb32a25bc2ed3f02e36"
SCOPE = "Eight production-only observations projected without secrets from the saved 2026-09-11 run of auth-pending-revocation revision 1. Explicit validSince update through privileged accounts:update with readback, phone MFA with test phone numbers, no tenant, no blocking hook, the recorded operation order and a single run. The held pending credential of target A, issued before the update and never completed, was presented after the update: start and finalize were accepted, the returned ID token's auth_time was at or after the set validSince, lookup and refresh succeeded. Baseline and fresh completions for A and control B, the recorded configuration restore with a matching digest, and Admin deletion with UID/email absence are included. The approval does not extend to a production/local comparison of this corpus, revocation propagation time, refusal of a pre-update refresh token, password changes, other MFA methods, tenants, blocking hooks, SDK checkRevoked, Rules or credential expiry."


def render(approval, receipt):
    expected = {
        "schemaVersion": 1,
        "subjectSha256": SUBJECT,
        "sourceCommit": SOURCE_COMMIT,
        "scope": SCOPE,
        "cases": list(publisher.CASES),
        "reviewer": "github:t-k (id:426779)",
        "reviewedAt": "2026-09-11",
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
    rows = {row["id"]: row for row in receipt["production"]["cases"]}
    return "\n".join(
        [
            "# MFA pending credential across an explicit revocation: scoped human approval",
            "",
            "8 production-only observations verified and approved within this limited scope. This is not a new production run, not a production/local comparison, and not a claim of complete Auth compatibility.",
            "",
            SCOPE,
            "",
            f"Subject: `{SUBJECT}`. Recomputed from the complete receipt; this approval cannot transfer to a changed subject.",
            "",
            f"Reviewed commit: `{approval['sourceCommit']}`. Reviewer: `{approval['reviewer']}`. Approval date: {approval['reviewedAt']}.",
            "",
            "This records the user's explicit decision, not a cryptographic signature or independent identity authentication. The source mapping's execution approval stays not-granted: approving the recorded observation does not authorize new production operations.",
            "",
            "| Approved observation | Basis | Recorded outcome |",
            "| --- | --- | --- |",
            *[
                f"| {case} | {'diagnostic' if case in publisher.DIAGNOSTIC else 'control'} | {rows[case]['outcome']} / {rows[case]['observedError'] or 'none'} |"
                for case in approval["cases"]
            ],
            "",
            "The held credential rows are approved as the observed outcome under the recorded conditions, not as a rule about revocation. Token values are not public, so independent signature verification is not established by these redacted checks. The two-second wait preceded the validSince update; the interval between the update and the retry was not measured.",
            "",
            "[Approval record](../../spec/compatibility/evidence/auth-pending-revocation/approval.json) · [Receipt](../../spec/compatibility/evidence/auth-pending-revocation/receipt.json) · [Candidate page](auth-pending-revocation.md).",
            "",
            "The candidate page remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these eight observations. The private run, the earlier unapproved candidate in history, the source mapping and every earlier approval remain unchanged.",
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
            raise ValueError("Generated pending-revocation approval page is stale")
    else:
        PAGE.write_text(page)
    print("Pending-revocation approval checked; subject " + SUBJECT)
