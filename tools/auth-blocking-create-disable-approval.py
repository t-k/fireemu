"""Record the scoped human approval of the auth-blocking-create-disable record without altering it."""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "auth_blocking_create_disable_publisher",
    ROOT / "tools/publish-auth-blocking-create-disable.py",
)
assert spec and spec.loader
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
APPROVAL = (
    ROOT / "spec/compatibility/evidence/auth-blocking-create-disable/approval.json"
)
PAGE = ROOT / "docs/compatibility/auth-blocking-create-disable-approval.md"
SUBJECT = "206490130d5191df9a25a80634315a2b2c0ba190860cc91f7455931a9c25b362"
SOURCE_COMMIT = "3cadafe7a42effb58b392897298e583a32e51792"
SCOPE = "Ten-case frame (eight executed rows, two conditionally skipped rows) projected without secrets from the saved 2026-09-12 production run of auth-blocking-create-disable revision 2 with a first-generation beforeSignIn function that answers disabled: true for an email-prefix selector. Approved as recorded: the creating sign-up is refused with USER_DISABLED, the created record exists and is disabled, a second sign-up with the same email is EMAIL_EXISTS, the control signs up and signs in and its sign-up photo URL is not persisted, the function was removed and the trigger registration restored with a digest comparison, and both accounts were deleted with absence confirmation. The two token rows were skipped because the sign-up was refused and are not approved as executed. One function shape, no tenant, a single run; not extended to other auto-creating sign-in methods, beforeCreate, SDK or Rules."
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
    rows = {r["id"]: r for r in receipt["production"]["cases"]}
    return "\n".join(
        [
            "# Blocking function on the creating request (revision 2): scoped human approval",
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
            "| Approved observation | Basis | Recorded outcome |",
            "| --- | --- | --- |",
            *[
                f"| {case} | {'diagnostic' if case in publisher.DIAGNOSTIC else 'control'} | {rows[case]['outcome']} / {rows[case]['observedError'] or 'none'} |"
                for case in approval["cases"]
            ],
            "",
            "[Approval record](../../spec/compatibility/evidence/auth-blocking-create-disable/approval.json) · [Record](../../spec/compatibility/evidence/auth-blocking-create-disable/receipt.json) · [Candidate page](auth-blocking-create-disable.md).",
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
    print("auth-blocking-create-disable approval checked; subject " + SUBJECT)
