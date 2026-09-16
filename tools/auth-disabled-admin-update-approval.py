"""Record the scoped human approval of the auth-disabled-admin-update record without altering it."""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "auth_disabled_admin_update_publisher",
    ROOT / "tools/publish-auth-disabled-admin-update.py",
)
assert spec and spec.loader
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
APPROVAL = ROOT / "spec/compatibility/evidence/auth-disabled-admin-update/approval.json"
PAGE = ROOT / "docs/compatibility/auth-disabled-admin-update-approval.md"
SUBJECT = "c5edbe9850fc52c66c666ca0c62961af3c4ad214fc074a950380c592960560fd"
SOURCE_COMMIT = "3cadafe7a42effb58b392897298e583a32e51792"
SCOPE = "Ten-case frame (eight executed rows, two conditionally skipped rows) projected without secrets from the saved 2026-09-12 production run of auth-disabled-admin-update revision 1. Approved as recorded: an administrative password replacement and a photo update of a disabled account are accepted and applied with no tokens returned, the account's own sign-in stays USER_DISABLED, the replaced password signs in after re-enablement, the control signs in at every phase, the configuration and password policy are unchanged, and both accounts are deleted with absence confirmation. The two token rows were skipped because no tokens were returned and are not approved as executed. No tenant, two update fields, a single run; not extended to other fields, self-service updates, SDK or Rules."
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
    rows = {r["id"]: r for r in receipt["production"]["cases"]}
    return "\n".join(
        [
            "# Administrative updates to a disabled account: scoped human approval",
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
            "[Approval record](../../spec/compatibility/evidence/auth-disabled-admin-update/approval.json) · [Record](../../spec/compatibility/evidence/auth-disabled-admin-update/receipt.json) · [Candidate page](auth-disabled-admin-update.md).",
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
    print("auth-disabled-admin-update approval checked; subject " + SUBJECT)
