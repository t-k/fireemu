"""Publish a human approval overlay without changing its frozen subject inputs."""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "auth_display_name_frozen_publisher", ROOT / "tools/publish-auth-display-name.py"
)
assert spec and spec.loader
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)

APPROVAL = ROOT / "spec/compatibility/evidence/auth-display-name/approval.json"
PAGE = ROOT / "docs/compatibility/auth-display-name-approval.md"
SUBJECT = "f6e31fd28a7c05651df454843fe5c40c48b4e70552617b796f1398c702b0d2ec"
SCOPE = "Display name setting, replacement and deletion through REST using end-user tokens; no tenant; local strict profile and recorded production configuration; only the recorded artifact, configuration and auth-display-name corpus revision 1 twelve cases; approved as redacted semantic observations matching the published checks."


def render(approval, receipt):
    # This is one recorded human decision, not a general approval authority.
    expected = {
        "schemaVersion": 1,
        "subjectSha256": SUBJECT,
        "sourceCommit": "f54ce460f2b743354400cddd56554a3164f30b7b",
        "scope": SCOPE,
        "cases": list(publisher.CASES),
        "reviewer": "github:t-k (id:426779)",
        "reviewedAt": "2026-09-10",
        "decision": "approve",
    }
    if approval != expected or publisher.digest(receipt) != SUBJECT:
        raise ValueError(
            "Approval does not match the recorded human decision and subject"
        )
    publisher.validate(receipt)
    if not all(
        row["passed"] is True
        for target in ("local", "production")
        for row in receipt[target]["cases"]
    ):
        raise ValueError("Approval requires all scoped observations to match")
    lines = [
        "# Auth displayName updates and deletion: scoped human approval",
        "",
        "Twelve scoped cases verified and approved as redacted semantic observations matching the published checks. This is not approval of Auth as a whole.",
        "",
        SCOPE,
        "",
        f"Subject: `{SUBJECT}`. Recomputed from the complete receipt during offline validation; approval cannot transfer to a changed subject.",
        "",
        f"Reviewed commit: `{approval['sourceCommit']}`. Reviewer: `{approval['reviewer']}`. Approval date: {approval['reviewedAt']}.",
        "",
        "This repository records the user's explicit approval; it is not a cryptographic signature or independent reviewer authentication mechanism.",
        "",
        "| Approved case | Local | Production |",
        "|---|---|---|",
        *[f"| {case} | Matched | Matched |" for case in approval["cases"]],
        "",
        "The original signup ID token is used for displayName updates, lookups and account deletion. Initial email/marker and independent UID lookups establish ownership; the private UID record is saved and reread before name mutation. Afterward, UID and email identify the account rather than its mutable name. Admin APIs support ownership and cleanup, not an Admin-only profile update test. Two fixed names test setting and replacement; malformed-token refusal attempts a third name before valid-token lookup compares selected state.",
        "",
        "Expired-token refusal, independent signature validation, token issuance during updates, Unicode/length boundaries, null/empty-string writes, simultaneous setting and clearing, credential changes and SDK behavior remain unverified by this slice. Recovery from communication loss or forced termination is not verified; completed cleanup observations do not establish fault-recovery guarantees. MFA, Rules, OOB, tenant behavior, public npm artifacts and complete Auth or profile-update compatibility are outside this approval.",
        "",
        "[Approval record](../../spec/compatibility/evidence/auth-display-name/approval.json) · [Redacted receipt](../../spec/compatibility/evidence/auth-display-name/receipt.json) · [Source and case mapping](../../spec/compatibility/evidence/auth-display-name/source-review.json). Token values, passwords, account identities and arbitrary returned names are not published. A closed enum distinguishes the initial marker, fixed corpus names, omission, null, empty strings and other values. Clearing is documented; exact JSON omission is the recorded observation, not a broader inferred specification. Third parties cannot independently reconstruct raw token/account checks from these redacted records.",
        "",
        "The [original candidate page](auth-display-name.md) and its source-review status are immutable acquisition-time history. This separate approval supersedes their pending-approval status only for the subject and twelve cases above. Existing Auth basic and photoUrl approvals, original observations and aggregation approvals remain unchanged; broad feature labels are not promoted.",
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    page = render(
        json.loads(APPROVAL.read_bytes()), json.loads(publisher.BUNDLE.read_bytes())
    )
    if args.check:
        if PAGE.read_text() != page:
            raise ValueError("Generated Auth approval page is stale")
    else:
        PAGE.write_text(page)
    print("Auth displayName approval checked; subject " + SUBJECT)
