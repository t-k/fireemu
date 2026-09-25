"""Publish a human approval overlay without changing its frozen subject inputs."""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "auth_profile_frozen_publisher", ROOT / "tools/publish-auth-profile.py"
)
assert spec and spec.loader
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)

APPROVAL = ROOT / "spec/compatibility/evidence/auth-profile/approval.json"
PAGE = ROOT / "docs/compatibility/auth-profile-approval.md"
SUBJECT = "23913299c5d414abbdffe0692711f77ead500b639318a09a60a5802bd1f199d2"
SCOPE = "Photo URL setting, replacement and deletion through REST using end-user tokens; no tenant; local strict profile and recorded production configuration; only the recorded artifact, configuration and auth-photo-url corpus revision 1 twelve cases; approved as redacted semantic observations matching the published checks."


def render(approval, receipt):
    # This is one recorded human decision, not a general approval authority.
    expected = {
        "schemaVersion": 1,
        "subjectSha256": SUBJECT,
        "sourceCommit": "bb2f1a2f15f8aa447bce9395e7322840ec11b5f3",
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
        "# Auth photoUrl updates and deletion: scoped human approval",
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
        "The original signup ID token is used for photoUrl updates, lookups and account deletion. Admin APIs support dedicated-account ownership verification and cleanup; this is not an Admin-only profile update test. Setting and replacing use two distinct fixed URLs, and malformed-token refusal attempts a third URL before a valid-token lookup compares selected state.",
        "",
        "Expired-token refusal, independent signature validation, token issuance during profile updates, null/empty-string writes, URL boundary conditions, displayName or credential changes and SDK behavior remain unverified by this slice. This is a URL attribute test, not image upload or retrieval. MFA, Rules, OOB, tenant behavior, public npm artifacts and complete Auth or profile-update compatibility are outside this approval.",
        "",
        "[Approval record](../../spec/compatibility/evidence/auth-profile/approval.json) · [Redacted receipt](../../spec/compatibility/evidence/auth-profile/receipt.json) · [Source and case mapping](../../spec/compatibility/evidence/auth-profile/source-review.json). Token values, passwords and arbitrary returned URLs are not published. A closed enum distinguishes omission, null, empty strings, fixed corpus URLs and other values. Clearing is documented; exact JSON omission is the recorded observation, not a broader inferred specification. Third parties cannot independently reconstruct raw token/account checks from these redacted records.",
        "",
        "The [original candidate page](auth-profile.md) and its source-review status are immutable acquisition-time history. This separate approval supersedes their pending-approval status only for the subject and twelve cases above. Existing Auth basic approvals, original observations and aggregation approvals remain unchanged; broad feature labels are not promoted.",
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
    print("Auth photoUrl approval checked; subject " + SUBJECT)
