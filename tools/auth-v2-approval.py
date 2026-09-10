"""Publish a human approval overlay without changing its frozen subject inputs."""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "auth_v2_frozen_publisher", ROOT / "tools/publish-auth-v2.py"
)
assert spec and spec.loader
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)

APPROVAL = ROOT / "spec/compatibility/evidence/auth-basic-v2/approval.json"
PAGE = ROOT / "docs/compatibility/auth-basic-v2-approval.md"
SUBJECT = "0eb3689e1eb636f4166d3f296bba2fea2cf2ac70bf6ab6901d1077575a2a60cb"
SCOPE = "Email/password Auth REST using end-user tokens; no tenant; local strict profile and recorded production configuration; only the recorded artifact, configuration and corpus revision 2 twelve cases; approved as redacted semantic observations matching the published checks."


def render(approval, receipt):
    # This is one recorded human decision, not a general approval authority.
    expected = {
        "schemaVersion": 1,
        "subjectSha256": SUBJECT,
        "sourceCommit": "29378b6f25fdad1e44e08114f5b684aeff4de808",
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
        "# Auth basic revision 2: scoped human approval",
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
        "Signup and signin tokens are used for account lookup and refresh; refreshed tokens are used for lookup, and the signin refresh flow supplies the deletion token. Admin APIs support dedicated-account ownership verification and cleanup, not an Admin-only authentication claim. Wrong-password refusal is conditional on the recorded improved email privacy configuration.",
        "",
        "Expired-token refusal and independent token signature validation remain unverified. Returned expiry is 3600 seconds in the four token-returning cases; this does not establish rejection after time elapses. SDK, MFA, Rules, OOB, tenant behavior, public npm artifacts and complete Auth compatibility are outside this approval.",
        "",
        "[Approval record](../../spec/compatibility/evidence/auth-basic-v2/approval.json) · [Redacted receipt](../../spec/compatibility/evidence/auth-basic-v2/receipt.json) · [Source and case mapping](../../spec/compatibility/evidence/auth-basic-v2/source-review.json). Token values and passwords are not published, so third parties cannot independently replay token checks from these records.",
        "",
        "The [original candidate page](auth-basic-v2.md) and its source-review status are immutable acquisition-time history. This separate approval supersedes their pending-approval status only for the subject and twelve cases above. Original nine-case observations and aggregation approvals remain unchanged; broad feature labels are not promoted.",
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
    print("Auth revision 2 approval checked; subject " + SUBJECT)
