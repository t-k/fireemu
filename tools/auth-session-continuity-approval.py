"""Record one human approval without changing its immutable observation subject."""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "continuity_frozen_publisher", ROOT / "tools/publish-auth-session-continuity.py"
)
assert spec and spec.loader
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)

APPROVAL = ROOT / "spec/compatibility/evidence/auth-session-continuity/approval.json"
PAGE = ROOT / "docs/compatibility/auth-session-continuity-approval.md"
SUBJECT = "8d8214f936b5061bf584e164f55a4a41c8a0a346354b0cb955c04973e29ee0b2"
SCOPE = "The 34 auth-session-continuity revision 1 observations, limited to the recorded artifact, configuration and corpus; no-password-change end-user REST continuity, no tenant, local strict profile and recorded production authentication/password-policy settings. Approved as redacted observations of successful use of fixed A/B tokens and reference-refresh credentials at target offsets 0/10/30 seconds, successful lookup with refresh-issued ID tokens, fixed invalid-input rejection and recorded deletion/process termination checks."


def render(approval, receipt):
    expected = {
        "schemaVersion": 1,
        "subjectSha256": SUBJECT,
        "sourceCommit": "8c0513c5d7eb1a601f759ea0d3b8d5d243beb05b",
        "scope": SCOPE,
        "cases": list(publisher.CASES),
        "reviewer": "github:t-k (id:426779)",
        "reviewedAt": "2026-09-10",
        "decision": "approve",
    }
    if (
        publisher.digest(approval) != publisher.digest(expected)
        or publisher.digest(receipt) != SUBJECT
    ):
        raise ValueError(
            "Approval does not match the recorded human decision and subject"
        )
    publisher.validate(receipt)
    for local, production in zip(
        receipt["local"]["cases"], receipt["production"]["cases"], strict=True
    ):
        if (
            publisher.comparison(
                local, production, publisher.round_controls(receipt, local["id"])
            )
            != "Same observed result"
        ):
            raise ValueError(
                "Approval requires all 34 scoped comparisons to match with valid controls"
            )
    return "\n".join(
        [
            "# Auth session continuity: scoped human approval",
            "",
            "34 observations verified and approved as redacted REST observations matching the published comparison conditions. This is not a guarantee of permanent validity or complete Auth compatibility.",
            "",
            SCOPE,
            "",
            f"Subject: `{SUBJECT}`. Recomputed from the complete receipt during offline validation; this approval cannot transfer to a changed subject.",
            "",
            f"Reviewed commit: `{approval['sourceCommit']}`. Reviewer: `{approval['reviewer']}`. Approval date: {approval['reviewedAt']}.",
            "",
            "This records the user's explicit approval, not a cryptographic signature or an independent reviewer authentication mechanism.",
            "",
            "| Approved observation | Local / production |",
            "|---|---|",
            *[
                f"| {case} | Matched under recorded controls |"
                for case in approval["cases"]
            ],
            "",
            "Fixed A/B credentials and reference-refresh credentials succeeded at the recorded observation times; refresh-issued ID tokens also succeeded in lookup. Original credentials were not replaced between observations. Final signin used the original password. Fixed invalid inputs were rejected with INVALID_REFRESH_TOKEN. Recorded dedicated-account deletion, UID/email absence and owned-process exit/listener checks are included.",
            "",
            "The 0-second target begins after the reference refresh and its issued-ID lookup complete. The reference refresh uses A's original refresh token and does not establish a third independent session; returned refresh bytes may be unchanged. The password-change and no-change experiments used separate accounts and runs, not simultaneous randomized causal trials. Permanent validity, actual elapsed expiry, whole token lineage, SDK/checkRevoked, Rules, strict causality or exact revocation propagation timing remain outside this approval. Normal cleanup is not fault-injected recovery; decoded JWT metadata is not independent signature verification.",
            "",
            "[Approval record](../../spec/compatibility/evidence/auth-session-continuity/approval.json) · [Redacted receipt](../../spec/compatibility/evidence/auth-session-continuity/receipt.json) · [Source and case mapping](../../spec/compatibility/evidence/auth-session-continuity/source-review.json). Tokens, passwords and account identifiers are not published; third parties cannot reconstruct raw token checks from these projections.",
            "",
            "The [original candidate page](auth-session-continuity.md) remains immutable acquisition-time history. This separate approval supersedes its pending status only for this subject and these 34 observations. All previous observations and approvals remain unchanged; broad feature labels are not promoted.",
            "",
            "[Pinned historical integrity checks](../../tools/compat-history/README.md) verify preservation of older evidence at its original source anchor. Their 304 offline tests are not a rerun of those behaviors on the latest runtime. Current-runtime regression tests and this artifact-bound observation remain separate evidence.",
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
            raise ValueError("Generated session continuity approval page is stale")
    else:
        PAGE.write_text(page)
    print("Auth session continuity approval checked; subject " + SUBJECT)
