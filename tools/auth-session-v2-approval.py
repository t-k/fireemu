"""Record one human approval without changing its immutable observation subject."""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "session_v2_frozen_publisher", ROOT / "tools/publish-auth-session-v2.py"
)
assert spec and spec.loader
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)

APPROVAL = ROOT / "spec/compatibility/evidence/auth-session-v2/approval.json"
PAGE = ROOT / "docs/compatibility/auth-session-v2-approval.md"
SUBJECT = "2650710c03f4ea3fce3e066ef14be16be801b63af14916666b7d7a5bfb24e4f1"
SCOPE = "The 34 auth-session-v2 revision 2 observations, limited to the recorded artifact, configuration and corpus; end-user REST routes, no tenant, local strict profile and recorded production authentication/password-policy settings. Approved as redacted observations matching the published comparison conditions: fixed pre-change A/B ID and refresh tokens, changed-response token controls, finite target offsets 0/10/30 seconds, and two fixed invalid-refresh input controls."


def render(approval, receipt):
    expected = {
        "schemaVersion": 1,
        "subjectSha256": SUBJECT,
        "sourceCommit": "e7360c5be399a4657dc33c1cdb7b49d47857347c",
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
            "# Auth session token revision 2: scoped human approval",
            "",
            "34 observations verified and approved as redacted REST observations matching the published comparison conditions. This is not a guarantee of universal immediate revocation or complete Auth compatibility.",
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
            "The original A/B credentials were usable before the password change and remained fixed during sampling. Old-ID accounts:lookup and old-refresh exchange are distinct routes. Changed-response credentials and final new-password signin/lookup are positive controls; successful refresh is distinguished from successful use of its issued ID token. The two deliberately invalid inputs retain INVALID_REFRESH_TOKEN rather than the known-revoked TOKEN_EXPIRED category. Approval also includes the recorded dedicated-account deletion/UID-and-email absence and owned-process exit/listener checks.",
            "",
            "The 0-second target begins after the password-change response, not at the server's internal mutation instant. Exact propagation latency, uniform immediate revocation across all routes, same-second issuance/change, whole rotated-session lineage, no-change longitudinal controls, Admin SDK verifyIdToken/checkRevoked, Rules, actual elapsed expiry, MFA, public npm artifacts and SDK behavior remain outside this approval. Successful normal cleanup does not prove communication-loss or forced-termination recovery. Decoded JWT timing metadata is not independently verified token-signature evidence.",
            "",
            "[Approval record](../../spec/compatibility/evidence/auth-session-v2/approval.json) · [Redacted receipt](../../spec/compatibility/evidence/auth-session-v2/receipt.json) · [Source and case mapping](../../spec/compatibility/evidence/auth-session-v2/source-review.json). Tokens, passwords and account identifiers are not published; third parties cannot reconstruct raw token checks from these projections.",
            "",
            "The [original candidate page](auth-session-v2.md) remains immutable acquisition-time history. This separate approval supersedes its pending status only for the subject and 34 observations above. Revision 1's six differences and all earlier observations/approvals remain unchanged; broad feature labels are not promoted.",
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
            raise ValueError("Generated session revision 2 approval page is stale")
    else:
        PAGE.write_text(page)
    print("Auth session revision 2 approval checked; subject " + SUBJECT)
