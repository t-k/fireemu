"""Record one human approval without changing its immutable observation subject."""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "minimum_frozen_publisher", ROOT / "tools/publish-auth-password-minimum.py"
)
assert spec and spec.loader
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)

APPROVAL = ROOT / "spec/compatibility/evidence/auth-password-minimum/approval.json"
PAGE = ROOT / "docs/compatibility/auth-password-minimum-approval.md"
SUBJECT = "b7ad987bdd466784b379a8281a3137e1d1dc259513df426cc9774a68efad7bb4"
SCOPE = "The 12 auth-password-minimum revision 1 cases, limited to the recorded artifact, configuration and corpus; fresh end-user ID token REST routes, no tenant, local strict profile and recorded production authentication settings and schema 1 ENFORCE password policy with minimum 6, maximum 4096 and no additional character requirements. Approved as redacted observations of a generated six-character URL-safe ASCII password change, old-password rejection, new-password same-account signin, actual use of update-issued ID and refresh tokens, selected account-field preservation and recorded deletion/process termination."


def render(approval, receipt):
    expected = {
        "schemaVersion": 1,
        "subjectSha256": SUBJECT,
        "sourceCommit": "db39f7133efbe009474308e9ce52df56a989a136",
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
    if not all(
        row["passed"] is True
        for target in ("local", "production")
        for row in receipt[target]["cases"]
    ):
        raise ValueError(
            "Approval requires all 12 cases to match the validated conditions"
        )
    return "\n".join(
        [
            "# Auth password minimum: scoped human approval",
            "",
            "12 observations verified and approved as redacted REST observations matching the published comparison conditions. This is not a guarantee of all password-policy boundaries or complete Auth compatibility.",
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
            "The recorded inputShape confirms original length 47, replacement length 6, URL-safe ASCII and distinct credentials. The baseline password works before the update and is rejected afterward; the generated new password signs in as the same account. Both the update-issued ID token and the same update response's refresh token are used, with lookup after refresh. Selected field checks and recorded dedicated-account deletion, UID/email absence and owned-process exit/listener checks are included.",
            "",
            "This approval covers the generated representative input, not every six-character combination. Unicode, other lengths and policy boundaries, empty/null, custom policy combinations, actual expiry, revocation timing, SDK, Rules and fault-injected recovery remain separate verification targets. Selected account fields do not establish invariance of all internal state. Redacted observations are recorder testimony, not independent token-signature verification or a password-security recommendation.",
            "",
            "[Approval record](../../spec/compatibility/evidence/auth-password-minimum/approval.json) · [Redacted receipt](../../spec/compatibility/evidence/auth-password-minimum/receipt.json) · [Source and case mapping](../../spec/compatibility/evidence/auth-password-minimum/source-review.json). Tokens, passwords and account identifiers are not published; third parties cannot reconstruct raw token checks from these projections.",
            "",
            "The [original candidate page](auth-password-minimum.md) remains immutable acquisition-time history. This separate approval supersedes its pending status only for this subject and these 12 observations. All previous observations and approvals remain unchanged; broad feature labels are not promoted.",
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
            raise ValueError("Generated password minimum approval page is stale")
    else:
        PAGE.write_text(page)
    print("Auth password minimum approval checked; subject " + SUBJECT)
