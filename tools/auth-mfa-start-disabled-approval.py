"""Record the scoped human approval of the auth-mfa-start-disabled production receipt."""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "mfa_start_disabled_publisher", ROOT / "tools/publish-auth-mfa-start-disabled.py"
)
assert spec and spec.loader
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
APPROVAL = ROOT / "spec/compatibility/evidence/auth-mfa-start-disabled/approval.json"
PAGE = ROOT / "docs/compatibility/auth-mfa-start-disabled-approval.md"
SUBJECT = "e0fdb84012734f99533f84e7fab173d26e1f0f0a9112f4703d990f1a968df442"
SOURCE_COMMIT = "aef95ad3e6f623d6ce8263f52ce20791b67afe68"
SCOPE = "Six production-only observations projected without secrets from the saved 2026-09-12 run of auth-mfa-start-disabled, recorded from a committed checkout. mfaSignIn:start on an account disabled after its pending credential is accepted and returns a session; its finalize is refused USER_DISABLED; after re-enablement the same pending credential starts and finalizes; a baseline and final fresh finalize are controls; the configuration was restored with a matching whole-configuration digest and the account deleted with UID/email absence. The approval does not extend to a production/local comparison of this corpus, to TOTP, tenants, blocking functions, SDK, Rules or the credential's expiry."


def render(approval, receipt):
    expected = {
        "schemaVersion": 1,
        "subjectSha256": SUBJECT,
        "sourceCommit": SOURCE_COMMIT,
        "scope": SCOPE,
        "cases": list(publisher.CASES),
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
            "# mfaSignIn:start on a disabled account: scoped human approval",
            "",
            "6 production-only observations verified and approved within this limited scope. This is not a new production run, not a production/local comparison, and not a claim of complete Auth compatibility.",
            "",
            SCOPE,
            "",
            f"Subject: `{SUBJECT}`. Recomputed from the complete receipt; this approval cannot transfer to a changed subject.",
            "",
            f"Reviewed commit: `{approval['sourceCommit']}`. Reviewer: `{approval['reviewer']}`. Approval date: {approval['reviewedAt']}.",
            "",
            "This records the user's explicit decision, not a cryptographic signature or independent identity authentication. The source mapping's execution approval stays not-granted.",
            "",
            "| Approved observation | Basis | Recorded outcome |",
            "| --- | --- | --- |",
            *[
                f"| {case} | {'diagnostic' if case in publisher.DIAGNOSTIC else 'control'} | {rows[case]['outcome']} / {rows[case]['observedError'] or 'none'} |"
                for case in approval["cases"]
            ],
            "",
            "Approved as the observed outcome under the recorded conditions: mfaSignIn:start on a disabled account is accepted and the disabled state is enforced at finalize (USER_DISABLED), and the held pending credential survives re-enablement. fireemu was corrected to match (GAP-AUTH-005); its local comparison is approved separately.",
            "",
            "[Approval record](../../spec/compatibility/evidence/auth-mfa-start-disabled/approval.json) · [Receipt](../../spec/compatibility/evidence/auth-mfa-start-disabled/receipt.json) · [Candidate page](auth-mfa-start-disabled.md).",
            "",
            "The candidate page remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these six observations. The private run, the source mapping and every earlier approval remain unchanged.",
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
    print("auth-mfa-start-disabled approval checked; subject " + SUBJECT)
