"""Record the scoped human approval of the refusal-precedence observation without altering it."""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "refusal_precedence_publisher", ROOT / "tools/publish-auth-refusal-precedence.py"
)
assert spec and spec.loader
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
APPROVAL = ROOT / "spec/compatibility/evidence/auth-refusal-precedence/approval.json"
PAGE = ROOT / "docs/compatibility/auth-refusal-precedence-approval.md"
SUBJECT = "6c76f862a7b7a2d9ad557ae43d03d3787221089a76e999ae03478e20069fe3c4"
SOURCE_COMMIT = "ae4ec3cdca687e1bb780916957005e6bcb67778d"
SCOPE = "Nine production-only observations projected without secrets from the saved 2026-09-12 run of auth-refusal-precedence revision 1, recorded from a committed checkout with the recorder at 7d6d6431. The verification code is checked before the account state (a disabled account's held SMS session is refused INVALID_CODE with a wrong code and USER_DISABLED with the correct code); the same held pending credentials and sessions complete after re-enablement, so neither refusal consumes them; a client accounts:update carrying a tampered ID token and an administrator-only field is refused INVALID_ID_TOKEN with nothing applied on readback. Fresh completions for A and B bound the run, the configuration was restored with a matching whole-configuration digest, and both accounts were deleted with UID/email absence. The approval does not extend to a production/local comparison of this corpus, to INVALID_ID_TOKEN always winning for any invalid-token condition, to INVALID_CODE always winning for any MFA refusal, to a valid active token with an administrator-only field, to mfaSignIn:start on a disabled account, to an expired pending credential, to TOTP, tenants, SDK or Rules."


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
    rows = {row["id"]: row for row in receipt["production"]["cases"]}
    return "\n".join(
        [
            "# Precedence of overlapping refusals: scoped human approval",
            "",
            "9 production-only observations verified and approved within this limited scope. This is not a new production run, not a production/local comparison, and not a claim of complete Auth compatibility.",
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
            "The diagnostic rows are approved as the observed outcome under the recorded conditions, not as a general precedence rule. The finalize order (code before account state) and the survival of the held credentials across disable and re-enablement match fireemu. The tampered-token row diverges: production verifies the ID token before judging the administrator-only field, while fireemu rejects the field first; the fireemu correction and its local comparison are separate steps. The approval does not establish INVALID_ID_TOKEN for any other invalid-token condition, nor the exact error for a valid token with an administrator-only field.",
            "",
            "[Approval record](../../spec/compatibility/evidence/auth-refusal-precedence/approval.json) · [Receipt](../../spec/compatibility/evidence/auth-refusal-precedence/receipt.json) · [Candidate page](auth-refusal-precedence.md).",
            "",
            "The candidate page remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these nine observations. The private run, the discarded run 1, the source mapping and every earlier approval remain unchanged.",
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
            raise ValueError("Generated refusal-precedence approval page is stale")
    else:
        PAGE.write_text(page)
    print("Refusal-precedence approval checked; subject " + SUBJECT)
