"""Record the scoped human approval of the auth-mfa-start-disabled local comparison."""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "mfa_start_disabled_comparison_publisher",
    ROOT / "tools/publish-auth-mfa-start-disabled-comparison.py",
)
assert spec and spec.loader
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
APPROVAL = (
    ROOT
    / "spec/compatibility/evidence/auth-mfa-start-disabled/comparison-approval.json"
)
PAGE = ROOT / "docs/compatibility/auth-mfa-start-disabled-comparison-approval.md"
SUBJECT = "07636ce70c9c46289b4e49d64b4f09fcae997901e1bcc89771e4ead3e7968353"
SOURCE_COMMIT = "aef95ad3e6f623d6ce8263f52ce20791b67afe68"
SCOPE = "Row-by-row comparison of the approved production record of auth-mfa-start-disabled with one run of the same corpus on an owned local fireemu artifact built after mfa_sign_in_start stopped refusing a disabled account (strict profile, artifact, runtime inputs and recorder files all bound to one commit). All six semantic projections agree, including mfaSignIn:start accepted on the disabled account and refused at finalize. Approved as a comparison of these cases on that artifact, profile and recorder; the pre-fix mismatch comparison stays in history. Not a production run and not a claim beyond these six cases."


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
    rows = {r["id"]: r for r in receipt["comparison"]}
    return "\n".join(
        [
            "# mfaSignIn:start on a disabled account, local comparison: scoped human approval",
            "",
            "Verified and approved within this limited scope. This is not a new production run and not a claim of complete Auth compatibility.",
            "",
            SCOPE,
            "",
            f"Subject: `{SUBJECT}`. Recomputed from the complete record; this approval cannot transfer to a changed subject.",
            "",
            f"Reviewed commit: `{approval['sourceCommit']}`. Reviewer: `{approval['reviewer']}`. Approval date: {approval['reviewedAt']}.",
            "",
            "This records the user's explicit decision, not a cryptographic signature or independent identity authentication.",
            "",
            "| Compared case | Same semantic projection |",
            "| --- | --- |",
            *[
                f"| {case} | {rows[case]['sameSemanticProjection']} |"
                for case in approval["cases"]
            ],
            "",
            "All six rows agree on the corrected artifact: mfaSignIn:start on a disabled account is accepted and refused at finalize, and the held pending survives re-enablement, matching the approved production record. Approved as a comparison of these cases on that artifact, profile and recorder.",
            "",
            "[Approval record](../../spec/compatibility/evidence/auth-mfa-start-disabled/comparison-approval.json) · [Comparison record](../../spec/compatibility/evidence/auth-mfa-start-disabled/local-comparison.json) · [Comparison page](auth-mfa-start-disabled-comparison.md).",
            "",
            "The comparison page remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these cases. The private runs, the pre-fix mismatch comparison in history, the source mapping and every earlier approval remain unchanged.",
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
            raise ValueError("Generated comparison approval page is stale")
    else:
        PAGE.write_text(page)
    print("auth-mfa-start-disabled-comparison approval checked; subject " + SUBJECT)
