"""Record the scoped human approval without altering either observation."""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "unicode_recheck_publisher",
    ROOT / "tools/publish-auth-password-unicode-boundary.py",
)
assert spec and spec.loader
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
APPROVAL = (
    ROOT / "spec/compatibility/evidence/auth-password-unicode-boundary/approval.json"
)
PAGE = ROOT / "docs/compatibility/auth-password-unicode-boundary-approval.md"
SUBJECT = "3b300cebcbddac2db8528f4c9f9ca29b1b767932ce47aede41ee4e6e6946121c"
SCOPE = "Three auth-password-unicode-boundary revision 1 input patterns, limited to the recorded artifact, configuration and generated patterns. End-user token REST routes, no tenant, local strict profile and recorded production minimum 6 / maximum 4096 password policy. Approval covers 4095/4096 UTF-16-unit acceptance, 4097-unit refusal and error, branch-specific credential use, selected account-state checks and recorded account deletion/process termination. It does not cover all Unicode strings, normalization, minimum-length counting, other API routes, SDK, Rules, elapsed expiry or fault recovery."


def render(approval, receipt):
    expected = {
        "schemaVersion": 1,
        "subjectSha256": SUBJECT,
        "sourceCommit": "e464affdd06065007cedc1b71a031d9453ff31df",
        "scope": SCOPE,
        "cases": list(publisher.CASES),
        "reviewer": "github:t-k (id:426779)",
        "reviewedAt": "2026-09-11",
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
    if receipt["local"]["cases"] != receipt["production"]["cases"] or [
        row["outcome"] for row in receipt["local"]["cases"]
    ] != ["accepted", "accepted", "refused"]:
        raise ValueError(
            "Approval requires identical cases and accepted/accepted/refused outcomes"
        )
    if (
        receipt["production"]["cases"][2]["observedError"]
        != "PASSWORD_DOES_NOT_MEET_REQUIREMENTS"
    ):
        raise ValueError("Approval requires the recorded exact refusal error")
    return "\n".join(
        [
            "# Supplementary-character password boundary: scoped human approval",
            "",
            "3 input patterns verified and approved: 4095/4096 accepted and 4097 refused under the recorded controls. This is not a claim of complete Unicode/Auth compatibility.",
            "",
            SCOPE,
            "",
            f"Subject: `{SUBJECT}`. Recomputed from the complete receipt; this approval cannot transfer to a changed subject.",
            "",
            f"Reviewed commit: `{approval['sourceCommit']}`. Reviewer: `{approval['reviewer']}`. Approval date: {approval['reviewedAt']}.",
            "",
            "This records the user's explicit decision, not a cryptographic signature or independent identity authentication.",
            "",
            "| Approved input pattern | Local / production |",
            "| --- | --- |",
            *[
                f"| {case} | Identical public results under recorded controls |"
                for case in approval["cases"]
            ],
            "",
            "The three patterns use separately generated private prefixes, not identical secret passwords across runs. Normalization, truncation of alternative inputs and all Unicode combinations remain separate verification targets. The positive controls use separate accounts; a successful update after refusal on the same account is not claimed. Token values are not public, so independent signature verification is not established by these redacted checks.",
            "",
            "[Approval record](../../spec/compatibility/evidence/auth-password-unicode-boundary/approval.json) · [Observation receipt](../../spec/compatibility/evidence/auth-password-unicode-boundary/receipt.json) · [Original mismatch](auth-password-unicode.md).",
            "",
            "The [original candidate page](auth-password-unicode-boundary.md) remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these three patterns. The original mismatch, earlier production observations, source mapping and earlier approvals remain unchanged. Historical validation is not a rerun of earlier behaviors on the latest runtime.",
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
            raise ValueError("Generated Unicode approval page is stale")
    else:
        PAGE.write_text(page)
    print("Supplementary boundary approval checked; subject " + SUBJECT)
