"""Record the scoped human approval without altering either observation."""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "unicode_recheck_publisher", ROOT / "tools/publish-auth-password-unicode-recheck.py"
)
assert spec and spec.loader
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
APPROVAL = (
    ROOT / "spec/compatibility/evidence/auth-password-unicode-recheck/approval.json"
)
PAGE = ROOT / "docs/compatibility/auth-password-unicode-recheck-approval.md"
SUBJECT = "5f13dcc611017940756158cbf225cc2efd85ffeed4d40fca4445039d7088a885"
SCOPE = "Eight recorded input patterns rechecked on the corrected local artifact against unchanged saved production observations. End-user token REST routes, no tenant, local strict profile and the recorded minimum 6 / maximum 4096 password policy. Approval covers acceptance/refusal, branch-specific credential use, selected account-state checks and recorded account deletion/process termination. This is not a new production run; random prefixes and accounts differ between runs. It does not cover all Unicode strings, normalization, length limits on other routes, elapsed expiry, SDK, Rules or fault recovery."


def render(approval, receipt):
    expected = {
        "schemaVersion": 1,
        "subjectSha256": SUBJECT,
        "sourceCommit": "6618d9365402f9d05e6f390ca1ef623052dac4ae",
        "scope": SCOPE,
        "cases": list(publisher.old.CASES),
        "reviewer": "github:t-k (id:426779)",
        "reviewedAt": "2026-09-10",
        "decision": "approve",
    }
    if (
        publisher.old.digest(approval) != publisher.old.digest(expected)
        or publisher.old.digest(receipt) != SUBJECT
    ):
        raise ValueError(
            "Approval must match the exact human decision and complete subject"
        )
    publisher.validate(receipt)
    return "\n".join(
        [
            "# Unicode password recheck: scoped human approval",
            "",
            "8 input patterns verified and approved as a recheck of the corrected local artifact against saved production observations. This is not a new production run or a claim of complete Unicode/Auth compatibility.",
            "",
            SCOPE,
            "",
            f"Subject: `{SUBJECT}`. Recomputed from the complete recheck receipt; this approval cannot transfer to a changed subject.",
            "",
            f"Reviewed commit: `{approval['sourceCommit']}`. Reviewer: `{approval['reviewer']}`. Approval date: {approval['reviewedAt']}.",
            "",
            "This records the user's explicit decision, not a cryptographic signature or independent identity authentication.",
            "",
            "| Approved input pattern | Corrected local / saved production |",
            "| --- | --- |",
            *[
                f"| {case} | Identical public results under recorded controls |"
                for case in approval["cases"]
            ],
            "",
            "The eight patterns use separately generated private prefixes, not identical secret passwords across runs. The exact 4097-unit supplementary-character boundary, normalization, truncation of alternative inputs and all Unicode combinations remain separate verification targets. Token values are not public, so independent signature verification is not established by these redacted checks.",
            "",
            "[Approval record](../../spec/compatibility/evidence/auth-password-unicode-recheck/approval.json) · [Recheck receipt](../../spec/compatibility/evidence/auth-password-unicode-recheck/receipt.json) · [Original mismatch](auth-password-unicode.md).",
            "",
            "The [recheck candidate page](auth-password-unicode-recheck.md) remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these eight patterns. The original mismatch, original production observation, source mapping and earlier approvals remain unchanged. Historical validation is not a rerun of earlier behaviors on the latest runtime.",
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
    print("Unicode recheck approval checked; subject " + SUBJECT)
