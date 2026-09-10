"""Record the scoped human approval without altering either observation."""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "disabled_recheck_publisher", ROOT / "tools/publish-auth-disabled-recheck.py"
)
assert spec and spec.loader
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
APPROVAL = ROOT / "spec/compatibility/evidence/auth-disabled-recheck/approval.json"
PAGE = ROOT / "docs/compatibility/auth-disabled-recheck-approval.md"
SUBJECT = "b9592f50c07bcac36b387dfa3baa4bbfe0bf328a6499c4e1855e541400b63e81"
SCOPE = "Eighteen observations rechecked on the recorded corrected local artifact against unchanged saved production observations. No tenant, local strict profile and recorded production authentication/password-policy settings. Admin disables and re-enables owned target A; independent B is the unaffected control. Each phase follows the recorded order: password signin, fixed original ID-token lookup, then fixed original refresh-token exchange; successful issued tokens are used for lookup. Approval includes selected state checks, Admin account cleanup and UID/email absence, and owned process termination. Only elapsedMs is excluded from semantic comparison: the three disabled-A routes return USER_DISABLED and the remaining fifteen succeed. This is not a new production run. Approval does not cover all operation orders after re-enable, long-term validity, SDK/checkRevoked, Rules, actual expiry, propagation time or fault recovery."


def render(approval, receipt):
    expected = {
        "schemaVersion": 1,
        "subjectSha256": SUBJECT,
        "sourceCommit": "fe7d57f0c1c7f9ac14639c472368dc8f98dda70b",
        "scope": SCOPE,
        "cases": list(publisher.old.CASES),
        "reviewer": "github:t-k (id:426779)",
        "reviewedAt": "2026-09-11",
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
            "# Account disable / re-enable recheck: scoped human approval",
            "",
            "18 observations verified and approved within this limited scope as a recheck of the corrected local artifact against saved production observations. This is not a new production run or a claim of complete Auth compatibility.",
            "",
            SCOPE,
            "",
            f"Subject: `{SUBJECT}`. Recomputed from the complete recheck receipt; this approval cannot transfer to a changed subject.",
            "",
            f"Reviewed commit: `{approval['sourceCommit']}`. Reviewer: `{approval['reviewer']}`. Approval date: {approval['reviewedAt']}.",
            "",
            "This records the user's explicit decision, not a cryptographic signature or independent identity authentication.",
            "",
            "| Approved observation | Corrected local / saved production |",
            "| --- | --- |",
            *[
                f"| {case} | Identical semantic projection; elapsedMs excluded |"
                for case in approval["cases"]
            ],
            "",
            "The runs use separate dedicated accounts and secret credentials. The preserved operation order does not establish that old credentials work after re-enable without prior password signin or under every ordering. Token values are not public, so independent signature verification is not established by these redacted checks.",
            "",
            "[Approval record](../../spec/compatibility/evidence/auth-disabled-recheck/approval.json) · [Recheck receipt](../../spec/compatibility/evidence/auth-disabled-recheck/receipt.json) · [Original mismatch](auth-disabled.md).",
            "",
            "The [recheck candidate page](auth-disabled-recheck.md) remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these eighteen observations. The original mismatch, original production observation, source mapping and earlier approvals remain unchanged. Historical validation is not a rerun of earlier behaviors on the latest runtime.",
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
            raise ValueError("Generated disable/re-enable approval page is stale")
    else:
        PAGE.write_text(page)
    print("Disable/re-enable recheck approval checked; subject " + SUBJECT)
