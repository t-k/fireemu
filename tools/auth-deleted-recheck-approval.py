"""Record the scoped human approval without altering either observation."""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "deleted_recheck_publisher", ROOT / "tools/publish-auth-deleted-recheck.py"
)
assert spec and spec.loader
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
APPROVAL = ROOT / "spec/compatibility/evidence/auth-deleted-recheck/approval.json"
PAGE = ROOT / "docs/compatibility/auth-deleted-recheck-approval.md"
SUBJECT = "538747b5e8e9fc3be27952255019fe1a147b766d12c919e8b8c1aef865744174"
SCOPE = "Twelve observations rechecked on the recorded corrected local artifact against unchanged saved production observations. No tenant, local strict profile and recorded production authentication/password-policy settings. Target A is deleted using its own fixed ID token; independent B is the unaffected successful control. Each phase follows the recorded order: password signin, fixed original ID-token lookup, then fixed original refresh-token exchange; successful issued tokens are used for lookup. Approval includes selected state checks, deletion and UID/email absence, remaining owned-account cleanup and owned process termination. Only elapsedMs is excluded from semantic comparison: deleted-A signin returns INVALID_LOGIN_CREDENTIALS, deleted-A ID lookup and refresh return USER_NOT_FOUND, and the remaining nine succeed. This is not a new production run. Approval explicitly excludes identifier-based accounts:lookup authorization; its authentication/authorization bypass is a separate required fix. No claim covers all credential series, ID-token UID reuse, SDK/checkRevoked, Rules, actual expiry, propagation time or fault recovery."


def render(approval, receipt):
    expected = {
        "schemaVersion": 1,
        "subjectSha256": SUBJECT,
        "sourceCommit": "7e9b327acbede270687cbe76164bef098d32b43b",
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
            "# Deleted-account credentials recheck: scoped human approval",
            "",
            "12 observations verified and approved within this limited scope as a recheck of the corrected local artifact against saved production observations. This is not a new production run or a claim of complete Auth compatibility.",
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
            "The runs use separate dedicated accounts and secret credentials. Token values are not public, so independent signature verification is not established by these redacted checks. The approval does not assert that identifier-based lookup is authorized correctly; that boundary requires a separate runtime correction.",
            "",
            "[Approval record](../../spec/compatibility/evidence/auth-deleted-recheck/approval.json) · [Recheck receipt](../../spec/compatibility/evidence/auth-deleted-recheck/receipt.json) · [Original mismatch](auth-deleted.md).",
            "",
            "The [recheck candidate page](auth-deleted-recheck.md) remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these twelve observations. The original mismatch, original production observation, source mapping and earlier approvals remain unchanged. Historical validation is not a rerun of earlier behaviors on the latest runtime.",
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
            raise ValueError("Generated deleted-account approval page is stale")
    else:
        PAGE.write_text(page)
    print("Deleted-account recheck approval checked; subject " + SUBJECT)
