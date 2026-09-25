"""Record the scoped human approval of the auth-blocking-readback record without altering it."""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "auth_blocking_readback_publisher", ROOT / "tools/publish-auth-blocking-readback.py"
)
assert spec and spec.loader
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
APPROVAL = ROOT / "spec/compatibility/evidence/auth-blocking-readback/approval.json"
PAGE = ROOT / "docs/compatibility/auth-blocking-readback-approval.md"
SUBJECT = "81dae6d26f525a31e121abb87669e875026696f50ce44a223fc9c396c9806b9b"
SOURCE_COMMIT = "3cadafe7a42effb58b392897298e583a32e51792"
SCOPE = "Eleven executed rows projected without secrets from the saved 2026-09-12 production run of auth-blocking-readback revision 1 with the recorded first-generation disabling function. Approved as recorded: two claimed accounts were refused on sign-in; the disabled flag read back as not disabled before, immediately after, five and about thirty-one seconds after the refusal for one account, and after thirty seconds with no earlier read for the other, while their second sign-ins were refused under the registered function; the control signed in first and last; the function was removed and the trigger registration restored with a digest comparison; the three accounts were deleted with absence confirmation. The measured seconds are recorder-side. Not extended to the same accounts after the function's removal, to propagation timing beyond these points, to other sign-in methods, or to SDK or Rules."
CASES = [
    "control-z-signin",
    "x-readback-before",
    "x-first-signin",
    "x-readback-immediate",
    "x-readback-after-5s",
    "x-readback-after-30s",
    "x-second-signin",
    "y-first-signin",
    "y-readback-after-30s-unread",
    "y-second-signin",
    "control-z-final-signin",
]


def render(approval, receipt):
    expected = {
        "schemaVersion": 1,
        "subjectSha256": SUBJECT,
        "sourceCommit": SOURCE_COMMIT,
        "scope": SCOPE,
        "cases": CASES,
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
            "# Hook-applied disable, readback timing: scoped human approval",
            "",
            "Verified and approved within this limited scope. This is not a new production run and not a claim of complete Auth compatibility.",
            "",
            SCOPE,
            "",
            f"Subject: `{SUBJECT}`. Recomputed from the complete record; this approval cannot transfer to a changed subject.",
            "",
            f"Reviewed commit: `{approval['sourceCommit']}`. Reviewer: `{approval['reviewer']}`. Approval date: {approval['reviewedAt']}.",
            "",
            "This records the user's explicit decision, not a cryptographic signature or independent identity authentication. The source mapping's execution approval stays not-granted: approving a recorded observation does not authorize new production operations.",
            "",
            "| Approved observation | Basis | Recorded outcome |",
            "| --- | --- | --- |",
            *[
                f"| {case} | {'diagnostic' if case in publisher.DIAGNOSTIC else 'control'} | {rows[case]['outcome']} / {rows[case]['observedError'] or 'none'} |"
                for case in approval["cases"]
            ],
            "",
            "[Approval record](../../spec/compatibility/evidence/auth-blocking-readback/approval.json) · [Record](../../spec/compatibility/evidence/auth-blocking-readback/receipt.json) · [Candidate page](auth-blocking-readback.md).",
            "",
            "The candidate page remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these cases. The private run, earlier candidates in history, the source mapping and every earlier approval remain unchanged.",
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
    print("auth-blocking-readback approval checked; subject " + SUBJECT)
