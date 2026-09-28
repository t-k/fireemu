"""Record the scoped human approval of the blocking-disable observation without altering it."""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "blocking_disable_publisher", ROOT / "tools/publish-auth-blocking-disable.py"
)
assert spec and spec.loader
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
APPROVAL = ROOT / "spec/compatibility/evidence/auth-blocking-disable/approval.json"
PAGE = ROOT / "docs/compatibility/auth-blocking-disable-approval.md"
SUBJECT = "81e74c75576f91b3cf889cae905e4eb21437a8f6a86846082b160dc1e4e6db0d"
SOURCE_COMMIT = "9cab49c7533bde3f6d420e104f59ec52a551ac54"
SCOPE = "Twelve-case frame (eight executed rows, four conditionally skipped rows) projected without secrets from the saved 2026-09-11 run of auth-blocking-disable revision 1, production only. One recorded response shape of a first-generation beforeSignIn function (disabled: true for accounts carrying a dedicated custom claim), phone MFA with test phone numbers, no tenant, a single run and the recorded operation order. Approved as recorded: USER_DISABLED on C's password sign-in and on A's phone MFA finalize, the immediate Admin readback of the disabled flag (C false, A true), refusal of the second sign-ins under the same registered function, the control B's successful completions before and after, and the recorded function removal, configuration restore with a matching digest and account absence confirmation. The four token lookup and refresh rows were skipped because the first requests were refused; they are not approved as executed or successful. The approval does not extend to an independent check of token absence in a refused response, to non-issuance inside the server, to immediate persistence of the disable on every path, to the cause or timing of the readback difference, to a production/local comparison of this corpus, to created-then-disabled accounts, beforeCreate, other MFA methods, tenants, SDK or Rules."


def render(approval, receipt):
    expected = {
        "schemaVersion": 1,
        "subjectSha256": SUBJECT,
        "sourceCommit": SOURCE_COMMIT,
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
    rows = {row["id"]: row for row in receipt["production"]["cases"]}
    return "\n".join(
        [
            "# Blocking function that disables the account: scoped human approval",
            "",
            "A twelve-case frame, eight executed rows and four conditionally skipped rows, verified and approved within this limited scope. This is not a new production run, not a production/local comparison, and not a claim of complete Auth compatibility.",
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
                f"| {case} | {'diagnostic' if case in publisher.DIAGNOSTIC else 'control'} | {rows[case]['outcome']} / {rows[case]['observedError'] or 'none'}{' (disabledPersisted=' + str(rows[case]['checks'].get('disabledPersisted')) + ')' if 'disabledPersisted' in rows[case]['checks'] else ''} |"
                for case in approval["cases"]
            ],
            "",
            "The hook rows are approved as the observed outcome under the recorded conditions, not as a rule about blocking functions. Refused rows carry the HTTP status and the classified error only. The skipped rows follow from refused first requests and are not approved as executed. The immediate readback differed between the two claimed accounts; nothing about persistence on every path or about propagation follows.",
            "",
            "[Approval record](../../spec/compatibility/evidence/auth-blocking-disable/approval.json) · [Receipt](../../spec/compatibility/evidence/auth-blocking-disable/receipt.json) · [Candidate page](auth-blocking-disable.md).",
            "",
            "The candidate page remains acquisition-time history. This separate approval supersedes its pending status only for this subject and this twelve-case frame. The private run, the earlier unapproved candidates in history, the source mapping and every earlier approval remain unchanged.",
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
            raise ValueError("Generated blocking-disable approval page is stale")
    else:
        PAGE.write_text(page)
    print("Blocking-disable approval checked; subject " + SUBJECT)
