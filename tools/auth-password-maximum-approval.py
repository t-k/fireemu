"""Record one human approval without changing its immutable observation subject."""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "maximum_frozen_publisher", ROOT / "tools/publish-auth-password-maximum.py"
)
assert spec and spec.loader
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)

APPROVAL = ROOT / "spec/compatibility/evidence/auth-password-maximum/approval.json"
PAGE = ROOT / "docs/compatibility/auth-password-maximum-approval.md"
SUBJECT = "ed7acb486dc950697ef562d645a8091396669812f2d5556001c86121ba87bd6f"
SCOPE = "The 21 auth-password-maximum revision 1 cases, limited to the recorded artifact, configuration and corpus; end-user token REST routes, no tenant, local strict profile and recorded production minimum 6 / maximum 4096 password policy. Approved as redacted observations of a generated 4096-character password update and signin, last-character and prefix signin rejection, 4097-character update refusal, subsequent fixed-credential use, selected account-field preservation and recorded deletion/process termination. This does not approve administrator-only field authorization."


def render(approval, receipt):
    expected = {
        "schemaVersion": 1,
        "subjectSha256": SUBJECT,
        "sourceCommit": "1ac61055283018857864efc877d9d7021e255832",
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
            "Approval requires all 21 cases to match the validated conditions"
        )
    if receipt["local"]["cases"] != receipt["production"]["cases"]:
        raise ValueError(
            "Approval requires identical public case results, including exact errors"
        )
    return "\n".join(
        [
            "# Auth password maximum: scoped human approval",
            "",
            "21 observations verified and approved as redacted REST observations matching the published comparison conditions. This is not a guarantee of all password-policy boundaries or complete Auth compatibility.",
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
            "The recorded inputShape binds the generated 4096-character ASCII password, its last-character variant, 4095-character prefix and 4097-character extension. The fixed ID and update-issued refresh credentials remain usable after oversized-update refusal. Public case results, including exact error codes, must agree between targets.",
            "",
            "This approval covers representative ASCII inputs, not all strings, Unicode counting, custom policies, expiry, SDK, Rules or recovery under injected failures. Administrator-only field authorization is explicitly excluded. The separately reported authorization defect does not invalidate these observations or become approved by this record.",
            "",
            "[Approval record](../../spec/compatibility/evidence/auth-password-maximum/approval.json) · [Redacted receipt](../../spec/compatibility/evidence/auth-password-maximum/receipt.json) · [Source and case mapping](../../spec/compatibility/evidence/auth-password-maximum/source-review.json). Tokens, passwords and account identifiers are not published; third parties cannot reconstruct raw token checks from these projections.",
            "",
            "The [original candidate page](auth-password-maximum.md) remains immutable acquisition-time history. This separate approval supersedes its pending status only for this subject and these 21 observations. All previous observations and approvals remain unchanged; broad feature labels are not promoted.",
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
            raise ValueError("Generated password maximum approval page is stale")
    else:
        PAGE.write_text(page)
    print("Auth password maximum approval checked; subject " + SUBJECT)
