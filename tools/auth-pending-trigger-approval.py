"""Record the scoped human approval of one AUTH-U04 trigger production receipt.

Parameterized by --trigger; one approval record and page per trigger. The approval is the
exact human decision recomputed against the complete receipt, never a signature.
"""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "auth_pending_triggers_publisher", ROOT / "tools/publish-auth-pending-triggers.py"
)
assert spec and spec.loader
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
TRIGGERS = publisher.TRIGGERS
REVIEWER = "github:t-k (id:426779)"
REVIEWED_AT = "2026-09-12"


def approval_path(trigger):
    return (
        ROOT
        / f"spec/compatibility/evidence/auth-pending-trigger-{trigger}/approval.json"
    )


def page_path(trigger):
    return ROOT / f"docs/compatibility/auth-pending-trigger-{trigger}-approval.md"


def scope(trigger):
    return f"Seven production-only observations projected without secrets from the saved 2026-09-12 run of the {trigger} trigger (auth-pending-trigger), recorded from a committed checkout. A pending MFA credential and SMS session held from before the transition are presented after it; whether they still start and finalize is the observed outcome, with a baseline and a final fresh completion as controls, the configuration restored with a matching whole-configuration digest, and the account deleted with UID/email absence. The approval does not extend to a production/local comparison of this corpus, to any other trigger, to a rule about revocation, to tenants, SDK or Rules."


def render(trigger, approval, receipt):
    subject = publisher.digest(receipt)
    expected = {
        "schemaVersion": 1,
        "subjectSha256": subject,
        "sourceCommit": approval["sourceCommit"],
        "scope": scope(trigger),
        "cases": list(publisher.CASES),
        "reviewer": REVIEWER,
        "reviewedAt": REVIEWED_AT,
        "decision": "approve",
    }
    if publisher.digest(approval) != publisher.digest(expected):
        raise ValueError("Approval must match the exact human decision")
    publisher.validate(receipt, trigger)
    rows = {row["id"]: row for row in receipt["production"]["cases"]}
    return "\n".join(
        [
            f"# Held MFA pending credential across {trigger}: scoped human approval",
            "",
            "7 production-only observations verified and approved within this limited scope. This is not a new production run, not a production/local comparison, and not a claim of complete Auth compatibility.",
            "",
            scope(trigger),
            "",
            f"Subject: `{subject}`. Recomputed from the complete receipt; this approval cannot transfer to a changed subject.",
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
            "The held rows are approved as the observed outcome under the recorded conditions and this trigger only, not as a rule about revocation. Token values are not public, so independent signature verification is not established by these redacted checks.",
            "",
            f"[Approval record](../../spec/compatibility/evidence/auth-pending-trigger-{trigger}/approval.json) · [Receipt](../../spec/compatibility/evidence/auth-pending-trigger-{trigger}/receipt.json) · [Candidate page](auth-pending-trigger-{trigger}.md).",
            "",
            "The candidate page remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these seven observations. The private run, the source mapping and every earlier approval remain unchanged.",
            "",
        ]
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trigger", required=True, choices=TRIGGERS)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    trigger = args.trigger
    approval = json.loads(approval_path(trigger).read_bytes())
    receipt = json.loads(publisher.bundle(trigger).read_bytes())
    page = render(trigger, approval, receipt)
    if args.check:
        if page_path(trigger).read_text() != page:
            raise ValueError("Generated approval page is stale")
    else:
        page_path(trigger).write_text(page)
    print(
        f"Auth pending trigger {trigger} approval checked; subject "
        + publisher.digest(receipt)
    )
