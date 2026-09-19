"""Record the scoped human approval of one AUTH-U04 trigger local comparison record."""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "auth_pending_triggers_comparison_publisher",
    ROOT / "tools/publish-auth-pending-triggers-comparison.py",
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
        / f"spec/compatibility/evidence/auth-pending-trigger-{trigger}/comparison-approval.json"
    )


def page_path(trigger):
    return (
        ROOT
        / f"docs/compatibility/auth-pending-trigger-{trigger}-comparison-approval.md"
    )


def scope(trigger):
    return f"Row-by-row comparison of the approved production record of the {trigger} trigger with one run of the same corpus on an owned local fireemu artifact (strict profile, artifact, runtime inputs and recorder files all bound to one commit). All seven semantic projections agree. Approved as a comparison of these cases on that artifact, profile and recorder; not a production run, and not a claim that the local artifact matches on anything outside these seven cases or for any other trigger."


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
    rows = {r["id"]: r for r in receipt["comparison"]}
    return "\n".join(
        [
            f"# Held MFA pending credential across {trigger}, local comparison: scoped human approval",
            "",
            "Verified and approved within this limited scope. This is not a new production run and not a claim of complete Auth compatibility.",
            "",
            scope(trigger),
            "",
            f"Subject: `{subject}`. Recomputed from the complete record; this approval cannot transfer to a changed subject.",
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
            f"[Approval record](../../spec/compatibility/evidence/auth-pending-trigger-{trigger}/comparison-approval.json) · [Comparison record](../../spec/compatibility/evidence/auth-pending-trigger-{trigger}/local-comparison.json) · [Comparison page](auth-pending-trigger-{trigger}-comparison.md).",
            "",
            "The comparison page remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these cases. The private runs, the source mapping and every earlier approval remain unchanged.",
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
    receipt = json.loads(publisher.bundle_path(trigger).read_bytes())
    page = render(trigger, approval, receipt)
    if args.check:
        if page_path(trigger).read_text() != page:
            raise ValueError("Generated comparison approval page is stale")
    else:
        page_path(trigger).write_text(page)
    print(
        f"Auth pending trigger {trigger} comparison approval checked; subject "
        + publisher.digest(receipt)
    )
