"""Validate and publish the redacted production-only refusal-precedence receipt.

The observation was recorded with the recorder at one commit and is re-evaluated with the
contract at publication time; both are named in the receipt and never conflated. Only
allowlisted fields of the private report are projected.
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/auth-refusal-precedence"))
sys.path.insert(0, str(ROOT / "tools/compat-inventory"))
from precedence_contract import (
    CASES,
    DIAGNOSTIC,
    classified,
    complete,
    require,
    validate_row,
)
from precedence_recorder import digest

BUNDLE = ROOT / "spec/compatibility/evidence/auth-refusal-precedence/receipt.json"
REVIEW = ROOT / "spec/compatibility/evidence/auth-refusal-precedence/source-review.json"
PAGE = ROOT / "docs/compatibility/auth-refusal-precedence.md"
SCOPE = "Nine sequential REST observations in production only: fresh phone MFA completions for A and B; a client accounts:update with A's baseline ID token altered by one signature character, a sentinel custom claim and a sentinel photo URL, sent before any disable and followed by a privileged readback; then, with a pending credential and an SMS session held by each account, both accounts disabled and read back, the held credential and session of A finalized with a fixed wrong code and those of B with the correct code; both accounts re-enabled and read back and the same held credentials and sessions finalized with the correct code; fresh completions for A and B. Phone MFA with test phone numbers, no tenant, no blocking function, one run. The oracle configuration was changed for the run and restored with a digest comparison. Admin is used for owned account setup, the disable and re-enable transitions, readback and cleanup. No human approval, no local artifact comparison, no claim about a valid token with a privileged field, about mfaSignIn:start on a disabled account, about the pending credential's expiry, TOTP, SDK or Rules."
CORPUS = {"slice": "auth-refusal-precedence", "revision": 1, "cases": list(CASES)}
# Fields of the private report that may appear in the receipt, and nothing else.
PROJECTED = (
    "target",
    "recordedAt",
    "probeSourceCommit",
    "committedCheckout",
    "cases",
    "setup",
    "held",
    "transitions",
    "invalidTokenStateUnchanged",
    "cleanup",
    "cleanupAccounts",
    "configRestored",
    "configRestoredReadback",
    "configDigestMatches",
)
CONFIGURATION_KEYS = (
    "sha256",
    "emailEnabled",
    "passwordRequired",
    "improvedEmailPrivacy",
    "blockingTriggersAbsent",
    "adminPasswordPolicyAbsent",
)
RESTORED_KEYS = ("mfa", "phoneNumber", "smsRegionConfig")
RECORDER_FILES = (
    "tools/auth-refusal-precedence/precedence_contract.py",
    "tools/auth-refusal-precedence/precedence_recorder.py",
    "tools/auth-pending-revocation/revocation_recorder.py",
)


def hex_value(value, length=64):
    require(
        isinstance(value, str) and re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value)
    )


def publication_contract_sha():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def working_tree_sha256(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def exact_keys(value, keys):
    """A published object carries exactly the allowlisted keys, never more."""
    require(isinstance(value, dict) and set(value) == set(keys))
    return {key: value[key] for key in keys}


def git_blob_sha256(commit, path):
    blob = subprocess.check_output(
        ["git", "show", f"{commit}:{path}"], cwd=ROOT, stderr=subprocess.DEVNULL
    )
    return hashlib.sha256(blob).hexdigest()


def recorded_with(report, recorder_commit):
    """The recorder that produced the observation: the files it hashed must be exactly
    the files at `recorder_commit`, which may differ from the commit it ran on."""
    hex_value(report["probeSourceCommit"], 40)
    hex_value(recorder_commit, 40)
    inputs = {path: report["probeInputs"][path] for path in RECORDER_FILES}
    for path, value in inputs.items():
        hex_value(value)
        require(git_blob_sha256(recorder_commit, path) == value)
    return {
        "probeSourceCommit": report["probeSourceCommit"],
        "recorderCommit": recorder_commit,
        "recorderInputs": inputs,
    }


def reevaluated_with():
    """The contract applied at publication, which may be stricter than the recorder's."""
    return {
        "commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "contractSha256": working_tree_sha256(RECORDER_FILES[0]),
    }


def project(report, recorder_commit):
    require(
        type(report["schemaVersion"]) is int
        and report["schemaVersion"] == 1
        and report["acceptance"] == "candidate"
        and report["target"] == "production"
        and report["project"] == "fireemu-35fe6"
        and report["projectNumber"] == "592603257417"
        and digest(report["corpus"]) == digest(CORPUS)
        and complete(report)
    )
    out = {key: report[key] for key in PROJECTED}
    # Nested objects are projected too: an unexpected key inside them refuses the input
    # rather than being copied through.
    out["configRestoredReadback"] = exact_keys(
        report["configRestoredReadback"], RESTORED_KEYS
    )
    out["cleanupAccounts"] = exact_keys(report["cleanupAccounts"], ("a", "b"))
    out["configuration"] = exact_keys(report["configReadback"], CONFIGURATION_KEYS)
    out["privateReceiptSha256"] = digest(report)
    out["recordedWith"] = recorded_with(report, recorder_commit)
    out["reevaluatedWith"] = reevaluated_with()
    validate_production(out)
    return out


def validate(value):
    require(
        set(value)
        == {
            "schemaVersion",
            "acceptance",
            "scope",
            "corpus",
            "sourceReviewSha256",
            "publicationContractSha256",
            "production",
        }
    )
    require(
        type(value["schemaVersion"]) is int
        and value["schemaVersion"] == 1
        and value["acceptance"] == "candidate"
        and value["scope"] == SCOPE
        and digest(value["corpus"]) == digest(CORPUS)
    )
    review = json.loads(REVIEW.read_bytes())
    require(value["publicationContractSha256"] == publication_contract_sha())
    require(value["sourceReviewSha256"] == digest(review))
    require([row["case"] for row in review["obligations"]] == list(CASES))
    require(review["executionApproval"] == "not-granted")
    validate_production(value["production"])


def validate_production(report):
    require(
        set(report)
        == set(PROJECTED)
        | {"configuration", "privateReceiptSha256", "recordedWith", "reevaluatedWith"}
    )
    require(
        report["target"] == "production"
        and isinstance(report["recordedAt"], str)
        and re.fullmatch(r"[0-9T:.+\-]+", report["recordedAt"])
    )
    require(complete({**report, "status": "observed"}))
    hex_value(report["privateReceiptSha256"])
    for row, name in zip(report["cases"], CASES, strict=True):
        validate_row(row, name)
        require(classified(row))
    require(report["committedCheckout"] is True)
    config = exact_keys(report["configuration"], CONFIGURATION_KEYS)
    require(all(config[key] is True for key in config if key != "sha256"))
    hex_value(config["sha256"])
    restored = exact_keys(report["configRestoredReadback"], RESTORED_KEYS)
    require(
        restored["mfa"] == {"state": "DISABLED"}
        and restored["phoneNumber"] == {}
        and restored["smsRegionConfig"] == {"allowlistOnly": {}}
    )
    require(
        exact_keys(report["cleanupAccounts"], ("a", "b"))
        == {"a": "absent", "b": "absent"}
    )
    recorded = exact_keys(
        report["recordedWith"],
        ("probeSourceCommit", "recorderCommit", "recorderInputs"),
    )
    require(recorded["probeSourceCommit"] == report["probeSourceCommit"])
    recorded_with(
        {
            "probeSourceCommit": recorded["probeSourceCommit"],
            "probeInputs": exact_keys(recorded["recorderInputs"], RECORDER_FILES),
        },
        recorded["recorderCommit"],
    )
    # The re-evaluation names a commit and a contract digest: the contract at that commit
    # and the contract this validation just ran must both have that content.
    reevaluated = exact_keys(report["reevaluatedWith"], ("commit", "contractSha256"))
    hex_value(reevaluated["commit"], 40)
    hex_value(reevaluated["contractSha256"])
    require(
        git_blob_sha256(reevaluated["commit"], RECORDER_FILES[0])
        == reevaluated["contractSha256"]
    )
    require(working_tree_sha256(RECORDER_FILES[0]) == reevaluated["contractSha256"])


def outcome(row):
    return f"{row['outcome']} / {row['observedError'] or 'none'}"


def render(value):
    validate(value)
    report = value["production"]
    rows = {row["id"]: row for row in report["cases"]}
    lines = [
        "# Precedence of overlapping refusals",
        "",
        "Status: candidate, not approved. Nine redacted production observations, not raw token responses or independent signature verification. No local artifact was run against this corpus in this record; the local order is enumerated separately in `tools/auth-refusal-precedence/README.md`.",
        "",
        SCOPE,
        "",
        "| Case | Basis | Outcome / error | Checks | Elapsed ms |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in report["cases"]:
        basis = "diagnostic" if row["id"] in DIAGNOSTIC else "control"
        checks = (
            ", ".join(f"{k}={v}" for k, v in sorted(row["checks"].items()))
            if row["checks"]
            else "none"
        )
        lines.append(
            f"| {row['id']} | {basis} | {outcome(row)} | {checks} | {row['elapsedMs']} |"
        )
    recorded, reevaluated = report["recordedWith"], report["reevaluatedWith"]
    lines.extend(
        [
            "",
            f"Tampered ID token with an administrator-only field, before any disable: **{outcome(rows['invalid-token-admin-field-update'])}**; A unchanged on readback: {report['invalidTokenStateUnchanged']}. Disabled account, held session, wrong code (A): **{outcome(rows['disabled-a-wrong-code-finalize'])}**. Disabled account, held session, correct code (B): **{outcome(rows['disabled-b-correct-code-finalize'])}**. The same held credentials and sessions after re-enablement: A {outcome(rows['reenabled-a-held-finalize'])}, B {outcome(rows['reenabled-b-held-finalize'])}.",
            "",
            f"Review subject (unapproved): `{digest(value)}`.",
            "",
            "A and B differ only in the code they present while disabled, on sessions started before the disable and read back afterwards, so the two rows together show which of the code and the account state is checked first. The re-enabled rows reuse the same pending credential and session, so they show whether each refusal consumed them. The tampered-token row carries a real ID token of A with one signature character changed inside the signature, so only an invalid signature and a privileged field overlap; the fields were chosen so that an acceptance could not have changed A's verified email, factor enrollment or ownership marker. Elapsed milliseconds are cumulative time from the recorder's measurement origin (set before account setup), sampled when each row is recorded after its checks; they are neither request latency nor time since the disable, and are excluded from semantic equality.",
            "",
            "The oracle project had MFA disabled, no phone sign-in and an empty SMS region allowlist. For the run, phone MFA, two test phone numbers with a fixed code (no SMS is sent) and the allow-by-default SMS region policy were enabled, and after a wait for enforcement the flow ran. The recorded values were restored in the recorder's final step before the accounts were deleted; the readback matched and the whole-configuration digest equaled the pre-run digest. Both accounts were deleted with UID and email absence confirmation. The run started from a committed checkout of every probe tree.",
            "",
            f"Recorded with the recorder files at commit `{recorded['recorderCommit']}` while the repository was at `{recorded['probeSourceCommit']}`; the receipt names the file digests the recorder hashed. Re-evaluated at publication with the contract at commit `{reevaluated['commit']}`. The observation itself was not re-run.",
            "",
            "This does not show what a valid token with a privileged field does, what mfaSignIn:start answers for a disabled account, how an expired pending credential ranks against a valid code, or anything about TOTP, tenants, blocking functions, SDK or Rules.",
            "",
            "[Receipt](../../spec/compatibility/evidence/auth-refusal-precedence/receipt.json) · [Source mapping](../../spec/compatibility/evidence/auth-refusal-precedence/source-review.json). All earlier evidence and approvals remain unchanged.",
            "",
        ]
    )
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--production", type=Path)
    parser.add_argument("--recorder-commit")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.production:
        require(bool(args.recorder_commit) and not args.check and not BUNDLE.exists())
        value = {
            "schemaVersion": 1,
            "acceptance": "candidate",
            "scope": SCOPE,
            "corpus": CORPUS,
            "sourceReviewSha256": digest(json.loads(REVIEW.read_bytes())),
            "publicationContractSha256": publication_contract_sha(),
            "production": project(
                json.loads(args.production.read_bytes()), args.recorder_commit
            ),
        }
        validate(value)
        BUNDLE.parent.mkdir(parents=True, exist_ok=True)
        BUNDLE.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    value = json.loads(BUNDLE.read_bytes())
    page = render(value)
    if args.check:
        require(PAGE.read_text() == page)
    else:
        PAGE.write_text(page)
    print("Auth refusal precedence candidate checked; subject " + digest(value))
