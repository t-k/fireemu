"""Validate and publish the redacted production-only MFA pending revocation receipt.

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
sys.path.insert(0, str(ROOT / "tools/auth-pending-revocation"))
sys.path.insert(0, str(ROOT / "tools/compat-inventory"))
from revocation_contract import (
    CASES,
    DIAGNOSTIC,
    complete,
    require,
    validate_row,
)
from revocation_recorder import digest

BUNDLE = ROOT / "spec/compatibility/evidence/auth-pending-revocation/receipt.json"
REVIEW = ROOT / "spec/compatibility/evidence/auth-pending-revocation/source-review.json"
PAGE = ROOT / "docs/compatibility/auth-pending-revocation.md"
SCOPE = "Eight sequential REST observations in production only: fresh phone MFA completions for target A and control B, then the pending credential of A issued before an explicit validSince update is presented to mfaSignIn:start and :finalize after the update and its readback, with lookup and refresh of any returned tokens, followed by fresh completions for A and B. Phone MFA with test phone numbers, no tenant, no blocking function, one run. The oracle configuration was changed for the run and restored with a digest comparison. Admin is used for owned account setup, the validSince update, readback and cleanup. No human approval, no local artifact comparison, no interval measurement between the update and the retry, and no revocation-propagation claim."
CORPUS = {"slice": "auth-pending-revocation", "revision": 1, "cases": list(CASES)}
# Fields of the private report that may appear in the receipt, and nothing else.
PROJECTED = (
    "target",
    "recordedAt",
    "probeSourceCommit",
    "cases",
    "setup",
    "revocation",
    "heldCredentialIssuedBeforeRevocation",
    "heldFinalizeTimes",
    "cleanup",
    "configRestored",
    "configRestoredReadback",
    "configDigestMatches",
)
RECORDER_FILES = (
    "tools/auth-pending-revocation/revocation_contract.py",
    "tools/auth-pending-revocation/revocation_recorder.py",
)


def hex_value(value, length=64):
    require(
        isinstance(value, str) and re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value)
    )


def publication_contract_sha():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


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
        "contractSha256": hashlib.sha256(
            (ROOT / RECORDER_FILES[0]).read_bytes()
        ).hexdigest(),
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
    out["configuration"] = report["configReadback"]
    out["privateReceiptSha256"] = digest(report)
    out["recordedWith"] = recorded_with(report, recorder_commit)
    out["reevaluatedWith"] = reevaluated_with()
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
    report = value["production"]
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
    config = report["configuration"]
    require(
        set(config)
        == {
            "sha256",
            "emailEnabled",
            "passwordRequired",
            "improvedEmailPrivacy",
            "blockingTriggersAbsent",
            "adminPasswordPolicyAbsent",
        }
    )
    require(all(config[key] is True for key in config if key != "sha256"))
    hex_value(config["sha256"])
    restored = report["configRestoredReadback"]
    require(
        restored["mfa"] == {"state": "DISABLED"}
        and not restored["phoneNumber"]
        and restored["smsRegionConfig"] == {"allowlistOnly": {}}
    )
    times = report["heldFinalizeTimes"]
    held = {r["id"]: r for r in report["cases"] if r["id"] in DIAGNOSTIC}
    if held["revoked-a-held-finalize"]["outcome"] == "accepted":
        require(
            set(times) == {"authTime", "iat", "validSince"}
            and all(type(v) is int for v in times.values())
            and times["authTime"] >= times["validSince"]
        )
    else:
        require(times is None)
    recorded = report["recordedWith"]
    require(set(recorded) == {"probeSourceCommit", "recorderCommit", "recorderInputs"})
    recorded_with(
        {
            "probeSourceCommit": recorded["probeSourceCommit"],
            "probeInputs": recorded["recorderInputs"],
        },
        recorded["recorderCommit"],
    )
    reevaluated = report["reevaluatedWith"]
    require(set(reevaluated) == {"commit", "contractSha256"})
    hex_value(reevaluated["commit"], 40)
    hex_value(reevaluated["contractSha256"])


def render(value):
    validate(value)
    report = value["production"]
    lines = [
        "# MFA pending credential across an explicit revocation",
        "",
        "Status: candidate, not approved. Eight redacted production observations, not raw token responses or independent signature verification. No local artifact was run against this corpus; the local behavior is pinned separately by the `pending_retry` regressions.",
        "",
        SCOPE,
        "",
        "| Case | Basis | Outcome / error | Checks | Elapsed ms |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in report["cases"]:
        basis = "diagnostic" if row["id"] in DIAGNOSTIC else "control"
        checks = ", ".join(sorted(row["checks"])) if row["checks"] else "none"
        lines.append(
            f"| {row['id']} | {basis} | {row['outcome']} / {row['observedError'] or 'none'} | {checks} | {row['elapsedMs']} |"
        )
    times = report["heldFinalizeTimes"]
    held = "accepted" if times else "refused"
    timing = (
        f"The ID token returned for the held credential carried `auth_time` {times['authTime']} and `iat` {times['iat']} against the set `validSince` {times['validSince']} (whole seconds)."
        if times
        else "No ID token was returned for the held credential."
    )
    recorded, reevaluated = report["recordedWith"], report["reevaluatedWith"]
    lines.extend(
        [
            "",
            f"Held credential outcome: **{held}** after the `validSince` update and its readback. {timing}",
            "",
            f"Review subject (unapproved): `{digest(value)}`.",
            "",
            "The held credential was issued, then after a two-second wait `validSince` was set to the current whole second through privileged `accounts:update` and read back for the target while the control stayed unchanged; only then was the held credential presented. The wait precedes the update, not the retry: the interval between the update and the retry was not measured in this run. Baseline rows completed a different fresh pending credential of each account before the update; fresh rows completed new pending credentials after the held observation. Elapsed milliseconds measure request start since the first observation row and are excluded from semantic equality.",
            "",
            "The oracle project had MFA disabled, no phone sign-in and an empty SMS region allowlist. For the run, phone MFA, two test phone numbers with a fixed code (no SMS is sent) and the allow-by-default SMS region policy were enabled, and after a wait for enforcement the flow ran. The recorded values were restored in the recorder's final step; the readback matched and the whole-configuration digest equaled the pre-run digest. Both accounts were deleted with UID and email absence confirmation.",
            "",
            f"Recorded with the recorder files at commit `{recorded['recorderCommit']}` while the repository was at `{recorded['probeSourceCommit']}`; the receipt names the file digests the recorder hashed. Re-evaluated at publication with the contract at commit `{reevaluated['commit']}`, whose completion check is stricter than the recorder's own (a matching configuration digest and a consistent held-credential chain are required). The observation itself was not re-run.",
            "",
            "This matches the local implementation, in which finalization does not compare a pending credential's start time with `validSince`; no revocation check was added on the strength of speculation. It does not show that revocation propagates within any interval, that a pre-update refresh token was refused, that password changes behave alike, or anything about tenants, blocking functions, SDK checkRevoked, Rules or the credential's own expiry.",
            "",
            "[Receipt](../../spec/compatibility/evidence/auth-pending-revocation/receipt.json) · [Source mapping](../../spec/compatibility/evidence/auth-pending-revocation/source-review.json). All earlier evidence and approvals remain unchanged.",
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
    print("Auth pending revocation candidate checked; subject " + digest(value))
