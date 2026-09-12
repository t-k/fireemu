"""Validate and publish the redacted production-only auth-pending-lifetime-boundary receipt.

The observation was recorded with the recorder at one commit and re-evaluated with the
contract at publication; both are named and never conflated. Only allowlisted fields are
projected, and the full execution-dependency set is bound to the recorder commit. The
receipt states a lower bound on the pending lifetime; a refusal records its age and error
but does not, in this revision, establish an upper bound, and the receipt never states an
exact TTL or an error precedence.
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/auth-pending-lifetime-boundary"))
sys.path.insert(0, str(ROOT / "tools/compat-inventory"))
from boundary_contract import (
    AGE_SECONDS,
    CASES,
    CORPUS,
    DIAGNOSTIC,
    classified,
    complete,
    lifetime_summary,
    require,
    validate_row,
)
from boundary_recorder import BUDGET, digest

BUNDLE = (
    ROOT / "spec/compatibility/evidence/auth-pending-lifetime-boundary/receipt.json"
)
REVIEW = (
    ROOT
    / "spec/compatibility/evidence/auth-pending-lifetime-boundary/source-review.json"
)
PAGE = ROOT / "docs/compatibility/auth-pending-lifetime-boundary.md"
SCOPE = "Ten sequential REST observations in production: fresh phone MFA completion controls surround independent pending credentials held untouched for 600, 1800, 3300 and 3900 seconds, each followed by start and, if accepted, finalize with a fresh SMS session. Six owned accounts, one test phone number, no tenant or blocking function, one recorded configuration and one run. The largest fully verified success is an observed survival lower bound. Refusals retain measured pending-age intervals and separate start/finalize stages; any boundary candidate assumes equivalent account conditions and monotonic usability and does not prove age-caused expiry. No lifetime upper bound, exact TTL, error precedence, universal account guarantee or result approval is asserted. Configuration recovery and account absence are verified. Refresh-token presence is not a refresh exchange. The expired-pending/independently-valid-code residual remains unobserved."

RECORDER_FILES = (
    "tools/auth-pending-lifetime-boundary/boundary_contract.py",
    "tools/auth-pending-lifetime-boundary/boundary_recorder.py",
    "tools/auth-pending-revocation/revocation_recorder.py",
    "tools/auth-pending-revocation/revocation_contract.py",
    "tools/auth-password-maximum/maximum_contract.py",
    "tools/auth-password-maximum/maximum_recorder.py",
)
PROJECTED = (
    "target",
    "recordedAt",
    "probeSourceCommit",
    "committedCheckout",
    "agingMode",
    "budget",
    "accountsUsed",
    "stopReason",
    "requestCount",
    "adminTokenAges",
    "privilegedRequests",
    "privilegedRequestCount",
    "publicRequestCount",
    "authRefreshAttempts",
    "authOperations",
    "wallElapsedSeconds",
    "configHoldSeconds",
    "cases",
    "setup",
    "cleanup",
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


def hex_value(value, length=64):
    require(
        isinstance(value, str) and re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value)
    )


def publication_contract_sha():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def working_tree_sha256(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def exact_keys(value, keys):
    require(isinstance(value, dict) and set(value) == set(keys))
    return {key: value[key] for key in keys}


def git_blob_sha256(commit, path):
    blob = subprocess.check_output(
        ["git", "show", f"{commit}:{path}"], cwd=ROOT, stderr=subprocess.DEVNULL
    )
    return hashlib.sha256(blob).hexdigest()


def recorded_with(report, recorder_commit):
    hex_value(report["probeSourceCommit"], 40)
    hex_value(recorder_commit, 40)
    require(report["probeSourceCommit"] == recorder_commit)
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
        and report["agingMode"] == "real-time"
        and digest(report["corpus"]) == digest(CORPUS)
        and complete(report)
    )
    validate_auth_projection(report)
    out = {key: report[key] for key in PROJECTED}
    out["configRestoredReadback"] = exact_keys(
        report["configRestoredReadback"], RESTORED_KEYS
    )
    out["configuration"] = exact_keys(report["configReadback"], CONFIGURATION_KEYS)
    out["lifetimeSummary"] = lifetime_summary(report)
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
    require(review["executionApproval"] == "not-conferred-by-source-review")
    validate_production(value["production"])


def validate_production(report):
    require(
        set(report)
        == set(PROJECTED)
        | {
            "configuration",
            "lifetimeSummary",
            "privateReceiptSha256",
            "recordedWith",
            "reevaluatedWith",
        }
    )
    require(
        report["target"] == "production"
        and report["agingMode"] == "real-time"
        and isinstance(report["recordedAt"], str)
        and re.fullmatch(r"[0-9T:.+\-]+", report["recordedAt"])
    )
    validate_auth_projection(report)
    require(complete({**report, "status": "observed"}))
    hex_value(report["privateReceiptSha256"])
    for row, name in zip(report["cases"], CASES, strict=True):
        validate_row(row, name)
        require(classified(row))
    require(report["committedCheckout"] is True)
    require(report["lifetimeSummary"] == lifetime_summary(report))
    config = exact_keys(report["configuration"], CONFIGURATION_KEYS)
    require(all(config[key] is True for key in config if key != "sha256"))
    hex_value(config["sha256"])
    restored = exact_keys(report["configRestoredReadback"], RESTORED_KEYS)
    require(
        restored["mfa"] == {"state": "DISABLED"}
        and restored["phoneNumber"] == {}
        and restored["smsRegionConfig"] == {"allowlistOnly": {}}
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
    reevaluated = exact_keys(report["reevaluatedWith"], ("commit", "contractSha256"))
    hex_value(reevaluated["commit"], 40)
    hex_value(reevaluated["contractSha256"])
    require(
        git_blob_sha256(reevaluated["commit"], RECORDER_FILES[0])
        == reevaluated["contractSha256"]
    )
    require(working_tree_sha256(RECORDER_FILES[0]) == reevaluated["contractSha256"])


def validate_auth_projection(report):
    require(report["budget"] == BUDGET)
    for row in report["privilegedRequests"]:
        exact_keys(
            row,
            (
                "sequence",
                "phase",
                "action",
                "started",
                "tokenAgeSeconds",
                "verifiedExpiry",
                "remainingSeconds",
            ),
        )
    for row in report["authOperations"]:
        exact_keys(row, ("phase", "operation", "started", "reserveSeconds"))
    for field in (
        "privilegedRequestCount",
        "publicRequestCount",
        "authRefreshAttempts",
    ):
        exact_keys(report[field], ("observation", "recovery"))


def outcome(row):
    if row["skipped"]:
        return "skipped"
    return f"{row['outcome']} / {row['observedError'] or 'none'}"


def age_display(row):
    timing = row["timing"]
    if "pendingAgeAtStart" in timing:
        return f"[{timing['pendingAgeAtStart']['lower']}, {timing['pendingAgeAtStart']['upper']}]"
    if "pendingAgeAtFinalize" in timing:
        return f"[{timing['pendingAgeAtFinalize']['lower']}, {timing['pendingAgeAtFinalize']['upper']}]"
    return "-"


def render(value):
    validate(value)
    report = value["production"]
    summary = report["lifetimeSummary"]
    recorded, reevaluated = report["recordedWith"], report["reevaluatedWith"]
    usable, refused, reasons = (
        summary["usableAges"],
        summary["refusedAges"],
        summary["refusalReasons"],
    )
    lower = summary["lowerBoundSeconds"]
    lines = [
        "# MFA pending credential lifetime: revision 2 boundary candidates",
        "",
        "Status: candidate, not approved. Ten redacted production observations, not raw token responses or independent signature verification. No local artifact was run against this corpus in this record; the owned local comparison is published separately.",
        "",
        SCOPE,
        "",
        "| Case | Basis | Pending age (s) | Outcome / error | Checks | Elapsed ms |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in report["cases"]:
        basis = "diagnostic" if row["id"] in DIAGNOSTIC else "control"
        checks = (
            ", ".join(f"{k}={v}" for k, v in sorted(row["checks"].items()))
            if row["checks"]
            else "none"
        )
        lines.append(
            f"| {row['id']} | {basis} | {age_display(row)} | {outcome(row)} | {checks} | {row['elapsedMs']} |"
        )
    refused_text = (
        "none"
        if not refused
        else ", ".join(f"{a} s ({reasons[str(a)]})" for a in refused)
    )
    lower_text = (
        f"an observed survival lower bound of **{lower} s** for this method, configuration and single run"
        if lower is not None
        else "no verified success at any sampled age"
    )
    lines.extend(
        [
            "",
            f"Sampled ages: {', '.join(str(a) for a in AGE_SECONDS)} s. Verified usable: {usable or 'none'}. Refused: {refused_text}. Indeterminate (accepted without a verified token): {summary['indeterminateAges'] or 'none'}. This establishes {lower_text}. A refused age records its error, but this revision does not prove a refusal is due to expiry, so it asserts no lifetime upper bound.",
            "",
            f"Start accepted at target ages: {summary['startAcceptedAges']}. Nonmonotonic observations: {summary['nonMonotonic']}. Boundary candidates: `{json.dumps(summary['boundaryCandidates'], sort_keys=True)}`. Candidate upper endpoints use the refused request interval upper endpoint, never its target age. Age-caused expiry and a shared upper bound remain unestablished.",
            "",
            f"Privileged HTTP requests: {len(report['privilegedRequests'])}; refresh attempts by phase: `{json.dumps(report['authRefreshAttempts'], sort_keys=True)}`. Each privileged project/configuration/account request has recorded verified expiry and remaining validity. Refresh, tokeninfo and preflight CLI operations are phase-budgeted; acquisition age alone is not expiry evidence.",
            "",
            f"Review subject (unapproved): `{digest(value)}`.",
            "",
            "Each pending credential was obtained near a common origin and left untouched until its own diagnostic, so no intermediate access could extend it; the SMS session was opened fresh at the diagnostic, so its age at finalize is recorded as an interval near zero while only the pending age grows. A sampled age is counted usable only when its start returned a session and its finalize both succeeded and passed every identity check; an accepted finalize with a missing or unverifiable token is recorded but counts as indeterminate, not usable. A refused start records its error and skips its finalize. The pending age at start and the session age at finalize are kept in a separate timing region on each row, saved on refusal too, and excluded from semantic equality along with the elapsed milliseconds, since they vary across runs and clocks.",
            "",
            "The oracle project had MFA disabled, no phone sign-in and an empty SMS region allowlist. For the run, phone MFA, one test phone number with a fixed code (no SMS is sent) and the allow-by-default SMS region policy were enabled, and after a wait for enforcement the flow ran. The recorded values were restored before the accounts were deleted; the readback matched and the whole-configuration digest equaled the pre-run digest. Every account was deleted with UID and email absence confirmation. The run aged by real waiting and started from a committed checkout.",
            "",
            f"Recorded with the recorder files at commit `{recorded['recorderCommit']}` while the repository was at `{recorded['probeSourceCommit']}`. Re-evaluated at publication with the contract at commit `{reevaluated['commit']}`. The observation itself was not re-run.",
            "",
            "This does not pin the exact pending lifetime or error precedence, does not separate pending-versus-session expiry, and does not generalize to tenants, blocking functions, SDK or Rules.",
            "",
            "[Receipt](../../spec/compatibility/evidence/auth-pending-lifetime-boundary/receipt.json) · [Source mapping](../../spec/compatibility/evidence/auth-pending-lifetime-boundary/source-review.json). All earlier evidence and approvals remain unchanged.",
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
    print("Auth pending-lifetime-boundary candidate checked; subject " + digest(value))
