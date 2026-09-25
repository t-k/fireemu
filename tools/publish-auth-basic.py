"""Publish allowlisted Auth observations, never raw responses or recovery journals."""

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools" / "auth-basic"))
from contract import CASES, complete, require
from recorder import digest, inputs

BUNDLE = ROOT / "spec/compatibility/evidence/auth-basic/observations.json"
PAGE = ROOT / "docs/compatibility/auth-basic-evidence.md"
TOKEN = {
    "httpOk",
    "noError",
    "idTokenPresent",
    "refreshTokenPresent",
    "uidMatches",
    "expiryValid",
    "emailMatches",
}
CHECKS = {
    "signup": TOKEN,
    "signin": TOKEN,
    "lookup": {"ownedIdentity"},
    "wrong-password": {"rejected", "expectedError"},
    "unchanged-state": {"selectedStableFieldsUnchanged"},
    "refresh": TOKEN - {"emailMatches"} | {"bearerType"},
    "refreshed-lookup": {"ownedIdentity"},
    "delete": {"httpOk", "noError"},
    "deleted-account-absent": {"bothSelectorsAbsent"},
}


def validate_case(row, name):
    require(
        isinstance(row, dict) and set(row) == {"id", "httpStatus", "checks", "passed"}
    )
    require(
        row["id"] == name
        and type(row["httpStatus"]) is int
        and 100 <= row["httpStatus"] <= 599
    )
    require(isinstance(row["checks"], dict) and set(row["checks"]) == CHECKS[name])
    require(all(type(value) is bool for value in row["checks"].values()))
    require(
        type(row["passed"]) is bool and row["passed"] == all(row["checks"].values())
    )
    expected = 400 if name == "wrong-password" else 200
    require(not row["passed"] or row["httpStatus"] == expected)


def hexadecimal(value, length=64):
    require(
        isinstance(value, str) and re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value)
    )
    return value


def project(report, target):
    require(
        complete(report)
        and report["target"] == target
        and report["acceptance"] == "candidate"
    )
    require(report["probeInputs"] == inputs())
    for row, name in zip(report["cases"], CASES, strict=True):
        validate_case(row, name)
    result = {
        key: report[key]
        for key in ["target", "recordedAt", "cases", "cleanup", "probeSourceCommit"]
    }
    result["privateReceiptSha256"] = digest(report)
    if target == "local":
        process = report["ownedProcess"]
        require(
            report["connection"] == "owned-artifact"
            and process["exitCode"] == 0
            and process["stopped"] is True
            and process["listenersClosed"] is True
        )
        require(
            report["instance"]["parentPid"] == process["pid"]
            and report["instance"]["wrongTokenStatus"] == 403
            and report["instance"]["profile"] == "strict"
        )
        require(
            report["artifact"]["sha256"] == report["build"]["artifactSha256"]
            and report["build"]["exitCode"] == 0
        )
        result.update(
            {
                "artifactSha256": report["artifact"]["sha256"],
                "runtimeSourceCommit": report["runtimeSourceCommit"],
                "runtimeInputsSha256": digest(report["build"]["inputs"]),
                "configurationSha256": report["configuration"]["sha256"],
                "ownedProcessVerified": True,
            }
        )
    else:
        require(
            report["project"] == "fireemu-35fe6"
            and report["projectNumber"] == "592603257417"
            and report["configurationUnchanged"] is True
        )
        result["configurationSha256"] = report["configReadback"]["sha256"]
    return result


def validate(value):
    require(
        set(value)
        == {
            "schemaVersion",
            "acceptance",
            "probeInputs",
            "corpus",
            "local",
            "production",
        }
    )
    require(value["schemaVersion"] == 1 and value["acceptance"] == "candidate")
    require(
        value["probeInputs"] == inputs()
        and value["corpus"] == {"revision": 1, "cases": list(CASES)}
    )
    common = {
        "target",
        "recordedAt",
        "cases",
        "cleanup",
        "probeSourceCommit",
        "privateReceiptSha256",
        "configurationSha256",
    }
    for target in ["local", "production"]:
        report = value[target]
        expected = common | (
            {
                "artifactSha256",
                "runtimeSourceCommit",
                "runtimeInputsSha256",
                "ownedProcessVerified",
            }
            if target == "local"
            else set()
        )
        require(set(report) == expected and report["target"] == target)
        require(
            isinstance(report["recordedAt"], str)
            and re.fullmatch(r"[0-9T:.+\-]+", report["recordedAt"])
        )
        require(report["cleanup"] == {"uidAbsent": True, "emailAbsent": True})
        for key in expected:
            if key.endswith("Sha256"):
                hexadecimal(report[key])
            if key.endswith("Commit"):
                hexadecimal(report[key], 40)
        if target == "local":
            require(report["ownedProcessVerified"] is True)
        require(len(report["cases"]) == len(CASES))
        for row, name in zip(report["cases"], CASES, strict=True):
            validate_case(row, name)


def render():
    value = json.loads(BUNDLE.read_bytes())
    validate(value)
    lines = [
        "# Bounded Auth basic observations",
        "",
        "Status: candidate observations, not approved. No feature-level execution approval is recorded by this page.",
        "",
        "Scope: email/password REST, default project (no tenant), local fireemu strict, and production with password sign-in and improved email privacy enabled. Exact Admin lookup is used only for ownership and cleanup. This does not attest SDK, MFA, OOB, Rules, public npm, or complete Auth compatibility.",
        "",
        "These are allowlisted semantic projections, not raw responses. Credentials and raw account data were not retained. Offline checks verify projection consistency and recorder inputs; they cannot independently recompute the observations from raw responses or verify token signatures. The owned-process assertion is recorder-reported; its detailed private receipt is hash-bound, not publicly reproduced.",
        "",
        "| Case | Local | Production |",
        "|---|---|---|",
    ]
    for local, production in zip(
        value["local"]["cases"], value["production"]["cases"], strict=True
    ):
        lines.append(
            f"| {local['id']} | {'Matched' if local['passed'] else 'Mismatch'} | {'Matched' if production['passed'] else 'Mismatch'} |"
        )
    for target in ["local", "production"]:
        report = value[target]
        count = sum(row["passed"] for row in report["cases"])
        lines.extend(
            [
                "",
                f"{target.capitalize()}: {count}/9 matched at `{report['recordedAt']}`. Exact UID and email absence confirmed. Recorder source: `{report['probeSourceCommit']}`. Configuration digest: `{report['configurationSha256']}`.",
            ]
        )
    lines.extend(
        [
            "",
            f"Local artifact SHA-256: `{value['local']['artifactSha256']}`. Runtime source: `{value['local']['runtimeSourceCommit']}`. The owned process exited and its Auth/control listeners closed.",
            "",
            "[Machine-readable projections](../../spec/compatibility/evidence/auth-basic/observations.json) · [Recorder, safety constraints and recovery](../../tools/auth-basic/README.md). Existing aggregation approvals remain separate. Source-section review, requirement mapping and human approval for this Auth slice remain pending.",
            "",
        ]
    )
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local", type=Path)
    parser.add_argument("--production", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.local or args.production:
        require(
            bool(args.local and args.production)
            and not args.check
            and not BUNDLE.exists()
        )
        value = {
            "schemaVersion": 1,
            "acceptance": "candidate",
            "probeInputs": inputs(),
            "corpus": {"revision": 1, "cases": list(CASES)},
            "local": project(json.loads(args.local.read_bytes()), "local"),
            "production": project(
                json.loads(args.production.read_bytes()), "production"
            ),
        }
        validate(value)
        BUNDLE.parent.mkdir(parents=True, exist_ok=True)
        BUNDLE.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    page = render()
    if args.check:
        require(PAGE.read_text() == page)
    else:
        PAGE.write_text(page)
    print("Auth candidate projections checked; no approvals granted")
