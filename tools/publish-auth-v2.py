"""Validate and publish the bounded, explicitly redacted Auth revision 2 receipt."""

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/auth-basic-v2"))
sys.path.insert(0, str(ROOT / "tools/compat-inventory"))
from auth_v2_contract import CASES, complete, expiry_seconds, require
from auth_v2_recorder import digest, inputs
from evidence_common import runtime_inputs

BUNDLE = ROOT / "spec/compatibility/evidence/auth-basic-v2/receipt.json"
REVIEW = ROOT / "spec/compatibility/evidence/auth-basic-v2/source-review.json"
PAGE = ROOT / "docs/compatibility/auth-basic-v2.md"
TOKEN = {
    "httpOk",
    "noError",
    "idTokenPresent",
    "refreshTokenPresent",
    "uidMatches",
    "expiryIsPositiveInteger",
    "expiryMatchesOneHour",
    "emailMatches",
}
CHECKS = {
    name: {"ownedIdentity"}
    for name in [
        "lookup",
        "refreshed-lookup",
        "signup-token-lookup",
        "signup-refreshed-lookup",
    ]
}
CHECKS.update(
    {
        "signup": TOKEN,
        "signin": TOKEN,
        "refresh": TOKEN - {"emailMatches"} | {"bearerType"},
        "signup-token-refresh": TOKEN - {"emailMatches"} | {"bearerType"},
        "wrong-password": {"rejected", "expectedError"},
        "unchanged-state": {"selectedStableFieldsUnchanged"},
        "delete": {"httpOk", "noError"},
        "deleted-account-absent": {"bothSelectorsAbsent"},
    }
)
SCOPE = "Email/password REST; default project; strict local artifact and recorded production configuration; corpus revision 2; twelve cases only; redacted semantic observations, not raw responses or independent JWT signature/expiry enforcement proof. No SDK, Rules, MFA, OOB, tenant, public npm or complete Auth claim."


def hex_value(value, length=64):
    require(
        isinstance(value, str) and re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value)
    )


def validate_case(row, name):
    token_case = "expiryIsPositiveInteger" in CHECKS[name]
    require(
        isinstance(row, dict)
        and set(row)
        == {"id", "httpStatus", "checks", "passed"}
        | ({"expirySeconds"} if token_case else set())
    )
    require(
        row["id"] == name
        and type(row["httpStatus"]) is int
        and 100 <= row["httpStatus"] <= 599
    )
    require(
        isinstance(row["checks"], dict)
        and set(row["checks"]) == CHECKS[name]
        and all(type(v) is bool for v in row["checks"].values())
    )
    require(
        type(row["passed"]) is bool and row["passed"] == all(row["checks"].values())
    )
    require(
        not row["passed"]
        or row["httpStatus"] == (400 if name == "wrong-password" else 200)
    )
    if token_case:
        seconds = row["expirySeconds"]
        require(seconds is None or expiry_seconds({"expiresIn": seconds}) == seconds)
        require(row["checks"]["expiryIsPositiveInteger"] == (seconds is not None))
        require(row["checks"]["expiryMatchesOneHour"] == (seconds == "3600"))


def project(report, target):
    require(
        report["schemaVersion"] == 2
        and report["acceptance"] == "candidate"
        and report["target"] == target
        and complete(report)
    )
    require(
        report["corpus"] == {"revision": 2, "cases": list(CASES)}
        and report["probeInputs"] == inputs()
    )
    out = {
        key: report[key]
        for key in ["target", "recordedAt", "probeSourceCommit", "cases", "cleanup"]
    }
    out["privateReceiptSha256"] = digest(report)
    if target == "local":
        require(report["connection"] == "owned-artifact")
        out.update(
            {
                key: report[key]
                for key in [
                    "artifact",
                    "configuration",
                    "ownedProcess",
                    "runtimeSourceCommit",
                ]
            }
        )
        out["build"] = {
            key: report["build"][key]
            for key in ["command", "exitCode", "artifactSha256", "inputs"]
        }
        out["instance"] = {
            key: report["instance"][key]
            for key in [
                "parentPid",
                "childPid",
                "nonce",
                "profile",
                "version",
                "wrongTokenStatus",
            ]
        }
    else:
        require(
            report["project"] == "fireemu-35fe6"
            and report["projectNumber"] == "592603257417"
            and report["configurationUnchanged"] is True
        )
        out["configuration"] = report["configReadback"]
        out["configurationUnchanged"] = True
    return out


def validate(value):
    require(
        set(value)
        == {
            "schemaVersion",
            "acceptance",
            "scope",
            "corpus",
            "probeInputs",
            "sourceReviewSha256",
            "local",
            "production",
        }
    )
    require(
        value["schemaVersion"] == 2
        and value["acceptance"] == "candidate"
        and value["scope"] == SCOPE
    )
    require(
        value["corpus"] == {"revision": 2, "cases": list(CASES)}
        and value["probeInputs"] == inputs()
    )
    review = json.loads(REVIEW.read_bytes())
    require(value["sourceReviewSha256"] == digest(review))
    require([row["case"] for row in review["obligations"]] == list(CASES))
    require(review["executionApproval"] == "not-granted")
    prior = ROOT / "spec/compatibility/evidence/auth-basic/source-review.json"
    require(review["priorSourceReviewSha256"] == digest(json.loads(prior.read_bytes())))
    for target in ["local", "production"]:
        report = value[target]
        common = {
            "target",
            "recordedAt",
            "probeSourceCommit",
            "cases",
            "cleanup",
            "privateReceiptSha256",
        }
        require(
            set(report)
            == common
            | (
                {
                    "artifact",
                    "configuration",
                    "ownedProcess",
                    "runtimeSourceCommit",
                    "build",
                    "instance",
                }
                if target == "local"
                else {"configuration", "configurationUnchanged"}
            )
        )
        require(
            report["target"] == target
            and isinstance(report["recordedAt"], str)
            and re.fullmatch(r"[0-9T:.+\-]+", report["recordedAt"])
        )
        hex_value(report["probeSourceCommit"], 40)
        hex_value(report["privateReceiptSha256"])
        require(report["cleanup"] == {"uidAbsent": True, "emailAbsent": True})
        require(len(report["cases"]) == len(CASES))
        for row, name in zip(report["cases"], CASES, strict=True):
            validate_case(row, name)
        if target == "production":
            config = report["configuration"]
            require(
                set(config)
                == {
                    "sha256",
                    "emailEnabled",
                    "passwordRequired",
                    "improvedEmailPrivacy",
                    "blockingTriggersAbsent",
                }
            )
            require(
                all(config[key] is True for key in config if key != "sha256")
                and report["configurationUnchanged"] is True
            )
            hex_value(config["sha256"])
            continue
        hex_value(report["runtimeSourceCommit"], 40)
        artifact = report["artifact"]
        require(
            set(artifact) == {"sha256", "version", "kind"}
            and artifact["kind"] == "local-build"
        )
        require(
            isinstance(artifact["version"], str)
            and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", artifact["version"])
        )
        hex_value(artifact["sha256"])
        config = report["configuration"]
        require(
            set(config) == {"value", "sha256", "fileSha256"}
            and config["value"] == {"schemaVersion": 1, "profile": "strict"}
        )
        require(config["sha256"] == digest(config["value"]))
        hex_value(config["fileSha256"])
        build = report["build"]
        require(set(build) == {"command", "exitCode", "artifactSha256", "inputs"})
        require(
            build["command"]
            == ["cargo", "build", "--locked", "-p", "fireemu", "--message-format=json"]
            and type(build["exitCode"]) is int
            and build["exitCode"] == 0
        )
        require(
            build["artifactSha256"] == artifact["sha256"]
            and build["inputs"] == runtime_inputs(ROOT)
        )
        process, instance = report["ownedProcess"], report["instance"]
        require(set(process) == {"pid", "exitCode", "stopped", "listenersClosed"})
        require(
            set(instance)
            == {
                "parentPid",
                "childPid",
                "nonce",
                "profile",
                "version",
                "wrongTokenStatus",
            }
        )
        require(
            type(process["pid"]) is int
            and process["pid"] > 1
            and type(instance["childPid"]) is int
            and instance["childPid"] > 1
        )
        require(
            type(instance["parentPid"]) is int
            and instance["parentPid"] == process["pid"]
            and instance["childPid"] != process["pid"]
        )
        require(
            type(process["exitCode"]) is int
            and process["exitCode"] == 0
            and process["stopped"] is True
            and process["listenersClosed"] is True
        )
        require(
            instance["wrongTokenStatus"] == 403
            and instance["profile"] == "strict"
            and instance["version"] == artifact["version"]
        )
        hex_value(instance["nonce"], 32)


def render(value):
    validate(value)
    subject = digest(value)
    lines = [
        "# Auth basic revision 2",
        "",
        "Status: candidate, not approved. This is an explicitly redacted semantic receipt, not retained raw Auth responses or a signed attestation.",
        "",
        SCOPE,
        "",
        "The twelve-case corpus adds signup-token lookup, signup-token refresh and lookup using that refreshed token. Numeric expiry is retained and checked separately for positive-integer shape and the explicit 3600-second expectation. Actual expired-token refusal is not tested.",
        "",
        "| Case | Local | Production | Expiry seconds (local / production) |",
        "|---|---|---|---|",
    ]
    for local, production in zip(
        value["local"]["cases"], value["production"]["cases"], strict=True
    ):
        lines.append(
            f"| {local['id']} | {'Matched' if local['passed'] else 'Mismatch'} | {'Matched' if production['passed'] else 'Mismatch'} | {local.get('expirySeconds', '—')} / {production.get('expirySeconds', '—')} |"
        )
    lines.extend(
        [
            "",
            f"Review subject (no approval granted): `{subject}`.",
            "",
            "[Public redacted receipt](../../spec/compatibility/evidence/auth-basic-v2/receipt.json) includes exact artifact/configuration/build inputs, process identity/exit checks and production configuration projection. Offline validation rechecks those relationships, expiry predicates and case verdict consistency. Token presence, identity relationships and service acceptance remain recorder observations; no reusable token values, passwords, raw account records or recovery journals are published. This is not independent cryptographic verification of the live service.",
            "",
            "[Source and case mapping](../../spec/compatibility/evidence/auth-basic-v2/source-review.json) extends the [selected-section review](auth-basic-source-review.md). [Original nine-case observations](auth-basic-evidence.md) and aggregation approvals remain unchanged. Human approval must name this subject and its limited redacted-observation scope; it cannot be transferred after an input or case change.",
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
            "schemaVersion": 2,
            "acceptance": "candidate",
            "scope": SCOPE,
            "corpus": {"revision": 2, "cases": list(CASES)},
            "probeInputs": inputs(),
            "sourceReviewSha256": digest(json.loads(REVIEW.read_bytes())),
            "local": project(json.loads(args.local.read_bytes()), "local"),
            "production": project(
                json.loads(args.production.read_bytes()), "production"
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
    print("Auth revision 2 candidate checked; subject " + digest(value))
