"""Validate and publish the bounded, explicitly redacted Auth revision 2 receipt."""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/auth-display-name"))
sys.path.insert(0, str(ROOT / "tools/compat-inventory"))
from display_name_contract import CASES, complete, require, validate_case
from display_name_recorder import digest, inputs
from evidence_common import runtime_inputs

BUNDLE = ROOT / "spec/compatibility/evidence/auth-display-name/receipt.json"
REVIEW = ROOT / "spec/compatibility/evidence/auth-display-name/source-review.json"
PAGE = ROOT / "docs/compatibility/auth-display-name.md"
SCOPE = "Display name REST updates using end-user tokens; no tenant; strict owned local artifact and recorded production configuration; auth-display-name corpus revision 1 only. Redacted semantic observations, not raw responses, independent JWT verification, expiry enforcement, SDK, MFA, Rules, credential changes or public npm compatibility."
CORPUS = {"slice": "auth-display-name", "revision": 1, "cases": list(CASES)}


def hex_value(value, length=64):
    require(
        isinstance(value, str) and re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value)
    )


def publication_contract_sha():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def project(report, target):
    require(
        report["schemaVersion"] == 2
        and report["acceptance"] == "candidate"
        and report["target"] == target
        and complete(report)
    )
    require(report["corpus"] == CORPUS and report["probeInputs"] == inputs())
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
            "publicationContractSha256",
            "local",
            "production",
        }
    )
    require(
        value["schemaVersion"] == 2
        and value["acceptance"] == "candidate"
        and value["scope"] == SCOPE
    )
    require(value["corpus"] == CORPUS and value["probeInputs"] == inputs())
    review = json.loads(REVIEW.read_bytes())
    require(value["publicationContractSha256"] == publication_contract_sha())
    require(value["sourceReviewSha256"] == digest(review))
    require([row["case"] for row in review["obligations"]] == list(CASES))
    require(review["executionApproval"] == "not-granted")

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
        serialized = json.dumps(config["value"], indent=2, sort_keys=True) + "\n"
        require(
            type(config["value"]["schemaVersion"]) is int
            and config["fileSha256"] == hashlib.sha256(serialized.encode()).hexdigest()
        )
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
    lines = [
        "# Auth displayName observations",
        "",
        "Status: candidate, not approved. These are redacted semantic observations, not retained raw responses or a signed attestation.",
        "",
        SCOPE,
        "",
        "| Case | Local | Production | Name state (local / production) |",
        "|---|---|---|---|",
    ]
    for local, production in zip(
        value["local"]["cases"], value["production"]["cases"], strict=True
    ):
        lines.append(
            f"| {local['id']} | {'Matched' if local['passed'] else 'Mismatch'} | {'Matched' if production['passed'] else 'Mismatch'} | {local.get('nameState', '—')} / {production.get('nameState', '—')} |"
        )
    lines.extend(
        [
            "",
            f"Review subject (no approval granted): `{digest(value)}`.",
            "",
            "The fixed synthetic names are Fireemu display first and Fireemu display second. initial identifies the private bootstrap marker; first/second identify corpus values. Absent, null and empty remain distinct; arbitrary names are never copied. Other/invalid-type remain visible mismatches. Classification is recorder testimony, not an independently reconstructable raw response.",
            "",
            "Only displayName is changed after bootstrap. Before the first change, exact email/marker and independent UID lookups establish ownership; the UID is saved and reread from a private identity file. Subsequent ownership and cleanup require that UID and email, not the mutable name. Unknown-UID recovery still requires the original marker and persists the recovered UID before deletion. Reused email with another UID is refused. The original signup ID token is reused; profile-update token issuance and refresh are not checked. Malformed-token refusal is not an expired-token test. Refusal-state comparison includes localId, email, displayName, emailVerified, disabled, providerUserInfo and photoUrl; success identity checks cover localId, email, photoUrl, emailVerified and disabled, not provider synchronization or full state.",
            "",
            "[Source and case mapping](../../spec/compatibility/evidence/auth-display-name/source-review.json) · [Redacted receipt](../../spec/compatibility/evidence/auth-display-name/receipt.json). The receipt binds fixed corpus, source review, probe/publication code, exact artifact/build/configuration and process exit. Published numeric expiry pertains only to account signup.",
            "",
            "Admin APIs are limited to dedicated-account ownership and cleanup. Both exact UID and email selectors must confirm absence. Project/configuration preflight and owned-process shutdown are required. No human approval is inferred from either target matching. [Existing Auth basic approval](auth-basic-v2-approval.md) and [photoUrl approval](auth-profile-approval.md) and aggregation evidence are unchanged and do not cover this new subject.",
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
            "corpus": CORPUS,
            "probeInputs": inputs(),
            "sourceReviewSha256": digest(json.loads(REVIEW.read_bytes())),
            "publicationContractSha256": publication_contract_sha(),
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
    print("Auth displayName candidate checked; subject " + digest(value))
