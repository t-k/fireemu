"""Validate and publish the bounded, explicitly redacted Auth revision 2 receipt."""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/auth-password-unicode-boundary"))
sys.path.insert(0, str(ROOT / "tools/compat-inventory"))
from boundary_contract import (
    CASES,
    SHAPES,
    complete,
    hypotheses,
    require,
    validate_case,
)
from boundary_recorder import PASSWORD_POLICY, digest, inputs
from evidence_common import runtime_inputs

BUNDLE = ROOT / "spec/compatibility/evidence/auth-password-unicode-boundary/receipt.json"
REVIEW = ROOT / "spec/compatibility/evidence/auth-password-unicode-boundary/source-review.json"
PAGE = ROOT / "docs/compatibility/auth-password-unicode-boundary.md"
INPUT_SHAPE = SHAPES
SCOPE = "Three generated password upper-bound inputs, each with a distinct dedicated account, under the recorded minimum 6 / maximum 4096 policy. End-user REST, no tenant, owned strict artifact versus production. Redacted observations of acceptance/refusal plus branch-specific credential/state controls; no human approval, no universal Unicode rule or SDK/Rules/expiry claim."
CORPUS = {"slice": "auth-password-unicode-boundary", "revision": 1, "cases": list(CASES)}


def hex_value(value, length=64):
    require(
        isinstance(value, str) and re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value)
    )


def publication_contract_sha():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def project(report, target):
    require(
        type(report["schemaVersion"]) is int
        and report["schemaVersion"] == 2
        and report["acceptance"] == "candidate"
        and report["target"] == target
        and complete(report)
    )
    require(
        digest(report["corpus"]) == digest(CORPUS) and report["probeInputs"] == inputs()
    )
    out = {
        key: report[key]
        for key in ["target", "recordedAt", "probeSourceCommit", "cases", "cleanup"]
    }
    require(digest(report["inputShape"]) == digest(INPUT_SHAPE))
    out["inputShape"] = report["inputShape"]
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
        type(value["schemaVersion"]) is int
        and value["schemaVersion"] == 2
        and value["acceptance"] == "candidate"
        and value["scope"] == SCOPE
    )
    require(
        digest(value["corpus"]) == digest(CORPUS) and value["probeInputs"] == inputs()
    )
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
            "inputShape",
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
        require(digest(report["inputShape"]) == digest(INPUT_SHAPE))
        hex_value(report["probeSourceCommit"], 40)
        hex_value(report["privateReceiptSha256"])
        require(
            isinstance(report["cleanup"], dict)
            and set(report["cleanup"]) == {"uidAbsent", "emailAbsent"}
        )
        require(all(item is True for item in report["cleanup"].values()))
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
                    "adminPasswordPolicyAbsent",
                    "passwordPolicy",
                }
            )
            require(
                all(
                    config[key] is True
                    for key in config
                    if key not in {"sha256", "passwordPolicy"}
                )
                and digest(config["passwordPolicy"]) == digest(PASSWORD_POLICY)
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
            type(instance["wrongTokenStatus"]) is int
            and instance["wrongTokenStatus"] == 403
            and instance["profile"] == "strict"
            and instance["version"] == artifact["version"]
        )
        hex_value(instance["nonce"], 32)


def render(value):
    validate(value)
    lines = [
        "# Unicode password upper-bound observations",
        "",
        "Status: candidate, not approved. Three input observations with validated credential/state and cleanup controls; not raw responses or independent token verification.",
        "",
        SCOPE,
        "",
        "| Input | Scalars | UTF-8 bytes | UTF-16 units | Local outcome / error | Production outcome / error | Same projection |",
        "|---|---:|---:|---:|---|---|---|",
    ]
    for local, production in zip(
        value["local"]["cases"], value["production"]["cases"], strict=True
    ):
        shape = local["inputShape"]
        lines.append(
            f"| {local['id']} | {shape['scalars']} | {shape['utf8Bytes']} | {shape['utf16Units']} | {local['outcome']} / {local['observedError'] or 'none'} | {production['outcome']} / {production['observedError'] or 'none'} | {local == production} |"
        )
    lines.extend(["", f"Review subject (unapproved): `{digest(value)}`.", ""])
    for target in ("local", "production"):
        fits = hypotheses({row["id"]: row["outcome"] for row in value[target]["cases"]})
        lines.append(
            f"{target}: counting hypotheses consistent with these three outcomes: {', '.join(fits) or 'none'}."
        )
    lines.extend(
        [
            "",
            "These are finite-pattern inferences, not proof of a universal counting rule. Each password contains a private random 32-character ASCII prefix and a U+10400 suffix repeated 2031 or 2032 times, followed by zero or one ASCII a. Separate accounts/runs are not strict causal experiments. Combining marks, normalization, grapheme clusters, isolated surrogates, minimum-length behavior and all Unicode strings remain untested.",
            "",
            "Before update, signup and signin credentials work, including the fixed baseline refresh token and derived ID lookup. After acceptance, the exact generated password signs in and update-issued ID/refresh tokens work. After refusal, the unchanged baseline ID, baseline refresh token and original password work. Selected account lookup fields are compared throughout. An incomplete flow, unknown/authentication error or cleanup failure is not a valid length observation; private diagnostics are retained.",
            "",
            "A policy-related HTTP 400 refusal is recorded as an observed outcome, not scored against an assumed counting rule. Its exact allowlisted error is compared across targets, as are all public row checks and expiry values. Every token control requires returned lifetime 3600 and same-account fields; no elapsed-expiry or independent-signature claim follows.",
            "",
            "Each account is created only after a private exclusive journal and independent absence preflight, identified by random email/marker plus saved/read-back UID, and deleted with UID/email absence confirmation. The suite stops on any incomplete sample. Owned artifact/config hashes, parent/child identity, process exit and listener closure are validated. Production project/policy configuration is read before/after without writes.",
            "",
            "[Receipt](../../spec/compatibility/evidence/auth-password-unicode-boundary/receipt.json) · [Source mapping](../../spec/compatibility/evidence/auth-password-unicode-boundary/source-review.json). Old observations, source reviews and approvals remain unchanged; none transfer to this subject.",
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
    print("Auth password candidate checked; subject " + digest(value))
