"""Validate and publish the bounded, explicitly redacted Auth revision 2 receipt."""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/auth-password-maximum"))
sys.path.insert(0, str(ROOT / "tools/compat-inventory"))
from evidence_common import runtime_inputs
from maximum_contract import CASES, complete, require, validate_case
from maximum_recorder import PASSWORD_POLICY, digest, inputs

BUNDLE = ROOT / "spec/compatibility/evidence/auth-password-maximum/receipt.json"
REVIEW = ROOT / "spec/compatibility/evidence/auth-password-maximum/source-review.json"
PAGE = ROOT / "docs/compatibility/auth-password-maximum.md"
INPUT_SHAPE = {
    "originalLength": 47,
    "maximumLength": 4096,
    "tailLength": 4096,
    "prefixLength": 4095,
    "oversizeLength": 4097,
    "ascii": True,
    "tailShares4095Prefix": True,
    "tailLastDifferent": True,
    "oversizeShares4096Prefix": True,
}
SCOPE = "Maximum4096 / oversize4097 URL-safe ASCII password REST observation under recorded schema1 ENFORCE min6/max4096 policy, no tenant, owned strict artifact and recorded production auth settings. Includes last-character and4095-prefix signin controls, fixed credentials after oversize update and recorded cleanup. auth-password-maximum revision1,21cases; candidate only, not all strings, Unicode, custom policies, SDK/Rules or expiry/revocation/fault-recovery guarantees."
CORPUS = {"slice": "auth-password-maximum", "revision": 1, "cases": list(CASES)}


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
        "# Auth maximum-password boundary observations",
        "",
        "Status: candidate, not approved. Redacted semantic observations, not raw responses or independently signed evidence.",
        "",
        SCOPE,
        "",
        "| Case | Local checks | Production checks | HTTP local / production | Error local / production | Comparison |",
        "|---|---|---|---|---|---|",
    ]
    for local, production in zip(
        value["local"]["cases"], value["production"]["cases"], strict=True
    ):
        same = local == production
        lines.append(
            f"| {local['id']} | {'Matched' if local['passed'] else 'Mismatch'} | {'Matched' if production['passed'] else 'Mismatch'} | {local['httpStatus']} / {production['httpStatus']} | {local.get('observedError', '—')} / {production.get('observedError', '—')} | {'Same projected result' if same else 'Different projections'} |"
        )
    lines.extend(
        [
            "",
            f"Review subject (no approval granted): `{digest(value)}`.",
            "",
            "The initial47-character password works before update. A random4096-character URL-safe ASCII replacement is sent to update and subsequent signin; the old password is rejected. Update-issued ID and refresh tokens are used with lookup. The same update-issued refresh bytes are reused after the4097-character update attempt; the post-attempt state lookup uses the fixed maximum-password signin ID token.",
            "",
            "The tail variant is4096characters and differs only in its final character; the4095-character prefix omits that final character. Both must fail signin as bad credentials, followed by selected-field lookup. The oversize update shares all4096prefix characters with the working password and appends one ASCII character. InputShape binds these lengths, ASCII and relationships without password bytes or hashes.",
            "",
            "Oversize checks require HTTP400 and a finite classified policy-related error, not arbitrary authentication or rate-limit failure. The exact allowlisted observedError is retained and compared separately across targets; matching broad check booleans alone do not establish identical error behavior. Unknown messages become UNCLASSIFIED_ERROR, never copied raw. The code is observed, not inferred from the minimum-length WEAK_PASSWORD rule.",
            "",
            "Successful complete runs prove only these generated inputs under recorded settings. Credential/state failure may leave a private incomplete diagnostic; it is not promoted into complete evidence. Full token signatures, exact revocation timing, elapsed expiry, Unicode counting, every4096-character input, all prefix lengths, custom policy combinations, SDK/Rules and fault-injected recovery remain outside scope.",
            "",
            "Dedicated random account ownership is established by marker/email and independent UID, persisted and read back before updates. Cleanup is by verified UID/email, independent of working credentials; both selectors must report absence. Owned artifact/config hashes, parent-child identity, exit0 and closed listeners are checked. No production policy change is performed.",
            "",
            "Seven token-returning cases across the flow check same-account credentials and expiry format/3600 separately. Selected state includes localId,email,emailVerified,displayName,photoUrl,disabled with presence/type distinctions; credential metadata is excluded. Raw passwords/tokens/UID/email are never public, and these semantic projections remain recorder testimony.",
            "",
            "[Source and case mapping](../../spec/compatibility/evidence/auth-password-maximum/source-review.json) · [Redacted receipt](../../spec/compatibility/evidence/auth-password-maximum/receipt.json). Prior snapshots retain their acquisition hashes/dates; prior evidence and approvals are unchanged. This candidate does not inherit any approval.",
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
