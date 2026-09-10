"""Validate and publish the bounded, explicitly redacted Auth revision 2 receipt."""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/auth-password"))
sys.path.insert(0, str(ROOT / "tools/compat-inventory"))
from evidence_common import runtime_inputs
from password_contract import CASES, complete, require, validate_case
from password_recorder import PASSWORD_POLICY, digest, inputs

BUNDLE = ROOT / "spec/compatibility/evidence/auth-password/receipt.json"
REVIEW = ROOT / "spec/compatibility/evidence/auth-password/source-review.json"
PAGE = ROOT / "docs/compatibility/auth-password.md"
SCOPE = "Password change REST using fresh end-user tokens; no tenant; strict owned local artifact and recorded production configuration; auth-password corpus revision 1 only. Production requires improved email privacy, omitted admin passwordPolicyConfig and explicit client policy schema 1 / ENFORCE / length 6-4096. Redacted semantic observations, not independent JWT verification, revocation timing, expired-token enforcement, recent-login boundaries, password-policy boundaries, SDK, MFA, Rules or public npm compatibility."
CORPUS = {"slice": "auth-password", "revision": 1, "cases": list(CASES)}


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
            instance["wrongTokenStatus"] == 403
            and instance["profile"] == "strict"
            and instance["version"] == artifact["version"]
        )
        hex_value(instance["nonce"], 32)


def render(value):
    validate(value)
    lines = [
        "# Auth password change observations",
        "",
        "Status: candidate, not approved. These are redacted semantic observations, not retained raw responses or a signed attestation.",
        "",
        SCOPE,
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
            f"Review subject (no approval granted): `{digest(value)}`.",
            "",
            "The original random password is proven by baseline signin before accounts:update changes it to a distinct random password with returnSecureToken=true. The update response ID token is used for lookup; its refresh token is used for refresh and a further lookup. The old password is expected to fail with HTTP400 INVALID_LOGIN_CREDENTIALS under the recorded improved-email-privacy setting. The new password must sign in as the same UID and its ID token must retrieve that account.",
            "",
            "Five token-returning cases independently check positive-integer expiry format and the 3600-second expectation. This does not prove elapsed-expiry rejection, token signatures, old-token revocation timing or recent-login limits. Lookup comparisons cover localId, email, emailVerified, displayName, photoUrl and disabled with JSON presence/type distinctions. Password hashes, passwordUpdatedAt, validSince, lastLoginAt and provider synchronization are not part of the unchanged-state claim.",
            "",
            "Passwords, tokens, password hashes, UID and email are never published. Selected-field comparisons and token use are recorder testimony; third parties cannot independently reconstruct the raw responses. Source snapshots retain acquisition hashes and times; the recorded client password policy is explicit, not inferred from omitted admin configuration. Custom policies outside the fixed preflight are unsupported by this recorder, not excluded from future compatibility work.",
            "",
            "[Source and case mapping](../../spec/compatibility/evidence/auth-password/source-review.json) · [Redacted receipt](../../spec/compatibility/evidence/auth-password/receipt.json). This subject binds corpus, source review, probe/publication code, artifact/build/configuration and process exit.",
            "",
            "Admin APIs only establish dedicated-account ownership and cleanup. Bootstrap marker/email and independent UID lookup precede persisted UID readback and any credential mutation. Cleanup uses verified UID/email independently of working passwords; recovered UID is persisted before deletion. Both selectors must confirm absence. Normal cleanup does not prove recovery under injected communication loss or forced termination.",
            "",
            "No human approval is inferred from either target matching. Existing Auth basic, photoUrl, displayName and aggregation approvals are unchanged and do not cover this new subject. Password reset, SDK, MFA, tenants, policy boundaries and full Auth compatibility remain separate verification targets.",
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
