"""Validate and publish bounded, redacted REST session-token diagnostics."""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/auth-session-token"))
sys.path.insert(0, str(ROOT / "tools/compat-inventory"))
from evidence_common import runtime_inputs
from session_contract import (
    CASES,
    CORPUS,
    SAMPLES,
    complete,
    integer,
    require,
    validate_case,
)
from session_recorder import PASSWORD_POLICY, digest, inputs

BUNDLE = ROOT / "spec/compatibility/evidence/auth-session-token/receipt.json"
REVIEW = ROOT / "spec/compatibility/evidence/auth-session-token/source-review.json"
PAGE = ROOT / "docs/compatibility/auth-session-token.md"
SCOPE = "Diagnostic REST observation of frozen pre-change A/B ID and refresh tokens after session A changes the password, with changed-response token controls. No tenant; strict owned local artifact; recorded production authentication/password policy; auth-session-token revision 1. Target offsets 0/10/30 seconds, request-start deadline 45 seconds. No universal immediate-revocation oracle, SDK checkRevoked, Rules, elapsed expiry, same-second boundary, whole-session lineage, physical-device or public npm claim."


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
        for key in [
            "target",
            "recordedAt",
            "probeSourceCommit",
            "cases",
            "cleanup",
            "status",
            "timing",
        ]
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
            "status",
            "timing",
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
        require(
            isinstance(report["cleanup"], dict)
            and set(report["cleanup"]) == {"uidAbsent", "emailAbsent"}
        )
        require(all(item is True for item in report["cleanup"].values()))
        require(len(report["cases"]) == len(CASES))
        for row, name in zip(report["cases"], CASES, strict=True):
            validate_case(row, name)
        validate_timing(report)
        require(complete(report))
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


def validate_timing(report):
    timing = report["timing"]
    require(
        isinstance(timing, dict)
        and set(timing)
        == {
            "sessionsSeparated",
            "issueGapMs",
            "preChangeWaitMs",
            "mutationStartMs",
            "mutationEndMs",
            "latestPreIssuedAt",
            "changedIssuedAt",
            "orderEstablished",
        }
    )
    require(timing["sessionsSeparated"] is True and timing["orderEstablished"] is True)
    require(
        integer(timing["issueGapMs"], 2000, 600000)
        and integer(timing["preChangeWaitMs"], 3000, 600000)
    )
    require(
        integer(timing["mutationStartMs"], 0, 600000)
        and integer(timing["mutationEndMs"], timing["mutationStartMs"], 600000)
    )
    rows = report["cases"]
    require(timing["issueGapMs"] == rows[2]["startMs"] - rows[1]["primaryEndMs"])
    require(timing["preChangeWaitMs"] == rows[9]["startMs"] - rows[8]["endMs"])
    prior = rows[:9]
    latest = max(
        row["response"]["tokenTime"]["iat"]
        for row in prior
        if row["response"].get("tokenTime") is not None
    )
    changed = rows[9]
    require(all(row["quality"] == "observed" for row in rows[:10]))
    require(
        timing["latestPreIssuedAt"] == latest and integer(timing["latestPreIssuedAt"])
    )
    require(
        timing["changedIssuedAt"] == changed["response"]["tokenTime"]["iat"]
        and integer(timing["changedIssuedAt"])
    )
    require(
        timing["changedIssuedAt"] > latest
        and timing["mutationStartMs"] == changed["startMs"]
    )
    require(timing["mutationEndMs"] >= changed["endMs"])


def signature(row):
    return (
        row["response"]["outcome"],
        row["response"]["error"],
        None
        if row["followup"] is None
        else (row["followup"]["outcome"], row["followup"]["error"]),
    )


def comparison(local, production, controls):
    if (
        not controls
        or local["quality"] != "observed"
        or production["quality"] != "observed"
    ):
        return "Inconclusive (controls/timing)"
    return (
        "Same observed result"
        if signature(local) == signature(production)
        else "Different observations"
    )


def round_controls(value, name):
    if name not in SAMPLES:
        return all(value[t]["status"] == "observed" for t in ("local", "production"))
    offset = name.split("@")[1]
    return all(
        row["quality"] == "observed"
        for target in ("local", "production")
        for row in value[target]["cases"]
        if row["id"]
        in {
            f"changed-id@{offset}",
            f"changed-refresh@{offset}",
            "new-password-signin",
            "new-password-lookup",
        }
    )


def result_text(row):
    primary = row["response"]
    label = primary["outcome"] + (f" ({primary['error']})" if primary["error"] else "")
    if row["followup"] is not None:
        label += " / issued-ID lookup: " + row["followup"]["outcome"]
    return label


def render(value):
    validate(value)
    lines = [
        "# Auth session token diagnostic observations",
        "",
        "Status: candidate, not approved. Observed agreement is not a universal revocation guarantee or a feature-completion claim.",
        "",
        SCOPE,
        "",
        "| Observation | Local | Production | Comparison | Actual interval ms (local / production) |",
        "|---|---|---|---|---|",
    ]
    for local, production in zip(
        value["local"]["cases"], value["production"]["cases"], strict=True
    ):
        label = comparison(local, production, round_controls(value, local["id"]))
        lines.append(
            f"| {local['id']} | {result_text(local)} | {result_text(production)} | {label} | {local['startMs']}–{local['endMs']} / {production['startMs']}–{production['endMs']} |"
        )
    lines.extend(
        [
            "",
            f"Review subject (no approval granted): `{digest(value)}`.",
            "",
            "Baseline and final control intervals are measured from recorder start; @offset samples are measured from the completed password-change response. Each request records actual start/end and refresh-derived lookup intervals. Sample starts more than 2000ms late, completion beyond 45000ms, missing samples or failed fresh controls are inconclusive. The schedule never extends until rejection. A difference between timed observations is not automatically a runtime incompatibility or an exact revocation-latency measurement.",
            "",
            "A and B are two REST signin credential sets for one dedicated account, separated before the change; they are not proven physical devices. Each original refresh token is used twice before mutation; the original ID and refresh bytes remain fixed afterward. Refresh rotation is recorded as a boolean, never substituted into the observed input. Successful refresh and successful use of its issued ID token are separate results. Exact-byte reuse is recorder testimony; token values and token digests are not public.",
            "",
            "Session A performs accounts:update. Fresh changed-response ID and refresh credentials are sampled as controls, and replacement-password signin/lookup is checked after the window. Missing/control-invalid results do not establish conformance. No rejection within the window does not mean permanent validity. Frozen-token replay does not describe every token in a rotated session lineage. There is no no-password-change longitudinal control in this slice.",
            "",
            "Timing claims iat/auth_time are decoded without signature verification and are published only as bounded numeric metadata. The recorder waits at least three monotonic seconds after baseline issuance, and requires the changed token's iat to exceed all pre-change issued iat values. validSince readback is advisory, not the oracle for REST acceptance. Same-second, SDK verifyIdToken/checkRevoked, Rules and actual elapsed-expiry tests are separate work.",
            "",
            "HTTP requests have a five-second socket/processing budget; transport libraries do not provide a hard real-time cancellation guarantee. No new primary or refresh-derived lookup starts at/after the 45-second sampling deadline. In-flight workers drain before account cleanup, which has separate bounded request timeouts. Timing overruns cannot be re-labelled on-time success. Normal cleanup does not prove forced-termination/network-loss recovery.",
            "",
            "[Source and case mapping](../../spec/compatibility/evidence/auth-session-token/source-review.json) · [Redacted receipt](../../spec/compatibility/evidence/auth-session-token/receipt.json). The subject binds code, source review, corpus, artifact/configuration and owned-process exit. Raw tokens, passwords, account identifiers and responses are not published. No human approval is inferred. Earlier password-change and other approvals remain unchanged.",
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
    print("Auth session token diagnostic checked; subject " + digest(value))
