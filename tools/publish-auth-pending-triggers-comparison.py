"""Publish the local-versus-production comparison of one AUTH-U04 trigger corpus.

The approved production receipt is read, never rewritten. The private local report is
projected to allowlisted fields, its recorder and runtime inputs are bound to the commits
that produced them, and the two are compared row by row on their semantic projection
(elapsed milliseconds excluded). One record per trigger, with its own subject.
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/auth-pending-triggers"))
sys.path.insert(0, str(ROOT / "tools/compat-inventory"))
from triggers_contract import (  # noqa: E402
    CASES,
    DIAGNOSTIC,
    TRIGGERS,
    complete,
    corpus,
    require,
    semantic_rows,
    validate_row,
)
from triggers_recorder import digest  # noqa: E402

EVID = ROOT / "spec/compatibility/evidence"
RECORDER_FILES = (
    "tools/auth-pending-triggers/triggers_contract.py",
    "tools/auth-pending-triggers/triggers_recorder.py",
    "tools/auth-pending-revocation/revocation_recorder.py",
)
LOCAL_PROJECTED = (
    "target",
    "recordedAt",
    "probeSourceCommit",
    "trigger",
    "cases",
    "setup",
    "providerLinked",
    "cleanup",
    "connection",
    "runtimeSourceCommit",
)
CONFIG_KEYS = ("value", "sha256", "fileSha256")
ARTIFACT_KEYS = ("sha256", "version", "kind")
PROCESS_KEYS = ("pid", "exitCode", "stopped", "listenersClosed")
INSTANCE_KEYS = (
    "parentPid",
    "childPid",
    "nonce",
    "profile",
    "version",
    "wrongTokenStatus",
)
BUILD_KEYS = ("command", "exitCode", "artifactSha256", "inputs")
RUNTIME_INPUT_ROOTS = (
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    ".cargo",
    "crates",
)


def receipt_path(trigger):
    return EVID / f"auth-pending-trigger-{trigger}/receipt.json"


def bundle_path(trigger):
    return EVID / f"auth-pending-trigger-{trigger}/local-comparison.json"


def page_path(trigger):
    return ROOT / f"docs/compatibility/auth-pending-trigger-{trigger}-comparison.md"


def scope(trigger):
    return (
        f"Row-by-row comparison of the approved production record of the {trigger} trigger "
        "(auth-pending-trigger) with one run of the same corpus on an owned local fireemu "
        "artifact (strict profile, --only auth, no configuration change, codes read from the "
        "emulator inspection route). Semantic projections exclude elapsed milliseconds. This "
        "is a comparison record, not a new production run, not an approval, and not a claim "
        "that the local artifact matches on anything outside these seven cases or for any "
        "other trigger."
    )


def hex_value(value, length=64):
    require(
        isinstance(value, str) and re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value)
    )


def exact_keys(value, keys):
    require(isinstance(value, dict) and set(value) == set(keys))
    return {key: value[key] for key in keys}


def git_blob_sha256(commit, path):
    blob = subprocess.check_output(
        ["git", "show", f"{commit}:{path}"], cwd=ROOT, stderr=subprocess.DEVNULL
    )
    return hashlib.sha256(blob).hexdigest()


def working_tree_sha256(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def runtime_inputs_at(commit):
    names = subprocess.check_output(
        ["git", "ls-tree", "-r", "--name-only", commit, "--", *RUNTIME_INPUT_ROOTS],
        cwd=ROOT,
        stderr=subprocess.DEVNULL,
        text=True,
    ).split("\n")
    return {
        name: git_blob_sha256(commit, name) for name in sorted(n for n in names if n)
    }


def publication_contract_sha():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def project_local(report, trigger, recorder_commit, runtime_commit):
    require("childCleanupFailure" not in report and "failure" not in report)
    require(
        report["schemaVersion"] == 1
        and report["acceptance"] == "candidate"
        and report["target"] == "local"
        and report["connection"] == "owned-artifact"
        and report["project"] == "fireemu-35fe6"
        and report["projectNumber"] is None
        and report["trigger"] == trigger
        and digest(report["corpus"]) == digest(corpus(trigger))
        and complete(report)
    )
    out = {key: report[key] for key in LOCAL_PROJECTED}
    out["configuration"] = exact_keys(report["configuration"], CONFIG_KEYS)
    out["artifact"] = exact_keys(report["artifact"], ARTIFACT_KEYS)
    out["ownedProcess"] = exact_keys(report["ownedProcess"], PROCESS_KEYS)
    out["instance"] = exact_keys(report["instance"], INSTANCE_KEYS)
    out["build"] = {key: report["build"][key] for key in BUILD_KEYS}
    out["privateReportSha256"] = digest(report)
    hex_value(recorder_commit, 40)
    hex_value(runtime_commit, 40)
    out["runtimeInputsCommit"] = runtime_commit
    inputs = {path: report["probeInputs"][path] for path in RECORDER_FILES}
    for path, value in inputs.items():
        require(git_blob_sha256(recorder_commit, path) == value)
    out["recordedWith"] = {"recorderCommit": recorder_commit, "recorderInputs": inputs}
    validate_local(out, trigger)
    return out


def validate_local(local, trigger):
    require(
        set(local)
        == set(LOCAL_PROJECTED)
        | {
            "configuration",
            "artifact",
            "ownedProcess",
            "instance",
            "build",
            "privateReportSha256",
            "recordedWith",
            "runtimeInputsCommit",
        }
    )
    require(local["target"] == "local" and local["connection"] == "owned-artifact")
    require(local["trigger"] == trigger)
    require(
        complete(
            {
                **local,
                "status": "observed",
                "configRestored": True,
                "configDigestMatches": True,
            }
        )
    )
    for row, name in zip(local["cases"], CASES, strict=True):
        validate_row(row, name, trigger)
    hex_value(local["probeSourceCommit"], 40)
    hex_value(local["runtimeSourceCommit"], 40)
    hex_value(local["privateReportSha256"])
    config = exact_keys(local["configuration"], CONFIG_KEYS)
    require(config["value"] == {"schemaVersion": 1, "profile": "strict"})
    require(config["sha256"] == digest(config["value"]))
    hex_value(config["fileSha256"])
    artifact = exact_keys(local["artifact"], ARTIFACT_KEYS)
    require(artifact["kind"] == "local-build")
    require(
        isinstance(artifact["version"], str)
        and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", artifact["version"])
    )
    hex_value(artifact["sha256"])
    build = exact_keys(local["build"], BUILD_KEYS)
    require(
        build["command"]
        == ["cargo", "build", "--locked", "-p", "fireemu", "--message-format=json"]
        and build["exitCode"] == 0
        and build["artifactSha256"] == artifact["sha256"]
        and build["inputs"] == runtime_inputs_at(local["runtimeInputsCommit"])
    )
    hex_value(local["runtimeInputsCommit"], 40)
    process = exact_keys(local["ownedProcess"], PROCESS_KEYS)
    instance = exact_keys(local["instance"], INSTANCE_KEYS)
    require(
        process["exitCode"] == 0
        and process["stopped"] is True
        and process["listenersClosed"] is True
    )
    require(
        instance["parentPid"] == process["pid"]
        and instance["childPid"] != process["pid"]
    )
    require(instance["wrongTokenStatus"] == 403 and instance["profile"] == "strict")
    require(instance["version"] == artifact["version"])
    hex_value(instance["nonce"], 32)
    recorded = exact_keys(local["recordedWith"], ("recorderCommit", "recorderInputs"))
    hex_value(recorded["recorderCommit"], 40)
    inputs = exact_keys(recorded["recorderInputs"], RECORDER_FILES)
    for path, value in inputs.items():
        require(git_blob_sha256(recorded["recorderCommit"], path) == value)


def compare(production_rows, local_rows):
    rows = []
    for production, local in zip(production_rows, local_rows, strict=True):
        require(production["id"] == local["id"])
        same = semantic_rows([production]) == semantic_rows([local])
        rows.append({"id": production["id"], "sameSemanticProjection": same})
    return rows


def validate(value, trigger):
    require(
        set(value)
        == {
            "schemaVersion",
            "acceptance",
            "scope",
            "productionSubjectSha256",
            "publicationContractSha256",
            "local",
            "comparison",
        }
    )
    require(
        value["schemaVersion"] == 1
        and value["acceptance"] == "candidate"
        and value["scope"] == scope(trigger)
    )
    receipt = json.loads(receipt_path(trigger).read_bytes())
    require(value["productionSubjectSha256"] == digest(receipt))
    require(value["publicationContractSha256"] == publication_contract_sha())
    validate_local(value["local"], trigger)
    require(
        value["comparison"]
        == compare(receipt["production"]["cases"], value["local"]["cases"])
    )
    return receipt


def render(value, trigger):
    receipt = validate(value, trigger)
    production = {r["id"]: r for r in receipt["production"]["cases"]}
    local = {r["id"]: r for r in value["local"]["cases"]}
    lines = [
        f"# Held MFA pending credential across {trigger}: local comparison",
        "",
        "Status: candidate comparison record, not approved. The approved production record is unchanged; this page adds one run of the same corpus on an owned local artifact and compares the two row by row.",
        "",
        scope(trigger),
        "",
        "| Case | Basis | Production outcome / error | Local outcome / error | Same semantic projection |",
        "| --- | --- | --- | --- | --- |",
    ]
    differing = []
    for row in value["comparison"]:
        p, loc = production[row["id"]], local[row["id"]]
        basis = "diagnostic" if row["id"] in DIAGNOSTIC else "control"
        lines.append(
            f"| {row['id']} | {basis} | {p['outcome']} / {p['observedError'] or 'none'} | {loc['outcome']} / {loc['observedError'] or 'none'} | {row['sameSemanticProjection']} |"
        )
        if not row["sameSemanticProjection"]:
            differing.append(row["id"])
    lines.extend(
        [
            "",
            f"Differing rows: {', '.join(differing) if differing else 'none'}.",
            "",
            f"Comparison subject (unapproved): `{digest(value)}`. Production subject compared: `{value['productionSubjectSha256']}`.",
            "",
            f"Local artifact `{value['local']['artifact']['version']}` built from the tree at `{value['local']['runtimeInputsCommit']}` (repository HEAD `{value['local']['runtimeSourceCommit']}` at run time) with recorder files at `{value['local']['recordedWith']['recorderCommit']}`; strict profile. Owned process exit 0 with listeners closed; the account was deleted with absence confirmation.",
            "",
            "The local run has no configuration change and reads phone codes from the emulator inspection route, so the configuration fields of the local report are placeholders. A row that differs is an open gap in the ledger, not a verdict about which side is right; agreement on these seven rows is agreement in scope, not compatibility coverage.",
            "",
            f"[Comparison record](../../spec/compatibility/evidence/auth-pending-trigger-{trigger}/local-comparison.json) · [Approved production receipt](../../spec/compatibility/evidence/auth-pending-trigger-{trigger}/receipt.json) · [Gap ledger](gaps.md).",
            "",
        ]
    )
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trigger", required=True, choices=TRIGGERS)
    parser.add_argument("--local", type=Path)
    parser.add_argument("--recorder-commit")
    parser.add_argument("--runtime-commit")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    trigger = args.trigger
    if args.local:
        require(
            bool(args.recorder_commit)
            and bool(args.runtime_commit)
            and not args.check
            and not bundle_path(trigger).exists()
        )
        receipt = json.loads(receipt_path(trigger).read_bytes())
        local = project_local(
            json.loads(args.local.read_bytes()),
            trigger,
            args.recorder_commit,
            args.runtime_commit,
        )
        value = {
            "schemaVersion": 1,
            "acceptance": "candidate",
            "scope": scope(trigger),
            "productionSubjectSha256": digest(receipt),
            "publicationContractSha256": publication_contract_sha(),
            "local": local,
            "comparison": compare(receipt["production"]["cases"], local["cases"]),
        }
        validate(value, trigger)
        bundle_path(trigger).write_text(
            json.dumps(value, sort_keys=True, indent=2) + "\n"
        )
    value = json.loads(bundle_path(trigger).read_bytes())
    page = render(value, trigger)
    if args.check:
        require(page_path(trigger).read_text() == page)
    else:
        page_path(trigger).write_text(page)
    print(
        f"Auth pending trigger {trigger} comparison checked; subject " + digest(value)
    )
