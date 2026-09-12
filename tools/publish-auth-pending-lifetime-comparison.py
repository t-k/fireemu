"""Publish the local-versus-production comparison of the auth-pending-lifetime corpus.

The recorded production receipt is read, never rewritten. The private local report is
projected to allowlisted fields, its full execution-dependency set is bound to the commit
that produced it, and the two are compared row by row on their semantic projection, which
excludes elapsed timing and the measured pending and session ages.
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/auth-pending-lifetime"))
sys.path.insert(0, str(ROOT / "tools/compat-inventory"))
from lifetime_contract import (
    CASES,
    CORPUS,
    DIAGNOSTIC,
    complete,
    lifetime_summary,
    require,
    semantic_rows,
    validate_row,
)
from lifetime_recorder import digest

RECEIPT = ROOT / "spec/compatibility/evidence/auth-pending-lifetime/receipt.json"
BUNDLE = (
    ROOT / "spec/compatibility/evidence/auth-pending-lifetime/local-comparison.json"
)
PAGE = ROOT / "docs/compatibility/auth-pending-lifetime-comparison.md"
SCOPE = "Row-by-row comparison of the recorded production observations of auth-pending-lifetime with one run of the same corpus on an owned local fireemu artifact (strict profile, --only auth, no configuration change, codes read from the emulator inspection route, pendings aged by advancing the virtual clock). Semantic projections exclude elapsed milliseconds and the measured pending and session ages. A comparison record, not a new production run, not an approval, and not a claim beyond these eight cases."
RECORDER_FILES = (
    "tools/auth-pending-lifetime/lifetime_contract.py",
    "tools/auth-pending-lifetime/lifetime_recorder.py",
    "tools/auth-pending-lifetime/lifetime_owned.py",
    "tools/auth-pending-revocation/revocation_recorder.py",
    "tools/auth-pending-revocation/revocation_contract.py",
    "tools/auth-password-maximum/maximum_contract.py",
    "tools/auth-password-maximum/maximum_recorder.py",
    "tools/compat-inventory/owned_runner.py",
    "tools/compat-inventory/evidence_common.py",
)
LOCAL_PROJECTED = (
    "target",
    "recordedAt",
    "probeSourceCommit",
    "agingMode",
    "budget",
    "accountsUsed",
    "stopReason",
    "requestCount",
    "wallElapsedSeconds",
    "configHoldSeconds",
    "cases",
    "setup",
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


def recorded_with(report, recorder_commit):
    hex_value(recorder_commit, 40)
    inputs = {path: report["probeInputs"][path] for path in RECORDER_FILES}
    for path, value in inputs.items():
        hex_value(value)
        require(git_blob_sha256(recorder_commit, path) == value)
    return {"recorderCommit": recorder_commit, "recorderInputs": inputs}


def project_local(report, recorder_commit, runtime_commit):
    require("childCleanupFailure" not in report and "failure" not in report)
    require(
        report["schemaVersion"] == 1
        and report["acceptance"] == "candidate"
        and report["target"] == "local"
        and report["agingMode"] == "virtual-clock"
        and report["connection"] == "owned-artifact"
        and report["project"] == "fireemu-35fe6"
        and report["projectNumber"] is None
        and digest(report["corpus"]) == digest(CORPUS)
        and complete(report)
    )
    out = {key: report[key] for key in LOCAL_PROJECTED}
    out["configuration"] = exact_keys(report["configuration"], CONFIG_KEYS)
    out["artifact"] = exact_keys(report["artifact"], ARTIFACT_KEYS)
    out["ownedProcess"] = exact_keys(report["ownedProcess"], PROCESS_KEYS)
    out["instance"] = exact_keys(report["instance"], INSTANCE_KEYS)
    out["build"] = {key: report["build"][key] for key in BUILD_KEYS}
    out["lifetimeSummary"] = lifetime_summary(report)
    out["privateReportSha256"] = digest(report)
    hex_value(runtime_commit, 40)
    out["runtimeInputsCommit"] = runtime_commit
    out["recordedWith"] = recorded_with(report, recorder_commit)
    validate_local(out)
    return out


def validate_local(local):
    require(
        set(local)
        == set(LOCAL_PROJECTED)
        | {
            "configuration",
            "artifact",
            "ownedProcess",
            "instance",
            "build",
            "lifetimeSummary",
            "privateReportSha256",
            "recordedWith",
            "runtimeInputsCommit",
        }
    )
    require(
        local["target"] == "local"
        and local["agingMode"] == "virtual-clock"
        and local["connection"] == "owned-artifact"
    )
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
        validate_row(row, name)
    require(local["lifetimeSummary"] == lifetime_summary(local))
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
        rows.append(
            {
                "id": production["id"],
                "sameSemanticProjection": semantic_rows([production])
                == semantic_rows([local]),
            }
        )
    return rows


def validate(value):
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
        and value["scope"] == SCOPE
    )
    receipt = json.loads(RECEIPT.read_bytes())
    require(value["productionSubjectSha256"] == digest(receipt))
    require(value["publicationContractSha256"] == publication_contract_sha())
    validate_local(value["local"])
    require(
        value["comparison"]
        == compare(receipt["production"]["cases"], value["local"]["cases"])
    )
    return receipt


def render(value):
    receipt = validate(value)
    production = {r["id"]: r for r in receipt["production"]["cases"]}
    local = {r["id"]: r for r in value["local"]["cases"]}
    prod_summary = receipt["production"]["lifetimeSummary"]
    local_summary = value["local"]["lifetimeSummary"]
    lines = [
        "# MFA pending credential lifetime: local comparison",
        "",
        "Status: candidate comparison record, not approved. The production record is unchanged; this page adds one owned local run and compares the two row by row.",
        "",
        SCOPE,
        "",
        "| Case | Basis | Production outcome / error | Local outcome / error | Same semantic projection |",
        "| --- | --- | --- | --- | --- |",
    ]
    differing = []
    for row in value["comparison"]:
        p, loc = production[row["id"]], local[row["id"]]
        basis = "diagnostic" if row["id"] in DIAGNOSTIC else "control"
        pout = (
            "skipped"
            if p["skipped"]
            else f"{p['outcome']} / {p['observedError'] or 'none'}"
        )
        lout = (
            "skipped"
            if loc["skipped"]
            else f"{loc['outcome']} / {loc['observedError'] or 'none'}"
        )
        lines.append(
            f"| {row['id']} | {basis} | {pout} | {lout} | {row['sameSemanticProjection']} |"
        )
        if not row["sameSemanticProjection"]:
            differing.append(row["id"])
    lines.extend(
        [
            "",
            f"Differing rows: {', '.join(differing) if differing else 'none'}.",
            "",
            f"Production lifetime: usable {prod_summary['usableAges'] or 'none'}, refused {prod_summary['refusedAges'] or 'none'}, lower bound {prod_summary['lowerBoundSeconds']} s. Local (owned artifact, virtual clock): usable {local_summary['usableAges'] or 'none'}, refused {local_summary['refusedAges'] or 'none'}, lower bound {local_summary['lowerBoundSeconds']} s. The measured pending ages themselves are excluded from the semantic comparison; the compared projection is each row's outcome, error and non-age checks.",
            "",
            f"Comparison subject (unapproved): `{digest(value)}`. Production subject compared: `{value['productionSubjectSha256']}`.",
            "",
            f"Local artifact `{value['local']['artifact']['version']}` built from the tree at `{value['local']['runtimeInputsCommit']}` (repository HEAD `{value['local']['runtimeSourceCommit']}` at run time) with recorder files at `{value['local']['recordedWith']['recorderCommit']}`; strict profile, pendings aged by the virtual clock. Owned process exit 0 with listeners closed; every account was deleted with absence confirmation.",
            "",
            "A row that differs is an open gap in the ledger, not a verdict about which side is right. Agreement on the remaining rows is agreement in scope, not compatibility coverage, and a matching lower bound is not a matching exact lifetime.",
            "",
            "[Comparison record](../../spec/compatibility/evidence/auth-pending-lifetime/local-comparison.json) · [Production receipt](../../spec/compatibility/evidence/auth-pending-lifetime/receipt.json) · [Gap ledger](gaps.md).",
            "",
        ]
    )
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local", type=Path)
    parser.add_argument("--recorder-commit")
    parser.add_argument("--runtime-commit")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.local:
        require(
            bool(args.recorder_commit)
            and bool(args.runtime_commit)
            and not args.check
            and not BUNDLE.exists()
        )
        receipt = json.loads(RECEIPT.read_bytes())
        local = project_local(
            json.loads(args.local.read_bytes()),
            args.recorder_commit,
            args.runtime_commit,
        )
        value = {
            "schemaVersion": 1,
            "acceptance": "candidate",
            "scope": SCOPE,
            "productionSubjectSha256": digest(receipt),
            "publicationContractSha256": publication_contract_sha(),
            "local": local,
            "comparison": compare(receipt["production"]["cases"], local["cases"]),
        }
        validate(value)
        BUNDLE.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    value = json.loads(BUNDLE.read_bytes())
    page = render(value)
    if args.check:
        require(PAGE.read_text() == page)
    else:
        PAGE.write_text(page)
    print("Auth pending-lifetime comparison checked; subject " + digest(value))
