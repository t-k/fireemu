"""Offline, campaign-specific authority for the immutable September 17 stream run.

Trust roots are reviewed commits and independently recorded byte hashes, never
caller-supplied object/digest pairs. No live lease, clock, credential, or API use.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

FROZEN = "dee737c14e68eb4f546b7ca4c827871fc48a2503"
REPAIRED = "567565bdd654cab00dbb84101edcc7bdc628e230"
PRODUCTION_SHA = "12956fbe82acefc106093eb2cd913ede9092f74aa98bd29f39e795492754b3f3"
PREPARED_SHA = "b43dbf0bffb4ea575467d12fa49727c78d15a34900401bbb9b3d0ebbc29d65d5"
INDEPENDENT_SHA = "1e109b1c84ea127649ae4cfbbc879ffa2301c13407a9dbfda8eb874d76b9a85f"
LOCAL_SHA = "34724f3881f0920c6a3afc14cd735066d5f07e0b25411684e4552c284da142ab"
ARTIFACT_SHA = "e792e0bc1947bbd227b3ee9778eca093cda94fbde767911dd6139a6cbfd90be4"
MANIFEST_SHA = "118f30ad5fc2e0a6ed4c757227b124f34654e77e705bc2ef13443c656898501c"
HERE = Path(__file__).resolve().parent


def require(condition, label):
    if not condition:
        raise ValueError(label)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require_hash(raw, expected, label):
    require(sha(raw) == expected, label + " digest differs")


def git(root, *args):
    git_path = shutil.which("git")
    require(git_path is not None, "Git executable is unavailable")
    git_executable = Path(git_path).resolve(strict=True)
    env = {
        "PATH": str(git_executable.parent),
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ATTR_NOSYSTEM": "1",
    }
    return subprocess.check_output(
        [
            str(git_executable),
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.attributesFile=/dev/null",
            "-C",
            str(root),
            *args,
        ],
        env=env,
    )


def source_checkout(path, commit):
    require(
        git(path, "rev-parse", "HEAD").decode().strip() == commit,
        "source commit differs",
    )
    require(
        not git(
            path,
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            commit,
            "--",
            "tools",
        ),
        "validator source differs",
    )
    require(
        not git(path, "ls-files", "--others", "--exclude-standard", "tools"),
        "untracked validator source",
    )


def compare_saved(root):
    root = Path(root).resolve()
    frozen = root / ".worktree/stream-credential-preparation"
    repaired = root / ".worktree/stream-repair-shadow"
    source_checkout(frozen, FROZEN)
    source_checkout(repaired, REPAIRED)
    snapshots = {}

    def raw(path, expected=None):
        path = Path(path).resolve()
        value = path.read_bytes()
        if expected:
            require_hash(value, expected, path.name)
        require(
            path not in snapshots or snapshots[path] == value,
            "input changed during validation",
        )
        snapshots[path] = value
        return value

    def load(path, expected=None):
        return json.loads(raw(path, expected))

    sys.path.insert(0, str(frozen / "tools/compat-broad/fs-write-txn"))
    import stream_production as p  # isort: skip

    import credential_prep as cp
    from broad_contract import digest
    from stream_bridge import grpc_code

    require(
        Path(p.__file__).resolve().is_relative_to(frozen), "unexpected validator import"
    )
    base = root / "docs.local/logs/2026-09-17"
    original = base / "stream-production-preflight"
    execution = original / "execution-dee737c14"
    new = base / "stream-repair-shadow-567565bdd"
    production = load(execution / "receipt.json", PRODUCTION_SHA)
    prepared = load(original / "approved-prepared-inputs-dee.json", PREPARED_SHA)
    independent = load(
        original / "independent-comparison-dee737c14.json", INDEPENDENT_SHA
    )
    local = load(new / "owned-run/receipt.json", LOCAL_SHA)
    manifest = load(new / "run-manifest.json", MANIFEST_SHA)
    verification = load(new / "verification.json")
    old = load(
        prepared["bindings"]["localReceiptPath"],
        prepared["bindings"]["localReceiptSha256"],
    )
    raw(prepared["bindings"]["artifactPath"], prepared["bindings"]["artifactSha256"])
    raw(new / "fireemu-567565bdd", ARTIFACT_SHA)
    raw(new / "owned-run/fireemu", ARTIFACT_SHA)
    permission = load(prepared["permissionPath"])
    require(
        permission == prepared["permission"]
        and digest(permission) == prepared["permissionDigest"],
        "permission binding",
    )
    require(prepared["bindings"]["frozenCommit"] == FROZEN, "frozen commit")
    require(
        p.stream_bridge.source_digest() == prepared["bindings"]["sourceDigest"],
        "frozen source",
    )
    comparator = raw(
        frozen / "tools/compat-broad/fs-write-txn/stream_comparison.mjs",
        prepared["bindings"]["comparatorSha256"],
    )
    require(
        raw(HERE.parent / "fs-write-txn/stream_comparison.mjs") == comparator,
        "kernel v1 source differs",
    )
    require(
        prepared["manifest"]
        == p.manifest(
            permission["nonce"], permission["ownerId"], permission["credentialMode"]
        ),
        "frozen manifest",
    )
    require(
        prepared["plan"]
        == p.prepared_plan(
            permission["nonce"], permission["ownerId"], digest(permission)
        ),
        "frozen plan",
    )
    require(
        prepared["comparisonContract"] == p.comparison_contract(prepared["plan"]),
        "comparison contract",
    )

    def validate_acquisition(receipt, directory, is_production):
        gate = receipt["gate"]
        require(receipt["kind"] == "stream-prepared-execution-v1", "outer receipt kind")
        for flag in [
            "acquisitionValidated",
            "reservationReleased",
            "configurationUnchanged",
        ]:
            require(receipt[flag] is True, flag)
        require(
            receipt["failures"] == []
            and receipt["productionExecuted"] is is_production,
            "execution facts",
        )
        require(gate == load(directory / "gate/state.json"), "saved gate differs")
        require(gate["planDigest"] == digest(gate["plan"]), "plan digest")
        p.stream_bridge.validate_plan(gate["plan"])
        p.stream_bridge.validate_absence(gate, "stream")
        p.metadata_valid(gate)
        require(
            gate["coordinatorInflight"] is False
            and type(gate["coordinatorDone"]) is int
            and gate["coordinatorDone"] == gate["plan"]["coordinatorRequests"],
            "coordinator incomplete",
        )
        for job in gate["jobs"].values():
            require(
                job["stopped"]
                and not job["inflight"]
                and set(job["absent"]) == set(job["resources"]),
                "cleanup incomplete",
            )
        nodes = set()

        def visit(value):
            if isinstance(value, dict):
                nodes.add(digest(value))
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        visit(receipt["collection"])
        require(len(gate["events"]) == 23, "data event count")
        for event in gate["events"]:
            response = event["receipt"]
            require(event["completed"] and not event.get("failure"), "incomplete event")
            require(event["responseDigest"] == digest(response), "response digest")
            require(
                event["requestDigest"] == response["requestDigest"], "request digest"
            )
            require(event["grpcCode"] == grpc_code(response["raw"]), "gRPC code")
            require(digest(response["raw"]) in nodes, "event not bound to collection")
        records = {
            name: load(directory / "credential-preparation" / (name + ".json"))
            for name in cp.JOURNAL_FILES
        }
        binding = records["binding"]
        proof = receipt["credentialPreparation"]
        require(
            proof["attempts"] == 2 and proof["journalDigest"] == digest(records),
            "sealed journal",
        )
        require(
            binding["observerSha256"] == p.stream_bridge.source_digest()
            and binding["contractDigest"] == digest(cp.contract()),
            "credential source contract",
        )
        require(records["complete"]["verified"] is True, "preparation incomplete")
        for ordinal, slot in enumerate(["refresh", "tokeninfo"], 1):
            charge, response = records[slot + "-charge"], records[slot + "-receipt"]
            require(
                charge["ordinal"] == ordinal
                and charge["slot"] == slot
                and charge["bindingDigest"] == digest(binding),
                "credential charge",
            )
            require(
                response["chargeDigest"] == digest(charge)
                and response["verified"] is True
                and response["workerReaped"] is True,
                "credential receipt",
            )
        accounting = receipt["outerAccounting"]
        require(accounting["requests"] == gate["total"] + 2 == 33, "request accounting")
        require(
            accounting["costMicrousd"] == gate["costMicrousd"] + 200 == 1303300,
            "cost accounting",
        )
        require(
            accounting["reservationStartedAt"]
            == binding["reservationStartedAt"]
            == proof["reservationStartedAt"],
            "reservation time",
        )
        require(
            0
            < accounting["finishedAt"] - accounting["reservationStartedAt"]
            < cp.OUTER_SECONDS,
            "historical duration",
        )
        return binding

    binding = validate_acquisition(production, execution, True)
    inputs = load(execution / "inputs.json")
    require(
        all(inputs[k] == prepared[k] for k in prepared), "execution prepared inputs"
    )
    require(production["gate"]["plan"] == prepared["plan"], "production plan")
    require(
        permission["issuedAt"]
        <= production["outerAccounting"]["reservationStartedAt"]
        <= production["outerAccounting"]["finishedAt"]
        < permission["expiresAt"],
        "historical permission window",
    )
    ticket = inputs["ticket"]
    ledger = load(Path(ticket["ledgerPath"]) / "state.json")
    reservation = ledger["reservations"][ticket["reservation"]]
    require(
        ledger["identity"] == ticket["ledgerIdentity"] == permission["ledgerIdentity"],
        "ledger identity",
    )
    require(
        reservation["state"] == "released"
        and reservation["finalGateDigest"] == digest(production["gate"]),
        "released final gate",
    )
    require(
        reservation["claim"] == inputs["claim"]
        and reservation["claimDigest"]
        == digest(inputs["claim"])
        == ticket["claimDigest"],
        "claim binding",
    )
    require(
        reservation["envelopeDigest"]
        == digest(inputs["envelope"])
        == ticket["envelopeDigest"],
        "envelope binding",
    )
    require(
        binding["ticketDigest"] == digest(ticket)
        and binding["claimDigest"] == digest(inputs["claim"])
        and binding["permissionDigest"] == digest(permission),
        "credential admission binding",
    )
    original_comparison = p.compare_bound(
        production["collection"], old, prepared["plan"]
    )
    require(
        original_comparison == production["comparison"] == independent["comparison"],
        "original v1 result",
    )
    local_binding = validate_acquisition(local, new / "owned-run/execution", False)
    local_ledger = load(new / "owned-run/ledger/state.json")
    require(len(local_ledger["reservations"]) == 1, "owned reservation count")
    local_id, local_row = next(iter(local_ledger["reservations"].items()))
    require(
        local_row["state"] == "released"
        and local_row["finalGateDigest"] == digest(local["gate"]),
        "owned released gate",
    )
    require(
        local_row["claimDigest"]
        == digest(local_row["claim"])
        == local_binding["claimDigest"],
        "owned claim",
    )
    local_ticket = {
        "ledgerPath": str(new / "owned-run/ledger"),
        "ledgerIdentity": local_ledger["identity"],
        "reservation": local_id,
        "claimDigest": local_row["claimDigest"],
        "envelopeDigest": local_row["envelopeDigest"],
    }
    require(local_binding["ticketDigest"] == digest(local_ticket), "owned ticket")
    require(
        local_binding["permissionDigest"] == local["gate"]["plan"]["permissionDigest"]
        and local_binding["planDigest"] == local["gate"]["planDigest"],
        "owned preparation plan",
    )
    require(
        manifest["executionCommit"]
        == REPAIRED
        == local["ownedArtifact"]["executionCommit"],
        "repaired execution commit",
    )
    require(manifest["build"] == local["ownedArtifact"]["build"], "build receipt")
    require(
        verification["receiptSha256"] == LOCAL_SHA
        and verification["artifactSha256"] == ARTIFACT_SHA
        and verification["buildManifestSha256"] == MANIFEST_SHA,
        "verification binding",
    )
    local_envelope = local_ledger["envelopes"][local_row["envelopeDigest"]]["envelope"]
    require(digest(local_envelope) == local_row["envelopeDigest"], "owned envelope")
    require(
        local_envelope["permissionDigest"] == local_binding["permissionDigest"],
        "owned envelope permission",
    )
    require(
        local_envelope["issuedAt"]
        <= local["outerAccounting"]["reservationStartedAt"]
        < local["outerAccounting"]["finishedAt"]
        < local_envelope["expiresAt"],
        "owned admission window",
    )
    for relative, expected_hash in manifest["build"]["inputs"].items():
        raw(repaired / relative, expected_hash)
    # Run the historical owned-build validator against its actual repaired tree.
    script = 'import sys,json;sys.path.insert(0,"tools/compat-broad/fs-write-txn");from stream_shadow import validate_owned_receipt;validate_owned_receipt(json.load(sys.stdin),sys.argv[1])'
    subprocess.run(
        [sys.executable, "-c", script, ARTIFACT_SHA],
        cwd=repaired,
        input=json.dumps(local),
        text=True,
        check=True,
        capture_output=True,
    )
    p.compare_bound(local["collection"], local, local["gate"]["plan"])
    for module in list(sys.modules.values()):
        module_path = getattr(module, "__file__", None)
        if module_path and Path(module_path).resolve().is_relative_to(frozen / "tools"):
            raw(module_path)
    sources = {
        path.name: raw(path).decode()
        for path in sorted(HERE.iterdir())
        if path.is_file()
    }
    kernel_input = {
        "production": production["collection"],
        "old": old,
        "local": local,
        "permission": permission,
        "v1Source": comparator.decode(),
        "v2Sources": sources,
        "artifact": {"sha256": ARTIFACT_SHA},
        "expected": p.comparison_contract(prepared["plan"]),
    }
    script = """import {compareStreamReceipts} from '../fs-write-txn/stream_comparison.mjs';
import {compareStreamReceiptsV2,v2Digest,v2TextDigest} from './stream_recompare_v2.mjs';
let s='';for await(const c of process.stdin)s+=c;const x=JSON.parse(s);
const compare=outer=>{const expected={...x.expected,local:{projectId:outer.gate.plan.projectId,documentPrefix:outer.gate.plan.documentPrefix}};
const input={production:x.production,local:outer.collection,expected};const v1Comparison=compareStreamReceipts(input);
const binding={permission:x.permission,v1Source:x.v1Source,v1Comparison,v2Sources:x.v2Sources,artifact:x.artifact};
for(const k of ['permission','v1Comparison','v2Sources','artifact'])binding[k+'Sha256']=v2Digest(binding[k]);
binding.v1SourceSha256=v2TextDigest(binding.v1Source);binding.productionReceiptSha256=v2Digest(input.production);binding.localReceiptSha256=v2Digest(input.local);
return compareStreamReceiptsV2({...input,binding});};process.stdout.write(JSON.stringify({oldPair:compare(x.old),newPair:compare(x.local)}));"""
    process = subprocess.run(
        [prepared["plan"]["nodeRuntime"]["path"], "--input-type=module", "-e", script],
        cwd=HERE,
        input=json.dumps(kernel_input),
        text=True,
        capture_output=True,
        check=True,
    )
    comparisons = json.loads(process.stdout)
    require(
        all(x["classification"] != "INDETERMINATE" for x in comparisons.values()),
        "v2 proof incomplete",
    )
    source_checkout(frozen, FROZEN)
    source_checkout(repaired, REPAIRED)
    for path, value in snapshots.items():
        require(path.read_bytes() == value, "snapshot changed during validation")
    return {
        "kind": "stream-saved-authority-v2",
        "acquisitionValidated": True,
        "promotionReady": False,
        "originalComparison": original_comparison,
        **comparisons,
        "bindings": {str(path): sha(value) for path, value in snapshots.items()},
        "fixedCommit": FROZEN,
        "repairedCommit": REPAIRED,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = compare_saved(args.root)
    except Exception as error:  # noqa: BLE001 -- Fail closed without exposing private input contents.
        result = {
            "classification": "INDETERMINATE",
            "acquisitionValidated": False,
            "promotionReady": False,
            "reason": type(error).__name__,
        }
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as output:
        json.dump(result, output, sort_keys=True)
        output.write("\n")
    return 0 if result["acquisitionValidated"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
