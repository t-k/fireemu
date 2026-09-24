"""Offline authority for the saved c1 transaction-stream comparison."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

RUNTIME_COMMIT = "c1d24250a62d23b38bcfed6da51f1ba4ed5798bb"
ARTIFACT_REL = Path("docs.local/runs/fs-write-txn-current-c1-shadow/fireemu")
MANIFEST_REL = Path("docs.local/runs/fs-write-txn-current-c1-build/local.json")
RECEIPT_REL = Path("docs.local/runs/fs-write-txn-current-c1-shadow/receipt.json")
PRODUCTION_REL = Path(
    "docs.local/logs/2026-09-17/stream-production-preflight/"
    "execution-dee737c14/receipt.json"
)
ARTIFACT_SHA = "4f049d0c5bfce865319d8bdbc662c0d0ea3f9568c21497f507b6bcbaed695fa9"
MANIFEST_SHA = "dce277b011ec825bd92515431f07a05cac791dbaebe8896bfef1ee9e9bbd2bea"
RECEIPT_SHA = "6dd039ad0474b37a32629a3ec2d27681b8a4926860a66488d5709c4776fb0bce"
PRODUCTION_SHA = "12956fbe82acefc106093eb2cd913ede9092f74aa98bd29f39e795492754b3f3"
BUILD_COMMAND = ["cargo", "build", "--locked", "-p", "fireemu", "--message-format=json"]
RUNTIME_INPUT_COUNT = 434
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
V1_PATH = Path("tools/compat-broad/fs-write-txn/stream_comparison.mjs")
V2_DIR = Path("tools/compat-broad/fs-write-txn-recompare-v2")
BOUND_RUNTIME_SOURCES = (
    Path("tools/compat-broad/fs-write-txn/broad_contract.py"),
    Path("tools/compat-broad/fs-write-txn/credential_prep.py"),
    Path("tools/compat-broad/fs-write-txn/stream_bridge.py"),
    Path("tools/compat-broad/fs-write-txn/stream_production.py"),
    Path("tools/compat-broad/fs-write-txn/stream_shadow.py"),
)


def require(condition: bool, label: str) -> None:
    if not condition:
        raise ValueError(label)


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def regular(path: Path) -> None:
    info = path.lstat()
    require(
        stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode),
        "regular trust root required",
    )


def read(path: Path, expected: str, snapshots: dict[Path, bytes]) -> bytes:
    regular(path)
    value = path.read_bytes()
    require(sha(value) == expected, "trust root digest differs")
    path = path.resolve()
    require(
        path not in snapshots or snapshots[path] == value,
        "input changed during validation",
    )
    snapshots[path] = value
    return value


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def git_bytes(root: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(root), *args])


def authority_sources(root: Path, authority_commit: str) -> dict[str, str]:
    require(
        COMMIT_RE.fullmatch(authority_commit) is not None, "invalid authority commit"
    )
    require(
        git(root, "rev-parse", "HEAD") == authority_commit, "authority commit differs"
    )
    require(
        not git(root, "status", "--porcelain", "--untracked-files=all"),
        "authority checkout is dirty",
    )
    v2_paths = sorted((root / V2_DIR).glob("*.mjs"))
    require(v2_paths, "reviewed V2 source closure is empty")
    paths = [
        Path(__file__).resolve().relative_to(root),
        V1_PATH,
        *(path.relative_to(root) for path in v2_paths),
        *BOUND_RUNTIME_SOURCES,
    ]
    result = {}
    for path in paths:
        current = (root / path).read_bytes()
        reviewed = git_bytes(root, "show", f"{authority_commit}:{path}")
        require(sha(current) == sha(reviewed), "reviewed source differs")
        result[str(path)] = sha(current)
    for path in BOUND_RUNTIME_SOURCES:
        current = (root / path).read_bytes()
        require(
            current == git_bytes(root, "show", f"{RUNTIME_COMMIT}:{path}"),
            "c1 validator source differs",
        )
    return result


def runtime_inputs_at_commit(root: Path) -> dict[str, str]:
    names = (
        git_bytes(
            root,
            "ls-tree",
            "-r",
            "-z",
            "--name-only",
            RUNTIME_COMMIT,
            "--",
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            ".cargo",
            "crates",
        )
        .decode()
        .split("\0")
    )
    names = sorted(name for name in names if name)
    require(len(names) == RUNTIME_INPUT_COUNT, "c1 runtime input count differs")
    return {
        name: sha(git_bytes(root, "show", f"{RUNTIME_COMMIT}:{name}")) for name in names
    }


def validate_manifest(
    manifest: dict, root: Path, artifact_sha: str
) -> dict[str, object]:
    runtime = manifest.get("runtimeSource")
    build = manifest.get("build")
    require(
        isinstance(runtime, dict) and isinstance(build, dict),
        "build manifest shape differs",
    )
    expected_inputs = runtime_inputs_at_commit(root)
    require(runtime.get("commit") == RUNTIME_COMMIT, "runtime source commit differs")
    require(runtime.get("files") == expected_inputs, "runtime source input map differs")
    require(build.get("inputs") == expected_inputs, "build input map differs")
    require(
        build.get("artifactSha256") == artifact_sha, "artifact build binding differs"
    )
    require(
        build.get("command") == BUILD_COMMAND and build.get("exitCode") == 0,
        "build record differs",
    )
    inputs_digest = sha(
        json.dumps(expected_inputs, sort_keys=True, separators=(",", ":")).encode()
    )
    return {
        "runtimeInputCount": len(expected_inputs),
        "runtimeInputsDigest": inputs_digest,
    }


def validate_local_receipt(root: Path, receipt: dict, artifact_sha: str) -> None:
    require(
        receipt.get("kind") == "stream-prepared-execution-v1",
        "local receipt kind differs",
    )
    for field in (
        "acquisitionValidated",
        "reservationReleased",
        "configurationUnchanged",
    ):
        require(receipt.get(field) is True, f"local {field} is false")
    require(
        receipt.get("productionExecuted") is False,
        "local receipt claims production execution",
    )
    require(
        receipt.get("productionDataExecuted") is False,
        "local receipt claims production data",
    )
    require(receipt.get("failures") == [], "local receipt contains failures")
    gate = receipt.get("gate")
    require(isinstance(gate, dict), "local gate is missing")
    sys.path.insert(0, str(root / "tools/compat-broad/fs-write-txn"))
    import stream_bridge
    import stream_production
    import stream_shadow
    from broad_contract import digest

    require(
        Path(stream_shadow.__file__).resolve() == root / BOUND_RUNTIME_SOURCES[-1],
        "unexpected receipt validator",
    )
    stream_shadow.validate_owned_receipt(receipt, artifact_sha)
    plan = gate.get("plan")
    require(
        isinstance(plan, dict) and gate.get("planDigest") == digest(plan),
        "local plan digest differs",
    )
    stream_bridge.validate_plan(plan)
    stream_bridge.validate_absence(gate, "stream")
    stream_production.metadata_valid(gate)
    require(
        gate.get("coordinatorInflight") is False, "local coordinator remains active"
    )
    require(
        gate.get("coordinatorDone") == plan.get("coordinatorRequests"),
        "local coordinator is incomplete",
    )
    for job in gate.get("jobs", {}).values():
        require(
            job.get("stopped") is True and not job.get("inflight"),
            "local job is not stopped",
        )
        require(
            set(job.get("absent", [])) == set(job.get("resources", [])),
            "local resources remain",
        )
    collection = receipt.get("collection", {})
    observations = collection.get("observations", [])
    recovery = collection.get("recoveryObservations", [])
    events = gate.get("events", [])
    require(
        len(observations) == 15 and len(recovery) == 10,
        "local observation counts differ",
    )
    require(
        len(events) == 23 and receipt.get("dataRequests") == 23,
        "local data request count differs",
    )
    nodes: set[str] = set()

    def visit(value: object) -> None:
        if isinstance(value, dict):
            nodes.add(digest(value))
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(collection)
    for event in events:
        response = event.get("receipt", {})
        require(
            event.get("completed") is True and not event.get("failure"),
            "local request incomplete",
        )
        require(
            event.get("responseDigest") == digest(response),
            "local response digest differs",
        )
        require(
            event.get("requestDigest") == response.get("requestDigest"),
            "local request digest differs",
        )
        require(
            event.get("grpcCode") == stream_bridge.grpc_code(response.get("raw")),
            "local gRPC code differs",
        )
        require(
            digest(response.get("raw")) in nodes,
            "local response is not collection-bound",
        )


def compare(
    root: Path, production: dict, local: dict, artifact_sha: str, node: str
) -> dict:
    comparator = root / V1_PATH
    v2_paths = sorted((root / V2_DIR).glob("*.mjs"))
    sources = {path.name: path.read_text() for path in v2_paths}
    sys.path.insert(0, str(root / "tools/compat-broad/fs-write-txn"))
    import stream_production

    expected = stream_production.comparison_contract(production["gate"]["plan"])
    local_plan = local["gate"]["plan"]
    expected["local"] = {
        "projectId": local_plan["projectId"],
        "documentPrefix": local_plan["documentPrefix"],
    }
    payload = {
        "production": production["collection"],
        "local": local["collection"],
        "expected": expected,
        "v1Source": comparator.read_text(),
        "v2Sources": sources,
        "artifact": {
            "sha256": artifact_sha,
            "executionCommit": local["ownedArtifact"]["executionCommit"],
        },
        "permission": {
            "kind": "c1-current-local-authority-v1",
            "planDigest": local["gate"]["planDigest"],
        },
    }
    script = """
import { compareStreamReceipts } from './stream_comparison.mjs';
import { compareStreamReceiptsV2, v2Digest, v2TextDigest } from '../fs-write-txn-recompare-v2/stream_recompare_v2.mjs';
let input = ''; for await (const chunk of process.stdin) input += chunk;
const x = JSON.parse(input);
const v1Comparison = compareStreamReceipts({production:x.production, local:x.local, expected:x.expected});
const binding = {permission:x.permission, v1Source:x.v1Source, v1Comparison, v2Sources:x.v2Sources, artifact:x.artifact};
for (const k of ['permission','v1Comparison','v2Sources','artifact']) binding[k+'Sha256'] = v2Digest(binding[k]);
binding.v1SourceSha256 = v2TextDigest(binding.v1Source);
binding.productionReceiptSha256 = v2Digest(x.production);
binding.localReceiptSha256 = v2Digest(x.local);
const v2 = compareStreamReceiptsV2({production:x.production, local:x.local, expected:x.expected, binding});
process.stdout.write(JSON.stringify({v1Classification:v1Comparison.classification, v2Classification:v2.classification,
  v1Indeterminate:v1Comparison.classification === 'INDETERMINATE' ? 1 : 0,
  v2Indeterminate:v2.classification === 'INDETERMINATE' ? 1 : 0,
  v1Comparison}));
"""
    result = subprocess.run(
        [node, "--input-type=module", "-e", script],
        cwd=comparator.parent,
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
        env={},
    )
    require(result.returncode == 0, "comparison execution failed")
    value = json.loads(result.stdout)
    require(
        value["v1Indeterminate"] == 0 and value["v2Indeterminate"] == 0,
        "comparison is indeterminate",
    )
    differences = value["v1Comparison"].get("differences", {})
    left, right = differences.get("production"), differences.get("local")
    require(
        isinstance(left, list) and isinstance(right, list) and len(left) == len(right),
        "V1 projection is incomplete",
    )
    leaf_counts = [
        difference_leaf_count(a, b) for a, b in zip(left, right, strict=True)
    ]
    result_value = {key: value[key] for key in ("v1Classification", "v2Classification")}
    result_value.update(
        {
            "v1ComparedSlotCount": len(left),
            "v1DifferingSlotCount": sum(count > 0 for count in leaf_counts),
            "v1DifferenceLeafCount": sum(leaf_counts),
            "indeterminate": value["v1Indeterminate"] + value["v2Indeterminate"],
        }
    )
    return result_value


MISSING = object()


def difference_leaf_count(left: object, right: object) -> int:
    if left is MISSING or right is MISSING:
        return 1
    if type(left) is not type(right):
        return 1
    if isinstance(left, dict):
        assert isinstance(right, dict)
        return sum(
            difference_leaf_count(left.get(key, MISSING), right.get(key, MISSING))
            for key in set(left) | set(right)
        )
    if isinstance(left, list):
        assert isinstance(right, list)
        return sum(
            difference_leaf_count(
                left[i] if i < len(left) else MISSING,
                right[i] if i < len(right) else MISSING,
            )
            for i in range(max(len(left), len(right)))
        )
    return int(left != right)


def run(args: argparse.Namespace) -> dict:
    root = Path(args.root).resolve(strict=True)
    inputs = Path(args.input_root or root).resolve(strict=True)
    snapshots: dict[Path, bytes] = {}
    artifact_path = Path(args.artifact) if args.artifact else inputs / ARTIFACT_REL
    manifest_path = (
        Path(args.build_manifest) if args.build_manifest else inputs / MANIFEST_REL
    )
    receipt_path = Path(args.receipt) if args.receipt else inputs / RECEIPT_REL
    production_path = (
        Path(args.production) if args.production else inputs / PRODUCTION_REL
    )
    artifact_bytes = read(artifact_path, ARTIFACT_SHA, snapshots)
    manifest_bytes = read(manifest_path, MANIFEST_SHA, snapshots)
    receipt_bytes = read(receipt_path, RECEIPT_SHA, snapshots)
    production_bytes = read(production_path, PRODUCTION_SHA, snapshots)
    artifact_sha = sha(artifact_bytes)
    manifest = json.loads(manifest_bytes)
    local = json.loads(receipt_bytes)
    production = json.loads(production_bytes)
    closure_before = authority_sources(root, args.authority_commit)
    manifest_binding = validate_manifest(manifest, root, artifact_sha)
    validate_local_receipt(root, local, artifact_sha)
    require(
        local.get("ownedArtifact", {}).get("executionCommit") == RUNTIME_COMMIT,
        "local execution commit differs",
    )
    require(
        production.get("acquisitionValidated") is True
        and production.get("productionExecuted") is True,
        "saved production receipt is not validated",
    )
    require(
        production.get("failures") == []
        and production.get("reservationReleased") is True,
        "saved production receipt is incomplete",
    )
    require(
        len(production.get("gate", {}).get("events", [])) == 23,
        "saved production request count differs",
    )
    require(
        len(production.get("collection", {}).get("observations", [])) == 15,
        "saved production observation count differs",
    )
    require(
        len(production.get("collection", {}).get("recoveryObservations", [])) == 10,
        "saved production recovery count differs",
    )
    node = local["gate"]["plan"]["nodeRuntime"]["path"]
    result = compare(root, production, local, artifact_sha, node)
    for path, expected in (
        (artifact_path, ARTIFACT_SHA),
        (manifest_path, MANIFEST_SHA),
        (receipt_path, RECEIPT_SHA),
        (production_path, PRODUCTION_SHA),
    ):
        read(path, expected, snapshots)
    closure_after = authority_sources(root, args.authority_commit)
    require(
        closure_before == closure_after, "authority sources changed during comparison"
    )
    require(
        result["v2Classification"] in {"MATCH", "MISMATCH", "EXPECTED_NONDETERMINISM"},
        "unexpected comparison classification",
    )
    return {
        "kind": "fs-write-txn-c1-current-authority-v1",
        "acquisitionValidated": True,
        "promotionReady": False,
        "classification": result["v2Classification"],
        "v1Classification": result["v1Classification"],
        "productionExecuted": False,
        "rowCounts": {
            "observations": 15,
            "recoveryObservations": 10,
            "gateEvents": 23,
            "v1ComparedSlotCount": result["v1ComparedSlotCount"],
            "v1DifferingSlotCount": result["v1DifferingSlotCount"],
            "v1DifferenceLeafCount": result["v1DifferenceLeafCount"],
            "indeterminate": result["indeterminate"],
        },
        "bindings": {
            "artifactSha256": artifact_sha,
            "manifestSha256": sha(manifest_bytes),
            "localReceiptSha256": sha(receipt_bytes),
            "productionReceiptSha256": sha(production_bytes),
            "runtimeSourceCommit": RUNTIME_COMMIT,
            "runtimeInputCount": manifest_binding["runtimeInputCount"],
            "runtimeInputsDigest": manifest_binding["runtimeInputsDigest"],
            "authorityCommit": args.authority_commit,
            "authoritySources": closure_after,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, required=True, help="clean committed authority checkout"
    )
    parser.add_argument(
        "--input-root", type=Path, help="repository containing ignored saved run inputs"
    )
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--build-manifest", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--production", type=Path)
    parser.add_argument("--authority-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        value = run(args)
        output = args.output.resolve()
        if output.exists():
            raise FileExistsError("fresh output required")
        output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write("\n")
        return 0
    except Exception as error:  # noqa: BLE001 -- CLI sanitizes every refusal.
        print(
            f"c1 current authority refused ({type(error).__name__}).", file=sys.stderr
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
