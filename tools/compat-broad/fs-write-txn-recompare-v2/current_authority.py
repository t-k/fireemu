"""Offline authority for one current-artifact Write-stream recompare."""

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

ARTIFACT_REL = Path(
    "docs.local/runs/saved-runtime-20260922-approved/projection-e896/fireemu"
)
MANIFEST_REL = Path(
    "docs.local/runs/saved-runtime-20260922-approved/build/build-local.json"
)
DEFAULT_RECEIPT_REL = Path(
    "docs.local/runs/write-txn-e896-2a1e95a98-retry01/receipt.json"
)
ARTIFACT_SHA = "8245b80ea941344e114fe8f61cd7721d2519739509779e7504c295c1bbb66849"
MANIFEST_SHA = "616c2a207d6df0d8b5cc2e5c56b1bd986763a31811b14c5b0b33f919a21515ba"
RECEIPT_SHA = "e1dc4671d8bd14722aa20922a2d44deab50935da798606192b881c928e062c69"
PRODUCTION_SHA = "12956fbe82acefc106093eb2cd913ede9092f74aa98bd29f39e795492754b3f3"
RUNTIME_COMMIT = "e896132a2317a5f38b2780857301f7b0f88b2e68"
BUILD_COMMAND = ["cargo", "build", "--locked", "-p", "fireemu", "--message-format=json"]
RUNTIME_INPUT_COUNT = 430
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
V1_PATH = Path("tools/compat-broad/fs-write-txn/stream_comparison.mjs")
V2_DIR = Path("tools/compat-broad/fs-write-txn-recompare-v2")


def require(condition: bool, label: str) -> None:
    if not condition:
        raise ValueError(label)


MISSING = object()


def json_difference_leaf_count(left: object, right: object) -> int:
    """Count differing JSON leaves, treating a missing typed leaf as one difference."""
    if left is MISSING or right is MISSING:
        return 1
    if type(left) is not type(right):
        return 1
    if isinstance(left, dict):
        assert isinstance(right, dict)
        keys = set(left) | set(right)
        return sum(json_difference_leaf_count(left.get(key, MISSING), right.get(key, MISSING)) for key in keys)
    if isinstance(left, list):
        assert isinstance(right, list)
        length = max(len(left), len(right))
        return sum(
            json_difference_leaf_count(
                left[index] if index < len(left) else MISSING,
                right[index] if index < len(right) else MISSING,
            )
            for index in range(length)
        )
    return int(left != right)


def v1_projection_metrics(comparison: dict) -> dict[str, int]:
    """Return slot and leaf counts from the comparator's JSON projection only."""
    differences = comparison.get("differences")
    if not isinstance(differences, dict):
        return {
            "v1ComparedSlotCount": 0,
            "v1DifferingSlotCount": 0,
            "v1DifferenceLeafCount": 0,
        }
    production = differences.get("production")
    local = differences.get("local")
    require(isinstance(production, list) and isinstance(local, list), "V1 projection differences must be arrays")
    require(len(production) == len(local), "V1 projection side lengths differ")
    differing_slots = sum(
        json_difference_leaf_count(left, right) > 0
        for left, right in zip(production, local, strict=True)
    )
    leaf_count = sum(
        json_difference_leaf_count(left, right)
        for left, right in zip(production, local, strict=True)
    )
    return {
        "v1ComparedSlotCount": len(production),
        "v1DifferingSlotCount": differing_slots,
        "v1DifferenceLeafCount": leaf_count,
    }


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def absolute(path: Path) -> Path:
    return Path(os.path.abspath(path))


def regular(path: Path) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError("regular trust root required")


def read(path: Path, expected: str | None = None, snapshots: dict[Path, bytes] | None = None) -> bytes:
    regular(path)
    value = path.read_bytes()
    if expected is not None and sha(value) != expected:
        raise ValueError("trust root digest mismatch")
    if snapshots is not None:
        path = path.resolve()
        previous = snapshots.get(path)
        if previous is not None and previous != value:
            raise ValueError("input changed during validation")
        snapshots[path] = value
    return value


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def git_bytes(root: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(root), *args])


def source_closure(root: Path, authority_commit: str) -> dict[str, str]:
    if not COMMIT_RE.fullmatch(authority_commit):
        raise ValueError("reviewed authority commit must be a full SHA")
    if git(root, "rev-parse", "--verify", f"{authority_commit}^{{commit}}") != authority_commit:
        raise ValueError("reviewed authority commit is unavailable")
    if git(root, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("authority checkout is dirty")
    try:
        subprocess.run(
            ["git", "-C", str(root), "merge-base", "--is-ancestor", authority_commit, "HEAD"],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError:
        raise ValueError("authority commit is not an ancestor") from None
    paths = [V1_PATH, *(V2_DIR / path.name for path in sorted((root / V2_DIR).glob("*.mjs")))]
    require(paths[1:], "reviewed V2 source closure is empty")
    result: dict[str, str] = {}
    for path in paths:
        current = read(root / path)
        reviewed = git_bytes(root, "show", f"{authority_commit}:{path}")
        require(sha(current) == sha(reviewed), "reviewed comparator source differs")
        result[str(path)] = sha(current)
    authority_path = root / V2_DIR / "current_authority.py"
    executed_path = Path(__file__).resolve()
    authority_bytes = read(authority_path)
    require(sha(authority_bytes) == sha(read(executed_path)), "executed authority source differs")
    result[str(authority_path.relative_to(root))] = sha(authority_bytes)
    return result


def clean_runtime_source(source: Path, expected_commit: str) -> None:
    require(COMMIT_RE.fullmatch(expected_commit) is not None, "invalid runtime source commit")
    require(git(source, "rev-parse", "HEAD") == expected_commit, "runtime source commit mismatch")
    require(not git(source, "status", "--porcelain", "--untracked-files=all"), "runtime source is dirty")


def runtime_inputs_at_commit(source: Path, commit: str) -> dict[str, str]:
    names = git_bytes(
        source,
        "ls-tree",
        "-r",
        "-z",
        "--name-only",
        commit,
        "--",
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        ".cargo",
        "crates",
    ).decode().split("\0")
    names = sorted(name for name in names if name)
    require(names, "runtime source input set is empty")
    return {name: sha(git_bytes(source, "show", f"{commit}:{name}")) for name in names}


def runtime_inputs_current(source: Path, expected_names: list[str]) -> dict[str, str]:
    names = git_bytes(
        source,
        "ls-files",
        "-z",
        "--",
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        ".cargo",
        "crates",
    ).decode().split("\0")
    names = sorted(name for name in names if name)
    require(names == expected_names, "runtime checkout input names differ")
    result = {}
    for name in names:
        path = source / name
        regular(path)
        result[name] = sha(path.read_bytes())
    return result


def validate_manifest(manifest: dict, runtime_source: Path, artifact_sha: str) -> dict:
    build = manifest.get("build")
    runtime = manifest.get("runtimeSource")
    require(isinstance(build, dict) and isinstance(runtime, dict), "runtime build receipt shape differs")
    require(runtime.get("commit") == RUNTIME_COMMIT, "runtime source commit differs")
    require(build.get("artifactSha256") == artifact_sha, "build artifact binding differs")
    require(build.get("exitCode") == 0, "build did not exit successfully")
    require(build.get("command") == BUILD_COMMAND, "build command differs")
    expected = runtime_inputs_at_commit(runtime_source, RUNTIME_COMMIT)
    require(len(expected) == RUNTIME_INPUT_COUNT, "runtime input count differs")
    require(runtime.get("files") == expected, "runtime source input map differs")
    require(build.get("inputs") == expected, "build input map differs")
    current = runtime_inputs_current(runtime_source, sorted(expected))
    require(current == expected, "runtime checkout input bytes differ")
    return {
        "runtimeInputCount": len(expected),
        "runtimeInputsDigest": sha(json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()),
    }


def validate_owned_receipt(authority_root: Path, receipt: dict, artifact_sha: str) -> None:
    script = """
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[2]) / 'tools/compat-broad/fs-write-txn'))
from stream_shadow import validate_owned_receipt
validate_owned_receipt(json.loads(sys.stdin.read()), sys.argv[1])
"""
    env = {k: v for k, v in os.environ.items() if k not in {"GOOGLE_APPLICATION_CREDENTIALS", "FIREBASE_TOKEN"}}
    result = subprocess.run(
        [sys.executable, "-c", script, artifact_sha, str(authority_root)],
        input=json.dumps(receipt),
        text=True,
        capture_output=True,
        check=False,
        cwd=authority_root,
        env=env,
    )
    if result.returncode != 0:
        raise ValueError("owned receipt validation failed")


def comparison(
    authority_root: Path,
    production: dict,
    local: dict,
    expected: dict,
    node: str,
    artifact_sha: str,
) -> dict:
    comparator = authority_root / V1_PATH
    v2_paths = sorted((authority_root / V2_DIR).glob("*.mjs"))
    sources = {path.name: path.read_text() for path in v2_paths}
    payload = {
        "production": production["collection"],
        "local": local["collection"],
        "expected": expected,
        "v1Source": comparator.read_text(),
        "v2Sources": sources,
        "artifact": {"sha256": artifact_sha, "executionCommit": local["ownedArtifact"]["executionCommit"]},
        "permission": {"kind": "current-local-authority-v1", "planDigest": local["gate"]["planDigest"]},
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
process.stdout.write(JSON.stringify({
  v1Classification: v1Comparison.classification,
  v2Classification: v2.classification,
  v1Comparison,
  v1Indeterminate: v1Comparison.classification === 'INDETERMINATE' ? 1 : 0,
  v2Indeterminate: v2.classification === 'INDETERMINATE' ? 1 : 0,
}));
"""
    result = subprocess.run(
        [node, "--input-type=module", "-e", script],
        cwd=comparator.parent,
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
        env={},
    )
    require(result.returncode == 0, "comparison execution failed")
    value = json.loads(result.stdout)
    require(value["v1Indeterminate"] == 0 and value["v2Indeterminate"] == 0, "comparison proof incomplete")
    metrics = v1_projection_metrics(value["v1Comparison"])
    del value["v1Comparison"]
    return {**value, **metrics}


def run(args: argparse.Namespace) -> dict:
    root = Path(args.root).resolve(strict=True)
    runtime_source = Path(args.runtime_source).resolve(strict=True)
    artifact_path = absolute(Path(args.artifact or root / ARTIFACT_REL))
    manifest_path = absolute(Path(args.build_manifest or root / MANIFEST_REL))
    production_path = absolute(Path(args.production))
    receipt_path = absolute(Path(args.receipt or root / DEFAULT_RECEIPT_REL))
    snapshots: dict[Path, bytes] = {}
    artifact_bytes = read(artifact_path, ARTIFACT_SHA, snapshots)
    manifest_bytes = read(manifest_path, MANIFEST_SHA, snapshots)
    receipt_bytes = read(receipt_path, RECEIPT_SHA, snapshots)
    production_bytes = read(production_path, PRODUCTION_SHA, snapshots)
    manifest = json.loads(manifest_bytes)
    receipt = json.loads(receipt_bytes)
    production = json.loads(production_bytes)
    closure_before = source_closure(root, args.authority_commit)
    clean_runtime_source(runtime_source, RUNTIME_COMMIT)
    manifest_summary = validate_manifest(manifest, runtime_source, sha(artifact_bytes))
    require(receipt.get("acquisitionValidated") is True, "local acquisition is not validated")
    require(receipt.get("productionExecuted") is False, "local receipt used production execution")
    require(receipt.get("productionDataExecuted") is False, "local receipt used production data")
    require(receipt.get("reservationReleased") is True and receipt.get("configurationUnchanged") is True, "local acquisition closure incomplete")
    require(receipt.get("failures") == [], "local acquisition has failures")
    owned = receipt.get("ownedArtifact", {})
    require(owned.get("executionCommit") == args.authority_commit, "local authority commit differs")
    validate_owned_receipt(root, receipt, sha(artifact_bytes))
    require(production.get("acquisitionValidated") is True and production.get("productionExecuted") is True, "production reference receipt is not validated")
    local_plan = receipt["gate"]["plan"]
    production_plan = production["gate"]["plan"]
    require(local_plan.get("protocol") == production_plan.get("protocol") == "firestore-grpc-stream-v1", "stream protocol differs")
    contract_script = "import json,sys;sys.path.insert(0,'tools/compat-broad/fs-write-txn');import stream_production as p;print(json.dumps(p.comparison_contract(json.loads(sys.stdin.read()))))"
    contract = json.loads(subprocess.check_output([sys.executable, "-c", contract_script], cwd=runtime_source, input=json.dumps(production_plan), text=True))
    contract["local"] = {"projectId": local_plan["projectId"], "documentPrefix": local_plan["documentPrefix"]}
    node = local_plan["nodeRuntime"]["path"]
    result = comparison(root, production, receipt, contract, node, sha(artifact_bytes))
    for path, expected in (
        (artifact_path, ARTIFACT_SHA),
        (manifest_path, MANIFEST_SHA),
        (receipt_path, RECEIPT_SHA),
        (production_path, PRODUCTION_SHA),
    ):
        read(path, expected, snapshots)
    closure_after = source_closure(root, args.authority_commit)
    require(closure_before == closure_after, "authority source changed during comparison")
    clean_runtime_source(runtime_source, RUNTIME_COMMIT)
    return {
        "kind": "stream-current-authority-v2",
        "acquisitionValidated": True,
        "promotionReady": False,
        "classification": result["v2Classification"],
        "v1Classification": result["v1Classification"],
        "productionExecuted": False,
        "rowCounts": {
            "observations": len(receipt.get("collection", {}).get("observations", [])),
            "recoveryObservations": len(receipt.get("collection", {}).get("recoveryObservations", [])),
            "gateEvents": len(receipt.get("gate", {}).get("events", [])),
            "v1ComparedSlotCount": result["v1ComparedSlotCount"],
            "v1DifferingSlotCount": result["v1DifferingSlotCount"],
            "v1DifferenceLeafCount": result["v1DifferenceLeafCount"],
            "indeterminate": result["v1Indeterminate"] + result["v2Indeterminate"],
        },
        "bindings": {
            "artifactSha256": sha(artifact_bytes),
            "manifestSha256": sha(manifest_bytes),
            "localReceiptSha256": sha(receipt_bytes),
            "productionReceiptSha256": sha(production_bytes),
            "runtimeSourceCommit": RUNTIME_COMMIT,
            "authorityCommit": args.authority_commit,
            "authoritySourceSha256": closure_after[str((root / V2_DIR / "current_authority.py").relative_to(root))],
            "comparatorSha256": closure_after[str(V1_PATH)],
            "v2SourceSha256": sha(
                json.dumps(
                    {key: value for key, value in closure_after.items() if key.startswith(str(V2_DIR)) and key.endswith(".mjs")},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ),
            **manifest_summary,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--runtime-source", type=Path, required=True)
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--build-manifest", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--production", type=Path, required=True)
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
        print(f"Current write authority refused ({type(error).__name__}).", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
