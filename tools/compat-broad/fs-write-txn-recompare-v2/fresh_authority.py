"""Offline authority for one retained current-artifact Write-stream replay."""

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

ARTIFACT_REL = Path("docs.local/artifacts/cx-limits-nx-20260922-record-20260922-030423/fireemu")
MANIFEST_REL = ARTIFACT_REL.with_name("manifest.json")
RECEIPT_REL = Path("docs.local/runs/cx-write-stream-0591-20260922/receipt.json")
PRODUCTION_REL = Path("docs.local/logs/2026-09-17/stream-production-preflight/execution-dee737c14/receipt.json")
ARTIFACT_SHA = "bf713deb0952db610c840d6233b9c343496df5b69b9c4e934a4054c27f765897"
MANIFEST_SHA = "38b7bbd5e496feb54925ae05d7ff82776ecd9a0a4d8420c381095cb7fae6436a"
RECEIPT_SHA = "67a89a1654a4891a57d212b341725a6f20602324d764d9b2f5402ec178c82a90"
PRODUCTION_SHA = "12956fbe82acefc106093eb2cd913ede9092f74aa98bd29f39e795492754b3f3"
BUILD_COMMAND = ["cargo", "build", "--locked", "-p", "fireemu", "--message-format=json"]
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def regular(path: Path) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError("regular trust root required")


def read(path: Path, expected: str | None = None) -> bytes:
    regular(path)
    value = path.read_bytes()
    if expected is not None and sha(value) != expected:
        raise ValueError("trust root digest mismatch")
    return value


def git(source: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(source), *args], text=True).strip()


def source_closure(root: Path, expected_commit: str) -> dict[str, str]:
    if not COMMIT_RE.fullmatch(expected_commit):
        raise ValueError("reviewed authority commit must be a full SHA")
    if git(root, "rev-parse", "--verify", f"{expected_commit}^{{commit}}") != expected_commit:
        raise ValueError("reviewed authority commit is unavailable")
    if git(root, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("authority checkout is dirty")
    v2_root = root / "tools/compat-broad/fs-write-txn-recompare-v2"
    v2_paths = sorted(v2_root.glob("*.mjs"))
    if not v2_paths:
        raise ValueError("reviewed V2 source closure is empty")
    paths = [
        Path(__file__).resolve().relative_to(root),
        Path("tools/compat-broad/fs-write-txn/stream_comparison.mjs"),
        *(path.relative_to(root) for path in v2_paths),
    ]
    result: dict[str, str] = {}
    for path in paths:
        absolute = root / path
        result[str(path)] = sha(read(absolute))
        reviewed = subprocess.check_output(
            ["git", "-C", str(root), "show", f"{expected_commit}:{path}"],
        )
        if sha(reviewed) != result[str(path)]:
            raise ValueError("authority source differs from reviewed commit")
    return result


def clean_runtime_source(source: Path, expected_commit: str) -> None:
    if git(source, "rev-parse", "HEAD") != expected_commit:
        raise ValueError("runtime source commit mismatch")
    if git(source, "status", "--porcelain"):
        raise ValueError("runtime source is dirty")


def runtime_binding(source: Path, manifest: dict, artifact_sha: str, receipt: dict) -> dict:
    script = """
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path('tools/compat-inventory').resolve()))
from evidence_common import runtime_inputs
from owned_runner import validate_build
root = Path(sys.argv[1])
manifest = json.loads(sys.stdin.readline())
receipt = json.loads(sys.stdin.readline())
inputs = runtime_inputs(root)
validate_build(manifest['build'], sys.argv[2], inputs)
if manifest['build']['command'] != ['cargo', 'build', '--locked', '-p', 'fireemu', '--message-format=json']:
    raise ValueError('build command mismatch')
print(json.dumps({'inputCount': len(inputs), 'inputsEqual': inputs == manifest['runtimeInputs']}))
"""
    payload = json.dumps(manifest) + "\n" + json.dumps(receipt)
    env = {k: v for k, v in os.environ.items() if k not in {"GOOGLE_APPLICATION_CREDENTIALS", "FIREBASE_TOKEN"}}
    result = subprocess.run(
        [sys.executable, "-c", script, str(source), artifact_sha],
        cwd=source,
        input=payload,
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )
    if result.returncode != 0:
        raise ValueError("runtime build input validation failed")
    value = json.loads(result.stdout)
    if value != {"inputCount": 427, "inputsEqual": True}:
        raise ValueError("runtime input map mismatch")
    return value


def owned_receipt_binding(source: Path, receipt: dict, artifact_sha: str) -> None:
    script = """
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path('tools/compat-broad/fs-write-txn').resolve()))
from stream_shadow import validate_owned_receipt
validate_owned_receipt(json.loads(sys.stdin.read()), sys.argv[1])
"""
    env = {k: v for k, v in os.environ.items() if k not in {"GOOGLE_APPLICATION_CREDENTIALS", "FIREBASE_TOKEN"}}
    result = subprocess.run(
        [sys.executable, "-c", script, artifact_sha],
        cwd=source,
        input=json.dumps(receipt),
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )
    if result.returncode != 0:
        raise ValueError("owned receipt validation failed")


def comparison(source_root: Path, production: dict, local: dict, expected: dict, node: str) -> dict:
    comparator = source_root / "tools/compat-broad/fs-write-txn/stream_comparison.mjs"
    v2 = source_root / "tools/compat-broad/fs-write-txn-recompare-v2/stream_recompare_v2.mjs"
    sources = {p.name: p.read_text() for p in sorted(v2.parent.iterdir()) if p.suffix == ".mjs"}
    payload = {
        "production": production["collection"],
        "local": local["collection"],
        "expected": expected,
        "v1Source": comparator.read_text(),
        "v2Sources": sources,
        "artifact": {"sha256": ARTIFACT_SHA, "executionCommit": local["ownedArtifact"]["executionCommit"]},
        "permission": {"kind": "fresh-local-replay-binding-v1", "planDigest": local["gate"]["planDigest"]},
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
const counts = {v1DifferenceCount: (v1Comparison.differences?.production?.length ?? 0), indeterminate: v1Comparison.classification === 'INDETERMINATE' ? 1 : 0};
process.stdout.write(JSON.stringify({v1Classification:v1Comparison.classification, v2Classification:v2.classification, rowCounts:counts}));
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
    if result.returncode != 0:
        raise ValueError("comparison execution failed")
    value = json.loads(result.stdout)
    if value["rowCounts"]["indeterminate"]:
        raise ValueError("comparison proof incomplete")
    return value


def run(args: argparse.Namespace) -> dict:
    input_root = Path(args.input_root or args.root).resolve(strict=True)
    runtime_source = Path(args.runtime_source).resolve(strict=True)
    artifact = input_root / ARTIFACT_REL
    manifest_path = input_root / MANIFEST_REL
    receipt_path = Path(args.receipt) if args.receipt else input_root / RECEIPT_REL
    production_path = input_root / PRODUCTION_REL
    artifact_bytes = read(artifact, ARTIFACT_SHA)
    manifest_bytes = read(manifest_path, MANIFEST_SHA)
    receipt_bytes = read(receipt_path, RECEIPT_SHA)
    production_bytes = read(production_path, PRODUCTION_SHA)
    manifest = json.loads(manifest_bytes)
    receipt = json.loads(receipt_bytes)
    production = json.loads(production_bytes)
    authority_root = Path(__file__).resolve().parents[3]
    closure_before = source_closure(authority_root, args.authority_commit)
    execution_commit = receipt["ownedArtifact"]["executionCommit"]
    clean_runtime_source(runtime_source, execution_commit)
    runtime_binding(runtime_source, manifest, sha(artifact_bytes), receipt)
    owned_receipt_binding(runtime_source, receipt, sha(artifact_bytes))
    local_plan = receipt["gate"]["plan"]
    contract_script = "import json,sys;sys.path.insert(0,'tools/compat-broad/fs-write-txn');import stream_production as p;print(json.dumps(p.comparison_contract(json.loads(sys.stdin.read()))))"
    production_plan = production["gate"]["plan"]
    contract = json.loads(subprocess.check_output([sys.executable, "-c", contract_script], cwd=runtime_source, input=json.dumps(production_plan), text=True))
    contract["local"] = {"projectId": local_plan["projectId"], "documentPrefix": local_plan["documentPrefix"]}
    node = local_plan["nodeRuntime"]["path"]
    result = comparison(authority_root, production, receipt, contract, node)
    before = [sha(artifact_bytes), sha(manifest_bytes), sha(receipt_bytes), sha(production_bytes)]
    after = [sha(read(artifact, ARTIFACT_SHA)), sha(read(manifest_path, MANIFEST_SHA)), sha(read(receipt_path, RECEIPT_SHA)), sha(read(production_path, PRODUCTION_SHA))]
    if before != after:
        raise ValueError("input changed during authority")
    closure_after = source_closure(authority_root, args.authority_commit)
    if closure_before != closure_after:
        raise ValueError("authority source changed during comparison")
    v2_path = authority_root / "tools/compat-broad/fs-write-txn-recompare-v2/stream_recompare_v2.mjs"
    return {
        "kind": "stream-fresh-authority-v1",
        "acquisitionValidated": True,
        "promotionReady": False,
        "classification": result["v2Classification"],
        "v1Classification": result["v1Classification"],
        "rowCounts": result["rowCounts"],
        "bindings": {"artifactSha256": sha(artifact_bytes), "manifestSha256": sha(manifest_bytes), "localReceiptSha256": sha(receipt_bytes), "productionReceiptSha256": sha(production_bytes), "executionCommit": execution_commit, "runtimeBuildCommit": manifest["executionCommit"], "authorityCommit": args.authority_commit, "authoritySourceSha256": closure_after[str(Path(__file__).resolve().relative_to(authority_root))], "comparatorSha256": closure_after["tools/compat-broad/fs-write-txn/stream_comparison.mjs"], "v2SourceSha256": closure_after[str(v2_path.relative_to(authority_root))], "runtimeInputCount": 427},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--input-root", type=Path)
    parser.add_argument("--runtime-source", type=Path, required=True)
    parser.add_argument("--authority-commit", required=True)
    parser.add_argument("--receipt", type=Path)
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
    except Exception as error:  # noqa: BLE001 -- CLI must sanitize every refusal.
        print(f"Fresh stream authority refused ({type(error).__name__}).", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
