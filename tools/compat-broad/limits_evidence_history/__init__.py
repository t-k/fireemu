"""Offline validation of two explicitly retained, immutable limits evidence sets.

Only these audited Git commits may supply code. Receipt-selected commits never
select executable code. Legacy final observations were not recorded and are not
reconstructed. This adapter cannot admit new production execution.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

PRODUCTION_COMMIT = "40dfc0da3a03968928fa1906cdee409b703a0bb1"
LOCAL_COMMIT = "8b33aac4ddd09e6b945cc8701a7e757a948223ac"
RECEIPT_SHA256 = "ca418bcf1eed6d906baebc7d22090161752071c7d845ab19a10bd3b6ddc429a7"
INPUTS_SHA256 = "27f62136d95e85ae514ffd4ec7ae885d806d09540bfbf8a4281f837c06323499"
ARTIFACT_SHA256 = "76f855367910ad237de6ffd491091f20bcdccdb2e5eb8ee417e80b94bf6ac397"
LOCAL_FILES = {
    "manifest.json": "e5d16ddc1dbfe813f0433f34b4c22c5d13c45975690cc554f14ff05263f3f6e5",
    "cases.json": "ea6f909eceb3226fbbe95f34bf6753a238024064c2ce4a331cc4cd1b29d1bf44",
    "result.json": "e6cccf32a6d045b09b118cb0c87b19238bb9b0a15966092f4f06448c74ccae7b",
    "shadow-binding.json": "59e0c0ee810bbb1472440eae11403380c426c76cc5b6ab493337f7ab0da9ac5e",
}
ROOT = Path(__file__).resolve().parents[3]
SOURCE_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

# Fixed, read-only entry point. It never calls production.main(), execute(), or
# any credential acquisition API. The audit hook blocks sockets and any subprocess
# except the read-only Git file listing required by runtime_inputs().
_VALIDATOR = r"""
import json, pathlib, sys
root, mode, ledger_root = sys.argv[1:]
def offline(event, args):
    if event.startswith("socket."):
        raise RuntimeError("network prohibited in historical validation")
    if event == "subprocess.Popen":
        command = args[1]
        if not isinstance(command, (list, tuple)) or list(command[:2]) != ["git", "ls-files"]:
            raise RuntimeError("only runtime input listing is allowed")
sys.addaudithook(offline)
sys.path.insert(0, str(pathlib.Path(root) / "tools/compat-broad/fs-write-limits"))
import production
production.SHARED_ROOT = pathlib.Path(ledger_root)
value = json.load(sys.stdin)
if mode == "production":
    receipt, inputs = value["receipt"], value["inputs"]
    if "acquisitionFailure" in receipt or "reservationFailure" in receipt or receipt.get("acquisitionValidated") is not True or receipt.get("failure") is not None:
        raise ValueError("historical acquisition failed")
    permission = inputs["permission"]
    production.approve(permission, permission["nonce"], inputs["localBundleDigest"],
        inputs["artifactSha256"], inputs["sourceCommit"], permission["apiKeyDigest"],
        permission["ledgerIdentity"], now=inputs["admittedAt"])
    production.validate_frozen(inputs, receipt)
    production.validate_acquisition(receipt, inputs)
    result = {"validated": True}
elif mode == "local":
    bundle = production.local_bundle(value["directory"], value["artifact"], value["commit"])
    result = {"validated": True, "digest": bundle["digest"], "artifactSha256": bundle["artifactSha256"]}
else:
    raise ValueError("unsupported historical mode")
print(json.dumps(result, sort_keys=True))
"""


def _run(commit, mode, value):
    if (commit, mode) not in {
        (PRODUCTION_COMMIT, "production"),
        (LOCAL_COMMIT, "local"),
    }:
        raise ValueError("historical validator is not allowlisted")
    with tempfile.TemporaryDirectory(prefix="limits-frozen-validation-") as temporary:
        root = Path(temporary)
        environment = {
            "PATH": os.defpath,
            "HOME": temporary,
            "GIT_CONFIG_NOSYSTEM": "1",
        }
        resolved = subprocess.check_output(
            ["git", "rev-parse", "--verify", f"{commit}^{{commit}}"],
            cwd=ROOT,
            env=environment,
            text=True,
        ).strip()
        if resolved != commit:
            raise ValueError("historical source identity differs")
        archive = subprocess.check_output(
            [
                "git",
                "archive",
                "--format=tar",
                commit,
                "tools",
                "spec",
                "Cargo.toml",
                "Cargo.lock",
                "rust-toolchain.toml",
                ".cargo",
                "crates",
            ],
            cwd=ROOT,
            env=environment,
        )
        with tarfile.open(fileobj=io.BytesIO(archive)) as tree:
            for member in tree.getmembers():
                path = Path(member.name)
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or not (member.isfile() or member.isdir())
                ):
                    raise ValueError("nonregular historical Git archive member")
            tree.extractall(root, filter="data")
        # runtime_inputs lists tracked and untracked files; an empty isolated Git
        # repository preserves that exact path set without touching the caller.
        subprocess.run(
            ["git", "init", "-q", str(root)],
            env=environment,
            check=True,
            capture_output=True,
        )
        ledger_root = Path.home() / ".local/state/fireemu-broad/production-admission-v1"
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                _VALIDATOR,
                str(root),
                mode,
                str(ledger_root),
            ],
            input=json.dumps(value),
            text=True,
            capture_output=True,
            cwd=root,
            env=environment,
            timeout=120,
            check=False,
        )
        if completed.returncode != 0:
            raise ValueError("frozen historical validation failed")
        result = json.loads(completed.stdout)
        expected_keys = (
            {"validated"}
            if mode == "production"
            else {"validated", "digest", "artifactSha256"}
        )
        if (
            not isinstance(result, dict)
            or set(result) != expected_keys
            or result["validated"] is not True
        ):
            raise ValueError("historical validator result invalid")
        if any(
            not isinstance(result[k], str)
            or len(result[k]) != 64
            or any(c not in "0123456789abcdef" for c in result[k])
            for k in expected_keys - {"validated"}
        ):
            raise ValueError("historical validator digest invalid")
        return result


def validate_production(receipt, inputs, receipt_hash, inputs_hash):
    if (
        "acquisitionFailure" in receipt
        or "reservationFailure" in receipt
        or receipt.get("acquisitionValidated") is not True
        or receipt.get("failure") is not None
        or receipt.get("kind") != "fs-write-limits-production-receipt-v1"
        or inputs.get("sourceCommit") != PRODUCTION_COMMIT
        or receipt_hash != RECEIPT_SHA256
        or inputs_hash != INPUTS_SHA256
    ):
        raise ValueError("unrecognized or failed historical receipt")
    return _run(PRODUCTION_COMMIT, "production", {"receipt": receipt, "inputs": inputs})


def validate_local(directory, artifact):
    directory, artifact = Path(directory), Path(artifact)
    with tempfile.TemporaryDirectory(prefix="limits-retained-local-") as temporary:
        snapshot = Path(temporary)
        for name, expected in {**LOCAL_FILES, "artifact": ARTIFACT_SHA256}.items():
            source = artifact if name == "artifact" else directory / name
            if (
                source.is_symlink()
                or not source.is_file()
                or source.stat().st_size > 128 * 1024 * 1024
            ):
                raise ValueError("bounded regular historical evidence required")
            data = source.read_bytes()
            if hashlib.sha256(data).hexdigest() != expected:
                raise ValueError("unrecognized retained local evidence")
            (snapshot / name).write_bytes(data)
        result = _run(
            LOCAL_COMMIT,
            "local",
            {
                "directory": str(snapshot),
                "artifact": str(snapshot / "artifact"),
                "commit": LOCAL_COMMIT,
            },
        )
        result["result"] = json.loads((snapshot / "result.json").read_bytes())
        return result
