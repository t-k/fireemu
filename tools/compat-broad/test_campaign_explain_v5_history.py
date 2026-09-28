"""Verify the immutable Explain v5 package against its historical source tree."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGE_DIR = ROOT / "spec/compatibility/broad-runs"
MANIFEST_PATH = PACKAGE_DIR / "prod-campaign-explain-01-v5.json"
BINDING_PATH = PACKAGE_DIR / "prod-campaign-explain-01-v5-binding.json"
SOURCE_COMMIT = "03b2942c7201da561f136890f07724fc0fca0449"
MANIFEST_SHA256 = "e9a5ab5f53e1c8fb13edd279b0facfcafd6551449f335e8fa5fc2bd8e6d3bb5f"
BINDING_SHA256 = "1cb661fab1afa4eab65b1a21ee9acfd23ff7e2301c77b6d854c9f92161007120"
OBSERVER_SHA256 = "7737e75a7bb976994b14ea011daa4ff8c634ac2c0289119fb8dac850f433c2a4"
MANIFEST_DIGEST = "44f5cb3215dd8b8da20f005e76d2692b1a6b765aff4e9c68f0ee881d69bbc911"


def load_json(path: Path) -> dict:
    return json.loads(path.read_bytes())


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()


def historical_blob(relative_path: str) -> bytes:
    return subprocess.check_output(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-C",
            str(ROOT),
            "cat-file",
            "blob",
            f"{SOURCE_COMMIT}:{relative_path}",
        ],
        stderr=subprocess.PIPE,
    )


def historical_observer_digest() -> str:
    campaign_files = (
        "campaign_explain.py",
        "campaign_explain_shadow.py",
        "batch_adapter.py",
        "shared_cases.py",
        "shared_gate.py",
        "shared_production.py",
        "shared_production_pair.py",
    )
    campaign = {
        name: hashlib.sha256(historical_blob(f"tools/compat-broad/{name}")).hexdigest()
        for name in campaign_files
    }
    shared_files = subprocess.check_output(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-C",
            str(ROOT),
            "ls-tree",
            "-r",
            "--name-only",
            SOURCE_COMMIT,
            "--",
            "tools/compat-broad",
        ],
        text=True,
    ).splitlines()
    excluded = {
        "campaign_explain.py",
        "campaign_explain_shadow.py",
        "test_campaign_explain.py",
    }
    shared = {
        Path(path).name: hashlib.sha256(historical_blob(path)).hexdigest()
        for path in shared_files
        if (
            path.startswith("tools/compat-broad/")
            and "/" not in path.removeprefix("tools/compat-broad/")
            and path.endswith(".py")
            and Path(path).name not in excluded
        )
    }
    runtime_helpers = {
        name: hashlib.sha256(
            historical_blob(f"tools/compat-inventory/{name}")
        ).hexdigest()
        for name in ("owned_runner.py", "evidence_common.py")
    }
    baseline = hashlib.sha256(
        historical_blob("tools/compat-broad/fixtures/database-settings-7be6cf08.json")
    ).hexdigest()
    return digest(
        {
            "campaign": campaign,
            "shared": digest(shared),
            "runtimeHelpers": runtime_helpers,
            "baseline": baseline,
        }
    )


def test_v5_package_bytes_and_cross_binding_are_immutable():
    manifest = load_json(MANIFEST_PATH)
    binding = load_json(BINDING_PATH)
    assert hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest() == MANIFEST_SHA256
    assert hashlib.sha256(BINDING_PATH.read_bytes()).hexdigest() == BINDING_SHA256
    assert manifest["kind"] == "production-campaign-explain-01-v5"
    assert binding["kind"] == "production-campaign-explain-01-comparison-v3"
    assert binding["manifestDigest"] == MANIFEST_DIGEST
    assert digest(manifest) == MANIFEST_DIGEST
    assert manifest["environment"]["observerSha256"] == OBSERVER_SHA256
    assert binding["observerSha256"] == OBSERVER_SHA256


def test_v5_observer_digest_uses_only_declared_historical_blobs():
    manifest = load_json(MANIFEST_PATH)
    binding = load_json(BINDING_PATH)
    assert historical_observer_digest() == OBSERVER_SHA256
    assert manifest["environment"]["observerSha256"] == binding["observerSha256"]
