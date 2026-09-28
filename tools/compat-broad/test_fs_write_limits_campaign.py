"""Validate the independent FS-DATA-WRITE-LIMITS-02 preparation package."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "spec/compatibility/broad-runs"
MANIFEST = PACKAGE / "fs-write-limits-02.json"
BINDING = PACKAGE / "fs-write-limits-02-binding.json"
SHADOW = PACKAGE / "fs-write-limits-02-local-shadow.json"

def load(path: Path) -> dict:
    return json.loads(path.read_bytes())

def test_limits_package_is_independent_and_blocked_before_gate() -> None:
    manifest, binding, shadow = map(load, (MANIFEST, BINDING, SHADOW))
    assert manifest["campaignId"] == binding["campaignId"] == shadow["campaignId"] == "FS-DATA-WRITE-LIMITS-02"
    assert manifest["parentFeatureGroups"] == ["FS-DATA-WRITE"]
    assert manifest["status"] == binding["status"] == "BLOCKED_OWNER"
    assert manifest["technicalStatus"] == binding["technicalStatus"] == "BLOCKED_TECHNICAL"
    assert manifest["productionExecuted"] is binding["productionExecuted"] is shadow["productionExecuted"] is False
    assert manifest["gate"]["productionAuthorization"] is False
    assert manifest["gate"]["owner"] is None
    assert manifest["sourceBinding"]["artifactSha256"] is None
    assert binding["source"]["artifactSha256"] is None
    assert shadow["artifactSha256"] is None
    assert len(manifest["cases"]) == 4
    assert {case["kind"] for case in manifest["cases"]} == {"positive-control", "negative-control"}
    assert manifest["locks"] == [
        {"key": "firestore/(default)/documents/oracle/{freshNonce}/limits-02/*", "mode": "WRITE"},
        {"key": "firestore/(default)/indexes", "mode": "READ"},
        {"key": "firestore/(default)/ruleset", "mode": "READ"},
    ]
    assert manifest["dependency"]["requires"] == []
    assert all("production" not in command.lower() for command in shadow["execution"]["commands"])

def test_binding_uses_current_manifest_digest_and_fail_closed_cleanup() -> None:
    manifest, binding = load(MANIFEST), load(BINDING)
    assert binding["manifest"]["sha256"] == hashlib.sha256(MANIFEST.read_bytes()).hexdigest()
    assert any("artifact" in reason for reason in binding["blockingReasons"])
    assert any("collector" in reason for reason in binding["blockingReasons"])
    assert "unconditional delete" in manifest["cleanup"]["recovery"]
    for case in manifest["cases"]:
        assert case["resource"].count("{freshNonce}") == 1
        assert case["expected"]
