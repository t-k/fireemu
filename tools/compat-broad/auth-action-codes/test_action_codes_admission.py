import hashlib
import json
import sys
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))
sys.path.insert(0, str(HERE))

import action_codes_admission as admission
import action_codes_descriptor as campaign
from broad_contract import digest
from o8_campaign import CAMPAIGN_APPROVAL_FIELDS


NONCE = "b" * 32


def _artifacts(tmp_path):
    descriptor = campaign.descriptor()
    plan = descriptor.plan_compiler(NONCE)
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"action-code-local-shadow-artifact")
    source_inputs = campaign.source_map()
    permission = campaign.permission_bindings(
        plan, "0" * 40, hashlib.sha256(artifact.read_bytes()).hexdigest(), source_inputs
    )
    inputs = admission.freeze_inputs(
        permission, plan, source_commit="0" * 40, artifact_sha256=permission["artifactSha256"]
    )
    manifest = {"kind": campaign.MANIFEST_KIND, "inputsDigest": inputs["inputsDigest"]}
    manifest_bytes = json.dumps(manifest, sort_keys=True).encode()
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(manifest_bytes)
    launcher = tmp_path / "launcher"
    launcher.write_bytes(b"offline launcher")
    now = time.time()
    approval = {
        "kind": campaign.APPROVAL_KIND,
        "status": "approved",
        "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "inputsDigest": inputs["inputsDigest"],
        "permissionDigest": inputs["permissionDigest"],
        "sourceCommit": inputs["sourceCommit"],
        "sourceInputsDigest": digest(inputs["sourceInputs"]),
        "artifactSha256": inputs["artifactSha256"],
        "planDigest": inputs["planDigest"],
        "nonceDigest": digest(NONCE),
        "ledgerRoot": str((tmp_path / "ledger").resolve()),
        "launcherSha256": hashlib.sha256(launcher.read_bytes()).hexdigest(),
        "artifactProfile": descriptor.artifact_profile,
        "windowStartsAt": now - 1,
        "windowExpiresAt": now + descriptor.window_seconds + 10,
        "executionHost": admission.execution_host(),
        "campaignId": campaign.CAMPAIGN,
    }
    assert set(approval) == CAMPAIGN_APPROVAL_FIELDS
    return descriptor, inputs, permission, manifest, manifest_bytes, manifest_path, artifact, launcher, approval


def test_o7_issue_path_accepts_temporary_ledger_artifacts(tmp_path):
    values = _artifacts(tmp_path)
    descriptor, inputs, permission, manifest, manifest_bytes, manifest_path, artifact, launcher, approval = values
    ledger = tmp_path / "ledger"
    ledger.mkdir()
    worker = (ROOT / campaign.WORKER_ENTRY).read_bytes()
    capability = admission.issue_production_capability(
        inputs=inputs,
        approval=approval,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        manifest_path=manifest_path,
        permission=permission,
        ledger_root=ledger,
        artifact_path=artifact,
        launcher_path=launcher,
        binding=worker,
        binding_digest=hashlib.sha256(worker).hexdigest(),
    )
    assert capability.campaign_id == campaign.CAMPAIGN


@pytest.mark.parametrize("field", ["project", "nonce", "planDigest"])
def test_forged_plan_binding_is_rejected(tmp_path, field):
    values = _artifacts(tmp_path)
    descriptor, inputs, permission, manifest, manifest_bytes, manifest_path, artifact, launcher, approval = values
    forged = json.loads(json.dumps(inputs))
    forged["plan"]["localProject"] = "foreign-project"
    if field == "nonce":
        forged["plan"]["nonce"] = "c" * 32
    if field == "planDigest":
        forged["planDigest"] = "0" * 64
    forged["inputsDigest"] = digest({key: value for key, value in forged.items() if key != "inputsDigest"})
    with pytest.raises(ValueError):
        admission.validate_o7_admission(
            inputs=forged,
            approval=approval,
            manifest=manifest,
            manifest_bytes=manifest_bytes,
            manifest_path=manifest_path,
            permission=permission,
            ledger_root=tmp_path / "ledger",
            artifact_path=artifact,
            launcher_path=launcher,
        )
