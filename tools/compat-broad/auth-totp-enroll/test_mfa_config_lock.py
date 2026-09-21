"""The locked configuration step: saved pre-value, verified apply, verified restore."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
for entry in (
    ROOT / "tools/compat-broad",
    ROOT / "tools/compat-broad/production-admission",
    ROOT / "tools/compat-broad/o8-core",
    HERE,
):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

from conftest_rehearsal import BASELINE_CONFIG
from mfa_collector import digest
from mfa_config_lock import (
    BASELINE_FILE,
    LOCK_FILE,
    UPDATE_MASK,
    ConfigLock,
    ConfigLockError,
    applied,
    campaign_patch,
    normalized,
    redacted_reference,
    restore_patch,
    validate_evidence,
)


class Service:
    def __init__(self, config=None):
        self.config = copy.deepcopy(BASELINE_CONFIG if config is None else config)
        self.patches = []
        self.refuse_patch = False

    def read(self):
        return 200, copy.deepcopy(self.config)

    def patch(self, body, mask):
        self.patches.append((copy.deepcopy(body), mask))
        if self.refuse_patch:
            return 403, {"error": {"code": 403, "message": "PERMISSION_DENIED"}}
        assert mask == UPDATE_MASK
        self.config["mfa"] = copy.deepcopy(body["mfa"])
        self.config.setdefault("signIn", {})["phoneNumber"] = copy.deepcopy(
            body["signIn"]["phoneNumber"]
        )
        self.config["smsRegionConfig"] = copy.deepcopy(body["smsRegionConfig"])
        return 200, copy.deepcopy(self.config)


def lock_for(tmp_path, service, baseline=None):
    return ConfigLock(
        tmp_path,
        read=service.read,
        patch=service.patch,
        frozen_baseline_digest=baseline or digest(service.config),
    )


def test_the_pre_value_is_saved_privately_before_the_change_and_restored_after(
    tmp_path,
):
    service = Service()
    lock = lock_for(tmp_path, service)
    lock.preflight()
    assert (tmp_path / BASELINE_FILE).stat().st_mode & 0o077 == 0
    assert json.loads((tmp_path / BASELINE_FILE).read_bytes()) == BASELINE_CONFIG
    assert lock.record["baselineReference"]["valuesRetained"] is False
    assert lock.record["baselineReference"]["topLevelFields"] == sorted(BASELINE_CONFIG)
    assert lock.record["changeAttempted"] is False
    lock.apply()
    assert applied(service.config)
    assert lock.record["applied"] is True
    assert json.loads((tmp_path / LOCK_FILE).read_bytes())["changeAttempted"] is True
    lock.restore()
    assert not applied(service.config)
    # The absent phone block reads back as its disabled object, which is equal only
    # under the documented normalization, and the status says so.
    assert lock.record["restoreStatus"] == "restored-verified-normalized"
    assert lock.record["restoreDifferingFields"] == ["signIn"]
    assert validate_evidence(
        lock.evidence(), frozen_baseline_digest=lock.frozen_baseline_digest
    )
    assert normalized(service.config) == normalized(BASELINE_CONFIG)


def test_an_exact_baseline_restores_exactly(tmp_path):
    config = copy.deepcopy(BASELINE_CONFIG)
    config["signIn"]["phoneNumber"] = {"enabled": False, "testPhoneNumbers": {}}
    service = Service(config)
    lock = lock_for(tmp_path, service)
    lock.preflight()
    lock.apply()
    lock.restore()
    assert lock.record["restoreStatus"] == "restored-verified"
    assert lock.record["restoreReadbackDigest"] == lock.frozen_baseline_digest
    assert lock.record["restoreDifferingFields"] == []


def test_a_drifted_baseline_refuses_preflight_and_sends_no_change(tmp_path):
    service = Service()
    lock = lock_for(tmp_path, service, baseline="0" * 64)
    with pytest.raises(
        ConfigLockError, match="differs from the frozen baseline digest"
    ):
        lock.preflight()
    assert service.patches == []
    assert not (tmp_path / BASELINE_FILE).exists()
    with pytest.raises(ConfigLockError, match="preflight required"):
        lock.apply()
    assert lock.restore() is None
    assert lock.record["restoreStatus"] == "not-attempted"
    assert validate_evidence(lock.evidence(), frozen_baseline_digest="0" * 64)


def test_a_refused_restore_is_named_and_retried_by_a_later_process(tmp_path):
    service = Service()
    lock = lock_for(tmp_path, service)
    lock.preflight()
    lock.apply()
    service.refuse_patch = True
    with pytest.raises(ConfigLockError, match="restore answered 403"):
        lock.restore()
    assert lock.record["restoreStatus"] == "restore-failed"
    assert not validate_evidence(
        lock.evidence(), frozen_baseline_digest=lock.frozen_baseline_digest
    )
    service.refuse_patch = False
    resumed = ConfigLock.resume(
        tmp_path,
        read=service.read,
        patch=service.patch,
        frozen_baseline_digest=lock.frozen_baseline_digest,
    )
    assert resumed.record["changeAttempted"] is True
    resumed.restore()
    assert resumed.record["restoreStatus"] == "restored-verified-normalized"
    assert resumed.record["restoreAttempts"] == 2


def test_a_resume_admits_the_normalized_live_shape_and_nothing_else(tmp_path):
    service = Service()
    lock = lock_for(tmp_path, service)
    lock.preflight()
    lock.apply()
    lock.restore()
    resumed = ConfigLock.resume(
        tmp_path,
        read=service.read,
        patch=service.patch,
        frozen_baseline_digest=lock.frozen_baseline_digest,
    )
    resumed.preflight(resume=True)
    resumed.apply()
    assert resumed.record["restoreStatus"] == "not-attempted"
    resumed.restore()
    assert resumed.record["restoreStatus"] == "restored-verified-normalized"
    service.config["emailPrivacyConfig"] = {"enableImprovedEmailPrivacy": False}
    again = ConfigLock.resume(
        tmp_path,
        read=service.read,
        patch=service.patch,
        frozen_baseline_digest=lock.frozen_baseline_digest,
    )
    with pytest.raises(
        ConfigLockError, match="differs from the frozen baseline digest"
    ):
        again.preflight(resume=True)


def test_the_restore_patch_writes_back_exactly_the_masked_fields():
    patch = restore_patch(BASELINE_CONFIG)
    assert set(patch) == {"mfa", "signIn", "smsRegionConfig"}
    assert patch["signIn"] == {
        "phoneNumber": {"enabled": False, "testPhoneNumbers": {}}
    }
    assert patch["mfa"] == {"state": "DISABLED"}
    assert campaign_patch()["mfa"]["providerConfigs"][0]["totpProviderConfig"] == {
        "adjacentIntervals": 1
    }
    with pytest.raises(ConfigLockError, match="another project"):
        restore_patch({"name": "projects/1/config"})
    reference = redacted_reference(BASELINE_CONFIG)
    assert set(reference) == {"sha256", "bytes", "topLevelFields", "valuesRetained"}
