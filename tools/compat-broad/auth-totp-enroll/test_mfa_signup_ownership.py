"""The real sequence must register a signup ACK before later setup can fail."""
from __future__ import annotations

from pathlib import Path

import pytest
import mfa_local_shadow as shadow
from mfa_collector import load_checkpoint, outstanding_cleanup, run_complete


class Local(shadow.Instance):
    def __init__(self, mode):
        super().__init__("http://127.0.0.1:9099", "http://127.0.0.1:9100", "CONTROL")
        self.mode = mode
        self.calls = []
        self.present = False
    def require(self, *args):
        return shadow.Instance.require(self, *args)
    def public(self, path, body):
        uid = body.get("localId")
        if isinstance(uid, list):
            uid = uid[0] if len(uid) == 1 else None
        operation = "delete" if path.endswith(":delete") else "lookup" if path.endswith(":lookup") else None
        with self._request_budget.attempt(operation=operation, uid=uid):
            pass
        self.calls.append(path)
        if path.endswith(":signUp"):
            self.present = True
            value = {"localId":"owned-uid", "email":body["email"], "idToken":"PRIVATE-ID"}
            if self.mode == "signup-missing-token":
                value.pop("idToken")
            if self.mode == "signup-rejected":
                return 400, value
            if self.mode == "signup-error-coexists":
                value["error"] = {"message":"FAILED"}
            if self.mode == "signup-wrong-email":
                value["email"] = "other@example.invalid"
            if self.mode == "signup-malformed-uid":
                value["localId"] = []
            return 200, value
        if self.mode == "signin-exception":
            raise OSError("PRIVATE-HTTP")
        if self.mode == "signin-rejected":
            return 400, {"error":{"message":"REFUSED"}}
        if self.mode == "signin-missing-token":
            return 200, {}
        if self.mode == "signin-wrong-owner":
            return 200, {"localId":"other", "idToken":"PRIVATE"}
        if self.mode == "signin-error-coexists":
            return 200, {"idToken":"PRIVATE", "error":{}}
        return 200, {"idToken":"PRIVATE-SECOND"}
    def admin(self, path, body):
        uid = body.get("localId")
        if isinstance(uid, list):
            uid = uid[0] if len(uid) == 1 else None
        operation = "delete" if path.endswith(":delete") else "lookup" if path.endswith(":lookup") else None
        with self._request_budget.attempt(operation=operation, uid=uid):
            pass
        self.calls.append(path)
        if path.endswith(":update"):
            if self.mode == "update-exception":
                raise OSError("PRIVATE-HTTP")
            if self.mode == "update-rejected":
                return 400, {"error":{"message":"REFUSED"}}
            return 200, {}
        if path.endswith(":delete"):
            assert body["localId"] == "owned-uid"
            self.present = False
            return 200, {}
        assert path.endswith(":lookup") and body["localId"] == ["owned-uid"]
        return 200, {"users": []}


@pytest.mark.parametrize("mode", ["update-exception", "update-rejected", "signin-exception", "signin-rejected", "signin-missing-token", "signup-missing-token", "signin-wrong-owner", "signin-error-coexists"])
def test_acknowledged_account_is_recovered_when_later_setup_fails(tmp_path, mode):
    instance = Local(mode)
    with pytest.raises((OSError, ValueError, KeyError, shadow.Refused)):
        shadow.run_sequence(instance, tmp_path)
    state = load_checkpoint((tmp_path/"checkpoint.json").read_bytes())
    assert len(state["ownedResources"]) == 1
    assert state["ownedResources"][0]["id"] == "owned-uid"
    assert not outstanding_cleanup(state)
    assert not instance.present
    assert not run_complete(state)
    assert instance.calls[-2].endswith(":delete") and instance.calls[-1].endswith(":lookup")
    assert state["requests"] == instance.requests
    assert b"PRIVATE" not in (tmp_path/"checkpoint.json").read_bytes()


@pytest.mark.parametrize("mode", ["signup-rejected", "signup-error-coexists", "signup-wrong-email", "signup-malformed-uid"])
def test_invalid_signup_never_grants_delete_authority(tmp_path, mode):
    instance = Local(mode)
    with pytest.raises((ValueError, KeyError, shadow.Refused)):
        shadow.run_sequence(instance, tmp_path)
    state = load_checkpoint((tmp_path/"checkpoint.json").read_bytes())
    assert not state["ownedResources"]
    assert len(instance.calls) == 1
    assert not run_complete(state)
    # The fake backend deliberately simulated a possible creation even on a
    # bad ACK. No UID discovery or automatic deletion is claimed by this test.
    assert instance.present


def test_checkpoint_failure_after_ack_does_not_start_verification_but_still_recovers(tmp_path, monkeypatch):
    instance = Local("normal")
    original = shadow.RunPersistence.save_checkpoint
    attempts = 0
    def write(journal, state):
        nonlocal attempts
        attempts += 1
        # Initial empty checkpoint is first; the second follows the signup ACK.
        if attempts == 2:
            raise OSError("checkpoint failed")
        return original(journal, state)
    monkeypatch.setattr(shadow.RunPersistence, "save_checkpoint", write)
    with pytest.raises(OSError, match="checkpoint failed"):
        shadow.run_sequence(instance, tmp_path)
    assert all(not path.endswith(":update") for path in instance.calls)
    assert not instance.present
    assert not outstanding_cleanup(load_checkpoint((tmp_path/"checkpoint.json").read_bytes()))


def test_callback_observes_ack_before_any_further_requests():
    instance = Local("normal")
    events = []
    account = shadow.create_account(instance, "ours@example.invalid", on_created=lambda a: events.append((dict(a), list(instance.calls))))
    assert len(events) == 1
    assert events[0][0] == {"localId":"owned-uid", "email":"ours@example.invalid"}
    assert len(events[0][1]) == 1 and events[0][1][0].endswith(":signUp")
    assert account["idToken"] == "PRIVATE-SECOND"


def test_malformed_error_body_does_not_mask_transport_cleanup():
    for body in [{"error":None}, {"error":"bad"}, [], None]:
        assert shadow._code_of(body) is None
