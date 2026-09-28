"""Recovery must not turn malformed lookups into absence or change account identity."""
from __future__ import annotations

import copy

import pytest

from action_codes_collector import CollectorError, _Run, collect
from test_action_codes_collector import FakeService, NONCE, ORIGIN, PROJECT


def run_service(service):
    return collect(origin=ORIGIN, project=PROJECT, nonce=NONCE,
                   send=service.send, clock=lambda: 0.0, sleep=lambda _: None,
                   tolerate_failure=True)


BAD_ABSENCE = [
    {}, {"users": None}, {"users": False}, {"users": 0}, {"users": ""},
    {"users": [None]}, {"users": [{}]},
    {"kind": "not-an-account-lookup"},
    {"users": [], "error": {"message": "UNAVAILABLE"}},
    {"kind": "identitytoolkit#GetAccountInfoResponse", "users": None},
    {"users": [{"email": "someone-else@example.invalid", "localId": "foreign"}]},
]


@pytest.mark.parametrize("body", BAD_ABSENCE)
def test_malformed_final_lookup_cannot_prove_absence(body):
    class Service(FakeService):
        lookups = 0
        def _lookup(self, request):
            if "email" in request:
                self.lookups += 1
                if self.lookups == 2:
                    return 200, copy.deepcopy(body)
            return super()._lookup(request)
    receipt = run_service(Service())
    assert receipt["absenceProven"] is False
    assert receipt["cleanupComplete"] is False
    assert receipt["remainingAccounts"] > 0


@pytest.mark.parametrize("field,value", [
    ("localId", None), ("localId", ""), ("localId", 9),
    ("localId", "different-uid"), ("email", None),
    ("email", "foreign@example.invalid"),
])
def test_discovery_with_invalid_or_changed_identity_never_deletes(field, value):
    class Service(FakeService):
        discovering = False
        recovery_deletes = []
        def _lookup(self, request):
            status, body = super()._lookup(request)
            if "email" in request:
                self.discovering = True
                if body.get("users"):
                    body["users"][0][field] = value
            return status, body
        def _delete(self, request):
            if self.discovering:
                self.recovery_deletes.append(request["localId"])
            return super()._delete(request)
    service = Service()
    receipt = run_service(service)
    assert service.recovery_deletes == []
    assert receipt["cleanupComplete"] is False


@pytest.mark.parametrize("mutation", ["duplicate-email", "duplicate-uid", "unpaged-token"])
def test_discovery_is_an_exact_unambiguous_owned_address_set(mutation):
    class Service(FakeService):
        def _lookup(self, request):
            status, body = super()._lookup(request)
            if "email" in request and body.get("users"):
                users = body["users"]
                if mutation == "duplicate-email": users.append(dict(users[0]))
                elif mutation == "duplicate-uid":
                    other = request["email"][-1]
                    users.append({"email": other, "localId": users[0]["localId"]})
                else: body["nextPageToken"] = "unconsumed-page"
            return status, body
    receipt = run_service(Service())
    assert receipt["cleanupComplete"] is False


@pytest.mark.parametrize("body", [
    {"users": []},
    {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []},
])
def test_explicit_typed_empty_result_remains_accepted(body):
    class Service(FakeService):
        def _lookup(self, request):
            status, actual = super()._lookup(request)
            if "email" in request and not actual.get("users"):
                return 200, copy.deepcopy(body)
            return status, actual
    service = Service()
    receipt = run_service(service)
    assert receipt["cleanupComplete"] is True
    assert receipt["absenceProven"] is True
    assert service.accounts == {}


def test_kind_only_empty_result_is_not_typed_absence():
    class Service(FakeService):
        def _lookup(self, request):
            status, actual = super()._lookup(request)
            if "email" in request and not actual.get("users"):
                return 200, {"kind": "identitytoolkit#GetAccountInfoResponse"}
            return status, actual

    receipt = run_service(Service())
    assert receipt["absenceProven"] is False
    assert receipt["cleanupComplete"] is False


def test_rate_wait_cannot_authorize_a_request_after_its_phase_deadline():
    clock = [0.0]
    calls = []
    run = _Run(ORIGIN, PROJECT, NONCE, lambda *args: calls.append(args),
               10, 4, 1, 3, lambda: clock[0], 4,
               lambda delay: clock.__setitem__(0, clock[0] + delay))
    run.last_start = 0.9
    clock[0] = 0.95
    with pytest.raises(CollectorError, match="wall clock"):
        run.request("/identitytoolkit.googleapis.com/v1/accounts:signUp", {}, False)
    assert calls == []


def test_exact_observation_deadline_is_closed_but_recovery_has_own_reserve():
    clock = [0.0]
    calls = []
    run = _Run(ORIGIN, PROJECT, NONCE, lambda *args: calls.append(args) or (200, {}),
               10, 4, 1, 3, lambda: clock[0], 4, lambda _: None)
    clock[0] = 1.0
    with pytest.raises(CollectorError, match="wall clock"):
        run.request("/identitytoolkit.googleapis.com/v1/accounts:signUp", {}, False)
    run.begin_recovery()
    run.request("/identitytoolkit.googleapis.com/v1/projects/{project}/accounts:lookup", {}, True)
    assert len(calls) == 1


def test_projection_failure_still_enters_recovery():
    class Service(FakeService):
        def _sendOobCode(self, request):
            status, body = super()._sendOobCode(request)
            body["email"] = []  # unhashable shape, after an actual owned create
            return status, body
    service = Service()
    receipt = run_service(service)
    assert receipt["recordingComplete"] is False
    assert receipt["cleanupComplete"] is True
    assert service.accounts == {}


def test_error_response_cannot_bind_a_successful_account_creation():
    class Service(FakeService):
        def _signUp(self, request):
            return 400, {"error": {"message": "INVALID_ARGUMENT"},
                         "localId": "unacknowledged-user", "email": request["email"]}
    receipt = run_service(Service())
    assert receipt["ownedAccounts"] == {}
    assert all(not row.get("accountCreated", False) for row in receipt["stages"])
