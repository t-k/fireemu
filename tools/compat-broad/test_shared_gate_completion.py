"""Request-complete ownership and retirement regressions; no network or credentials."""

import copy
import socket
from urllib.parse import quote

import pytest
import shared_gate
from shared_gate import (
    Gate,
    abandoned_cleanup_complete,
    body_reference,
    can_create,
    create,
    creating_outcome,
    unconfirmed_creates,
)

ROOT = "projects/p/databases/(default)/documents"
RESOURCES = [ROOT + "/owned/a", ROOT + "/owned/b"]
AUTH_RESOURCES = [
    "projects/demo/auth/accounts/acct-0",
    "projects/demo/auth/accounts/acct-1",
    "projects/demo/auth/accounts/acct-2",
]
VERSION = "2026-09-18T00:00:00.000000Z"
ABSENCE = {"error": {"code": 404, "status": "NOT_FOUND"}}


class Clock:
    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        assert seconds >= 0
        self.now += seconds


@pytest.fixture(autouse=True)
def local_only(monkeypatch):
    # Deterministic time does not replace persistence or Gate/Ledger decisions.
    monkeypatch.setattr(shared_gate, "time", Clock())

    def forbidden(*_args, **_kwargs):
        pytest.fail("network is forbidden in ownership unit tests")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


def fields(resource):
    return {"_sharedOwner": {"referenceValue": resource}}


def conditional(resource):
    return {
        "update": {"name": resource, "fields": fields(resource)},
        "currentDocument": {"exists": False},
    }


def transform(resource=RESOURCES[0]):
    return {
        "transform": {
            "document": resource,
            "fieldTransforms": [{"fieldPath": "n", "increment": {"integerValue": "1"}}],
        },
        "currentDocument": {"exists": True},
    }


def bulk(writes=None, endpoint="commit"):
    return {
        "service": "firestore",
        "method": "POST",
        "path": "/v1/" + ROOT + ":" + endpoint,
        "body": {"writes": [transform()] if writes is None else writes},
    }


def read(resource):
    return {
        "service": "firestore",
        "method": "GET",
        "path": "/v1/" + resource,
        "body": None,
    }


def auth_lookup(resource, account, *, recovery_marker=False):
    operation = {
        "service": "auth",
        "method": "POST",
        "path": "identitytoolkit.googleapis.com/v1/projects/demo/accounts:lookup",
        "body": {"localId": ["$binding:" + account + "Uid"]},
        "form": False,
        "owner": True,
        "kind": "uid-absence",
        "account": account,
        "resource": resource,
    }
    if recovery_marker:
        operation["recoveryMarker"] = True
    return operation


def plan(operation, *, scheduled=False, full_cleanup=False):
    recovery = []
    for resource in RESOURCES:
        if full_cleanup:
            source = len(recovery)
            recovery.extend(
                [
                    read(resource),
                    {
                        "service": "firestore",
                        "method": "DELETE",
                        "path": "/v1/" + resource,
                        "body": None,
                        "versionFrom": source,
                    },
                ]
            )
        recovery.append(read(resource))
    job = {"resources": RESOURCES[:], "observation": [operation], "recovery": recovery}
    if scheduled:
        job["schedule"] = [
            {"phase": "observation", "index": 0, "creates": True},
            *[
                {"phase": "recovery", "index": i, "creates": False}
                for i in range(len(recovery))
            ],
        ]
    return {
        "contract": "shared-local-v2",
        "wallSeconds": 1000,
        "recoverySeconds": 500,
        "requestSeconds": 1,
        "observationRequests": 1,
        "costMicrousd": 10000,
        "requestCostMicrousd": 100,
        "intervalSeconds": 0.25,
        "jobs": {"case": job},
    }


def started(tmp_path, operation, **kwargs):
    p = plan(operation, **kwargs)
    path = tmp_path / "gate"
    create(path, p)
    gate = Gate(path, "case")
    gate.claim()
    return gate, p


def recover(gate, p, created=()):
    """Simulated owned cleanup including guarded deletes and final typed readback."""
    operations = p["jobs"]["case"]["recovery"]
    for index, frozen in enumerate(operations):
        operation = copy.deepcopy(frozen)
        source = operation.pop("versionFrom", None)
        resource = (
            operation["resource"]
            if operation["service"] == "auth"
            else operation["path"].removeprefix("/v1/")
        )
        if source is not None and resource in created:
            operation["path"] += "?currentDocument.updateTime=" + quote(
                VERSION, safe=""
            )
        if operation["service"] == "auth":
            gate.dispatch(operation, True, lambda: (200, {"users": []}))
        elif operation["method"] == "DELETE":
            gate.dispatch(operation, True, lambda: (200, {}))
        elif (
            resource in created
            and index + 1 < len(operations)
            and operations[index + 1]["method"] == "DELETE"
        ):
            gate.dispatch(
                operation,
                True,
                lambda resource=resource: (
                    200,
                    {
                        "name": resource,
                        "fields": fields(resource),
                        "updateTime": VERSION,
                    },
                ),
            )
        else:
            gate.dispatch(operation, True, lambda: (404, copy.deepcopy(ABSENCE)))


def response(codes, endpoint="batchWrite"):
    body = {
        "writeResults": [
            {"updateTime": VERSION} if code == 0 else {} for code in codes
        ]
    }
    if endpoint == "batchWrite":
        body["status"] = [{} if code == 0 else {"code": code} for code in codes]
    else:
        body["commitTime"] = VERSION
    return 200, body


@pytest.mark.parametrize("value", [1, 1.0, "true", False, None, 0, {}, []])
def test_transform_requires_an_actual_json_true(value):
    operation = bulk()
    operation["body"]["writes"][0]["currentDocument"]["exists"] = value
    assert can_create(operation) is True


@pytest.mark.parametrize("endpoint", ["commit", "batchWrite"])
def test_known_existing_transform_remains_non_creating(endpoint):
    operation = bulk([transform(resource) for resource in RESOURCES], endpoint)
    assert can_create(operation) is False


@pytest.mark.parametrize("change", [
    "service", "method", "path", "query", "fragment", "body-reference",
    "update-oneof", "delete-oneof", "unknown-write-field", "extra-precondition",
    "missing-precondition", "missing-transform", "empty-writes", "mixed-batch",
])
def test_non_creating_shortcut_refuses_unrecognized_or_ambiguous_shapes(change):
    operation = bulk()
    write = operation["body"]["writes"][0]
    if change == "service":
        operation["service"] = "auth"
    elif change == "method":
        operation["method"] = "PATCH"
    elif change == "path":
        operation["path"] = "/v1/something:commit"
    elif change == "query":
        operation["path"] += "?unknown=true"
    elif change == "fragment":
        operation["path"] += "#fragment"
    elif change == "body-reference":
        operation["bodyRef"] = {"sha256": "0" * 64, "bytes": 123}
    elif change == "update-oneof":
        write["update"] = {"name": RESOURCES[1]}
    elif change == "delete-oneof":
        write["delete"] = RESOURCES[1]
    elif change == "unknown-write-field":
        write["unknown"] = True
    elif change == "extra-precondition":
        write["currentDocument"]["updateTime"] = VERSION
    elif change == "missing-precondition":
        del write["currentDocument"]
    elif change == "missing-transform":
        del write["transform"]
    elif change == "empty-writes":
        operation["body"]["writes"] = []
    elif change == "mixed-batch":
        operation["body"]["writes"].append(conditional(RESOURCES[1]))
    assert can_create(operation) is True


@pytest.mark.parametrize("value", [1, 1.0, "true"])
def test_schedule_cannot_declare_numeric_or_string_guard_non_creating(tmp_path, value):
    operation = bulk()
    operation["body"]["writes"][0]["currentDocument"]["exists"] = value
    p = plan(operation, scheduled=True)
    p["jobs"]["case"]["schedule"][0]["creates"] = False
    with pytest.raises(ValueError, match="can create"):
        create(tmp_path / "gate", p)
    assert not (tmp_path / "gate").exists()


@pytest.mark.parametrize("endpoint", ["commit", "batchWrite"])
def test_unknown_legacy_transform_guard_survives_full_recovery(tmp_path, endpoint):
    operation = bulk(endpoint=endpoint)
    operation["body"]["writes"][0]["currentDocument"]["exists"] = 1
    gate, p = started(tmp_path, operation)

    def timeout():
        raise TimeoutError("simulated lost acknowledgement")

    with pytest.raises(TimeoutError):
        gate.dispatch(operation, False, timeout)
    recover(gate, p)
    assert unconfirmed_creates(gate.snapshot(), "case") == 1
    with pytest.raises(ValueError, match="ownership retained"):
        gate.finish()
    assert gate.snapshot()["jobs"]["case"]["complete"] is False


@pytest.mark.parametrize("scheduled", [False, True], ids=["legacy", "scheduled"])
# Transient and unclassified failures retain ownership, unlike a typed
# ALREADY_EXISTS on an exact conditional create.
@pytest.mark.parametrize("code", [4, 13, 14, 2, 8])
@pytest.mark.parametrize("failed_index", [0, 1])
def test_partial_batch_acknowledgement_retains_unknown_creation(
    tmp_path, scheduled, code, failed_index
):
    operation = bulk([conditional(resource) for resource in RESOURCES], "batchWrite")
    gate, p = started(tmp_path, operation, scheduled=scheduled, full_cleanup=True)
    codes = [0, 0]
    codes[failed_index] = code
    gate.dispatch(operation, False, lambda: response(codes))
    proved = RESOURCES[1 - failed_index]
    # A settled sibling's cleanup authority is retained, but not promoted to a
    # complete acknowledgement of the other potentially creating write.
    assert set(gate.snapshot()["jobs"]["case"]["creationProofs"]) == {proved}
    recover(gate, p, created=[proved])
    snapshot = gate.snapshot()
    assert set(snapshot["jobs"]["case"]["absent"]) == set(RESOURCES)
    assert snapshot["jobs"]["case"]["recovery"] == len(p["jobs"]["case"]["recovery"])
    assert unconfirmed_creates(snapshot, "case") == 1
    assert snapshot["events"][0]["creationOutcome"] == "unknown"
    before = (gate.path / "state.json").read_bytes()
    with pytest.raises(ValueError, match="ownership retained"):
        gate.finish()
    assert (gate.path / "state.json").read_bytes() == before


@pytest.mark.parametrize("endpoint", ["commit", "batchWrite"])
@pytest.mark.parametrize("scheduled", [False, True])
def test_all_confirmed_creates_still_finish(tmp_path, endpoint, scheduled):
    operation = bulk([conditional(resource) for resource in RESOURCES], endpoint)
    gate, p = started(tmp_path, operation, scheduled=scheduled, full_cleanup=True)
    gate.dispatch(operation, False, lambda: response([0, 0], endpoint))
    assert unconfirmed_creates(gate.snapshot(), "case") == 0
    recover(gate, p, created=RESOURCES)
    gate.finish()
    assert gate.snapshot()["jobs"]["case"]["complete"] is True


@pytest.mark.parametrize("codes", [[0, 3], [3, 0], [3, 3]])
@pytest.mark.parametrize("scheduled", [False, True])
def test_typed_invalid_argument_items_are_settled_without_fabricating_proofs(
    tmp_path, codes, scheduled
):
    operation = bulk([conditional(resource) for resource in RESOURCES], "batchWrite")
    gate, p = started(tmp_path, operation, scheduled=scheduled, full_cleanup=True)
    gate.dispatch(operation, False, lambda: response(codes))
    proved = [
        resource
        for resource, code in zip(RESOURCES, codes, strict=True)
        if code == 0
    ]
    snapshot = gate.snapshot()
    assert set(snapshot["jobs"]["case"]["creationProofs"]) == set(proved)
    assert unconfirmed_creates(snapshot, "case") == 0
    expected = "created" if proved else "refused"
    assert snapshot["events"][0]["creationOutcome"] == expected
    recover(gate, p, created=proved)
    gate.finish()


@pytest.mark.parametrize("endpoint", ["commit", "batchWrite"])
@pytest.mark.parametrize(
    "shape",
    ["unguarded-update", "unguarded-transform", "numeric-false", "mixed-oneof"],
)
def test_one_creation_proof_does_not_settle_an_unaccounted_write(
    tmp_path, endpoint, shape
):
    writes = [conditional(resource) for resource in RESOURCES]
    if shape == "unguarded-update":
        writes[1].pop("currentDocument")
    elif shape == "unguarded-transform":
        writes[1] = {"transform": transform(RESOURCES[1])["transform"]}
    elif shape == "numeric-false":
        writes[1]["currentDocument"]["exists"] = 0
    elif shape == "mixed-oneof":
        writes[1]["transform"] = transform(RESOURCES[1])["transform"]
    operation = bulk(writes, endpoint)
    gate, p = started(tmp_path, operation)
    gate.dispatch(operation, False, lambda: response([0, 0], endpoint))
    recover(gate, p)
    assert unconfirmed_creates(gate.snapshot(), "case") == 1
    with pytest.raises(ValueError, match="ownership retained"):
        gate.finish()


@pytest.mark.parametrize("endpoint", ["commit", "batchWrite"])
def test_existing_guarded_transform_does_not_require_a_new_creation_proof(
    tmp_path, endpoint
):
    operation = bulk([conditional(RESOURCES[0]), transform(RESOURCES[1])], endpoint)
    gate, p = started(tmp_path, operation)
    gate.dispatch(operation, False, lambda: response([0, 0], endpoint))
    assert set(gate.snapshot()["jobs"]["case"]["creationProofs"]) == {RESOURCES[0]}
    assert unconfirmed_creates(gate.snapshot(), "case") == 0
    recover(gate, p)
    gate.finish()


@pytest.mark.parametrize("status,body", [
    (400, {"error": {"code": 400, "status": "INVALID_ARGUMENT"}}),
    (500, {"error": {"code": 500, "status": "INTERNAL"}}),
    (504, {"error": {"code": 504, "status": "DEADLINE_EXCEEDED"}}),
    (400, {"error": {"code": "400", "status": "INVALID_ARGUMENT"}}),
])
def test_whole_request_refusal_keeps_its_existing_narrow_contract(
    tmp_path, status, body
):
    operation = bulk([conditional(resource) for resource in RESOURCES])
    gate, _ = started(tmp_path, operation)
    gate.dispatch(operation, False, lambda: (status, body))
    settled = status == 400 and type(body["error"]["code"]) is int
    assert unconfirmed_creates(gate.snapshot(), "case") == (0 if settled else 1)
    expected = "refused" if settled else "unsettled"
    assert creating_outcome(gate.snapshot(), "case") == expected


@pytest.mark.parametrize("scheduled", [False, True])
def test_http_finish_accepts_current_typed_readback(tmp_path, scheduled):
    operation = read(RESOURCES[0])
    p = plan(operation, scheduled=scheduled)
    if scheduled:
        p["jobs"]["case"]["schedule"][0]["creates"] = False
    create(tmp_path / "gate", p)
    gate = Gate(tmp_path / "gate", "case")
    gate.claim()
    gate.dispatch(operation, False, lambda: (404, copy.deepcopy(ABSENCE)))
    recover(gate, p)
    gate.finish()
    assert gate.snapshot()["jobs"]["case"]["complete"] is True


@pytest.mark.parametrize("services", [("auth", "auth"), ("auth", "firestore")])
def test_generic_facade_completion_does_not_require_firestore_only_receipts(
    tmp_path, services
):
    # Generic Gate completion and production Ledger release are different
    # boundaries. These synthetic facade responses test the former only;
    # they are not Identity Platform wire-format or production evidence.
    operation = read(RESOURCES[0])
    p = plan(operation)
    p["project"] = "demo"
    job = p["jobs"]["case"]
    job["resources"] = [AUTH_RESOURCES[0]]
    job["recovery"] = [auth_lookup(AUTH_RESOURCES[0], "acct0", recovery_marker=True)]
    for index, service in enumerate(services[1:], start=1):
        if service == "auth":
            job["resources"].append(AUTH_RESOURCES[index])
            job["recovery"].append(auth_lookup(AUTH_RESOURCES[index], f"acct{index}"))
        else:
            job["resources"].append(RESOURCES[0])
            job["recovery"].append(read(RESOURCES[0]))
    create(tmp_path / "gate", p)
    gate = Gate(tmp_path / "gate", "case")
    gate.claim()
    gate.dispatch(operation, False, lambda: (404, copy.deepcopy(ABSENCE)))
    recover(gate, p)
    gate.finish()
    assert gate.snapshot()["jobs"]["case"]["complete"] is True


@pytest.mark.parametrize("body_kind", ["inline", "reference"])
@pytest.mark.parametrize("phase", ["observation", "recovery"])
def test_legacy_body_slots_cannot_underreserve_declared_wire_ceiling(
    tmp_path, body_kind, phase
):
    operation = bulk([conditional(resource) for resource in RESOURCES])
    if body_kind == "reference":
        operation["bodyRef"] = body_reference(operation.pop("body"))
    p = plan(operation if phase == "observation" else read(RESOURCES[0]))
    if phase == "recovery":
        p["jobs"]["case"]["recovery"][0] = operation
    p["transportCeilingSeconds"] = 5
    with pytest.raises(ValueError, match="invalid shared allocation"):
        create(tmp_path / "gate", p)
    assert not (tmp_path / "gate").exists()


@pytest.mark.parametrize("seconds", [5, 6])
def test_legacy_body_slots_accept_sufficient_wire_reserve(tmp_path, seconds):
    p = plan(bulk([conditional(resource) for resource in RESOURCES]))
    p.update(transportCeilingSeconds=5, requestSeconds=seconds)
    create(tmp_path / "gate", p)


def test_legacy_read_only_slots_do_not_inherit_a_body_upload_ceiling(tmp_path):
    p = plan(read(RESOURCES[0]))
    p["transportCeilingSeconds"] = 5
    create(tmp_path / "gate", p)


@pytest.mark.parametrize("scheduled", [False, True])
def test_conditional_patch_creation_keeps_its_existing_completion_path(
    tmp_path, scheduled
):
    resource = RESOURCES[0]
    operation = {
        "service": "firestore",
        "method": "PATCH",
        "path": "/v1/" + resource + "?currentDocument.exists=false",
        "body": {"fields": fields(resource)},
    }
    gate, p = started(tmp_path, operation, scheduled=scheduled, full_cleanup=True)
    gate.dispatch(
        operation,
        False,
        lambda: (
            200,
            {"name": resource, "fields": fields(resource), "updateTime": VERSION},
        ),
    )
    assert unconfirmed_creates(gate.snapshot(), "case") == 0
    recover(gate, p, created=[resource])
    gate.finish()
    assert gate.snapshot()["jobs"]["case"]["complete"] is True


@pytest.mark.parametrize("codes", [[3, 3], [0, 3]])
@pytest.mark.parametrize(
    "invalid_result",
    [None, [], {"updateTime": VERSION}, {"transformResults": []}, {"unknown": 0}],
)
def test_malformed_or_contradictory_refusal_result_cannot_settle_creation(
    tmp_path, codes, invalid_result
):
    operation = bulk([conditional(resource) for resource in RESOURCES], "batchWrite")
    gate, p = started(tmp_path, operation)
    status, body = response(codes)
    body["writeResults"][1] = invalid_result
    gate.dispatch(operation, False, lambda: (status, body))
    recover(gate, p)
    assert unconfirmed_creates(gate.snapshot(), "case") == 1
    with pytest.raises(ValueError, match="ownership retained"):
        gate.finish()


@pytest.mark.parametrize("scheduled", [False, True])
@pytest.mark.parametrize("codes", [(0, 6), (6, 0), (6, 6), (3, 6), (6, 3)])
def test_conditional_batch_conflicts_settle_without_granting_foreign_ownership(
    tmp_path, scheduled, codes
):
    operation = bulk([conditional(resource) for resource in RESOURCES], "batchWrite")
    gate, declared = started(tmp_path, operation, scheduled=scheduled, full_cleanup=True)
    gate.dispatch(operation, False, lambda: response(codes))
    state = gate.snapshot()
    owned = {RESOURCES[i] for i, code in enumerate(codes) if code == 0}
    assert set(state["jobs"]["case"]["owned"]) == owned
    assert unconfirmed_creates(state, "case") == 0
    recover(gate, declared, created=owned)
    gate.finish()
    assert gate.snapshot()["jobs"]["case"]["complete"] is True


@pytest.mark.parametrize("scheduled", [False, True])
@pytest.mark.parametrize("bad_result", [{"updateTime": VERSION}, None, [], "", False])
def test_conflicting_batch_status_with_nonempty_or_untyped_result_stays_unknown(
    tmp_path, scheduled, bad_result
):
    operation = bulk([conditional(resource) for resource in RESOURCES], "batchWrite")
    gate, declared = started(tmp_path, operation, scheduled=scheduled, full_cleanup=True)
    status, body = response((0, 6))
    body["writeResults"][1] = bad_result
    gate.dispatch(operation, False, lambda: (status, body))
    assert unconfirmed_creates(gate.snapshot(), "case") == 1
    assert RESOURCES[1] not in gate.snapshot()["jobs"]["case"]["owned"]
    recover(gate, declared, created={RESOURCES[0]})
    with pytest.raises(ValueError, match="ownership retained"):
        gate.finish()


@pytest.mark.parametrize("scheduled", [False, True])
@pytest.mark.parametrize("sibling_code", [0, 3])
def test_empty_batch_item_with_typed_refusal_settles_the_batch(
    tmp_path, scheduled, sibling_code
):
    """R3: an undecodable BatchWrite item alongside a real conditional write.

    An empty item names no document, so it never earns a creation proof, but a
    complete typed refusal (code 3, empty result) for it does not leave the
    sibling write's outcome unknown.
    """
    operation = bulk([{}, conditional(RESOURCES[0])], "batchWrite")
    gate, declared = started(tmp_path, operation, scheduled=scheduled, full_cleanup=True)
    gate.dispatch(operation, False, lambda: response([3, sibling_code]))
    state = gate.snapshot()
    proved = {RESOURCES[0]} if sibling_code == 0 else set()
    assert set(state["jobs"]["case"]["owned"]) == proved
    assert unconfirmed_creates(state, "case") == 0
    assert state["events"][0]["creationOutcome"] == ("created" if proved else "refused")
    recover(gate, declared, created=proved)
    gate.finish()
    assert gate.snapshot()["jobs"]["case"]["complete"] is True


@pytest.mark.parametrize("scheduled", [False, True])
@pytest.mark.parametrize(
    "malform",
    ["wrong-code", "nonempty-result", "missing-code-field", "untyped-result"],
)
def test_empty_batch_item_without_a_clean_refusal_stays_unknown(
    tmp_path, scheduled, malform
):
    operation = bulk([{}, conditional(RESOURCES[0])], "batchWrite")
    gate, declared = started(tmp_path, operation, scheduled=scheduled, full_cleanup=True)
    status, body = response([3, 0])
    if malform == "wrong-code":
        body["status"][0] = {"code": 6}
    elif malform == "nonempty-result":
        body["writeResults"][0] = {"updateTime": VERSION}
    elif malform == "missing-code-field":
        body["status"][0] = {}
    elif malform == "untyped-result":
        body["writeResults"][0] = None
    gate.dispatch(operation, False, lambda: (status, body))
    assert unconfirmed_creates(gate.snapshot(), "case") == 1
    recover(gate, declared, created={RESOURCES[0]})
    with pytest.raises(ValueError, match="ownership retained"):
        gate.finish()


def test_abandoned_run_closes_on_partial_creation_once_absence_is_proven(tmp_path):
    """A stop between the first and the last create is not escalation-only.

    Only RESOURCES[0] is created; RESOURCES[1] is typed-refused and therefore
    never needs a creation proof, only the typed absence read every resource
    gets. The job's overall creating outcome stays "unsettled" (one real
    create among its events), so the Gate still dispatches every recovery
    slot for the record instead of zero-wire skipping the untouched resource.
    """
    operation = bulk([conditional(resource) for resource in RESOURCES], "batchWrite")
    gate, p = started(tmp_path, operation, scheduled=True, full_cleanup=True)
    gate.dispatch(operation, False, lambda: response([0, 3]))
    gate.abandon_observation("boundary stop before the batch finished creating")
    recover(gate, p, created={RESOURCES[0]})
    assert abandoned_cleanup_complete(gate.snapshot()) == [RESOURCES[0]]


def test_abandoned_run_with_recovery_still_pending_stays_unclosed(tmp_path):
    """Created-but-unproven: recovery has not run, so nothing is closable yet."""
    operation = bulk([conditional(resource) for resource in RESOURCES], "batchWrite")
    gate, p = started(tmp_path, operation, scheduled=True, full_cleanup=True)
    gate.dispatch(operation, False, lambda: response([0, 3]))
    gate.abandon_observation("boundary stop before recovery ran")
    assert abandoned_cleanup_complete(gate.snapshot()) is None


def test_abandoned_run_with_an_unconfirmed_create_stays_escalation_only(tmp_path):
    """Dispatched-but-unconfirmed: an ambiguous acknowledgement is never abandon-closable."""
    operation = bulk([conditional(resource) for resource in RESOURCES], "batchWrite")
    gate, p = started(tmp_path, operation, scheduled=True, full_cleanup=True)
    gate.dispatch(operation, False, lambda: response([0, 4]))
    assert unconfirmed_creates(gate.snapshot(), "case") == 1
    gate.abandon_observation("boundary stop with a lost second acknowledgement")
    recover(gate, p, created={RESOURCES[0]})
    assert abandoned_cleanup_complete(gate.snapshot()) is None
