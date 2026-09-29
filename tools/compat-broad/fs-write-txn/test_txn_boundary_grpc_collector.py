"""Fresh boundary samples stop on uncertain ownership and retain real intervals."""

import base64
import copy
import datetime as dt
import importlib

import pytest


class Clock:
    def __init__(self): self.seconds = 100.0
    def now(self): return self.seconds
    def utc(self): return (dt.datetime(2026, 9, 29, tzinfo=dt.timezone.utc) + dt.timedelta(seconds=self.seconds)).isoformat().replace("+00:00", "Z")
    def sleep(self, seconds): self.seconds += seconds


class Wire:
    def __init__(self, clock, codes, *, fail_at=None, rollback_code=0, rollback_unknown=False, duplicate=False):
        self.clock, self.codes = clock, codes
        self.fail_at, self.rollback_code, self.rollback_unknown, self.duplicate = fail_at, rollback_code, rollback_unknown, duplicate
        self.calls, self.transactions = [], {}
        self.document = None
        self.bad_ack = self.bad_ack_timestamp = self.bad_owner = self.bad_version = self.wrong_post = False
        self.read_delay = 0

    def send(self, method, request, **_kwargs):
        self.calls.append((method, copy.deepcopy(request)))
        self.clock.sleep(0.01)
        if len(self.calls) == self.fail_at:
            return {"kind": "txn-p10b-grpc-receipt-v1", "complete": False, "code": 14, "details": "lost", "response": None, "childReaped": True, "dispatchedRequests": 1}
        code, details, response = 0, "", {}
        token = request.get("transaction")
        if method == "BeginTransaction":
            assert request["options"] == {"readWrite": {}}
            token = base64.b64encode(f"issued-{0 if self.duplicate else len(self.transactions)}".encode()).decode()
            self.transactions[token] = copy.deepcopy(self.document)
            response = {"transaction": token}
        elif method == "Commit":
            code = self.codes[int(request["writes"][0]["update"]["fields"]["state"]["stringValue"].removeprefix("accepted-idle-")) - 65] if token else 0
            if code:
                details, response = "The referenced transaction has expired or is no longer valid.", None
            else:
                self.document = copy.deepcopy(request["writes"][0]["update"])
                self.document["updateTime"] = {"seconds": "1788004860", "nanos": len(self.calls)}
                response = {"writeResults": [] if self.bad_ack and token else [{"updateTime": self.document["updateTime"]}]}
                if self.bad_ack_timestamp and token: response = {"writeResults": [{}]}
        elif method == "GetDocument":
            if token: self.clock.sleep(self.read_delay)
            document = self.transactions[token] if token else self.document
            if document is None: code, response = 5, None
            else:
                response = copy.deepcopy(document)
                if self.bad_owner and not token: response["fields"]["owner"]["stringValue"] = "foreign"
                if self.wrong_post and not token and len(self.calls) > 2: response["fields"]["state"]["stringValue"] = "created"
                if self.bad_version: response["updateTime"] = {"seconds": "not-native", "nanos": -1}
        elif method == "Rollback":
            code = 14 if self.rollback_unknown else self.rollback_code
            if code: details, response = "release refusal", None
        elif method == "DeleteDocument":
            assert request["currentDocument"]["updateTime"] == self.document["updateTime"]
            self.document = None
        return {"kind": "txn-p10b-grpc-receipt-v1", "complete": code != 14, "code": code, "details": details, "response": response, "childReaped": True, "dispatchedRequests": 1}


def fixture(codes=(0, 0, 0, 0, 0, 0), **kwargs):
    program = importlib.import_module("txn_boundary_grpc_program")
    module = importlib.import_module("txn_boundary_grpc_collector")
    clock = Clock()
    plan = program.compile_plan("a" * 32, "b" * 32)
    wire = Wire(clock, codes, **kwargs)
    budget, journal = program.RequestBudget(plan), []
    collector = module.Collector(plan, budget, wire, "owner", save=lambda value: journal.append(copy.deepcopy(value)), monotonic=clock.now, utc=clock.utc, sleep=clock.sleep)
    return module, collector, wire, budget, journal, clock


@pytest.mark.parametrize("codes", [(0, 0, 0, 0, 0, 0), (10, 10, 10, 10, 10, 10), (0, 0, 0, 10, 10, 10)])
def test_six_samples_are_fresh_and_failed_tokens_release_before_the_next_begin(codes):
    module, collector, wire, budget, journal, clock = fixture(codes)
    receipt = collector.run()
    assert receipt["complete"] is True
    assert budget.used["observation"] == 26
    assert budget.used["tokenCleanup"] == sum(code != 0 for code in codes)
    assert budget.used["documentCleanup"] == 3
    assert len(receipt["tokens"]) == 6
    assert not receipt["openTokens"]
    assert not receipt["unknownStarts"] and not receipt["unknownCommits"] and not receipt["unknownRollbacks"]
    assert len(receipt["waits"]) == 6
    assert clock.seconds >= 505
    assert wire.document is None
    active = None
    for method, request in wire.calls:
        if method == "BeginTransaction":
            assert active is None
            active = "pending"
        elif method == "GetDocument" and request.get("transaction"):
            active = request["transaction"]
        elif method == "Commit" and request.get("transaction"):
            seconds = int(request["writes"][0]["update"]["fields"]["state"]["stringValue"].removeprefix("accepted-idle-"))
            if codes[seconds - 65] == 0: active = None
        elif method == "Rollback":
            assert request["transaction"] == active
            active = None
    assert active is None
    projected = module.projection(receipt)
    assert [row["code"] for row in projected["cases"]] == list(codes)
    assert projected["exactThresholdProven"] is False
    assert projected["cleanup"] == {"absent": True}
    assert any(value["unknownStarts"] == ["idle-65/begin"] for value in journal)
    for seconds, wait in zip(range(65, 71), receipt["waits"], strict=True):
        assert wait["seconds"] == seconds
        assert wait["idleInterval"]["lowerSeconds"] >= seconds
        assert wait["idleInterval"]["upperSeconds"] > wait["idleInterval"]["lowerSeconds"]
        assert wait["totalAgeInterval"]["upperSeconds"] < 270


@pytest.mark.parametrize("code,unknown", [(3, False), (10, False), (14, True)])
def test_nonzero_or_unknown_release_stops_next_candidate_without_retry(code, unknown):
    _, collector, wire, _, _, _ = fixture((10,) * 6, rollback_code=code, rollback_unknown=unknown)
    receipt = collector.run()
    assert not receipt["complete"] and receipt["unrecovered"]
    assert sum(method == "BeginTransaction" for method, _ in wire.calls) == 1
    assert sum(method == "Rollback" for method, _ in wire.calls) == 1
    assert receipt["openTokens"] == ["idle-65"]
    assert bool(receipt["unknownRollbacks"]) == unknown


@pytest.mark.parametrize("fail_at,field", [(2, "unknownCommits"), (3, "unknownStarts"), (5, "unknownCommits"), (7, "unknownRollbacks")])
def test_unknown_operation_blocks_later_candidate_and_keeps_responsibility(fail_at, field):
    _, collector, wire, _, _, _ = fixture((10,) * 6, fail_at=fail_at)
    receipt = collector.run()
    assert not receipt["complete"] and receipt["unrecovered"]
    assert receipt[field]
    assert sum(method == "BeginTransaction" for method, _ in wire.calls) <= 1
    if field == "unknownRollbacks": assert sum(method == "Rollback" for method, _ in wire.calls) == 1


@pytest.mark.parametrize("flag", ["bad_ack", "bad_ack_timestamp", "bad_owner", "bad_version", "wrong_post"])
def test_unproven_publication_owner_or_cleanup_version_cannot_freeze(flag):
    module, collector, wire, _, _, _ = fixture()
    setattr(wire, flag, True)
    receipt = collector.run()
    assert not receipt["complete"]
    with pytest.raises(ValueError): module.projection(receipt)
    if flag in ("bad_owner", "bad_version"): assert not any(method == "DeleteDocument" for method, _ in wire.calls)


def test_duplicate_minted_token_stops_the_second_sample():
    _, collector, wire, _, _, _ = fixture(duplicate=True)
    receipt = collector.run()
    assert not receipt["complete"] and receipt["unknownStarts"] == ["idle-66/begin"]
    assert sum(method == "BeginTransaction" for method, _ in wire.calls) == 2


def test_journal_failure_before_begin_dispatch_prevents_every_later_send():
    _, collector, wire, _, _, _ = fixture()
    def fail_on_begin(value):
        if value["unknownStarts"]: raise OSError("synthetic responsibility journal failure")
    collector.save = fail_on_begin
    receipt = collector.run()
    assert not receipt["complete"] and receipt["journalFailure"]
    assert len(wire.calls) == 2


def test_sample_total_age_headroom_is_checked_before_the_candidate_commit():
    _, collector, wire, _, _, _ = fixture()
    wire.read_delay = 200
    receipt = collector.run()
    assert not receipt['complete']
    assert sum(method == 'BeginTransaction' for method, _ in wire.calls) == 1
    assert not any(method == 'Commit' and request.get('transaction') for method, request in wire.calls)


def test_scheduling_overshoot_does_not_silently_become_another_candidate():
    _, collector, wire, _, _, clock = fixture()
    collector.sleep = lambda _seconds: clock.sleep(67)
    receipt = collector.run()
    assert not receipt['complete']
    assert not any(method == 'Commit' and request.get('transaction') for method, request in wire.calls)


def test_wait_at_the_one_second_scheduling_slack_retains_its_measured_interval():
    module, collector, _, _, _, clock = fixture()
    first = True
    def sleep(seconds):
        nonlocal first
        clock.sleep(66 if first else seconds)
        first = False
    collector.sleep = sleep
    receipt = collector.run()
    assert receipt['complete']
    assert receipt['waits'][0]['idleInterval']['lowerSeconds'] >= 66
    assert module.projection(receipt)['exactThresholdProven'] is False


@pytest.mark.parametrize("change", ["wait", "order", "count", "token", "release", "state", "absence", "timing", "age"])
def test_projection_derives_evidence_instead_of_accepting_claimed_completion(change):
    module, collector, _, _, _, _ = fixture((0, 0, 0, 10, 10, 10))
    receipt = collector.run()
    assert receipt["complete"]
    if change == "wait": receipt["waits"][0]["seconds"] = 64
    elif change == "order": receipt["steps"][3], receipt["steps"][4] = receipt["steps"][4], receipt["steps"][3]
    elif change == "count": receipt["phaseRequests"]["observation"] -= 1
    elif change == "token": receipt["tokens"]["idle-70"]["value"] = receipt["tokens"]["idle-65"]["value"]
    elif change == "release": receipt["cleanupSteps"][0]["result"]["code"] = 10
    elif change == "state": receipt["expectedState"] = "created"
    elif change == "absence": receipt["cleanupSteps"][-1]["result"].update(code=0, response={})
    elif change == "timing": receipt["waits"][0]["idleInterval"]["lowerSeconds"] = 0
    else: receipt["waits"][0]["totalAgeInterval"]["upperSeconds"] = 270
    with pytest.raises(ValueError): module.projection(receipt)


def test_nonmonotonic_or_overlapping_candidate_results_are_indeterminate():
    module, collector, _, _, _, _ = fixture((0, 10, 0, 10, 10, 10))
    receipt = collector.run()
    projected = module.projection(receipt)
    assert projected["boundaryClassification"] == "INDETERMINATE"
    receipt = fixture((0, 0, 0, 10, 10, 10))[1].run()
    for wait in receipt["waits"]: wait["idleInterval"]["upperSeconds"] += 2
    assert module.boundary_classification(receipt["waits"], receipt["observations"]) == "INDETERMINATE"


@pytest.mark.parametrize("codes", [(0,) * 6, (10,) * 6])
def test_native_protobuf_oneof_discriminator_preserves_owned_marker_and_cleanup(codes):
    module, collector, wire, _, _, _ = fixture(codes)
    send = wire.send
    def native_send(method, request, **kwargs):
        result = send(method, request, **kwargs)
        if method == 'GetDocument' and result['code'] == 0:
            for value in result['response']['fields'].values():
                value['valueType'] = 'stringValue'
        return result
    wire.send = native_send
    receipt = collector.run()
    assert receipt['complete'] is True
    assert wire.document is None and receipt['cleanup']['absent'] is True
    assert [row['code'] for row in module.projection(receipt)['cases']] == list(codes)


@pytest.mark.parametrize('extra', [{'valueType': 'integerValue'}, {'valueType': None}, {'valueType': True}, {'integerValue': '1'}, {'unknown': 'field'}])
def test_conflicting_oneof_discriminator_or_extra_value_cannot_authorize_deletion(extra):
    module, collector, wire, _, _, _ = fixture()
    send = wire.send
    def malformed_send(method, request, **kwargs):
        result = send(method, request, **kwargs)
        if method == 'GetDocument' and result['code'] == 0:
            result['response']['fields']['owner'].update(extra)
        return result
    wire.send = malformed_send
    receipt = collector.run()
    assert receipt['complete'] is False
    assert not any(method == 'DeleteDocument' for method, _request in wire.calls)
    with pytest.raises(ValueError):
        module.projection(receipt)


@pytest.mark.parametrize('extra', [{'valueType': 'integerValue'}, {'valueType': None}, {'valueType': True}, {'integerValue': '1'}, {'unknown': 'field'}])
def test_projection_rejects_conflicting_oneof_or_extra_value_in_saved_native_rows(extra):
    module, collector, _, _, _, _ = fixture()
    receipt = collector.run()
    assert receipt['complete'] is True
    receipt['steps'][3]['result']['response']['fields']['owner'].update(extra)
    with pytest.raises(ValueError):
        module.projection(receipt)
