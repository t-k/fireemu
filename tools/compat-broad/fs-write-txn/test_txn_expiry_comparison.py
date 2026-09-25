"""The comparator separates infrastructure failure from semantic disagreement."""

import base64
import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parents[1]))

import txn_expiry_cases as cases
import txn_expiry_collector as collector
import txn_expiry_comparison as comparison
import txn_expiry_plan as plan_module


def receipt(target, *, project, nonce, timing):
    prefix = plan_module.document_prefix(nonce)
    rows = []
    elapsed = 0
    for case in cases.CASES:
        required = case["requiresElapsedSeconds"]
        waited = None
        if required > elapsed:
            step = required - elapsed
            waited = {
                "mode": timing,
                "requestedSeconds": step,
                "measuredSeconds": step,
                "startedAt": "2026-09-18T00:00:00Z",
                "endedAt": "2026-09-18T00:01:30Z",
                "wallSeconds": step,
                "checkpoints": 1,
            }
            elapsed = required
        expected = case["expectedLocal"]
        message = expected["message"]
        if case["id"] == "idle-expiry/commit-after-idle":
            message = f'Document "{project}/{prefix}/locked-a" is gone. {message}'
        row = {
            "slot": case["id"],
            "phase": case["group"],
            "caseId": case["id"],
            "rpc": expected["rpc"],
            "role": case["resources"][0] if case["resources"] else None,
            "observed": {
                "code": expected["code"],
                "status": expected["status"],
                "message": message,
            },
            "complete": True,
            "waited": waited,
            "expectedLocal": dict(expected),
        }
        if required:
            row["idleSeconds"] = required
            row["idleOfTransaction"] = "a"
        rows.append(row)
        if not case["resources"]:
            continue
        role = case["resources"][0]
        state = (case["postState"] or {}).get(role, "created")
        rows.append(
            {
                "slot": f"verify/{case['id']}",
                "phase": "readback",
                "caseId": None,
                "verifiesCase": case["id"],
                "rpc": "GetDocument",
                "role": role,
                "observed": {"code": 0, "status": "OK", "message": None},
                "complete": True,
                "waited": None,
                "document": {
                    "exists": True,
                    "code": 0,
                    "name": collector.RESOURCE_SLOT,
                    "updateTime": collector.TOKEN_SLOT,
                    "updateTimeOrdinal": 0,
                    "fields": {
                        "owner": {"stringValue": collector.OWNER_SLOT},
                        "role": {"stringValue": role},
                        "nonce": {"stringValue": collector.TOKEN_SLOT},
                        "state": {"stringValue": state},
                    },
                },
            }
        )
    return {
        "kind": collector.CONTRACT,
        "campaign": cases.CAMPAIGN,
        "casesDigest": cases.cases_digest(),
        "sourceDigest": plan_module.source_digest(),
        "target": target,
        "timing": timing,
        "projectId": project,
        "database": "(default)",
        "documentPrefix": prefix,
        "nonce": nonce,
        "rows": rows,
        "cleanup": [],
        "transactionReleases": [],
        "openTransactions": [],
        "checkpoints": [],
        "unrecovered": [],
        "missingCases": [],
        "failure": None,
        "complete": True,
    }


def production():
    return receipt(
        "production",
        project="fireemu-35fe6",
        nonce="o3expiry-prod-000000000001",
        timing=collector.WALL_CLOCK,
    )


def local(timing=collector.CONTROL_CLOCK):
    return receipt(
        "local",
        project="fireemu-test",
        nonce="o3expiry-local-00000000001",
        timing=timing,
    )


def test_agreeing_runs_across_projects_are_expected_nondeterminism():
    result = comparison.compare(production(), local())
    assert result["classification"] == comparison.EXPECTED_NONDETERMINISM
    assert result["acquisitionValidated"] is False
    assert result["promotionReady"] is False


def test_identical_identities_and_semantics_are_a_match():
    value = production()
    other = copy.deepcopy(value)
    other["target"] = "local"
    other["timing"] = collector.WALL_CLOCK
    assert comparison.compare(value, other)["classification"] == comparison.MATCH


def case_row(receipt, case_id):
    return next(row for row in receipt["rows"] if row["caseId"] == case_id)


def test_a_different_code_is_a_semantic_mismatch():
    value = local()
    row = case_row(value, "idle-expiry/commit-after-idle")
    row["observed"]["code"] = 0
    row["observed"]["status"] = "OK"
    result = comparison.compare(production(), value)
    assert result["classification"] == comparison.SEMANTIC_MISMATCH
    assert "idle-expiry/commit-after-idle" in result["differences"]


def test_a_different_diagnostic_is_a_semantic_mismatch():
    value = local()
    for row in value["rows"]:
        if row["caseId"] == "retry-token/retry-with-committed-previous":
            row["observed"]["message"] = "Invalid retry transaction id."
    result = comparison.compare(production(), value)
    assert result["classification"] == comparison.SEMANTIC_MISMATCH


def test_request_bound_resource_identities_do_not_create_a_mismatch():
    result = comparison.compare(production(), local())
    assert result["classification"] != comparison.SEMANTIC_MISMATCH


def test_an_incomplete_receipt_is_indeterminate_not_a_mismatch():
    value = local()
    value["failure"] = "deadline-reached"
    result = comparison.compare(production(), value)
    assert result["classification"] == comparison.INDETERMINATE
    assert any(r["code"] == "collection-failed" for r in result["reasons"])


def test_unrecovered_resources_are_indeterminate():
    value = production()
    value["unrecovered"] = ["locked-a"]
    result = comparison.compare(value, local())
    assert result["classification"] == comparison.INDETERMINATE
    assert any(r["code"] == "unrecovered-resources" for r in result["reasons"])


def test_a_production_receipt_with_simulated_time_is_refused():
    value = production()
    value["timing"] = collector.CONTROL_CLOCK
    result = comparison.compare(value, local())
    assert result["classification"] == comparison.INDETERMINATE
    assert any(r["code"] == "production-timing-simulated" for r in result["reasons"])


def test_a_receipt_whose_measured_idle_time_is_short_is_refused():
    value = production()
    for row in value["rows"]:
        if "idleSeconds" in row:
            row["idleSeconds"] = 1
    result = comparison.compare(value, local())
    assert result["classification"] == comparison.INDETERMINATE
    assert any(r["code"] == "elapsed-time-not-reached" for r in result["reasons"])


def test_a_receipt_that_declares_the_wait_but_never_took_it_is_refused():
    value = production()
    for row in value["rows"]:
        if row["waited"]:
            row["waited"]["measuredSeconds"] = 0
    result = comparison.compare(value, local())
    assert result["classification"] == comparison.INDETERMINATE
    assert any(r["code"] == "wait-shorter-than-requested" for r in result["reasons"])


def test_a_receipt_with_an_unmeasured_wait_is_refused():
    value = production()
    for row in value["rows"]:
        if row["waited"]:
            row["waited"]["measuredSeconds"] = None
    result = comparison.compare(value, local())
    assert result["classification"] == comparison.INDETERMINATE
    assert any(r["code"] == "wait-not-measured" for r in result["reasons"])


def test_a_control_that_aged_past_the_idle_limit_is_refused():
    value = production()
    for row in value["rows"]:
        if row["caseId"] == "idle-expiry/commit-before-idle":
            row["idleSeconds"] = cases.DECLARED_IDLE_LIMIT_SECONDS + 5
    result = comparison.compare(value, local())
    assert result["classification"] == comparison.INDETERMINATE
    assert any(r["code"] == "control-aged-past-idle-limit" for r in result["reasons"])


def test_a_receipt_with_an_open_transaction_is_refused():
    value = local()
    value["openTransactions"] = ["a"]
    result = comparison.compare(production(), value)
    assert result["classification"] == comparison.INDETERMINATE
    assert any(r["code"] == "open-transactions" for r in result["reasons"])


def test_receipts_from_different_collector_versions_are_not_compared():
    value = local()
    value["sourceDigest"] = "f" * 64
    result = comparison.compare(production(), value)
    assert result["classification"] == comparison.INDETERMINATE
    assert any(
        r["code"] == "collector-source-digest-differs" for r in result["reasons"]
    )


def test_a_receipt_carrying_credential_material_is_refused():
    value = local()
    value["note"] = "Authorization: Bearer ya29.something"
    result = comparison.compare(production(), value)
    assert result["classification"] == comparison.INDETERMINATE
    assert any(r["code"] == "credential-material-in-receipt" for r in result["reasons"])


def test_a_stale_case_table_binding_is_refused():
    value = local()
    value["casesDigest"] = "0" * 64
    result = comparison.compare(production(), value)
    assert result["classification"] == comparison.INDETERMINATE
    assert any(r["code"] == "cases-digest" for r in result["reasons"])


def test_the_timing_mechanism_difference_is_recorded_not_hidden():
    result = comparison.compare(production(), local())
    assert result["timing"]["mechanismDiffers"] is True
    assert result["timing"]["note"]


def test_local_self_contract_accepts_the_frozen_expected_results():
    result = comparison.local_self_contract(local())
    assert result["classification"] == comparison.MATCH
    assert result["disagreements"] == {}
    assert sorted(result["casesChecked"]) == sorted(c["id"] for c in cases.CASES)


def test_local_self_contract_reports_a_disagreeing_case():
    value = local()
    case_row(value, "idle-expiry/commit-after-idle")["observed"]["code"] = 0
    result = comparison.local_self_contract(value)
    assert result["classification"] == comparison.SEMANTIC_MISMATCH
    assert "idle-expiry/commit-after-idle" in result["disagreements"]


def test_the_synthetic_receipt_shape_matches_a_real_collector_receipt():
    """The fixtures above must not drift from what the collector emits."""
    from test_txn_expiry_collector import Endpoint, advances, options

    real = collector.collect(
        options(), Endpoint(), advance=advances([]), monotonic=lambda: 0.0
    )
    synthetic = local()
    assert set(synthetic) <= set(real), set(synthetic) - set(real)
    real_case_rows = [row for row in real["rows"] if row["caseId"]]
    synthetic_row = next(row for row in synthetic["rows"] if row["caseId"])
    assert set(synthetic_row) <= set(real_case_rows[0]) | {
        "idleSeconds",
        "idleOfTransaction",
    }
    waited = next(row["waited"] for row in real["rows"] if row["waited"])
    synthetic_waited = next(row["waited"] for row in synthetic["rows"] if row["waited"])
    assert set(synthetic_waited) == set(waited)


def test_a_production_receipt_measured_by_a_no_op_sleeper_is_refused():
    """The end-to-end form of MF-1: a real run that never waited is refused."""
    from test_txn_expiry_collector import Endpoint, options

    faked = collector.collect(
        options(
            target="production",
            host=collector.PRODUCTION_HOST,
            timing=collector.WALL_CLOCK,
        ),
        Endpoint(),
        sleeper=lambda seconds: None,
        monotonic=lambda: 0.0,
        wall=lambda: 1_800_000_000.0,
    )
    assert faked["timing"] == collector.WALL_CLOCK
    assert faked["target"] == "production"
    result = comparison.compare(faked, local())
    assert result["classification"] == comparison.INDETERMINATE
    codes = {r["code"] for r in result["reasons"]}
    assert "wait-shorter-than-requested" in codes
    assert "elapsed-time-not-reached" in codes


class CaseAwareEndpoint:
    """A backend that answers every case with the code the table expects.

    It exists to separate the two things a receipt has to carry. Every response
    code is correct, so nothing a code-only comparison looks at can disagree.
    What changes is what the backend actually did to the documents, which is the
    thing a post-state readback is there to catch.
    """

    def __init__(self, *, silent_success=None, mutating_refusal=None):
        self.silent_success = silent_success
        self.mutating_refusal = mutating_refusal
        self.documents = {}
        self.issued = 0
        self.steps = None
        self.rows = None

    def attach(self, collection):
        self.rows = collection.rows
        self.steps = [
            step for step in collection.plan["operations"] if step["phase"] != "cleanup"
        ]

    def _step(self):
        index = len(self.rows)
        return self.steps[index] if index < len(self.steps) else None

    def __call__(self, request):
        step = self._step()
        slot = step["slot"] if step else "cleanup"
        case = collector.CASE_BY_ID.get(step["caseId"]) if step else None
        code = case["expectedLocal"]["code"] if case else 0
        message = case["expectedLocal"]["message"] if case else None
        rpc = request["rpc"]
        body = request.get("body") or {}
        reply = {"code": code, "status": collector.CANONICAL_STATUS[code], "message": message, "complete": True}
        if rpc == "BeginTransaction":
            if code:
                return reply
            self.issued += 1
            token = base64.b64encode(f"token-{self.issued}".encode()).decode()
            return {**reply, "body": {"transaction": token}}
        if rpc == "Rollback":
            return reply if code else {**reply, "body": {}}
        if rpc == "GetDocument":
            name = request["name"]
            if name not in self.documents:
                return {
                    "code": 5,
                    "status": "NOT_FOUND",
                    "message": "not found",
                    "complete": True,
                }
            fields, version = self.documents[name]
            return {
                "code": 0,
                "status": "OK",
                "message": None,
                "complete": True,
                "body": {
                    "name": name,
                    "fields": dict(fields),
                    "updateTime": f"2026-09-18T00:00:{version:02d}.000001Z",
                },
            }
        if rpc == "Commit":
            writes = body["writes"]
            for write in writes:
                name = write.get("delete") or write["update"]["name"]
                current = write.get("currentDocument") or {}
                if current.get("exists") is False and name in self.documents:
                    return {
                        "code": 6,
                        "status": "ALREADY_EXISTS",
                        "message": "already exists",
                        "complete": True,
                    }
            applies = code == 0 or slot == self.mutating_refusal
            if applies and slot != self.silent_success:
                for write in writes:
                    if "delete" in write:
                        self.documents.pop(write["delete"], None)
                    else:
                        name = write["update"]["name"]
                        version = self.documents.get(name, (None, 0))[1] + 1
                        self.documents[name] = (
                            dict(write["update"]["fields"]),
                            version,
                        )
            if code:
                return reply
            return {
                **reply,
                "body": {
                    "writeResults": [
                        {"updateTime": "2026-09-18T00:00:00.000001Z"} for _ in writes
                    ]
                },
            }
        raise AssertionError(rpc)


def collect_with(endpoint, *, target="local"):
    nonce = (
        "o3expiry-0000000000000001"
        if target == "local"
        else "o3expiry-0000000000000002"
    )
    project = "fireemu-test" if target == "local" else "oracle-project"
    value = {
        "target": target,
        "host": "127.0.0.1" if target == "local" else collector.PRODUCTION_HOST,
        "projectId": project,
        "database": "(default)",
        "nonce": nonce,
        "ownerId": "11111111222233334444555566667777",
        "timing": collector.CONTROL_CLOCK
        if target == "local"
        else collector.WALL_CLOCK,
        "deadlineSeconds": 300,
    }
    plan = plan_module.compile_plan(nonce, value["ownerId"], project=project)
    clock = {"now": 0.0}

    def tick(seconds):
        clock["now"] += seconds
        return seconds

    collection = collector.Collection(
        value,
        plan,
        endpoint,
        advance=tick,
        sleeper=tick,
        monotonic=lambda: clock["now"],
        wall=lambda: 1_800_000_000 + clock["now"],
    )
    endpoint.attach(collection)
    return collection.run()


def test_a_faithful_pair_of_runs_agrees_on_every_post_state():
    produced = collect_with(CaseAwareEndpoint(), target="production")
    local = collect_with(CaseAwareEndpoint())
    report = comparison.compare(produced, local)
    assert report["classification"] == comparison.EXPECTED_NONDETERMINISM, report
    assert comparison.local_self_contract(local)["classification"] == comparison.MATCH


def test_a_commit_that_succeeds_without_updating_its_document_is_detected():
    endpoint = CaseAwareEndpoint(silent_success="idle/commit-before")
    local = collect_with(endpoint)
    rows = {row["caseId"]: row for row in local["rows"] if row["caseId"]}
    assert rows["idle-expiry/commit-before-idle"]["observed"]["code"] == 0
    contract = comparison.local_self_contract(local)
    assert contract["classification"] == comparison.SEMANTIC_MISMATCH
    assert "idle-expiry/commit-before-idle#postState" in contract["disagreements"]
    produced = collect_with(CaseAwareEndpoint(), target="production")
    report = comparison.compare(produced, local)
    assert report["classification"] == comparison.SEMANTIC_MISMATCH
    assert "idle-expiry/commit-before-idle#postState" in report["differences"]


def test_a_refusal_that_nevertheless_changes_its_document_is_detected():
    endpoint = CaseAwareEndpoint(mutating_refusal="idle/commit-after")
    local = collect_with(endpoint)
    rows = {row["caseId"]: row for row in local["rows"] if row["caseId"]}
    assert rows["idle-expiry/commit-after-idle"]["observed"]["code"] == 10
    contract = comparison.local_self_contract(local)
    assert contract["classification"] == comparison.SEMANTIC_MISMATCH
    assert "idle-expiry/commit-after-idle#postState" in contract["disagreements"]
    produced = collect_with(CaseAwareEndpoint(), target="production")
    report = comparison.compare(produced, local)
    assert report["classification"] == comparison.SEMANTIC_MISMATCH
    assert "idle-expiry/commit-after-idle#postState" in report["differences"]


def test_a_resource_whose_ownership_was_never_confirmed_is_indeterminate():
    value = local()
    value["responsibility"] = [
        {"role": "control", "state": "sent-unknown", "resolved": False}
    ]
    result = comparison.compare(production(), value)
    assert result["classification"] == comparison.INDETERMINATE
    assert any(r["code"] == "unconfirmed-resource-ownership" for r in result["reasons"])


def test_a_responsibility_the_run_discharged_is_not_a_reason():
    value = local()
    value["responsibility"] = [
        {"role": "control", "state": "absence-confirmed", "resolved": True}
    ]
    result = comparison.compare(production(), value)
    assert result["classification"] == comparison.EXPECTED_NONDETERMINISM


def test_a_receipt_that_stopped_on_an_authority_refusal_is_indeterminate():
    value = local()
    value["authorityRefusal"] = "PERMISSION_DENIED"
    result = comparison.compare(production(), value)
    assert result["classification"] == comparison.INDETERMINATE
    assert any(r["code"] == "authority-refused" for r in result["reasons"])


def test_a_post_state_readback_that_named_another_document_is_indeterminate():
    value = local()
    for row in value["rows"]:
        if row.get("verifiesCase") == "idle-expiry/commit-after-idle":
            row["complete"] = False
            row["incomplete"] = "get-wrong-document"
            row["document"] = {
                "exists": None,
                "code": 0,
                "incomplete": "get-wrong-document",
            }
    result = comparison.compare(production(), value)
    assert result["classification"] == comparison.INDETERMINATE
    assert any(r["code"] == "post-state-readback-incomplete" for r in result["reasons"])
