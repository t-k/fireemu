"""Offline regression obligations for the versioned saved-reference evaluator."""

import copy
import importlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
COLLECTOR = ROOT.parent / "campaign-explain-reference-109a9b45"
SAVED = Path("/Users/tk/work/firebase-emulator/docs.local/logs/2026-09-14")


def sample():
    operation = {
        "service": "firestore",
        "path": "/v1/projects/fireemu-35fe6/databases/(default)/documents/campaign/"
        + "a" * 32
        + ":runQuery",
        "method": "POST",
        "body": {
            "structuredQuery": {"from": [{"collectionId": "items"}], "limit": 0},
            "explainOptions": {"analyze": True},
        },
        "privileged": True,
        "form": False,
    }
    body = [
        {
            "readTime": "2026-09-14T11:58:21.463876Z",
            "explainMetrics": {
                "planSummary": {},
                "executionStats": {
                    "executionDuration": "0.011995s",
                    "readOperations": "1",
                    "debugStats": {"documents_scanned": "0"},
                },
            },
        }
    ]
    return operation, body


def test_old_code_reproduces_default_omission_rejection():
    if not COLLECTOR.is_dir():
        pytest.skip("frozen collector checkout unavailable")
    operation, body = sample()
    program = "import sys,json; sys.path.insert(0,sys.argv[1]); import campaign_explain as c; p=json.loads(sys.argv[2]); print(json.dumps(c.explain_response_valid(p[0],200,p[1])))"
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            program,
            str(COLLECTOR / "tools/compat-broad"),
            json.dumps([operation, body]),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(result.stdout) is False


def test_normalizes_only_two_omitted_defaults_without_mutating_source():
    evaluator = importlib.import_module("evaluate")
    operation, body = sample()
    saved = copy.deepcopy(body)
    normalized, paths = evaluator.canonical_body(operation, 200, body)
    expected = copy.deepcopy(body)
    expected[0]["explainMetrics"]["planSummary"]["indexesUsed"] = []
    expected[0]["explainMetrics"]["executionStats"]["resultsReturned"] = "0"
    assert normalized == expected
    assert len(paths) == 2
    assert body == saved


@pytest.mark.parametrize(
    "mutation",
    [
        "nonempty-query",
        "aggregation",
        "plan-only",
        "status",
        "missing-plan",
        "missing-stats",
        "null-indexes",
        "null-results",
        "numeric-results",
        "bool-results",
        "wrong-index-type",
    ],
)
def test_defaults_never_widen_scope_or_replace_present_wrong_types(mutation):
    evaluator = importlib.import_module("evaluate")
    operation, body = sample()
    status = 200
    if mutation == "nonempty-query":
        operation["body"]["structuredQuery"]["limit"] = 1
    elif mutation == "aggregation":
        operation["path"] = operation["path"].replace(
            ":runQuery", ":runAggregationQuery"
        )
    elif mutation == "plan-only":
        operation["body"]["explainOptions"]["analyze"] = False
    elif mutation == "status":
        status = 400
    elif mutation == "missing-plan":
        body[0]["explainMetrics"].pop("planSummary")
    elif mutation == "missing-stats":
        body[0]["explainMetrics"].pop("executionStats")
    elif mutation in ("null-indexes", "wrong-index-type"):
        body[0]["explainMetrics"]["planSummary"]["indexesUsed"] = (
            None if mutation == "null-indexes" else {}
        )
    else:
        body[0]["explainMetrics"]["executionStats"]["resultsReturned"] = {
            "null-results": None,
            "numeric-results": 0,
            "bool-results": False,
        }[mutation]
    normalized, _ = evaluator.canonical_body(operation, status, body)
    if mutation in ("null-indexes", "wrong-index-type"):
        assert (
            normalized[0]["explainMetrics"]["planSummary"]["indexesUsed"]
            == body[0]["explainMetrics"]["planSummary"]["indexesUsed"]
        )
    elif mutation in ("null-results", "numeric-results", "bool-results"):
        assert type(
            normalized[0]["explainMetrics"]["executionStats"]["resultsReturned"]
        ) is type(body[0]["explainMetrics"]["executionStats"]["resultsReturned"])
    else:
        assert normalized == body


def test_protobuf_serialization_confirms_the_two_default_omissions():
    from google.protobuf import (
        descriptor_pb2,
        descriptor_pool,
        json_format,
        message_factory,
        struct_pb2,
    )

    file = descriptor_pb2.FileDescriptorProto(
        name="explain-defaults-test.proto", package="test", syntax="proto3"
    )
    plan = file.message_type.add(name="PlanSummary")
    plan.field.add(
        name="indexes_used",
        number=1,
        type=descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE,
        type_name=".google.protobuf.Struct",
        label=descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED,
    )
    stats = file.message_type.add(name="ExecutionStats")
    stats.field.add(
        name="results_returned",
        number=1,
        type=descriptor_pb2.FieldDescriptorProto.TYPE_INT64,
        label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL,
    )
    pool = descriptor_pool.DescriptorPool()
    file.dependency.append("google/protobuf/struct.proto")
    pool.AddSerializedFile(struct_pb2.DESCRIPTOR.serialized_pb)
    pool.Add(file)
    for name, explicit in [
        ("PlanSummary", {"indexesUsed": []}),
        ("ExecutionStats", {"resultsReturned": "0"}),
    ]:
        cls = message_factory.GetMessageClass(
            pool.FindMessageTypeByName("test." + name)
        )
        assert json_format.MessageToDict(cls()) == {}
        assert (
            json_format.MessageToDict(cls(), always_print_fields_with_no_presence=True)
            == explicit
        )


@pytest.fixture(scope="module")
def frozen_records():
    evaluator = importlib.import_module("evaluate")
    production_dir = SAVED / "campaign-explain-production-109a9b45"
    local_path = SAVED / "campaign-explain-shadow-109a9b45/result.json"
    if not production_dir.exists() or not local_path.exists() or not COLLECTOR.exists():
        pytest.skip("private frozen reference inputs unavailable")
    records, pinned, _ = evaluator.read_inputs(production_dir, local_path)
    old = evaluator.load_collector(COLLECTOR)
    return evaluator, records, pinned, old, local_path.parent


def test_saved_reference_passes_all_old_bindings_without_mutating(frozen_records):
    evaluator, records, pinned, old, local_dir = frozen_records
    before = copy.deepcopy(records)
    assert evaluator.validate_records(records, pinned, old, local_dir)
    assert records == before
    assert records["production"]["completed"] is False
    rows = evaluator.compare_rows(records["production"], records["local"], old)
    target = next(row for row in rows if row["id"] == "explain/query/empty-analyze")
    assert len(target["defaultEquivalencesApplied"]["production"]) == 2
    assert target["compatibility"] == "mismatch"
    assert (
        target["production"]["body"][0]["explainMetrics"]["executionStats"][
            "readOperations"
        ]
        == "1"
    )
    assert any(row["compatibility"] == "mismatch" for row in rows)


@pytest.mark.parametrize(
    "mutation",
    [
        "request",
        "principal",
        "dispatch",
        "plan",
        "permission",
        "nonce",
        "state",
        "cleanup",
        "creation",
        "delete-version",
        "final404",
        "completed",
        "failure",
        "original-reason",
        "execution-inputs",
    ],
)
def test_old_lifecycle_checks_still_refuse_tampered_records(frozen_records, mutation):
    evaluator, saved, pinned, old, local_dir = frozen_records
    records = copy.deepcopy(saved)
    production = records["production"]
    receipt = production["receipt"]
    if mutation == "request":
        receipt["rows"][6]["request"]["body"]["structuredQuery"]["limit"] = 1
    elif mutation == "principal":
        receipt["principalEvidence"]["principal"] = "anonymous"
    elif mutation == "dispatch":
        receipt["principalEvidence"]["dispatch"]["observation"].pop()
    elif mutation == "plan":
        production["gate"]["plan"]["totalRequests"] = 31
    elif mutation == "permission":
        production["permission"]["expiresAt"] = 0
    elif mutation == "nonce":
        production["nonce"] = "f" * 32
    elif mutation == "state":
        receipt["rows"][-1]["body"]["fields"] = {}
    elif mutation == "cleanup":
        receipt["cleanupComplete"] = False
    elif mutation == "creation":
        receipt["ownershipJournal"].pop()
    elif mutation == "delete-version":
        receipt["cleanup"][1]["request"]["path"] = receipt["cleanup"][1]["request"][
            "path"
        ].split("?")[0]
    elif mutation == "final404":
        receipt["cleanup"][-1]["status"] = 200
    elif mutation == "completed":
        production["completed"] = True
    elif mutation == "failure":
        production["failure"] = "uncertain"
    elif mutation == "original-reason":
        records["originalComparison"]["reason"] = "another failure"
    else:
        records["executionInputs"]["localRecordSha256"] = "0" * 64
    # The alias is rebound intentionally so this exercises the strict old checks.
    production["jobs"]["query-explain"] = copy.deepcopy(receipt)
    with pytest.raises((ValueError, TypeError, KeyError)):
        evaluator.validate_records(records, pinned, old, local_dir)


def test_only_equivalent_defaults_compare_equal_and_real_metrics_remain():
    evaluator = importlib.import_module("evaluate")
    operation, omitted = sample()
    explicit = copy.deepcopy(omitted)
    explicit[0]["explainMetrics"]["planSummary"]["indexesUsed"] = []
    explicit[0]["explainMetrics"]["executionStats"]["resultsReturned"] = "0"
    left, _ = evaluator.canonical_body(operation, 200, omitted)
    right, _ = evaluator.canonical_body(operation, 200, explicit)
    assert evaluator.digest(left) == evaluator.digest(right)
    right[0]["explainMetrics"]["executionStats"]["readOperations"] = "9"
    assert evaluator.digest(left) != evaluator.digest(right)


def rebind_response(production, index):
    evaluator = importlib.import_module("evaluate")
    row = production["receipt"]["rows"][index]
    digest = evaluator.digest(row["body"])
    production["receipt"]["principalEvidence"]["dispatch"]["observation"][index][
        "responseDigest"
    ] = digest
    next(
        event
        for event in production["gate"]["events"]
        if event["phase"] == "observation" and event["index"] == index
    )["responseDigest"] = digest
    production["jobs"]["query-explain"] = copy.deepcopy(production["receipt"])


@pytest.mark.parametrize(
    "mutation",
    [
        "empty-array",
        "null-indexes",
        "null-results",
        "numeric-results",
        "bool-limit",
        "missing-parent",
    ],
)
def test_rebound_wrong_typed_values_are_not_default_equivalences(
    frozen_records, mutation
):
    evaluator, saved, pinned, old, local_dir = frozen_records
    records = copy.deepcopy(saved)
    production = records["production"]
    row = production["receipt"]["rows"][6]
    if mutation == "empty-array":
        row["body"] = []
    elif mutation == "null-indexes":
        row["body"][0]["explainMetrics"]["planSummary"]["indexesUsed"] = None
    elif mutation in ("null-results", "numeric-results"):
        row["body"][0]["explainMetrics"]["executionStats"]["resultsReturned"] = (
            None if mutation == "null-results" else 0
        )
    elif mutation == "bool-limit":
        row["request"]["body"]["structuredQuery"]["limit"] = False
        production["receipt"]["principalEvidence"]["dispatch"]["observation"][6][
            "requestDigest"
        ] = evaluator.digest(row["request"])
        next(
            event
            for event in production["gate"]["events"]
            if event["phase"] == "observation" and event["index"] == 6
        )["requestDigest"] = evaluator.digest(row["request"])
    else:
        row["body"][0]["explainMetrics"].pop("planSummary")
    rebind_response(production, 6)
    with pytest.raises((ValueError, TypeError, KeyError)):
        evaluator.validate_records(records, pinned, old, local_dir)


def test_rebound_real_metric_difference_is_valid_but_preserved(frozen_records):
    evaluator, saved, pinned, old, local_dir = frozen_records
    records = copy.deepcopy(saved)
    production = records["production"]
    production["receipt"]["rows"][6]["body"][0]["explainMetrics"]["executionStats"][
        "readOperations"
    ] = "99"
    rebind_response(production, 6)
    assert evaluator.validate_records(records, pinned, old, local_dir)
    row = evaluator.compare_rows(production, records["local"], old)[6]
    assert (
        row["production"]["body"][0]["explainMetrics"]["executionStats"][
            "readOperations"
        ]
        == "99"
    )
    assert row["compatibility"] == "mismatch"


def test_pinned_input_hash_refuses_changes_before_validation(tmp_path):
    evaluator = importlib.import_module("evaluate")
    folder = tmp_path / "production"
    folder.mkdir()
    (folder / "result.json").write_text("{}")
    with pytest.raises(ValueError, match="frozen production bytes differ"):
        evaluator.read_inputs(folder, tmp_path / "local.json")


def test_documented_cli_retains_original_comparison_and_writes_separate_report(
    tmp_path, frozen_records
):
    evaluator, _, _, _, local_dir = frozen_records
    if not (ROOT / evaluator.ANCHOR).exists():
        pytest.skip("Stage B evaluator anchor not committed yet")
    production_dir = SAVED / "campaign-explain-production-109a9b45"
    files = [
        production_dir / name
        for name in ("result.json", "comparison.json", "execution-inputs.json")
    ]
    before = [path.read_bytes() for path in files]
    output = tmp_path / "reevaluation.json"
    command = [
        sys.executable,
        "-I",
        str(ROOT / "tools/compat-explain-reference/evaluate.py"),
        "--collector-root",
        str(COLLECTOR),
        "--production-dir",
        str(production_dir),
        "--local",
        str(local_dir / "result.json"),
        "--output",
        str(output),
    ]
    result = subprocess.run(
        command, cwd=tmp_path, capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(output.read_bytes())
    assert report["compatibility"] == "mismatch"
    assert report["collectionComplete"] is True
    assert report["originalProductionCompleted"] is False
    assert report["originalComparison"]["compatibility"] == "indeterminate"
    assert len(report["rows"]) == 12
    assert before == [path.read_bytes() for path in files]
    repeated = subprocess.run(
        command, cwd=tmp_path, capture_output=True, text=True, check=False
    )
    assert repeated.returncode != 0


def test_cli_cannot_write_into_original_production_directory(frozen_records):
    _, _, _, _, local_dir = frozen_records
    production_dir = SAVED / "campaign-explain-production-109a9b45"
    target = production_dir / "forbidden-evaluation.json"
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(ROOT / "tools/compat-explain-reference/evaluate.py"),
            "--collector-root",
            str(COLLECTOR),
            "--production-dir",
            str(production_dir),
            "--local",
            str(local_dir / "result.json"),
            "--output",
            str(target),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert not target.exists()


@pytest.mark.parametrize("mutation", ["wrong-request", "empty-explain", "false-state"])
def test_both_sides_rebound_invalid_values_never_become_matches(
    frozen_records, mutation
):
    evaluator, saved, pinned, old, _ = frozen_records
    records = copy.deepcopy(saved)
    for value in (records["production"], records["local"]):
        row = value["receipt"]["rows"][6]
        if mutation == "wrong-request":
            row["request"]["body"]["structuredQuery"]["limit"] = 1
        elif mutation == "empty-explain":
            row["body"] = []
        else:
            value["receipt"]["stateValidation"] = False
        for target in (
            value["receipt"]["principalEvidence"]["dispatch"]["observation"][6],
            next(
                event
                for event in value["gate"]["events"]
                if event["phase"] == "observation" and event["index"] == 6
            ),
        ):
            target.update(
                requestDigest=evaluator.digest(row["request"]),
                responseDigest=evaluator.digest(row["body"]),
            )
        if value["productionExecuted"]:
            value["jobs"]["query-explain"] = copy.deepcopy(value["receipt"])
        else:
            value["fileDigests"]["gate/state.json"] = evaluator.digest(value["gate"])
            value["fileDigests"]["worker/result.json"] = evaluator.digest(
                value["receipt"]
            )
    production = records["production"]
    production["localRecordSha256"] = evaluator.digest(records["local"])
    production["permission"]["localRecordSha256"] = production["localRecordSha256"]
    records["executionInputs"]["permission"] = copy.deepcopy(production["permission"])
    records["executionInputs"]["localRecordSha256"] = production["localRecordSha256"]
    with pytest.raises(ValueError):
        evaluator.validate_records(records, pinned, old, None)
