import copy
import json
from pathlib import Path

import pytest

import production_denominator_v2 as v2


ROOT = Path(__file__).parents[2]


def load(path: str):
    return json.loads((ROOT / path).read_text())


def load_mapping():
    return load(v2.MAPPING_PATH)


def test_generated_v2_has_complete_parent_targets_and_sparse_provider_binding():
    value = load(v2.OUTPUT_PATH)
    assert value["schemaVersion"] == 2
    assert len(value["targets"]) == 2713
    assert sum(target["coverage"] == "partial" for target in value["targets"]) == 2
    assert all(target["coverage"] != "complete" for target in value["targets"])
    assert len(value["evidence"]) == 1
    assert len(value["bindings"]) == 1
    surfaces = value["bindings"][0]["surfaces"]
    assert {surface["targetId"] for surface in surfaces} == {
        "identitytoolkit-v1:method:REST:identitytoolkit.accounts.update",
        "identitytoolkit-v1:field:REST:schemas/GoogleCloudIdentitytoolkitV1SetAccountInfoRequest/properties/deleteProvider",
    }
    assert value["evidence"][0]["production"]["raw"]["availability"] == "private-hash-only"
    assert any("normalized" in limitation for limitation in value["evidence"][0]["limitations"])


def test_v2_validator_rejects_sibling_surface_mapping():
    value = load(v2.OUTPUT_PATH)
    mutated = copy.deepcopy(value)
    mutated["bindings"][0]["surfaces"][0]["targetId"] = (
        "identitytoolkit-v1:field:REST:schemas/GoogleCloudIdentitytoolkitV1SetAccountInfoRequest/properties/deleteProvider/items"
    )
    with pytest.raises(v2.ValidationError, match="binding selectors"):
        v2.validate_document(ROOT, mutated)


def test_v2_validator_rejects_missing_or_duplicate_target():
    value = load(v2.OUTPUT_PATH)
    missing = copy.deepcopy(value)
    missing["targets"].pop()
    with pytest.raises(v2.ValidationError, match="target multiset"):
        v2.validate_document(ROOT, missing)

    duplicate = copy.deepcopy(value)
    duplicate["targets"].append(copy.deepcopy(duplicate["targets"][0]))
    with pytest.raises(v2.ValidationError, match="target multiset"):
        v2.validate_document(ROOT, duplicate)


def test_v2_validator_rejects_local_only_forged_oracle_promotion():
    value = load(v2.OUTPUT_PATH)
    mutated = copy.deepcopy(value)
    evidence = mutated["evidence"][0]
    evidence["production"] = None
    mutated["bindings"][0]["evidenceLevel"] = "oracle-compared"
    with pytest.raises(v2.ValidationError, match="local-only evidence"):
        v2.validate_document(ROOT, mutated)


def test_v2_validator_rejects_stale_evidence_bytes():
    value = load(v2.OUTPUT_PATH)
    mutated = copy.deepcopy(value)
    mutated["evidence"][0]["production"]["receipt"]["sha256"] = "0" * 64
    with pytest.raises(v2.ValidationError, match="stale evidence bytes"):
        v2.validate_document(ROOT, mutated)


def test_v2_validator_rejects_forged_comparison_result():
    value = load(v2.OUTPUT_PATH)
    mutated = copy.deepcopy(value)
    mutated["evidence"][0]["comparator"]["result"] = "mismatch"
    with pytest.raises(v2.ValidationError, match="comparator result is forged"):
        v2.validate_document(ROOT, mutated)


def test_v2_validator_rejects_target_binding_index_mutation():
    value = load(v2.OUTPUT_PATH)
    mutated = copy.deepcopy(value)
    target = next(item for item in mutated["targets"] if item["coverage"] == "partial")
    target["bindingIds"] = []
    with pytest.raises(v2.ValidationError, match="target binding index"):
        v2.validate_document(ROOT, mutated)


def test_mapping_requires_the_approved_comparison_subject_and_decision():
    mapping = load_mapping()
    parent = load(v2.PARENT_PATH)
    parent_targets = {target["id"]: target for target in parent["targets"]}
    mutated = copy.deepcopy(mapping)
    mutated["comparisonApproval"] = mutated["receipt"]
    with pytest.raises(v2.ValidationError, match="approval"):
        v2.validate_mapping(ROOT, mutated, parent_targets)

    approval = load("spec/compatibility/evidence/auth-pending-trigger-provider-unlink/comparison-approval.json")
    approval["decision"] = "reject"
    with pytest.raises(v2.ValidationError, match="approval"):
        v2.validate_approval(ROOT, approval, load("spec/compatibility/evidence/auth-pending-trigger-provider-unlink/local-comparison.json"), mapping["corpus"])


def test_mapping_rejects_sibling_target_and_wrong_case_pointer():
    mapping = load_mapping()
    parent = load(v2.PARENT_PATH)
    parent_targets = {target["id"]: target for target in parent["targets"]}
    sibling = copy.deepcopy(mapping)
    sibling["bindings"][0]["surfaces"][1]["targetId"] += "/items"
    with pytest.raises(v2.ValidationError, match="provider-unlink mapping"):
        v2.validate_mapping(ROOT, sibling, parent_targets)

    wrong_case = copy.deepcopy(mapping)
    wrong_case["bindings"][0]["caseId"] = "held-start"
    with pytest.raises(v2.ValidationError, match="provider-unlink mapping"):
        v2.validate_mapping(ROOT, wrong_case, parent_targets)


def test_mapping_rejects_unrelated_assertion_pointer():
    mapping = load_mapping()
    parent = load(v2.PARENT_PATH)
    parent_targets = {target["id"]: target for target in parent["targets"]}
    mutated = copy.deepcopy(mapping)
    mutated["bindings"][0]["surfaces"][0]["assertionPointers"] = ["/production/target"]
    with pytest.raises(v2.ValidationError, match="provider-unlink mapping"):
        v2.validate_mapping(ROOT, mutated, parent_targets)


@pytest.mark.parametrize(
    ("path", "replacement", "message"),
    [
        (("evidence", 0, "local", "runtimeArtifact", "sha256"), "0" * 64, "runtime artifact"),
        (("evidence", 0, "local", "runtimeSourceCommit"), "0" * 40, "runtime source"),
        (("evidence", 0, "comparator", "contract", "sha256"), "0" * 64, "contract"),
    ],
)
def test_exported_document_rejects_forged_nested_identity(path, replacement, message):
    value = load(v2.OUTPUT_PATH)
    mutated = copy.deepcopy(value)
    target = mutated
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = replacement
    with pytest.raises(v2.ValidationError, match=message):
        v2.validate_document(ROOT, mutated)


def test_exported_document_rejects_unsafe_corpus_reference_and_unbound_partial_coverage():
    value = load(v2.OUTPUT_PATH)
    unsafe = copy.deepcopy(value)
    unsafe["evidence"][0]["corpus"]["inputs"] = [{"path": "../../outside", "sha256": "0" * 64, "unknown": True}]
    with pytest.raises(v2.ValidationError, match="corpus input"):
        v2.validate_document(ROOT, unsafe)

    partial = copy.deepcopy(value)
    target = next(item for item in partial["targets"] if item["coverage"] == "none")
    target["coverage"] = "partial"
    with pytest.raises(v2.ValidationError, match="coverage"):
        v2.validate_document(ROOT, partial)


def test_exported_document_rejects_forged_projection_semantics():
    value = load(v2.OUTPUT_PATH)
    mutated = copy.deepcopy(value)
    mutated["evidence"][0]["comparator"]["projection"] = "exact wire bytes including headers and elapsedMs"
    with pytest.raises(v2.ValidationError, match="projection"):
        v2.validate_document(ROOT, mutated)


def test_exported_document_rejects_redirected_configuration_pointer():
    value = load(v2.OUTPUT_PATH)
    mutated = copy.deepcopy(value)
    mutated["evidence"][0]["local"]["configuration"]["evidencePointer"] = "/production/configuration"
    with pytest.raises(v2.ValidationError, match="configuration"):
        v2.validate_document(ROOT, mutated)


def test_exported_document_rejects_unknown_nested_collector_input_field():
    value = load(v2.OUTPUT_PATH)
    mutated = copy.deepcopy(value)
    mutated["evidence"][0]["production"]["collector"]["inputs"][0]["unknown"] = True
    with pytest.raises(v2.ValidationError, match="collector input"):
        v2.validate_document(ROOT, mutated)


def test_v2_json_parser_rejects_duplicate_keys(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"schemaVersion": 2, "schemaVersion": 1}')
    with pytest.raises(v2.ValidationError, match="duplicate JSON key"):
        v2.read_json(path)


def test_v2_generation_is_immutable_and_deterministic(tmp_path):
    mapping = ROOT / v2.MAPPING_PATH
    first = tmp_path / "v2.json"
    report = tmp_path / "v2.md"
    v2.generate(ROOT, mapping, first, report)
    original = first.read_bytes(), report.read_bytes()
    v2.generate(ROOT, mapping, first, report)
    assert (first.read_bytes(), report.read_bytes()) == original
    first.write_text(first.read_text().replace('"schemaVersion": 2', '"schemaVersion": 9', 1))
    with pytest.raises(ValueError, match="immutable denominator version"):
        v2.generate(ROOT, mapping, first, report)
