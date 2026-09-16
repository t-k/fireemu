"""Generate and validate the immutable sparse evidence overlay for denominator v2."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

import production_denominator as v1

V2_VERSION = "ip-fs-standard-2026-09-14.v2"
OUTPUT_PATH = "spec/compatibility/denominators/ip-fs-standard-2026-09-14.v2.json"
MAPPING_PATH = "spec/compatibility/denominators/ip-fs-standard-2026-09-14.v2.mapping.json"
DOCUMENT_PATH = "docs/compatibility/production-denominator-v2.md"
PARENT_PATH = v1.OUTPUT_PATH
PARENT_SHA256 = "189b614707fd0cbf7090146679c14a9d27184340cecf67d934c3ffe7fdca038b"
ADAPTER_ID = "auth-pending-trigger-provider-unlink.v1"
PROVIDER_CASE_ID = "trigger"
PROVIDER_METHOD_TARGET = "identitytoolkit-v1:method:REST:identitytoolkit.accounts.update"
PROVIDER_FIELD_TARGET = "identitytoolkit-v1:field:REST:schemas/GoogleCloudIdentitytoolkitV1SetAccountInfoRequest/properties/deleteProvider"
PROVIDER_FACTS = {
    "trigger": "provider-unlink",
    "transport": "REST",
    "tenant": False,
    "providerLinkedBeforeTransition": True,
    "providerAbsentAfterTransition": True,
    "heldCredentialAndSmsSessionCreatedBeforeTransition": True,
}
PROVIDER_CORPUS_INPUTS = [
    "tools/auth-pending-triggers/triggers_contract.py",
    "tools/auth-pending-triggers/triggers_recorder.py",
]
SEMANTIC_PROJECTION = "semantic row projection excluding elapsedMs"
EVIDENCE_LEVELS = {"historical-reference", "local-verified", "production-observed", "oracle-compared"}
COMPARISON_RESULTS = {"not-compared", "match", "mismatch", "indeterminate"}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")


class ValidationError(ValueError):
    """Raised when a v2 input fails a fail-closed invariant."""


def read_json(path: Path) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValidationError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        return json.loads(path.read_text(), object_pairs_hook=reject_duplicates)
    except ValidationError:
        raise
    except (OSError, json.JSONDecodeError) as error:
        raise ValidationError(f"invalid JSON: {path}: {error}") from error


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def file_digest(root: Path, relative: str) -> str:
    path = repository_path(root, relative)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_blob_digest(root: Path, commit: str, relative: str) -> str:
    if not isinstance(commit, str) or not HEX40.fullmatch(commit):
        raise ValidationError("collector commit is not a full commit SHA")
    if not isinstance(relative, str):
        raise ValidationError("collector input path is invalid")
    repository_path(root, relative)
    try:
        content = subprocess.check_output(
            ["git", "show", f"{commit}:{relative}"], cwd=root, stderr=subprocess.DEVNULL
        )
    except subprocess.CalledProcessError as error:
        raise ValidationError(f"collector input is missing at bound commit: {relative}") from error
    return hashlib.sha256(content).hexdigest()


def validate_commit_exists(root: Path, commit: str, context: str) -> None:
    if not isinstance(commit, str) or not HEX40.fullmatch(commit):
        raise ValidationError(f"{context}: commit is not a full commit SHA")
    try:
        subprocess.check_call(
            ["git", "cat-file", "-e", f"{commit}^{{commit}}"], cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except subprocess.CalledProcessError as error:
        raise ValidationError(f"{context}: commit does not exist") from error


def validate_bound_inputs(root: Path, commit: str, inputs: dict[str, Any], context: str) -> None:
    if not isinstance(inputs, dict) or not inputs:
        raise ValidationError(f"{context}: inputs must be nonempty")
    for path, expected in sorted(inputs.items()):
        if not isinstance(expected, str) or not HEX64.fullmatch(expected):
            raise ValidationError(f"{context}: invalid input digest")
        if git_blob_digest(root, commit, path) != expected:
            raise ValidationError(f"{context}: input digest mismatch: {path}")


def repository_path(root: Path, relative: str) -> Path:
    path = Path(relative)
    if path.is_absolute() or not relative or any(part in {"", ".", ".."} for part in path.parts):
        raise ValidationError(f"unsafe repository path: {relative}")
    candidate = root.resolve(strict=True)
    for part in path.parts:
        candidate /= part
        if candidate.is_symlink():
            raise ValidationError(f"symlink repository path: {relative}")
        if not candidate.exists():
            raise ValidationError(f"repository path does not exist: {relative}")
    if not candidate.resolve(strict=True).is_relative_to(root.resolve(strict=True)):
        raise ValidationError(f"repository path escapes root: {relative}")
    if not candidate.is_file():
        raise ValidationError(f"repository path is not a file: {relative}")
    return candidate


def checked_reference(root: Path, reference: dict[str, Any], context: str) -> Path:
    if set(reference) != {"path", "sha256"}:
        raise ValidationError(f"{context}: invalid reference fields")
    path = reference["path"]
    expected = reference["sha256"]
    if not isinstance(path, str) or not isinstance(expected, str) or not HEX64.fullmatch(expected):
        raise ValidationError(f"{context}: invalid reference")
    resolved = repository_path(root, path)
    if file_digest(root, path) != expected:
        raise ValidationError(f"{context}: stale evidence bytes")
    return resolved


def exact(value: Any, keys: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValidationError(f"{context}: invalid fields")
    return value


def pointer(value: Any, path: str, context: str) -> Any:
    if not path.startswith("/"):
        raise ValidationError(f"{context}: invalid pointer")
    current = value
    for part in path[1:].split("/"):
        if not part or not isinstance(current, (dict, list)):
            raise ValidationError(f"{context}: unresolved JSON pointer {path}")
        if isinstance(current, list):
            if not part.isdigit() or int(part) >= len(current):
                raise ValidationError(f"{context}: unresolved JSON pointer {path}")
            current = current[int(part)]
        elif part not in current:
            raise ValidationError(f"{context}: unresolved JSON pointer {path}")
        else:
            current = current[part]
    return current


def target_structural(target: dict[str, Any]) -> dict[str, Any]:
    return {key: target[key] for key in ("id", "definition", "locator", "kind", "transport", "featureGroup", "scope", "scopeReason")}


def parent_and_source(root: Path) -> tuple[dict[str, Any], dict[str, Any], str]:
    parent_path = repository_path(root, PARENT_PATH)
    parent_bytes = parent_path.read_bytes()
    if hashlib.sha256(parent_bytes).hexdigest() != PARENT_SHA256:
        raise ValidationError("parent denominator SHA-256 does not match immutable anchor")
    parent = read_json(parent_path)
    if parent.get("schemaVersion") != 1 or parent.get("denominatorVersion") != v1.VERSION:
        raise ValidationError("parent denominator is not the pinned schema-v1 version")
    source_path = repository_path(root, v1.SOURCE_PATH)
    source_bytes = source_path.read_bytes()
    source_sha = hashlib.sha256(source_bytes).hexdigest()
    if source_sha != v1.SOURCE_SHA256:
        raise ValidationError("source snapshot SHA-256 does not match immutable anchor")
    source = read_json(source_path)
    expected = v1.build(source, v1.SOURCE_PATH, source_sha)
    expected_by_id = {target["id"]: target for target in expected["targets"]}
    actual_by_id = {target["id"]: target for target in parent.get("targets", [])}
    if len(actual_by_id) != len(parent.get("targets", [])) or actual_by_id != expected_by_id:
        raise ValidationError("parent target multiset is not the pinned source ledger")
    return parent, source, source_sha


def validate_mapping(root: Path, mapping: dict[str, Any], parent_targets: dict[str, dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    exact(mapping, {"schemaVersion", "evidenceId", "adapterId", "receipt", "localComparison", "comparisonApproval", "sourceReview", "corpus", "bindings"}, "mapping")
    if mapping["schemaVersion"] != 1 or mapping["adapterId"] != ADAPTER_ID:
        raise ValidationError("unsupported mapping adapter")
    receipt_ref = mapping["receipt"]
    local_ref = mapping["localComparison"]
    approval_ref = mapping["comparisonApproval"]
    review_ref = mapping["sourceReview"]
    receipt = read_json(checked_reference(root, receipt_ref, "receipt"))
    comparison = read_json(checked_reference(root, local_ref, "local comparison"))
    approval = read_json(checked_reference(root, approval_ref, "comparison approval"))
    review = read_json(checked_reference(root, review_ref, "source review"))
    if receipt.get("schemaVersion") != 1 or receipt.get("production", {}).get("target") != "production":
        raise ValidationError("receipt is not a production observation")
    if comparison.get("schemaVersion") != 1 or comparison.get("local", {}).get("target") != "local":
        raise ValidationError("comparison is not a local observation")
    corpus = mapping["corpus"]
    exact(corpus, {"revision", "caseIds", "inputPaths"}, "mapping corpus")
    if corpus["caseIds"] != receipt.get("corpus", {}).get("cases") or corpus["revision"] != receipt.get("corpus", {}).get("revision"):
        raise ValidationError("mapping corpus does not equal receipt corpus")
    if len(set(corpus["caseIds"])) != len(corpus["caseIds"]) or not corpus["caseIds"]:
        raise ValidationError("mapping corpus has duplicate or missing cases")
    if sorted(corpus["inputPaths"]) != PROVIDER_CORPUS_INPUTS:
        raise ValidationError("provider-unlink corpus inputs are not allowlisted")
    for path in corpus["inputPaths"]:
        if not isinstance(path, str):
            raise ValidationError("mapping corpus input path is invalid")
        repository_path(root, path)
    production = receipt["production"]
    recorded = production.get("recordedWith", {})
    validate_bound_inputs(root, recorded.get("recorderCommit"), recorded.get("recorderInputs"), "production recorder")
    local = comparison["local"]
    local_recorded = local.get("recordedWith", {})
    validate_bound_inputs(root, local_recorded.get("recorderCommit"), local_recorded.get("recorderInputs"), "local recorder")
    validate_bound_inputs(root, local.get("runtimeInputsCommit"), local.get("build", {}).get("inputs"), "local runtime")
    prod_cases = receipt.get("production", {}).get("cases")
    local_cases = comparison.get("local", {}).get("cases")
    if not isinstance(prod_cases, list) or not isinstance(local_cases, list):
        raise ValidationError("evidence cases are missing")
    prod_by_id = {row.get("id"): row for row in prod_cases}
    local_by_id = {row.get("id"): row for row in local_cases}
    if len(prod_by_id) != len(prod_cases) or len(local_by_id) != len(local_cases) or set(prod_by_id) != set(corpus["caseIds"]) or set(local_by_id) != set(corpus["caseIds"]):
        raise ValidationError("evidence case selectors do not equal the pinned corpus")
    comparison_rows = {row.get("id"): row for row in comparison.get("comparison", [])}
    if len(comparison_rows) != len(comparison.get("comparison", [])) or set(comparison_rows) != set(corpus["caseIds"]):
        raise ValidationError("comparison rows do not equal the pinned corpus")
    for case_id in corpus["caseIds"]:
        if prod_by_id[case_id].get("skipped") or local_by_id[case_id].get("skipped"):
            raise ValidationError("skipped case cannot be promoted")
        expected_match = semantic_row(prod_by_id[case_id]) == semantic_row(local_by_id[case_id])
        if comparison_rows[case_id].get("sameSemanticProjection") is not expected_match:
            raise ValidationError("stored comparison does not match recomputed projection")
    validate_approval(root, approval, comparison, corpus)
    bindings = mapping["bindings"]
    if not isinstance(bindings, list) or len(bindings) != 1:
        raise ValidationError("provider-unlink mapping must contain exactly one binding")
    binding_ids: set[str] = set()
    seen: set[tuple[str, str]] = set()
    for binding in bindings:
        exact(binding, {"id", "caseId", "evidenceLevel", "comparisonResult", "conditions", "surfaces"}, "mapping binding")
        bid = binding["id"]
        case_id = binding["caseId"]
        if not isinstance(bid, str) or not bid or bid in binding_ids:
            raise ValidationError("duplicate binding ID")
        binding_ids.add(bid)
        if case_id not in corpus["caseIds"]:
            raise ValidationError("binding case selector is not in corpus")
        if case_id != PROVIDER_CASE_ID:
            raise ValidationError("provider-unlink mapping case must be trigger")
        if binding["evidenceLevel"] not in EVIDENCE_LEVELS or binding["comparisonResult"] not in COMPARISON_RESULTS:
            raise ValidationError("invalid binding evidence level")
        if binding["comparisonResult"] == "match" and comparison_rows[binding["caseId"]].get("sameSemanticProjection") is not True:
            raise ValidationError("binding comparison result is forged")
        if binding["comparisonResult"] == "mismatch" and comparison_rows[binding["caseId"]].get("sameSemanticProjection") is True:
            raise ValidationError("binding comparison result is forged")
        exact(binding["conditions"], {"facts", "evidencePointers"}, "binding conditions")
        if binding["conditions"]["facts"] != PROVIDER_FACTS or binding["conditions"]["evidencePointers"] != ["/production/trigger", "/production/providerLinked", "/production/cases/1/checks/providerAbsentAfter"]:
            raise ValidationError("provider-unlink mapping conditions are not allowlisted")
        for p in binding["conditions"]["evidencePointers"]:
            pointer({"production": receipt["production"], "local": comparison["local"]}, p, "condition")
        surfaces = binding["surfaces"]
        if not isinstance(surfaces, list) or len(surfaces) != 2 or {surface.get("targetId") for surface in surfaces} != {PROVIDER_METHOD_TARGET, PROVIDER_FIELD_TARGET}:
            raise ValidationError("provider-unlink mapping surfaces are not allowlisted")
        for surface in surfaces:
            exact(surface, {"targetId", "observationPointers", "assertionPointers", "coverage", "reason"}, "binding surface")
            target_id = surface["targetId"]
            if target_id not in parent_targets or parent_targets[target_id]["scope"] != "target":
                raise ValidationError("target selector is not an in-scope parent target")
            if surface["coverage"] != "partial" or not surface["reason"]:
                raise ValidationError("surface coverage must remain partial")
            expected_assertions = {
                PROVIDER_METHOD_TARGET: ["/production/cases/1/checks/noError", "/local/cases/1/checks/noError"],
                PROVIDER_FIELD_TARGET: ["/production/cases/1/checks/providerAbsentAfter", "/local/cases/1/checks/providerAbsentAfter"],
            }[target_id]
            if surface["observationPointers"] != ["/production/cases/1", "/local/cases/1"] or surface["assertionPointers"] != expected_assertions:
                raise ValidationError("provider-unlink mapping assertion pointers are not allowlisted")
            for p in surface["observationPointers"] + surface["assertionPointers"]:
                pointer({"production": receipt["production"], "local": comparison["local"]}, p, "surface")
            observations = [pointer({"production": receipt["production"], "local": comparison["local"]}, p, "surface") for p in surface["observationPointers"]]
            if any(observation.get("id") != PROVIDER_CASE_ID for observation in observations):
                raise ValidationError("provider-unlink mapping observation case mismatch")
            if any(pointer({"production": receipt["production"], "local": comparison["local"]}, p, "surface") is not True for p in surface["assertionPointers"]):
                raise ValidationError("provider-unlink mapping assertions must be true")
            key = (case_id, target_id)
            if key in seen:
                raise ValidationError("duplicate mapping assertion")
            seen.add(key)
    return receipt, comparison, approval, review


def semantic_row(row: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in row.items() if key != "elapsedMs"}


def validate_approval(root: Path, approval: dict[str, Any], comparison: dict[str, Any], corpus: dict[str, Any]) -> None:
    exact(approval, {"schemaVersion", "subjectSha256", "sourceCommit", "scope", "cases", "reviewer", "reviewedAt", "decision"}, "approval")
    if approval["schemaVersion"] != 1 or approval["decision"] != "approve":
        raise ValidationError("approval decision is not approve")
    if approval["subjectSha256"] != digest(comparison):
        raise ValidationError("approval subject digest does not match comparison")
    if approval["cases"] != corpus["caseIds"]:
        raise ValidationError("approval cases do not match corpus")
    if not isinstance(approval["sourceCommit"], str) or not HEX40.fullmatch(approval["sourceCommit"]):
        raise ValidationError("approval source commit is invalid")
    validate_commit_exists(root, approval["sourceCommit"], "approval source")


def evidence_document(root: Path, mapping: dict[str, Any], parent: dict[str, Any], source_sha: str, receipt: dict[str, Any], comparison: dict[str, Any]) -> dict[str, Any]:
    receipt_ref = mapping["receipt"]
    local_ref = mapping["localComparison"]
    corpus = mapping["corpus"]
    input_refs = [{"path": path, "sha256": file_digest(root, path)} for path in sorted(corpus["inputPaths"])]
    prod = receipt["production"]
    local = comparison["local"]
    comparison_rows = comparison["comparison"]
    all_match = all(row["sameSemanticProjection"] is True for row in comparison_rows)
    targets = []
    bindings_by_target: dict[str, list[str]] = {}
    for binding in mapping["bindings"]:
        for surface in binding["surfaces"]:
            bindings_by_target.setdefault(surface["targetId"], []).append(binding["id"])
    for target in parent["targets"]:
        structural = target_structural(target)
        binding_ids = sorted(set(bindings_by_target.get(target["id"], [])))
        targets.append({**structural, "bindingIds": binding_ids, "coverage": "partial" if binding_ids else "none"})
    production_subject = digest(receipt)
    local_subject = digest(local["cases"])
    evidence = {
        "id": mapping["evidenceId"],
        "adapterId": mapping["adapterId"],
        "adapter": {"path": "tools/compat-inventory/production_denominator_v2.py", "sha256": file_digest(root, "tools/compat-inventory/production_denominator_v2.py")},
        "production": {
            "receipt": receipt_ref,
            "subjectDigest": {"algorithm": "sha256", "sha256": production_subject},
            "raw": {"sha256": prod.get("privateReceiptSha256"), "availability": "private-hash-only"},
            "representation": "normalized",
            "collector": {"commit": prod["probeSourceCommit"], "inputs": [{"path": path, "sha256": value} for path, value in sorted(prod["recordedWith"]["recorderInputs"].items())]},
            "configuration": {"sha256": prod["configuration"]["sha256"], "evidencePointer": "/production/configuration"},
            "recordedAt": prod["recordedAt"],
        },
        "local": {
            "receipt": local_ref,
            "runtimeArtifact": local["artifact"],
            "runtimeSourceCommit": local["runtimeSourceCommit"],
            "runtimeInputs": {"commit": local["runtimeInputsCommit"], "digestAlgorithm": "sha256", "sha256": digest(local["build"]["inputs"]), "evidencePointer": "/local/build/inputs"},
            "collector": {"commit": local["probeSourceCommit"], "inputs": [{"path": path, "sha256": value} for path, value in sorted(local["recordedWith"]["recorderInputs"].items())]},
            "configuration": {"sha256": local["configuration"]["sha256"], "evidencePointer": "/local/configuration"},
        },
        "corpus": {"id": receipt["corpus"]["slice"], "revision": corpus["revision"], "digestAlgorithm": "sha256", "sha256": digest(receipt["corpus"]), "caseIds": corpus["caseIds"], "inputs": input_refs},
        "comparator": {
            "id": "publish-auth-pending-triggers-comparison.v1",
            "inputs": [{"path": "tools/publish-auth-pending-triggers-comparison.py", "sha256": file_digest(root, "tools/publish-auth-pending-triggers-comparison.py")}],
            "contract": {"digestAlgorithm": "sha256", "sha256": prod["reevaluatedWith"]["contractSha256"]},
            "comparison": {"path": local_ref["path"], "sha256": local_ref["sha256"]},
            "productionSubjectDigest": production_subject,
            "localSubjectDigest": local_subject,
            "projection": SEMANTIC_PROJECTION,
            "result": "match" if all_match else "mismatch",
        },
        "limitations": [
            "production raw receipt bytes are unavailable; privateReceiptSha256 is a historical identity hash only",
            "comparison representation is normalized and excludes elapsedMs; it does not prove wire bytes, headers or timing",
            "one non-tenant REST provider-unlink transition is partial evidence and does not cover sibling, item, tenant, SDK or Rules surfaces",
        ],
        "approval": {"path": mapping["comparisonApproval"]["path"], "sha256": mapping["comparisonApproval"]["sha256"], "subjectDigest": digest(comparison)},
    }
    bindings = []
    for binding in mapping["bindings"]:
        bindings.append({**binding, "evidenceId": mapping["evidenceId"]})
    return {
        "schemaVersion": 2,
        "goal": v1.GOAL,
        "denominatorVersion": V2_VERSION,
        "parentDenominator": {"path": PARENT_PATH, "version": parent["denominatorVersion"], "sha256": PARENT_SHA256},
        "sourceSnapshot": {"path": v1.SOURCE_PATH, "sha256": source_sha},
        "definitions": parent["definitions"],
        "mappingSource": {"path": MAPPING_PATH, "sha256": file_digest(root, MAPPING_PATH)},
        "generator": {"path": "tools/compat-inventory/production_denominator_v2.py", "sha256": file_digest(root, "tools/compat-inventory/production_denominator_v2.py")},
        "targets": targets,
        "evidence": [evidence],
        "bindings": bindings,
    }


def validate_document(root: Path, value: dict[str, Any]) -> None:
    exact(value, {"schemaVersion", "goal", "denominatorVersion", "parentDenominator", "sourceSnapshot", "definitions", "mappingSource", "generator", "targets", "evidence", "bindings"}, "v2 document")
    if value["schemaVersion"] != 2 or value["goal"] != v1.GOAL or value["denominatorVersion"] != V2_VERSION:
        raise ValidationError("invalid v2 header")
    parent, _source, source_sha = parent_and_source(root)
    parent_ref = value["parentDenominator"]
    exact(parent_ref, {"path", "version", "sha256"}, "parentDenominator")
    if parent_ref != {"path": PARENT_PATH, "version": parent["denominatorVersion"], "sha256": PARENT_SHA256}:
        raise ValidationError("parent denominator anchor mismatch")
    if value["sourceSnapshot"] != {"path": v1.SOURCE_PATH, "sha256": source_sha}:
        raise ValidationError("source snapshot anchor mismatch")
    if value["definitions"] != parent["definitions"]:
        raise ValidationError("definitions differ from parent")
    mapping_ref = value["mappingSource"]
    mapping_path = checked_reference(root, mapping_ref, "mapping source")
    mapping = read_json(mapping_path)
    if mapping_ref["path"] != MAPPING_PATH:
        raise ValidationError("mapping source path is not the pinned mapping")
    generator_ref = value["generator"]
    checked_reference(root, generator_ref, "generator")
    if generator_ref["path"] != "tools/compat-inventory/production_denominator_v2.py":
        raise ValidationError("generator path is not pinned")
    parent_targets = {target["id"]: target for target in parent["targets"]}
    expected_targets = {target["id"]: target for target in value["targets"]}
    if len(expected_targets) != len(value["targets"]) or len(expected_targets) != len(parent_targets):
        raise ValidationError("target multiset cardinality mismatch")
    for target_id, parent_target in parent_targets.items():
        target = expected_targets.get(target_id)
        if target is None:
            raise ValidationError("target multiset structural mismatch")
        exact(target, {"id", "definition", "locator", "kind", "transport", "featureGroup", "scope", "scopeReason", "bindingIds", "coverage"}, "v2 target")
        if target_structural(target) != target_structural(parent_target):
            raise ValidationError("target multiset structural mismatch")
        if target["coverage"] not in {"none", "partial"} or not isinstance(target["bindingIds"], list) or len(set(target["bindingIds"])) != len(target["bindingIds"]):
            raise ValidationError("invalid target coverage")
    receipt, comparison, _approval, _review = validate_mapping(root, mapping, parent_targets)
    evidence_by_id = {item.get("id"): item for item in value["evidence"]}
    if len(evidence_by_id) != len(value["evidence"]) or set(evidence_by_id) != {mapping["evidenceId"]}:
        raise ValidationError("evidence IDs are not unique")
    evidence = evidence_by_id[mapping["evidenceId"]]
    exact(evidence, {"id", "adapterId", "adapter", "production", "local", "corpus", "comparator", "limitations", "approval"}, "v2 evidence")
    exact(evidence["adapter"], {"path", "sha256"}, "evidence adapter")
    if evidence["adapterId"] != ADAPTER_ID or evidence["adapter"]["path"] != "tools/compat-inventory/production_denominator_v2.py":
        raise ValidationError("unsupported evidence adapter")
    if evidence["adapter"]["sha256"] != file_digest(root, evidence["adapter"]["path"]):
        raise ValidationError("evidence adapter hash mismatch")
    if not isinstance(evidence["limitations"], list) or not evidence["limitations"]:
        raise ValidationError("evidence limitations must be nonempty")
    exact(evidence["corpus"], {"id", "revision", "digestAlgorithm", "sha256", "caseIds", "inputs"}, "evidence corpus")
    exact(evidence["approval"], {"path", "sha256", "subjectDigest"}, "evidence approval")
    if evidence["corpus"]["id"] != receipt["corpus"]["slice"] or evidence["corpus"]["revision"] != mapping["corpus"]["revision"] or evidence["corpus"]["caseIds"] != mapping["corpus"]["caseIds"] or evidence["corpus"]["sha256"] != digest(receipt["corpus"]):
        raise ValidationError("evidence corpus selector or digest mismatch")
    expected_corpus_inputs = [{"path": path, "sha256": file_digest(root, path)} for path in sorted(mapping["corpus"]["inputPaths"])]
    for input_ref in evidence["corpus"]["inputs"]:
        exact(input_ref, {"path", "sha256"}, "corpus input")
    if evidence["corpus"]["inputs"] != expected_corpus_inputs:
        raise ValidationError("corpus input references do not match supported paths")
    if evidence["approval"] != {"path": mapping["comparisonApproval"]["path"], "sha256": mapping["comparisonApproval"]["sha256"], "subjectDigest": digest(comparison)}:
        raise ValidationError("evidence approval selector mismatch")
    for binding in value["bindings"]:
        for surface in binding.get("surfaces", []):
            if surface.get("targetId") not in parent_targets:
                raise ValidationError("target selector is not an in-scope parent target")
    expected_bindings = [{**binding, "evidenceId": mapping["evidenceId"]} for binding in mapping["bindings"]]
    if value["bindings"] != expected_bindings:
        raise ValidationError("binding selectors differ from reviewed mapping")
    production = evidence.get("production")
    if production is None:
        raise ValidationError("local-only evidence cannot promote production binding")
    if not isinstance(production, dict) or not isinstance(production.get("receipt"), dict):
        raise ValidationError("production receipt selector mismatch")
    checked_reference(root, production["receipt"], "receipt")
    if production["receipt"] != mapping["receipt"]:
        raise ValidationError("production receipt selector mismatch")
    exact(production, {"receipt", "subjectDigest", "raw", "representation", "collector", "configuration", "recordedAt"}, "production evidence")
    exact(production["subjectDigest"], {"algorithm", "sha256"}, "production subject")
    if production["subjectDigest"] != {"algorithm": "sha256", "sha256": digest(receipt)}:
        raise ValidationError("production subject digest mismatch")
    exact(production["raw"], {"sha256", "availability"}, "production raw")
    if not isinstance(production["raw"]["sha256"], str) or not HEX64.fullmatch(production["raw"]["sha256"]):
        raise ValidationError("production raw hash is invalid")
    if production["raw"]["availability"] != "private-hash-only" or production["representation"] != "normalized":
        raise ValidationError("production raw/normalized limitation is not explicit")
    exact(production["collector"], {"commit", "inputs"}, "production collector")
    for input_ref in production["collector"]["inputs"]:
        exact(input_ref, {"path", "sha256"}, "collector input")
    if production["collector"]["commit"] != receipt["production"]["probeSourceCommit"]:
        raise ValidationError("production collector commit mismatch")
    if {item["path"]: item["sha256"] for item in production["collector"]["inputs"]} != receipt["production"]["recordedWith"]["recorderInputs"]:
        raise ValidationError("production collector inputs mismatch")
    exact(production["configuration"], {"sha256", "evidencePointer"}, "production configuration")
    if production["configuration"]["evidencePointer"] != "/production/configuration":
        raise ValidationError("production configuration pointer is not canonical")
    if production["configuration"]["sha256"] != receipt["production"]["configuration"]["sha256"]:
        raise ValidationError("production configuration digest mismatch")
    if production.get("raw", {}).get("sha256") != receipt["production"].get("privateReceiptSha256"):
        raise ValidationError("raw receipt hash does not match the bound production record")
    local = evidence.get("local")
    if not isinstance(local, dict) or local.get("receipt") != mapping["localComparison"]:
        raise ValidationError("local receipt selector mismatch")
    checked_reference(root, local["receipt"], "local comparison")
    exact(local, {"receipt", "runtimeArtifact", "runtimeSourceCommit", "runtimeInputs", "collector", "configuration"}, "local evidence")
    exact(local["runtimeArtifact"], {"kind", "sha256", "version"}, "local runtime artifact")
    if local["runtimeArtifact"] != comparison["local"]["artifact"]:
        raise ValidationError("runtime artifact identity mismatch")
    if local["runtimeSourceCommit"] != comparison["local"]["runtimeSourceCommit"]:
        raise ValidationError("runtime source commit mismatch")
    exact(local["runtimeInputs"], {"commit", "digestAlgorithm", "sha256", "evidencePointer"}, "local runtime inputs")
    if not HEX64.fullmatch(local["runtimeArtifact"]["sha256"]) or not HEX40.fullmatch(local["runtimeSourceCommit"]) or not HEX40.fullmatch(local["runtimeInputs"]["commit"]):
        raise ValidationError("local runtime commit is invalid")
    validate_commit_exists(root, local["runtimeSourceCommit"], "runtime source")
    if local["runtimeInputs"]["commit"] != comparison["local"]["runtimeInputsCommit"]:
        raise ValidationError("runtime input commit mismatch")
    if local["runtimeInputs"]["sha256"] != digest(comparison["local"]["build"]["inputs"]):
        raise ValidationError("local runtime inputs digest mismatch")
    exact(local["collector"], {"commit", "inputs"}, "local collector")
    for input_ref in local["collector"]["inputs"]:
        exact(input_ref, {"path", "sha256"}, "collector input")
    if local["collector"]["commit"] != comparison["local"]["probeSourceCommit"] or {item["path"]: item["sha256"] for item in local["collector"]["inputs"]} != comparison["local"]["recordedWith"]["recorderInputs"]:
        raise ValidationError("local collector inputs mismatch")
    exact(local["configuration"], {"sha256", "evidencePointer"}, "local configuration")
    if local["configuration"]["evidencePointer"] != "/local/configuration":
        raise ValidationError("local configuration pointer is not canonical")
    if local["configuration"]["sha256"] != comparison["local"]["configuration"]["sha256"]:
        raise ValidationError("local configuration digest mismatch")
    comparator = evidence.get("comparator")
    if not isinstance(comparator, dict) or comparator.get("comparison", {}).get("path") != mapping["localComparison"]["path"]:
        raise ValidationError("comparison selector mismatch")
    checked_reference(root, comparator["comparison"], "comparison")
    exact(comparator, {"id", "inputs", "contract", "comparison", "productionSubjectDigest", "localSubjectDigest", "projection", "result"}, "evidence comparator")
    if comparator["projection"] != SEMANTIC_PROJECTION:
        raise ValidationError("comparator projection is not canonical")
    if comparator["result"] not in {"match", "mismatch"}:
        raise ValidationError("invalid comparator result")
    expected_comparison_result = "match" if all(row["sameSemanticProjection"] is True for row in comparison["comparison"]) else "mismatch"
    if comparator["result"] != expected_comparison_result:
        raise ValidationError("comparator result is forged")
    exact(comparator["contract"], {"digestAlgorithm", "sha256"}, "comparator contract")
    if comparator["contract"] != {"digestAlgorithm": "sha256", "sha256": receipt["production"]["reevaluatedWith"]["contractSha256"]}:
        raise ValidationError("comparator contract digest mismatch")
    comparator_inputs = []
    for item in comparator["inputs"]:
        exact(item, {"path", "sha256"}, "comparator input")
        comparator_inputs.append(item)
    if len(comparator_inputs) != 1 or comparator_inputs[0]["path"] != "tools/publish-auth-pending-triggers-comparison.py":
        raise ValidationError("comparator input path is not supported")
    reevaluation_commit = receipt["production"]["reevaluatedWith"]["commit"]
    expected_contract_hash = git_blob_digest(root, reevaluation_commit, "tools/auth-pending-triggers/triggers_contract.py")
    if expected_contract_hash != comparator["contract"]["sha256"]:
        raise ValidationError("comparator contract is not bound to contract bytes")
    validate_bound_inputs(root, reevaluation_commit, {item["path"]: item["sha256"] for item in comparator_inputs}, "comparator")
    if comparator.get("productionSubjectDigest") != digest(receipt) or comparator.get("localSubjectDigest") != digest(comparison["local"]["cases"]):
        raise ValidationError("comparison subject digest mismatch")
    if evidence["comparator"]["result"] == "match" and not all(row["sameSemanticProjection"] is True for row in comparison["comparison"]):
        raise ValidationError("stored comparison result is forged")
    binding_ids: set[str] = set()
    for binding in value["bindings"]:
        exact(binding, {"id", "evidenceId", "caseId", "evidenceLevel", "comparisonResult", "conditions", "surfaces"}, "v2 binding")
        exact(binding["conditions"], {"facts", "evidencePointers"}, "v2 binding conditions")
        if binding.get("evidenceId") != mapping["evidenceId"]:
            raise ValidationError("binding evidence selector mismatch")
        if binding["id"] in binding_ids:
            raise ValidationError("duplicate binding ID")
        binding_ids.add(binding["id"])
        for surface in binding["surfaces"]:
            exact(surface, {"targetId", "observationPointers", "assertionPointers", "coverage", "reason"}, "v2 binding surface")
        if binding["evidenceLevel"] == "oracle-compared" and evidence.get("production") is None:
            raise ValidationError("local-only evidence cannot promote oracle-compared binding")
    expected_target_bindings: dict[str, list[str]] = {}
    for binding in value["bindings"]:
        for surface in binding["surfaces"]:
            expected_target_bindings.setdefault(surface["targetId"], []).append(binding["id"])
    for target in value["targets"]:
        if set(target["bindingIds"]) - binding_ids:
            raise ValidationError("target references unknown binding")
        expected_ids = sorted(set(expected_target_bindings.get(target["id"], [])))
        if target["bindingIds"] != expected_ids:
            raise ValidationError("target binding index mismatch")
        expected_coverage = "partial" if expected_ids else "none"
        if target["coverage"] != expected_coverage:
            raise ValidationError("target coverage does not match binding index")
    canonical = evidence_document(root, mapping, parent, source_sha, receipt, comparison)["evidence"]
    if [evidence] != canonical:
        raise ValidationError("evidence differs from canonical bound evidence")


def serialized(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()


def write_immutable(path: Path, contents: bytes) -> None:
    if path.exists():
        if path.read_bytes() == contents:
            return
        raise ValueError("immutable denominator version already exists; bump V2_VERSION and output path")
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o666)
    with os.fdopen(descriptor, "wb") as output:
        output.write(contents)


def report(value: dict[str, Any]) -> bytes:
    partial = sum(target["coverage"] == "partial" for target in value["targets"])
    return (f"<!-- Generated by tools/compat-inventory/production_denominator_v2.py. Do not edit. -->\n\n"
            f"# Identity Platform and Firestore Standard production denominator v2\n\n"
            f"Goal: `{value['goal']}`. Denominator: `{value['denominatorVersion']}`.\n\n"
            f"This immutable overlay preserves the v1 target ledger byte-for-byte through an exact parent hash and adds sparse evidence bindings. It contains {len(value['targets'])} targets; {partial} have partial case evidence. No target is complete or compat-verified.\n\n"
            "The provider-unlink record retains a private raw receipt hash and a normalized semantic comparison. Those limitations do not prove wire bytes, headers or timing. Exact case and target selectors are required; feature groups never propagate evidence.\n\n"
            f"Parent: `{value['parentDenominator']['path']}` (`{value['parentDenominator']['sha256']}`). Mapping: `{value['mappingSource']['path']}` (`{value['mappingSource']['sha256']}`).\n").encode()


def generate(root: Path, mapping_path: Path, output: Path, document: Path) -> None:
    parent, _source, source_sha = parent_and_source(root)
    mapping = read_json(mapping_path)
    parent_targets = {target["id"]: target for target in parent["targets"]}
    receipt, comparison, _approval, _review = validate_mapping(root, mapping, parent_targets)
    value = evidence_document(root, mapping, parent, source_sha, receipt, comparison)
    validate_document(root, value)
    write_immutable(output, serialized(value))
    write_immutable(document, report(value))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--mapping", default=MAPPING_PATH)
    parser.add_argument("--output", default=OUTPUT_PATH)
    parser.add_argument("--document", default=DOCUMENT_PATH)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    mapping = repository_path(root, args.mapping)
    output = root / args.output
    document = root / args.document
    if args.check:
        expected_parent, _source, source_sha = parent_and_source(root)
        mapping_value = read_json(mapping)
        parent_targets = {target["id"]: target for target in expected_parent["targets"]}
        receipt, comparison, _approval, _review = validate_mapping(root, mapping_value, parent_targets)
        expected = evidence_document(root, mapping_value, expected_parent, source_sha, receipt, comparison)
        validate_document(root, read_json(output))
        if output.read_bytes() != serialized(expected) or document.read_bytes() != report(expected):
            raise SystemExit("stale denominator v2 output")
        return 0
    generate(root, mapping, output, document)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
