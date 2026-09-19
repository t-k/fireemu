"""Generate the immutable auth-time/listCollectionIds denominator overlay."""

from __future__ import annotations

import hashlib
import json
import argparse
from pathlib import Path
from typing import Any

import production_denominator_v2 as parent

ROOT_PARENT = parent.Path(__file__).parents[2]
VERSION = "ip-fs-standard-2026-09-14.v2-auth-time-listcollectionids.v1"
OUTPUT_PATH = "spec/compatibility/denominators/ip-fs-standard-2026-09-14.v2-auth-time-listcollectionids.v1.json"
MAPPING_PATH = "spec/compatibility/denominators/ip-fs-standard-2026-09-14.v2-auth-time-listcollectionids.v1.mapping.json"
DOCUMENT_PATH = "docs/compatibility/production-denominator-v2-auth-time-listcollectionids.md"
PARENT_SHA256 = "22d9aa2f3ff3172a0e0f0f4cabfa49ba5304175806f5c15bc3a02fba1e95b5fe"
AUTH_TIME_TARGETS = {
    "securetoken-v1:method:REST:securetoken.token",
    "securetoken-v1:request:REST:securetoken.token/request",
    "securetoken-v1:response:REST:securetoken.token/response",
    "securetoken-v1:field:REST:schemas/GrantTokenResponse/properties/id_token",
}
LIST_COLLECTION_IDS_TARGETS = {
    "firestore-v1:method:REST:firestore.projects.databases.documents.listCollectionIds",
    "firestore-v1:request:REST:firestore.projects.databases.documents.listCollectionIds/request",
    "firestore-v1:response:REST:firestore.projects.databases.documents.listCollectionIds/response",
    "firestore-v1:schema:REST:schemas/ListCollectionIdsRequest",
    "firestore-v1:schema:REST:schemas/ListCollectionIdsResponse",
    "firestore-v1:field:REST:firestore.projects.databases.documents.listCollectionIds/parameters/parent",
    "firestore-v1:field:REST:schemas/ListCollectionIdsRequest/properties/pageSize",
    "firestore-v1:field:REST:schemas/ListCollectionIdsResponse/properties/collectionIds",
}
ALL_NEW_TARGETS = AUTH_TIME_TARGETS | LIST_COLLECTION_IDS_TARGETS
AUTH_CASE_IDS = {
    "auth-session-v2-refresh-auth-time": "changed-refresh@0",
    "auth-session-continuity-refresh-auth-time": "reference-refresh",
}
AUTH_ASSERTION_PATHS = {
    "securetoken-v1:method:REST:securetoken.token": "response/checks/idTokenPresent",
    "securetoken-v1:request:REST:securetoken.token/request": "response/checks/refreshTokenPresent",
    "securetoken-v1:response:REST:securetoken.token/response": "response/checks/noError",
    "securetoken-v1:field:REST:schemas/GrantTokenResponse/properties/id_token": "response/checks/idTokenPresent",
}
FIRESTORE_CASE_IDS = [
    "firestore:queries/projection-and-listing#list-collection-ids-root",
    "firestore:queries/projection-and-listing#list-collection-ids-of-a-missing-document",
    "firestore:queries/projection-and-listing#list-collection-ids-paged",
]
FIRESTORE_OBSERVATION_PATHS = {
    target: ["/cases/54", "/cases/55", "/cases/56"]
    for target in {
        "firestore-v1:method:REST:firestore.projects.databases.documents.listCollectionIds",
        "firestore-v1:request:REST:firestore.projects.databases.documents.listCollectionIds/request",
        "firestore-v1:response:REST:firestore.projects.databases.documents.listCollectionIds/response",
        "firestore-v1:schema:REST:schemas/ListCollectionIdsRequest",
        "firestore-v1:schema:REST:schemas/ListCollectionIdsResponse",
        "firestore-v1:field:REST:firestore.projects.databases.documents.listCollectionIds/parameters/parent",
        "firestore-v1:field:REST:schemas/ListCollectionIdsResponse/properties/collectionIds",
    }
}
FIRESTORE_OBSERVATION_PATHS["firestore-v1:field:REST:schemas/ListCollectionIdsRequest/properties/pageSize"] = ["/cases/56"]
FIRESTORE_ASSERTION_PATHS = {
    target: ["/cases/54/status", "/cases/55/status"]
    for target in {
        "firestore-v1:method:REST:firestore.projects.databases.documents.listCollectionIds",
        "firestore-v1:request:REST:firestore.projects.databases.documents.listCollectionIds/request",
    }
}
FIRESTORE_ASSERTION_PATHS.update({
    "firestore-v1:schema:REST:schemas/ListCollectionIdsRequest": ["/cases/54/status"],
    "firestore-v1:field:REST:firestore.projects.databases.documents.listCollectionIds/parameters/parent": ["/cases/54/status"],
    "firestore-v1:field:REST:schemas/ListCollectionIdsRequest/properties/pageSize": ["/cases/56/status"],
    "firestore-v1:response:REST:firestore.projects.databases.documents.listCollectionIds/response": ["/cases/54/expected/body/collectionIds", "/cases/55/expected/body/collectionIds"],
    "firestore-v1:schema:REST:schemas/ListCollectionIdsResponse": ["/cases/54/expected/body/collectionIds"],
    "firestore-v1:field:REST:schemas/ListCollectionIdsResponse/properties/collectionIds": ["/cases/54/expected/body/collectionIds", "/cases/55/expected/body/collectionIds"],
})
class ValidationError(parent.ValidationError):
    pass

def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def read(path: Path) -> Any:
    return parent.read_json(path)

def ref(root: Path, value: dict[str, str], label: str) -> Any:
    if set(value) != {"path", "sha256"} or not parent.HEX64.fullmatch(value["sha256"]):
        raise ValidationError(f"{label}: invalid reference")
    return read(parent.checked_reference(root, value, label))

def structural(target: dict[str, Any]) -> dict[str, Any]:
    return parent.target_structural(target)

def validate_auth(root: Path, spec: dict[str, Any]) -> dict[str, Any]:
    receipt = ref(root, spec["receipt"], "auth receipt")
    approval = ref(root, spec["approval"], "auth approval")
    ref(root, spec["sourceReview"], "auth source review")
    if receipt.get("schemaVersion") != 2 or receipt.get("acceptance") != "candidate":
        raise ValidationError("auth receipt is not the pinned candidate receipt")
    if receipt["production"].get("target") != "production" or receipt["local"].get("target") != "local":
        raise ValidationError("auth receipt targets are invalid")
    if approval.get("schemaVersion") != 1 or approval.get("decision") != "approve" or approval.get("subjectSha256") != digest(receipt):
        raise ValidationError("auth approval subject or decision is invalid")
    production = {row["id"]: row for row in receipt["production"]["cases"]}
    local = {row["id"]: row for row in receipt["local"]["cases"]}
    for case_id in spec["caseIds"]:
        for rows in (production, local):
            row = rows.get(case_id)
            response = row.get("response", {}) if row else {}
            claims = response.get("tokenTime", {})
            if response.get("outcome") != "accepted" or response.get("httpStatus") != 200 or not all(response.get("checks", {}).get(k) is True for k in ("idTokenPresent", "refreshTokenPresent", "noError")):
                raise ValidationError("auth refresh case is not accepted")
            if not isinstance(claims.get("authTime"), int) or not isinstance(claims.get("iat"), int) or not 0 <= claims["authTime"] <= claims["iat"] <= 2**31 - 1:
                raise ValidationError("auth-time claims are outside the bounded range")
    # The production and local decoded authTime values intentionally differ in these receipts.
    if all(production[c]["response"]["tokenTime"]["authTime"] == local[c]["response"]["tokenTime"]["authTime"] for c in spec["caseIds"]):
        raise ValidationError("auth-time mismatch limitation is not present")
    return receipt

def validate_firestore(root: Path, spec: dict[str, Any]) -> dict[str, Any]:
    artifact = ref(root, spec["artifact"], "listCollectionIds artifact")
    ids = ["firestore:queries/projection-and-listing#list-collection-ids-root", "firestore:queries/projection-and-listing#list-collection-ids-of-a-missing-document", "firestore:queries/projection-and-listing#list-collection-ids-paged"]
    if spec["caseIds"] != ids:
        raise ValidationError("listCollectionIds case IDs are not canonical")
    rows = {row["id"]: row for row in artifact["cases"]}
    for case_id in ids:
        row = rows.get(case_id, {})
        if row.get("status") != "match" or row.get("basis") != "historical-production-reference":
            raise ValidationError("listCollectionIds row is not a production reference")
        actual, expected = row.get("actual", {}), row.get("expected", {})
        if expected != {"status": 200, "code": "OK", "body": actual.get("body")} or set(expected.get("body", {})) != {"collectionIds"}:
            raise ValidationError("listCollectionIds response shape is not exact")
        if actual.get("http", {}).get("complete") is not True:
            raise ValidationError("listCollectionIds response is incomplete")
    return artifact

def validate_pointers(root: Path, mapping: dict[str, Any]) -> None:
    auth_by_id = {spec["id"]: validate_auth(root, spec) for spec in mapping["auth"]}
    artifact = validate_firestore(root, mapping["firestore"])
    for binding in mapping["bindings"]:
        if binding["evidenceId"] in auth_by_id:
            receipt = auth_by_id[binding["evidenceId"]]
            selected = {row["id"]: i for i, row in enumerate(receipt["production"]["cases"])}
            local_selected = {row["id"]: i for i, row in enumerate(receipt["local"]["cases"])}
            if binding["caseId"] not in selected:
                raise ValidationError("auth binding case is absent")
            expected_case = AUTH_CASE_IDS[binding["evidenceId"]]
            if binding["caseId"] != expected_case:
                raise ValidationError("auth binding case is not allowlisted")
            expected_condition_pointers = [
                f"/production/cases/{selected[binding['caseId']]}",
                f"/local/cases/{local_selected[binding['caseId']]}",
            ]
            condition_pointers = binding.get("conditions", {}).get("evidencePointers")
            if condition_pointers != expected_condition_pointers:
                raise ValidationError("auth condition pointers are not allowlisted")
            for condition_path in condition_pointers:
                parent.pointer({"production": receipt["production"], "local": receipt["local"]}, condition_path, "auth condition")
            for surface in binding["surfaces"]:
                expected_observations = [
                    f"/production/cases/{selected[binding['caseId']]}",
                    f"/local/cases/{local_selected[binding['caseId']]}",
                ]
                if surface["observationPointers"] != expected_observations:
                    raise ValidationError("auth observation pointers are not allowlisted")
                expected_assertions = [
                    f"/production/cases/{selected[binding['caseId']]}/{AUTH_ASSERTION_PATHS.get(surface['targetId'], '')}",
                    f"/local/cases/{local_selected[binding['caseId']]}/{AUTH_ASSERTION_PATHS.get(surface['targetId'], '')}",
                ]
                if surface["assertionPointers"] != expected_assertions:
                    raise ValidationError("auth assertion pointers are not allowlisted")
                for pointer_path in surface["observationPointers"] + surface["assertionPointers"]:
                    parent.pointer({"production": receipt["production"], "local": receipt["local"]}, pointer_path, "auth evidence pointer")
                for assertion_path in surface["assertionPointers"]:
                    if parent.pointer({"production": receipt["production"], "local": receipt["local"]}, assertion_path, "auth assertion") is not True:
                        raise ValidationError("auth assertion pointer is not true")
        elif binding["evidenceId"] == mapping["firestore"]["id"]:
            selected = {row["id"]: i for i, row in enumerate(artifact["cases"])}
            if binding["caseId"] not in selected:
                raise ValidationError("Firestore binding case is absent")
            if binding["caseId"] != FIRESTORE_CASE_IDS[0] or mapping["firestore"]["caseIds"] != FIRESTORE_CASE_IDS:
                raise ValidationError("Firestore case selection is not allowlisted")
            expected_case_by_index = {index: row["id"] for index, row in enumerate(artifact["cases"])}
            condition_pointers = binding.get("conditions", {}).get("evidencePointers")
            expected_condition_pointers = [f"/cases/{i}" for i in (54, 55, 56)]
            if condition_pointers != expected_condition_pointers:
                raise ValidationError("Firestore condition pointers are not allowlisted")
            for condition_path in condition_pointers:
                condition_row = parent.pointer(artifact, condition_path, "Firestore condition")
                index = int(condition_path.split("/")[2])
                if not isinstance(condition_row, dict) or condition_row.get("id") != expected_case_by_index.get(index):
                    raise ValidationError("Firestore condition selects the wrong case")
            for surface in binding["surfaces"]:
                target_id = surface["targetId"]
                if surface["observationPointers"] != FIRESTORE_OBSERVATION_PATHS.get(target_id) or surface["assertionPointers"] != FIRESTORE_ASSERTION_PATHS.get(target_id):
                    raise ValidationError("Firestore pointers are not allowlisted")
                for pointer_path in surface["observationPointers"] + surface["assertionPointers"]:
                    value = parent.pointer(artifact, pointer_path, "Firestore evidence pointer")
                    if pointer_path in surface["observationPointers"] and (not isinstance(value, dict) or value.get("id") != expected_case_by_index.get(int(pointer_path.split("/")[2]))):
                        raise ValidationError("Firestore observation does not select a complete case row")
                    if pointer_path.endswith("/status") and value != "match":
                        raise ValidationError("Firestore status assertion is not match")
                    if "/expected/body/collectionIds" in pointer_path and not isinstance(value, list):
                        raise ValidationError("Firestore collectionIds assertion is not a list")

def validate_document(root: Path, value: dict[str, Any]) -> None:
    if set(value) != {"schemaVersion", "goal", "denominatorVersion", "parentDenominator", "sourceSnapshot", "definitions", "mappingSource", "generator", "targets", "evidence", "bindings"} or value["schemaVersion"] != 2 or value["denominatorVersion"] != VERSION:
        raise ValidationError("invalid overlay header")
    parent_path = root / parent.OUTPUT_PATH
    if hashlib.sha256(parent_path.read_bytes()).hexdigest() != PARENT_SHA256:
        raise ValidationError("parent denominator hash mismatch")
    base = read(parent_path)
    parent.validate_document(root, base)
    mapping_ref = value["mappingSource"]
    if mapping_ref != {"path": MAPPING_PATH, "sha256": parent.file_digest(root, MAPPING_PATH)}:
        raise ValidationError("mapping source identity mismatch")
    mapping = ref(root, mapping_ref, "mapping source")
    parent_targets = {target["id"]: target for target in base["targets"]}
    if value["goal"] != base["goal"] or value["sourceSnapshot"] != base["sourceSnapshot"] or value["definitions"] != base["definitions"]:
        raise ValidationError("overlay parent metadata differs")
    generator = value["generator"]
    if generator != {"path": "tools/compat-inventory/production_denominator_v2_auth_time.py", "sha256": parent.file_digest(root, generator["path"])}:
        raise ValidationError("overlay generator identity mismatch")
    if len(value["targets"]) != len(parent_targets):
        raise ValidationError("overlay target count mismatch")
    bindings = mapping["bindings"]
    validate_pointers(root, mapping)
    allowed = {surface["targetId"] for binding in bindings for surface in binding["surfaces"]}
    if allowed != ALL_NEW_TARGETS or "firestore-v1:field:REST:schemas/ListCollectionIdsResponse/properties/nextPageToken" in allowed:
        raise ValidationError("overlay mapped surface set is invalid")
    for target in value["targets"]:
        old = parent_targets.get(target["id"])
        if old is None or structural(target) != structural(old):
            raise ValidationError("overlay target structure mismatch")
        expected = sorted(set(old.get("bindingIds", [])) | {b["id"] for b in bindings if any(s["targetId"] == target["id"] for s in b["surfaces"])})
        if target["bindingIds"] != expected or target["coverage"] != ("partial" if expected else "none"):
            raise ValidationError("overlay target coverage mismatch")
    for binding in bindings:
        if set(binding) != {"id", "evidenceId", "caseId", "evidenceLevel", "comparisonResult", "conditions", "surfaces"}:
            raise ValidationError("overlay binding shape mismatch")
        if binding["evidenceLevel"] not in parent.EVIDENCE_LEVELS or binding["comparisonResult"] not in parent.COMPARISON_RESULTS:
            raise ValidationError("overlay binding classification invalid")
        for surface in binding["surfaces"]:
            if set(surface) != {"targetId", "observationPointers", "assertionPointers", "coverage", "reason"} or surface["coverage"] != "partial" or not surface["reason"]:
                raise ValidationError("overlay surface shape mismatch")
    canonical = generate_value(root, mapping)
    if value != canonical:
        raise ValidationError("overlay differs from canonical evidence")

def generate_value(root: Path, mapping: dict[str, Any]) -> dict[str, Any]:
    base = read(root / parent.OUTPUT_PATH)
    for spec in mapping["auth"]: validate_auth(root, spec)
    validate_firestore(root, mapping["firestore"])
    targets = []
    for old in base["targets"]:
        extra = sorted(b["id"] for b in mapping["bindings"] if any(s["targetId"] == old["id"] for s in b["surfaces"]))
        ids = sorted(set(old.get("bindingIds", [])) | set(extra))
        targets.append({**old, "bindingIds": ids, "coverage": "partial" if ids else "none"})
    evidence = []
    for spec in mapping["auth"]:
        evidence.append({"id": spec["id"], "adapterId": "auth-refresh-auth-time.v1", "adapter": {"path": "tools/compat-inventory/production_denominator_v2_auth_time.py", "sha256": parent.file_digest(root, "tools/compat-inventory/production_denominator_v2_auth_time.py")}, "production": {"receipt": spec["receipt"]}, "local": {"receipt": spec["receipt"]}, "corpus": {"caseIds": spec["caseIds"]}, "comparator": {"projection": "bounded decoded authTime/iat and refresh response checks", "result": "mismatch"}, "limitations": ["decoded authTime and iat are unsigned bounded metadata", "production/local authTime values differ; this is partial evidence rather than parity"], "approval": spec["approval"]})
    fs = mapping["firestore"]
    evidence.append({"id": fs["id"], "adapterId": "firestore-list-collection-ids.v1", "adapter": {"path": "tools/compat-inventory/production_denominator_v2_auth_time.py", "sha256": parent.file_digest(root, "tools/compat-inventory/production_denominator_v2_auth_time.py")}, "production": {"receipt": fs["artifact"]}, "local": {"receipt": fs["artifact"]}, "corpus": {"caseIds": fs["caseIds"]}, "comparator": {"projection": "exact normalized JSON status/code/body", "result": "match"}, "limitations": ["exact three saved rows do not emit or consume a continuation token", "pageToken, readTime, continuation consumption, FieldMask and SAML remain unmapped"], "approval": fs["artifact"]})
    return {"schemaVersion": 2, "goal": base["goal"], "denominatorVersion": VERSION, "parentDenominator": {"path": parent.OUTPUT_PATH, "version": parent.V2_VERSION, "sha256": PARENT_SHA256}, "sourceSnapshot": base["sourceSnapshot"], "definitions": base["definitions"], "mappingSource": {"path": MAPPING_PATH, "sha256": parent.file_digest(root, MAPPING_PATH)}, "generator": {"path": "tools/compat-inventory/production_denominator_v2_auth_time.py", "sha256": parent.file_digest(root, "tools/compat-inventory/production_denominator_v2_auth_time.py")}, "targets": targets, "evidence": evidence, "bindings": mapping["bindings"]}

def generate(root: Path, output: Path, report: Path) -> None:
    mapping = read(root / MAPPING_PATH)
    value = generate_value(root, mapping)
    validate_document(root, value)
    parent.write_immutable(output, parent.serialized(value))
    parent.write_immutable(report, b"<!-- Generated by production_denominator_v2_auth_time.py. Do not edit. -->\n\n# Production denominator v2 auth-time and listCollectionIds overlay\n\nThe overlay records bounded unsigned auth-time metadata as partial evidence because production and local values differ. It maps the exact three saved `listCollectionIds` rows. `pageToken`, response `nextPageToken`, `readTime`, continuation consumption, FieldMask and SAML surfaces remain unmapped.\n")

def check(root: Path, output: Path, report: Path) -> None:
    expected = generate_value(root, read(root / MAPPING_PATH))
    validate_document(root, read(output))
    expected_report = b"<!-- Generated by production_denominator_v2_auth_time.py. Do not edit. -->\n\n# Production denominator v2 auth-time and listCollectionIds overlay\n\nThe overlay records bounded unsigned auth-time metadata as partial evidence because production and local values differ. It maps the exact three saved `listCollectionIds` rows. `pageToken`, response `nextPageToken`, `readTime`, continuation consumption, FieldMask and SAML surfaces remain unmapped.\n"
    if output.read_bytes() != parent.serialized(expected) or report.read_bytes() != expected_report:
        raise ValidationError("stale auth-time overlay output")

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT_PARENT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    output, report = root / OUTPUT_PATH, root / DOCUMENT_PATH
    if args.check:
        check(root, output, report)
        return 0
    generate(root, output, report)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
