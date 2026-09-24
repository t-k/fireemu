"""Compile a finite, credential-free REST request-byte boundary plan."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

REQUEST_LIMIT = 11_534_336
REQUEST_TARGETS = (REQUEST_LIMIT - 1, REQUEST_LIMIT, REQUEST_LIMIT + 1)
CATALOG_MAXIMUM = 10_485_760
RAW_16MIB_OVER_BYTES = 16_777_217
RAW_16MIB_OVER_CASE_ID = "FS-LIMIT-API-REQUEST-BYTES-RAW-16MIB-OVER"
RAW_16MIB_OVER_LABEL = "raw-16mib-over"
DOCUMENT_SAFETY_MARGIN = 900 * 1024
PAYLOAD_DOCUMENT_COUNT = 16
DOCUMENT_COUNT = 17
PROBES = ("under", "exact", "over")
CAMPAIGN = "FS-LIMIT-API-REQUEST-BYTES"
_TARGET = re.compile(r"^[A-Za-z0-9_-]+$")
_NONCE = re.compile(r"^[0-9a-f]{32}$")


def compact_utf8(value: Any) -> bytes:
    return json.dumps(
        value, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def logical_fields_digest(fields: dict[str, Any]) -> str:
    """Hash logical maps independently of response field order, unlike wire bytes."""
    encoded = json.dumps(
        fields,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _string_size(value: str) -> int:
    return len(value.encode("utf-8")) + 1


def _fields_size(fields: dict[str, dict[str, Any]]) -> int:
    total = 0
    for name, value in fields.items():
        if set(value) != {"stringValue"}:
            raise ValueError("request-bytes fixture supports string values only")
        total += _string_size(name) + _string_size(value["stringValue"])
    return total


def document_size_bytes(resource: str, fields: dict[str, dict[str, Any]]) -> int:
    if not isinstance(resource, str):
        raise ValueError("malformed document resource")
    parts = resource.split("/", 5)
    if (len(parts) != 6 or parts[0] != "projects" or not parts[1]
            or parts[2] != "databases" or not parts[3] or parts[4] != "documents"):
        raise ValueError("malformed document resource")
    segments = parts[5].split("/")
    if len(segments) < 2 or len(segments) % 2 or any(not segment for segment in segments):
        raise ValueError("malformed document resource")
    return (
        16
        + sum(_string_size(segment) for segment in segments)
        + 32
        + _fields_size(fields)
    )


def _validate_target(project: str, database: str, nonce: str) -> None:
    if not isinstance(project, str) or not _TARGET.fullmatch(project):
        raise ValueError("malformed project")
    if not isinstance(database, str) or (
        database != "(default)" and not _TARGET.fullmatch(database)
    ):
        raise ValueError("malformed database")
    if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
        raise ValueError("nonce must be 32 lowercase hexadecimal characters")


def _fields(nonce: str, blob: str) -> dict[str, dict[str, str]]:
    return {"_owner": {"stringValue": nonce}, "blob": {"stringValue": blob}}


def _resources(scope: str, payload_count: int = PAYLOAD_DOCUMENT_COUNT) -> list[str]:
    return [f"{scope}/items/control"] + [
        f"{scope}/items/payload-{index:02d}" for index in range(payload_count)
    ]


def _body(resources: list[str], lengths: list[int], nonce: str) -> dict[str, Any]:
    writes = []
    for index, (resource, length) in enumerate(zip(resources, lengths)):
        writes.append(
            {
                "update": {
                    "name": resource,
                    "fields": _fields(nonce, "control" if index == 0 else "x" * length),
                },
                "currentDocument": {"exists": False},
            }
        )
    return {"writes": writes}


def _balanced_lengths(
    resources: list[str], target: int, nonce: str, *, payload_count: int = PAYLOAD_DOCUMENT_COUNT
) -> list[int]:
    empty = _body(resources, [7] + [0] * payload_count, nonce)
    total = target - len(compact_utf8(empty))
    if total <= 0:
        raise ValueError("fixed request shape exceeds target")
    quotient, remainder = divmod(total, payload_count)
    return [quotient + (index < remainder) for index in range(payload_count)]


def _op(
    kind: str,
    method: str,
    path: str,
    probe: str,
    expect: dict[str, Any],
    resource: str | None = None,
    body: Any = None,
) -> dict[str, Any]:
    row = {
        "kind": kind,
        "service": "firestore",
        "method": method,
        "path": path,
        "body": body,
        "privileged": True,
        "form": False,
        "probe": probe,
        "expect": expect,
    }
    if resource is not None:
        row["resource"] = resource
    return row


def compile_request_bytes_plan(
    project: str, database: str, nonce: str
) -> dict[str, Any]:
    _validate_target(project, database, nonce)
    root = f"projects/{project}/databases/{database}/documents/oracle/{nonce}/request-bytes-01"
    scopes = {
        "under": root + "/probe-u01",
        "exact": root + "/probe-e01",
        "over": root + "/probe-o01",
    }
    resources_by_probe = {probe: _resources(scope) for probe, scope in scopes.items()}
    probes, observation, recovery, documents, schedule = [], [], [], {}, []
    endpoint = f"/v1/projects/{project}/databases/{database}/documents:commit"
    for probe, target in zip(PROBES, REQUEST_TARGETS):
        observation_start, recovery_start = len(observation), len(recovery)
        resources = resources_by_probe[probe]
        lengths = [7] + _balanced_lengths(resources, target, nonce)
        body = _body(resources, lengths, nonce)
        if len(compact_utf8(body)) != target:
            raise AssertionError("canonical body did not reach requested size")
        expected_documents = []
        for resource, length in zip(resources, lengths):
            fields = _fields(
                nonce, "control" if resource.endswith("/control") else "x" * length
            )
            logical = document_size_bytes(resource, fields)
            if logical >= DOCUMENT_SAFETY_MARGIN:
                raise ValueError("document safety margin exceeded")
            documents[resource] = {
                "resource": resource,
                "fieldsSha256": logical_fields_digest(fields),
                "logicalBytes": logical,
            }
            expected_documents.append(
                {"name": resource, "fieldsSha256": documents[resource]["fieldsSha256"]}
            )
        expected = {
            "prior": "all-absent",
            "accepted": {"all": expected_documents},
            "refused": {"all": "absent"},
        }
        probes.append(
            {
                "label": probe,
                "scope": scopes[probe],
                "resources": resources,
                "body": body,
                "bodyBytes": target,
                "path": endpoint,
                "expected": expected,
            }
        )
        for resource in resources:
            observation.append(
                _op(
                    "preflight-typed-absence",
                    "GET",
                    "/v1/" + resource,
                    probe,
                    {"status": 404, "typed": "NOT_FOUND", "owned": False},
                    resource,
                )
            )
        observation.append(
            _op(
                "conditional-create-commit",
                "POST",
                endpoint,
                probe,
                expected,
                body=body,
            )
        )
        for resource in resources:
            observation.append(
                _op(
                    "probe-readback",
                    "GET",
                    "/v1/" + resource,
                    probe,
                    {
                        "accepted": expected["accepted"],
                        "refused": expected["refused"],
                        "sameProbe": True,
                    },
                    resource,
                )
            )
        for resource in resources:
            recovery.extend(
                [
                    _op(
                        "cleanup-ownership-read",
                        "GET",
                        "/v1/" + resource,
                        probe,
                        {
                            "statuses": [200, 404],
                            "owned": True,
                            "versionRequired": True,
                        },
                        resource,
                    ),
                    {
                        **_op(
                            "cleanup-version-bound-delete",
                            "DELETE",
                            "/v1/" + resource,
                            probe,
                            {"status": 200, "owned": True, "versionBound": True},
                            resource,
                        ),
                        "versionFrom": "cleanup-ownership-read",
                    },
                    _op(
                        "cleanup-verify-absence",
                        "GET",
                        "/v1/" + resource,
                        probe,
                        {"status": 404, "typed": "NOT_FOUND"},
                        resource,
                    ),
                ]
            )
        schedule.extend(
            {"phase": "observation", "index": i}
            for i in range(observation_start, len(observation))
        )
        schedule.extend(
            {"phase": "recovery", "index": i}
            for i in range(recovery_start, len(recovery))
        )
    return {
        "schemaVersion": 3,
        "campaignId": CAMPAIGN,
        "catalogId": CAMPAIGN,
        "catalogMaximum": CATALOG_MAXIMUM,
        "project": project,
        "database": database,
        "nonce": nonce,
        "protocol": "REST",
        "metric": "REST raw HTTP body UTF-8 bytes",
        "metricStatus": "observation hypothesis",
        "unicodeNormalization": "none",
        "gRPCScope": "separate case required",
        "ownedScope": root,
        "ownedScopes": list(scopes.values()),
        "ownedResources": [
            r for resources in resources_by_probe.values() for r in resources
        ],
        "documents": documents,
        "probes": probes,
        "observation": observation,
        "recovery": recovery,
        "executionSchedule": schedule,
        "probeTransition": "complete typed cleanup required before next probe",
        "ownershipRequirements": [
            "preflight typed absence",
            "every Commit write has currentDocument.exists=false",
            "successful conditional-creation proof required before cleanup",
            "version-bound conditional cleanup",
        ],
        "readbackRequirements": [
            "accepted probe compares every document with its own expected snapshot",
            "refused probe requires every document absent",
            "mixed publication is indeterminate",
        ],
        "bounds": {
            "probeCount": 3,
            "maxInFlight": 1,
            "requestBytes": max(REQUEST_TARGETS),
            "distinctDocumentCount": 51,
            "peakLiveDocumentCount": 17,
            "observationRequests": 105,
            "recoveryRequests": 153,
            "totalRequestBound": 258,
            "responseByteCap": 2 * 1024 * 1024,
        },
        "claims": [
            "REST-only",
            "does not claim gRPC coverage",
            "does not claim document, depth, transform, or operation-count limits",
        ],
    }


def compile_request_bytes_sentinel_plan(
    project: str, database: str, nonce: str
) -> dict[str, Any]:
    """Compile the separately scoped, outcome-neutral 16 MiB follow-up case."""
    _validate_target(project, database, nonce)
    root = f"projects/{project}/databases/{database}/documents/oracle/{nonce}/request-bytes-02"
    scope = root + "/probe-r16m1"
    endpoint = f"/v1/projects/{project}/databases/{database}/documents:commit"
    resources = _resources(scope, payload_count=19)
    lengths = [7] + _balanced_lengths(
        resources, RAW_16MIB_OVER_BYTES, nonce, payload_count=19
    )
    body = _body(resources, lengths, nonce)
    if len(compact_utf8(body)) != RAW_16MIB_OVER_BYTES:
        raise AssertionError("sentinel body did not reach requested size")

    documents: dict[str, dict[str, Any]] = {}
    expected_documents = []
    for resource, length in zip(resources, lengths):
        fields = _fields(
            nonce, "control" if resource.endswith("/control") else "x" * length
        )
        logical = document_size_bytes(resource, fields)
        if logical >= DOCUMENT_SAFETY_MARGIN:
            raise ValueError("document safety margin exceeded")
        entry = {
            "resource": resource,
            "fieldsSha256": logical_fields_digest(fields),
            "logicalBytes": logical,
        }
        documents[resource] = entry
        expected_documents.append(
            {"name": resource, "fieldsSha256": entry["fieldsSha256"]}
        )

    expected = {
        "prior": "all-absent",
        "accepted": {"all": expected_documents},
        "refused": {"all": "absent"},
        "outcome": "capture-without-semantic-expectation",
    }
    probe = {
        "label": RAW_16MIB_OVER_LABEL,
        "caseId": RAW_16MIB_OVER_CASE_ID,
        "scope": scope,
        "resources": resources,
        "body": body,
        "bodyBytes": RAW_16MIB_OVER_BYTES,
        "path": endpoint,
        "expected": expected,
    }
    observation = [
        _op(
            "preflight-typed-absence",
            "GET",
            "/v1/" + resource,
            RAW_16MIB_OVER_LABEL,
            {"status": 404, "typed": "NOT_FOUND", "owned": False},
            resource,
        )
        for resource in resources
    ]
    observation.append(
        _op(
            "conditional-create-commit",
            "POST",
            endpoint,
            RAW_16MIB_OVER_LABEL,
            expected,
            body=body,
        )
    )
    observation.extend(
        _op(
            "probe-readback",
            "GET",
            "/v1/" + resource,
            RAW_16MIB_OVER_LABEL,
            {
                "accepted": expected["accepted"],
                "refused": expected["refused"],
                "sameProbe": True,
            },
            resource,
        )
        for resource in resources
    )
    recovery = []
    for resource in resources:
        recovery.extend(
            [
                _op(
                    "cleanup-ownership-read",
                    "GET",
                    "/v1/" + resource,
                    RAW_16MIB_OVER_LABEL,
                    {"statuses": [200, 404], "owned": True, "versionRequired": True},
                    resource,
                ),
                {
                    **_op(
                        "cleanup-version-bound-delete",
                        "DELETE",
                        "/v1/" + resource,
                        RAW_16MIB_OVER_LABEL,
                        {"status": 200, "owned": True, "versionBound": True},
                        resource,
                    ),
                    "versionFrom": "cleanup-ownership-read",
                },
                _op(
                    "cleanup-verify-absence",
                    "GET",
                    "/v1/" + resource,
                    RAW_16MIB_OVER_LABEL,
                    {"status": 404, "typed": "NOT_FOUND"},
                    resource,
                ),
            ]
        )
    schedule = [
        *({"phase": "observation", "index": index} for index in range(len(observation))),
        *({"phase": "recovery", "index": index} for index in range(len(recovery))),
    ]
    return {
        "schemaVersion": 3,
        "caseMode": "single-exploratory-sentinel",
        "caseId": RAW_16MIB_OVER_CASE_ID,
        "campaignId": CAMPAIGN,
        "catalogId": CAMPAIGN,
        "catalogMaximum": CATALOG_MAXIMUM,
        "project": project,
        "database": database,
        "nonce": nonce,
        "protocol": "REST",
        "metric": "REST raw HTTP body UTF-8 bytes",
        "metricStatus": "observation hypothesis",
        "unicodeNormalization": "none",
        "gRPCScope": "separate case required",
        "ownedScope": root,
        "ownedScopes": [scope],
        "ownedResources": resources,
        "documents": documents,
        "probes": [probe],
        "observation": observation,
        "recovery": recovery,
        "executionSchedule": schedule,
        "probeTransition": "one Commit only; complete typed cleanup required before close",
        "ownershipRequirements": [
            "preflight typed absence",
            "every Commit write has currentDocument.exists=false",
            "successful conditional-creation proof required before cleanup",
            "version-bound conditional cleanup",
        ],
        "readbackRequirements": [
            "capture accepted or refused state without predicting either outcome",
            "accepted state compares every document with its own expected snapshot and Commit version",
            "refused state requires every document absent",
            "mixed publication is indeterminate",
        ],
        "bounds": {
            "probeCount": 1,
            "maxInFlight": 1,
            "requestBytes": RAW_16MIB_OVER_BYTES,
            "distinctDocumentCount": 20,
            "peakLiveDocumentCount": 20,
            "observationRequests": len(observation),
            "recoveryRequests": len(recovery),
            "totalRequestBound": len(observation) + len(recovery),
            "responseByteCap": 2 * 1024 * 1024,
        },
        "claims": [
            "one exploratory REST Commit input only",
            "does not infer a service threshold or quota metric",
            "does not claim gRPC coverage",
            "does not claim document, depth, transform, or operation-count limits",
        ],
    }


def validate_request_bytes_sentinel_plan(plan: dict[str, Any]) -> None:
    """Validate the one-case sentinel without borrowing historical probe rules."""
    if not isinstance(plan, dict) or plan.get("caseMode") != "single-exploratory-sentinel":
        raise ValueError("sentinel plan mode required")
    expected_contract = {
        "schemaVersion": 3,
        "caseId": RAW_16MIB_OVER_CASE_ID,
        "campaignId": CAMPAIGN,
        "catalogId": CAMPAIGN,
        "catalogMaximum": CATALOG_MAXIMUM,
        "protocol": "REST",
        "metric": "REST raw HTTP body UTF-8 bytes",
        "metricStatus": "observation hypothesis",
        "unicodeNormalization": "none",
        "gRPCScope": "separate case required",
    }
    if any(plan.get(key) != value for key, value in expected_contract.items()):
        raise ValueError("sentinel metric contract drift")
    project, database, nonce = plan.get("project"), plan.get("database"), plan.get("nonce")
    _validate_target(project, database, nonce)
    root = f"projects/{project}/databases/{database}/documents/oracle/{nonce}/request-bytes-02"
    scope = root + "/probe-r16m1"
    endpoint = f"/v1/projects/{project}/databases/{database}/documents:commit"
    probes = plan.get("probes")
    if not isinstance(probes, list) or len(probes) != 1:
        raise ValueError("sentinel requires exactly one probe")
    probe = probes[0]
    resources = _resources(scope, payload_count=19)
    if (
        probe.get("label") != RAW_16MIB_OVER_LABEL
        or probe.get("caseId") != RAW_16MIB_OVER_CASE_ID
        or probe.get("scope") != scope
        or probe.get("resources") != resources
        or probe.get("path") != endpoint
    ):
        raise ValueError("sentinel identity or scope drift")
    body = probe.get("body")
    if not isinstance(body, dict) or set(body) != {"writes"}:
        raise ValueError("sentinel Commit body shape drift")
    writes = body["writes"]
    if not isinstance(writes, list) or len(writes) != 20:
        raise ValueError("sentinel requires twenty Commit writes")
    docs: dict[str, dict[str, Any]] = {}
    accepted = []
    for resource, write in zip(resources, writes):
        if (
            not isinstance(write, dict)
            or set(write) != {"update", "currentDocument"}
            or write["currentDocument"] != {"exists": False}
        ):
            raise ValueError("sentinel requires exists-false ownership preconditions")
        update = write["update"]
        if (
            not isinstance(update, dict)
            or set(update) != {"name", "fields"}
            or update["name"] != resource
        ):
            raise ValueError("sentinel write identity drift")
        fields = update["fields"]
        if (
            not isinstance(fields, dict)
            or set(fields) != {"_owner", "blob"}
            or fields["_owner"] != {"stringValue": nonce}
            or set(fields["blob"]) != {"stringValue"}
            or not isinstance(fields["blob"]["stringValue"], str)
        ):
            raise ValueError("sentinel payload ownership or field drift")
        logical = document_size_bytes(resource, fields)
        if logical >= DOCUMENT_SAFETY_MARGIN:
            raise ValueError("sentinel document safety margin exceeded")
        entry = {
            "resource": resource,
            "fieldsSha256": logical_fields_digest(fields),
            "logicalBytes": logical,
        }
        docs[resource] = entry
        accepted.append({"name": resource, "fieldsSha256": entry["fieldsSha256"]})
    if len(compact_utf8(body)) != RAW_16MIB_OVER_BYTES or probe.get("bodyBytes") != RAW_16MIB_OVER_BYTES:
        raise ValueError("sentinel byte length drift")
    expected = {
        "prior": "all-absent",
        "accepted": {"all": accepted},
        "refused": {"all": "absent"},
        "outcome": "capture-without-semantic-expectation",
    }
    if probe.get("expected") != expected:
        raise ValueError("sentinel outcome-neutral expectation drift")
    if (
        plan.get("ownedScope") != root
        or plan.get("ownedScopes") != [scope]
        or plan.get("ownedResources") != resources
        or plan.get("documents") != docs
    ):
        raise ValueError("sentinel owned resource manifest drift")
    observation, recovery = plan.get("observation"), plan.get("recovery")
    if not isinstance(observation, list) or len(observation) != 41:
        raise ValueError("sentinel observation schedule drift")
    if not isinstance(recovery, list) or len(recovery) != 60:
        raise ValueError("sentinel recovery schedule drift")
    expected_observation = [
        _op(
            "preflight-typed-absence",
            "GET",
            "/v1/" + resource,
            RAW_16MIB_OVER_LABEL,
            {"status": 404, "typed": "NOT_FOUND", "owned": False},
            resource,
        )
        for resource in resources
    ]
    expected_observation.append(
        _op(
            "conditional-create-commit",
            "POST",
            endpoint,
            RAW_16MIB_OVER_LABEL,
            expected,
            body=body,
        )
    )
    expected_observation.extend(
        _op(
            "probe-readback",
            "GET",
            "/v1/" + resource,
            RAW_16MIB_OVER_LABEL,
            {
                "accepted": expected["accepted"],
                "refused": expected["refused"],
                "sameProbe": True,
            },
            resource,
        )
        for resource in resources
    )
    expected_recovery = []
    for resource in resources:
        expected_recovery.extend(
            [
                _op(
                    "cleanup-ownership-read",
                    "GET",
                    "/v1/" + resource,
                    RAW_16MIB_OVER_LABEL,
                    {"statuses": [200, 404], "owned": True, "versionRequired": True},
                    resource,
                ),
                {
                    **_op(
                        "cleanup-version-bound-delete",
                        "DELETE",
                        "/v1/" + resource,
                        RAW_16MIB_OVER_LABEL,
                        {"status": 200, "owned": True, "versionBound": True},
                        resource,
                    ),
                    "versionFrom": "cleanup-ownership-read",
                },
                _op(
                    "cleanup-verify-absence",
                    "GET",
                    "/v1/" + resource,
                    RAW_16MIB_OVER_LABEL,
                    {"status": 404, "typed": "NOT_FOUND"},
                    resource,
                ),
            ]
        )
    if observation != expected_observation or recovery != expected_recovery:
        raise ValueError("sentinel observation or recovery operation drift")
    schedule = [
        *({"phase": "observation", "index": index} for index in range(41)),
        *({"phase": "recovery", "index": index} for index in range(60)),
    ]
    if plan.get("executionSchedule") != schedule:
        raise ValueError("sentinel execution schedule drift")
    bounds = {
        "probeCount": 1,
        "maxInFlight": 1,
        "requestBytes": RAW_16MIB_OVER_BYTES,
        "distinctDocumentCount": 20,
        "peakLiveDocumentCount": 20,
        "observationRequests": 41,
        "recoveryRequests": 60,
        "totalRequestBound": 101,
        "responseByteCap": 2 * 1024 * 1024,
    }
    if plan.get("bounds") != bounds:
        raise ValueError("sentinel request bounds drift")


def validate_request_bytes_plan(plan: dict[str, Any]) -> None:
    """Independently check endpoint, scopes, ownership, bytes, and schedule."""
    fixed_contract = {
        "schemaVersion": 3,
        "campaignId": CAMPAIGN,
        "catalogId": CAMPAIGN,
        "catalogMaximum": CATALOG_MAXIMUM,
        "protocol": "REST",
        "metric": "REST raw HTTP body UTF-8 bytes",
        "metricStatus": "observation hypothesis",
        "unicodeNormalization": "none",
        "gRPCScope": "separate case required",
    }
    if any(
        compact_utf8(plan.get(key)) != compact_utf8(value)
        for key, value in fixed_contract.items()
    ):
        raise ValueError("unsupported metric contract")
    project, database, nonce = (
        plan.get("project"),
        plan.get("database"),
        plan.get("nonce"),
    )
    _validate_target(project, database, nonce)
    root = f"projects/{project}/databases/{database}/documents/oracle/{nonce}/request-bytes-01"
    probes = plan.get("probes")
    if (
        not isinstance(probes, list)
        or len(probes) != 3
        or [p.get("label") for p in probes] != list(PROBES)
    ):
        raise ValueError("probe count or labels drift")
    endpoint = f"/v1/projects/{project}/databases/{database}/documents:commit"
    all_resources = []
    expected_documents = {}
    for probe, target in zip(probes, REQUEST_TARGETS):
        scope = (
            root
            + {"under": "/probe-u01", "exact": "/probe-e01", "over": "/probe-o01"}[
                probe["label"]
            ]
        )
        resources = probe.get("resources")
        if (
            probe.get("scope") != scope
            or not isinstance(resources, list)
            or len(resources) != DOCUMENT_COUNT
            or len(set(resources)) != DOCUMENT_COUNT
        ):
            raise ValueError("probe scope or resource count drift")
        if any(
            not isinstance(r, str)
            or not r.startswith(scope + "/")
            or r.count("/") != scope.count("/") + 2
            for r in resources
        ):
            raise ValueError("probe resource scope drift")
        if set(resources) & set(all_resources):
            raise ValueError("probe resources are not disjoint")
        expected_resources = [scope + "/items/control"] + [
            scope + f"/items/payload-{i:02d}" for i in range(16)
        ]
        if resources != expected_resources:
            raise ValueError("document identities drift")
        all_resources.extend(resources)
        if probe.get("path") != endpoint:
            raise ValueError("commit endpoint drift")
        if not isinstance(probe.get("body"), dict) or set(probe["body"]) != {"writes"}:
            raise ValueError("commit body must contain only writes")
        writes = probe["body"]["writes"]
        if not isinstance(writes, list) or len(writes) != DOCUMENT_COUNT:
            raise ValueError("commit payload shape drift")
        names = []
        for write in writes:
            if (
                set(write) != {"update", "currentDocument"}
                or not isinstance(write["currentDocument"], dict)
                or set(write["currentDocument"]) != {"exists"}
                or write["currentDocument"]["exists"] is not False
            ):
                raise ValueError("missing exists-false ownership precondition")
            update = write["update"]
            if (
                set(update) != {"name", "fields"}
                or update["name"] not in resources
                or update["name"] in names
            ):
                raise ValueError("owned resource or duplicate drift")
            names.append(update["name"])
            fields = update["fields"]
            if (
                set(fields) != {"_owner", "blob"}
                or fields["_owner"] != {"stringValue": nonce}
                or not isinstance(fields["blob"].get("stringValue"), str)
            ):
                raise ValueError("payload owner or field shape drift")
            logical = document_size_bytes(update["name"], fields)
            expected_documents[update["name"]] = {
                "resource": update["name"],
                "fieldsSha256": logical_fields_digest(fields),
                "logicalBytes": logical,
            }
            if logical >= DOCUMENT_SAFETY_MARGIN:
                raise ValueError("document safety margin exceeded")
        if (
            names != resources
            or len(compact_utf8(probe["body"])) != target
            or probe.get("bodyBytes") != target
        ):
            raise ValueError("payload identity or byte length drift")
        expected = {
            "prior": "all-absent",
            "accepted": {
                "all": [
                    {
                        "name": w["update"]["name"],
                        "fieldsSha256": logical_fields_digest(w["update"]["fields"]),
                    }
                    for w in writes
                ]
            },
            "refused": {"all": "absent"},
        }
        if probe.get("expected") != expected:
            raise ValueError("per-probe expected state drift")
    if plan.get("documents") != expected_documents:
        raise ValueError("document manifest drift")
    if (
        plan.get("ownedScope") != root
        or plan.get("ownedResources") != all_resources
        or plan.get("ownedScopes") != [p["scope"] for p in probes]
    ):
        raise ValueError("owned resource manifest drift")
    observation, recovery = plan.get("observation"), plan.get("recovery")
    if (
        not isinstance(observation, list)
        or not isinstance(recovery, list)
        or len(observation) != 105
        or len(recovery) != 153
    ):
        raise ValueError("complete schedule or operation count drift")
    for index, probe in enumerate(probes):
        rows = observation[index * 35 : (index + 1) * 35]
        if (
            [r["kind"] for r in rows[:17]] != ["preflight-typed-absence"] * 17
            or rows[17]["kind"] != "conditional-create-commit"
            or [r["resource"] for r in rows[18:]] != probe["resources"]
            or any(r.get("probe") != probe["label"] for r in rows)
        ):
            raise ValueError("observation schedule drift")
        rows = recovery[index * 51 : (index + 1) * 51]
        expected_kinds = [
            k
            for _ in range(17)
            for k in (
                "cleanup-ownership-read",
                "cleanup-version-bound-delete",
                "cleanup-verify-absence",
            )
        ]
        if (
            [r["kind"] for r in rows] != expected_kinds
            or [r["resource"] for r in rows[::3]] != probe["resources"]
            or any(
                r.get("probe") != probe["label"]
                or r["resource"] not in probe["resources"]
                for r in rows
            )
            or any(
                r["kind"] == "cleanup-version-bound-delete"
                and r.get("versionFrom") != "cleanup-ownership-read"
                for r in rows
            )
        ):
            raise ValueError("cleanup schedule or foreign target drift")
    # Validate actual wire tuples, independently of the compiler's operation helper.
    for probe_index, probe in enumerate(probes):
        obs = observation[probe_index * 35 : (probe_index + 1) * 35]
        rec = recovery[probe_index * 51 : (probe_index + 1) * 51]
        for index, row in enumerate(obs):
            if index == 17:
                method, path, body, resource = "POST", endpoint, probe["body"], None
                expectation = probe["expected"]
                kind = "conditional-create-commit"
            else:
                resource = probe["resources"][index if index < 17 else index - 18]
                method, path, body = "GET", "/v1/" + resource, None
                kind = "preflight-typed-absence" if index < 17 else "probe-readback"
                expectation = (
                    {"status": 404, "typed": "NOT_FOUND", "owned": False}
                    if index < 17
                    else {
                        "accepted": probe["expected"]["accepted"],
                        "refused": probe["expected"]["refused"],
                        "sameProbe": True,
                    }
                )
            expected_row = {
                "kind": kind,
                "service": "firestore",
                "method": method,
                "path": path,
                "body": body,
                "privileged": True,
                "form": False,
                "probe": probe["label"],
                "expect": expectation,
            }
            if resource is not None:
                expected_row["resource"] = resource
            if json.dumps(row, sort_keys=True, allow_nan=False) != json.dumps(
                expected_row, sort_keys=True, allow_nan=False
            ):
                raise ValueError("actual observation wire drift")
        for index, row in enumerate(rec):
            resource = probe["resources"][index // 3]
            stage = index % 3
            expected_row = {
                "kind": (
                    "cleanup-ownership-read",
                    "cleanup-version-bound-delete",
                    "cleanup-verify-absence",
                )[stage],
                "service": "firestore",
                "method": "DELETE" if stage == 1 else "GET",
                "path": "/v1/" + resource,
                "body": None,
                "privileged": True,
                "form": False,
                "probe": probe["label"],
                "resource": resource,
                "expect": (
                    {"statuses": [200, 404], "owned": True, "versionRequired": True},
                    {"status": 200, "owned": True, "versionBound": True},
                    {"status": 404, "typed": "NOT_FOUND"},
                )[stage],
            }
            if stage == 1:
                expected_row["versionFrom"] = "cleanup-ownership-read"
            if json.dumps(row, sort_keys=True, allow_nan=False) != json.dumps(
                expected_row, sort_keys=True, allow_nan=False
            ):
                raise ValueError("actual cleanup wire drift")
    expected_schedule = []
    for probe_index in range(3):
        expected_schedule.extend(
            {"phase": "observation", "index": i}
            for i in range(probe_index * 35, (probe_index + 1) * 35)
        )
        expected_schedule.extend(
            {"phase": "recovery", "index": i}
            for i in range(probe_index * 51, (probe_index + 1) * 51)
        )
    if (
        plan.get("executionSchedule") != expected_schedule
        or plan.get("probeTransition")
        != "complete typed cleanup required before next probe"
    ):
        raise ValueError("cleanup-before-next-probe schedule required")
    if plan.get("ownershipRequirements") != [
        "preflight typed absence",
        "every Commit write has currentDocument.exists=false",
        "successful conditional-creation proof required before cleanup",
        "version-bound conditional cleanup",
    ]:
        raise ValueError("ownership contract drift")
    if plan.get("readbackRequirements") != [
        "accepted probe compares every document with its own expected snapshot",
        "refused probe requires every document absent",
        "mixed publication is indeterminate",
    ]:
        raise ValueError("readback contract drift")
    if plan.get("claims") != [
        "REST-only",
        "does not claim gRPC coverage",
        "does not claim document, depth, transform, or operation-count limits",
    ]:
        raise ValueError("evidence claim drift")
    if plan.get("bounds") != {
        "probeCount": 3,
        "maxInFlight": 1,
        "requestBytes": max(REQUEST_TARGETS),
        "distinctDocumentCount": 51,
        "peakLiveDocumentCount": 17,
        "observationRequests": 105,
        "recoveryRequests": 153,
        "totalRequestBound": 258,
        "responseByteCap": 2 * 1024 * 1024,
    }:
        raise ValueError("bounds drift")
