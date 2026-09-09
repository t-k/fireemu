"""Offline, fail-closed validation and projection of one bounded evidence bundle."""

import gzip
import io
import json
import math
import re
from datetime import UTC, date, datetime

from aggregation_corpus import CONFIG, SCOPE, corpus, index_definition, query_body
from aggregation_index import owned_index, resolved_operation
from capture import extract_page
from evidence_common import (
    ROOT,
    fingerprint,
    probe_inputs,
    read,
    require,
    runtime_inputs,
    sha,
)
from owned_runner import local_addresses, validate_build
from probe import DATABASE, NUMBER, PROJECT, owned_name, summarize_aggregation

DIRECTORY = ROOT / "spec/compatibility/evidence/aggregation"
PAGE = ROOT / "docs/compatibility/aggregation-evidence.md"
URL = "https://firebase.google.com/docs/firestore/query-data/aggregation-queries"
LOCATORS = [
    "use_the_count_aggregation",
    "use_the_sum_aggregation",
    "use_the_average_aggregation",
    "calculate_multiple_aggregations_in_a_query",
    "limitations",
]
OBLIGATIONS = [
    {
        "id": "AGG-COUNT",
        "locator": LOCATORS[0],
        "condition": "Count alone includes all four query documents.",
        "cases": ["count-alone", "bounded-count"],
    },
    {
        "id": "AGG-NUMERIC",
        "locator": LOCATORS[4],
        "condition": "Sum and average ignore strings; count still includes present nonnumeric fields.",
        "cases": ["count-sum", "count-average", "sum-average"],
    },
    {
        "id": "AGG-INTERSECTION",
        "locator": LOCATORS[4],
        "condition": "Multiple fields use the intersection of field existence, with a composite index.",
        "cases": ["multiple-fields"],
    },
    {
        "id": "AGG-BOUNDARY",
        "locator": LOCATORS[4],
        "condition": "Derived boundary controls: empty results and missing fields before a limit.",
        "cases": ["empty-result", "missing-before-limit"],
    },
    {
        "id": "AGG-STATE",
        "locator": LOCATORS[3],
        "condition": "Harness control, not a claim from this section: refused Commit leaves all fixture documents unchanged.",
        "cases": ["refused-commit", "unchanged-state"],
    },
]


def case_ids() -> list[str]:
    return [c["id"] for c in corpus()["queries"]] + corpus()["stateCases"]


def approved_cases(
    approvals: list, subject: str, eligible: set[str] | None = None
) -> set[str]:
    eligible = set(case_ids()) if eligible is None else eligible
    accepted = set()
    for approval in approvals:
        require(
            set(approval)
            == {"subjectSha256", "cases", "reviewer", "reviewedAt", "decision"},
            "unknown approval fields",
        )
        require(
            approval["decision"] == "approve" and approval["subjectSha256"] == subject,
            "stale approval subject",
        )
        require(
            isinstance(approval["reviewer"], str)
            and bool(approval["reviewer"].strip()),
            "approval requires a named reviewer",
        )
        require(
            date.fromisoformat(approval["reviewedAt"]) <= datetime.now(UTC).date(),
            "future approval",
        )
        cases = approval["cases"]
        require(
            isinstance(cases, list)
            and bool(cases)
            and len(cases) == len(set(cases))
            and set(cases) <= set(case_ids()),
            "approval scope exceeds corpus",
        )
        require(not accepted.intersection(cases), "duplicate approval scope")
        require(set(cases) <= eligible, "mismatched case cannot be approved")
        accepted.update(cases)
    return accepted


def validate_aggregate_fields(fields: dict, case: dict) -> None:
    require(
        set(fields) == set(case["expected"]), "missing or unexpected aggregate alias"
    )
    for alias, value in fields.items():
        require(
            isinstance(value, dict) and len(value) == 1, "invalid aggregate Value oneof"
        )
        kind, scalar = next(iter(value.items()))
        allowed = {
            "count": {"integerValue"},
            "sum": {"integerValue", "doubleValue"},
            "avg": {"doubleValue", "nullValue"},
        }[alias]
        require(kind in allowed, "invalid aggregate scalar type")
        if kind == "integerValue":
            require(
                isinstance(scalar, str)
                and re.fullmatch(r"-?(0|[1-9][0-9]*)", scalar) is not None,
                "invalid integer encoding",
            )
            require(-(2**63) <= int(scalar) < 2**63, "integer out of range")
        elif kind == "doubleValue":
            require(
                type(scalar) in [int, float] and math.isfinite(scalar),
                "invalid finite double",
            )
        else:
            require(scalar is None, "invalid null encoding")


def validate_query_cases(rows: list, collection: str) -> set[str]:
    matched = set()
    require(
        [r["id"] for r in rows] == [c["id"] for c in corpus()["queries"]],
        "query case set/order changed",
    )
    for row, case in zip(rows, corpus()["queries"], strict=True):
        require(
            row["request"] == query_body(case, collection) and row["httpStatus"] == 200,
            "query request/status mismatch",
        )
        fields = summarize_aggregation(row["rawResponse"])
        validate_aggregate_fields(fields, case)
        passed = fields == case["expected"]
        require(
            row["passed"] is passed, "recorded verdict contradicts the raw response"
        )
        if passed:
            matched.add(case["id"])
    return matched


def validate_document(document: dict) -> None:
    require(
        set(document) == {"name", "fields", "createTime", "updateTime"},
        "incomplete document snapshot",
    )
    for key in ["createTime", "updateTime"]:
        timestamp = document[key]
        require(
            isinstance(timestamp, str)
            and re.fullmatch(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})",
                timestamp,
            )
            is not None,
            "invalid document timestamp",
        )
        require(
            datetime.fromisoformat(timestamp).utcoffset() is not None, "naive timestamp"
        )


def validate_receipt(value: dict, target: str) -> set[str]:
    require(
        value["schemaVersion"] == 2
        and value["acceptance"] == "candidate"
        and value["status"] in ["passed", "failed"]
        and value["target"] == target
        and value["scope"] == SCOPE
        and value["project"] == PROJECT,
        "receipt scope/status mismatch",
    )
    require(
        not any(
            k in value for k in ["failure", "cleanupFailure", "childCleanupFailure"]
        ),
        "receipt contains failure",
    )
    require(
        value["probeSource"]["files"] == probe_inputs()
        and value["corpusSha256"] == fingerprint(corpus()),
        "stale probe/corpus",
    )
    collection = value["collection"]
    names = [owned_name(collection, key) for key in corpus()["fixtures"]]
    require(
        value["attemptedResources"] == names and value["ownedResources"] == names,
        "fixture ownership mismatch",
    )
    require([r["id"] for r in value["cases"]] == case_ids(), "missing/duplicate cases")
    matched = validate_query_cases(value["cases"][:8], collection)
    require(
        value["status"] == ("passed" if len(matched) == 8 else "failed"),
        "summary verdict contradicts cases",
    )
    marker = value["ownershipMarker"]
    require(
        re.fullmatch(r"[a-f0-9]{32}", marker) is not None, "invalid ownership marker"
    )
    before = value["stateBefore"]
    require(
        set(before) == set(names) and before == value["stateAfter"],
        "fixture state changed",
    )
    for key, fields in corpus()["fixtures"].items():
        name = owned_name(collection, key)
        validate_document(before[name])
        require(
            before[name]["name"] == name
            and before[name]["fields"]
            == {**fields, "__fireemuOracleOwner": {"stringValue": marker}},
            "wrong fixture input",
        )
    refused = value["cases"][8]
    expected_writes = {
        "writes": [
            {"update": {"name": names[0], "fields": {"x": {"integerValue": "99"}}}},
            {
                "update": {"name": names[3], "fields": {}},
                "currentDocument": {"exists": False},
            },
        ]
    }
    require(
        refused["request"] == expected_writes
        and refused["httpStatus"] == 409
        and refused["rawResponse"]["error"]["status"] == "ALREADY_EXISTS"
        and refused["passed"] is True
        and value["cases"][9]["passed"] is True,
        "refusal/state control failed",
    )
    cleanup = value["cleanup"]
    require(
        [r["name"] for r in cleanup] == names
        and all(
            r["deleted"] is True and r["confirmedMissing"] is True and "error" not in r
            for r in cleanup
        ),
        "cleanup incomplete",
    )
    if target == "production":
        require(
            value["connection"] == "production"
            and value["verifiedProjectNumber"] == NUMBER,
            "wrong production identity",
        )
        require(
            value["database"]["name"] == DATABASE
            and value["database"]["type"] == "FIRESTORE_NATIVE"
            and value["database"]["databaseEdition"] == "STANDARD",
            "wrong production database",
        )
        index = value["index"]
        require(
            re.fullmatch(
                re.escape(DATABASE) + r"/operations/[A-Za-z0-9_-]+", index["operation"]
            )
            is not None,
            "operation belongs to another database",
        )
        require(
            index["operationReadback"].get("response", {}).get("name")
            == index["ready"]["name"],
            "operation result is not the measured index",
        )
        require(
            index["collection"] == collection
            and index["baselineEmpty"] is True
            and index["createAttempted"] is True
            and index["definition"] == index_definition()
            and resolved_operation(index["operationReadback"], index["operation"])
            and "error" not in index["operationReadback"]
            and owned_index(index["ready"], collection)
            and index["ready"]["state"] == "READY"
            and index["deletedNames"] == [index["ready"]["name"]]
            and index["confirmedMissing"] is True
            and "cleanupError" not in index,
            "index ownership/cleanup incomplete",
        )
        require(
            not any(k in value for k in ["artifact", "runtimeSource", "build"]),
            "production inherited a local identity",
        )
    else:
        validate_owned(value)
    return matched | set(corpus()["stateCases"])


def validate_owned(value: dict) -> None:
    require(
        value["connection"] == "owned-artifact",
        "external daemon cannot attest an artifact",
    )
    instance, process, config = (
        value["instance"],
        value["ownedProcess"],
        value["configuration"],
    )
    require(
        all(
            type(instance[key]) is int and instance[key] > 1
            for key in ["childPid", "parentPid"]
        )
        and instance["childPid"] != instance["parentPid"],
        "invalid process identities",
    )
    firestore_origin = instance["firestoreOrigin"]
    require(
        isinstance(firestore_origin, str) and firestore_origin.startswith("http://"),
        "invalid firestore origin",
    )
    local_addresses(
        firestore_origin.removeprefix("http://"), instance["controlOrigin"] + "/v1/"
    )
    require(
        process["launch"]
        == {
            "command": "exec",
            "project": PROJECT,
            "only": "firestore",
            "ports": "OS-assigned",
            "configurationSha256": fingerprint(CONFIG),
        },
        "contradictory launch receipt",
    )
    artifact = value["artifact"]
    require(
        artifact["kind"] == "local-binary"
        and artifact["platform"] in ["linux", "darwin", "win32"]
        and isinstance(artifact["version"], str)
        and bool(artifact["version"])
        and isinstance(artifact["python"], str)
        and bool(artifact["python"]),
        "missing artifact metadata",
    )
    require(
        isinstance(artifact["sha256"], str)
        and re.fullmatch(r"[a-f0-9]{64}", artifact["sha256"]) is not None,
        "malformed artifact digest",
    )
    for key, data in [("fileSha256", CONFIG), ("indexFileSha256", config["indexes"])]:
        require(
            config[key]
            == sha((json.dumps(data, indent=2, allow_nan=False) + "\n").encode()),
            "configuration file digest mismatch",
        )
    require(
        config["basis"]
        == "owned immutable launch inputs plus runtime profile readback",
        "unknown configuration basis",
    )
    require(
        isinstance(value["build"]["rustc"], str)
        and value["build"]["rustc"].startswith("rustc "),
        "missing compiler identity",
    )
    require(
        instance["parentPid"] == process["pid"]
        and instance["nonce"] == value["collection"].removeprefix("compat_")
        and instance["project"] == PROJECT
        and instance["authorizedStatus"] == 200
        and instance["wrongTokenStatus"] == 403
        and instance["profile"] == "strict"
        and instance["version"] == value["artifact"]["version"],
        "instance proof mismatch",
    )
    require(
        process["exitCode"] == 0
        and process["stopped"] is True
        and process["listenersClosed"] is True,
        "owned process not stopped",
    )
    require(
        config["value"] == CONFIG
        and config["sha256"] == fingerprint(CONFIG)
        and config["effectiveProfile"] == "strict"
        and config["indexes"]
        == {
            "indexes": [{"collectionGroup": value["collection"], **index_definition()}],
            "fieldOverrides": [],
        },
        "launch configuration mismatch",
    )
    require(
        value["runtimeSource"]["files"] == runtime_inputs(ROOT)
        and value["runtimeSource"]["relationship"] == "built-by-recorder",
        "unbound runtime source",
    )
    validate_build(
        value["build"], value["artifact"]["sha256"], value["runtimeSource"]["files"]
    )


def validate_bundle(directory=DIRECTORY) -> tuple[dict, set[str], str]:
    index = json.loads(read(directory, "index.json"))
    require(
        index["schemaVersion"] == 1 and index["scope"] == SCOPE,
        "bundle schema/scope mismatch",
    )
    require(
        set(index["files"])
        == {
            "source.html.gz",
            "source-review.json",
            "corpus.json",
            "local.json",
            "production.json",
        },
        "bundle file set mismatch",
    )
    files = {}
    for name, expected in index["files"].items():
        raw = read(directory, name)
        require(sha(raw) == expected, "bundle artifact hash changed")
        files[name] = raw
    with gzip.GzipFile(fileobj=io.BytesIO(files["source.html.gz"])) as compressed:
        raw_source = compressed.read(2 * 1024 * 1024 + 1)
    require(len(raw_source) <= 2 * 1024 * 1024, "source decompression exceeds budget")
    extracted = extract_page(raw_source.decode())
    review = json.loads(files["source-review.json"])
    require(
        review["url"] == URL
        and review["rawSha256"] == sha(raw_source)
        and review["bodySha256"] == sha(extracted["text"].encode())
        and review["extractor"] == extracted["extractor"]
        and review["extractorSha256"] == probe_inputs()["capture.py"],
        "source/extractor binding changed",
    )
    require(
        review["locators"] == LOCATORS
        and set(LOCATORS) <= set(extracted["sections"])
        and review["obligations"] == OBLIGATIONS
        and review["reviewer"]
        and review["extent"] == "selected-sections-only",
        "source review scope changed",
    )
    require(
        date.fromisoformat(review["reviewedAt"]) <= datetime.now(UTC).date(),
        "future source review",
    )
    requirements = json.loads(
        (ROOT / "verification/requirements/requirements.json").read_bytes()
    )
    require(
        review["parentRequirement"] == "REQ-FS-PARITY-01"
        and any(
            r["id"] == review["parentRequirement"] for r in requirements["requirements"]
        ),
        "unknown parent requirement",
    )
    require(json.loads(files["corpus.json"]) == corpus(), "corpus changed")
    eligible = set(case_ids())
    for target in ["local", "production"]:
        eligible &= validate_receipt(json.loads(files[f"{target}.json"]), target)
    subject = fingerprint({"scope": index["scope"], "files": index["files"]})
    return index, approved_cases(index["approvals"], subject, eligible), subject


def render() -> str:
    _index, accepted, subject = validate_bundle()
    matches = {
        target: {
            row["id"]
            for row in json.loads(read(DIRECTORY, f"{target}.json"))["cases"]
            if row["passed"]
        }
        for target in ["local", "production"]
    }
    eligible = matches["local"] & matches["production"]
    prefix = "../../spec/compatibility/evidence/aggregation/"
    lines = [
        "# Bounded compound-aggregation evidence",
        "",
        "Generated by `tools/compat-inventory/aggregation_evidence.py`; do not edit.",
        "",
        "This is a finite Standard/Native REST, strict-profile, admin-bypass slice. It does not attest the entire aggregation feature, SDK/gRPC support, Rules authorization or all numeric/index/scheduling cases.",
        "",
        f"[Source review]({prefix}source-review.json) covers five selected section locators, not the whole official page. The original acquisition snapshot remains unchanged. The reviewer authored source interpretations; this is separate from approval of execution evidence.",
        "",
        f"[Local owned artifact]({prefix}local.json): {len(matches['local'])}/10 expectations match. [Fresh production observation]({prefix}production.json): {len(matches['production'])}/10 match. Both completed all 10 cases and cleanup checks. Well-formed mismatches remain visible and cannot be approved; malformed or incomplete evidence is rejected. Matching candidates still require explicit approval.",
        "",
        f"Approval subject: `{subject}`. Approved cases: {len(accepted)}/10. [Approval record]({prefix}index.json).",
        "",
        "| Obligation / parent REQ-FS-PARITY-01 | Condition | Cases | Approval |",
        "| --- | --- | --- | --- |",
    ]
    for obligation in OBLIGATIONS:
        status = (
            "Mismatch: not eligible"
            if not set(obligation["cases"]) <= eligible
            else "Approved for these cases only"
            if set(obligation["cases"]) <= accepted
            else "Pending human review"
        )
        lines.append(
            f"| {obligation['id']} | {obligation['condition']} | {', '.join(obligation['cases'])} | {status} |"
        )
    lines += [
        "",
        "## Case comparison",
        "",
        "| Case | Local vs fixed expectation | Production vs fixed expectation |",
        "| --- | --- | --- |",
    ]
    for case in case_ids():
        lines.append(
            f"| {case} | {'Matches' if case in matches['local'] else 'Mismatch'} | {'Matches' if case in matches['production'] else 'Mismatch'} |"
        )
    lines += [
        "",
        "## Approval procedure",
        "",
        "Review the pinned source, corpus, complete raw responses, build/configuration/process identities and cleanup. Only then add a named, dated approval with the exact subject digest and reviewed case IDs to index.json. Re-run the offline publisher. Any changed bound input invalidates approval; no automatic promotion is implemented.",
        "",
        "The receipt records recorder-invoked Cargo build inputs and the copied artifact hash, not a reproducible-build guarantee or signed supply-chain attestation. Process ownership and control-token checks prevent accidental daemon mixups, not malicious artifacts. The effective profile is read back; full effective configuration is not exposed by the runtime.",
        "",
        "The official source capsule preserves Google documentation and attribution (CC BY 4.0; code samples Apache 2.0). It is included to reproduce body extraction offline, not to claim review of every sample or section.",
        "",
    ]
    return "\n".join(lines)


def check_or_write(write: bool) -> None:
    generated = render()
    if write:
        PAGE.write_text(generated)
    else:
        require(
            PAGE.read_text() == generated, "generated aggregation evidence page drift"
        )
