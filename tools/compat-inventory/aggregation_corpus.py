"""Fixed, bounded Standard/Native REST aggregation expectations; never learned from runs."""

from copy import deepcopy

SCOPE = {
    "feature": "FS-AGGREGATIONS",
    "edition": "STANDARD",
    "apiMode": "FIRESTORE_NATIVE",
    "transport": "REST",
    "profile": "strict",
    "rules": "admin-bypass",
}
CONFIG = {
    "schemaVersion": 1,
    "profile": "strict",
    "limits": {
        "catalog": "firestore-standard-2026-08-25",
        "queryCatalog": "firestore-standard-query-2026-08-25",
        "rulesCatalog": "firebase-rules-2026-08-25",
    },
    "firestore": {
        "edition": "standard",
        "apiMode": "native",
        "indexFile": "indexes.json",
    },
    "rules": {"executionMode": "admin-bypass"},
}


def corpus() -> dict:
    count = {"alias": "count", "count": {}}
    total = {"alias": "sum", "sum": {"field": {"fieldPath": "x"}}}
    avg = {"alias": "avg", "avg": {"field": {"fieldPath": "x"}}}
    queries = [
        ("count-alone", [count], {}, {"count": {"integerValue": "4"}}),
        (
            "count-sum",
            [count, total],
            {},
            {"count": {"integerValue": "3"}, "sum": {"doubleValue": 30.5}},
        ),
        (
            "count-average",
            [count, avg],
            {},
            {"count": {"integerValue": "3"}, "avg": {"doubleValue": 15.25}},
        ),
        (
            "sum-average",
            [total, avg],
            {},
            {"sum": {"doubleValue": 30.5}, "avg": {"doubleValue": 15.25}},
        ),
        (
            "multiple-fields",
            [count, total, {"alias": "avg", "avg": {"field": {"fieldPath": "y"}}}],
            {},
            {
                "count": {"integerValue": "2"},
                "sum": {"integerValue": "10"},
                "avg": {"doubleValue": 60},
            },
        ),
        (
            "empty-result",
            [count, total, avg],
            {
                "where": {
                    "fieldFilter": {
                        "field": {"fieldPath": "x"},
                        "op": "GREATER_THAN",
                        "value": {"integerValue": "1000"},
                    }
                }
            },
            {
                "count": {"integerValue": "0"},
                "sum": {"integerValue": "0"},
                "avg": {"nullValue": None},
            },
        ),
        (
            "missing-before-limit",
            [count, total],
            {"limit": 2},
            {"count": {"integerValue": "2"}, "sum": {"doubleValue": 30.5}},
        ),
        (
            "bounded-count",
            [{"alias": "count", "count": {"upTo": "2"}}],
            {},
            {"count": {"integerValue": "2"}},
        ),
    ]
    for name, direction, offset, limit, selected, summed in [
        ("explicit-x-asc", "ASCENDING", None, 2, "2", {"doubleValue": 30.5}),
        ("explicit-x-desc", "DESCENDING", None, 2, "2", {"doubleValue": 20.5}),
        ("explicit-x-offset", "ASCENDING", 2, 1, "1", {"integerValue": "0"}),
    ]:
        queries.append(
            (
                name,
                [count, total],
                {
                    "orderBy": [{"field": {"fieldPath": "x"}, "direction": direction}],
                    "limit": limit,
                    **({"offset": offset} if offset is not None else {}),
                },
                {"count": {"integerValue": selected}, "sum": summed},
            )
        )
    return deepcopy(
        {
            "schemaVersion": 2,
            "revision": 2,
            "scope": SCOPE,
            "fixtures": {
                "A": {"x": {"integerValue": "10"}, "y": {"integerValue": "100"}},
                "B": {},
                "C": {
                    "x": {"stringValue": "not-a-number"},
                    "y": {"integerValue": "20"},
                },
                "D": {"x": {"doubleValue": 20.5}},
            },
            "queries": [
                {"id": name, "aggregations": aggs, "query": query, "expected": expected}
                for name, aggs, query, expected in queries
            ]
            + [
                {
                    "id": "explicit-name-rejected",
                    "aggregations": [count, total],
                    "query": {
                        "orderBy": [
                            {
                                "field": {"fieldPath": "__name__"},
                                "direction": "ASCENDING",
                            }
                        ],
                        "limit": 2,
                    },
                    "expectedError": {"httpStatus": 400, "status": "INVALID_ARGUMENT"},
                }
            ],
            "stateCases": ["refused-commit", "unchanged-state"],
            "limitations": [
                "REST only; no SDK, gRPC, Rules authorization, transactions, Enterprise or MongoDB attestation.",
                "Finite fixtures, not all numeric precision, null/NaN, cursor/index or scheduling combinations.",
            ],
        }
    )


def query_body(case: dict, collection: str) -> dict:
    return deepcopy(
        {
            "structuredAggregationQuery": {
                "structuredQuery": {
                    "from": [{"collectionId": collection}],
                    **case["query"],
                },
                "aggregations": case["aggregations"],
            }
        }
    )


def index_definition() -> dict:
    return {
        "queryScope": "COLLECTION",
        "fields": [
            {"fieldPath": name, "order": "ASCENDING"} for name in ["x", "y", "__name__"]
        ],
    }
