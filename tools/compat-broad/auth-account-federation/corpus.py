"""Offline typed inputs for Auth account/federation native tests, never a cloud runner.

Expected results encode the bounded local contract. They are not production observations,
but the query rows follow what the Identity Platform sandbox answered on 2026-09-23
(conformance/auth-account-production.json): only the first expression is evaluated, and an
empty selector is no constraint.
The checked-in JSON is consumed by native handler tests; Python tests alone cannot pass
native acceptance. No tokens, credentials, permissions, or network entrypoints are accepted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
OUTPUT = ROOT / "spec/compatibility/auth-account-federation-local-v1.json"


def build() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []

    def add(label: str, request: dict[str, Any], ids: list[str] | None, *, status: int = 200, count: int | None = None) -> None:
        rows.append({"id": label, "request": request, "expected": {
            "status": status, "ids": ids, "count": str(len(ids) if count is None and ids is not None else count) if status == 200 else None,
        }})

    add("unfiltered", {}, ["a", "b", "c", "d"])
    add("null-expression", {"expression": None}, ["a", "b", "c", "d"])
    add("empty-expression", {"expression": []}, ["a", "b", "c", "d"])
    for label, predicate, ids in [
        ("email-case", {"email": "A@EXAMPLE.COM"}, ["a"]),
        ("phone", {"phoneNumber": "+15550000002"}, ["b"]),
        ("uid", {"userId": "c"}, ["c"]),
        ("email-precedes-phone-and-uid", {"email": "a@example.com", "phoneNumber": "+15550000002", "userId": "c"}, ["a"]),
        ("phone-precedes-uid", {"email": None, "phoneNumber": "+15550000002", "userId": "c"}, ["b"]),
        ("empty-email-falls-through", {"email": "", "userId": "a"}, ["a"]),
        ("wildcards-are-literal", {"email": "%@example.com"}, []),
        ("prefix-not-claimed", {"email": "a@"}, []),
        ("uid-case-sensitive", {"userId": "A"}, []),
        ("phone-exact", {"phoneNumber": "15550000002"}, []),
    ]:
        add(label, {"expression": [predicate]}, ids)
    group = [{"userId": "a"}, {"email": "a@example.com"}, {"userId": "c"}, {"userId": "d"}]
    add("only-the-first-expression", {"expression": group}, ["a"])
    add("filter-sort-page-asc", {"expression": group, "sortBy": "NAME", "offset": 0, "limit": 2}, ["a"])
    add("filter-sort-page-desc", {"expression": group, "sortBy": "NAME", "order": "DESC", "offset": 1, "limit": 2}, [])
    add("filtered-count", {"expression": group, "returnUserInfo": False}, None, count=1)
    add("empty-count", {"expression": [{"userId": "none"}], "returnUserInfo": False}, None, count=0)
    add("zero-limit", {"expression": group, "limit": 0}, [])
    add("max-offset", {"expression": group, "offset": "9223372036854775807"}, [])
    for label, expression in [
        ("object-array", {}), ("sql-string", "SELECT *"), ("bool-array", False),
        ("null-item", [None]), ("list-item", [[]]),
        ("bool-selector", [{"email": True}]),
        ("number-selector", [{"userId": 1}]), ("object-selector", [{"phoneNumber": {}}]),
        ("unknown-selector", [{"name": "A"}]),
        ("malformed-lower-priority", [{"email": "a@example.com", "userId": False}]),
        ("unknown-lower-priority", [{"email": "a@example.com", "anything": None}]),
        ("control-character", [{"userId": "a\n"}]),
    ]:
        add(label, {"expression": expression}, None, status=400)
    add("empty-item-is-unconstrained", {"expression": [{}]}, ["a", "b", "c", "d"])
    # A JSON null is an unset proto field, so it is the same as an empty item.
    add("null-selector-is-unconstrained", {"expression": [{"userId": None}]}, ["a", "b", "c", "d"])
    add("later-empty-item-is-ignored", {"expression": [{"userId": "a"}, {}]}, ["a"])
    for label, expression, status in [
        ("predicate-count-exact", [{"userId": "a"}] * 128, 200),
        ("predicate-count-over", [{"userId": "a"}] * 129, 400),
        ("selector-bytes-exact", [{"userId": "x" * 4096}], 200),
        ("selector-bytes-over", [{"userId": "x" * 4097}], 400),
        ("selector-unicode-below", [{"userId": "あ" * 1365}], 200),
        ("selector-unicode-over", [{"userId": "あ" * 1366}], 400),
    ]:
        add(label, {"expression": expression}, ["a"] if label == "predicate-count-exact" else [], status=status)
    add("count-offset-refused", {"expression": group, "returnUserInfo": False, "offset": 1}, None, status=400)

    saml: list[dict[str, Any]] = []
    for label, name in [("empty", ""), ("boolean", False), ("integer", 1), ("array", []), ("object", {}), ("null", None), ("control", "bad\nname")]:
        saml.append({"id": "saml-name-" + label, "response": {"assertion": {"subject": {"nameId": name}}}, "status": 400})
    saml += [
        {"id": "saml-assertion-type", "response": {"assertion": False}, "status": 400},
        {"id": "saml-subject-type", "response": {"assertion": {"subject": 1}}, "status": 400},
        {"id": "saml-attributes-type", "response": {"assertion": {"subject": {"nameId": "person@example.test"}, "attributeStatements": []}}, "status": 400},
        {"id": "saml-valid-json-fixture", "response": {"assertion": {"subject": {"nameId": "person@example.test"}}}, "status": 200},
    ]
    return {
        "schemaVersion": 1,
        "kind": "auth-account-federation-local-v1",
        "productionAllowed": False,
        "productionExecuted": False,
        "nativeExecuted": False,
        "account": {
            "policy": "local-exact-union-v1",
            "caveats": ["OR/exact matching are local policy; not verified production search semantics", "128 predicates and 4096 UTF-8 bytes are local parser bounds, not service quotas"],
            "fixture": [
                {"localId": "a", "email": "a@example.com", "displayName": "B"},
                {"localId": "b", "email": "b@example.com", "displayName": "A", "phoneNumber": "+15550000002"},
                {"localId": "c", "email": "z@example.com", "displayName": "Z"},
                {"localId": "d", "email": "d@example.com", "displayName": "C"},
            ],
            "cases": rows,
        },
        "federation": {
            "policy": "local-pending-token-v1",
            "localTtlSeconds": 300,
            "maxHandles": 256,
            "maxEntryBytes": 65536,
            "maxAggregateBytes": 1048576,
            "samlFixtureCases": saml,
            "nativeSequenceObligations": [
                "reusable-before-expiry-without-extension", "signed-assertion-expiry-rechecked", "namespace-and-reset-generation-bound",
                "never-cache-link-id-token", "different-validation-authorities-refused", "changed-pin-refused",
                "current-provider-config-rechecked", "current-blocking-hooks-applied", "snapshot-does-not-export-or-resurrect",
                "malformed-token-no-fallback", "no-live-eviction", "bounded-logical-bytes", "fixture-mode-explicit",
            ],
            "unimplemented": ["signed-XML-SAML", "redirect-authorization-code-exchange", "legacy-deprecated-pendingIdToken"],
        },
    }


def encode(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n").encode()


def validate(value: object) -> None:
    # Equality must preserve boolean/int and exact types, not Python's loose True == 1.
    if not isinstance(value, dict) or encode(value) != encode(build()):
        raise ValueError("local corpus drift or fabricated execution authority")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="check the fixed repository corpus")
    args = parser.parse_args(argv)
    payload = encode(build())
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_bytes() != payload:
            raise SystemExit("local corpus must be regenerated and reviewed")
        print(json.dumps({"sha256": hashlib.sha256(payload).hexdigest(), "nativeExecuted": False, "productionExecuted": False}))
    else:
        # Writes only the one new local corpus, not old observations/manifests/permissions.
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_bytes(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
