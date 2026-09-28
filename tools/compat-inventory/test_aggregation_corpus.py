"""The reviewed aggregation slice has fixed partitions and typed expectations."""

from aggregation_corpus import corpus, query_body


def test_corpus_covers_the_reviewed_partitions_without_mutating_templates():
    value = corpus()
    assert value["revision"] == 2
    assert len(value["queries"]) == 12
    assert len({q["id"] for q in value["queries"]}) == 12
    assert value["fixtures"]["B"] == {}
    assert value["fixtures"]["C"]["x"] == {"stringValue": "not-a-number"}
    assert value["fixtures"]["D"]["x"] == {"doubleValue": 20.5}
    multiple = next(q for q in value["queries"] if q["id"] == "multiple-fields")
    assert multiple["expected"] == {
        "count": {"integerValue": "2"},
        "sum": {"integerValue": "10"},
        "avg": {"doubleValue": 60},
    }
    first = query_body(value["queries"][0], "first")
    assert first["structuredAggregationQuery"]["structuredQuery"]["from"] == [
        {"collectionId": "first"}
    ]
    first["structuredAggregationQuery"]["aggregations"].clear()
    assert query_body(corpus()["queries"][0], "second")["structuredAggregationQuery"][
        "aggregations"
    ]


def test_ordering_revision_preserves_independent_discriminating_controls():
    cases = {case["id"]: case for case in corpus()["queries"]}
    assert cases["missing-before-limit"]["expected"] == {
        "count": {"integerValue": "2"},
        "sum": {"doubleValue": 30.5},
    }
    for name, direction, offset, limit, count, total in [
        ("explicit-x-asc", "ASCENDING", None, 2, "2", {"doubleValue": 30.5}),
        ("explicit-x-desc", "DESCENDING", None, 2, "2", {"doubleValue": 20.5}),
        ("explicit-x-offset", "ASCENDING", 2, 1, "1", {"integerValue": "0"}),
    ]:
        case = cases[name]
        assert case["query"] == {
            "orderBy": [{"field": {"fieldPath": "x"}, "direction": direction}],
            "limit": limit,
            **({"offset": offset} if offset is not None else {}),
        }
        assert case["expected"] == {"count": {"integerValue": count}, "sum": total}
    rejected = cases["explicit-name-rejected"]
    assert rejected["query"] == {
        "orderBy": [{"field": {"fieldPath": "__name__"}, "direction": "ASCENDING"}],
        "limit": 2,
    }
    assert rejected["expectedError"] == {
        "httpStatus": 400,
        "status": "INVALID_ARGUMENT",
    }
    assert "expected" not in rejected
