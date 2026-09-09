"""The reviewed aggregation slice has fixed partitions and typed expectations."""

from aggregation_corpus import corpus, query_body


def test_corpus_covers_the_reviewed_partitions_without_mutating_templates():
    value = corpus()
    assert len(value["queries"]) == 8
    assert len({q["id"] for q in value["queries"]}) == 8
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
