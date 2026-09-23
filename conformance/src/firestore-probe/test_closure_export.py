"""The bundled sandbox corpus names every REST closure recipe before recording."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

MODULE = Path(__file__).with_name("closure_export.py")
ROOT = Path(__file__).resolve().parents[3]


def _corpus() -> dict:
    spec = importlib.util.spec_from_file_location("closure_export", MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.build_corpus()


def test_sandbox_corpus_covers_the_frozen_closure_recipes() -> None:
    corpus = _corpus()
    programs = corpus["restPrograms"]
    ids = [program["id"] for program in programs]
    assert len(ids) == len(set(ids)) == 69
    assert {
        "writes/limits/field-path-mask/1499",
        "writes/limits/field-path-mask/1500",
        "writes/limits/implied-array-key/1494",
        "writes/limits/implied-array-key/1495",
        "writes/limits/index-entry-sum/500-19999",
        "writes/limits/index-entry-sum/500-20000",
        "writes/limits/index-entry-string-name/2600",
        "writes/limits/empty-document-name/5000",
        "writes/batch-write-malformed/two-fields-bad-integer",
        "writes/limits/aggregate-map/strict-only",
        "writes/limits/non-commit-rest-request-bytes/batch-write/10485760",
        "writes/limits/non-commit-rest-request-bytes/batch-write/10485761",
        "writes/limits/non-commit-rest-request-bytes/batch-get/10485760",
        "writes/limits/non-commit-rest-request-bytes/batch-get/10485761",
        "writes/limits/non-commit-rest-request-bytes/run-query/10485760",
        "writes/limits/non-commit-rest-request-bytes/run-query/10485761",
        "writes/limits/non-commit-rest-request-bytes/create/10485760",
        "writes/limits/non-commit-rest-request-bytes/create/10485761",
        "writes/limits/non-commit-rest-request-bytes/patch/10485760",
        "writes/limits/non-commit-rest-request-bytes/patch/10485761",
    }.issubset(ids)
    assert len(corpus["streamRecipes"]) == 6
    assert {recipe["id"] for recipe in corpus["streamRecipes"]} == {
        "writes/write-stream-transaction",
        "writes/write-stream-terminal/trailing-metadata",
        "writes/write-stream-terminal/half-close",
        "writes/write-stream-terminal/response-before-half-close",
        "writes/limits/grpc-unary-request-bytes/10485760",
        "writes/limits/grpc-unary-request-bytes/10485761",
    }
    recipes = {recipe["id"]: recipe for recipe in corpus["streamRecipes"]}
    assert recipes["writes/write-stream-transaction"] == {
        "id": "writes/write-stream-transaction",
        "transport": "saved-reference",
        "source": "spec/compatibility/broad-runs/fs-write-txn-dee737c14-production-result.json",
    }
    assert recipes["writes/write-stream-terminal/trailing-metadata"] == {
        "id": "writes/write-stream-terminal/trailing-metadata",
        "transport": "grpc",
        "action": "invalid-empty-write-after-handshake",
        "maxFrames": 2,
    }
    assert recipes["writes/write-stream-terminal/half-close"] == {
        "id": "writes/write-stream-terminal/half-close",
        "transport": "grpc",
        "action": "half-close-after-handshake",
        "maxFrames": 1,
    }
    assert recipes["writes/write-stream-terminal/response-before-half-close"] == {
        "id": "writes/write-stream-terminal/response-before-half-close",
        "transport": "grpc",
        "action": "empty-write-response-before-half-close",
        "maxFrames": 2,
    }
    closure = json.loads(
        (ROOT / "spec/compatibility/closure/FS-DATA-WRITE.json").read_text()
    )
    for condition in closure["conditions"]:
        if (
            condition["conditionId"].startswith("FS-DATA-WRITE/final-")
            or condition["conditionId"] == "FS-DATA-WRITE/closure-review"
            or condition["status"] == "PENDING_CORPUS"
        ):
            continue
        for recipe in condition["recipeIds"]:
            assert (
                recipe in ids
                or any(candidate.startswith(recipe + "/") for candidate in ids)
                or recipe in {item["id"] for item in corpus["streamRecipes"]}
            ), recipe
    mapped = [
        recipe
        for condition in closure["conditions"]
        if condition["conditionId"]
        not in {
            "FS-DATA-WRITE/final-artifact-regression",
            "FS-DATA-WRITE/closure-review",
        }
        for recipe in condition["recipeIds"]
    ]
    assert all(
        any(
            program_id == recipe or program_id.startswith(recipe + "/")
            for recipe in mapped
        )
        for program_id in ids
    ), "every sandbox REST program needs a direct closure condition"
    assert corpus["restRequestCount"] == sum(len(p["steps"]) for p in programs)
    assert corpus["restRequestCount"] < 400


def test_collection_id_syntax_is_sent_in_fixed_sandbox_project() -> None:
    corpus = _corpus()
    programs = {program["id"]: program for program in corpus["restPrograms"]}
    for suffix in ("slash", "dot", "dot-dot", "reserved"):
        program = programs[f"writes/limits/collection-id-{suffix}"]
        assert program["steps"][0]["method"] == "POST"
        assert program["steps"][0]["path"].startswith(
            "/v1/projects/fireemu-oracle-sbx/databases/(default)/documents"
        )
