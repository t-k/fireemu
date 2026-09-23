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
    assert len(ids) == len(set(ids)) == 24
    assert len(corpus["streamRecipes"]) == 3
    assert {recipe["id"] for recipe in corpus["streamRecipes"]} == {
        "writes/write-stream-transaction",
        "writes/write-stream-terminal/trailing-metadata",
        "writes/write-stream-terminal/half-close",
    }
    closure = json.loads(
        (ROOT / "spec/compatibility/closure/FS-DATA-WRITE.json").read_text()
    )
    for condition in closure["conditions"]:
        if (
            condition["conditionId"].startswith("FS-DATA-WRITE/final-")
            or condition["conditionId"] == "FS-DATA-WRITE/closure-review"
        ):
            continue
        for recipe in condition["recipeIds"]:
            assert (
                recipe in ids
                or any(candidate.startswith(recipe + "/") for candidate in ids)
                or recipe in {item["id"] for item in corpus["streamRecipes"]}
            ), recipe
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
