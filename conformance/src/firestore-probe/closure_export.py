"""Assemble the bounded FS-DATA-WRITE sandbox corpus without network access."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from limits03_export import build_programs as limits03_programs
from request_bytes_export import build_programs as request_byte_programs
from sandbox_expansion import build_programs as sandbox_expansion_programs

PROJECT = "fireemu-oracle-sbx"
DOCS = f"projects/{PROJECT}/databases/(default)/documents"
COMMIT = f"/v1/{DOCS}:commit"
BATCH_GET = f"/v1/{DOCS}:batchGet"
WEBCHANNEL_PATH = "/google.firestore.v1.Firestore/Write/channel?database=projects%2Ffireemu-oracle-sbx%2Fdatabases%2F(default)&VER=8&RID=1&SID=missing-fireemu-byte-probe&AID=0"


def _invalid_collection_program(suffix: str, collection_id: str) -> dict[str, Any]:
    resource = f"{DOCS}/{collection_id}/x"
    if suffix == "slash":
        # Keep the encoded slash in the REST collectionId path parameter.
        first = {
            "id": "create-invalid",
            "method": "POST",
            "path": f"/v1/{DOCS}/bad%2Finside?documentId=x",
            "body": {"fields": {"v": {"integerValue": "1"}}},
        }
    else:
        first = {
            "id": "commit-invalid",
            "method": "POST",
            "path": COMMIT,
            "body": {
                "writes": [
                    {
                        "update": {
                            "name": resource,
                            "fields": {"v": {"integerValue": "1"}},
                        },
                        "currentDocument": {"exists": False},
                    }
                ]
            },
        }
    steps = [
        first,
        {
            "id": "readback",
            "method": "POST",
            "path": BATCH_GET,
            "body": {"documents": [resource]},
        },
    ]
    return {
        "id": f"writes/limits/collection-id-{suffix}",
        "area": "writes",
        "steps": steps,
    }


def build_corpus() -> dict[str, Any]:
    expansion = sandbox_expansion_programs()
    index_sum_id = "writes/limits/index-entry-sum/adjacent"
    index_sum_programs = [
        program for program in expansion if program["id"] == index_sum_id
    ]
    if len(index_sum_programs) != 1:
        raise ValueError("one adjacent index-sum program is required")
    programs = [
        *limits03_programs(),
        *request_byte_programs(),
        *(program for program in expansion if program["id"] != index_sum_id),
        _invalid_collection_program("slash", "bad/inside"),
        _invalid_collection_program("dot", "."),
        _invalid_collection_program("dot-dot", ".."),
        _invalid_collection_program("reserved", "__reserved__"),
        *(
            {
                "id": f"writes/limits/webchannel-request-bytes/{size}",
                "area": "writes",
                "steps": [
                    {
                        "id": "unknown-session",
                        "method": "POST",
                        "path": WEBCHANNEL_PATH,
                        "webchannelBodyBytes": size,
                    }
                ],
            }
            for size in (10_485_760, 10_485_761)
        ),
        *index_sum_programs,
    ]
    stream_recipes = [
        {
            "id": "writes/write-stream-transaction",
            "transport": "saved-reference",
            "source": "spec/compatibility/broad-runs/fs-write-txn-dee737c14-production-result.json",
        },
        {
            "id": "writes/write-stream-terminal/trailing-metadata",
            "transport": "grpc",
            "action": "invalid-empty-write-after-handshake",
            "maxFrames": 2,
        },
        {
            "id": "writes/write-stream-terminal/half-close",
            "transport": "grpc",
            "action": "half-close-after-handshake",
            "maxFrames": 1,
        },
        {
            "id": "writes/write-stream-terminal/response-before-half-close",
            "transport": "grpc",
            "action": "empty-write-response-before-half-close",
            "maxFrames": 2,
        },
        *(
            {
                "id": f"writes/limits/grpc-unary-request-bytes/{size}",
                "transport": "grpc",
                "action": "get-document-transaction-bytes",
                "wireBytes": size,
                "maxFrames": 1,
            }
            for size in (10_485_760, 10_485_761)
        ),
        *(
            {
                "id": f"writes/limits/grpc-stream-request-bytes/{size}",
                "transport": "grpc",
                "action": "write-stream-token-bytes",
                "wireBytes": size,
                "maxFrames": 1,
            }
            for size in (10_485_760, 10_485_761)
        ),
    ]
    ids = [program["id"] for program in programs]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate FS-DATA-WRITE program ID")
    for program in programs:
        for step in program["steps"]:
            if not (
                step["path"].startswith(f"/v1/{DOCS}")
                or step["path"] == WEBCHANNEL_PATH
            ):
                raise ValueError("program escaped the sandbox project")
    return {
        "schemaVersion": 1,
        "restPrograms": programs,
        "streamRecipes": stream_recipes,
        "restRequestCount": sum(len(program["steps"]) for program in programs),
    }


def build_delta_corpus() -> dict[str, Any]:
    """Return only the pending DELETE-boundary and response-before-half-close probes."""
    corpus = build_corpus()
    delete_prefix = "writes/limits/near-limit-delete-refusal/"
    delete_ids = {
        f"{delete_prefix}{route}/{count}"
        for route in ("rest", "commit", "batch-write")
        for count in (12112, 12113)
    }
    programs = [
        program for program in corpus["restPrograms"] if program["id"] in delete_ids
    ]
    if {program["id"] for program in programs} != delete_ids or len(programs) != 6:
        raise ValueError("delta-v3 requires the exact six route-specific DELETE recipes")
    stream_id = "writes/write-stream-terminal/response-before-half-close"
    streams = [recipe for recipe in corpus["streamRecipes"] if recipe["id"] == stream_id]
    if len(streams) != 1 or streams[0]["transport"] != "grpc" or streams[0]["maxFrames"] != 2:
        raise ValueError("delta-v3 requires the single response-before-half-close stream recipe")
    return {
        "schemaVersion": 1,
        "sourceCorpusSha256": hashlib.sha256(
            json.dumps(corpus, separators=(",", ":")).encode()
        ).hexdigest(),
        "restPrograms": programs,
        "streamRecipes": streams,
        "restRequestCount": sum(len(program["steps"]) for program in programs),
    }


if __name__ == "__main__":
    json.dump(build_corpus(), sys.stdout, separators=(",", ":"))
