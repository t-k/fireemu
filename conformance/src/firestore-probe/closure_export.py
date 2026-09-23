"""Assemble the bounded FS-DATA-WRITE sandbox corpus without network access."""

from __future__ import annotations

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
    programs = [
        *limits03_programs(),
        *request_byte_programs(),
        *sandbox_expansion_programs(),
        _invalid_collection_program("slash", "bad/inside"),
        _invalid_collection_program("dot", "."),
        _invalid_collection_program("dot-dot", ".."),
        _invalid_collection_program("reserved", "__reserved__"),
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
            if not step["path"].startswith(f"/v1/{DOCS}"):
                raise ValueError("program escaped the sandbox project")
    return {
        "schemaVersion": 1,
        "restPrograms": programs,
        "streamRecipes": stream_recipes,
        "restRequestCount": sum(len(program["steps"]) for program in programs),
    }


if __name__ == "__main__":
    json.dump(build_corpus(), sys.stdout, separators=(",", ":"))
