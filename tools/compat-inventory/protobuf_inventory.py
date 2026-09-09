# /// script
# dependencies = ["protobuf>=5,<7"]
# ///
"""Enumerate the pinned, vendored Firestore protobuf API using protoc descriptors."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from google.protobuf.descriptor_pb2 import FileDescriptorSet


def surfaces(descriptor: FileDescriptorSet) -> list[dict]:
    found = []

    def add(locator: str, kind: str) -> None:
        found.append(
            {
                "locator": locator,
                "kind": kind,
                "transport": "gRPC",
                "classification": "unknown",
                "requirements": [],
            }
        )

    def enum(value, prefix: str) -> None:
        name = f"{prefix}.{value.name}"
        add(name, "enum")
        for member in value.value:
            add(f"{name}.{member.name}", "enum-value")

    def message(value, prefix: str) -> None:
        name = f"{prefix}.{value.name}"
        add(name, "message")
        for field in value.field:
            add(f"{name}.{field.name}", "field")
        for oneof in value.oneof_decl:
            add(f"{name}.{oneof.name}", "oneof")
        for child in value.nested_type:
            message(child, name)
        for child in value.enum_type:
            enum(child, name)

    for file in descriptor.file:
        if not file.name.startswith("google/firestore/v1/"):
            continue
        for service in file.service:
            for method in service.method:
                name = f"{file.package}.{service.name}.{method.name}"
                add(name, "method")
                for role in ["input", "output"]:
                    found.append(
                        {
                            "locator": f"{name}/{role}",
                            "kind": "request" if role == "input" else "response",
                            "type": getattr(method, f"{role}_type"),
                            "streaming": method.client_streaming
                            if role == "input"
                            else method.server_streaming,
                            "transport": "gRPC",
                            "classification": "unknown",
                            "requirements": [],
                        }
                    )
        for child in file.message_type:
            message(child, file.package)
        for child in file.enum_type:
            enum(child, file.package)
    return sorted(found, key=lambda row: (row["locator"], row["kind"]))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path("crates/fireemu-proto-firestore/proto")
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("refusing to overwrite a recorded protobuf inventory")
    files = sorted(args.root.glob("google/firestore/v1/*.proto"))
    with tempfile.TemporaryDirectory(prefix="fireemu-proto-inventory-") as directory:
        binary = Path(directory) / "descriptor.bin"
        subprocess.run(
            [
                "protoc",
                f"-I{args.root}",
                "--include_imports",
                f"--descriptor_set_out={binary}",
                *[str(p.relative_to(args.root)) for p in files],
            ],
            check=True,
        )
        raw = binary.read_bytes()
    descriptor = FileDescriptorSet()
    descriptor.ParseFromString(raw)
    result = {
        "schemaVersion": 1,
        "upstreamCommit": (args.root / "UPSTREAM_COMMIT").read_text().strip(),
        "descriptorSha256": hashlib.sha256(raw).hexdigest(),
        "sources": [
            {"path": str(p), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
            for p in sorted(args.root.rglob("*.proto"))
        ],
        "surfaces": surfaces(descriptor),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as destination:
        json.dump(result, destination, indent=2)
        destination.write("\n")
    print(
        f"protobuf: {len(result['surfaces'])} structural items from {len(files)} Firestore files"
    )


if __name__ == "__main__":
    main()
