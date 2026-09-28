"""Generate the immutable, bounded Firestore v1 gRPC denominator companion."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SOURCE_FILE = Path(__file__).resolve()
SOURCE_PATH = "spec/compatibility/upstream/firestore-protobuf.json"
OUTPUT_PATH = "spec/compatibility/denominators/firestore-v1-grpc-2026-09-16.v2.json"
GENERATOR_PATH = "tools/compat-inventory/protobuf_denominator.py"
VERSION = "firestore-v1-grpc-2026-09-16.v2"
PINNED_SOURCE_SHA256 = (
    "0e4a9f8bbc8cf782f73fb3266960cd9ff09f8267d4614fbba997d107f29f0fd9"
)
PINNED_UPSTREAM_COMMIT = "1f38da6aa7661cf22e17247ad33d2d566a2c356e"
PINNED_DESCRIPTOR_SHA256 = (
    "3fa4e3045827c76244e478059dc9f75b1c73ba60612f1921527eec98da1f0fe0"
)
GOAL = "IP-FS-PRODUCTION-COMPATIBILITY"
PARENT_DENOMINATORS = [
    {
        "path": "spec/compatibility/denominators/ip-fs-standard-2026-09-14.v1.json",
        "version": "ip-fs-standard-2026-09-14.v1",
        "sha256": "189b614707fd0cbf7090146679c14a9d27184340cecf67d934c3ffe7fdca038b",
    },
    {
        "path": "spec/compatibility/denominators/ip-fs-standard-2026-09-14.v2.json",
        "version": "ip-fs-standard-2026-09-14.v2",
        "sha256": "22d9aa2f3ff3172a0e0f0f4cabfa49ba5304175806f5c15bc3a02fba1e95b5fe",
    },
]
EXCLUSION_IDS = (
    "enterprise-pipeline",
    "enterprise-full-text",
    "mongodb-compatibility",
    "datastore-mode",
)


class ValidationError(ValueError):
    """Raised when a denominator input or generated value is inconsistent."""


def _pinned_file(root: Path, relative: str, label: str) -> Path:
    """Resolve a repository input while rejecting symlinked path components."""
    relative_path = Path(relative)
    if relative_path.is_absolute() or any(
        part in ("", ".", "..") for part in relative_path.parts
    ):
        raise ValidationError(f"{label} path is not a safe repository path")
    candidate = root
    parts = relative_path.parts
    for index, part in enumerate(parts):
        candidate /= part
        try:
            if candidate.is_symlink():
                raise ValidationError(f"{label} path contains a symlink: {relative}")
            if index == len(parts) - 1 and not candidate.is_file():
                raise ValidationError(f"{label} is not a regular file: {relative}")
        except OSError as exc:
            raise ValidationError(f"{label} cannot be inspected: {relative}") from exc
    return candidate


def _generator_bytes() -> bytes:
    if SOURCE_FILE.is_symlink() or not SOURCE_FILE.is_file():
        raise ValidationError("generator is not a regular file")
    try:
        return SOURCE_FILE.read_bytes()
    except OSError as exc:
        raise ValidationError("generator cannot be read") from exc


def pipeline_surface(locator: str) -> bool:
    return (
        locator.startswith(
            (
                "google.firestore.v1.Firestore.ExecutePipeline",
                "google.firestore.v1.ExecutePipeline",
                "google.firestore.v1.Pipeline",
                "google.firestore.v1.StructuredPipeline",
            )
        )
        or locator == "google.firestore.v1.Value.pipeline_value"
    )


def _validate_source(source: dict[str, Any]) -> list[dict[str, Any]]:
    if source.get("schemaVersion") != 1:
        raise ValidationError("protobuf source schema must be 1")
    surfaces = source.get("surfaces")
    if not isinstance(surfaces, list) or not surfaces:
        raise ValidationError("protobuf source surfaces must be nonempty")
    keys: set[tuple[str, str]] = set()
    for surface in surfaces:
        if not isinstance(surface, dict):
            raise ValidationError("protobuf source surface must be an object")
        locator = surface.get("locator")
        kind = surface.get("kind")
        if not isinstance(locator, str) or not locator or not isinstance(kind, str):
            raise ValidationError("protobuf source surface requires locator and kind")
        key = (locator, kind)
        if key in keys:
            raise ValidationError(
                f"duplicate protobuf source surface: {locator}/{kind}"
            )
        keys.add(key)
    return surfaces


def _exclusion_row(exclusion_id: str, surface_ids: list[str]) -> dict[str, Any]:
    details = {
        "enterprise-pipeline": (
            "enterprise-only",
            "gRPC",
            "Enterprise Pipeline structural surfaces are outside the Standard/Native target.",
            "Pinned Firestore v1 descriptors expose these rows, but this companion does not attest Enterprise execution.",
        ),
        "enterprise-full-text": (
            "enterprise-only",
            "gRPC",
            "Enterprise full-text search is outside the Standard/Native target.",
            "Full-text search has no pinned Firestore v1 protobuf structural rows in this source.",
        ),
        "mongodb-compatibility": (
            "enterprise-only",
            "MongoDB",
            "MongoDB-compatible Firestore surfaces are outside the Standard/Native target.",
            "MongoDB wire APIs and drivers are not represented by Firestore v1 protobuf descriptors.",
        ),
        "datastore-mode": (
            "outside-goal",
            "gRPC",
            "Datastore mode is outside the declared Firestore Native target.",
            "Datastore mode is an explicit product boundary and has no distinct Firestore v1 protobuf rows here.",
        ),
    }
    scope, transport, reason, detail = details[exclusion_id]
    return {
        "id": exclusion_id,
        "scope": scope,
        "transport": transport,
        "status": "excluded",
        "surfaceIds": surface_ids,
        "surfaceCount": len(surface_ids),
        "reason": reason,
        "detail": detail,
    }


def build(
    source: dict[str, Any],
    *,
    source_path: str,
    source_sha256: str,
    generator_sha256: str,
) -> dict[str, Any]:
    source_surfaces = _validate_source(source)
    surfaces: list[dict[str, Any]] = []
    exclusion_ids: dict[str, list[str]] = {key: [] for key in EXCLUSION_IDS}
    for source_surface in source_surfaces:
        locator = source_surface["locator"]
        kind = source_surface["kind"]
        surface_id = f"firestore-protobuf:{kind}:gRPC:{locator}"
        excluded = pipeline_surface(locator)
        exclusion_id = "enterprise-pipeline" if excluded else None
        if exclusion_id is not None:
            exclusion_ids[exclusion_id].append(surface_id)
        surfaces.append(
            {
                **source_surface,
                "id": surface_id,
                "definition": "firestore-protobuf",
                "scope": "enterprise-only" if excluded else "target",
                "scopeReason": (
                    "Enterprise Pipeline structural surface outside the Standard/Native target."
                    if excluded
                    else "Firestore Standard/Native gRPC structural surface; behavior remains unverified."
                ),
                "featureGroup": (
                    "FS-ENTERPRISE-PIPELINE-EXCLUDED"
                    if excluded
                    else "FS-GRPC-STRUCTURAL"
                ),
                "evidenceState": "waiting-oracle",
                "receiptRefs": [],
            }
        )
    surfaces.sort(key=lambda row: row["id"])
    exclusions = [
        _exclusion_row(exclusion_id, sorted(exclusion_ids[exclusion_id]))
        for exclusion_id in EXCLUSION_IDS
    ]
    excluded_surface_count = sum(len(ids) for ids in exclusion_ids.values())
    return {
        "schemaVersion": 1,
        "goal": GOAL,
        "denominatorVersion": VERSION,
        "source": {
            "path": source_path,
            "sha256": source_sha256,
            "upstreamCommit": source["upstreamCommit"],
            "descriptorSha256": source["descriptorSha256"],
            "surfaceCount": len(source_surfaces),
        },
        "companionTo": PARENT_DENOMINATORS,
        "generator": {
            "path": GENERATOR_PATH,
            "sha256": generator_sha256,
        },
        "surfaces": surfaces,
        "exclusions": exclusions,
        "coverageDebt": [
            {
                "id": "firestore-sdk-inventory",
                "bounded": True,
                "status": "debt",
                "scope": "Firestore SDK/platform combinations",
                "surfaceCount": 0,
                "reason": "Pinned protobuf descriptors do not enumerate SDK packages or platform transports.",
                "nextAction": "Inventory pinned SDK package/platform combinations and bind each to a separate source snapshot.",
            }
        ],
        "summary": {
            "surfaceCount": len(surfaces),
            "targetCount": len(surfaces) - excluded_surface_count,
            "excludedSurfaceCount": excluded_surface_count,
            "excludedBy": {
                exclusion_id: len(exclusion_ids[exclusion_id])
                for exclusion_id in EXCLUSION_IDS
            },
        },
    }


def validate(value: dict[str, Any], source: dict[str, Any], source_sha256: str) -> None:
    if value.get("schemaVersion") != 1 or value.get("denominatorVersion") != VERSION:
        raise ValidationError("unsupported protobuf denominator version")
    if source_sha256 != PINNED_SOURCE_SHA256:
        raise ValidationError("protobuf source is not the pinned snapshot")
    source_file = _pinned_file(ROOT, SOURCE_PATH, "protobuf source")
    actual_source_sha256 = hashlib.sha256(source_file.read_bytes()).hexdigest()
    if source_sha256 != actual_source_sha256:
        raise ValidationError("protobuf source digest does not match source file")
    if source.get("upstreamCommit") != PINNED_UPSTREAM_COMMIT:
        raise ValidationError("protobuf upstream commit is not pinned")
    if source.get("descriptorSha256") != PINNED_DESCRIPTOR_SHA256:
        raise ValidationError("protobuf descriptor digest is not pinned")
    source_meta = value.get("source")
    if not isinstance(source_meta, dict) or source_meta.get("path") != SOURCE_PATH:
        raise ValidationError("protobuf source path is not pinned")
    if source_meta.get("sha256") != source_sha256:
        raise ValidationError("source digest does not match pinned protobuf input")
    generator = value.get("generator")
    if not isinstance(generator, dict) or generator.get("path") != GENERATOR_PATH:
        raise ValidationError("generator path is not pinned")
    generator_sha256 = generator.get("sha256") if isinstance(generator, dict) else None
    if not isinstance(generator_sha256, str) or len(generator_sha256) != 64:
        raise ValidationError("generator digest is missing")
    actual_generator_sha256 = hashlib.sha256(_generator_bytes()).hexdigest()
    if generator_sha256 != actual_generator_sha256:
        raise ValidationError("generator digest does not match checked-in generator")
    companions = value.get("companionTo")
    if companions != PARENT_DENOMINATORS:
        raise ValidationError(
            "companion denominator anchors do not match pinned values"
        )
    for anchor in PARENT_DENOMINATORS:
        try:
            parent_path = _pinned_file(ROOT, anchor["path"], "companion denominator")
            actual_parent_sha256 = hashlib.sha256(parent_path.read_bytes()).hexdigest()
        except ValidationError as exc:
            raise ValidationError(str(exc)) from exc
        if actual_parent_sha256 != anchor["sha256"]:
            raise ValidationError(f"companion denominator changed: {anchor['path']}")
    expected = build(
        source,
        source_path=SOURCE_PATH,
        source_sha256=source_sha256,
        generator_sha256=generator_sha256,
    )
    for key in ("source", "surfaces", "exclusions", "coverageDebt", "summary"):
        if value.get(key) != expected[key]:
            if key == "surfaces":
                raise ValidationError(
                    "surface scope classification does not match source"
                )
            raise ValidationError(f"{key} does not match source-derived denominator")
    if value.get("companionTo") != PARENT_DENOMINATORS:
        raise ValidationError("companion denominator anchors do not match")


def serialized(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def write_immutable(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("immutable denominator output must not be a symlink")
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o644,
        )
    except FileExistsError:
        if path.is_symlink():
            raise ValueError("immutable denominator output must not be a symlink")
        if path.read_text() == contents:
            return
        raise ValueError(
            "immutable denominator version already exists; bump VERSION and output path"
        )
    with os.fdopen(descriptor, "w") as stream:
        stream.write(contents)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--source", default=SOURCE_PATH)
    parser.add_argument("--output", default=OUTPUT_PATH)
    parser.add_argument(
        "--check", action="store_true", help="validate the checked-in companion"
    )
    args = parser.parse_args()
    output_path = args.root / args.output
    source_file = _pinned_file(args.root, args.source, "protobuf source")
    source_bytes = source_file.read_bytes()
    source = json.loads(source_bytes)
    source_sha256 = hashlib.sha256(source_bytes).hexdigest()
    if args.check:
        value = json.loads(output_path.read_text())
        validate(value, source, source_sha256)
        print("protobuf denominator: valid")
        return
    generator_sha256 = hashlib.sha256(_generator_bytes()).hexdigest()
    value = build(
        source,
        source_path=args.source,
        source_sha256=source_sha256,
        generator_sha256=generator_sha256,
    )
    write_immutable(output_path, serialized(value))
    print(
        f"protobuf denominator: {value['summary']['surfaceCount']} surfaces, "
        f"{value['summary']['targetCount']} targets, "
        f"{value['summary']['excludedSurfaceCount']} excluded"
    )


if __name__ == "__main__":
    main()
