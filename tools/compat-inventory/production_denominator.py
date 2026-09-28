"""Generate the exact production-compatibility denominator from a pinned snapshot."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

GOAL = "IP-FS-PRODUCTION-COMPATIBILITY"
VERSION = "ip-fs-standard-2026-09-14.v1"
SOURCE_PATH = "spec/compatibility/upstream/2026-09-09-retry/discovery.json"
SOURCE_ANCHOR_SHA = "3cb2f548af450c737122b06df7f764b23cd7747e"
SOURCE_SHA256 = "eaa632da268ee815bd87ab0c657033368861475c66240a597b6b348b02dda256"
OUTPUT_PATH = "spec/compatibility/denominators/ip-fs-standard-2026-09-14.v1.json"
DOCUMENT_PATH = "docs/compatibility/production-denominator.md"


def enterprise_only(locator: str) -> bool:
    return locator.startswith(
        (
            "firestore.projects.databases.documents.executePipeline",
            "firestore.projects.databases.changeStreams.",
            "firestore.projects.databases.userCreds.",
            "schemas/ExecutePipeline",
            "schemas/Pipeline",
            "schemas/StructuredPipeline",
            "schemas/GoogleFirestoreAdminV1ChangeStream",
            "schemas/GoogleFirestoreAdminV1ListChangeStreams",
            "schemas/GoogleFirestoreAdminV1UserCreds",
            "schemas/GoogleFirestoreAdminV1ListUserCreds",
            "schemas/GoogleFirestoreAdminV1DisableUserCredsRequest",
            "schemas/GoogleFirestoreAdminV1EnableUserCredsRequest",
            "schemas/GoogleFirestoreAdminV1Search",
            "schemas/GoogleFirestoreAdminV1Database/properties/mongodbCompatibleDataAccessMode",
        )
    ) or locator in {
        "schemas/Value/properties/pipelineValue",
        "schemas/GoogleFirestoreAdminV1Index/properties/searchIndexOptions",
        "schemas/GoogleFirestoreAdminV1IndexField/properties/searchConfig",
        "schemas/GoogleFirestoreAdminV1Database/properties/databaseEdition/enum/ENTERPRISE",
        "schemas/GoogleFirestoreAdminV1Index/properties/apiScope/enum/MONGODB_COMPATIBLE_API",
    }


def datastore_only(locator: str) -> bool:
    return locator in {
        "schemas/GoogleFirestoreAdminV1Database/properties/type/enum/DATASTORE_MODE",
        "schemas/GoogleFirestoreAdminV1Index/properties/apiScope/enum/DATASTORE_MODE_API",
    }


def feature_group(definition: str, locator: str) -> str:
    lower = locator.lower()
    if definition == "securetoken-v1":
        return "AUTH-CREDENTIAL"
    if definition.startswith("identitytoolkit-"):
        if "mfa" in lower or "totp" in lower:
            return "AUTH-MFA"
        if any(
            marker in lower
            for marker in (
                "supportedidp",
                "saml",
                "oauthidp",
                "signinwithidp",
                "createauthuri",
                "gamecenter",
            )
        ):
            return "AUTH-FEDERATION"
        if "tenant" in lower:
            return "AUTH-TENANT"
        if "blocking" in lower:
            return "AUTH-BLOCKING"
        if any(marker in lower for marker in ("passwordpolicy", "recaptcha", "config")):
            return "AUTH-CONFIG"
        if any(
            marker in lower
            for marker in (
                "sendoobcode",
                "resetpassword",
                "emailaction",
                "email link",
                "email_link",
                "signinwithemaillink",
            )
        ):
            return "AUTH-ACTION"
        if any(
            marker in lower
            for marker in (
                "token",
                "sessioncookie",
                "publickeys",
                "signinwithpassword",
                "signinwithcustomtoken",
            )
        ):
            return "AUTH-CREDENTIAL"
        if any(marker in lower for marker in ("account", "user", "signup")):
            return "AUTH-ACCOUNT"
        return "AUTH-CROSS-CUTTING"
    if definition == "firestore-v1":
        if enterprise_only(locator):
            return "FS-ENTERPRISE-EXCLUDED"
        if datastore_only(locator):
            return "FS-DATASTORE-EXCLUDED"
        if any(
            marker in lower
            for marker in (
                "listen",
                "write/request",
                "write/response",
                "writestream",
                "targetchange",
                "documentchange",
                "documentdelete",
                "documentremove",
            )
        ):
            return "FS-LISTEN-SDK"
        if any(
            marker in lower
            for marker in (
                "transaction",
                "rollback",
                "begint",
                "readtime",
            )
        ):
            return "FS-TRANSACTION"
        if any(
            marker in lower
            for marker in (
                "query",
                "aggregation",
                "partition",
                "explain",
                "index",
                "filter",
                "cursor",
                "findnearest",
                "vector",
                "orderby",
            )
        ):
            return "FS-QUERY-INDEX"
        if locator.startswith("firestore.projects.databases.documents.") or any(
            marker in lower
            for marker in (
                "document",
                "write",
                "commit",
                "mask",
                "precondition",
                "transform",
            )
        ):
            return "FS-DATA-WRITE"
        if locator.startswith("firestore.projects.") or "googlefirestoreadmin" in lower:
            return "FS-CONFIG-LIFECYCLE"
        return "FS-CROSS-CUTTING"
    raise ValueError(f"unsupported pinned definition: {definition}")


def build(source: dict, source_path: str, source_sha256: str) -> dict:
    definitions = []
    targets = []
    for definition in source["definitions"]:
        definition_id = definition["id"]
        definitions.append(
            {
                "id": definition_id,
                "revision": definition["revision"],
                "sha256": definition["sha256"],
            }
        )
        for surface in definition["surfaces"]:
            locator = surface["locator"]
            kind = surface["kind"]
            transport = surface["transport"]
            excluded = definition_id == "firestore-v1" and enterprise_only(locator)
            outside_goal = definition_id == "firestore-v1" and datastore_only(locator)
            scope = (
                "enterprise-only"
                if excluded
                else ("outside-goal" if outside_goal else "target")
            )
            targets.append(
                {
                    "id": f"{definition_id}:{kind}:{transport}:{locator}",
                    "definition": definition_id,
                    "locator": locator,
                    "kind": kind,
                    "transport": transport,
                    "featureGroup": feature_group(definition_id, locator),
                    "scope": scope,
                    "scopeReason": (
                        "Firestore Enterprise-only Pipeline, change-stream, MongoDB credential or search surface"
                        if excluded
                        else (
                            "Datastore-mode API variant outside the declared Firestore Native target"
                            if outside_goal
                            else "Application-facing Identity Platform or Firestore Standard/Native target"
                        )
                    ),
                    "evidenceState": "waiting-oracle",
                    "receiptRefs": [],
                }
            )
    definitions.sort(key=lambda row: row["id"])
    targets.sort(key=lambda row: row["id"])
    return {
        "schemaVersion": 1,
        "goal": GOAL,
        "denominatorVersion": VERSION,
        "sourceSnapshot": source_path,
        "sourceSnapshotSha256": source_sha256,
        "parentDenominator": None,
        "definitions": definitions,
        "targets": targets,
    }


def serialized(value: dict) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def write_immutable(path: Path, contents: str) -> None:
    if path.exists():
        if path.read_text() == contents:
            return
        raise ValueError(
            "immutable denominator version already exists; bump VERSION and output path"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents)


def repository_path(
    root: Path, relative: str, *, allow_missing_leaf: bool = False
) -> Path:
    path = Path(relative)
    if (
        path.is_absolute()
        or not relative
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError(f"unsafe repository-relative path: {relative}")
    canonical_root = root.resolve(strict=True)
    candidate = canonical_root
    for index, part in enumerate(path.parts):
        candidate /= part
        final = index == len(path.parts) - 1
        if candidate.is_symlink():
            raise ValueError(f"symlink repository path is not accepted: {relative}")
        if not candidate.exists():
            if final and allow_missing_leaf:
                break
            raise ValueError(f"repository path does not exist: {relative}")
    if candidate.exists() and not candidate.resolve(strict=True).is_relative_to(
        canonical_root
    ):
        raise ValueError(f"repository path escapes root: {relative}")
    return candidate


def write_document(path: Path, contents: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o666)
    with os.fdopen(descriptor, "w") as output:
        output.write(contents)


def verify_source_digest(source_bytes: bytes) -> str:
    actual = hashlib.sha256(source_bytes).hexdigest()
    if actual != SOURCE_SHA256:
        raise ValueError("source snapshot does not match the immutable content SHA-256")
    return actual


def git_file(root: Path, ref: str, relative: str) -> bytes | None:
    if re.fullmatch(r"[0-9a-f]{40}", ref) is None:
        raise ValueError("git ref must be a full lowercase commit SHA")
    listing = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", ref, "--", relative],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    if relative not in listing:
        return None
    return subprocess.run(
        ["git", "show", f"{ref}:{relative}"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout


def verify_immutable_history(
    root: Path, base_ref: str, *, source_anchor: str = SOURCE_ANCHOR_SHA
) -> None:
    source = repository_path(root, SOURCE_PATH).read_bytes()
    anchored_source = git_file(root, source_anchor, SOURCE_PATH)
    if anchored_source is None or source != anchored_source:
        raise ValueError(
            f"published immutable input differs from source anchor {source_anchor}: {SOURCE_PATH}"
        )
    for relative in (SOURCE_PATH, OUTPUT_PATH):
        previous = git_file(root, base_ref, relative)
        if previous is None:
            continue
        current = repository_path(root, relative).read_bytes()
        if current != previous:
            raise ValueError(
                f"published immutable input differs from base {base_ref}: {relative}"
            )


def render(value: dict) -> str:
    targets = value["targets"]
    in_scope = [target for target in targets if target["scope"] == "target"]
    enterprise = [target for target in targets if target["scope"] == "enterprise-only"]
    outside = [target for target in targets if target["scope"] == "outside-goal"]
    groups: dict[str, dict[str, int]] = {}
    for target in targets:
        counts = groups.setdefault(
            target["featureGroup"],
            {"target": 0, "enterprise-only": 0, "outside-goal": 0},
        )
        counts[target["scope"]] += 1
    rows = "\n".join(
        f"| {group} | {counts['target']} | {counts['enterprise-only']} | {counts['outside-goal']} |"
        for group, counts in sorted(groups.items())
    )
    definitions = "\n".join(
        f"| {definition['id']} | {definition['revision']} | `{definition['sha256']}` |"
        for definition in value["definitions"]
    )
    return f"""<!-- Generated by tools/compat-inventory/production_denominator.py. Do not edit. -->

# Identity Platform and Firestore Standard production denominator

Goal: `{value["goal"]}`. Denominator: `{value["denominatorVersion"]}`.

Source snapshot: `{value["sourceSnapshot"]}` (`{value["sourceSnapshotSha256"]}`).

This ledger is the exact API-definition denominator for the pinned Discovery snapshot. It is not a production compatibility claim. Every source surface appears exactly once. A feature group is an ownership and reporting category; it does not transfer evidence to every surface in that group.

The denominator contains {len(targets)} source surfaces: {len(in_scope)} Identity Platform or Firestore Standard/Native targets, {len(enterprise)} explicit Firestore Enterprise-only exclusions and {len(outside)} Datastore-mode variants outside this goal. Excluded rows remain visible so the declared scope cannot shrink the source set silently.

## Pinned definitions

| Definition | Revision | Source SHA-256 |
| --- | --- | --- |
{definitions}

## Feature groups

| Feature group | Target surfaces | Enterprise-only surfaces | Outside-goal surfaces |
| --- | ---: | ---: | ---: |
{rows}

## Evidence states

`waiting-oracle`, `local-verified`, `oracle-compared`, `repaired` and `compat-verified` are separate states. The initial ledger keeps every target at `waiting-oracle`; existing schema-v1 observations remain immutable historical references and are not promoted automatically. Any later state needs an exact receipt binding the source revision, artifact, configuration, case corpus and comparator. A local pass is never rendered as production compatibility.

## Scope boundary

The target set includes application-facing Identity Platform and Firestore Standard/Native API definitions, including administration needed by those features. Pipeline execution, Enterprise change streams, MongoDB user credentials, MongoDB API modes and Enterprise search configuration use `FS-ENTERPRISE-EXCLUDED`. Datastore-only mode variants use `FS-DATASTORE-EXCLUDED`. Standard vector query fields remain in `FS-QUERY-INDEX`.

## Updating

The versioned JSON is immutable after publication. A later denominator must use a new versioned path and explicitly bind its predecessor under a reviewed schema; do not overwrite this file. Run `uv run --project tools/compat-inventory --locked tools/compat-inventory/production_denominator.py` while creating this initial version, and run the same command with `--check`, then `cargo run -p compat-check`, before committing. The Rust gate compares the ledger to the pinned source set and refuses missing, invented, reshaped or silently reclassified Enterprise targets.
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--source",
        default=SOURCE_PATH,
    )
    parser.add_argument(
        "--output",
        default=OUTPUT_PATH,
    )
    parser.add_argument("--document", default=DOCUMENT_PATH)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--check-base")
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    source_path = repository_path(root, args.source)
    output = repository_path(root, args.output, allow_missing_leaf=True)
    document = repository_path(root, args.document, allow_missing_leaf=True)
    if args.check_base:
        verify_immutable_history(root, args.check_base)
    source_bytes = source_path.read_bytes()
    source_sha256 = verify_source_digest(source_bytes)
    source = json.loads(source_bytes)
    expected = serialized(build(source, args.source, source_sha256))
    expected_document = render(json.loads(expected))
    if args.check:
        stale = []
        if not output.is_file() or output.read_text() != expected:
            stale.append(args.output)
        if not document.is_file() or document.read_text() != expected_document:
            stale.append(args.document)
        if stale:
            raise SystemExit("stale production denominator output: " + ", ".join(stale))
        return 0
    write_immutable(output, expected)
    write_document(document, expected_document)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
