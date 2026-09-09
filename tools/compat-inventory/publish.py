"""Publish bounded candidate observations and check source snapshots offline.

This is an integrity and regression gate, not an authenticity signature or approval.
It deliberately cannot promote candidates to accepted feature evidence.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from capture import check, digest
from probe import DATABASE, NUMBER, PROJECT

ROOT = Path(__file__).resolve().parents[2]
INDEX = ROOT / "spec/compatibility/acquisition.json"
REPORT = ROOT / "docs/compatibility/acquisition.md"
AGGREGATIONS = {
    "count-alone-includes-missing": {"count": {"integerValue": "4"}},
    "count-with-sum-excludes-missing": {
        "count": {"integerValue": "3"},
        "sum": {"integerValue": "30"},
    },
    "count-with-avg-excludes-missing": {
        "count": {"integerValue": "3"},
        "avg": {"doubleValue": 15},
    },
    "sum-and-avg-ignore-nonnumeric": {
        "sum": {"integerValue": "30"},
        "avg": {"doubleValue": 15},
    },
}
REFUSAL = "commit-refuses-existing-document"
UNCHANGED = "queries-and-refused-commit-preserve-fields-and-times"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_aggregation(value: dict) -> None:
    cases = value["cases"]
    require(
        value["status"] == "passed" and value["executedCases"] == len(cases) == 6,
        "incomplete aggregation receipt",
    )
    require(
        len({row["id"] for row in cases}) == 6
        and all(row["passed"] is True for row in cases),
        "false or duplicate aggregation pass",
    )
    for row in cases:
        if row["id"] in AGGREGATIONS:
            require(
                row.get("actual") == row.get("expected") == AGGREGATIONS[row["id"]]
                and row.get("httpStatus") == 200,
                "aggregation value mismatch",
            )
        elif row["id"] == REFUSAL:
            require(
                row.get("httpStatus") == 409 and row.get("code") == "ALREADY_EXISTS",
                "missing refused Commit evidence",
            )
        elif row["id"] != UNCHANGED:
            raise ValueError("unknown aggregation case")
    require(
        {r["id"] for r in cases} == set(AGGREGATIONS) | {REFUSAL, UNCHANGED},
        "missing required aggregation cases",
    )
    owned = set(value["ownedResources"])
    cleanup = value["cleanup"]
    require(
        len(owned) == len(cleanup) == 4
        and {row["name"] for row in cleanup} == owned
        and all(row["confirmedMissing"] is True for row in cleanup),
        "unconfirmed cleanup",
    )
    require(
        set(value.get("stateBefore", {})) == owned
        and value.get("stateBefore") == value.get("stateAfter"),
        "missing unchanged-state observation",
    )


def validate_timestamps(value: dict) -> None:
    results = value["results"]
    require(
        len(results) == 6
        and {(r["shape"], r["precision"]) for r in results}
        == {
            (s, p)
            for s in ["timestamp", "map", "nested"]
            for p in ["123456", "123456789"]
        },
        "incomplete timestamp corpus",
    )
    labels = [
        "union1",
        "union2",
        "union3",
        "remove",
        "remove_again",
        "operand_duplicates",
        "set_union",
        "set_remove",
        "ordinary_duplicates",
        "remove_duplicates",
    ]
    for result in results:
        item = {"timestampValue": "2026-09-01T00:00:00.123456Z"}
        if result["shape"] in {"map", "nested"}:
            item = {"mapValue": {"fields": {"at": item}}}
        if result["shape"] == "nested":
            item = {
                "mapValue": {"fields": {"nested": {"arrayValue": {"values": [item]}}}}
            }
        require(
            [s["label"] for s in result["steps"]] == labels,
            "incomplete timestamp steps",
        )
        previous = None
        for step in result["steps"]:
            label = step["label"]
            document = step["document"]
            expected = (
                []
                if label
                in {"remove", "remove_again", "set_remove", "remove_duplicates"}
                else [item, item]
                if label == "ordinary_duplicates"
                else [item]
            )
            require(
                document["fields"]["values"]["arrayValue"].get("values", [])
                == expected,
                "timestamp value mismatch",
            )
            write_result = step["commit"]["writeResults"][0]
            require(
                write_result["updateTime"] == document["updateTime"],
                "write timestamp mismatch",
            )
            if "transform" in step["write"] or "updateTransforms" in step["write"]:
                require(
                    write_result["transformResults"] == [{"nullValue": None}],
                    "transform result mismatch",
                )
            if label in {"union2", "union3", "remove_again", "set_union"}:
                require(document["updateTime"] == previous, "no-op changed updateTime")
            previous = document["updateTime"]
    require(
        len(value["cleanup"]) == 6
        and {r["name"] for r in value["cleanup"]} == {r["name"] for r in results}
        and all(r["status"] == "fulfilled" for r in value["cleanup"]),
        "timestamp cleanup failed",
    )


def local_path(name: str) -> Path:
    path = (ROOT / name).resolve()
    require(
        path.is_relative_to(ROOT) and not Path(name).is_absolute(),
        "path outside source tree",
    )
    return path


def validate_identity(receipt: dict, value: dict, index: dict) -> None:
    corpus, target = receipt["corpus"], receipt["target"]
    if corpus == "timestamps":
        require(
            value["project"] == (PROJECT if target == "production" else "demo-app"),
            "timestamp project mismatch",
        )
        return
    require(
        value.get("acceptance") == "candidate" and value.get("project") == PROJECT,
        "receipt candidate/project mismatch",
    )
    tool = (
        "tools/compat-inventory/auth_probe.py"
        if corpus == "auth"
        else "tools/compat-inventory/probe.py"
    )
    require(
        value.get("probeSha256") == index["files"][tool], "receipt tool digest mismatch"
    )
    if target == "production":
        require(
            value.get("projectNumberVerified") is True,
            "missing production identity readback",
        )
    if corpus == "auth":
        require(
            target == value.get("target") == "production"
            and value.get("configReadback") == {"httpStatus": 403, "available": False},
            "Auth 403 blocker lacks readback",
        )
    else:
        require(
            value.get("kind")
            == ("live-production" if target == "production" else "live-fireemu")
            and value.get("profile")
            == ("production" if target == "production" else "strict"),
            "receipt target mismatch",
        )
        require(
            value.get("binarySha256") == index["binarySha256"]
            and value.get("expectedProjectNumber") == NUMBER,
            "receipt binary/project-number mismatch",
        )
        if target == "production":
            db = value.get("database", {})
            require(
                db.get("name") == DATABASE
                and db.get("type") == "FIRESTORE_NATIVE"
                and db.get("databaseEdition") == "STANDARD",
                "missing Standard/Native readback",
            )


def load_index() -> tuple[dict, dict, dict, dict]:
    index = json.loads(INDEX.read_text())
    require(
        index["schemaVersion"] == 1 and index["acceptance"] == "candidate",
        "candidate index required",
    )
    snapshot = local_path(index["snapshot"])
    check(snapshot)
    for name, expected in index["files"].items():
        require(
            digest(local_path(name).read_bytes()) == expected, f"artifact drift: {name}"
        )
    require(
        str((snapshot / "manifest.json").relative_to(ROOT)) in index["files"],
        "unbound source snapshot",
    )
    proto_path = index["protobuf"]
    require(proto_path in index["files"], "unbound protobuf inventory")
    proto = json.loads(local_path(proto_path).read_text())
    for source in proto["sources"]:
        require(
            digest(local_path(source["path"]).read_bytes()) == source["sha256"],
            "vendored protobuf drift",
        )
    require(
        proto["upstreamCommit"]
        == (ROOT / "crates/fireemu-proto-firestore/proto/UPSTREAM_COMMIT")
        .read_text()
        .strip(),
        "protobuf revision drift",
    )
    require(
        len({(r["locator"], r["kind"]) for r in proto["surfaces"]})
        == len(proto["surfaces"])
        > 0
        and all(
            r["classification"] == "unknown" and r["requirements"] == []
            for r in proto["surfaces"]
        ),
        "protobuf extraction is not review",
    )
    require(
        len(index["observations"]) == 5
        and {(r["corpus"], r["target"]) for r in index["observations"]}
        == {
            ("aggregation", "production"),
            ("aggregation", "fireemu"),
            ("timestamps", "production"),
            ("timestamps", "fireemu"),
            ("auth", "production"),
        },
        "incomplete or duplicate candidate corpus set",
    )
    for receipt in index["observations"]:
        require(
            receipt["path"] in index["files"] and receipt["acceptance"] == "candidate",
            "unbound or promoted observation",
        )
        value = json.loads(local_path(receipt["path"]).read_text())
        validate_identity(receipt, value, index)
        if receipt["corpus"] == "aggregation":
            validate_aggregation(value)
        elif receipt["corpus"] == "timestamps":
            validate_timestamps(value)
        elif receipt["corpus"] == "auth":
            require(
                value["status"] == "inconclusive"
                and value["cases"] == []
                and value["resourceMutations"] == 0,
                "Auth blocker cannot become a pass",
            )
        else:
            raise ValueError("unknown corpus")
    return (
        index,
        json.loads((snapshot / "catalog.json").read_text()),
        json.loads((snapshot / "discovery.json").read_text()),
        proto,
    )


def render() -> str:
    index, catalog, discovery, proto = load_index()
    snapshot = index["snapshot"]
    extracted = json.loads((local_path(snapshot) / "extracted.json").read_text())[
        "pages"
    ]
    acquisitions = json.loads((local_path(snapshot) / "acquisitions.json").read_text())[
        "requests"
    ]
    lines = [
        "<!-- Generated by tools/compat-inventory/publish.py --write. Do not edit. -->",
        "",
        "# Source acquisition and fresh candidate observations",
        "",
        "This page separates URL discovery, structural extraction, semantic review and execution. No candidate below is accepted feature evidence, a release attestation or a global compatibility percentage.",
        "",
        "## Bounded official-source inventory",
        "",
        f"Snapshot: `{catalog['capturedAt']}`. Status: `{catalog['status']}`. Scope: {catalog['scope']}.",
        "",
        "| Layer | Count | Meaning |",
        "| --- | ---: | --- |",
        f"| Canonical URLs | {len(catalog['pages'])} | Discovered, not individually fetched or reviewed |",
        f"| Successful acquisitions | {len(acquisitions)} | Sitemap, Discovery and seed-page responses; not reviewed documents |",
        f"| Unavailable acquisitions | {len(catalog['failures'])} | Retained as explicit debt |",
        f"| Extracted seed articles | {len(extracted)} | Headings, tables, warnings and code retained in local review cache; unreviewed |",
        "| Semantically reviewed pages | 0 | Extraction is not completed review |",
        f"| REST structural items | {sum(len(d['surfaces']) for d in discovery['definitions'])} | Methods, roles, schemas, fields and enum members; unknown mappings |",
        f"| gRPC structural items | {len(proto['surfaces'])} | Pinned Firestore v1 descriptors, including streaming roles and oneofs; unknown mappings |",
        "",
        f"Machine-readable [URL catalog](../../{snapshot}/catalog.json), [acquisitions and hashes](../../{snapshot}/acquisitions.json), [article locators](../../{snapshot}/extracted.json), [REST items](../../{snapshot}/discovery.json), and [gRPC items](../../{index['protobuf']}). The raw public documentation bodies stay in the operator's ignored cache; the public repository does not republish upstream articles. Hashes detect drift but are not independently signed provenance.",
        "",
        "| REST definition | Structural items |",
        "| --- | ---: |",
    ]
    lines.extend(
        f"| {d['id']} | {len(d['surfaces'])} |" for d in discovery["definitions"]
    )
    counts = Counter(r["kind"] for r in proto["surfaces"])
    lines += [
        "",
        "gRPC kinds: "
        + "; ".join(f"{kind}: {count}" for kind, count in sorted(counts.items()))
        + ".",
        "",
        "## Fresh observations",
        "",
        "The timestamp corpus is six programs with ten steps each, not sixty independent features. Both targets asserted the same bounded expectations. The focused aggregation corpus checks four aggregation combinations, a refused Commit, and unchanged document fields/times. Local binaries were built from this worktree; these are REST observations, not SDK or published npm-package validation.",
        "",
        "| Corpus | Target | Result | Receipt |",
        "| --- | --- | --- | --- |",
    ]
    for row in index["observations"]:
        result = (
            "Blocked before cases: Auth config readback HTTP 403"
            if row["corpus"] == "auth"
            else "6 cases passed; four deletions confirmed missing"
            if row["corpus"] == "aggregation"
            else "60 steps passed; six DELETE requests fulfilled"
        )
        lines.append(
            f"| {row['corpus']} | {row['target']} | {result} | [Candidate](../../{row['path']}) |"
        )
    lines += [
        "",
        f"Runtime source revision: `{index['runtimeSourceCommit']}`. Local binary SHA-256: `{index['binarySha256']}`. [Capture metadata and artifact hashes](../../spec/compatibility/acquisition.json) bind the tools and receipts. Focused receipts include project-number verification and Standard/Native database readback. The older timestamp harness does not emit configuration or binary provenance itself; its metadata is operator-recorded and must not be treated as a self-attested execution receipt.",
        "",
        "## Remaining obligations",
        "",
        "- Review each discovered page and section, classify normative requirements versus examples and managed-service boundaries, and map them to stable requirements and tests. All extracted API items remain unknown until this happens.",
        "- Expand beyond the captured sitemap set: omitted/unlisted URLs, linked SDK variants, and upstream changes can remain undiscovered. An error-free sitemap traversal is not proof that all documentation is known.",
        "- Auth configuration readback returned PERMISSION_DENIED. No Auth cases or user mutations occurred. Resolve the least-privilege read access separately before attempting positive controls; no MFA/TOTP compatibility is inferred.",
        "- Standard/Native Firestore observations do not cover Enterprise/Native, MongoDB compatibility, admin operations, SDK/platform combinations, authorization rules or external IdPs.",
        "- Review and approve source/configuration/corpus-bound receipts before promoting feature labels. Existing accepted conformance matrices and schema-1 evidence remain unchanged.",
        "",
        "## Reproduce without production access",
        "",
        "```sh",
        "uv run --with pytest --with protobuf pytest tools/compat-inventory -q",
        "uv run tools/compat-inventory/publish.py --check",
        "```",
        "",
        "CI performs these offline integrity checks, not fresh upstream capture or production requests. For explicit acquisition/probe commands and cleanup limitations, see [the tool guide](../../tools/compat-inventory/README.md).",
        "",
    ]
    return "\n".join(lines)


def record(directory: Path, snapshot: str) -> None:
    require(not INDEX.exists(), "candidate index already exists")
    destination = ROOT / "spec/compatibility/observations/2026-09-09"
    destination.mkdir(parents=True, exist_ok=False)
    observations = []
    files = {}
    for name, corpus, target in [
        ("timestamps-production.json", "timestamps", "production"),
        ("timestamps-fireemu.json", "timestamps", "fireemu"),
        ("aggregation-production-final.json", "aggregation", "production"),
        ("aggregation-fireemu-final.json", "aggregation", "fireemu"),
        ("auth-production-final.json", "auth", "production"),
    ]:
        raw = (directory / name).read_bytes()
        (destination / name).write_bytes(raw)
        path = str((destination / name).relative_to(ROOT))
        files[path] = digest(raw)
        observations.append(
            {
                "path": path,
                "corpus": corpus,
                "target": target,
                "acceptance": "candidate",
            }
        )
    proto = "spec/compatibility/upstream/firestore-protobuf.json"
    for path in [
        f"{snapshot}/manifest.json",
        proto,
        "tools/sdk-smoke/timestamp-array-oracle.mjs",
        "tools/compat-inventory/probe.py",
        "tools/compat-inventory/auth_probe.py",
        "tools/compat-inventory/capture.py",
        "tools/compat-inventory/protobuf_inventory.py",
    ]:
        files[path] = digest(local_path(path).read_bytes())
    receipt = json.loads((directory / "aggregation-fireemu-final.json").read_text())
    value = {
        "schemaVersion": 1,
        "acceptance": "candidate",
        "snapshot": snapshot,
        "protobuf": proto,
        "runtimeSourceCommit": "52169935671f0cbb6dcf56cd732eb310029c1b27",
        "binarySha256": receipt["binarySha256"],
        "observations": observations,
        "files": files,
    }
    INDEX.write_text(json.dumps(value, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", type=Path)
    parser.add_argument("--snapshot")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.record:
        require(bool(args.snapshot), "snapshot required")
        record(args.record, args.snapshot)
    generated = render()
    if args.write:
        REPORT.write_text(generated)
    else:
        require(REPORT.read_text() == generated, "generated acquisition page drift")
    print("Candidate acquisition/observation integrity checks passed (offline)")


if __name__ == "__main__":
    main()
