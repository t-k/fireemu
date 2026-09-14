import subprocess
from pathlib import Path

import pytest
from production_denominator import (
    OUTPUT_PATH,
    SOURCE_PATH,
    build,
    render,
    repository_path,
    verify_immutable_history,
    verify_source_digest,
    write_immutable,
)


def source():
    return {
        "schemaVersion": 1,
        "definitions": [
            {
                "id": "identitytoolkit-v1",
                "revision": "20260813",
                "sha256": "a" * 64,
                "surfaces": [
                    {
                        "locator": "identitytoolkit.accounts.signUp",
                        "kind": "method",
                        "transport": "REST",
                        "classification": "unknown",
                        "requirements": [],
                    },
                    {
                        "locator": "schemas/SignupNewUserRequest/properties/email",
                        "kind": "field",
                        "transport": "REST",
                        "classification": "unknown",
                        "requirements": [],
                    },
                ],
            },
            {
                "id": "firestore-v1",
                "revision": "20260826",
                "sha256": "b" * 64,
                "surfaces": [
                    {
                        "locator": "firestore.projects.databases.documents.runQuery",
                        "kind": "method",
                        "transport": "REST",
                        "classification": "unknown",
                        "requirements": [],
                    },
                    {
                        "locator": "firestore.projects.databases.documents.executePipeline",
                        "kind": "method",
                        "transport": "REST",
                        "classification": "unknown",
                        "requirements": [],
                    },
                    {
                        "locator": "schemas/GoogleFirestoreAdminV1Index/properties/searchIndexOptions",
                        "kind": "field",
                        "transport": "REST",
                        "classification": "unknown",
                        "requirements": [],
                    },
                    {
                        "locator": "schemas/GoogleFirestoreAdminV1DisableUserCredsRequest",
                        "kind": "schema",
                        "transport": "REST",
                        "classification": "unknown",
                        "requirements": [],
                    },
                    {
                        "locator": "schemas/GoogleFirestoreAdminV1VectorConfig",
                        "kind": "schema",
                        "transport": "REST",
                        "classification": "unknown",
                        "requirements": [],
                    },
                    {
                        "locator": "schemas/FindNearest",
                        "kind": "schema",
                        "transport": "REST",
                        "classification": "unknown",
                        "requirements": [],
                    },
                    {
                        "locator": "schemas/GoogleFirestoreAdminV1Database/properties/databaseEdition/enum/ENTERPRISE",
                        "kind": "enum-value",
                        "transport": "REST",
                        "classification": "unknown",
                        "requirements": [],
                    },
                    {
                        "locator": "schemas/GoogleFirestoreAdminV1Database/properties/mongodbCompatibleDataAccessMode",
                        "kind": "field",
                        "transport": "REST",
                        "classification": "unknown",
                        "requirements": [],
                    },
                    {
                        "locator": "schemas/GoogleFirestoreAdminV1Database/properties/type/enum/DATASTORE_MODE",
                        "kind": "enum-value",
                        "transport": "REST",
                        "classification": "unknown",
                        "requirements": [],
                    },
                    {
                        "locator": "schemas/GoogleFirestoreAdminV1Index/properties/apiScope/enum/DATASTORE_MODE_API",
                        "kind": "enum-value",
                        "transport": "REST",
                        "classification": "unknown",
                        "requirements": [],
                    },
                ],
            },
        ],
    }


def test_build_preserves_every_pinned_surface_once():
    result = build(
        source(), "spec/compatibility/upstream/pinned/discovery.json", "c" * 64
    )

    assert len(result["targets"]) == 12
    assert len({target["id"] for target in result["targets"]}) == 12
    assert all(
        target["evidenceState"] == "waiting-oracle" for target in result["targets"]
    )
    assert (
        result["sourceSnapshot"] == "spec/compatibility/upstream/pinned/discovery.json"
    )
    assert result["sourceSnapshotSha256"] == "c" * 64


def test_build_classifies_standard_and_enterprise_surfaces_separately():
    targets = {
        target["locator"]: target
        for target in build(
            source(), "spec/compatibility/upstream/pinned/discovery.json", "c" * 64
        )["targets"]
    }

    assert (
        targets["firestore.projects.databases.documents.runQuery"]["scope"] == "target"
    )
    assert (
        targets["firestore.projects.databases.documents.runQuery"]["featureGroup"]
        == "FS-QUERY-INDEX"
    )
    assert (
        targets["firestore.projects.databases.documents.executePipeline"]["scope"]
        == "enterprise-only"
    )
    assert (
        targets["firestore.projects.databases.documents.executePipeline"][
            "featureGroup"
        ]
        == "FS-ENTERPRISE-EXCLUDED"
    )
    for locator in (
        "schemas/GoogleFirestoreAdminV1Index/properties/searchIndexOptions",
        "schemas/GoogleFirestoreAdminV1DisableUserCredsRequest",
        "schemas/GoogleFirestoreAdminV1Database/properties/databaseEdition/enum/ENTERPRISE",
        "schemas/GoogleFirestoreAdminV1Database/properties/mongodbCompatibleDataAccessMode",
    ):
        assert targets[locator]["scope"] == "enterprise-only"
        assert targets[locator]["featureGroup"] == "FS-ENTERPRISE-EXCLUDED"
    for locator in (
        "schemas/GoogleFirestoreAdminV1VectorConfig",
        "schemas/FindNearest",
    ):
        assert targets[locator]["scope"] == "target"
        assert targets[locator]["featureGroup"] == "FS-QUERY-INDEX"
    for locator in (
        "schemas/GoogleFirestoreAdminV1Database/properties/type/enum/DATASTORE_MODE",
        "schemas/GoogleFirestoreAdminV1Index/properties/apiScope/enum/DATASTORE_MODE_API",
    ):
        assert targets[locator]["scope"] == "outside-goal"
        assert targets[locator]["featureGroup"] == "FS-DATASTORE-EXCLUDED"


def test_build_is_deterministic_when_source_rows_are_reordered():
    first = build(
        source(), "spec/compatibility/upstream/pinned/discovery.json", "c" * 64
    )
    changed = source()
    changed["definitions"].reverse()
    for definition in changed["definitions"]:
        definition["surfaces"].reverse()

    assert (
        build(changed, "spec/compatibility/upstream/pinned/discovery.json", "c" * 64)
        == first
    )


def test_render_keeps_scope_and_evidence_limits_visible():
    page = render(
        build(source(), "spec/compatibility/upstream/pinned/discovery.json", "c" * 64)
    )

    assert "12" in page
    assert "5" in page
    assert "2" in page
    assert "waiting-oracle" in page
    assert "not a production compatibility claim" in page
    assert "FS-ENTERPRISE-EXCLUDED" in page


def test_published_denominator_version_cannot_be_overwritten(tmp_path):
    output = tmp_path / "v1.json"
    write_immutable(output, "first\n")
    write_immutable(output, "first\n")

    with pytest.raises(ValueError, match="immutable denominator version"):
        write_immutable(output, "changed\n")


def test_pinned_source_content_digest_is_enforced():
    source_bytes = (Path(__file__).parents[2] / SOURCE_PATH).read_bytes()
    assert len(verify_source_digest(source_bytes)) == 64
    with pytest.raises(ValueError, match="immutable content SHA-256"):
        verify_source_digest(source_bytes + b" ")


def test_published_source_and_existing_version_must_equal_base(tmp_path):
    root = tmp_path / "repository"
    source_path = root / SOURCE_PATH
    source_path.parent.mkdir(parents=True)
    source_path.write_text("source-v1\n")
    subprocess.run(["git", "init", "-q", root], check=True)
    subprocess.run(
        ["git", "-C", root, "config", "user.email", "test@example.invalid"], check=True
    )
    subprocess.run(["git", "-C", root, "config", "user.name", "Test"], check=True)
    subprocess.run(["git", "-C", root, "add", SOURCE_PATH], check=True)
    subprocess.run(["git", "-C", root, "commit", "-qm", "base"], check=True)
    base = subprocess.run(
        ["git", "-C", root, "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    verify_immutable_history(root, base, source_anchor=base)
    source_path.write_text("changed\n")
    with pytest.raises(ValueError, match="immutable input differs"):
        verify_immutable_history(root, base, source_anchor=base)

    source_path.write_text("source-v1\n")
    output = root / OUTPUT_PATH
    output.parent.mkdir(parents=True)
    output.write_text("denominator-v1\n")
    subprocess.run(["git", "-C", root, "add", OUTPUT_PATH], check=True)
    subprocess.run(["git", "-C", root, "commit", "-qm", "publish"], check=True)
    published = subprocess.run(
        ["git", "-C", root, "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    output.write_text("rewritten\n")
    with pytest.raises(ValueError, match="immutable input differs"):
        verify_immutable_history(root, published, source_anchor=base)


def test_generator_paths_reject_symlinks(tmp_path):
    root = tmp_path / "repository"
    (root / "spec/compatibility/denominators").mkdir(parents=True)
    victim = tmp_path / "victim.json"
    victim.write_text("untouched\n")
    (root / OUTPUT_PATH).symlink_to(victim)

    with pytest.raises(ValueError, match="symlink"):
        repository_path(root, OUTPUT_PATH, allow_missing_leaf=True)
    assert victim.read_text() == "untouched\n"
