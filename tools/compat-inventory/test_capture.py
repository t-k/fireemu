"""Source discovery and coverage-denominator regression tests (no network mocks)."""

import json

import pytest
from capture import (
    canonical_url,
    check,
    digest,
    discovery_surfaces,
    extract_page,
    in_scope,
    sitemap_entries,
)


def test_snapshot_hashes_reject_each_modified_component(tmp_path):
    components = {
        "catalog.json": {
            "pages": [
                {"url": "https://firebase.google.com/docs/auth", "review": "discovered"}
            ],
            "reviewed": 0,
        },
        "discovery.json": {"definitions": []},
        "extracted.json": {"pages": []},
        "acquisitions.json": {"requests": []},
    }
    manifest = {"schemaVersion": 1, "files": {}}
    for name, value in components.items():
        data = json.dumps(value).encode()
        (tmp_path / name).write_bytes(data)
        manifest["files"][name] = digest(data)
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    check(tmp_path)
    for name in components:
        path = tmp_path / name
        original = path.read_bytes()
        path.write_bytes(original + b" ")
        with pytest.raises(ValueError, match="snapshot drift"):
            check(tmp_path)
        path.write_bytes(original)


def test_review_claim_is_rejected_even_when_the_manifest_is_rehashed(tmp_path):
    components = {
        "catalog.json": {
            "pages": [
                {"url": "https://firebase.google.com/docs/auth", "review": "reviewed"}
            ],
            "reviewed": 1,
        },
        "discovery.json": {"definitions": []},
        "extracted.json": {"pages": []},
        "acquisitions.json": {"requests": []},
    }
    manifest = {"schemaVersion": 1, "files": {}}
    for name, value in components.items():
        data = json.dumps(value).encode()
        (tmp_path / name).write_bytes(data)
        manifest["files"][name] = digest(data)
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="not completed review"):
        check(tmp_path)


def test_canonicalization_preserves_versions_and_excludes_translations():
    assert (
        canonical_url("https://cloud.google.com/firestore/docs/x?hl=en#part")
        == "https://docs.cloud.google.com/firestore/docs/x"
    )
    assert canonical_url("https://firebase.google.com/docs/auth?hl=ja") is None
    assert (
        canonical_url(
            "https://identitytoolkit.googleapis.com/$discovery/rest?version=v2"
        )
        == "https://identitytoolkit.googleapis.com/$discovery/rest?version=v2"
    )
    assert (
        canonical_url("https://firebase.google.com/docs/auth?unexpected=value") is None
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/docs/auth",
        "http://firebase.google.com/docs/auth",
        "https://firebase.google.com.evil.example/docs/auth",
        "https://firebase.google.com/docs/auth|broken",
    ],
)
def test_unknown_origins_and_markup_are_refused(url):
    assert canonical_url(url) is None


def test_scope_keeps_enterprise_mongodb_admin_rules_and_sdk_references():
    for path in [
        "/docs/firestore/enterprise/overview",
        "/docs/firestore/enterprise/supported-features",
        "/docs/auth/web/totp-mfa",
        "/docs/rules/rules-behavior",
        "/docs/reference/js/firestore_.vectorvalue",
        "/docs/reference/android/com/google/firebase/auth/FirebaseAuth",
    ]:
        assert in_scope("https://firebase.google.com" + path)
    assert in_scope(
        "https://docs.cloud.google.com/firestore/mongodb-compatibility/docs/supported-features"
    )
    assert in_scope(
        "https://docs.cloud.google.com/identity-platform/docs/reference/rest/v2/projects.tenants"
    )
    assert not in_scope("https://firebase.google.com/docs/storage/web/start")


def test_sitemap_distinguishes_index_and_page_lists():
    index = b'<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><sitemap><loc>https://firebase.google.com/sitemap_0.xml</loc></sitemap></sitemapindex>'
    assert sitemap_entries(index) == (
        True,
        ["https://firebase.google.com/sitemap_0.xml"],
    )
    with pytest.raises(ValueError):
        sitemap_entries(b"<html>error page</html>")


def test_body_extraction_keeps_table_warning_code_and_heading_locators():
    result = extract_page(
        '<html><nav>noise</nav><article><h1>Title</h1><h2 id="limits">Limits</h2><aside>Warning</aside><table><tr><th>Value</th><td>10</td></tr></table><pre><code>x &lt; 10</code></pre></article><footer>noise</footer></html>'
    )
    assert "noise" not in result["text"]
    for text in ["Warning", "Value", "10", "x < 10"]:
        assert text in result["text"]
    assert result["sections"] == ["limits"]
    with pytest.raises(ValueError):
        extract_page("<html><main>No article</main></html>")


def test_discovery_walk_covers_nested_methods_fields_arrays_maps_and_enums():
    doc = {
        "resources": {
            "projects": {
                "resources": {
                    "accounts": {
                        "methods": {
                            "create": {
                                "id": "auth.projects.accounts.create",
                                "request": {"$ref": "Input"},
                                "response": {"$ref": "Output"},
                                "parameters": {"key": {"type": "string"}},
                            }
                        }
                    }
                }
            }
        },
        "schemas": {
            "Input": {
                "properties": {
                    "items": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["A", "B"]},
                    },
                    "labels": {"additionalProperties": {"type": "string"}},
                    "nested": {"properties": {"flag": {"type": "boolean"}}},
                }
            },
            "Output": {"properties": {"done": {"type": "boolean"}}},
        },
    }
    result = discovery_surfaces(doc)
    pairs = {(row["locator"], row["kind"]) for row in result}
    assert ("auth.projects.accounts.create", "method") in pairs
    assert ("auth.projects.accounts.create/request", "request") in pairs
    assert ("auth.projects.accounts.create/parameters/key", "field") in pairs
    assert ("schemas/Input/properties/items/items/enum/A", "enum") in pairs
    assert ("schemas/Input/properties/labels/additionalProperties", "field") in pairs
    assert ("schemas/Input/properties/nested/properties/flag", "field") in pairs
    assert all(row["classification"] == "unknown" for row in result)
