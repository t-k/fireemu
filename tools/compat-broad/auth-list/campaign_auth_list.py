"""Finite local campaign contract for Auth refresh and ListCollectionIds."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

PROJECT = "demo-firestore-probe"
SOURCE_COMMIT = "aad1a41de926fae244b42ac1bd2baa57bf2bcdde"
NONCE = "{freshNonce}"


def _auth(path, body, kind, resource, *, token=None):
    if kind == "auth-refresh":
        path = "securetoken.googleapis.com" + path
    elif not path.startswith("identitytoolkit.googleapis.com"):
        path = "identitytoolkit.googleapis.com" + path
    binding = resource + "Uid"
    provenance = {
        "source": "owned-auth-session-v2",
        "uid": resource if kind == "auth-sign-up" else "$binding:" + binding,
    }
    if kind == "auth-refresh":
        provenance["token"] = token or "owned-refresh-token"
    operation = {
        "service": "auth",
        "path": path,
        "method": "POST",
        "body": body,
        "privileged": "/projects/" in path,
        "form": kind == "auth-refresh",
        "operationType": kind,
        "principal": "owned-auth-bootstrap"
        if kind == "auth-sign-up"
        else "$binding:" + resource + "Principal",
        "resource": resource,
        "provenance": provenance,
    }
    # The shared Gate lets recovery delete only an account whose creating observation it
    # knows as a sign-up (`kind`, 6c95efcc0).
    if kind == "auth-sign-up":
        operation["kind"] = "sign-up"
    return operation


def _list(parent, case, *, page_token=None):
    # Firestore's parent is the resource path in the HTTP template, not a body
    # field. Keep the request shape identical to the public REST contract.
    body = {}
    if case == "page-size-one":
        body["pageSize"] = 1
    provenance = {"source": "owned-firestore-fixture", "case": case}
    if page_token is not None:
        body["pageToken"] = "$binding:pagedToken"
        provenance.update(
            pageToken="observed-continuation",
            tokenValue="$binding:pagedToken",
            consumed=False,
        )
    return {
        "service": "firestore",
        "path": "/v1/" + parent + ":listCollectionIds",
        "method": "POST",
        "body": body,
        "privileged": True,
        "form": False,
        "operationType": "firestore-list-collection-ids",
        "principal": "owned-firestore-admin",
        "resource": parent,
        "provenance": provenance,
    }


def _doc(path, value, *, operation_type="firestore-document-create"):
    create = operation_type.endswith("create")
    return {
        "service": "firestore",
        "path": "/v1/" + path + ("?currentDocument.exists=false" if create else ""),
        "method": "PATCH" if create else "DELETE",
        "body": {
            "fields": {
                "_sharedOwner": {"referenceValue": path},
                "marker": {"stringValue": value},
            }
        }
        if create
        else None,
        "privileged": True,
        "form": False,
        "operationType": operation_type,
        "principal": "owned-firestore-admin",
        "resource": path,
        "provenance": {
            "source": "owned-firestore-fixture",
            "resource": path,
            "marker": "_campaignOwner",
        },
    }


def _doc_read(path):
    return {
        "service": "firestore",
        "path": "/v1/" + path,
        "method": "GET",
        "body": None,
        "privileged": True,
        "form": False,
        "operationType": "firestore-document-read",
        "principal": "owned-firestore-admin",
        "resource": path,
        "provenance": {
            "source": "owned-firestore-fixture",
            "resource": path,
            "marker": "_campaignOwner",
        },
    }


def campaign_cases():
    """Return the five accepted cases and explicit out-of-scope entries."""
    accepted = [
        {
            "id": "auth/refresh/changed-refresh@0",
            "service": "auth",
            "sequence": "auth-session-v2",
            "principal": "owned-account:changed",
            "operations": ["sign-up", "sign-in", "changed-refresh", "issued-id-lookup"],
        },
        {
            "id": "auth/refresh/reference-refresh",
            "service": "auth",
            "sequence": "auth-session-continuity",
            "principal": "owned-account:reference",
            "operations": [
                "sign-up",
                "sign-in",
                "reference-refresh",
                "issued-id-lookup",
            ],
        },
        {
            "id": "firestore/list-collection-ids/root",
            "service": "firestore",
            "sequence": "listCollectionIds",
            "principal": "owned-firestore-admin",
            "operations": ["setup", "root-list", "readback", "cleanup"],
        },
        {
            "id": "firestore/list-collection-ids/missing-document-parent",
            "service": "firestore",
            "sequence": "listCollectionIds",
            "principal": "owned-firestore-admin",
            "operations": ["setup-subcollection", "missing-parent-list", "cleanup"],
        },
        {
            "id": "firestore/list-collection-ids/page-size-one",
            "service": "firestore",
            "sequence": "listCollectionIds",
            "principal": "owned-firestore-admin",
            "operations": [
                "setup-two-child-collections",
                "first-page",
                "continuation-once",
                "cleanup",
            ],
        },
    ]
    outside = [
        (
            "firestore/list-collection-ids/rules-refusal",
            "Rules setup is outside this campaign",
        ),
        (
            "firestore/list-collection-ids/tenant",
            "Tenant routing is outside this campaign",
        ),
        ("auth/refresh/mfa", "MFA is outside this campaign"),
        (
            "auth/refresh/cloud",
            "Cloud credentials are forbidden by the local entry gate",
        ),
    ]
    return accepted + [
        {"id": key, "admission": "outside", "reason": reason} for key, reason in outside
    ]


def campaign_manifest(nonce=NONCE):
    if nonce != NONCE and not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise ValueError("fresh hexadecimal namespace required")
    root = f"projects/{PROJECT}/databases/(default)/documents"
    changed = "changed-" + nonce
    reference = "reference-" + nonce
    parents = {
        "root": root,
        "missing": root + "/missing-parent-" + nonce + "/parent",
        "paged": root + "/paged-parent-" + nonce + "/rootdoc",
    }
    password = "LocalOnly-" + nonce
    observation = [
        _auth(
            "/v1/accounts:signUp",
            {
                "email": changed + "@example.invalid",
                "password": password,
                "returnSecureToken": True,
            },
            "auth-sign-up",
            changed,
        ),
        _auth(
            "/v1/accounts:signInWithPassword",
            {
                "email": changed + "@example.invalid",
                "password": password,
                "returnSecureToken": True,
            },
            "auth-sign-in",
            changed,
        ),
        _auth(
            "/v1/token",
            {
                "grant_type": "refresh_token",
                "refresh_token": "$binding:changed-" + nonce + "Refresh",
            },
            "auth-refresh",
            changed,
        ),
        _auth(
            "/v1/accounts:lookup",
            {"idToken": "$binding:" + changed + "IdToken"},
            "auth-lookup",
            changed,
        ),
        _auth(
            "/v1/accounts:signUp",
            {
                "email": reference + "@example.invalid",
                "password": password,
                "returnSecureToken": True,
            },
            "auth-sign-up",
            reference,
        ),
        _auth(
            "/v1/accounts:signInWithPassword",
            {
                "email": reference + "@example.invalid",
                "password": password,
                "returnSecureToken": True,
            },
            "auth-sign-in",
            reference,
        ),
        _auth(
            "/v1/token",
            {
                "grant_type": "refresh_token",
                "refresh_token": "$binding:reference-" + nonce + "Refresh",
            },
            "auth-refresh",
            reference,
        ),
        _auth(
            "/v1/accounts:lookup",
            {"idToken": "$binding:" + reference + "IdToken"},
            "auth-lookup",
            reference,
        ),
        _list(parents["root"], "root"),
        _doc_read(parents["missing"]),
        _list(parents["missing"], "missing-document-parent"),
        _list(parents["paged"], "page-size-one"),
        _list(parents["paged"], "page-size-one", page_token="observed-token"),
    ]
    resources = [
        root + "/child-" + nonce + "/doc",
        parents["missing"] + "/children/doc",
        parents["paged"],
        parents["paged"] + "/alpha/doc",
        parents["paged"] + "/beta/doc",
    ]
    observation[:0] = [
        _doc(path, label)
        for path, label in zip(
            resources,
            ["root", "missing-child", "paged-parent", "alpha", "beta"],
            strict=True,
        )
    ]
    recovery = []
    for index, path in enumerate(resources):
        recovery.extend(
            [
                {
                    **_doc(path, "", operation_type="firestore-document-create"),
                    "path": "/v1/" + path,
                    "method": "GET",
                    "body": None,
                    "operationType": "firestore-document-read",
                    "versionFrom": None,
                },
                {
                    **_doc(path, "", operation_type="firestore-document-delete"),
                    "versionFrom": 3 * index,
                },
                {
                    **_doc(path, "", operation_type="firestore-document-create"),
                    "path": "/v1/" + path,
                    "method": "GET",
                    "body": None,
                    "operationType": "firestore-document-read",
                    "versionFrom": None,
                },
            ]
        )
    recovery.extend(
        [
            _auth(
                "/v1/projects/" + PROJECT + "/accounts:delete",
                {"localId": "$binding:" + changed + "Uid"},
                "auth-delete",
                changed,
            ),
            _auth(
                "/v1/projects/" + PROJECT + "/accounts:delete",
                {"localId": "$binding:" + reference + "Uid"},
                "auth-delete",
                reference,
            ),
            _auth(
                "/v1/projects/" + PROJECT + "/accounts:lookup",
                {"localId": "$binding:" + changed + "Uid"},
                "auth-lookup",
                changed,
            ),
            _auth(
                "/v1/projects/" + PROJECT + "/accounts:lookup",
                {"localId": "$binding:" + reference + "Uid"},
                "auth-lookup",
                reference,
            ),
        ]
    )
    auth_cleanup_resource = (
        "identitytoolkit.googleapis.com/v1/projects/"
        + PROJECT
        + "/accounts:delete"
    )
    auth_lookup_resource = auth_cleanup_resource.replace(
        "accounts:delete", "accounts:lookup"
    )
    return {
        "contract": "shared-local-v2",
        "sourceCommit": SOURCE_COMMIT,
        "nonce": nonce,
        "transport": "local-only",
        "localOrigins": {
            "auth": "http://127.0.0.1:18081",
            "firestore": "http://127.0.0.1:18082",
        },
        "jobs": {
            "auth-list": {
                # Firestore documents are journaled resources. Auth accounts are
                # bound separately and verified by the delete/lookup pair. The
                # route sentinel lets the shared gate retain ownership of the
                # privileged cleanup request without treating it as a document.
                "resources": resources + [auth_cleanup_resource, auth_lookup_resource],
                "observation": observation,
                "recovery": recovery,
            }
        },
        "wallSeconds": 600,
        "recoverySeconds": 300,
        "intervalSeconds": 0.25,
        "observationRequests": len(observation),
        "requestCostMicrousd": 100,
        "fixedCostMicrousd": 3000,
        "costMicrousd": 8000,
        "coordinatorRequests": 2,
        "maxConcurrency": 1,
        "ownerInputs": {
            "owner": None,
            "permissionReference": None,
            "startsAt": None,
            "endsAt": None,
            "nonce": None,
        },
        "productionExecutable": False,
    }


def proposal():
    plan = campaign_manifest()
    return {
        "kind": "production-campaign-auth-list-01-v1",
        "status": "prepared-offline",
        "planTemplate": plan,
        "cases": campaign_cases(),
        "artifactSha256": None,
        "configurationDigest": None,
        "networkCalls": 0,
        "productionExecuted": False,
    }


def validate_proposal(value):
    if value != proposal():
        raise ValueError("campaign proposal drift or owner inputs supplied")
    if (
        value["planTemplate"]["transport"] != "local-only"
        or value["productionExecuted"]
    ):
        raise ValueError("production entry is closed")
    if any(
        case.get("admission") == "accepted" and case["id"].startswith("cloud")
        for case in value["cases"]
    ):
        raise ValueError("external case admitted")
    return True


def compare_rows(local, production):
    """Keep recording/state/cleanup/compatibility outcomes independent."""
    result = {
        "recording": local.get("recordingComplete")
        and production.get("recordingComplete"),
        "state": local.get("stateValidation") and production.get("stateValidation"),
        "cleanup": local.get("cleanupComplete") and production.get("cleanupComplete"),
    }
    if not result["recording"] or not result["state"] or not result["cleanup"]:
        result["compatibility"] = "indeterminate"
    elif local.get("rows") == production.get("rows"):
        result["compatibility"] = "match"
    else:
        result["compatibility"] = "mismatch"
    return result


def write_manifest(path: Path):
    value = proposal()
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    return hashlib.sha256(path.read_bytes()).hexdigest()
