"""Bounded OAuth, project, database, Auth and Rules readbacks for one run."""

from __future__ import annotations

import http.client
import hashlib
import json
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import batch_adapter
import txn_expiry_preflight
from credential_prep import _private_request

preflight = txn_expiry_preflight.preflight
PROJECT = "fireemu-oracle-sbx"
RULES_RELEASE = f"projects/{PROJECT}/releases/cloud.firestore"
RULES_HOST = "firebaserules.googleapis.com"
RULES_RESPONSE_LIMIT = 65_536
PRE_SLOTS = ("oauth-tokeninfo", "project", "database", "auth", "rules-release", "ruleset-source")
POST_SLOTS = ("project", "database", "auth")


def _default_request(slot, token, resource=None):
    """Send one fixed management request without returning an unbounded body."""
    if slot == "oauth-tokeninfo":
        return _private_request("tokeninfo", token, deadline=12)
    if slot in ("project", "database", "auth"):
        response = batch_adapter.wire(
            preflight.metadata_url(slot),
            "GET",
            None,
            {"Authorization": "Bearer " + token, "x-goog-user-project": PROJECT},
            timeout=12,
            receipt=True,
        )
        http = response.get("http", {}) if isinstance(response, dict) else {}
        return {
            "complete": http.get("complete") is True and http.get("bodyKind") == "json",
            "workerReaped": True,
            "status": http.get("status"),
            "body": response.get("body") if isinstance(response, dict) else None,
        }
    if slot not in ("rules-release", "ruleset-source"):
        raise ValueError("management request outside the fixed slots")
    if slot == "ruleset-source" and (
        not isinstance(resource, str)
        or re.fullmatch(rf"projects/{PROJECT}/rulesets/[A-Za-z0-9_-]+", resource) is None
    ):
        raise ValueError("Rules source needs the validated release ruleset")
    name = RULES_RELEASE if slot == "rules-release" else resource
    connection = http.client.HTTPSConnection(RULES_HOST, timeout=12)
    try:
        connection.request(
            "GET",
            f"/v1/{name}",
            headers={"Authorization": "Bearer " + token, "x-goog-user-project": PROJECT},
        )
        response = connection.getresponse()
        raw = response.read(RULES_RESPONSE_LIMIT + 1)
        if len(raw) > RULES_RESPONSE_LIMIT:
            raise ValueError("Rules release response exceeds the bound")
        if response.status != 200:
            return {"complete": False, "workerReaped": True, "status": response.status, "body": None}
        body = json.loads(raw)
        return {
            "complete": isinstance(body, dict),
            "workerReaped": True,
            "status": response.status,
            "body": body,
        }
    finally:
        connection.close()


class MetadataSession:
    """One credential and nine fixed, pre-charged management slots."""

    def __init__(self, token, baseline, budget, *, request_fn=None):
        if not isinstance(token, str) or not 0 < len(token) <= 8192:
            raise ValueError("bounded OAuth credential required")
        preflight.validate_frozen_baselines(baseline)
        preflight.validate_principal(baseline.get("credentialPrincipal"))
        preflight.validate_project_number(baseline.get("projectNumber"))
        source_sha = baseline.get("rulesSourceSha256")
        if not isinstance(source_sha, str) or re.fullmatch(r"[a-f0-9]{64}", source_sha) is None:
            raise ValueError("frozen Rules source SHA-256 required")
        self._token = token
        self.baseline = baseline
        self.budget = budget
        self.request = request_fn or _default_request
        self._ready = False

    def _read(self, slot, resource=None):
        self.budget.charge("management")
        sent = time.monotonic()
        result = self.request(slot, self._token, resource)
        if (
            not isinstance(result, dict)
            or result.get("complete") is not True
            or result.get("workerReaped") is not True
            or result.get("status") != 200
            or not isinstance(result.get("body"), dict)
        ):
            raise ValueError(f"{slot} management readback is incomplete or refused")
        if slot == "oauth-tokeninfo":
            preflight.verify_token(
                self._token,
                result,
                self.baseline["credentialPrincipal"],
                sent=sent,
                now=time.monotonic(),
                required_seconds=1600,
            )
            return {"verified": True, "requiredSeconds": 1600}
        body = result["body"]
        if slot == "rules-release":
            ruleset = body.get("rulesetName")
            if body.get("name") != RULES_RELEASE or not isinstance(ruleset, str) or re.fullmatch(
                rf"projects/{PROJECT}/rulesets/[A-Za-z0-9_-]+", ruleset
            ) is None:
                raise ValueError("rules release has no valid Rules source")
            return ruleset
        if slot == "ruleset-source":
            files = (body.get("source") or {}).get("files")
            if body.get("name") != resource or not isinstance(files, list) or len(files) != 1:
                raise ValueError("rules source is missing or ambiguous")
            source = files[0]
            if not isinstance(source, dict) or not isinstance(source.get("content"), str):
                raise ValueError("rules source content is missing")
            content = source["content"]
            if "match /conf_txn/{id}" not in content or "allow read, write: if true;" not in content:
                raise ValueError("rules source does not allow the transaction collection")
            digest = hashlib.sha256(content.encode()).hexdigest()
            if digest != self.baseline["rulesSourceSha256"]:
                raise ValueError("rules source differs from the frozen baseline")
            return digest
        return preflight.verify_metadata(slot, body, self.baseline)["bodyDigest"]

    def preflight(self):
        observed = {slot: self._read(slot) for slot in PRE_SLOTS[:-1]}
        observed["rulesSourceSha256"] = self._read("ruleset-source", observed["rules-release"])
        self._ready = True
        observed["rulesetName"] = observed.pop("rules-release")
        return observed

    def postflight(self):
        if not self._ready:
            raise ValueError("postflight needs a complete preflight")
        return {slot: self._read(slot) for slot in POST_SLOTS}
