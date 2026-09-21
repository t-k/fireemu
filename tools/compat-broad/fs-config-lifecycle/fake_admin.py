"""In-memory stand-in for the Firestore Admin v1 configuration surface.

Used by the lane's tests and the temporary-Ledger integration proof only. It serves
the saved production database projection, keeps one field configuration per owned
field, answers a patch with a long-running operation that completes after a declared
number of polls, and can inject the failures the recovery path must survive. It opens
no socket and is never a transport the production launcher can bind.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from .cases import DEFAULT_DATABASE, PROJECT

FIXTURE = "tools/compat-broad/fixtures/database-settings-7be6cf08.json"


def saved_projection() -> dict[str, Any]:
    root = Path(__file__).resolve().parents[3]
    fixture = json.loads((root / FIXTURE).read_text(encoding="utf-8"))
    return copy.deepcopy(fixture["observations"][0]["body"])


def _error(status: int, code: str, message: str) -> dict[str, Any]:
    return {
        "status": status,
        "body": {"error": {"code": status, "message": message, "status": code}},
        "complete": True,
        "failure": None,
    }


def _ok(body: Any) -> dict[str, Any]:
    return {"status": 200, "body": body, "complete": True, "failure": None}


class FakeAdmin:
    """One project's configuration state behind `transmit(request, *, deadline)`."""

    def __init__(
        self,
        *,
        poll_rounds: int = 1,
        refuse_revert: set[str] | None = None,
        refuse_apply: set[str] | None = None,
        fail_at: dict[str, str] | None = None,
        credential_refuse_at: str | None = None,
        never_done: set[str] | None = None,
        ignore_revert: set[str] | None = None,
        answer_without_operation: set[str] | None = None,
        answer_5xx: set[str] | None = None,
        raise_after_apply: set[str] | None = None,
        projection: dict[str, Any] | None = None,
        databases: list[str] | None = None,
        drift_enumeration_after: int | None = None,
    ) -> None:
        self.projection = projection or saved_projection()
        self.databases = databases or [
            f"projects/{PROJECT}/databases/{DEFAULT_DATABASE}"
        ]
        self.poll_rounds = poll_rounds
        self.refuse_revert = refuse_revert or set()
        self.refuse_apply = refuse_apply or set()
        self.fail_at = fail_at or {}
        self.credential_refuse_at = credential_refuse_at
        self.never_done = never_done or set()
        self.ignore_revert = ignore_revert or set()
        self.answer_without_operation = answer_without_operation or set()
        self.answer_5xx = answer_5xx or set()
        self.raise_after_apply = raise_after_apply or set()
        self.drift_enumeration_after = drift_enumeration_after
        self.fields: dict[str, dict[str, Any]] = {}
        self.operations: dict[str, dict[str, Any]] = {}
        self.requests: list[dict[str, Any]] = []
        self.patches: list[tuple[str, str, Any]] = []

    # -- helpers ------------------------------------------------------------

    def field(self, name: str) -> dict[str, Any]:
        if name not in self.fields:
            self.fields[name] = {
                "name": name,
                "indexConfig": {
                    "indexes": [
                        {
                            "queryScope": "COLLECTION",
                            "fields": [
                                {
                                    "fieldPath": name.rsplit("/", 1)[-1],
                                    "order": "ASCENDING",
                                }
                            ],
                        },
                        {
                            "queryScope": "COLLECTION",
                            "fields": [
                                {
                                    "fieldPath": name.rsplit("/", 1)[-1],
                                    "order": "DESCENDING",
                                }
                            ],
                        },
                        {
                            "queryScope": "COLLECTION",
                            "fields": [
                                {
                                    "fieldPath": name.rsplit("/", 1)[-1],
                                    "arrayConfig": "CONTAINS",
                                }
                            ],
                        },
                    ],
                    "usesAncestorConfig": True,
                },
            }
        return self.fields[name]

    def _operation(self, field_name: str, mask: str) -> dict[str, Any]:
        index = len(self.operations)
        name = (
            f"projects/{PROJECT}/databases/{DEFAULT_DATABASE}/operations/op{index:04d}"
        )
        done = self.poll_rounds == 0 and field_name not in self.never_done
        self.operations[name] = {
            "name": name,
            "metadata": {
                "@type": "type.googleapis.com/google.firestore.admin.v1.FieldOperationMetadata",
                "field": field_name,
                "state": "SUCCESSFUL" if done else "PROCESSING",
                "startTime": "2026-09-21T00:00:00.000000Z",
            },
            "done": done,
            "_polls": 0,
            "_field": field_name,
        }
        return {
            key: value
            for key, value in self.operations[name].items()
            if not key.startswith("_")
        }

    # -- transport ------------------------------------------------------------

    def transmit(self, request: dict[str, Any], *, deadline: float) -> dict[str, Any]:
        self.requests.append(copy.deepcopy(request))
        case = request["case"]
        if case in self.fail_at and self.fail_at[case] == "raise":
            raise ConnectionResetError("injected transport failure")
        if case in self.fail_at and self.fail_at[case] == "incomplete":
            return {
                "status": None,
                "body": None,
                "complete": False,
                "failure": "injected-timeout",
            }
        if self.credential_refuse_at == case:
            return _error(401, "UNAUTHENTICATED", "injected credential refusal")
        path, method = request["path"], request["method"]
        prefix = f"/v1/projects/{PROJECT}/databases/{DEFAULT_DATABASE}"
        if method == "GET" and path == prefix:
            return _ok(copy.deepcopy(self.projection))
        if method == "GET" and path == f"/v1/projects/{PROJECT}/databases":
            names = list(self.databases)
            if (
                self.drift_enumeration_after is not None
                and sum(1 for r in self.requests if r["path"] == path)
                > self.drift_enumeration_after
            ):
                names.append(f"projects/{PROJECT}/databases/stray")
            return _ok({"databases": [{"name": name} for name in names]})
        if method == "GET" and "/operations/" in path:
            operation = self.operations.get(path.removeprefix("/v1/"))
            if operation is None:
                return _error(404, "NOT_FOUND", "no such operation")
            operation["_polls"] += 1
            if (
                operation["_polls"] >= self.poll_rounds
                and operation["_field"] not in self.never_done
            ):
                operation["done"] = True
                operation["metadata"]["state"] = "SUCCESSFUL"
            return _ok({k: v for k, v in operation.items() if not k.startswith("_")})
        if method == "GET" and path.endswith("/fields"):
            # Production semantics: the index filter lists fields whose index
            # configuration is overridden; a TTL-only override keeps
            # usesAncestorConfig and is visible only under `ttlConfig:*`.
            parent = path.removeprefix("/v1/").removesuffix("/fields")
            filter_ = request["query"].get("filter")
            if filter_ == "indexConfig.usesAncestorConfig:false":

                def selected(field):
                    return field["indexConfig"].get("usesAncestorConfig") is False
            elif filter_ == "ttlConfig:*":

                def selected(field):
                    return "ttlConfig" in field
            else:
                return _error(400, "INVALID_ARGUMENT", "unsupported filter")
            listed = [
                copy.deepcopy(field)
                for name, field in self.fields.items()
                if name.startswith(parent + "/fields/") and selected(field)
            ]
            return _ok({"fields": listed} if listed else {})
        if "/fields/" in path and method == "GET":
            return _ok(copy.deepcopy(self.field(path.removeprefix("/v1/"))))
        if "/fields/" in path and method == "PATCH":
            name = path.removeprefix("/v1/")
            mask = request["query"]["updateMask"]
            body = request["body"] or {}
            field = self.field(name)
            # Enabling TTL sends an empty ttlConfig message; disabling omits it.
            # An exemption sends indexConfig.indexes; a reset sends an empty
            # indexConfig.
            reverting = (
                mask not in body
                if mask == "ttlConfig"
                else body.get(mask) in ({}, None)
            )
            self.patches.append((name, mask, copy.deepcopy(body.get(mask))))
            if reverting and case in self.refuse_revert:
                return _error(400, "FAILED_PRECONDITION", "injected revert refusal")
            if not reverting and case in self.refuse_apply:
                return _error(
                    501,
                    "UNIMPLEMENTED",
                    "single-field exemptions have no runtime transition",
                )
            if reverting and case in self.ignore_revert:
                # Acknowledged with a done operation, but the field is left as is.
                return _ok(self._operation(name, mask))
            if not reverting and case in self.answer_without_operation:
                self._apply(field, name, mask, body, reverting=False)
                return _ok({"metadata": {"field": name, "state": "PROCESSING"}})
            if not reverting and case in self.answer_5xx:
                self._apply(field, name, mask, body, reverting=False)
                return _error(503, "UNAVAILABLE", "injected 5xx after apply")
            if not reverting and case in self.raise_after_apply:
                self._apply(field, name, mask, body, reverting=False)
                raise ConnectionResetError(
                    "injected failure after the patch was applied"
                )
            outcome = self._apply(field, name, mask, body, reverting)
            if outcome is not None:
                return outcome
            return _ok(self._operation(name, mask))
        return _error(404, "NOT_FOUND", f"no route for {method} {path}")

    def _apply(self, field, name, mask, body, reverting):
        if mask == "ttlConfig":
            if reverting:
                field.pop("ttlConfig", None)
            else:
                field["ttlConfig"] = {"state": "ACTIVE"}
        elif mask == "indexConfig":
            if reverting:
                self.fields.pop(name)
                self.field(name)
            else:
                field["indexConfig"] = {"indexes": [], "usesAncestorConfig": False}
        else:
            return _error(400, "INVALID_ARGUMENT", "unknown update mask")
        return None
