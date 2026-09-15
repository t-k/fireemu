"""Campaign-owned typed facade over the frozen shared Gate."""

from __future__ import annotations

import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shared_gate import Gate as FrozenGate
from shared_gate import _save, create


def validate(operation):
    kind = operation.get("operationType")
    if kind is None:
        raise ValueError("typed operation required")
    if not isinstance(operation.get("principal"), str) or not operation["principal"]:
        raise ValueError("typed principal required")
    if not isinstance(operation.get("resource"), str) or not operation["resource"]:
        raise ValueError("typed resource required")
    provenance = operation.get("provenance")
    if not isinstance(provenance, dict) or not provenance.get("source"):
        raise ValueError("typed provenance required")
    if kind == "auth-refresh" and (
        provenance.get("token") != "owned-refresh-token"
        or not isinstance(operation.get("body"), dict)
        or operation["body"].get("grant_type") != "refresh_token"
        or not operation["body"].get("refresh_token")
    ):
        raise ValueError("owned refresh token required")
    if kind == "auth-delete" and (
        operation.get("method") != "POST"
        or ":delete" not in operation.get("path", "")
        or not isinstance(operation.get("body"), dict)
        or not operation["body"].get("localId")
    ):
        raise ValueError("typed Auth delete required")
    if kind == "firestore-list-collection-ids":
        body = operation.get("body")
        resource = operation.get("resource")
        if (
            operation.get("method") != "POST"
            or not isinstance(resource, str)
            or operation.get("path") != "/v1/" + resource + ":listCollectionIds"
        ):
            raise ValueError("ListCollectionIds wire shape required")
        if not isinstance(body, dict) or "parent" in body:
            raise ValueError("ListCollectionIds parent must be in URL")
        if body.get("pageToken") is not None and (
            provenance.get("pageToken") != "observed-continuation"
            or provenance.get("tokenValue") != body["pageToken"]
            or provenance.get("consumed") is not False
        ):
            raise ValueError("page token provenance or single-use binding required")


class CampaignGate(FrozenGate):
    def __init__(self, path, job):
        super().__init__(path, job)
        self.bindings = {}

    def bind(self, name, value):
        if not isinstance(name, str) or not isinstance(value, str) or not value:
            raise ValueError("runtime binding required")
        self.bindings[name] = value

    def _template(self, value):
        if isinstance(value, str):
            for name, actual in self.bindings.items():
                if value == actual:
                    return "$binding:" + name
            return value
        if isinstance(value, dict):
            return {key: self._template(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._template(item) for item in value]
        return value

    def dispatch(self, operation, recovery, send):
        validate(operation)
        normalized = copy.deepcopy(operation)
        normalized = self._template(normalized)
        # The frozen gate compares the closed recipe; typed metadata remains bound.
        result = super().dispatch(normalized, recovery, send)
        if recovery and operation.get("operationType") == "auth-lookup":
            status, body = result or (None, None)
            if status == 200 and isinstance(body, dict) and body.get("users", []) == []:
                route = operation["path"].split("?", 1)[0].removeprefix("/v1/")
                with self.locked() as state:
                    absent = state["jobs"][self.job]["absent"]
                    if route not in absent:
                        absent.append(route)
                        _save(self.path, state)
        return result

    def adapter_request(self, adapter, operation, send):
        extra = getattr(adapter, "campaign_operation", {})
        merged = {**operation, **extra}
        validate(merged)
        return super().adapter_request(adapter, merged, send)


__all__ = ["CampaignGate", "create", "validate"]
