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
        if operation.get("method") != "POST" or not operation.get("path", "").endswith(
            ":listCollectionIds"
        ):
            raise ValueError("ListCollectionIds wire shape required")
        if not isinstance(body, dict) or body.get("parent") != operation["resource"]:
            raise ValueError("ListCollectionIds parent binding required")
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
        extra_resource = None
        if recovery and operation["service"] == "auth":
            extra_resource = operation["path"].split("?", 1)[0].removeprefix("/v1/")
            with self.locked() as state:
                resources = state["jobs"][self.job]["resources"]
                if extra_resource not in resources:
                    resources.append(extra_resource)
                    _save(self.path, state)
        # The frozen gate compares the closed recipe; typed metadata remains bound.
        result = super().dispatch(normalized, recovery, send)
        if extra_resource is not None:
            status = result[0] if result else None
            if (operation["operationType"] == "auth-delete" and status == 200) or (
                operation["operationType"] == "auth-lookup" and status == 404
            ):
                with self.locked() as state:
                    absent = state["jobs"][self.job]["absent"]
                    for resource in (extra_resource, operation["resource"]):
                        if resource not in absent:
                            absent.append(resource)
                        _save(self.path, state)
        return result

    def adapter_request(self, adapter, operation, send):
        extra = getattr(adapter, "campaign_operation", {})
        merged = {**operation, **extra}
        validate(merged)
        return super().adapter_request(adapter, merged, send)


__all__ = ["CampaignGate", "create", "validate"]
