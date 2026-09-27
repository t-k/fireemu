"""Fixed-origin, source-pinned Firestore REST transport for the sandbox run."""

from __future__ import annotations

import hashlib
import json
import time

import txn_expiry_remote_transport as remote
from txn_expiry_remote_transport import _run_process_exchange


class FixedDataWire:
    """One collector request enters the single data budget before dispatch."""

    def __init__(self, token, budget):
        if (
            not isinstance(token, str)
            or not 0 < len(token) <= 8192
            or not all(33 <= ord(character) <= 126 for character in token)
        ):
            raise ValueError("bounded OAuth token required")
        self._token = token
        self.budget = budget
        self._worker = remote.worker_source()
        if hashlib.sha256(self._worker).hexdigest() != remote.WORKER_SHA256:
            raise ValueError("fixed HTTPS worker differs from its reviewed digest")

    def __call__(self, request):
        method, path, body = remote.build(request)
        site = request.get("site")
        if not isinstance(site, str) or not site:
            raise ValueError("a fixed plan site is required")
        phase = "recovery" if site.startswith(("release/", "cleanup/")) else "observation"
        self.budget.charge("data", phase=phase)
        deadline = time.monotonic() + min(
            request["timeoutSeconds"], remote.MAX_SECONDS
        )
        header = {
            "method": method,
            "path": path,
            "authorization": "Bearer " + self._token,
            "project": request["projectId"],
            "bodyBytes": len(body or b""),
            "deadline": deadline,
        }
        payload = json.dumps(header, separators=(",", ":")).encode() + b"\n" + (body or b"")
        try:
            status, content_type, raw, failure = _run_process_exchange(
                worker_source=self._worker,
                worker_sha256=remote.WORKER_SHA256,
                request_payload=payload,
                deadline=deadline,
                response_cap=remote.MAX_RESPONSE_BYTES,
            )
        except Exception as error:  # noqa: BLE001 -- return a bounded incomplete result.
            return remote._incomplete(None, type(error).__name__)
        if failure is not None or type(status) is not int or not 100 <= status <= 599:
            return remote._incomplete(
                status if type(status) is int else None, failure or "status-missing"
            )
        if 300 <= status < 400:
            return remote._incomplete(status, "redirect")
        if content_type.split(";", 1)[0].strip().lower() != "application/json":
            return remote._incomplete(status, "invalid-media-type")
        return remote.normalize(status, raw, request)
