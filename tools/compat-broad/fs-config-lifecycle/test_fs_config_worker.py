"""The fixed HTTPS worker admits exactly the campaign's routes and nothing joined."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from fs_config_lifecycle import lifecycle_https_worker as worker
from fs_config_lifecycle import lifecycle_remote_transport as transport
from fs_config_lifecycle.cases import compile_cases, locked_steps
from fs_config_lifecycle.lifecycle_collector import (
    RECONCILIATION_FILTERS,
    http_request,
    request_url_path,
)

NONCE = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
OPERATION = "projects/fireemu-35fe6/databases/(default)/operations/op-00_1.a"


def _campaign_routes() -> list[str]:
    routes = []
    for case in compile_cases(NONCE):
        extra = {"operation_name": OPERATION} if case["id"] == "OC-22" else {}
        routes.append(request_url_path(http_request(case, **extra)))
    for step in locked_steps(NONCE):
        parent = step["resource"].rsplit("/fields/", 1)[0]
        for _label, filter_ in RECONCILIATION_FILTERS:
            routes.append(
                request_url_path(
                    {
                        "path": f"/v1/{parent}/fields",
                        "query": {"filter": filter_, "pageSize": "20"},
                    }
                )
            )
    return routes


def test_every_campaign_route_and_reconciliation_read_is_admitted_by_the_worker() -> (
    None
):
    routes = _campaign_routes()
    assert len(routes) == 12 + 4
    for route in routes:
        assert worker._PATH.fullmatch(route), route


def test_a_concatenation_of_two_routes_and_any_other_database_are_refused() -> None:
    routes = _campaign_routes()
    for left in routes[:3]:
        for right in routes[:3]:
            if left != right:
                assert not worker._PATH.fullmatch(left + right.removeprefix("/v1")), (
                    left,
                    right,
                )
    joined = (
        "/v1/projects/fireemu-35fe6/databases?showDeleted=false/(default)/"
        "collectionGroups/fsconfig_ttl_a1b2c3d4e5f6/fields/expiresAt"
    )
    assert not worker._PATH.fullmatch(joined)
    for refused in (
        "/v1/projects/fireemu-35fe6/databases/other",
        "/v1/projects/fireemu-35fe6/databases/(default)/documents/c/d",
        "/v1/projects/other-project/databases/(default)",
        "/v1/projects/fireemu-35fe6/databases/(default)/collectionGroups/users/fields/x",
        (
            "/v1/projects/fireemu-35fe6/databases/(default)/collectionGroups/"
            "fsconfig_ttl_a1b2c3d4e5f6/fields/expiresAt?updateMask=indexConfig,ttlConfig"
        ),
        (
            "/v1/projects/fireemu-35fe6/databases/(default)/collectionGroups/"
            "fsconfig_ttl_a1b2c3d4e5f6/fields?filter=ttlConfig%3A%2A&pageSize=200"
        ),
        "/v1/projects/fireemu-35fe6/databases:import",
        "/v1/projects/fireemu-35fe6/databases/(default)/operations/a/b",
    ):
        assert not worker._PATH.fullmatch(refused), refused


def test_the_transport_pins_the_worker_bytes_on_disk() -> None:
    source = Path(worker.__file__).read_bytes()
    assert hashlib.sha256(source).hexdigest() == transport._WORKER_SHA256
    assert re.fullmatch(r"[0-9a-f]{64}", transport._WORKER_SHA256)
