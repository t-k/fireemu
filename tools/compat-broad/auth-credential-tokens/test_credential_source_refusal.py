"""Frozen historical source evidence, never a live production request."""

import importlib.util
import sys
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "production-admission"))
from test_auth_source_refusal import (
    historical_source,  # noqa: F401 -- shared explicit fixture
)


def test_frozen_production_signup_rejects_before_request_construction(
    historical_source,  # noqa: F811 -- pytest fixture injection
):
    import credential_source_refusal as refusal

    source, hashes = historical_source
    refusal.validate_source(source, hashes)
    path = source / refusal.WORKER
    spec = importlib.util.spec_from_file_location("historical_worker", path)
    worker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(worker)
    previous = urllib.request.Request
    calls = []

    def forbidden(*args, **kwargs):
        calls.append(True)
        raise AssertionError("network request construction forbidden")

    urllib.request.Request = forbidden
    try:
        for body in ("{}", '{"password":"synthetic"}', "null"):
            with pytest.raises(ValueError, match="project authority"):
                worker.exchange(
                    {
                        "url": "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=synthetic",
                        "body": body,
                        "headers": {},
                        "seconds": 1,
                    },
                    fixture=False,
                )
        assert calls == []
    finally:
        urllib.request.Request = previous
