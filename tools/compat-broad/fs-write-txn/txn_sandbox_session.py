"""One source-bound transaction acquisition with durable resource responsibility."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

import txn_expiry_collector as collector
import txn_expiry_plan as plan_module
import txn_sandbox_contract as contract
import txn_sandbox_management as management
import txn_sandbox_wire as wire_module


def _access_token():
    try:
        result = subprocess.run(
            ["gcloud", "auth", "application-default", "print-access-token"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError("OAuth acquisition failed") from None
    token = result.stdout.strip()
    if not token or len(token) > 8192 or any(ord(ch) <= 32 for ch in token):
        raise ValueError("OAuth acquisition returned no bounded credential")
    return token


def _responsibility_writer(path):
    """Persist each allowlisted responsibility state with atomic replace and fsync."""
    path = Path(path)

    def write(snapshot):
        encoded = (json.dumps(snapshot, ensure_ascii=False, sort_keys=True) + "\n").encode()
        if len(encoded) > 65_536 or any(
            marker.encode() in encoded for marker in contract.SECRET_MARKERS
        ):
            raise ValueError("bounded secret-free responsibility required")
        fd, temp_name = tempfile.mkstemp(prefix=".responsibility-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, path)
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    return write


def run_once(
    nonce,
    owner_id,
    run_dir,
    baseline,
    *,
    credential_fn=_access_token,
    metadata_factory=management.MetadataSession,
    wire_factory=wire_module.FixedDataWire,
    collector_factory=collector.Collection,
):
    """Return one secret-free receipt; management precedes data and follows cleanup."""
    plan = plan_module.compile_plan(nonce, owner_id)
    contract.validate_scope(plan)
    budget = contract.RequestBudget(plan)
    run_dir = Path(run_dir)
    if not run_dir.is_dir():
        raise ValueError("private run directory is missing")
    budget.charge("credential")
    token = credential_fn()
    metadata = metadata_factory(token, baseline, budget)
    before = metadata.preflight()
    data = wire_factory(token, budget)
    options = {
        "target": "production",
        "host": collector.PRODUCTION_HOST,
        "projectId": contract.PROJECT,
        "database": contract.DATABASE,
        "nonce": nonce,
        "ownerId": owner_id,
        "timing": collector.WALL_CLOCK,
        "deadlineSeconds": plan_module.WALL_SECONDS,
    }
    collection = collector_factory(
        options,
        plan,
        data,
        responsibility=_responsibility_writer(run_dir / "responsibility.json"),
    )
    receipt = collection.run()
    if not isinstance(receipt, dict):
        raise ValueError("collector returned no bounded receipt")
    receipt["preflight"] = before
    receipt["postflight"] = None
    if receipt.get("complete") is True:
        try:
            receipt["postflight"] = metadata.postflight()
        except Exception as error:  # noqa: BLE001 -- keep the resource receipt and stop review.
            receipt["complete"] = False
            receipt["failure"] = f"postflight-{type(error).__name__}"
    receipt["sandboxRequests"] = budget.total
    return receipt
