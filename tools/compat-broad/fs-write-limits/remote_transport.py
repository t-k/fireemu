"""Fixed-target limits wire worker. Production permission belongs to the caller's Gate.

This module neither acquires credentials nor approves a campaign. The parent and
worker independently match every request to the closed compiler operation.
"""

# ruff: noqa: BLE001 -- Worker errors must never serialize secret input.
from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote, unquote

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from compiler import compile_limits_plan
from transport import MAX_CAP, _exchange

PROJECT = "fireemu-35fe6"
ORIGIN = "https://firestore.googleapis.com"
TIMEOUT = 12
INPUT_CAP = 4 * 1024 * 1024


def _json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def prepare(value):
    if not isinstance(value, dict) or set(value) != {
        "nonce",
        "phase",
        "index",
        "operation",
        "token",
    }:
        raise ValueError("closed wire input required")
    token = value["token"]
    if (
        not isinstance(token, str)
        or len(token) > 8192
        or not re.fullmatch(r"[A-Za-z0-9._~+/-]{1,8192}=*", token)
    ):
        raise ValueError("invalid credential shape")
    phase, index = value["phase"], value["index"]
    if phase not in ("observation", "recovery") or type(index) is not int:
        raise ValueError("invalid operation position")
    plan = compile_limits_plan(PROJECT, "(default)", value["nonce"])
    operations = plan["localGatePlan"]["jobs"]["limits"][phase]
    if not 0 <= index < len(operations):
        raise ValueError("operation outside plan")
    expected = dict(operations[index])
    operation = value["operation"]
    if not isinstance(operation, dict):
        raise TypeError("invalid operation")
    if expected.pop("versionFrom", None) is not None:
        prefix = expected["path"] + "?currentDocument.updateTime="
        path = operation.get("path")
        if not isinstance(path, str) or not path.startswith(prefix):
            raise ValueError("conditional cleanup version required")
        version = unquote(path[len(prefix) :])
        if not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z", version
        ):
            raise ValueError("invalid cleanup version")
        try:
            datetime.strptime(
                version.split(".")[0].removesuffix("Z"), "%Y-%m-%dT%H:%M:%S"
            ).replace(tzinfo=UTC)
        except ValueError:
            raise ValueError("invalid cleanup time") from None
        expected["path"] = prefix + quote(version, safe="")
    if _json(operation) != _json(expected):
        raise ValueError("request differs from closed plan")
    offset = (
        0
        if phase == "observation"
        else len(plan["localGatePlan"]["jobs"]["limits"]["observation"])
    )
    response_cap = plan["requests"][offset + index]["responseByteLimit"]
    data = None if operation["body"] is None else _json(operation["body"]).encode()
    if data is not None and len(data) > MAX_CAP or not 0 < response_cap <= MAX_CAP:
        raise ValueError("compiled request exceeds wire ceiling")
    return {
        "url": ORIGIN + expected["path"],
        "method": expected["method"],
        "data": data,
        "headers": {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + token,
            "x-goog-user-project": PROJECT,
        },
        "response_cap": response_cap,
    }


def request(value):
    """One already-admitted wire operation; secrets travel on stdin, never argv/env."""
    prepare(value)
    encoded = _json(value)
    if len(encoded.encode()) > INPUT_CAP:
        raise ValueError("wire input limit")
    try:
        child = subprocess.run(
            [sys.executable, "-I", str(Path(__file__).resolve()), "--worker"],
            input=encoded,
            text=True,
            capture_output=True,
            env={},
            timeout=TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"kind": "deadline-exceeded", "complete": False}
    if child.returncode != 0:
        return {"kind": "worker-error", "complete": False}
    try:
        result = json.loads(child.stdout)
    except (ValueError, UnicodeDecodeError):
        return {"kind": "worker-error", "complete": False}
    return result


def main():
    raw = sys.stdin.buffer.read(INPUT_CAP + 1)
    if len(raw) > INPUT_CAP:
        raise ValueError("wire input limit")
    args = prepare(json.loads(raw))
    print(json.dumps(_exchange(**args, timeout=TIMEOUT), allow_nan=False))


if __name__ == "__main__":
    try:
        if sys.argv[1:] != ["--worker"]:
            raise ValueError("worker entrypoint only")
        main()
    except Exception:
        sys.exit(2)
