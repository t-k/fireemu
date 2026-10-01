#!/usr/bin/env python3
"""Resident memory of a fireemu daemon around a Firestore export (Linux, /proc only).

Fills the default database with N small documents over REST (owner credential, batches of
500), then runs `fireemu emulators:export` against the running daemon and reports VmRSS
before, the VmHWM peak, and VmRSS right after and some seconds after the export, as JSON
lines. The question it answers is whether the memory an export allocates is returned to the
system afterwards. Standard library only.

Usage: firestore_export_rss.py <fireemu binary> <work dir> <documents> [payload bytes]
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def status(pid: int) -> dict[str, int]:
    out = {}
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            key, _, rest = line.partition(":")
            if key in ("VmRSS", "VmHWM"):
                out[key] = int(rest.split()[0])
    return out


def mib(kib: int) -> float:
    return round(kib / 1024, 1)


def main() -> int:
    binary, work, count = sys.argv[1], sys.argv[2], int(sys.argv[3])
    payload = "x" * (int(sys.argv[4]) if len(sys.argv) > 4 else 1024)
    os.makedirs(work, exist_ok=True)
    project = "demo-export-rss"
    ports = {name: free_port() for name in ("fs", "hub", "http", "st")}
    with open(os.path.join(work, "fireemu.json"), "w") as f:
        json.dump({"schemaVersion": 1, "profile": "emulator",
                   "firestore": {"edition": "standard", "apiMode": "native"}}, f)
    daemon = subprocess.Popen(
        [binary, "up", "--config", os.path.join(work, "fireemu.json"), "--only", "firestore",
         "--project", project, "--firestore-port", str(ports["fs"]),
         "--hub-port", str(ports["hub"]), "--http-port", str(ports["http"]),
         "--storage-port", str(ports["st"]), "--ui-port", "0", "--logging-port", "0",
         "--log-verbosity", "quiet"],
        cwd=work, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={"PATH": os.environ.get("PATH", ""), "HOME": work})
    try:
        base = f"http://127.0.0.1:{ports['fs']}/v1/projects/{project}/databases/(default)/documents"
        for _ in range(300):
            try:
                with socket.create_connection(("127.0.0.1", ports["fs"]), timeout=1):
                    break
            except OSError:
                time.sleep(0.1)
        time.sleep(0.5)
        print(json.dumps({"event": "ready", "rss_mib": mib(status(daemon.pid)["VmRSS"])}), flush=True)
        done = 0
        while done < count:
            writes = []
            for _ in range(min(500, count - done)):
                writes.append({"update": {
                    "name": f"projects/{project}/databases/(default)/documents/items/{done:09d}",
                    "fields": {"i": {"integerValue": str(done)}, "payload": {"stringValue": payload}}}})
                done += 1
            request = urllib.request.Request(
                f"{base}:commit", data=json.dumps({"writes": writes}).encode(), method="POST",
                headers={"Content-Type": "application/json", "Authorization": "Bearer owner"})
            with urllib.request.urlopen(request, timeout=120) as response:
                response.read()
        time.sleep(3)
        before = status(daemon.pid)
        print(json.dumps({"event": "filled", "documents": count, "payload_bytes": len(payload),
                          "rss_mib": mib(before["VmRSS"]), "hwm_mib": mib(before["VmHWM"])}), flush=True)
        exported = subprocess.run(
            [binary, "emulators:export", os.path.join(work, "export"), "--project", project, "--force"],
            cwd=work, capture_output=True, text=True,
            env={"PATH": os.environ.get("PATH", ""), "HOME": work,
                 "FIREBASE_EMULATOR_HUB": f"127.0.0.1:{ports['hub']}"})
        after = status(daemon.pid)
        print(json.dumps({"event": "exported", "code": exported.returncode,
                          "rss_mib": mib(after["VmRSS"]), "hwm_mib": mib(after["VmHWM"]),
                          "stderr_tail": exported.stderr[-300:]}), flush=True)
        for wait in (5, 30):
            time.sleep(wait)
            print(json.dumps({"event": "settled", "seconds": wait,
                              "rss_mib": mib(status(daemon.pid)["VmRSS"])}), flush=True)
        return 0 if exported.returncode == 0 else 1
    finally:
        daemon.terminate()
        try:
            daemon.wait(timeout=10)
        except subprocess.TimeoutExpired:
            daemon.kill()
            daemon.wait()


if __name__ == "__main__":
    sys.exit(main())
