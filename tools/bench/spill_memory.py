#!/usr/bin/env python3
"""Storage spill memory measurement: N single-shot uploads, then resident memory of the daemon.

Linux only (reads VmRSS from /proc). Runs one fresh daemon per call and stops it with SIGINT, then
checks that its spill directory is gone. Standard library only.
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

SPILL_THRESHOLD = 1024 * 1024
BUCKET = "demo-bucket"


def parse_vmrss_kib(status_text: str) -> int:
    for line in status_text.splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    raise ValueError("no VmRSS line in /proc status")


def read_rss_kib(pid: int) -> int:
    return parse_vmrss_kib(Path(f"/proc/{pid}/status").read_text())


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_port(port: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def upload(port: int, name: str, body: bytes) -> int:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=600)
    try:
        path = f"/upload/storage/v1/b/{BUCKET}/o?uploadType=media&name={name}"
        conn.request("POST", path, body=body, headers={"Content-Type": "application/octet-stream"})
        response = conn.getresponse()
        response.read()
        return response.status
    finally:
        conn.close()


def spill_entries(root: Path) -> list[str]:
    found = []
    if root.exists():
        for dirpath, dirnames, filenames in os.walk(root):
            for name in dirnames + filenames:
                if name.startswith("fireemu-spill-") or name.startswith("spill-"):
                    found.append(os.path.join(dirpath, name))
    return found


def measure(binary: Path, mode: str, objects: int, size_mib: int, out: Path) -> dict:
    work = Path(tempfile.mkdtemp(prefix="spill-memory-"))
    home = work / "home"
    tmp = work / "tmp"
    home.mkdir()
    tmp.mkdir()
    config = work / "config.json"
    body_config: dict = {"schemaVersion": 1}
    if mode == "on":
        body_config["storage"] = {"spillObjectBytes": SPILL_THRESHOLD}
    config.write_text(json.dumps(body_config))
    port = free_port()
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home), "TMPDIR": str(tmp) + "/"}
    log = open(work / "daemon.log", "w")
    proc = subprocess.Popen(
        [str(binary), "up", "--no-config-discovery", "--config", str(config), "--only", "storage",
         "--storage-port", str(port), "--ui-port", "0", "--project", "demo-app"],
        env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
    )
    samples: list[int] = []
    stop_sampling = threading.Event()

    def sampler() -> None:
        while not stop_sampling.is_set() and proc.poll() is None:
            try:
                samples.append(read_rss_kib(proc.pid))
            except OSError:
                break
            time.sleep(0.2)

    try:
        if not wait_for_port(port, 120):
            raise RuntimeError("the Storage port did not open; see daemon.log")
        time.sleep(2)
        base_kib = read_rss_kib(proc.pid)
        thread = threading.Thread(target=sampler, daemon=True)
        thread.start()
        payload = os.urandom(size_mib * 1024 * 1024)
        codes = [upload(port, f"obj-{n}.bin", payload) for n in range(1, objects + 1)]
        del payload
        time.sleep(5)
        steady_kib = read_rss_kib(proc.pid)
        spill_bytes = sum(
            os.path.getsize(p) for p in spill_entries(tmp) if os.path.isfile(p)
        )
    finally:
        stop_sampling.set()
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        log.close()
    leftover = spill_entries(tmp)
    result = {
        "mode": mode,
        "objects": objects,
        "size_mib": size_mib,
        "statuses": codes,
        "base_rss_kib": base_kib,
        "steady_rss_kib": steady_kib,
        "peak_rss_kib": max(samples + [steady_kib]),
        "spill_file_bytes_before_stop": spill_bytes,
        "leftover_spill_entries_after_stop": len(leftover),
        "daemon_exit_code": proc.returncode,
    }
    out.write_text(json.dumps(result, indent=2) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fireemu", required=True, type=Path)
    parser.add_argument("--mode", choices=["off", "on"], required=True)
    parser.add_argument("--objects", type=int, default=20)
    parser.add_argument("--size-mib", type=int, default=50)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        print("spill_memory.py reads /proc and runs on Linux only", file=sys.stderr)
        return 2
    if not 1 <= args.objects <= 200 or not 1 <= args.size_mib <= 256:
        print("objects must be 1 to 200 and size-mib 1 to 256", file=sys.stderr)
        return 2
    result = measure(args.fireemu, args.mode, args.objects, args.size_mib, args.out)
    print(json.dumps(result))
    ok = all(code == 200 for code in result["statuses"]) and result["leftover_spill_entries_after_stop"] == 0
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
