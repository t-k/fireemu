#!/usr/bin/env python3
"""Negative-control helpers for the stage3 launch-accounting harness (design v4 section 7).

Each mode leaves the runner's process group before it writes its ready file (follow-up F1), so a
`kill_now` of the runner's group cannot remove it, and ends itself after HOLD seconds. Only a
control fixture starts these; the refusal fixture never does.

  orphan READY HOLD            (i)   new process group, reparented to launchd, still in the session
  escaper READY HOLD           (ii)  a new session (setsid first: it is not a group leader)
  listener READY PORTFILE BOUND HOLD
                               (iii) a new session that binds the claimed port, retrying until it can
  leftover READY HOLD          (iv)  its own process group, staying a child of its parent
"""
import json
import os
import socket
import sys
import time


def ready(path, **extra):
    info = {
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "pgid": os.getpgid(0),
        "sid": os.getsid(0),
        **extra,
    }
    temp = path + ".tmp"
    with open(temp, "w") as handle:
        json.dump(info, handle)
    os.replace(temp, path)


def wait_for(path, seconds):
    deadline = time.monotonic() + seconds
    while not os.path.exists(path):
        if time.monotonic() > deadline:
            raise SystemExit("helper did not become ready")
        time.sleep(0.02)


def main(argv):
    mode = argv[1]
    if mode == "orphan":
        path, hold = argv[2], float(argv[3])
        if os.fork():
            # The starter returns only once the grandchild is in its own group.
            wait_for(path, 10)
            return 0
        os.setpgid(0, 0)
        if os.fork():
            os._exit(0)
        ready(path)
        time.sleep(hold)
        return 0
    if mode == "escaper":
        path, hold = argv[2], float(argv[3])
        os.setsid()
        ready(path)
        time.sleep(hold)
        return 0
    if mode == "listener":
        path, port_file, bound_file, hold = argv[2], argv[3], argv[4], float(argv[5])
        os.setsid()
        ready(path)
        with open(port_file) as handle:
            port = int(json.load(handle)["port"])
        deadline = time.monotonic() + hold
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while True:
            try:
                server.bind(("127.0.0.1", port))
                break
            except OSError:
                if time.monotonic() > deadline:
                    return 1
                time.sleep(0.1)
        server.listen(1)
        temp = bound_file + ".tmp"
        with open(temp, "w") as handle:
            json.dump({"port": port, "boundAt": time.time()}, handle)
        os.replace(temp, bound_file)
        time.sleep(max(0.0, deadline - time.monotonic()))
        return 0
    if mode == "leftover":
        path, hold = argv[2], float(argv[3])
        os.setpgid(0, 0)
        ready(path)
        time.sleep(hold)
        return 0
    raise SystemExit("unknown helper mode")


if __name__ == "__main__":
    sys.exit(main(sys.argv))
