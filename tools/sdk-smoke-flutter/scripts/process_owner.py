#!/usr/bin/env python3
"""Keep the owned session leader alive until the caller finishes group cleanup."""
import os
import signal
import subprocess
import sys
import threading

signal.signal(signal.SIGTERM, lambda *_: None)
result_fd = int(sys.argv[1])
go_fd = int(sys.argv[2])
os.write(result_fd, ('READY ' + str(os.getpid()) + '\n').encode())
if os.read(go_fd, 3) != b'GO\n':
    sys.exit(125)

def stop_own_group():
    # This still-running session leader owns its PID; it cannot have been reused.
    if os.getpgid(0) == os.getpid():
        os.killpg(os.getpid(), signal.SIGKILL)


def parent_lifeline():
    try:
        while os.read(go_fd, 1):
            pass
    except OSError:
        pass
    stop_own_group()


threading.Thread(target=parent_lifeline, daemon=True).start()
try:
    status = subprocess.call(sys.argv[3:], close_fds=True)
except OSError:
    status = 127
try:
    os.write(result_fd, (str(status) + '\n').encode())
except BrokenPipeError:
    stop_own_group()
os.close(result_fd)
while True:
    signal.pause()
