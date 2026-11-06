#!/usr/bin/env python3
"""Keep the owned session leader alive until the caller finishes group cleanup."""
import os
import signal
import subprocess
import sys

signal.signal(signal.SIGTERM, lambda *_: None)
result_fd = int(sys.argv[1])
go_fd = int(sys.argv[2])
os.write(result_fd, ('READY ' + str(os.getpid()) + '\n').encode())
if os.read(go_fd, 3) != b'GO\n':
    sys.exit(125)
os.close(go_fd)
try:
    status = subprocess.call(sys.argv[3:], close_fds=True)
except OSError:
    status = 127
os.write(result_fd, (str(status) + '\n').encode())
os.close(result_fd)
while True:
    signal.pause()
