"""Starts the real Python runner and talks to it the way the daemon does."""

import json
import os
import subprocess
import sys
import threading
import urllib.error
import urllib.request

from conftest import FIXTURE, RUNNER_DIR

SECRET = "test-runner-secret"
SCRIPT = RUNNER_DIR / "runner.py"


def read_runner_frame(stream):
    """One runner-to-daemon frame (`hello`, `result`, `log`), or None at the end of the stream."""
    header = b""
    while True:
        byte = stream.read(1)
        if not byte:
            assert header == b"", f"stream ended inside a frame header: {header!r}"
            return None
        if byte == b"\n":
            break
        assert byte.isdigit(), f"a non-digit in a frame header: {header + byte!r}"
        header += byte
    assert header and not header.startswith(b"0"), f"not a canonical length: {header!r}"
    payload = stream.read(int(header))
    assert len(payload) == int(header), "short frame body"
    return json.loads(payload.decode("utf-8"))


class Runner:
    """A runner process on a codebase; frames it sends are collected, and `stderr` is kept."""

    def __init__(self, source=FIXTURE, extra_env=None, name="default"):
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", ""),
            "GCLOUD_PROJECT": "demo-proj",
            "GOOGLE_CLOUD_PROJECT": "demo-proj",
            "FIREEMU_RUNNER_SECRET": SECRET,
            "FIRESTORE_EMULATOR_HOST": "127.0.0.1:9",
            "FIREBASE_AUTH_EMULATOR_HOST": "127.0.0.1:9",
            "METADATA_SERVER_DETECTION": "none",
            "PYTHONUNBUFFERED": "1",
        }
        env.update(extra_env or {})
        self.process = subprocess.Popen(
            [sys.executable, str(SCRIPT), "--source", str(source), "--codebase", name],
            cwd=str(source),
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.frames = []
        self._cond = threading.Condition()
        self._stderr = []
        self._readers = [
            threading.Thread(target=self._pump_stdout, daemon=True),
            threading.Thread(target=self._pump_stderr, daemon=True),
        ]
        for reader in self._readers:
            reader.start()

    def _pump_stdout(self):
        try:
            while (frame := read_runner_frame(self.process.stdout)) is not None:
                with self._cond:
                    self.frames.append(frame)
                    self._cond.notify_all()
        except Exception as error:  # a corrupt frame is recorded as a failure the test can see
            with self._cond:
                self.frames.append({"type": "corrupt", "error": repr(error)})
                self._cond.notify_all()

    def _pump_stderr(self):
        for line in self.process.stderr:
            with self._cond:
                self._stderr.append(line.decode("utf-8", "replace"))

    @property
    def stderr(self):
        with self._cond:
            return "".join(self._stderr)

    def wait_frame(self, predicate, timeout=20):
        with self._cond:
            if not self._cond.wait_for(lambda: any(predicate(frame) for frame in self.frames), timeout):
                raise AssertionError(f"no matching frame; got {self.frames}; stderr:\n{self.stderr}")
            return next(frame for frame in self.frames if predicate(frame))

    def hello(self):
        return self.wait_frame(lambda frame: frame["type"] == "hello")

    def send(self, message):
        from fireemu_runner.framing import encode_frame

        self.process.stdin.write(encode_frame(message))
        self.process.stdin.flush()

    def send_raw(self, data: bytes):
        self.process.stdin.write(data)
        self.process.stdin.flush()

    def invoke(self, invocation_id, function, trigger, event, entry_point=None):
        message = {"type": "invoke", "invocationId": invocation_id, "function": function, "trigger": trigger, "event": event}
        if entry_point is not None:
            message["entryPoint"] = entry_point
        self.send(message)
        return self.wait_frame(lambda frame: frame["type"] == "result" and frame["invocationId"] == invocation_id)

    def url(self, path):
        return f"http://127.0.0.1:{self.hello()['httpPort']}{path}"

    def request(self, path, *, method="GET", body=None, headers=None, secret=SECRET):
        request_headers = dict(headers or {})
        if secret is not None:
            request_headers["x-fireemu-runner-secret"] = secret
        data = body if isinstance(body, bytes) or body is None else json.dumps(body).encode()
        if isinstance(body, dict) and "content-type" not in {k.lower() for k in request_headers}:
            request_headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.url(path), data=data, method=method, headers=request_headers)
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as error:
            return error.code, dict(error.headers), error.read()

    def seen(self):
        status, _, body = self.request("/demo-proj/us-central1/seen")
        assert status == 200, body
        return json.loads(body)

    def close(self, timeout=10):
        """Closes stdin and waits; returns the exit code."""
        try:
            self.process.stdin.close()
        except Exception:
            pass
        try:
            return self.process.wait(timeout)
        finally:
            for stream in (self.process.stdout, self.process.stderr):
                try:
                    stream.close()
                except Exception:
                    pass

    def kill(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()
