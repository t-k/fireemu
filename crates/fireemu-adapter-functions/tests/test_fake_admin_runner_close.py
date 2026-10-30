"""Verify the fake runner closes stdin before it requests a verdict."""

import json
import subprocess
import sys
import unittest
from pathlib import Path


class RunnerCloseOrder(unittest.TestCase):
    def test_stdin_is_closed_when_verify_request_arrives(self):
        runner = Path(__file__).with_name("fake_admin_runner.py")
        with subprocess.Popen(
            [sys.executable, str(runner)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0
        ) as child:
            try:
                def read_frame():
                    length = int(child.stdout.readline())
                    return json.loads(child.stdout.read(length))

                self.assertEqual(read_frame()["type"], "hello")
                event = {
                    "requests": [{"requestId": "r", "projectId": "p", "token": "t"}],
                    "closeStdin": True,
                    "closeDelaySeconds": 1,
                }
                payload = json.dumps({"type": "invoke", "event": event}).encode()
                child.stdin.write(str(len(payload)).encode() + b"\n" + payload)
                child.stdin.flush()
                self.assertEqual(read_frame()["type"], "appCheck:verify")
                with self.assertRaises(BrokenPipeError):
                    child.stdin.write(b"probe")
                    child.stdin.flush()
            finally:
                child.kill()
                child.wait()


if __name__ == "__main__":
    unittest.main()
