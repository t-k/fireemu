"""Process-boundary tests for the external O8 archive bootstrap."""

import hashlib
import io
import os
import py_compile
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
BOOTSTRAP = HERE / "o8_fd_bootstrap.py"


def archive(main: str, *, include_main: bool = True) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as bundle:
        if include_main:
            bundle.writestr("__main__.py", main)
        else:
            bundle.writestr("other.py", main)
    return output.getvalue()


class BootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.marker = self.root / "ran"
        self.main = f"from pathlib import Path\nPath({str(self.marker)!r}).write_text('archive main')\n"
        self.good = archive(self.main)
        self.digest = hashlib.sha256(self.good).hexdigest()

    def run_bootstrap(
        self,
        content: bytes,
        *,
        expected: str | None = None,
        fd_argument: str | None = None,
        close_fd: bool = False,
        linked: bool = False,
        writable: bool = False,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        path = self.root / "archive.pyz"
        path.write_bytes(content)
        os.chmod(path, 0o600)
        fd = os.open(path, os.O_RDWR if writable else os.O_RDONLY)
        try:
            if not linked:
                path.unlink()
            argument = fd_argument if fd_argument is not None else str(fd)
            command = [sys.executable, "-I", "-S", "-B", str(BOOTSTRAP), argument, expected or self.digest]
            return subprocess.run(
                command,
                pass_fds=() if close_fd else (fd,),
                cwd=self.root,
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        finally:
            os.close(fd)

    def test_valid_owned_archive_runs_main(self) -> None:
        result = self.run_bootstrap(self.good)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.marker.read_text(), "archive main")

    def test_archive_main_observes_fd_origin_and_isolated_flags(self) -> None:
        report = self.root / "origin"
        source = (
            "import sys\n"
            "from pathlib import Path\n"
            f"Path({str(report)!r}).write_text(repr((__file__, sys.argv[0], "
            "sys.flags.isolated, sys.flags.no_site, sys.flags.dont_write_bytecode)))\n"
        )
        content = archive(source)
        result = self.run_bootstrap(content, expected=hashlib.sha256(content).hexdigest())
        self.assertEqual(result.returncode, 0, result.stderr)
        observed = report.read_text()
        self.assertIn("/dev/fd/", observed)
        self.assertIn("1, 1, 1", observed)

    def test_changed_archive_refuses_before_main(self) -> None:
        changed = bytearray(self.good)
        changed[0] ^= 1
        result = self.run_bootstrap(bytes(changed))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.marker.exists())

    def test_wrong_or_closed_descriptor_refuses_before_main(self) -> None:
        for argument, closed in (("999999", False), (None, True)):
            with self.subTest(argument=argument, closed=closed):
                result = self.run_bootstrap(self.good, fd_argument=argument, close_fd=closed)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.marker.exists())

    def test_linked_or_writable_descriptor_refuses_before_main(self) -> None:
        for options in ({"linked": True}, {"writable": True}):
            with self.subTest(options=options):
                result = self.run_bootstrap(self.good, **options)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.marker.exists())

    def test_preexisting_writable_alias_can_change_archive_after_validation(self) -> None:
        original = self.good
        mutated_main = (
            f"from pathlib import Path\nPath({str(self.marker)!r}).write_text('mutated main')\n"
        )
        mutated = archive(mutated_main)
        self.assertEqual(len(mutated), len(original))

        path = self.root / "archive.pyz"
        path.write_bytes(original)
        os.chmod(path, 0o600)
        writer = os.open(path, os.O_RDWR)
        reader = os.open(path, os.O_RDONLY)
        path.unlink()
        verified = self.root / "verified"
        mutate = self.root / "mutate"
        child = (
            "import os, runpy, sys, time\n"
            "bootstrap = runpy.run_path(sys.argv[1])\n"
            "fd = int(sys.argv[2])\n"
            "bootstrap['verify'](fd, sys.argv[3])\n"
            "open(sys.argv[4], 'w').close()\n"
            "while not os.path.exists(sys.argv[5]): time.sleep(0.001)\n"
            "os.set_inheritable(fd, True)\n"
            "os.execv(sys.executable, [sys.executable, '-I', '-S', '-B', f'/dev/fd/{fd}'])\n"
        )
        result: subprocess.Popen[str] | None = None
        try:
            result = subprocess.Popen(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    "-c",
                    child,
                    str(BOOTSTRAP),
                    str(reader),
                    self.digest,
                    str(verified),
                    str(mutate),
                ],
                cwd=self.root,
                pass_fds=(reader,),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for _ in range(1000):
                if verified.exists():
                    break
                time.sleep(0.001)
            else:
                self.fail("bootstrap did not finish validation")
            self.assertEqual(os.pwrite(writer, mutated, 0), len(mutated))
            mutate.touch()
            stdout, stderr = result.communicate(timeout=10)
            self.assertEqual(result.returncode, 0, stderr or stdout)
            self.assertEqual(self.marker.read_text(), "mutated main")
        finally:
            if result is not None and result.poll() is None:
                result.terminate()
                result.wait(timeout=10)
            os.close(reader)
            os.close(writer)

    def test_alternate_valid_zip_or_missing_main_refuses_before_main(self) -> None:
        for content in (archive(self.main + "# alternate\n"), archive(self.main, include_main=False)):
            with self.subTest(content_hash=hashlib.sha256(content).hexdigest()):
                result = self.run_bootstrap(content)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.marker.exists())

    def test_missing_main_refuses_even_with_matching_digest(self) -> None:
        content = archive(self.main, include_main=False)
        result = self.run_bootstrap(content, expected=hashlib.sha256(content).hexdigest())
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.marker.exists())

    def test_shadow_modules_environment_and_pyc_do_not_run_before_validation(self) -> None:
        shadow_marker = self.root / "shadow"
        shadow = f"from pathlib import Path\nPath({str(shadow_marker)!r}).write_text('shadow')\n"
        for name in ("argparse.py", "sitecustomize.py"):
            path = self.root / name
            path.write_text(shadow)
            py_compile.compile(str(path), cfile=str(path.with_suffix(".pyc")), doraise=True)
        env = dict(os.environ, PYTHONPATH=str(self.root))
        result = self.run_bootstrap(archive(self.main + "# changed\n"), env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.marker.exists())
        self.assertFalse(shadow_marker.exists())
        result = self.run_bootstrap(self.good, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.marker.read_text(), "archive main")
        self.assertFalse(shadow_marker.exists())


if __name__ == "__main__":
    unittest.main()
