"""Fail-first process contract for the proposed O8 supervised child boundary."""

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
BOOTSTRAP = HERE / "o8_fd_bootstrap.py"
SPEC = importlib.util.spec_from_file_location("o8_bundle", HERE / "o8_bundle.py")
assert SPEC is not None and SPEC.loader is not None
bundle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bundle)


def _archive(tmp_path: Path) -> tuple[bytes, str]:
    main = (
        b"import json, os, sys\n"
        b"from pathlib import Path\n"
        b"import witness\n"
        b"Path(sys.argv[1]).write_text(json.dumps({"
        b"'main': __file__, 'witness': witness.__file__, "
        b"'argv0': sys.argv[0], 'isolated': sys.flags.isolated, "
        b"'no_site': sys.flags.no_site, 'no_bytecode': sys.flags.dont_write_bytecode}))\n"
    )
    witness = b"VALUE = 'reviewed'\n"
    (tmp_path / "__main__.py").write_bytes(main)
    (tmp_path / "witness.py").write_bytes(witness)
    manifest = {
        "__main__.py": hashlib.sha256(main).hexdigest(),
        "witness.py": hashlib.sha256(witness).hexdigest(),
    }
    archive, sha = bundle.build_archive(tmp_path, manifest)
    bundle.verify_archive(archive, manifest, sha)
    return archive, sha


def _command(fd: int, sha: str, marker: Path) -> list[str]:
    return [sys.executable, "-I", "-S", "-B", str(BOOTSTRAP), str(fd), sha, str(marker)]


def test_supervisor_passes_the_same_approved_archive_fd_to_child(
    tmp_path: Path,
) -> None:
    """The current supervisor closes the FD, so this contract must fail first."""
    sys.path.insert(0, str(HERE.parent))
    try:
        import broad
    finally:
        sys.path.pop(0)
    archive, sha = _archive(tmp_path)
    marker = tmp_path / "child-ran.json"
    with bundle.unlinked_archive_fd(archive, sha) as fd:
        report: dict = {}
        broad.supervise(
            _command(fd, sha, marker),
            tmp_path,
            "o8-fd-test",
            report,
            inherited_fd=fd,
            archive_sha256=sha,
        )
        assert marker.exists(), report
        observed = json.loads(marker.read_text())
        assert observed["main"] == f"/dev/fd/{fd}/__main__.py"
        assert observed["witness"] == f"/dev/fd/{fd}/witness.py"
        assert observed["argv0"] == f"/dev/fd/{fd}"
        assert (observed["isolated"], observed["no_site"], observed["no_bytecode"]) == (
            1,
            1,
            1,
        )


@pytest.mark.parametrize("invalid", ["missing", "closed", "different"])
def test_invalid_archive_fd_refuses_before_child_side_effects(
    tmp_path: Path, invalid: str
) -> None:
    archive, sha = _archive(tmp_path)
    marker = tmp_path / "child-ran.json"
    with bundle.unlinked_archive_fd(archive, sha) as fd:
        if invalid == "missing":
            requested_fd, inherited = 999999, ()
        elif invalid == "closed":
            requested_fd, inherited = fd, ()
        else:
            other = tmp_path / "different.pyz"
            other.write_bytes(archive + b"different")
            different_fd = os.open(other, os.O_RDONLY)
            requested_fd, inherited = different_fd, (different_fd,)
        try:
            result = subprocess.run(
                _command(requested_fd, sha, marker),
                pass_fds=inherited,
                cwd=tmp_path,
                capture_output=True,
                text=True,
                check=False,
            )
        finally:
            if invalid == "different":
                os.close(different_fd)
        assert result.returncode != 0
        assert "O8 archive bootstrap refused" in result.stderr
        assert not marker.exists()


def test_supervisor_rejects_unbound_open_fd_before_child_side_effects(tmp_path: Path) -> None:
    sys.path.insert(0, str(HERE.parent))
    try:
        import broad
    finally:
        sys.path.pop(0)
    marker = tmp_path / "unexpected"
    with (tmp_path / "ordinary.txt").open("wb") as ordinary:
        result = broad.supervise(
            [sys.executable, "-c", f"open({str(marker)!r}, 'w').close()"],
            tmp_path, "n", {}, inherited_fd=ordinary.fileno()
        )
    assert result["stopReason"] == "process-start-failure"
    assert not marker.exists()


def test_supervisor_rejects_bootstrap_digest_mismatch_before_launch(tmp_path: Path) -> None:
    sys.path.insert(0, str(HERE.parent))
    try:
        import broad
    finally:
        sys.path.pop(0)
    archive, sha = _archive(tmp_path)
    marker = tmp_path / "unexpected"
    with bundle.unlinked_archive_fd(archive, sha) as fd:
        command = _command(fd, sha, marker)
        result = broad.supervise(
            command, tmp_path, "n", {}, inherited_fd=fd, archive_sha256="0" * 64
        )
    assert result["stopReason"] == "process-start-failure"
    assert not marker.exists()
