"""Offline tests for the reviewed O8 source archive boundary."""

import hashlib
import importlib.util
import io
import os
import zipfile
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "o8_bundle", Path(__file__).with_name("o8_bundle.py")
)
assert _SPEC is not None and _SPEC.loader is not None
o8_bundle = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(o8_bundle)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source_tree(tmp_path: Path) -> dict[str, str]:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "__main__.py").write_bytes(
        b"from pkg import helper\nprint(helper.VALUE)\n"
    )
    (tmp_path / "pkg" / "__init__.py").write_bytes(b"")
    (tmp_path / "pkg" / "helper.py").write_bytes(b"VALUE = 7\n")
    return {
        "__main__.py": digest((tmp_path / "__main__.py").read_bytes()),
        "pkg/__init__.py": digest(b""),
        "pkg/helper.py": digest((tmp_path / "pkg" / "helper.py").read_bytes()),
    }


def test_deterministic_reviewed_source_archive(tmp_path: Path) -> None:
    manifest = source_tree(tmp_path)
    archive, sha = o8_bundle.build_archive(tmp_path, manifest)
    assert (archive, sha) == o8_bundle.build_archive(
        tmp_path, dict(reversed(list(manifest.items())))
    )
    assert sha == digest(archive)
    o8_bundle.verify_archive(archive, manifest, sha)
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        assert bundle.namelist() == sorted(manifest)
        assert all(
            info.compress_type == zipfile.ZIP_STORED for info in bundle.infolist()
        )


@pytest.mark.parametrize(
    "name",
    [
        "../escape.py",
        "/absolute.py",
        "pkg/../bad.py",
        "pkg\\bad.py",
        "pkg/x.pyc",
        "pkg/x.so",
        "pkg//x.py",
        "pkg/./x.py",
    ],
)
def test_unsafe_source_name_is_rejected(tmp_path: Path, name: str) -> None:
    with pytest.raises(ValueError):
        o8_bundle.build_archive(
            tmp_path, {"__main__.py": digest(b""), name: digest(b"")}
        )


def test_missing_mismatched_and_symlink_sources_are_rejected(tmp_path: Path) -> None:
    manifest = source_tree(tmp_path)
    with pytest.raises(ValueError):
        o8_bundle.build_archive(tmp_path, {**manifest, "missing.py": digest(b"")})
    with pytest.raises(ValueError):
        o8_bundle.build_archive(
            tmp_path, {**manifest, "pkg/helper.py": digest(b"wrong")}
        )
    (tmp_path / "pkg" / "helper.py").unlink()
    (tmp_path / "pkg" / "helper.py").symlink_to(tmp_path / "__main__.py")
    with pytest.raises(ValueError):
        o8_bundle.build_archive(tmp_path, manifest)


def test_verify_rejects_extra_duplicate_compressed_and_changed_members(
    tmp_path: Path,
) -> None:
    manifest = source_tree(tmp_path)
    archive, sha = o8_bundle.build_archive(tmp_path, manifest)
    with pytest.raises(ValueError):
        o8_bundle.verify_archive(archive + b"x", manifest, sha)
    for compression, names in [
        (zipfile.ZIP_STORED, [*manifest, "extra.py"]),
        (zipfile.ZIP_STORED, [*manifest, "__main__.py"]),
        (zipfile.ZIP_DEFLATED, list(manifest)),
    ]:
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as bundle:
            for name in names:
                bundle.writestr(name, b"x", compress_type=compression)
        with pytest.raises(ValueError):
            o8_bundle.verify_archive(
                output.getvalue(), manifest, digest(output.getvalue())
            )
    with pytest.raises(ValueError):
        o8_bundle.verify_archive(archive, {**manifest, "other.py": digest(b"")}, sha)


def test_read_only_fd_zipapp_ignores_local_shadow_and_child_inherits_fd(
    tmp_path: Path,
) -> None:
    import os
    import subprocess
    import sys

    source = tmp_path / "source"
    source.mkdir()
    main = b"import argparse, os, subprocess, sys\nfrom pkg import helper\nassert helper.VALUE == 7\nassert '/dev/fd/' in helper.__file__\nassert 'shadow' not in argparse.__file__\nif len(sys.argv) == 1:\n    child = subprocess.run([sys.executable, '-I', '-S', '-B', sys.argv[0], 'child'], pass_fds=(int(sys.argv[0].split('/')[-1]),), check=True)\nprint('ok')\n"
    manifest = source_tree(source)
    (source / "__main__.py").write_bytes(main)
    manifest["__main__.py"] = digest(main)
    archive, sha = o8_bundle.build_archive(source, manifest)
    o8_bundle.verify_archive(archive, manifest, sha)
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    (shadow / "argparse.py").write_text("raise RuntimeError('shadow imported')\n")
    with o8_bundle.unlinked_archive_fd(archive, sha) as fd:
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", f"/dev/fd/{fd}"],
            cwd=shadow,
            env={**os.environ, "PYTHONPATH": str(shadow)},
            pass_fds=(fd,),
            capture_output=True,
            text=True,
            check=True,
        )
    assert result.stdout == "ok\nok\n"


def test_unlinked_snapshot_rejects_path_replacement_and_detects_fd_mutation(
    tmp_path: Path,
) -> None:
    archive = b"reviewed archive"
    with o8_bundle.unlinked_archive_fd(archive, digest(archive)) as fd:
        assert o8_bundle.verify_archive_fd(fd, digest(archive)) is None
        assert os.fstat(fd).st_nlink == 0
        replacement = tmp_path / "bundle.pyz"
        replacement.write_bytes(b"tampered")
        assert o8_bundle.verify_archive_fd(fd, digest(archive)) is None
        os.lseek(fd, 0, os.SEEK_SET)
        assert os.read(fd, len(archive)) == archive
        replacement.unlink()


def test_unlinked_snapshot_rejects_bad_digest_and_writable_fd(tmp_path: Path) -> None:
    with (
        pytest.raises(ValueError, match="digest"),
        o8_bundle.unlinked_archive_fd(b"archive", digest(b"wrong")),
    ):
        pass
    writable = tmp_path / "writable"
    writable.write_bytes(b"archive")
    with writable.open("r+b") as source, pytest.raises(ValueError, match="read-only"):
        o8_bundle.verify_archive_fd(source.fileno(), digest(b"archive"))


def test_unlinked_fd_rejects_mutation_through_preexisting_writer(
    tmp_path: Path,
) -> None:
    path = tmp_path / "archive.pyz"
    path.write_bytes(b"reviewed")
    writer = os.open(path, os.O_RDWR)
    reader = os.open(path, os.O_RDONLY)
    try:
        path.unlink()
        o8_bundle.verify_archive_fd(reader, digest(b"reviewed"))
        os.pwrite(writer, b"tampered", 0)
        with pytest.raises(ValueError, match="digest"):
            o8_bundle.verify_archive_fd(reader, digest(b"reviewed"))
    finally:
        os.close(reader)
        os.close(writer)
