"""Inspect a stopped or interrupted local Listen run without contacting a server.

This is the read-only first stage of recovery, NOT a cleanup/restart capability.
Even an intact hash chain is an unauthenticated historical responsibility record:
ports and PIDs may have been reused, writes may still be in flight, and a final
lookup cannot resolve an unacknowledged create. Nothing here sends requests,
loads an SDK, signals a PID, changes the input directory, or grants deletion.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import stat
import sys
import types
from typing import Any

if not __package__:
    package = types.ModuleType("o6_local_recovery_inspect")
    package.__path__ = [str(Path(__file__).resolve().parent)]
    sys.modules[package.__name__] = package
    __package__ = package.__name__
from . import local_supervisor as supervisor
from .campaign import owned_paths, secondary_paths
from .export_spec import budget_document, campaign_document, cases_document

SCHEMA = "local-listen-recovery-inspection-v1"
PHASES = ("ready", "account-create-intent", "account-created", "documents-at-risk", "lifecycle-result")
CHECKPOINTS = tuple(f"{i}-{phase}.json" for i, phase in enumerate(PHASES))
INPUTS = ("campaign.json", "catalog.json", "budget.json")
MAX_FILE = 1024 * 1024
MAX_CHECKPOINT = 32768
SHA = re.compile(r"[a-f0-9]{64}")
NONCE = re.compile(r"[a-f0-9]{32}")
PROJECT = re.compile(r"demo-[a-zA-Z0-9_-]{1,123}")
UID = re.compile(r"[a-zA-Z0-9_-]{1,128}")


class InvalidEvidence(ValueError):
    """A fixed diagnostic code; never include untrusted file data in a message."""


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _object(value: Any, keys: set[str]) -> bool:
    return type(value) is dict and set(value) == keys


def _signature(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _private(info: os.stat_result) -> None:
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise InvalidEvidence("nonprivate-evidence")


def _directory(path: Path, *, require_private: bool = True) -> int:
    """Open each absolute path component without following a symlink.

    A descriptor pins the inspected directory even if a parent is renamed.
    This is not an adversarial same-UID filesystem attestation.
    """
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise InvalidEvidence("posix-required")
    absolute = Path(os.path.abspath(path))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in absolute.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        if require_private:
            _private(os.fstat(fd))
        return fd
    except BaseException:
        os.close(fd)
        raise


class Archive:
    """Read only bounded private files anchored to the original directory FD."""
    def __init__(self, path: Path):
        self.fd = _directory(path)
        self.directories = {"": self.fd}
        self.directory_signatures = {"": _signature(os.fstat(self.fd))}
        self.files: dict[str, dict[str, Any]] = {}
        self.file_signatures: dict[str, tuple[int, ...]] = {}
        self.absent: set[str] = set()

    def close(self) -> None:
        for fd in self.directories.values():
            os.close(fd)

    def directory(self, name: str) -> int:
        if name not in self.directories:
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.fd)
            try:
                _private(os.fstat(fd))
            except BaseException:
                os.close(fd)
                raise
            self.directories[name] = fd
            self.directory_signatures[name] = _signature(os.fstat(fd))
        return self.directories[name]

    def _location(self, relative: str) -> tuple[int, str]:
        # Callers use only the small fixed namespace below, never archived paths.
        parts = relative.split("/")
        if len(parts) == 1 and parts[0] in (*INPUTS, "launch.json", "result.json"):
            return self.fd, parts[0]
        if len(parts) == 2 and parts[0] == "checkpoints" and parts[1] in CHECKPOINTS:
            return self.directory("checkpoints"), parts[1]
        raise InvalidEvidence("unexpected-evidence-path")

    def read(self, relative: str, limit: int = MAX_FILE, *, optional: bool = False) -> bytes | None:
        directory, name = self._location(relative)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            self.absent.add(relative)
            if optional:
                return None
            raise InvalidEvidence("missing-evidence") from None
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
                raise InvalidEvidence("invalid-evidence-file")
            _private(before)
            chunks, remaining = [], limit + 1
            while remaining:
                part = os.read(fd, min(65536, remaining))
                if not part:
                    break
                chunks.append(part)
                remaining -= len(part)
            raw = b"".join(chunks)
            if (len(raw) != before.st_size or len(raw) > limit
                    or _signature(os.fstat(fd)) != _signature(before)
                    or _signature(os.stat(name, dir_fd=directory, follow_symlinks=False)) != _signature(before)):
                raise InvalidEvidence("evidence-changed-during-read")
            self.files[relative] = {"file": relative, "bytes": len(raw), "sha256": _sha(raw)}
            self.file_signatures[relative] = _signature(before)
            return raw
        finally:
            os.close(fd)

    def stable(self) -> None:
        # Recheck both opened files and recorded absences. A parent report that
        # appears during inspection cannot retroactively turn this into success.
        for relative, signature in self.file_signatures.items():
            directory, name = self._location(relative)
            if _signature(os.stat(name, dir_fd=directory, follow_symlinks=False)) != signature:
                raise InvalidEvidence("evidence-changed-during-inspection")
        for relative in self.absent:
            directory, name = self._location(relative)
            try:
                os.stat(name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise InvalidEvidence("evidence-appeared-during-inspection")
        for name, fd in self.directories.items():
            before = self.directory_signatures[name]
            if _signature(os.fstat(fd)) != before:
                raise InvalidEvidence("directory-changed-during-inspection")
            if name and _signature(os.stat(name, dir_fd=self.fd, follow_symlinks=False)) != before:
                raise InvalidEvidence("directory-replaced-during-inspection")


def _decode(raw: bytes | None) -> Any:
    if raw is None:
        raise InvalidEvidence("missing-evidence")
    try:
        return supervisor._decode(raw)
    except supervisor.Refused:
        raise InvalidEvidence("invalid-json-evidence") from None


def _digests(value: Any) -> bool:
    return (type(value) is dict and 0 < len(value) <= 128
            and all(type(k) is str and len(k) <= 512
                    and re.fullmatch(r"[a-zA-Z0-9_./-]+", k)
                    and not k.startswith("/") and not any(p in ("", ".", "..") for p in k.split("/"))
                    and type(v) is str and SHA.fullmatch(v) for k, v in value.items()))


def _launch(value: Any) -> dict[str, Any]:
    keys = {"schema", "nonce", "projectId", "accountEmail", "firestoreEndpoint", "authEndpoint",
            "timeoutSeconds", "sourceDigests", "inputDigests", "productionExecuted", "authorizesCleanup",
            "recoveryState"}
    if (not _object(value, keys) or value["schema"] != supervisor.SCHEMA
            or type(value["nonce"]) is not str or not NONCE.fullmatch(value["nonce"])
            or type(value["projectId"]) is not str or not PROJECT.fullmatch(value["projectId"])
            or value["accountEmail"] != f"o6-{value['nonce']}@example.test"
            or value["productionExecuted"] is not False or value["authorizesCleanup"] is not False
            or value["recoveryState"] != "possibly-outstanding-until-typed-completion"
            or not _digests(value["sourceDigests"]) or not _digests(value["inputDigests"])
            or set(value["inputDigests"]) != set(INPUTS)):
        raise InvalidEvidence("invalid-launch-contract")
    try:
        supervisor._seconds(value["timeoutSeconds"])
        supervisor._endpoint(value["firestoreEndpoint"])
        supervisor._endpoint(value["authEndpoint"])
    except (supervisor.Refused, OverflowError):
        raise InvalidEvidence("invalid-local-launch-boundary") from None
    return value


def _checkpoint(item: Any, index: int, previous: str | None, last: int,
                launch: dict[str, Any]) -> dict[str, Any]:
    keys = {"schema", "phase", "nonce", "projectId", "accountEmail", "previousSha256", "authorizesCleanup", "value"}
    if (not _object(item, keys) or item["schema"] != "local-listen-checkpoint-v1"
            or item["phase"] != PHASES[index] or item["nonce"] != launch["nonce"]
            or item["projectId"] != launch["projectId"] or item["accountEmail"] != launch["accountEmail"]
            or item["authorizesCleanup"] is not False or item["previousSha256"] != previous
            or index <= last or (last < 0 and index != 0) or (index in (2, 3) and last != index - 1)
            or type(item["value"]) is not dict):
        raise InvalidEvidence("invalid-checkpoint-chain")
    value = item["value"]
    if index == 2:
        two = _object(value, {"uid", "paths", "secondaryUid", "secondaryPaths"})
        if ((not two and not _object(value, {"uid", "paths"})) or type(value["uid"]) is not str
                or not UID.fullmatch(value["uid"]) or value["paths"] != owned_paths(launch["nonce"], value["uid"])):
            raise InvalidEvidence("invalid-checkpoint-scope")
        if two and (type(value["secondaryUid"]) is not str or not UID.fullmatch(value["secondaryUid"])
                or value["secondaryUid"] == value["uid"]
                or value["secondaryPaths"] != secondary_paths(launch["nonce"], value["secondaryUid"])):
            raise InvalidEvidence("invalid-checkpoint-scope")
    elif index == 4:
        if (not _object(value, {"complete", "accountCleanupComplete", "clientsComplete", "documentsCleanupComplete"})
                or any(type(v) is not bool for v in value.values())):
            raise InvalidEvidence("invalid-checkpoint-result")
        if value["complete"] and (last != 3 or not all(value.values())):
            raise InvalidEvidence("contradictory-checkpoint-completion")
    elif value:
        raise InvalidEvidence("unexpected-checkpoint-data")
    return value


def inspect(directory: Path) -> dict[str, Any]:
    """Return a private diagnostic report. No result authorizes any mutation.

    An interrupted journal is not repaired, truncated or overwritten. On a bad
    tail only the earlier validated prefix is retained, and uncertainty expands
    rather than dropping the account/document responsibility. Hashes establish
    internal consistency, not authorship or freshness of the running emulator.
    """
    report: dict[str, Any] = {"schema": SCHEMA, "inspectionOnly": True, "evidenceIntact": False,
        "authorizesCleanup": False, "productionExecuted": False, "currentArtifactVerified": False,
        "currentResourceStateVerified": False, "processStateVerified": False,
        "requiresLiveRevalidation": True, "inspectorSha256": _sha(Path(__file__).read_bytes()),
        "issues": [], "verifiedPrefix": [], "candidateScope": None,
        "parentCompletionClaim": "not-recorded", "checkpointCompletionClaim": None,
        "sourceMatchesCurrent": None, "inputsMatchCurrent": None}
    archive = None
    try:
        archive = Archive(directory)
        launch = _launch(_decode(archive.read("launch.json")))
        report["launchSha256"] = archive.files["launch.json"]["sha256"]
        report["runSourceDigests"] = launch["sourceDigests"]
        try:
            report["sourceMatchesCurrent"] = launch["sourceDigests"] == supervisor._bindings()
        except OSError:
            # A missing current checkout file must not erase a historical UID.
            report["issues"].append("current-source-unavailable")
        scope = {k: launch[k] for k in ("nonce", "projectId", "accountEmail", "firestoreEndpoint", "authEndpoint")}
        scope.update(uid=None, secondaryUid=None, accountCreation="not-yet-inspected", documentsAtRisk=None,
                     documents=[])
        report["candidateScope"] = scope
        current = dict(zip(INPUTS, (campaign_document(launch["nonce"]), cases_document(), budget_document()), strict=True))
        matches = True
        for name in INPUTS:
            try:
                raw = archive.read(name)
                if _sha(raw) != launch["inputDigests"][name]:
                    raise InvalidEvidence("input-digest-mismatch")
                value = _decode(raw)
                # Canonical typed JSON, not Python's True == 1 == 1.0 equality.
                matches = matches and supervisor._encode(value) == supervisor._encode(current[name])
            except (OSError, ValueError) as error:
                report["issues"].append(str(error) if isinstance(error, InvalidEvidence) else "unreadable-input")
                matches = False
                # The immutable launch still binds the checkpoint chain. Keep
                # discovering responsibility, but never accept a damaged run.
        report["inputsMatchCurrent"] = matches
        checkpoint_dir = archive.directory("checkpoints")
        with os.scandir(checkpoint_dir) as entries:
            names = [e.name for e in itertools.islice(entries, len(CHECKPOINTS) + 1)]
        unexpected = len(names) > len(CHECKPOINTS) or any(name not in CHECKPOINTS for name in names)
        previous, last = None, -1
        scope.update(accountCreation="not-recorded", documentsAtRisk=False)
        for index, name in enumerate(CHECKPOINTS):
            if name not in names:
                archive.read("checkpoints/" + name, MAX_CHECKPOINT, optional=True)
                continue
            raw = archive.read("checkpoints/" + name, MAX_CHECKPOINT)
            value = _checkpoint(_decode(raw), index, previous, last, launch)
            previous, last = _sha(raw), index
            report["verifiedPrefix"].append({"file": name, "phase": PHASES[index], "sha256": previous})
            if index == 1:
                scope["accountCreation"] = "attempted-outcome-unknown"
            elif index == 2:
                scope["uid"] = value["uid"]
                scope["accountCreation"] = "acknowledgement-recorded-current-state-unknown"
                scope["secondaryUid"] = value.get("secondaryUid")
                scope["documents"] = [{"name": name, "path": path, "pathDigest": _sha(path.encode()),
                    "creationProven": False, "versionEvidence": None}
                    for name, path in {**value["paths"], **value.get("secondaryPaths", {})}.items()
                    if name != "run"]
            elif index == 3:
                scope["documentsAtRisk"] = True
            elif index == 4:
                report["checkpointCompletionClaim"] = value
        if unexpected:
            raise InvalidEvidence("unexpected-checkpoint-entry")
        raw = archive.read("result.json", optional=True)
        if raw is not None:
            parent = _decode(raw)
            if (type(parent) is not dict or parent.get("schema") != supervisor.SCHEMA
                    or parent.get("nonceDigest") != _sha(launch["nonce"].encode())
                    or parent.get("productionExecuted") is not False
                    or parent.get("authorizesCleanup") is not False
                    or any(type(parent.get(k)) is not bool for k in
                           ("completed", "resourceCleanupComplete", "processCleanupComplete", "recoveryRequired"))):
                raise InvalidEvidence("invalid-parent-report")
            if parent["completed"] and (not parent["resourceCleanupComplete"]
                    or not parent["processCleanupComplete"] or parent["recoveryRequired"]):
                raise InvalidEvidence("contradictory-parent-report")
            report["parentCompletionClaim"] = "reported" if parent["completed"] else "not-completed"
            # A parent's claim is not permission or a proof of current absence.
            if parent["completed"] and (scope["uid"] is None or report["checkpointCompletionClaim"] != {
                    "complete": True, "accountCleanupComplete": True, "clientsComplete": True,
                    "documentsCleanupComplete": True}):
                raise InvalidEvidence("parent-checkpoint-disagreement")
        archive.stable()
        report["evidenceIntact"] = not report["issues"]
        if report["issues"]:
            scope["uncertaintyAfterVerifiedPrefix"] = True
    except (OSError, ValueError, TypeError, KeyError) as error:
        report["issues"].append(str(error) if isinstance(error, InvalidEvidence) else "unreadable-evidence")
        if report["candidateScope"] is not None:
            report["candidateScope"]["uncertaintyAfterVerifiedPrefix"] = True
    finally:
        if archive is not None:
            try:
                archive.stable()
            except (OSError, ValueError):
                report["evidenceIntact"] = False
                report["issues"].append("evidence-not-stable")
                if report["candidateScope"] is not None:
                    report["candidateScope"]["uncertaintyAfterVerifiedPrefix"] = True
            report["evidenceFiles"] = list(archive.files.values())
            original = archive.directory_signatures[""]
            report["archiveIdentity"] = {"device": original[0], "inode": original[1]}
            archive.close()
    report["disposition"] = ("review-recorded-completion" if report["evidenceIntact"]
                             and report["parentCompletionClaim"] == "reported" else
                             "review-recorded-responsibility" if report["evidenceIntact"] else
                             "incomplete-evidence-preserve-responsibility")
    report["requiredBeforeAnyRecovery"] = [
        "verify-producer-stopped-with-current-identity-not-a-reused-pid",
        "verify-current-emulator-instance-not-merely-recorded-loopback-ports",
        "obtain-fresh-scope-bound-recovery-authority-and-bounded-budget",
        "revalidate-account-uid-email-and-document-owner-marker-and-version",
        "do-not-resolve-unknown-creates-by-a-later-absence-read",
        "delete-account-only-after-document-obligations-are-resolved",
        "record-conditional-cleanup-and-typed-final-readbacks-in-new-evidence",
    ]
    return report


def public_summary(report: dict[str, Any]) -> dict[str, Any]:
    """Never print the raw UID, nonce, email, endpoints, paths or source bodies."""
    keys = ("schema", "inspectionOnly", "evidenceIntact", "disposition", "authorizesCleanup",
            "productionExecuted", "currentArtifactVerified", "currentResourceStateVerified",
            "processStateVerified", "requiresLiveRevalidation", "sourceMatchesCurrent", "inputsMatchCurrent", "issues")
    summary = {key: report[key] for key in keys}
    scope = report["candidateScope"] or {}
    summary.update(checkpoints=len(report["verifiedPrefix"]), knownAccount=scope.get("uid") is not None,
                   candidateDocuments=len(scope.get("documents", [])))
    return summary


def run(directory: Path, output: Path) -> dict[str, Any]:
    """Create one new private report directory outside both input and checkout."""
    directory, output = Path(os.path.abspath(directory)), Path(os.path.abspath(output))
    if (output.is_relative_to(directory) or directory.is_relative_to(output)
            or output.resolve().is_relative_to(supervisor.ROOT)
            or output.exists() or output.is_symlink()):
        raise InvalidEvidence("fresh-independent-output-required")
    # Pin the parent to avoid following a substituted output symlink. Creating
    # this sibling directory does not touch any of the source evidence.
    parent = _directory(output.parent, require_private=False)
    try:
        os.mkdir(output.name, 0o700, dir_fd=parent)
        fd = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            report = inspect(directory)
            raw = supervisor._encode(report)
            file_fd = os.open("inspection.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            with os.fdopen(file_fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent)
    finally:
        os.close(parent)
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True, dest="directory")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = run(args.directory, args.output)
    except (OSError, ValueError):
        print("Local recovery inspection refused or report could not be saved.", file=sys.stderr)
        return 2
    print(json.dumps(public_summary(report), sort_keys=True))
    # Zero only means internally intact evidence was inspected. No live state
    # has been observed and no cleanup/restart has been performed or authorized.
    return 0 if report["evidenceIntact"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
