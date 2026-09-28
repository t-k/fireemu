"""Private, local-only MFA responsibility records; never restart deletion authority.

A create intent is fsynced before a signup. Only a typed, same-run ACK connects
that intent to a UID. An unacknowledged request remains unknown even when no
known resources remain. Checkpoints use same-directory atomic replacement;
append-only events preserve intents independently of the latest checkpoint.

POSIX/local-filesystem contract. This is not a signature, an instance identity,
a hard-kill recovery engine, or a guarantee against arbitrary same-user edits.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid
from typing import Any

from mfa_collector import checkpoint_bytes, digest

SCHEMA = "o2-mfa-local-responsibility-v1"
MAX_RECORD_BYTES = 128 * 1024


def _encoded(value: Any) -> bytes:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(data) > MAX_RECORD_BYTES:
        raise ValueError("responsibility record exceeds local bound")
    return data


def _file_info(directory: int, name: str) -> os.stat_result | None:
    try:
        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077):
        raise ValueError("private single-link regular file required")
    return info


def _identity(info: os.stat_result | None) -> tuple | None:
    return None if info is None else (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _publish(directory: int, name: str, data: bytes, *, previous: tuple | None = None) -> tuple:
    """Publish complete bytes, never truncate the previous checkpoint in place.

    previous=None creates exclusively. For replacement, the caller's last file
    identity must still match. A failed post-rename fsync may leave the NEW,
    complete bytes visible; it is still an error, not a durability success.
    """
    if not isinstance(data, bytes) or not re.fullmatch(r"[a-zA-Z0-9_.-]+", name):
        raise ValueError("invalid private publication")
    before = _identity(_file_info(directory, name))
    if before != previous:
        raise ValueError("private publication target changed or already exists")
    temp = f".pending-{uuid.uuid4().hex}"
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=directory)
    try:
        try:
            remaining = memoryview(data)
            while remaining:
                written = os.write(fd, remaining)
                if written <= 0:
                    raise OSError("private write made no progress")
                remaining = remaining[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        if _identity(_file_info(directory, name)) != before:
            raise ValueError("private publication target changed during write")
        if previous is None:
            os.link(temp, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
            os.unlink(temp, dir_fd=directory)
        else:
            os.replace(temp, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
        identity = _identity(_file_info(directory, name))
        if identity is None:
            raise ValueError("published private file disappeared")
        return identity
    finally:
        # Never remove a destination or somebody else's evidence after failure.
        try:
            os.unlink(temp, dir_fd=directory)
        except FileNotFoundError:
            pass


class RunPersistence:
    """One non-resumable sequence writer; completed files confer no permission."""

    def __init__(self, output: Path, state: dict, plan: dict) -> None:
        self._root = self._events = -1
        self.failed = False
        self.failures: list[str] = []
        self._sequence = 0
        self._previous: str | None = None
        self._checkpoint: tuple | None = None
        self._intents: dict[str, dict] = {}
        self._closed = False
        self._finalized = False
        self._final_record_saved = False
        self._outcome_published = False
        self._completion_allowed = False
        if state["nonce"] != plan["owner"]["nonceDigest"] or state["planDigest"] != digest(plan):
            raise ValueError("collector state and local plan binding differ")
        self._binding = {"nonceDigest": state["nonce"], "planDigest": state["planDigest"], "project": plan["project"]}
        self._emails = {entry["role"]: entry["email"] for entry in plan["owner"]["accounts"]}
        try:
            self._root = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            info = os.fstat(self._root)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise ValueError("private owned run directory required")
            if _file_info(self._root, "checkpoint.json") is not None:
                raise ValueError("checkpoint already exists; a fresh run is required")
            os.mkdir("responsibility", mode=0o700, dir_fd=self._root)
            os.fsync(self._root)
            self._events = os.open("responsibility", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self._root)
            self._event("launch", {"productionExecuted": False})
            self.save_checkpoint(state)
        except BaseException:
            # Preserve the original initialization failure; no service call has run.
            try:
                self.close()
            except OSError:
                pass
            raise

    def _fault(self, error: BaseException) -> None:
        self.failed = True
        name = type(error).__name__
        if name not in self.failures:
            self.failures.append(name)

    def _writable(self) -> None:
        if self._closed or self._finalized or self.failed:
            raise RuntimeError("MFA responsibility recording is closed or failed")

    def _event(self, kind: str, body: dict) -> str:
        record = {"schema": SCHEMA, **self._binding, "sequence": self._sequence,
                  "kind": kind, "previousSha256": self._previous,
                  "authorizesCleanup": False, "body": body}
        raw = _encoded(record)
        try:
            _publish(self._events, f"{self._sequence:04d}-{kind}.json", raw)
        except BaseException as error:
            self._fault(error)
            raise
        self._previous = hashlib.sha256(raw).hexdigest()
        self._sequence += 1
        return self._previous

    def email_for(self, role: str) -> str | None:
        if role not in self._emails:
            raise ValueError("account role is outside the frozen MFA plan")
        return None if role == "interaction-anonymous" else self._emails[role]

    def intent(self, role: str) -> None:
        """Must finish before the signup call; failure MUST prevent that call."""
        self._writable()
        email = self.email_for(role)
        if role in self._intents:
            raise ValueError("account creation role was already attempted")
        # Conservatively retain an attempted publication even if fsync fails.
        intent = {"role": role, "email": email, "uid": None, "acknowledged": False}
        self._intents[role] = intent
        self._event("create-intent", {"role": role, "email": email})

    def acknowledge(self, role: str, uid: str) -> None:
        self._writable()
        intent = self._intents.get(role)
        if (intent is None or intent["acknowledged"] or not isinstance(uid, str) or not uid
                or len(uid.encode("utf-8")) > 1024 or any(ord(c) < 32 or ord(c) == 127 for c in uid)
                or any(value["uid"] == uid for value in self._intents.values())):
            raise ValueError("invalid or duplicate same-run signup acknowledgement")
        self._event("create-ack", {"role": role, "uid": uid})
        intent.update(uid=uid, acknowledged=True)

    def save_checkpoint(self, state: dict) -> None:
        """Atomic latest-state publication. A failure latches future observations.

        A final best-effort checkpoint is allowed even after a failure, but does
        not clear failed or authorize another signup/observation.
        """
        if self._closed or self._finalized:
            raise RuntimeError("MFA persistence is closed")
        self._write_checkpoint(state)

    def _write_checkpoint(self, state: dict) -> None:
        try:
            raw = checkpoint_bytes(state)
            if state["nonce"] != self._binding["nonceDigest"] or state["planDigest"] != self._binding["planDigest"]:
                raise ValueError("checkpoint belongs to a different local run")
            self._checkpoint = _publish(self._root, "checkpoint.json", raw, previous=self._checkpoint)
        except BaseException as error:
            self._fault(error)
            raise

    def finalize(self, state: dict, *, request_budget: dict | None = None) -> dict:
        """Append private responsibility/cleanup state, never grant restart access."""
        if self._closed or self._finalized:
            raise RuntimeError("MFA responsibility record is already finalized")
        checkpoint_bytes(state)
        if state["nonce"] != self._binding["nonceDigest"] or state["planDigest"] != self._binding["planDigest"]:
            raise ValueError("recovery belongs to a different local run")
        resources = {item["id"]: item for item in state["ownedResources"] if item["kind"] == "account"}
        intents = copy.deepcopy(list(self._intents.values()))
        for intent in intents:
            resource = resources.get(intent["uid"], {})
            intent["cleanupVerified"] = (intent["acknowledged"] is True
                                         and resource.get("deleted") is True
                                         and resource.get("absenceVerified") is True)
        known = {item["uid"] for item in intents if item["acknowledged"]}
        unknown = sum(not item["acknowledged"] for item in intents)
        remaining = sum(item["acknowledged"] and not item["cleanupVerified"] for item in intents)
        untracked = len(set(resources) - known)
        summary = {"schema": SCHEMA, "authorizesCleanup": False,
                   "journalComplete": not self.failed, "attemptedAccounts": len(intents),
                   "acknowledgedAccounts": len(known), "unresolvedCreations": unknown,
                   "remainingKnownAccounts": remaining, "untrackedOwnedAccounts": untracked,
                   "resourceCleanupComplete": not self.failed and unknown == 0 and remaining == 0 and untracked == 0}
        try:
            sha = self._event("recovery", {"summary": summary, "accounts": intents,
                                          "recordingFailures": list(self.failures),
                                          "requestsCharged": state["requests"],
                                          "observationAborted": state["aborted"],
                                          **({"requestBudget": copy.deepcopy(request_budget)}
                                             if request_budget is not None else {})})
        finally:
            self._finalized = True
        self._final_record_saved = True
        self._completion_allowed = summary["resourceCleanupComplete"] and state["aborted"] is False
        return {**summary, "recordSha256": sha}

    def finish_checkpoint(self, state: dict) -> None:
        """Confirm the outcome only after recovery publication; at most once.

        Until this point the latest checkpoint is deliberately non-complete.
        An incomplete responsibility record can never publish a success state.
        """
        if (self._closed or not self._finalized or not self._final_record_saved
                or self._outcome_published):
            raise RuntimeError("final MFA recovery record is unavailable or already consumed")
        if state["aborted"] is not True and not self._completion_allowed:
            raise ValueError("incomplete responsibility cannot finalize a successful checkpoint")
        self._outcome_published = True
        self._write_checkpoint(state)

    def close(self) -> None:
        self._closed = True
        first = None
        for name in ("_events", "_root"):
            fd = getattr(self, name)
            setattr(self, name, -1)
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError as error:
                    if first is None:
                        first = error
        if first is not None:
            raise first


def complete_summary(value: Any, owned_accounts: Any) -> bool:
    """Validate explicit local responsibility claims, not filesystem/remote truth."""
    required = {"schema", "authorizesCleanup", "journalComplete", "attemptedAccounts",
                "acknowledgedAccounts", "unresolvedCreations", "remainingKnownAccounts",
                "untrackedOwnedAccounts", "resourceCleanupComplete", "recordSha256"}
    if not isinstance(value, dict) or set(value) != required:
        return False
    if (value["schema"] != SCHEMA or value["authorizesCleanup"] is not False
            or value["journalComplete"] is not True or value["resourceCleanupComplete"] is not True
            or not isinstance(value["recordSha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", value["recordSha256"]) is None
            or type(owned_accounts) is not int or owned_accounts < 0):
        return False
    counts = ("attemptedAccounts", "acknowledgedAccounts", "unresolvedCreations",
              "remainingKnownAccounts", "untrackedOwnedAccounts")
    if any(type(value[name]) is not int or value[name] < 0 for name in counts):
        return False
    return (value["attemptedAccounts"] == value["acknowledgedAccounts"] == owned_accounts
            and value["unresolvedCreations"] == value["remainingKnownAccounts"] == value["untrackedOwnedAccounts"] == 0)
