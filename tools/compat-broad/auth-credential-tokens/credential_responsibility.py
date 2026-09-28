"""Write-ahead local creation responsibility; records never authorize deletion.

The CLI opens a fresh private journal before starting its owned emulator. Every
potential account creation is persisted before sending. Unknown ACKs remain
unknown even after a later not-found response. No network or credential reads.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any

MAX_CREATIONS = 4
MAX_RECORD_BYTES = 16_384


class JournalFailure(ValueError):
    """A local responsibility record could not be retained."""


class Journal:
    def __init__(self, directory: Path, nonce: str):
        directory.mkdir(mode=0o700, exist_ok=False)
        self.path = directory.absolute()
        self.fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.sequence = 0
        self.previous = None
        self.nonce = nonce
        self.failed = False
        self.closed = False
        try:
            parent = os.open(directory.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        except OSError:
            os.close(self.fd)
            self.closed = True
            raise JournalFailure('responsibility directory persistence failed') from None
        info = os.fstat(self.fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            os.close(self.fd)
            self.closed = True
            raise JournalFailure('private responsibility directory required')

    def append(self, event: dict[str, Any]) -> None:
        if self.closed or self.failed:
            raise JournalFailure('responsibility journal unavailable')
        value = {'schema': 'credential-responsibility-v1', 'nonce': self.nonce,
                 'sequence': self.sequence, 'previousSha256': self.previous,
                 'event': event}
        payload = (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode('utf-8')
        if len(payload) > MAX_RECORD_BYTES:
            self.failed = True
            raise JournalFailure('responsibility record exceeds bound')
        name = f'{self.sequence:04d}.json'
        temporary = name + '.partial'
        fd = None
        try:
            info = os.fstat(self.fd)
            named = os.stat(self.path, follow_symlinks=False)
            if (info.st_uid != os.geteuid() or info.st_mode & 0o077
                    or not stat.S_ISDIR(named.st_mode)
                    or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
                raise JournalFailure('responsibility directory changed')
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=self.fd)
            view = memoryview(payload)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError('no journal write progress')
                view = view[written:]
            os.fsync(fd)
            os.close(fd)
            fd = None
            os.link(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd,
                    follow_symlinks=False)
            os.unlink(temporary, dir_fd=self.fd)
            os.fsync(self.fd)
            named = os.stat(self.path, follow_symlinks=False)
            if (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino):
                raise JournalFailure('responsibility directory replaced during publication')
        except (OSError, ValueError):
            self.failed = True
            raise JournalFailure('responsibility publication failed') from None
        finally:
            if fd is not None:
                os.close(fd)
        self.previous = hashlib.sha256(payload).hexdigest()
        self.sequence += 1

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            os.close(self.fd)


def attach(tracker: dict[str, Any], directory: Path, binding: dict[str, Any]) -> None:
    if '_responsibilityJournal' in tracker or tracker.get('creationIntents'):
        raise JournalFailure('fresh responsibility tracking required')
    journal = Journal(directory, tracker['nonce'])
    tracker['_responsibilityJournal'] = journal
    tracker['creationIntents'] = {}
    tracker['responsibilityRecordingComplete'] = True
    try:
        _append(tracker, {'type': 'run', 'sourceBinding': binding,
                          'authorizesCleanup': False, 'productionExecuted': False})
    except BaseException:
        journal.close()
        raise


def _append(tracker: dict[str, Any], event: dict[str, Any]) -> None:
    if tracker.get('responsibilityRecordingComplete') is False:
        raise JournalFailure('prior responsibility recording failure')
    journal = tracker.get('_responsibilityJournal')
    if journal is not None:
        try:
            journal.append(event)
        except Exception:
            tracker['responsibilityRecordingComplete'] = False
            raise


def begin(tracker: dict[str, Any], operation: str, *, email: str | None = None,
          requested_uid: str | None = None) -> str:
    if operation not in ('signup', 'custom-signin'):
        raise ValueError('unsupported creation operation')
    intents = tracker.setdefault('creationIntents', {})
    if len(intents) >= MAX_CREATIONS:
        raise ValueError('creation count bound exceeded')
    for text in (email, requested_uid):
        if text is not None and (type(text) is not str or not text or len(text) > 1024):
            raise ValueError('invalid intended identifier')
    name = f'creation-{len(intents)}'
    # Memory responsibility is established before publication too. A failed
    # intent publication prevents sending, not a later claim of complete work.
    intent = {'operation': operation, 'email': email, 'requestedUid': requested_uid,
              'state': 'unknown', 'uid': None}
    intents[name] = intent
    _append(tracker, {'type': 'intent', 'id': name, **intent})
    return name


def resolve(tracker: dict[str, Any], name: str, uid: str, *, created: bool) -> None:
    intent = tracker['creationIntents'][name]
    if intent['state'] != 'unknown' or type(uid) is not str or not uid or len(uid) > 128 or type(created) is not bool:
        raise ValueError('invalid creation acknowledgement')
    if intent['requestedUid'] is not None and uid != intent['requestedUid']:
        raise ValueError('creation acknowledgement UID mismatch')
    intent.update(uid=uid, state='confirmed' if created else 'existing')
    _append(tracker, {'type': 'acknowledgement', 'id': name, 'uid': uid,
                      'created': created})


def note_recovery(tracker: dict[str, Any], uid: str) -> None:
    for name, intent in tracker.get('creationIntents', {}).items():
        if intent['state'] == 'confirmed' and intent['uid'] == uid:
            try:
                _append(tracker, {'type': 'recovery', 'id': name, 'uid': uid,
                                  'absenceVerified': True})
            except Exception:
                # Persistence failure is latched, but known owned resources still
                # need recovery. Do not replace the caller's original exception.
                tracker['responsibilityRecordingComplete'] = False
                continue
            intent['state'] = 'recovered'


def summary(tracker: dict[str, Any]) -> dict[str, Any] | None:
    if 'creationIntents' not in tracker:
        return None
    values = list(tracker['creationIntents'].values())
    return {'intentCount': len(values),
            'unknownCreates': sum(v['state'] == 'unknown' for v in values),
            'confirmedCreates': sum(v['state'] in ('confirmed', 'recovered') for v in values),
            'existingAccounts': sum(v['state'] == 'existing' for v in values),
            'recordingComplete': tracker.get('responsibilityRecordingComplete') is not False,
            'durable': '_responsibilityJournal' in tracker,
            'authorizesCleanup': False}


def close(tracker: dict[str, Any]) -> None:
    journal = tracker.get('_responsibilityJournal')
    if journal is not None:
        try:
            journal.close()
        except OSError:
            tracker['responsibilityRecordingComplete'] = False
