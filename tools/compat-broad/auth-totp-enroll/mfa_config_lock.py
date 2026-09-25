"""The project configuration change this campaign makes, modelled as a locked step.

The campaign needs multi-factor authentication enabled with TOTP and phone factors, a
test phone number so no SMS is sent, and an SMS region policy that admits the test
number. That is a production write to `projects/{project}/config`, so it is treated
like every other production write: the pre-value is saved before the change is
attempted, the change is applied only inside the reservation envelope, the readback is
verified, and the pre-value is restored and verified again at the end of the run and on
every path that stops it early.

Nothing here performs transport. The lock is driven by a caller that supplies two
callables, one that reads the configuration and one that patches it, and the lock
records what it saw as digests. The configuration body itself stays in the private
run directory: the receipt carries the digests and a redacted reference, which names
the top-level fields and the byte length, never the values.
"""

from __future__ import annotations

import copy
import json
import os
import re
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from mfa_collector import digest

PROJECT = "fireemu-35fe6"
PROJECT_NUMBER = "592603257417"
CONFIG_PATH = f"/admin/v2/projects/{PROJECT}/config"
# The fields the campaign changes, and therefore the only fields it may restore. A
# restore that wrote back more than it changed would itself be an unreviewed write.
UPDATE_MASK = "mfa,signIn.phoneNumber,smsRegionConfig"
TEST_PHONE = "+15555550100"
TEST_CODE = "135790"
# One adjacent interval either side is the acceptance window the local policy uses
# and the value the campaign's replay row assumes; it is declared here so a reviewer
# reads it in the code that sends it.
TOTP_ADJACENT_INTERVALS = 1
CAMPAIGN_MFA = {
    "state": "ENABLED",
    "enabledProviders": ["PHONE_SMS"],
    "providerConfigs": [
        {
            "state": "ENABLED",
            "totpProviderConfig": {"adjacentIntervals": TOTP_ADJACENT_INTERVALS},
        }
    ],
}
CAMPAIGN_PHONE = {"enabled": True, "testPhoneNumbers": {TEST_PHONE: TEST_CODE}}
# The oracle project blocks SMS in every region; test numbers still pass the region
# check, and the earlier production recorder found that an allowlist of one region was
# refused. Allow-by-default with no disallowed region is what that run used and
# restored from. It is restored to whatever was read, never to a constant.
CAMPAIGN_SMS_REGIONS = {"allowByDefault": {"disallowedRegions": []}}

RESTORE_STATUSES = (
    "not-attempted",
    "restored-verified",
    "restored-verified-normalized",
    "restore-readback-differs",
    "restore-failed",
)
VERIFIED_RESTORE_STATUSES = ("restored-verified", "restored-verified-normalized")
# The disabled shapes the service reads back for a masked field that was absent
# before the run. The earlier production recorder observed that a null phone
# configuration reads back as an empty object after a restore, so a byte-exact
# whole-configuration digest can differ from the baseline while every field the run
# touched is back in its disabled state. Equality under this normalization is
# reported as its own status, never folded into the exact one.
_DISABLED_PHONE = {"enabled": False, "testPhoneNumbers": {}}
_DISABLED_MFA = {"state": "DISABLED"}
LOCK_FILE = "config-lock.json"
BASELINE_FILE = "config-baseline.json"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ConfigLockError(RuntimeError):
    """The configuration step could not be taken, verified or restored."""


def config_digest(body: Any) -> str:
    """The whole-configuration digest the restore proof compares against."""
    if not isinstance(body, dict) or "error" in body:
        raise ConfigLockError("configuration readback is not a configuration")
    return digest(body)


def redacted_reference(body: dict) -> dict:
    """What a receipt may say about a configuration body: shape and size, no values."""
    config_digest(body)
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return {
        "sha256": digest(body),
        "bytes": len(encoded),
        "topLevelFields": sorted(body),
        "valuesRetained": False,
    }


def validate_configuration(body: Any, *, project_number: str = PROJECT_NUMBER) -> dict:
    """A production configuration names the project it belongs to."""
    if not isinstance(body, dict) or "error" in body:
        raise ConfigLockError("configuration readback is not a configuration")
    if body.get("name") != f"projects/{project_number}/config":
        raise ConfigLockError("configuration belongs to another project")
    return body


def campaign_patch() -> dict:
    """The change the campaign applies, exactly, in PATCH shape."""
    return {
        "mfa": copy.deepcopy(CAMPAIGN_MFA),
        "signIn": {"phoneNumber": copy.deepcopy(CAMPAIGN_PHONE)},
        "smsRegionConfig": copy.deepcopy(CAMPAIGN_SMS_REGIONS),
    }


def restore_patch(baseline: dict) -> dict:
    """The configuration to write back: what was read, projected onto the mask.

    A field the baseline did not carry is written back as its disabled shape, which is
    what the earlier production recorder observed the service reads back for an absent
    value; the whole-configuration digest check afterwards decides whether that was
    exact, and a difference is reported rather than assumed away.
    """
    validate_configuration(baseline)
    phone = (baseline.get("signIn") or {}).get("phoneNumber") or {
        "enabled": False,
        "testPhoneNumbers": {},
    }
    return {
        "mfa": copy.deepcopy(baseline.get("mfa") or {"state": "DISABLED"}),
        "signIn": {"phoneNumber": copy.deepcopy(phone)},
        "smsRegionConfig": copy.deepcopy(baseline.get("smsRegionConfig") or {}),
    }


def applied(readback: dict) -> bool:
    """Whether a readback carries the campaign configuration in the masked fields."""
    validate_configuration(readback)
    phone = (readback.get("signIn") or {}).get("phoneNumber") or {}
    return (
        readback.get("mfa") == CAMPAIGN_MFA
        and phone.get("enabled") is True
        and phone.get("testPhoneNumbers") == CAMPAIGN_PHONE["testPhoneNumbers"]
        and "allowByDefault" in (readback.get("smsRegionConfig") or {})
    )


def normalized(body: dict) -> dict:
    """The configuration with each masked field's absent and disabled shapes unified.

    Only the pairs the earlier production recorder proved equivalent are unified
    here: an absent phone block and its explicit disabled shape, and an absent
    `mfa` and its explicit `{"state": "DISABLED"}` shape. `providerConfigs` (the
    TOTP factor's state and `adjacentIntervals`) is never known-equivalent to
    absence, so its presence blocks the `mfa` normalization outright; a restore
    that left a TOTP difference behind must compare unequal here, not be folded
    into the disabled shape.
    """
    value = copy.deepcopy(body)
    sign_in = value.get("signIn") or {}
    phone = sign_in.get("phoneNumber") or {}
    if not phone.get("enabled") and not phone.get("testPhoneNumbers"):
        sign_in = {**sign_in, "phoneNumber": copy.deepcopy(_DISABLED_PHONE)}
    value["signIn"] = sign_in
    mfa = value.get("mfa") or {}
    if (
        mfa.get("state") in (None, "DISABLED")
        and not mfa.get("enabledProviders")
        and not mfa.get("providerConfigs")
    ):
        value["mfa"] = copy.deepcopy(_DISABLED_MFA)
    value["smsRegionConfig"] = value.get("smsRegionConfig") or {}
    return value


def differing_fields(readback: dict, baseline: dict) -> list[str]:
    """Top-level field names whose values differ, for a restore that did not verify."""
    names = sorted(set(readback) | set(baseline))
    return [name for name in names if readback.get(name) != baseline.get(name)]


def _private_write(path: Path, value: Any) -> None:
    """Write the private lock record so a reader never observes a partial file.

    A truncate-then-write in place (the earlier shape) leaves a zero-byte file
    for any stop between the truncate and the write; `ConfigLock.resume()` reads
    the file whole and a truncated one refuses recovery outright. This writes a
    freshly created, uniquely named temporary file in the same directory, fsyncs
    it, and only then renames it onto the target: a stop at any point up to the
    rename leaves the previous record exactly as it was, and a stop after the
    rename leaves the new one complete. `os.replace` is a single filesystem
    rename, so no reader of `path` ever observes a partial write either way. A
    temporary file a stop left behind before the rename is simply an unreferenced
    file beside it; the next write picks its own fresh unique name and the reader
    only ever opens `path` by its exact name.
    """
    encoded = json.dumps(value, sort_keys=True, indent=2).encode() + b"\n"
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    replaced = False
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        replaced = True
    finally:
        if not replaced:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _private_read(path: Path) -> Any:
    if path.is_symlink() or not path.is_file():
        raise ConfigLockError("private lock record missing")
    info = path.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ConfigLockError("private lock record required")
    return json.loads(path.read_bytes())


class ConfigLock:
    """One run's configuration change, from frozen baseline to verified restore.

    The lock persists itself in the private run directory so a resumed process knows
    whether a change was attempted, and the baseline body it must restore. The record
    is private state, not authority: a resumed process still has to read the live
    configuration back and compare it before it may proceed.
    """

    def __init__(
        self,
        directory: Path,
        *,
        read: Callable[[], tuple[int, Any]],
        patch: Callable[[dict, str], tuple[int, Any]],
        frozen_baseline_digest: str,
    ) -> None:
        if not isinstance(frozen_baseline_digest, str) or not _HEX64.fullmatch(
            frozen_baseline_digest
        ):
            raise ConfigLockError("frozen Auth configuration baseline digest required")
        self.directory = Path(directory)
        self._read = read
        self._patch = patch
        self.frozen_baseline_digest = frozen_baseline_digest
        self.record: dict[str, Any] = {
            "frozenBaselineDigest": frozen_baseline_digest,
            "preflightReadbackDigest": None,
            "baselineReference": None,
            "changeAttempted": False,
            "appliedReadbackDigest": None,
            "applied": False,
            "restoreAttempts": 0,
            "restoreReadbackDigest": None,
            "restoreStatus": "not-attempted",
            "restoreDifferingFields": None,
        }

    # -- persistence ---------------------------------------------------------------
    def save(self) -> None:
        _private_write(self.directory / LOCK_FILE, self.record)

    @classmethod
    def resume(
        cls,
        directory: Path,
        *,
        read: Callable[[], tuple[int, Any]],
        patch: Callable[[dict, str], tuple[int, Any]],
        frozen_baseline_digest: str,
    ) -> ConfigLock:
        lock = cls(
            directory,
            read=read,
            patch=patch,
            frozen_baseline_digest=frozen_baseline_digest,
        )
        record = _private_read(lock.directory / LOCK_FILE)
        if (
            not isinstance(record, dict)
            or set(record) != set(lock.record)
            or record["frozenBaselineDigest"] != frozen_baseline_digest
        ):
            raise ConfigLockError("private lock record does not bind this run")
        lock.record = record
        return lock

    def _baseline_body(self) -> dict:
        body = _private_read(self.directory / BASELINE_FILE)
        if config_digest(body) != self.frozen_baseline_digest:
            raise ConfigLockError("saved baseline differs from the frozen digest")
        return body

    # -- steps ---------------------------------------------------------------------
    def preflight(self, *, resume: bool = False) -> str:
        """Read the live configuration; refuse to start unless it is the frozen baseline.

        The frozen digest came from the owner's baseline observation. A different live
        configuration means the project changed since the permission was written, and
        a restore would then write back a configuration nobody reviewed. A resumed run
        whose previous stop restored the baseline under the documented normalization
        finds the normalized shape live, and is admitted only against the saved
        baseline body it will restore again.
        """
        status, body = self._read()
        if status != 200:
            raise ConfigLockError(f"configuration preflight answered {status}")
        validate_configuration(body)
        observed = config_digest(body)
        self.record["preflightReadbackDigest"] = observed
        if observed != self.frozen_baseline_digest:
            admitted = (
                resume
                and self.record["restoreStatus"] == "restored-verified-normalized"
                and normalized(body) == normalized(self._baseline_body())
            )
            if not admitted:
                self.save()
                raise ConfigLockError(
                    "Auth configuration readback differs from the frozen baseline digest"
                )
            self.save()
            return observed
        # The pre-value is saved before the change can be attempted, under the private
        # directory, so a change that reaches the server without a readable response
        # can still be restored by a later process.
        _private_write(self.directory / BASELINE_FILE, body)
        self.record["baselineReference"] = redacted_reference(body)
        self.save()
        return observed

    def apply(self) -> str:
        """Apply the campaign configuration and verify it by readback."""
        if self.record["baselineReference"] is None:
            raise ConfigLockError("configuration preflight required before apply")
        self.record["changeAttempted"] = True
        self.record["restoreStatus"] = "not-attempted"
        self.record["restoreReadbackDigest"] = None
        self.record["restoreDifferingFields"] = None
        self.save()
        status, body = self._patch(campaign_patch(), UPDATE_MASK)
        if status != 200 or not isinstance(body, dict) or "error" in body:
            raise ConfigLockError(f"configuration change answered {status}")
        status, readback = self._read()
        if status != 200:
            raise ConfigLockError(f"configuration readback answered {status}")
        if not applied(readback):
            raise ConfigLockError("configuration readback does not carry the change")
        self.record["appliedReadbackDigest"] = config_digest(readback)
        self.record["applied"] = True
        self.save()
        return self.record["appliedReadbackDigest"]

    def restore(self) -> str | None:
        """Write the pre-value back and verify whole-configuration digest equality.

        Idempotent: a restore that already verified is not repeated. A change that was
        never attempted has nothing to restore and sends nothing; the status stays
        `not-attempted`, which the evidence check accepts only together with
        `changeAttempted` false.
        """
        if self.record["restoreStatus"] in VERIFIED_RESTORE_STATUSES:
            return self.record["restoreReadbackDigest"]
        if not self.record["changeAttempted"]:
            return None
        self.record["restoreAttempts"] += 1
        try:
            baseline = self._baseline_body()
            try:
                status, body = self._patch(restore_patch(baseline), UPDATE_MASK)
            except ConfigLockError:
                raise
            except Exception as error:
                raise ConfigLockError(
                    "configuration restore transport failed"
                ) from error
            if status != 200 or not isinstance(body, dict) or "error" in body:
                raise ConfigLockError(f"configuration restore answered {status}")
            try:
                status, readback = self._read()
            except Exception as error:
                raise ConfigLockError("restore readback transport failed") from error
            if status != 200:
                raise ConfigLockError(f"restore readback answered {status}")
            validate_configuration(readback)
            observed = config_digest(readback)
            self.record["restoreReadbackDigest"] = observed
            if observed == self.frozen_baseline_digest:
                self.record["restoreStatus"] = "restored-verified"
                self.record["restoreDifferingFields"] = []
                return observed
            self.record["restoreDifferingFields"] = differing_fields(readback, baseline)
            if normalized(readback) == normalized(baseline):
                self.record["restoreStatus"] = "restored-verified-normalized"
                return observed
            self.record["restoreStatus"] = "restore-readback-differs"
            raise ConfigLockError(
                "restored configuration digest differs from the frozen baseline"
            )
        except ConfigLockError:
            if self.record["restoreStatus"] != "restore-readback-differs":
                self.record["restoreStatus"] = "restore-failed"
            raise
        finally:
            self.save()

    def evidence(self) -> dict:
        """The secret-free summary a receipt carries."""
        return copy.deepcopy(self.record)


def validate_evidence(value: Any, *, frozen_baseline_digest: str) -> bool:
    """Whether a receipt's configuration evidence proves a verified restore.

    A change that was never attempted needs no restore; a change that was needs a
    verified one, exact or under the documented normalization.
    """
    if not isinstance(value, dict):
        return False
    try:
        if value["frozenBaselineDigest"] != frozen_baseline_digest:
            return False
        reference = value["baselineReference"]
        if value["changeAttempted"] is False:
            return (
                value["restoreStatus"] == "not-attempted" and value["applied"] is False
            )
        if (
            not isinstance(reference, dict)
            or reference.get("valuesRetained") is not False
            or value["preflightReadbackDigest"] != frozen_baseline_digest
            and value["restoreStatus"] != "restored-verified-normalized"
            # A change whose readback was lost (applied false) still counts once
            # its restore verified; an applied change must carry its readback.
            or (
                value["applied"] is True
                and (
                    not isinstance(value["appliedReadbackDigest"], str)
                    or _HEX64.fullmatch(value["appliedReadbackDigest"]) is None
                )
            )
            or value["restoreStatus"] not in VERIFIED_RESTORE_STATUSES
            or not isinstance(value["restoreReadbackDigest"], str)
            or _HEX64.fullmatch(value["restoreReadbackDigest"]) is None
            or not isinstance(value["restoreDifferingFields"], list)
        ):
            return False
        if value["restoreStatus"] == "restored-verified":
            return (
                value["restoreReadbackDigest"] == frozen_baseline_digest
                and value["restoreDifferingFields"] == []
            )
        return True
    except (KeyError, TypeError):
        return False
