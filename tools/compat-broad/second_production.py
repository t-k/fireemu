"""Second45 explicit production connection. Default preparation performs no I/O to Cloud."""

from __future__ import annotations

import argparse
import copy
import json
import os
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit

from batch_adapter import Adapter, request_headers, wire
from batch_contract import DATABASE_PROJECTION, NUMBER, PROJECT
from broad import save
from broad_contract import ROOT, digest
from second_admission import manifest as local_manifest
from second_mapped import LocalAdapter, execute_45
from second_production_contract import approve, binding, manifest, observer_digest


class Production45Adapter(LocalAdapter):
    """A distinct closed constructor; never initialized through loopback state."""

    def __init__(self, value, permission, nonce, output):
        approve(value, permission, nonce, observer_digest(), time.time())
        frozen = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        if (
            permission.get("frozenCommit") != frozen
            or subprocess.check_output(
                ["git", "status", "--porcelain"], cwd=ROOT
            ).strip()
        ):
            raise ValueError("approved frozen checkout required")
        key = os.environ.get("PRODUCTION_ORACLE_API_KEY")
        if not key:
            raise ValueError("API key required")
        consumed = Path.home() / ".local/state/fireemu-broad/consumed"
        consumed.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(consumed / nonce, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(digest(permission))
            stream.flush()
            os.fsync(stream.fileno())
        self.manifest, self.permission, self.nonce = value, permission, nonce
        self.local, self.ready, self.api_key = None, False, key
        self.initialize_state(output, nonce)
        self.initialize_second(nonce, "mapped")
        self.metadata_trace = []
        self.configuration_unchanged = None
        self.metadata_phase = None
        self.confirmed_key_digest = None

    def auth_query_key(self):
        # The recipe uses a bound abstract key. Resolve only at the actual wire edge.
        return "fake"

    def names(self):
        return {
            "authEmails": {
                r: f"broad-{self.nonce}-{r}@example.invalid" for r in ("a", "b")
            },
            "authUids": {
                r: self.accounts.get(f"broad-{self.nonce}-{r}@example.invalid")
                for r in ("a", "b")
            },
            "firestoreParents": {},
        }

    def request(
        self, service, path, body=None, *, method="POST", privileged=False, form=False
    ):
        if service == "metadata":
            allowed = {
                f"cloudresourcemanager.googleapis.com/v1/projects/{PROJECT}",
                f"firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)",
                f"identitytoolkit.googleapis.com/admin/v2/projects/{PROJECT}/config",
                "apikeys.googleapis.com/v2/keys:lookupKey?"
                + urlencode({"keyString": self.api_key}),
            }
            if (
                self.metadata_phase not in {"preflight", "postflight"}
                or path not in allowed
                or body is not None
                or method != "GET"
                or not privileged
                or form
            ):
                raise ValueError("closed metadata admission")
            entry = {"phase": self.metadata_phase, "operation": path.split("?", 1)[0]}
            self.metadata_trace.append(entry)
            try:
                result = Adapter.request(
                    self,
                    service,
                    path,
                    body,
                    method=method,
                    privileged=privileged,
                    form=form,
                )
                entry["observation"] = copy.deepcopy(self.last_observation)
                return result
            finally:
                save(self.output / "metadata-trace.json", self.metadata_trace)
        if not self.ready:
            raise ValueError("complete preflight required before data operations")
        return super().request(
            service, path, body, method=method, privileged=privileged, form=form
        )

    def preflight(self):
        if (
            self.confirmed_key_digest is not None
            and self.confirmed_key_digest != digest(self.api_key)
        ):
            raise ValueError("verified API key binding changed")
        self.metadata_phase = "postflight" if self.budget.recovery else "preflight"
        try:
            Adapter.preflight(self)
            self.confirmed_key_digest = digest(self.api_key)
        finally:
            self.metadata_phase = None

    def collect(self, service, path, body, method, token, entry):
        if self.confirmed_key_digest != digest(self.api_key):
            raise ValueError("verified API key binding changed")
        if token:
            if not self.credential.usable(time.monotonic()):
                raise ValueError("verified expiry no longer covers request")
            self.auth_evidence.append(
                {
                    "ordinal": entry["ordinal"],
                    "operation": path.split("?", 1)[0],
                    "phase": "recovery" if self.budget.recovery else "observation",
                    "verifiedRemainingSeconds": self.credential.expiry
                    - time.monotonic(),
                    "basis": "tokeninfo",
                }
            )
        parsed = urlsplit(path)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if service == "auth" and not entry["sent"]["privileged"]:
            if pairs != [("key", "fake")]:
                raise ValueError("exact bound key slot required")
            path = parsed.path + "?" + urlencode({"key": self.api_key})
        elif any(k == "key" for k, _ in pairs):
            raise ValueError("unexpected administrator key slot")
        url = (
            "https://firestore.googleapis.com" + path
            if service == "firestore"
            else "https://" + path
        )
        return wire(
            url,
            method,
            body,
            request_headers(token, local=False, form=False),
            receipt=True,
        )

    def permits_absent_after(self):
        return True

    def finish(self):
        if not self.ready:
            return
        self.budget.recovery = True
        try:
            self.preflight()
            self.configuration_unchanged = True
        except Exception:
            self.configuration_unchanged = False
            raise

    def result_fields(self):
        return {
            "kind": "second45-production-run-v1",
            "target": "production",
            "manifestDigest": digest(manifest()),
            "admissionDigest": digest(local_manifest()),
            "comparisonContractDigest": digest(binding()),
            "observerDigest": observer_digest(),
            "configurationUnchanged": self.configuration_unchanged,
            "metadataTrace": self.metadata_trace,
            "privilegedRequests": self.auth_evidence,
            "databaseObservations": self.database_observations,
            "productionExecuted": True,
            "preflightComplete": self.ready,
            "permission": self.permission,
            "permissionDigest": digest(self.permission),
        }


class CurrentLocal45Adapter(LocalAdapter):
    """Explicit loopback constructor with the current comparison contract."""

    def permits_absent_after(self):
        return True

    def result_fields(self):
        return {
            "kind": "second45-current-local-run-v1",
            "target": "local",
            "manifestDigest": digest(manifest()),
            "admissionDigest": digest(local_manifest()),
            "comparisonContractDigest": digest(binding()),
            "observerDigest": observer_digest(),
            "productionExecuted": False,
        }


def local_child(output, nonce):
    from owned_runner import control_get, local_addresses
    from second_admission import origins

    auth = "http://" + os.environ["FIREBASE_AUTH_EMULATOR_HOST"]
    fs, control = local_addresses(
        os.environ["FIRESTORE_EMULATOR_HOST"], os.environ["FIREEMU_CONTROL_URL"]
    )
    local = origins({"auth": auth, "firestore": fs})
    token = os.environ["FIREEMU_CONTROL_TOKEN"]
    status, body = control_get(control, "/v1/sessions/default/resources", token)
    wrong, _ = control_get(control, "/v1/sessions/default/resources", token + "-wrong")
    if (
        status != 200
        or wrong != 403
        or body.get("project") != PROJECT
        or os.environ["GOOGLE_CLOUD_PROJECT"] != PROJECT
    ):
        raise ValueError("owned runtime identity mismatch")
    save(
        output / "instance.json",
        {
            "pid": os.getpid(),
            "parentPid": os.getppid(),
            "argv": sys.argv,
            "nonce": nonce,
            "authOrigin": auth,
            "firestoreOrigin": fs,
            "controlOrigin": control,
            "wrongTokenStatus": wrong,
        },
    )
    initial = json.loads((output / "manifest.json").read_bytes())
    identity = {
        key: initial[key]
        for key in ("artifactSha256", "executionCommit", "configurationDigest")
    }
    adapter = CurrentLocal45Adapter(local, uuid.uuid4().hex, output / "mapped")
    result = execute_45(adapter, adapter.output, identity)
    save(
        output / "cases.json",
        {
            "schemaVersion": 1,
            "kind": "second45-current-local-v1",
            "cases": [
                {
                    "id": row["id"],
                    "family": "second45-current-local",
                    "basis": "local-safety-not-production-compatibility",
                    "status": "pass" if result["safety"] is True else "indeterminate",
                }
                for row in result["rows"]
            ]
            or [
                {
                    "id": "second45/incomplete",
                    "family": "second45-current-local",
                    "status": "indeterminate",
                }
            ],
            "recordingComplete": result["recordingComplete"],
            "localObservations": {"mapped": result},
            "productionExecuted": False,
        },
    )
    return (
        0
        if result["recordingComplete"]
        and result["cleanupComplete"]
        and result["safety"] is True
        else 2
    )


def execution_inputs():
    frozen = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT).strip():
        raise ValueError("freeze checkout before package creation")
    return {
        "kind": "second45-prepared-inputs-not-permission-v1",
        "frozenCommit": frozen,
        "manifest": manifest(),
        "manifestSha256": digest(manifest()),
        "observerSha256": observer_digest(),
        "comparisonContract": binding(),
        "comparisonContractDigest": digest(binding()),
        "databaseProjectionContract": DATABASE_PROJECTION,
        "databaseProjectionContractDigest": digest(DATABASE_PROJECTION),
        "project": PROJECT,
        "projectNumber": NUMBER,
        "quotaProject": PROJECT,
        "ownerIdentity": None,
        "permissionReference": None,
        "nonce": None,
        "issuedAt": None,
        "expiresAt": None,
        "databaseProjection": None,
        "databaseProjectionDigest": None,
        "authConfigDigest": None,
        "pricingLocation": None,
        "pricingCheckedAt": None,
        "tariffsConfirmedBelowPlanningCeilings": None,
        "costAssumptions": None,
        "productionExecuted": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-output", type=Path)
    parser.add_argument("--child", type=Path)
    parser.add_argument("--nonce")
    parser.add_argument("--write-inputs", type=Path)
    parser.add_argument("--execute-permission", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.child:
        return local_child(args.child, args.nonce)
    if args.local_output:
        from broad import run

        report = run(
            args.local_output.resolve(),
            child_script=Path(__file__).resolve(),
            project=PROJECT,
            configuration={"daemon": {"authProjectNumbers": {PROJECT: NUMBER}}},
            execution_timeout=1230,
            recovery_grace=300,
        )
        return 0 if report["status"] == "completed" else 2
    if args.write_inputs:
        save(args.write_inputs, execution_inputs())
        return 0
    if not (args.execute_permission and args.manifest and args.output):
        parser.error(
            "offline --write-inputs or explicit --execute-permission --manifest --output required"
        )
    permission = json.loads(args.execute_permission.read_bytes())
    adapter = Production45Adapter(
        json.loads(args.manifest.read_bytes()),
        permission,
        permission.get("nonce"),
        args.output,
    )
    result = execute_45(
        adapter,
        args.output,
        {
            "executionCommit": permission["frozenCommit"],
            "project": PROJECT,
            "projectNumber": NUMBER,
        },
    )
    return (
        0
        if result["recordingComplete"]
        and result["cleanupComplete"]
        and result["safety"] is True
        else 2
    )


if __name__ == "__main__":

    def interrupted(_signal, _frame):
        raise InterruptedError("stop requested; unwind owned cleanup")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    raise SystemExit(main())
