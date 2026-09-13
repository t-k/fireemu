"""Execute the closed second45 admission twice on an owned local runtime."""

# ruff: noqa: BLE001 -- Retain failures and unwind owned resources.
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import signal
import subprocess
import sys
import uuid
from pathlib import Path
from urllib.parse import quote, urlencode

from batch_adapter import Adapter, observer_digest, request_headers
from batch_contract import NUMBER, PROJECT, candidate
from broad import run, save
from broad_contract import digest
from owned_runner import control_get, local_addresses
from second_admission import (
    BASE,
    FS_IDS,
    SecondBudget,
    auth_recipe,
    equal,
    fs_recipe,
    manifest,
    operation,
    origins,
    require_operation,
)
from second_cases import auth_cases, auth_invariants
from second_mapping import compare_second

ADMIN = f"identitytoolkit.googleapis.com/v1/projects/{PROJECT}/accounts:"
CLIENT = "identitytoolkit.googleapis.com/v1/accounts:"


class LocalAdapter(Adapter):
    """First transport/ownership only; never invokes its production execution path."""

    def __init__(self, local_origins, nonce, output, mode="mapped"):
        super().__init__(
            candidate(), nonce, output, local_origins=origins(local_origins)
        )
        self.budget = SecondBudget()
        self.phase = "setup"
        self.expected = None
        self.baseline = None
        self.trace = []
        self.cleanup_version = {}
        self.owner_rejected = False
        self.second_nonce = nonce
        if mode not in {"direct", "mapped"}:
            raise ValueError("unknown mode")
        self.mode = mode
        self.users = {}
        self.case_index = None
        self.program_index = None
        self.versions = {}

    def request(
        self, service, path, body=None, *, method="POST", privileged=False, form=False
    ):
        if privileged and self.owner_rejected:
            raise ValueError("local owner credential previously rejected")
        actual = operation(service, path, body, method, privileged)
        if form or service not in {"auth", "firestore"}:
            raise ValueError("closed local transport only")
        if self.expected is not None:
            require_operation(actual, self.expected)
            self.expected = None
        elif service == "auth":
            if path == ADMIN + "lookup" and privileged:
                if (
                    not isinstance(body, dict)
                    or set(body) != {"email"}
                    or not isinstance(body["email"], list)
                    or len(body["email"]) != 1
                    or body["email"][0]
                    not in {
                        f"broad-{self.second_nonce}-{r}@example.invalid"
                        for r in ("a", "b")
                    }
                ):
                    raise ValueError("unowned lookup")
            elif (
                self.phase == "setup"
                and path == CLIENT + "signUp?key=fake"
                and not privileged
            ):
                email = (body or {}).get("email")
                if email not in {
                    f"broad-{self.second_nonce}-{r}@example.invalid" for r in ("a", "b")
                }:
                    raise ValueError("unowned setup")
                require_operation(
                    actual,
                    operation(
                        "auth",
                        path,
                        {
                            "email": email,
                            "password": "abc123",
                            "returnSecureToken": True,
                        },
                    ),
                )
            elif self.phase == "baseline" and self.baseline is not None:
                role = next(
                    (
                        r
                        for r, u in self.users.items()
                        if u["uid"] == self.baseline.get("localId")
                    ),
                    None,
                )
                if role is None or self.case_index is None:
                    raise ValueError("unowned baseline context")
                expected_baseline = {
                    "localId": self.users[role]["uid"],
                    "displayName": role
                    + f"-before-second/auth/{self.case_index + 1:02d}",
                    "emailVerified": False,
                }
                require_operation(
                    actual,
                    operation(
                        "auth", ADMIN + "update", expected_baseline, privileged=True
                    ),
                )
            elif self.budget.recovery and path == ADMIN + "delete" and privileged:
                if (
                    not isinstance(body, dict)
                    or set(body) != {"localId"}
                    or body["localId"] not in self.accounts.values()
                    or body["localId"] is None
                ):
                    raise ValueError("unowned deletion")
            else:
                raise ValueError("unexpected Auth phase operation")
            if method != "POST":
                raise ValueError("Auth method mismatch")
        elif self.budget.recovery:
            name = path.split("?", 1)[0].removeprefix("/v1/")
            if name not in self.documents:
                raise ValueError("unowned recovery document")
            if method == "GET":
                require_operation(
                    actual,
                    operation(
                        "firestore", "/v1/" + name, method="GET", privileged=True
                    ),
                )
            elif method == "DELETE" and name in self.cleanup_version:
                require_operation(
                    actual,
                    operation(
                        "firestore",
                        "/v1/"
                        + name
                        + "?"
                        + urlencode(
                            {"currentDocument.updateTime": self.cleanup_version[name]}
                        ),
                        method="DELETE",
                        privileged=True,
                    ),
                )
            else:
                raise ValueError("unexpected recovery operation")
        else:
            raise ValueError("Firestore requires closed operation ticket")
        entry = {
            "ordinal": len(self.trace),
            "phase": self.phase,
            "recovery": self.budget.recovery,
            "sent": actual,
        }
        self.trace.append(entry)
        self.last_observation = None
        self.persist_trace()
        try:
            if len(json.dumps(body).encode()) > 16384:
                raise ValueError("request byte bound")
            token = self.access() if privileged else None
            self.reserve(service)
            assert self.local is not None
            origin = self.local[service]
            payload = {
                "url": origin + (path if service == "firestore" else "/" + path),
                "origin": origin,
                "method": method,
                "body": body,
                "headers": request_headers(token, local=True, form=False),
                "privateDirectory": str(self.output / "wire" / str(entry["ordinal"])),
            }
            process = subprocess.run(
                ["node", str(Path(__file__).with_name("second_wire.mjs"))],
                input=json.dumps(payload),
                text=True,
                capture_output=True,
                timeout=12,
                check=True,
                env={
                    k: os.environ[k]
                    for k in ("PATH", "LANG", "SYSTEMROOT")
                    if k in os.environ
                },
            )
            received = json.loads(process.stdout)
            http = received["http"]
            status, result = http["status"], received.get("body")
            self.last_observation = {
                "httpStatus": status,
                "mediaType": http["contentType"].split(";", 1)[0].strip().lower(),
                "body": result,
                "http": http,
            }
            if privileged and status in (401, 403):
                self.owner_rejected = True
                self.credential.fail()
                raise ValueError("local owner credential rejected")
            if not http["complete"]:
                raise ValueError("HTTP " + str(http["failure"]))
            if http["bodyKind"] != "json" or not isinstance(result, dict):
                raise ValueError("received non-JSON or unexpected JSON shape")
            if status >= 500 or status == 429 or (privileged and status in (401, 403)):
                raise ValueError("unexpected response")
            entry["observation"] = copy.deepcopy(self.last_observation)
            if (
                self.budget.recovery
                and service == "firestore"
                and method == "GET"
                and status == 200
            ):
                self.cleanup_version[result["name"]] = result["updateTime"]
            return status, result
        except Exception as error:
            entry["failure"] = type(error).__name__
            entry["observation"] = copy.deepcopy(self.last_observation)
            entry["collection"] = (
                "received-rejected-response"
                if self.last_observation is not None
                else "transport-incomplete"
            )
            raise
        finally:
            self.persist_trace()

    def persist_trace(self):
        save(
            self.output / "transport-trace.json",
            {
                "contract": "bounded-http-v1",
                "trace": self.trace,
                "counts": self.budget.counts,
            },
        )

    def send(self, actual):
        if actual["service"] == "auth":
            if self.phase != "diagnostic" or self.case_index is None:
                raise ValueError("Auth diagnostic context required")
            expected = auth_recipe(self.case_index, self.users)
        else:
            if self.program_index not in (0, 1, 2):
                raise ValueError("Firestore program context required")
            name = BASE + (
                "/cur/c"
                if self.mode == "direct"
                else f"/_fireemuBroad/{self.second_nonce}-{self.program_index}/cur/c"
            )
            if self.phase == "absence":
                expected = operation(
                    "firestore", "/v1/" + name, method="GET", privileged=True
                )
            elif self.phase == "seed":
                expected = operation(
                    "firestore",
                    "/v1/" + name + "?currentDocument.exists=false",
                    {
                        "fields": {
                            "n": {"integerValue": "2"},
                            "g": {"stringValue": "q"},
                            "a": {"mapValue": {"fields": {"b": {"integerValue": "7"}}}},
                        }
                    },
                    "PATCH",
                    True,
                )
            else:
                expected, _ = fs_recipe(
                    FS_IDS[self.program_index], self.phase, name, self.versions
                )
        require_operation(actual, expected)
        self.expected = expected
        path = actual["path"]
        if actual["query"]:
            path += "?" + urlencode([tuple(pair) for pair in actual["query"]])
        return self.request(
            actual["service"],
            path,
            actual["body"],
            method=actual["method"],
            privileged=actual["privileged"],
        )

    def recover(self):
        self.phase = "recovery"
        super().cleanup()
        failed_docs = {r["name"] for r in self.unrecovered if r["kind"] == "document"}
        failed_accounts = {
            r["email"] for r in self.unrecovered if r["kind"] == "account"
        }
        self.documents.intersection_update(failed_docs)
        self.accounts = {k: v for k, v in self.accounts.items() if k in failed_accounts}
        if self.unrecovered:
            raise ValueError("incomplete recovery")
        self.budget.recovery = False


def render_auth(case, users):
    actor = case["actor"]
    role = actor if actor in users else "b"
    body = {
        k: "updated-" + case["id"] if v == "$sentinel" else copy.deepcopy(v)
        for k, v in case["fields"].items()
        if v != "$missing"
    }
    selector = case["selector"]
    if selector != "missing":
        body["localId"] = {
            "self": users[role]["uid"],
            "other": users["a" if role == "b" else "b"]["uid"],
            "null": None,
            "number": 0,
            "object": {},
            "array": [],
        }[selector]
    if actor in users:
        body["idToken"] = users[actor]["token"]
    elif actor in ("null", "number", "invalid"):
        body["idToken"] = {
            "null": None,
            "number": 0,
            "invalid": "controlled-invalid-token",
        }[actor]
    return operation(
        "auth",
        ADMIN + "update" if actor == "admin" else CLIENT + "update?key=fake",
        body,
        privileged=actor == "admin",
    )


def render_fs(step, name, versions):
    abstract = "projects/PROJECT/databases/(default)/documents/cur/c"

    def map_value(value):
        if isinstance(value, dict):
            return {k: map_value(v) for k, v in value.items()}
        if isinstance(value, list):
            return [map_value(v) for v in value]
        if isinstance(value, str):
            return (
                value.replace(abstract, name)
                .replace("projects/PROJECT", f"projects/{PROJECT}")
                .replace(
                    "{{original.updateTime}}",
                    quote(versions.get("original", ""), safe=""),
                )
            )
        return value

    value = map_value(step)
    return operation(
        "firestore", value["path"], value.get("body"), value["method"], True
    )


def execute_side(local_origins, output, mode, nonce, runtime_identity):
    if mode not in {"direct", "mapped"}:
        raise ValueError("unknown mode")
    a = LocalAdapter(local_origins, nonce, output, mode)
    users, rows, documents = {}, [], {}
    a.users = users
    result = {
        "kind": "second45-local-run-v1",
        "mode": mode,
        "runtimeIdentity": runtime_identity,
        "nonce": nonce,
        "manifestDigest": digest(manifest()),
        "observerDigest": digest(
            {
                "python": observer_digest(),
                "wire": {
                    name: hashlib.sha256(
                        Path(__file__).with_name(name).read_bytes()
                    ).hexdigest()
                    for name in ("second_wire.mjs", "record-http.mjs")
                },
            }
        ),
        "bindings": users,
        "documents": documents,
        "rows": rows,
        "recordingComplete": False,
        "cleanupComplete": False,
        "safety": True,
        "productionCompatibility": "unobserved",
        "failure": None,
    }

    def persist():
        result["counts"] = dict(a.budget.counts)
        result["trace"] = copy.deepcopy(a.trace)
        result["unrecovered"] = copy.deepcopy(a.unrecovered)
        save(output / "result.json", result)

    def snapshot():
        found = {}
        for role, user in users.items():
            values = a.lookup(user["email"])
            if (
                len(values) != 1
                or values[0].get("localId") != user["uid"]
                or values[0].get("email") != user["email"]
            ):
                raise ValueError("unusable account readback")
            found[role] = values[0]
        return found

    persist()
    try:
        for role in ("a", "b"):
            email = f"broad-{nonce}-{role}@example.invalid"
            status, body = a.auth_call(
                CLIENT + "signUp?key=fake",
                {"email": email, "password": "abc123", "returnSecureToken": True},
            )
            if status != 200 or not body.get("idToken"):
                raise ValueError("setup failed")
            users[role] = {
                "uid": body["localId"],
                "token": body["idToken"],
                "email": email,
            }
        initial = None
        for index, case in enumerate(auth_cases()):
            a.case_index = index
            a.phase = "baseline"
            for role in ("a", "b"):
                a.baseline = {
                    "localId": users[role]["uid"],
                    "displayName": role + "-before-" + case["id"],
                    "emailVerified": False,
                }
                status, _ = a.auth_call(ADMIN + "update", a.baseline, admin=True)
                if status != 200:
                    raise ValueError("baseline failed")
            a.phase = "before"
            before = snapshot()
            if any(
                before[r].get("displayName") != r + "-before-" + case["id"]
                or before[r].get("emailVerified") is not False
                for r in users
            ):
                raise ValueError("baseline readback mismatch")
            protected = {
                r: {
                    k: v
                    for k, v in before[r].items()
                    if k in ("disabled", "customAttributes", "mfaInfo")
                }
                for r in users
            }
            if initial is None:
                initial = copy.deepcopy(protected)
            elif not equal(initial, protected):
                result["safety"] = False
                raise ValueError("protected baseline drift; stop without repair")
            actual = render_auth(case, users)
            if case["actor"] == "admin":
                a.owner(users["b"]["uid"])
            a.phase = "diagnostic"
            status, _ = a.send(actual)
            observation = copy.deepcopy(a.last_observation)
            a.phase = "after"
            after = snapshot()
            checks = auth_invariants(case, status, before, after)
            rows.append(
                {
                    "id": case["id"],
                    "sent": actual,
                    "observation": observation,
                    "before": before,
                    "after": after,
                    "checks": checks,
                    "relation": None,
                }
            )
            result["safety"] = all(checks.values())
            persist()
            if not result["safety"]:
                raise ValueError("protected state changed; Auth stopped")
        a.recover()
        for index, program in enumerate(manifest()["firestorePrograms"]):
            name = BASE + (
                "/cur/c"
                if mode == "direct"
                else f"/_fireemuBroad/{nonce}-{index}/cur/c"
            )
            documents[program["id"]] = name
            a.program_index = index
            a.phase = "absence"
            op = operation("firestore", "/v1/" + name, method="GET", privileged=True)
            status, _ = a.send(op)
            if status != 404:
                raise ValueError("seed target not absent")
            a.record({"kind": "document-attempt", "name": name})
            a.documents.add(name)
            a.phase = "seed"
            seed_body = {"fields": program["seed"][0]["fields"]}
            expected_seed = {
                "fields": {
                    "n": {"integerValue": "2"},
                    "g": {"stringValue": "q"},
                    "a": {"mapValue": {"fields": {"b": {"integerValue": "7"}}}},
                }
            }
            if not equal(seed_body, expected_seed) or len(program["seed"]) != 1:
                raise ValueError("closed seed changed")
            op = operation(
                "firestore",
                "/v1/" + name + "?currentDocument.exists=false",
                seed_body,
                "PATCH",
                True,
            )
            status, _ = a.send(op)
            if status != 200:
                raise ValueError("seed failed")
            versions, reads = {}, {}
            a.versions = versions
            for step in program["steps"]:
                a.phase = step["id"]
                actual = render_fs(step, name, versions)
                _expected, relation = fs_recipe(
                    program["id"], step["id"], name, versions
                )
                status, body = a.send(actual)
                observation = copy.deepcopy(a.last_observation)
                if step["id"] in ("original", "before", "after"):
                    if (
                        status != 200
                        or not isinstance(body, dict)
                        or body.get("name") != name
                        or not isinstance(body.get("fields"), dict)
                        or not isinstance(body.get("updateTime"), str)
                    ):
                        raise ValueError(
                            "unusable document readback; state indeterminate"
                        )
                    versions[step["id"]] = body["updateTime"]
                    reads[step["id"]] = body
                rows.append(
                    {
                        "id": program["id"] + "/" + step["id"],
                        "sent": actual,
                        "observation": observation,
                        "document": name,
                        "versions": copy.deepcopy(versions),
                        "relation": relation,
                    }
                )
                persist()
            diagnostic = next(
                r for r in rows if r["id"] == program["id"] + "/diagnostic"
            )
            if diagnostic["observation"]["httpStatus"] >= 400 and not equal(
                reads["before"], reads["after"]
            ):
                result["safety"] = False
                raise ValueError("refused operation changed document")
            a.recover()
        result["recordingComplete"] = len(rows) == 45
    except Exception as error:
        result["failure"] = {
            "kind": type(error).__name__,
            "reason": str(error),
            "phase": a.phase,
        }
    finally:
        try:
            if a.accounts or a.documents:
                a.recover()
        except Exception as error:
            result["cleanupFailure"] = type(error).__name__
        if not result["recordingComplete"] and result["safety"] is not False:
            result["safety"] = None
        result["cleanupComplete"] = (
            not a.accounts and not a.documents and not a.unrecovered
        )
        persist()
    return result


def run_pair(local_origins, output, runtime_identity):
    origins(local_origins)
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    direct = execute_side(
        local_origins, output / "direct", "direct", uuid.uuid4().hex, runtime_identity
    )
    if (
        direct["safety"] is False
        or not direct["cleanupComplete"]
        or not direct["recordingComplete"]
    ):
        mapped = {
            "mode": "mapped",
            "nonce": None,
            "rows": [],
            "recordingComplete": False,
            "cleanupComplete": True,
            "safety": None,
            "skipReason": "direct incomplete, safety violation, or unconfirmed cleanup",
        }
        comparison = compare_second(direct, mapped)
        save(output / "comparison.json", comparison)
        return comparison
    mapped = execute_side(
        local_origins, output / "mapped", "mapped", uuid.uuid4().hex, runtime_identity
    )
    comparison = compare_second(direct, mapped)
    save(output / "comparison.json", comparison)
    return comparison


def child(output, nonce):
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
    runtime_identity = {
        k: initial[k]
        for k in ("artifactSha256", "executionCommit", "configurationDigest")
    }
    comparison = run_pair(local, output / "pair", runtime_identity)
    cases = [
        {
            "id": r["id"],
            "family": "second45-mapping",
            "basis": "independently-admitted-local-pair",
            "status": "pass" if r["mapping"] == "match" else "mismatch",
            "productionCompatibility": "unobserved",
        }
        for r in comparison["rows"]
    ]
    if not cases:
        cases = [
            {
                "id": "second45/incomplete",
                "family": "second45-mapping",
                "basis": "incomplete-local-recording",
                "status": "indeterminate",
            }
        ]
    save(
        output / "cases.json",
        {
            "schemaVersion": 1,
            "kind": "second45-local-pair-v1",
            "cases": cases,
            "manifest": manifest(),
            "manifestDigest": digest(manifest()),
            "recordingComplete": comparison["recordingComplete"],
            "localObservations": {"comparison": comparison},
            "productionExecuted": False,
        },
    )
    if (
        not comparison["recordingComplete"]
        or not comparison["safety"]
        or comparison["mapping"] != "match"
    ):
        raise ValueError(
            "second45 incomplete, unsafe, or mapping mismatch; retained private results"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--child", type=Path)
    parser.add_argument("--nonce")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--write-manifest", type=Path)
    args = parser.parse_args()
    if args.write_manifest:
        save(args.write_manifest, manifest())
        return 0
    if args.child:
        child(args.child, args.nonce)
        return 0
    if args.output is None:
        parser.error("--output required")
    report = run(
        args.output.resolve(),
        child_script=Path(__file__).resolve(),
        project=PROJECT,
        configuration={"daemon": {"authProjectNumbers": {PROJECT: NUMBER}}},
        execution_timeout=2430,
        recovery_grace=300,
    )
    print(
        json.dumps(
            {
                "status": report["status"],
                "recordingComplete": report["recordingComplete"],
            }
        )
    )
    return 0 if report["status"] == "completed" else 2


if __name__ == "__main__":

    def interrupted(_signal, _frame):
        raise InterruptedError("stop requested; unwind cleanup")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    sys.exit(main())
