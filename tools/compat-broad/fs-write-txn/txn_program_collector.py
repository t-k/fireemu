"""A finite closed-graph recording with durable responsibility before each dispatch.

`Ledger` holds every rule about tokens, owned documents and unresolved outcomes, and has no I/O.
The collector drives it while recording; `projection` replays a saved recording through a fresh
one, so a completion claim is only ever what the native rows derive."""

from __future__ import annotations

import copy
import datetime as dt
import math
import re
import time

from txn_program_program import GraphCursor, canonical_token, compile_plan, corpus_digest, marker_fields, outcome_class, request_for_step, source_digest, validate_plan

RECEIPT_KIND = "txn-program-receipt-v1"
RECORDING_KIND = "txn-program-recording-v1"
RESOLVED_TOKENS = ("committed", "rolled-back", "released-refused")
_GRPC_TIME = "gRPC updateTime"
_REST_TIME = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,9})?Z\Z")


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _utc_seconds(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("UTC endpoint required")
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def check_timing(value):
    if not isinstance(value, dict) or set(value) != {"dispatchMonotonic", "responseMonotonic", "dispatchUtc", "responseUtc"}:
        raise ValueError("closed RPC timing required")
    a, b = value["dispatchMonotonic"], value["responseMonotonic"]
    if any(type(x) not in (int, float) or not math.isfinite(x) or x < 0 for x in (a, b)) or b < a:
        raise ValueError("monotonic endpoint invalid")
    ua, ub = _utc_seconds(value["dispatchUtc"]), _utc_seconds(value["responseUtc"])
    if ub < ua or abs((ub - ua) - (b - a)) > 0.25:
        raise ValueError("UTC and monotonic RPC elapsed differ")


def check_timestamp(value, transport):
    """A document version stamp as its transport answers it: gRPC seconds and nanos, REST RFC 3339."""
    if transport == "rest":
        if not isinstance(value, str) or not _REST_TIME.fullmatch(value):
            raise ValueError("REST updateTime required")
        return value
    if not isinstance(value, dict) or set(value) - {"seconds", "nanos"} or not isinstance(value.get("seconds"), str) or not re.fullmatch(r"[0-9]{1,12}", value["seconds"]) or type(value.get("nanos", 0)) is not int or not 0 <= value.get("nanos", 0) <= 999999999:
        raise ValueError(f"native {_GRPC_TIME} required")
    return {"seconds": value["seconds"], "nanos": value.get("nanos", 0)}


def _string_field(value):
    # Native protobuf decoding can include its matching oneof discriminator.
    return isinstance(value, dict) and set(value) in ({"stringValue"}, {"stringValue", "valueType"}) and isinstance(value.get("stringValue"), str) and value.get("valueType", "stringValue") == "stringValue"


class Ledger:
    def __init__(self, plan):
        self.plan = plan
        self.last_use = {}
        for step in plan["steps"]:
            if step["tokenInput"]:
                self.last_use[step["tokenInput"]] = step["id"]
        self.tokens = {}
        self.docs = {role: {"status": "unexamined", "state": None, "possible": [], "stamp": None} for role in plan["documents"]}
        self.unknown_starts, self.unknown_rollbacks, self.unknown_commits = set(), set(), set()
        self._prior = {}
        self._probes = set()

    def snapshot(self):
        return {
            "tokens": copy.deepcopy(self.tokens),
            "documents": copy.deepcopy(self.docs),
            "unknownStarts": sorted(self.unknown_starts),
            "unknownRollbacks": sorted(self.unknown_rollbacks),
            "unknownCommits": sorted(self.unknown_commits),
        }

    def token_values(self):
        return {role: entry["value"] for role, entry in self.tokens.items()}

    def _token_for(self, value):
        for role, entry in self.tokens.items():
            if entry["value"] == value:
                return role, entry
        return None, None

    def unresolved_tokens(self):
        return [role for role, entry in self.tokens.items() if entry["state"] in ("open", "unconfirmed-release")]

    def pending_release(self, step):
        """Tokens whose last declared use is `step` and that no answer has finished."""
        return [role for role, entry in self.tokens.items() if self.last_use.get(role) == step["id"] and entry["state"] == "open"]

    def release_request(self, role):
        return {"database": self.plan["database"], "transaction": self.tokens[role]["value"]}

    def cleanup_request(self, kind, role):
        name = self.plan["documents"][role]
        if kind == "delete":
            return {"name": name, "currentDocument": {"updateTime": self.docs[role]["stamp"]}}
        return {"name": name}

    def owed_documents(self):
        return [role for role, doc in self.docs.items() if doc["status"] in ("possibly-owned", "created")]

    def all_absent(self):
        return all(doc["status"] == "confirmed-absent" for doc in self.docs.values())

    def guard(self, method, request, step):
        """Refuse a dispatch the graph forbids; nothing is recorded."""
        if method == "BeginTransaction":
            if any(entry["state"] in ("open", "unconfirmed-release") for entry in self.tokens.values()):
                raise ValueError("a prior chain's token is unresolved")
        elif method == "Rollback":
            _role, entry = self._token_for(request["transaction"])
            if entry is None:
                raise ValueError("rollback names no issued token")
            # A declared rollback of a token an answer already finished is a probe; only an open token is released.
            if step is None and entry["state"] != "open":
                raise ValueError("token release cannot repeat")

    def before(self, site, transport, method, request, step):
        """Record the responsibility a dispatch takes on, once the graph allows it."""
        self.guard(method, request, step)
        if method == "BeginTransaction":
            self.unknown_starts.add(site)
        elif method == "Rollback":
            role, entry = self._token_for(request["transaction"])
            if entry["state"] == "open":
                self.unknown_rollbacks.add(role)
                entry["state"] = "unconfirmed-release"
            else:
                self._probes.add(site)
        elif method == "Commit":
            self.unknown_commits.add(site)
            self._prior[site] = {}
            for write in step["writes"] if step else []:
                doc = self.docs[write["document"]]
                self._prior[site][write["document"]] = copy.deepcopy(doc)
                if doc["status"] != "created":
                    doc["status"] = "possibly-owned"
                if write["state"] not in doc["possible"]:
                    doc["possible"].append(write["state"])

    def _check_receipt(self, transport, method, result):
        if not isinstance(result, dict) or result.get("kind") != RECEIPT_KIND or result.get("transport") != transport:
            raise ValueError("native receipt differs from the dispatch")
        code = result.get("code")
        if type(code) is not int or not 0 <= code <= 16 or type(result.get("dispatchedRequests")) is not int or result["dispatchedRequests"] != 1 or result.get("complete") is not True or result.get("childReaped") is not True or outcome_class(code) == "UNKNOWN":
            raise ValueError("native outcome is indeterminate")
        if not isinstance(result.get("details"), str) or len(result["details"].encode()) > 16384:
            raise ValueError("native details are malformed")
        if code == 0 and not isinstance(result.get("response"), dict):
            raise ValueError("native success has no typed response")

    def after(self, site, transport, method, request, step, result, timing):
        self._check_receipt(transport, method, result)
        code = result["code"]
        self._apply(site, transport, method, request, step, result, timing, code)
        if step is not None and code not in step["allow"]:
            raise ValueError(f"outcome {code} at {site} is outside the declared set")

    def _apply(self, site, transport, method, request, step, result, timing, code):
        if method == "BeginTransaction":
            self.unknown_starts.discard(site)
            if code == 0:
                token = canonical_token(result["response"].get("transaction"))
                if token in self.token_values().values():
                    raise ValueError("minted token is not fresh")
                self.tokens[step["tokenOutput"]] = {"value": token, "state": "open", "transport": transport, "start": copy.deepcopy(timing), "lastUse": copy.deepcopy(timing)}
            return
        if method == "Commit":
            self.unknown_commits.discard(site)
            if code == 0:
                writes = result["response"].get("writeResults")
                if not isinstance(writes, list) or len(writes) != len(request["writes"]) or any(not isinstance(write, dict) for write in writes):
                    raise ValueError("commit lacks its per-write acknowledgements")
                for write in writes:
                    check_timestamp(write.get("updateTime"), transport)
                for write in step["writes"]:
                    doc = self.docs[write["document"]]
                    doc.update(status="created", state=write["state"], possible=[write["state"]])
                _role, entry = self._token_for(request.get("transaction"))
                if entry is not None:
                    entry["state"] = "committed"
            else:
                for role, prior in self._prior.pop(site, {}).items():
                    self.docs[role] = prior
            self._prior.pop(site, None)
        elif method == "DeleteDocument":
            if code != 0:
                raise ValueError("version deletion refused")
        elif method == "Rollback":
            role, entry = self._token_for(request["transaction"])
            probe = site in self._probes
            self._probes.discard(site)
            if not probe:
                self.unknown_rollbacks.discard(role)
                if code == 0:
                    entry["state"] = "rolled-back"
                elif step is not None and code in step["allow"]:
                    entry["state"] = "released-refused"
                else:
                    entry["state"] = "open"
        if code == 0 and method != "BeginTransaction":
            _role, entry = self._token_for(request.get("transaction"))
            if entry is not None:
                entry["lastUse"] = copy.deepcopy(timing)
        if method == "GetDocument":
            self._read(site, transport, request, result, code, step)

    def _role_of(self, name):
        return next(role for role, document in self.plan["documents"].items() if document == name)

    def _owned(self, role, document, transport, allowed):
        if not isinstance(document, dict) or document.get("name") != self.plan["documents"][role]:
            raise ValueError("read did not return its exact document")
        fields = document.get("fields")
        if not isinstance(fields, dict) or set(fields) != {"owner", "nonce", "role", "state"} or any(not _string_field(field) for field in fields.values()):
            raise ValueError("owned marker schema differs")
        expected = {"owner": self.plan["ownerId"], "nonce": self.plan["nonce"], "role": role}
        if any(fields[key]["stringValue"] != value for key, value in expected.items()):
            raise ValueError("document owner differs; deletion refused")
        if fields["state"]["stringValue"] not in allowed:
            raise ValueError("document state differs from the acknowledged state")
        return check_timestamp(document.get("updateTime"), transport)

    def _read(self, site, transport, request, result, code, step):
        role = self._role_of(request["name"])
        doc = self.docs[role]
        if site.startswith("cleanup/"):
            return self._cleanup_read(site, role, transport, result, code)
        if doc["status"] == "unexamined":
            doc["status"] = "confirmed-absent" if code == 5 else "pre-existing"
            if code != 5:
                raise ValueError("document was not absent; no write admitted")
            return
        if code != 0:
            return
        if doc["state"] is None:
            raise ValueError("a document this recording never wrote exists")
        self._owned(role, result["response"], transport, {doc["state"]})

    def _cleanup_read(self, site, role, transport, result, code):
        doc = self.docs[role]
        if site.startswith("cleanup/read/"):
            if code != 0:
                raise ValueError("owned document is not readable for deletion")
            doc["stamp"] = self._owned(role, result["response"], "grpc", set(doc["possible"]) | {doc["state"]})
        elif site.startswith("cleanup/verify/") and code == 5:
            doc["status"] = "confirmed-absent"
        elif site.startswith("cleanup/verify/"):
            raise ValueError("deleted document is not absent")


class Collector:
    def __init__(self, plan, table, budget, wire, bearer, *, save, before_send=lambda: None, monotonic=time.monotonic, observation_deadline=None, utc=utc_now):
        validate_plan(plan, table)
        self.plan, self.table = copy.deepcopy(plan), table
        self.budget, self.wire, self.bearer, self.save, self.before_send = budget, wire, bearer, save, before_send
        self.monotonic, self.utc = monotonic, utc
        self.ledger = Ledger(self.plan)
        self.observation_deadline = observation_deadline or monotonic() + plan["observationSeconds"]
        self.deadline = self.observation_deadline
        self.rows, self.cleanup_rows = [], []
        self.pending = None
        self.journal_failure = False
        self._last_monotonic = monotonic()

    def _now(self):
        current = self.monotonic()
        if type(current) not in (int, float) or not math.isfinite(current) or current < self._last_monotonic:
            raise ValueError("clock is invalid or moved backwards")
        self._last_monotonic = current
        return current

    def _state(self):
        return {"kind": "txn-program-responsibility-v1", "plan": self.plan, **self.ledger.snapshot(), "pending": copy.deepcopy(self.pending), "rows": copy.deepcopy(self.rows), "cleanupRows": copy.deepcopy(self.cleanup_rows), "requests": self.budget.total}

    def _persist(self):
        try:
            self.save(self._state())
        except (Exception, KeyboardInterrupt):
            self.journal_failure = True
            self.budget.failed = True
            raise

    def _rpc(self, site, transport, method, request, phase, *, step=None):
        if self.journal_failure:
            raise ValueError("journal failed; no further dispatch is safe")
        self.before_send()
        wanted = step["deadlineMs"] / 1000 if step else 10
        need = max(13, wanted + 3)
        if self.deadline - self._now() < need:
            raise TimeoutError("phase deadline exceeded")
        self.ledger.guard(method, request, step)
        self.budget.charge(phase)
        self.ledger.before(site, transport, method, request, step)
        self.pending = {"site": site, "rpc": method, "transport": transport}
        self._persist()
        self.before_send()
        remaining = self.deadline - self._now()
        if remaining < need:
            raise TimeoutError("dispatch no longer fits after durable journal")
        timing = {"dispatchMonotonic": self._now(), "dispatchUtc": self.utc()}
        result = self.wire.send(transport, method, request, nonce=self.plan["nonce"], owner_id=self.plan["ownerId"], bearer=self.bearer, deadline_ms=max(1, min(int(wanted * 1000), int(remaining * 1000))))
        timing.update(responseMonotonic=self._now(), responseUtc=self.utc())
        check_timing(timing)
        row = {"sequence": len(self.rows) + len(self.cleanup_rows), "phase": phase, "timing": timing, "site": site, "transport": transport, "rpc": method, "caseId": step["caseId"] if step else None, "request": copy.deepcopy(request), "result": copy.deepcopy(result)}
        (self.rows if phase == "observation" else self.cleanup_rows).append(row)
        try:
            self.ledger.after(site, transport, method, request, step, result, timing)
        except (Exception, KeyboardInterrupt):
            self._persist()
            raise
        row["outcomeClass"] = outcome_class(result["code"])
        self.pending = None
        self._persist()
        return result

    def _observe(self):
        cursor = GraphCursor(self.plan, self.table)
        for declared in self.plan["steps"]:
            step = cursor.claim(declared["id"])
            request = request_for_step(self.plan, step, self.ledger.token_values(), self.table)
            self._rpc(step["id"], step["transport"], step["rpc"], request, "observation", step=step)
            for role in self.ledger.pending_release(step):
                site = f"cleanup/token/{role}"
                self._rpc(site, self.ledger.tokens[role]["transport"], "Rollback", self.ledger.release_request(role), "tokenCleanup")
                if self.ledger.tokens[role]["state"] != "rolled-back":
                    raise ValueError("chain release is unconfirmed; next chain forbidden")
        return cursor.complete

    def _cleanup(self):
        for role in list(self.ledger.tokens):
            if self.ledger.tokens[role]["state"] != "open":
                continue
            try:
                self._rpc(f"cleanup/token/{role}", self.ledger.tokens[role]["transport"], "Rollback", self.ledger.release_request(role), "tokenCleanup")
            except (Exception, KeyboardInterrupt):
                # A release attempted during observation or recovery cannot repeat.
                continue
        for role in self.ledger.owed_documents():
            try:
                self._rpc(f"cleanup/read/{role}", "grpc", "GetDocument", self.ledger.cleanup_request("read", role), "documentCleanup")
                self._rpc(f"cleanup/delete/{role}", "grpc", "DeleteDocument", self.ledger.cleanup_request("delete", role), "documentCleanup")
                self._rpc(f"cleanup/verify/{role}", "grpc", "GetDocument", self.ledger.cleanup_request("verify", role), "documentCleanup")
            except (Exception, KeyboardInterrupt):
                continue
        return self.ledger.all_absent()

    def run(self):
        failure = None
        graph_complete = False
        try:
            graph_complete = self._observe()
        except (Exception, KeyboardInterrupt) as error:
            failure = type(error).__name__
        absent = self.ledger.all_absent()
        try:
            if hasattr(self.budget, "begin_recovery"):
                self.budget.begin_recovery()
            self.deadline = self._now() + self.plan["recoverySeconds"]
            absent = self._cleanup()
        except (Exception, KeyboardInterrupt) as error:
            failure = failure or type(error).__name__
        snapshot = self.ledger.snapshot()
        open_tokens = self.ledger.unresolved_tokens()
        observations = [row for row in self.rows if row["caseId"]]
        unrecovered = bool(open_tokens or snapshot["unknownStarts"] or snapshot["unknownRollbacks"] or snapshot["unknownCommits"] or not absent or self.journal_failure)
        complete = graph_complete and failure is None and not unrecovered and [row["caseId"] for row in observations] == self.plan["cases"]
        return {
            "kind": RECORDING_KIND,
            "complete": complete,
            "graphComplete": graph_complete,
            "program": self.plan["program"],
            "packetName": self.plan["packetName"],
            "sourceDigest": self.plan["sourceDigest"],
            "corpusDigest": self.plan["corpusDigest"],
            "nonce": self.plan["nonce"],
            "ownerId": self.plan["ownerId"],
            "observations": copy.deepcopy(observations),
            "steps": copy.deepcopy(self.rows),
            "cleanupSteps": copy.deepcopy(self.cleanup_rows),
            "tokens": snapshot["tokens"],
            "documents": snapshot["documents"],
            "unknownStarts": snapshot["unknownStarts"],
            "unknownRollbacks": snapshot["unknownRollbacks"],
            "unknownCommits": snapshot["unknownCommits"],
            "timingMode": "wall-clock",
            "timingSource": "parent-wire-envelope",
            "openTokens": open_tokens,
            "journalFailure": self.journal_failure,
            "cleanup": {"absent": absent},
            "unrecovered": unrecovered,
            "failureType": failure,
            "sandboxRequests": self.budget.total,
            "phaseRequests": dict(self.budget.used),
        }


def projection(receipt, table):
    """Replay every row of a complete recording; only what the rows derive can freeze."""
    if not isinstance(receipt, dict) or receipt.get("kind") != RECORDING_KIND or receipt.get("complete") is not True or receipt.get("graphComplete") is not True or receipt.get("journalFailure") is not False or receipt.get("unrecovered") is not False or receipt.get("failureType") is not None or any(receipt.get(key) for key in ["openTokens", "unknownStarts", "unknownRollbacks", "unknownCommits"]) or receipt.get("cleanup") != {"absent": True}:
        raise ValueError("only complete acquisitions can freeze")
    plan = compile_plan(table, receipt.get("nonce"), receipt.get("ownerId"))
    if any(receipt.get(key) != plan[key] for key in ["program", "packetName", "sourceDigest", "corpusDigest"]):
        raise ValueError("acquisition source binding differs")
    counts = receipt.get("phaseRequests")
    if not isinstance(counts, dict) or set(counts) != set(plan["caps"]) or any(type(value) is not int or not 0 <= value <= plan["caps"][key] for key, value in counts.items()) or type(receipt.get("sandboxRequests")) is not int or sum(counts.values()) != receipt["sandboxRequests"] or receipt["sandboxRequests"] > plan["maxRequests"]:
        raise ValueError("request accounting differs")
    steps, cleanup = receipt.get("steps"), receipt.get("cleanupSteps")
    if not isinstance(steps, list) or len(steps) != len(plan["steps"]) or counts["observation"] != len(plan["steps"]) or not isinstance(cleanup, list) or len(cleanup) != counts["tokenCleanup"] + counts["documentCleanup"]:
        raise ValueError("graph or cleanup accounting differs")
    rows = steps + cleanup
    if any(not isinstance(row, dict) or type(row.get("sequence")) is not int for row in rows) or sorted(row["sequence"] for row in rows) != list(range(len(rows))):
        raise ValueError("native sequence differs")
    ledger = Ledger(plan)
    index, owed, queue, releases = 0, [], None, 0
    observations, reads = [], []
    for row in sorted(rows, key=lambda row: row["sequence"]):
        check_timing(row.get("timing"))
        site, transport, method, request, result = row.get("site"), row.get("transport"), row.get("rpc"), row.get("request"), row.get("result")
        if row.get("phase") == "observation":
            if owed or queue is not None or index >= len(steps) or row != steps[index]:
                raise ValueError("observation sequence differs")
            declared = plan["steps"][index]
            if site != declared["id"] or method != declared["rpc"] or transport != declared["transport"] or row.get("caseId") != declared["caseId"] or request != request_for_step(plan, declared, ledger.token_values(), table):
                raise ValueError("closed request graph differs")
            ledger.before(site, transport, method, request, declared)
            ledger.after(site, transport, method, request, declared, result, row["timing"])
            if row.get("outcomeClass") != outcome_class(result["code"]):
                raise ValueError("outcome class differs from its code")
            if declared["caseId"]:
                observations.append(row)
            if method == "GetDocument" and result["code"] == 0:
                reads.append({"site": site, "code": 0, "state": result["response"]["fields"]["state"]["stringValue"]})
            elif method == "GetDocument":
                reads.append({"site": site, "code": result["code"], "state": None})
            owed = ledger.pending_release(declared)
            index += 1
        elif row.get("phase") == "tokenCleanup":
            if not owed or site != f"cleanup/token/{owed[0]}" or method != "Rollback" or transport != ledger.tokens[owed[0]]["transport"] or request != ledger.release_request(owed[0]):
                raise ValueError("per-chain release proof differs")
            ledger.before(site, transport, method, request, None)
            ledger.after(site, transport, method, request, None, result, row["timing"])
            if ledger.tokens[owed[0]]["state"] != "rolled-back":
                raise ValueError("chain release is unconfirmed")
            owed.pop(0)
            releases += 1
        elif row.get("phase") == "documentCleanup":
            if owed or index != len(steps) or ledger.unresolved_tokens():
                raise ValueError("final recovery ordering differs")
            if queue is None:
                queue = [(kind, role) for role in ledger.owed_documents() for kind in ("read", "delete", "verify")]
            if not queue or site != f"cleanup/{queue[0][0]}/{queue[0][1]}":
                raise ValueError("cleanup graph differs")
            kind, role = queue.pop(0)
            expected_rpc = "DeleteDocument" if kind == "delete" else "GetDocument"
            if method != expected_rpc or transport != "grpc" or request != ledger.cleanup_request(kind, role):
                raise ValueError("cleanup request differs")
            ledger.before(site, transport, method, request, None)
            ledger.after(site, transport, method, request, None, result, row["timing"])
        else:
            raise ValueError("undeclared native phase")
    if index != len(steps) or owed or queue or releases != counts["tokenCleanup"] or not ledger.all_absent() or ledger.unresolved_tokens() or observations != receipt.get("observations") or ledger.snapshot()["tokens"] != receipt.get("tokens") or ledger.snapshot()["documents"] != receipt.get("documents"):
        raise ValueError("completion claims cannot be derived from native rows")
    if receipt.get("timingMode") != "wall-clock" or receipt.get("timingSource") != "parent-wire-envelope":
        raise ValueError("timing provenance differs")

    def details(row):
        value = row["result"]["details"]
        for role, entry in ledger.tokens.items():
            value = value.replace(entry["value"], f"<token:{role}>")
        return value.replace(receipt["nonce"], "<nonce>").replace(receipt["ownerId"], "<owner>")

    return {
        "program": plan["program"],
        "packetName": plan["packetName"],
        "corpusDigest": plan["corpusDigest"],
        "cases": [{"caseId": row["caseId"], "transport": row["transport"], "rpc": row["rpc"], "code": row["result"]["code"], "outcomeClass": outcome_class(row["result"]["code"]), "details": details(row)} for row in observations],
        "reads": reads,
        "tokens": {role: {"transport": entry["transport"], "state": entry["state"]} for role, entry in ledger.tokens.items()},
        "expectedStates": {role: doc["state"] for role, doc in ledger.docs.items() if doc["state"] is not None},
        "cleanup": {"absent": True},
    }
