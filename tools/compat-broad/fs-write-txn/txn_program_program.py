"""Closed request graphs for FS-TRANSACTION programs; a table declares one, and this module grants no send permission.

A program is a table (steps, owned documents, marker states, request caps) plus its tests. The
plan compiled from a table is the only thing a recording may follow: every request is resolved
from a declared step and the tokens issued earlier in the same recording, never composed by the
caller. Both transports (REST and native gRPC) run the same logical requests."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

PROJECT = "fireemu-oracle-sbx"
DATABASE = "(default)"
TRANSPORTS = ("rest", "grpc")
RPCS = ("GetDocument", "BatchGetDocuments", "BeginTransaction", "Commit", "Rollback")
ROLES = ("control", "observation", "outside-writer", "post-state")
PHASES = ("observation", "tokenCleanup", "documentCleanup", "management", "credential")
UNKNOWN_CODES = (1, 2, 4, 13, 14)
REFUSED_CODES = (3, 5, 9, 10)
DEFAULT_DEADLINE_MS = 10000
WRITER_DEADLINE_MS = 30000
_IDENTITY = re.compile(r"[a-f0-9]{32}\Z")
_LABEL = re.compile(r"[a-z0-9][a-z0-9-]{0,47}\Z")
MAX_DOCUMENTS = 8
MAX_STATES = 32
_STEP_KEYS = ("id", "transport", "rpc", "document", "tokenInput", "tokenOutput", "writes", "caseId", "role", "allow")
_OPTIONAL_STEP_KEYS = ("deadlineMs", "documents", "mode", "readAt", "newTransaction")


def outcome_class(code):
    if type(code) is not int or not 0 <= code <= 16:
        raise ValueError("gRPC status code required")
    if code == 0:
        return "OK"
    if code in UNKNOWN_CODES:
        return "UNKNOWN"
    return "REFUSED" if code in REFUSED_CODES else "OTHER"


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _bad(reason):
    raise ValueError(f"txn-program table: {reason}")


def source_digest(table):
    return hashlib.sha256(Path(table["sourceFile"]).read_bytes()).hexdigest()


def _step(row):
    if not isinstance(row, dict) or not set(_STEP_KEYS) <= set(row) or set(row) - set(_STEP_KEYS) - set(_OPTIONAL_STEP_KEYS):
        _bad("a step has a missing or unknown key")
    step = {key: row[key] for key in _STEP_KEYS}
    step["writes"] = [dict(write) for write in row["writes"]]
    step["allow"] = sorted(row["allow"]) if isinstance(row["allow"], (list, tuple)) and len(set(row["allow"])) == len(row["allow"]) else _bad("allowed codes repeat or are not a list")
    step["deadlineMs"] = row.get("deadlineMs", DEFAULT_DEADLINE_MS)
    if "mode" in row:
        step["mode"] = row["mode"]
    if "readAt" in row:
        # A version of an owned document, by the time its commit was acknowledged: {"document": role, "version": index}.
        step["readAt"] = dict(row["readAt"]) if isinstance(row["readAt"], dict) else _bad("readAt is not a mapping")
    if "newTransaction" in row:
        step["newTransaction"] = row["newTransaction"]
    if "documents" in row:
        # Only a batch read names several documents; an absent key keeps every earlier table's digest.
        step["documents"] = list(row["documents"]) if isinstance(row["documents"], (list, tuple)) else _bad("batch documents are not a list")
    return step


def _validate_table(table):
    if not isinstance(table, dict) or not all(key in table for key in ("name", "program", "slug", "documents", "states", "steps", "caps", "observationSeconds", "recoverySeconds", "maxTokens", "sourceFile")):
        _bad("a table field is missing")
    if not isinstance(table["slug"], str) or not _LABEL.fullmatch(table["slug"]) or not isinstance(table["program"], str) or not isinstance(table["name"], str):
        _bad("name, program or slug is malformed")
    if not isinstance(table.get("envelopeId"), str) or not re.fullmatch(rf"FS-TRANSACTION-{re.escape(table['name'])}-[0-9]{{3}}", table["envelopeId"]):
        _bad("the envelope id is not this program's next numbered one")
    documents, states = tuple(table["documents"]), tuple(table["states"])
    if not documents or len(documents) > MAX_DOCUMENTS or len(set(documents)) != len(documents) or any(not isinstance(role, str) or not _LABEL.fullmatch(role) for role in documents):
        _bad("owned document roles are malformed")
    if not states or len(states) > MAX_STATES or len(set(states)) != len(states) or any(not isinstance(state, str) or not _LABEL.fullmatch(state) for state in states):
        _bad("marker states are malformed")
    caps = table["caps"]
    if not isinstance(caps, dict) or set(caps) != set(PHASES) or any(type(value) is not int or value < 0 for value in caps.values()):
        _bad("request caps are malformed")
    if any(type(table[key]) is not int or table[key] <= 0 for key in ("observationSeconds", "recoverySeconds", "maxTokens")):
        _bad("clock or token limits are malformed")
    steps = [_step(row) for row in table["steps"]]
    if not steps or caps["observation"] != len(steps):
        _bad("the observation cap is not the step count")
    if caps["tokenCleanup"] < table["maxTokens"] or caps["documentCleanup"] < 3 * len(documents):
        _bad("the cleanup reserve cannot release every token or clean every document")
    ids, cases, issued, probed, modes, acked = set(), set(), {}, set(), {}, {}
    last_use = {}
    for index, step in enumerate(steps):
        if isinstance(step["tokenInput"], str):
            last_use[step["tokenInput"]] = index
    for index, step in enumerate(steps):
        if not isinstance(step["id"], str) or not step["id"] or step["id"] in ids:
            _bad("step ids are missing or repeat")
        ids.add(step["id"])
        if step["transport"] not in TRANSPORTS or step["rpc"] not in RPCS or step["role"] not in ROLES:
            _bad(f"{step['id']} has an unknown transport, rpc or role")
        if step["document"] is not None and step["document"] not in documents:
            _bad(f"{step['id']} names an unknown document")
        if not step["allow"] or any(type(code) is not int or not 0 <= code <= 16 or code in UNKNOWN_CODES for code in step["allow"]):
            _bad(f"{step['id']} allows no code or an unknown-outcome code")
        if type(step["deadlineMs"]) is not int or not 1 <= step["deadlineMs"] <= (WRITER_DEADLINE_MS if step["role"] == "outside-writer" else DEFAULT_DEADLINE_MS):
            _bad(f"{step['id']} has a bad deadline")
        if step["caseId"] is not None:
            if step["role"] not in ("observation", "outside-writer") or not isinstance(step["caseId"], str) or step["caseId"] in cases:
                _bad(f"{step['id']} has a case id that is misplaced or repeats")
            cases.add(step["caseId"])
        rpc = step["rpc"]
        if step["role"] == "control" and (step["allow"] != [0] and not (step["allow"] == [5] and rpc == "GetDocument")):
            _bad(f"{step['id']} is a control step that may be refused")
        if step["role"] == "post-state" and step["allow"] != [0]:
            _bad(f"{step['id']} is a post-state read that may be refused")
        if rpc != "BeginTransaction" and "mode" in step:
            _bad(f"{step['id']} names a transaction mode on a request that does not begin one")
        if rpc == "BeginTransaction" and step.get("mode", "readWrite") not in ("readWrite", "readOnly"):
            _bad(f"{step['id']} names an unknown transaction mode")
        if "readAt" in step:
            at = step["readAt"]
            if set(at) != {"document", "version"} or at["document"] not in documents or type(at["version"]) is not int or not 0 <= at["version"] < acked.get(at["document"], 0):
                _bad(f"{step['id']} reads at a version no earlier step can have acknowledged")
            if rpc not in ("GetDocument", "BatchGetDocuments") and not (rpc == "BeginTransaction" and step.get("mode") == "readOnly"):
                _bad(f"{step['id']} reads at a time on a request that cannot")
            if step["tokenInput"] is not None or "newTransaction" in step:
                _bad(f"{step['id']} reads at a time inside a transaction")
        if "newTransaction" in step:
            if rpc != "BatchGetDocuments" or step["newTransaction"] not in ("readWrite", "readOnly") or step["tokenInput"] is not None or not isinstance(step["tokenOutput"], str) or step["tokenOutput"] in issued:
                _bad(f"{step['id']} is not a batch read that begins one fresh transaction")
            if any(last_use.get(token, -1) > index for token in issued):
                _bad(f"{step['id']} begins while an earlier chain still uses its token")
            issued[step["tokenOutput"]] = step["transport"]
            modes[step["tokenOutput"]] = step["newTransaction"]
        elif rpc != "BeginTransaction" and step["tokenOutput"] is not None:
            _bad(f"{step['id']} outputs a token without beginning one")
        if rpc == "BeginTransaction":
            if any(last_use.get(token, -1) > index for token in issued):
                _bad(f"{step['id']} begins while an earlier chain still uses its token")
            if step["tokenInput"] is not None or not isinstance(step["tokenOutput"], str) or step["tokenOutput"] in issued or step["document"] is not None or step["writes"]:
                _bad(f"{step['id']} is not a fresh begin")
            issued[step["tokenOutput"]] = step["transport"]
            modes[step["tokenOutput"]] = step.get("mode", "readWrite")
            continue
        if step["tokenInput"] is not None and issued.get(step["tokenInput"]) != step["transport"]:
            _bad(f"{step['id']} uses a token that is not issued earlier on its transport")
        if rpc != "BatchGetDocuments" and "documents" in step:
            _bad(f"{step['id']} names a batch on a request that is not a batch read")
        if rpc == "BatchGetDocuments":
            batch = step.get("documents")
            if not batch or len(set(batch)) != len(batch) or any(role not in documents for role in batch) or step["document"] is not None or step["writes"]:
                _bad(f"{step['id']} is not a batch read of distinct owned documents")
            if any(role not in probed for role in batch):
                _bad(f"{step['id']} batch-reads a document before an absence probe")
        elif rpc == "GetDocument":
            if step["document"] is None or step["writes"]:
                _bad(f"{step['id']} is not a plain read")
            if step["document"] not in probed:
                # The first touch of an owned document proves it is absent, so nothing foreign is ever written or deleted.
                if step["role"] != "control" or step["tokenInput"] is not None or step["allow"] != [5]:
                    _bad(f"{step['id']} touches {step['document']} before an absence probe")
                probed.add(step["document"])
        elif rpc == "Rollback":
            if step["tokenInput"] is None or step["document"] is not None or step["writes"]:
                _bad(f"{step['id']} is not a rollback of an issued token")
        else:
            if step["document"] is not None or (not step["writes"] and (step["tokenInput"] is None or step["role"] == "outside-writer")):
                _bad(f"{step['id']} commits no writes outside a transaction")
            if step["role"] == "outside-writer" and step["tokenInput"] is not None:
                _bad(f"{step['id']} is an outside writer that carries a token")
            if step["writes"] and modes.get(step["tokenInput"]) == "readOnly" and 0 in step["allow"]:
                _bad(f"{step['id']} writes on a read-only transaction and may succeed")
            targets = [write.get("document") for write in step["writes"]]
            if len(set(targets)) != len(targets):
                _bad(f"{step['id']} writes one document twice")
            for write in step["writes"]:
                if set(write) != {"document", "state", "exists"} or write["document"] not in documents or write["state"] not in states or type(write["exists"]) is not bool:
                    _bad(f"{step['id']} has a malformed write")
                if write["document"] not in probed:
                    _bad(f"{step['id']} writes {write['document']} before an absence probe")
        if rpc != "Commit" and step["role"] == "outside-writer":
            _bad(f"{step['id']} is an outside writer that is not a commit")
        if rpc == "Commit":
            for write in step["writes"]:
                acked[write["document"]] = acked.get(write["document"], 0) + 1
    if len(issued) != table["maxTokens"]:
        _bad("the token count is not the declared maximum")
    return steps


def _identity(value, label):
    if not isinstance(value, str) or not _IDENTITY.fullmatch(value):
        raise ValueError(f"canonical run {label} required")


def corpus_digest(table):
    steps = _validate_table(table)
    body = {
        "steps": steps,
        "documents": list(table["documents"]),
        "states": list(table["states"]),
        "waits": {},
        "transports": sorted({step["transport"] for step in steps}),
        "outcomeClasses": {step["id"]: [outcome_class(code) for code in step["allow"]] for step in steps},
    }
    return hashlib.sha256(_canonical(body).encode()).hexdigest()


def compile_plan(table, nonce, owner_id):
    _identity(nonce, "nonce")
    _identity(owner_id, "owner")
    steps = _validate_table(table)
    database = f"projects/{PROJECT}/databases/{DATABASE}"
    caps = dict(table["caps"])
    return {
        "kind": "txn-program-plan-v1",
        "program": table["program"],
        "packetName": table["name"],
        "project": PROJECT,
        "database": database,
        "nonce": nonce,
        "ownerId": owner_id,
        "documents": {role: f"{database}/documents/oracle/{nonce}/{table['slug']}/{role}" for role in table["documents"]},
        "states": list(table["states"]),
        "steps": steps,
        "cases": [step["caseId"] for step in steps if step["caseId"]],
        "maxTokens": table["maxTokens"],
        "maxUnresolvedTokens": 1,
        "releasePolicy": "rollback-zero-before-next-chain",
        "waits": {},
        "timing": "wall-clock",
        "caps": caps,
        "maxRequests": sum(caps.values()),
        "observationSeconds": table["observationSeconds"],
        "recoverySeconds": table["recoverySeconds"],
        "iamConfig": "none",
        "retries": "none",
        "sourceDigest": source_digest(table),
        "corpusDigest": corpus_digest(table),
    }


def validate_plan(value, table):
    if not isinstance(value, dict):
        raise ValueError("closed-graph plan required")
    expected = compile_plan(table, value.get("nonce"), value.get("ownerId"))
    try:
        same = _canonical(value) == _canonical(expected)
    except (ValueError, TypeError):
        same = False
    if not same:
        raise ValueError("plan differs from its closed source graph")


def canonical_token(value):
    if not isinstance(value, str) or not 0 < len(value) <= 2048:
        raise ValueError("bounded canonical transaction bytes required")
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError:
        raise ValueError("bounded canonical transaction bytes required") from None
    if not decoded or len(decoded) > 1024 or base64.b64encode(decoded).decode() != value:
        raise ValueError("bounded canonical transaction bytes required")
    return value


def marker_fields(plan, role, state):
    return {name: {"stringValue": entry} for name, entry in {"owner": plan["ownerId"], "nonce": plan["nonce"], "role": role, "state": state}.items()}


def request_for_step(value, step, tokens, table, times=None):
    """Resolve only a declared slot using already issued private token bindings."""
    validate_plan(value, table)
    if step not in value["steps"] or not isinstance(tokens, dict):
        raise ValueError("declared step and token bindings required")
    token = None
    if step["tokenInput"]:
        if step["tokenInput"] not in tokens:
            raise ValueError("step has no earlier issued token")
        token = canonical_token(tokens[step["tokenInput"]])
    rpc = step["rpc"]
    read_time = None
    if "readAt" in step:
        read_time = (times or {}).get(f"{step['readAt']['document']}:{step['readAt']['version']}")
        if not isinstance(read_time, dict):
            raise ValueError("step reads at a version that has not been acknowledged")
        read_time = {"seconds": read_time["seconds"], "nanos": read_time["nanos"]}
    if rpc == "GetDocument":
        return {"name": value["documents"][step["document"]], **({"transaction": token} if token else {}), **({"readTime": read_time} if read_time else {})}
    if rpc == "BatchGetDocuments":
        return {"database": value["database"], "documents": [value["documents"][role] for role in step["documents"]], **({"transaction": token} if token else {}), **({"readTime": read_time} if read_time else {}), **({"newTransaction": {step["newTransaction"]: {}}} if "newTransaction" in step else {})}
    if rpc == "Rollback":
        return {"database": value["database"], "transaction": token}
    if rpc == "BeginTransaction":
        mode = step.get("mode", "readWrite")
        return {"database": value["database"], "options": {mode: {"readTime": read_time} if read_time else {}}}
    writes = [{"update": {"name": value["documents"][write["document"]], "fields": marker_fields(value, write["document"], write["state"])}, "currentDocument": {"exists": write["exists"]}} for write in step["writes"]]
    return {"database": value["database"], "writes": writes, **({"transaction": token} if token else {})}


class GraphCursor:
    """Claim each observation slot once and in the declared order."""

    def __init__(self, value, table):
        validate_plan(value, table)
        self._plan = json.loads(_canonical(value))
        self._next = 0

    @property
    def complete(self):
        return self._next == len(self._plan["steps"])

    def claim(self, name):
        if self.complete or name != self._plan["steps"][self._next]["id"]:
            raise ValueError("graph slot is repeated, missing or out of order")
        row = self._plan["steps"][self._next]
        self._next += 1
        return dict(row)


class RequestBudget:
    """Charge before dispatch; observation cannot borrow recovery reserves."""

    def __init__(self, value, table):
        validate_plan(value, table)
        self._caps = dict(value["caps"])
        self._max = value["maxRequests"]
        self.used = {phase: 0 for phase in self._caps}

    @property
    def total(self):
        return sum(self.used.values())

    def charge(self, phase):
        if not isinstance(phase, str) or phase not in self._caps or self.used[phase] >= self._caps[phase] or self.total >= self._max:
            raise ValueError("request phase exhausted or unknown")
        self.used[phase] += 1
