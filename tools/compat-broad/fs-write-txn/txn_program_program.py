"""Closed request graphs for FS-TRANSACTION programs; a table declares one, and this module grants no send permission.

A program is a table (steps, owned documents, marker states, request caps) plus its tests. The
plan compiled from a table is the only thing a recording may follow: every request is resolved
from a declared step and the tokens issued earlier in the same recording, never composed by the
caller. Both transports (REST and native gRPC) run the same logical requests."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import math
import re
from pathlib import Path

PROJECT = "fireemu-oracle-sbx"
# The shared and query projects are billed; FS-TRANSACTION owns the free-tier txn project.
PROJECTS = (PROJECT, "fireemu-oracle-txn", "fireemu-oracle-query")
FREE_TIER_PROJECTS = ("fireemu-oracle-txn",)


def budget_for(project):
    """(estimated US$ per recording, reserve US$) an envelope for this project carries: the free-tier project spends nothing."""
    if project not in PROJECTS:
        raise ValueError("program project differs")
    return (0.0, 0.0) if project in FREE_TIER_PROJECTS else (0.01, 0.04)
DATABASE = "(default)"
TRANSPORTS = ("rest", "grpc")
RPCS = ("GetDocument", "BatchGetDocuments", "BeginTransaction", "Commit", "Rollback", "RunQuery")
# A native query stream a step cancels itself after this many frames at most (the transport keeps at most this many frames).
MAX_CANCEL_FRAMES = 16
ROLES = ("control", "observation", "outside-writer", "post-state")
PHASES = ("observation", "tokenCleanup", "documentCleanup", "management", "credential")
UNKNOWN_CODES = (1, 2, 4, 13, 14)
REFUSED_CODES = (3, 5, 9, 10)
DEFAULT_DEADLINE_MS = 10000
# An outside writer held by a lock may wait this long: P06 recording 2 was still held at 30 s.
WRITER_DEADLINE_MS = 90000
_IDENTITY = re.compile(r"[a-f0-9]{32}\Z")
_LABEL = re.compile(r"[a-z0-9][a-z0-9-]{0,47}\Z")
MAX_DOCUMENTS = 8
MAX_WAIT_SECONDS = 600
MAX_STATES = 32
_STEP_KEYS = ("id", "transport", "rpc", "document", "tokenInput", "tokenOutput", "writes", "caseId", "role", "allow")
_OPTIONAL_STEP_KEYS = ("deadlineMs", "documents", "mode", "readAt", "newTransaction", "waitSeconds", "sinceBegin", "concurrentWith", "retryOf", "tokenLiteral", "readAgoSeconds", "query", "cancelAfter", "onDatabase")
# A read may name a time this many seconds before it is sent: at most two hours, enough for the one-hour retention boundary.
READ_AGO_MAX = 7200
# Transaction tokens the table never issued. "malformed" does not decode as base64 (a REST request only: a gRPC client cannot send it); "unknown" decodes and
# was never issued by any transaction.
LITERAL_TOKENS = {"malformed": "not base64!", "unknown": "ZmlyZWVtdS11bmlzc3VlZC10eG4tdG9rZW4="}


def step_outcome_class(step, code):
    """The class of an answer to a step: a native query stream the step cancelled itself answers code 1, which is a definite outcome there and unknown anywhere else."""
    if code == 1 and "cancelAfter" in step:
        return "CLIENT_CANCEL"
    return outcome_class(code)


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
    if "onDatabase" in row:
        step["onDatabase"] = row["onDatabase"]
    if "mode" in row:
        step["mode"] = row["mode"]
    if "readAt" in row:
        # A version of an owned document, by the time its commit was acknowledged: {"document": role, "commit": step id}.
        step["readAt"] = dict(row["readAt"]) if isinstance(row["readAt"], dict) else _bad("readAt is not a mapping")
    if "newTransaction" in row:
        step["newTransaction"] = row["newTransaction"]
    if "sinceBegin" in row:
        # A read-write transaction's first read may show any state acknowledged since its begin (the snapshot may be taken
        # at the begin or at the read); only present on that read.
        step["sinceBegin"] = row["sinceBegin"]
    if "tokenLiteral" in row:
        step["tokenLiteral"] = row["tokenLiteral"]
    if "readAgoSeconds" in row:
        step["readAgoSeconds"] = row["readAgoSeconds"]
    if "query" in row:
        # A query over this table's own collection: every owned document, or the ones in one declared state.
        step["query"] = copy.deepcopy(row["query"])
    if "cancelAfter" in row:
        step["cancelAfter"] = row["cancelAfter"]
    if "retryOf" in row:
        # A read-write begin that names an earlier token of the same table as the attempt it retries (REST `retryTransaction`);
        # only present on that begin. The named token is released after this begin, not before it.
        step["retryOf"] = row["retryOf"]
    if "concurrentWith" in row:
        # An outside writer sent while the step before it (its anchor: a holder's Commit or Rollback, after the anchor's wait) is
        # still to be sent: the writer may be held by the holder's locks, and its answer is collected after the anchor's.
        step["concurrentWith"] = row["concurrentWith"]
    if "waitSeconds" in row:
        # Idle time, in seconds, before this request is sent; only present on a step that waits.
        step["waitSeconds"] = row["waitSeconds"]
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
    if "project" in table and (not isinstance(table["project"], str) or table["project"] not in PROJECTS):
        _bad("the table names a project that is not one of the sandbox projects")
    # Database aliases bind full resource templates; only the run nonce may be substituted.
    databases = table.get("databases", {})
    placements = table.get("placements", {})
    if not isinstance(databases, dict) or not isinstance(placements, dict):
        _bad("database declarations and placements must be mappings")
    primary = f"projects/{table.get('project', PROJECT)}/databases/{DATABASE}"
    for alias, resource in databases.items():
        if not isinstance(alias, str) or not _LABEL.fullmatch(alias) or alias == "default" or not isinstance(resource, str):
            _bad("database declaration is malformed")
        rendered = resource.replace("{nonce}", "a" * 32)
        if not re.fullmatch(r"projects/(" + "|".join(map(re.escape, PROJECTS)) + r")/databases/(\(default\)|[a-z][a-z0-9-]{2,61}[a-z0-9])", rendered):
            _bad("database declaration names an invalid database or project")
    if any(resource.split("/")[1] != table.get("project", PROJECT) and resource.split("/")[1] not in FREE_TIER_PROJECTS for resource in databases.values()):
        _bad("billed secondary project requires its own budget; use it as the primary project")
    if len(set(databases.values()) | {primary}) != len(databases) + 1:
        _bad("database declarations repeat")
    if any(role not in table["documents"] or not isinstance(alias, str) or alias not in databases for role, alias in placements.items()):
        _bad("placement names an undeclared role or database")
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
    thresholds = table.get("thresholds")
    if thresholds is not None and (not isinstance(thresholds, dict) or not {"totalAgeSeconds"} <= set(thresholds) <= {"totalAgeSeconds", "releaseAfterAgeSeconds"} or type(thresholds["totalAgeSeconds"]) is not int or thresholds["totalAgeSeconds"] <= 0):
        _bad("thresholds are malformed")
    if thresholds is not None and "releaseAfterAgeSeconds" in thresholds and (type(thresholds["releaseAfterAgeSeconds"]) is not int or thresholds["releaseAfterAgeSeconds"] < thresholds["totalAgeSeconds"]):
        _bad("the release age is malformed or below the total-age threshold")
    steps = [_step(row) for row in table["steps"]]
    if thresholds is not None and "releaseAfterAgeSeconds" in thresholds and any(step["transport"] == "grpc" and (step["rpc"] == "BeginTransaction" or step["tokenInput"] or step["tokenOutput"]) for step in steps):
        _bad("the release age rests on the REST lifetime; no table with a gRPC transaction may declare it until the gRPC lifetime is recorded")
    if not steps or caps["observation"] != len(steps):
        _bad("the observation cap is not the step count")
    if caps["tokenCleanup"] < table["maxTokens"] or caps["documentCleanup"] < 3 * len(documents):
        _bad("the cleanup reserve cannot release every token or clean every document")
    ids, cases, issued, probed, modes, acked = set(), set(), {}, set(), {}, {}
    plain_reads = set()
    last_use = {}
    for index, step in enumerate(steps):
        if isinstance(step["tokenInput"], str):
            last_use[step["tokenInput"]] = index
        if isinstance(step.get("retryOf"), str):
            # The retry is the named token's last use, and the new token is released right after the retry that issued it.
            last_use[step["retryOf"]] = index
            if isinstance(step["tokenOutput"], str):
                last_use[step["tokenOutput"]] = max(last_use.get(step["tokenOutput"], -1), index)
    for index, step in enumerate(steps):
        if not isinstance(step["id"], str) or not step["id"] or step["id"] in ids:
            _bad("step ids are missing or repeat")
        ids.add(step["id"])
        if step["transport"] not in TRANSPORTS or step["rpc"] not in RPCS or step["role"] not in ROLES:
            _bad(f"{step['id']} has an unknown transport, rpc or role")
        if step["document"] is not None and step["document"] not in documents:
            _bad(f"{step['id']} names an unknown document")
        if not step["allow"] or any(type(code) is not int or not 0 <= code <= 16 or (code in UNKNOWN_CODES and not (code == 1 and "cancelAfter" in step)) for code in step["allow"]):
            _bad(f"{step['id']} allows no code or an unknown-outcome code")
        if type(step["deadlineMs"]) is not int or not 1 <= step["deadlineMs"] <= (WRITER_DEADLINE_MS if step["role"] == "outside-writer" else DEFAULT_DEADLINE_MS):
            _bad(f"{step['id']} has a bad deadline")
        if "waitSeconds" in step:
            if type(step["waitSeconds"]) is not int or not 1 <= step["waitSeconds"] <= MAX_WAIT_SECONDS or index == 0:
                _bad(f"{step['id']} has a wait that is not a whole number of seconds up to {MAX_WAIT_SECONDS}, or nothing to follow")
            if step["tokenInput"] is None and step["role"] != "outside-writer" and "retryOf" not in step:
                _bad(f"{step['id']} waits outside a transaction and is not an outside writer or a retry")
        if step["caseId"] is not None:
            if step["role"] not in ("observation", "outside-writer") or not isinstance(step["caseId"], str) or step["caseId"] in cases:
                _bad(f"{step['id']} has a case id that is misplaced or repeats")
            cases.add(step["caseId"])
        rpc = step["rpc"]
        alias = step.get("onDatabase")
        if "onDatabase" in step and (not isinstance(alias, str) or alias not in databases):
            _bad(f"{step['id']} names an undeclared database")
        targets = ([step["document"]] if step["document"] is not None else []) + list(step.get("documents", [])) + [write.get("document") for write in step["writes"]]
        if any(placements.get(role) != alias for role in targets):
            _bad(f"{step['id']} names a document in another database")
        if step["role"] == "control" and (step["allow"] != [0] and not (step["allow"] == [5] and rpc == "GetDocument")):
            _bad(f"{step['id']} is a control step that may be refused")
        if step["role"] == "post-state" and step["allow"] != [0]:
            _bad(f"{step['id']} is a post-state read that may be refused")
        if "retryOf" in step:
            retried = step["retryOf"]
            if rpc != "BeginTransaction" or step.get("mode", "readWrite") != "readWrite" or step["transport"] != "rest" or "readAt" in step:
                _bad(f"{step['id']} retries on something other than a REST read-write begin")
            if not isinstance(retried, str) or issued.get(retried) != "rest" or modes.get(retried) != "readWrite" or retried == step["tokenOutput"]:
                _bad(f"{step['id']} retries a token that is not an earlier read-write token of this table over REST")
        if rpc != "BeginTransaction" and "mode" in step:
            _bad(f"{step['id']} names a transaction mode on a request that does not begin one")
        if rpc == "BeginTransaction" and step.get("mode", "readWrite") not in ("readWrite", "readOnly"):
            _bad(f"{step['id']} names an unknown transaction mode")
        if "tokenLiteral" in step:
            # A token the table never issued: on a read, a commit or a rollback that names no issued token; never a control, a post-state read or a writer.
            if step["tokenLiteral"] not in LITERAL_TOKENS or step["tokenInput"] is not None or rpc not in ("GetDocument", "BatchGetDocuments", "Commit", "Rollback") or step["role"] != "observation":
                _bad(f"{step['id']} names a literal token that is not allowed here")
            if step["tokenLiteral"] == "malformed" and step["transport"] != "rest":
                _bad(f"{step['id']} sends a malformed token over gRPC, which a native client cannot")
        if "query" in step or rpc == "RunQuery":
            query = step.get("query")
            if rpc != "RunQuery" or not isinstance(query, dict) or set(query) - {"stateEquals"} or ("stateEquals" in query and query["stateEquals"] not in states):
                _bad(f"{step['id']} is a query that is malformed or on another request")
            if step["document"] is not None or step["writes"] or step["tokenOutput"] is not None or "readAgoSeconds" in step or "newTransaction" in step or step["role"] == "outside-writer":
                _bad(f"{step['id']} is a query that names a document, writes, outputs a token or reads at another time")
        if "cancelAfter" in step:
            # The client cancels a native query stream itself: the one use of code 1 that is a definite outcome.
            cancel = step["cancelAfter"]
            if rpc != "RunQuery" or step["transport"] != "grpc" or type(cancel) is not int or not 1 <= cancel <= MAX_CANCEL_FRAMES or step["allow"] != [1]:
                _bad(f"{step['id']} cancels something other than a native query stream, or allows more than the cancel")
        if "readAgoSeconds" in step:
            # A time before the request is sent, not a version this table wrote: never inside a transaction and never beside a version time.
            ago = step["readAgoSeconds"]
            if type(ago) is not int or not 1 <= ago <= READ_AGO_MAX or "readAt" in step or "newTransaction" in step or step["tokenInput"] is not None or "tokenLiteral" in step:
                _bad(f"{step['id']} names a read time ago that is out of range or beside another consistency selector")
            if rpc not in ("GetDocument", "BatchGetDocuments") and not (rpc == "BeginTransaction" and step.get("mode") == "readOnly"):
                _bad(f"{step['id']} reads a time ago on a request that cannot")
        if "readAt" in step:
            at = step["readAt"]
            if set(at) != {"document", "commit"} or not isinstance(at["commit"], str) or at["document"] not in acked.get(at["commit"], ()):
                _bad(f"{step['id']} reads at a version that no earlier must-succeed commit acknowledges")
            if rpc not in ("GetDocument", "BatchGetDocuments") and not (rpc == "BeginTransaction" and step.get("mode") == "readOnly"):
                _bad(f"{step['id']} reads at a time on a request that cannot")
            if step["tokenInput"] is not None or "newTransaction" in step:
                _bad(f"{step['id']} reads at a time inside a transaction")
        if "sinceBegin" in step:
            if step["sinceBegin"] is not True or rpc not in ("GetDocument", "BatchGetDocuments") or step["role"] != "observation" or modes.get(step["tokenInput"]) != "readWrite" or step["tokenInput"] in plain_reads:
                _bad(f"{step['id']} marks a read that is not the first observation read of a read-write transaction")
        if step["tokenInput"] is not None and rpc in ("GetDocument", "BatchGetDocuments"):
            plain_reads.add(step["tokenInput"])
        if "concurrentWith" in step:
            anchor = steps[index - 1] if index else None
            if anchor is None or step["concurrentWith"] != anchor["id"] or "concurrentWith" in anchor or step["role"] != "outside-writer" or rpc != "Commit" or step["tokenInput"] is not None or not step["writes"] or "waitSeconds" in step:
                _bad(f"{step['id']} is not a concurrent outside writer of the step before it")
            if not isinstance(anchor["tokenInput"], str) or anchor["rpc"] not in ("Commit", "Rollback") or type(anchor.get("waitSeconds")) is not int or not 1 <= anchor["waitSeconds"] <= step["deadlineMs"] / 1000 - 10:
                _bad(f"{step['id']} has an anchor that is not a holder release after a wait that lands inside the writer's deadline")
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
        elif rpc == "RunQuery":
            pass   # a query reads the run's own collection; nothing foreign can be in it (the nonce is the run's)
        elif rpc == "Rollback":
            if (step["tokenInput"] is None and "tokenLiteral" not in step) or step["document"] is not None or step["writes"]:
                _bad(f"{step['id']} is not a rollback of an issued token")
        else:
            if step["document"] is not None or (not step["writes"] and ((step["tokenInput"] is None and "tokenLiteral" not in step) or step["role"] == "outside-writer")):
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
        if rpc == "Commit" and step["allow"] == [0]:
            # Only a commit that must succeed names a version, so a refused optional write cannot shift which one is read.
            acked[step["id"]] = {write["document"] for write in step["writes"]}
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
        "waits": {step["id"]: step["waitSeconds"] for step in steps if "waitSeconds" in step},
        "transports": sorted({step["transport"] for step in steps}),
        "outcomeClasses": {step["id"]: [step_outcome_class(step, code) for code in step["allow"]] for step in steps},
    }
    if table.get("thresholds"):
        body["thresholds"] = dict(table["thresholds"])
    if table.get("project", PROJECT) != PROJECT:
        body["project"] = table["project"]   # bound only when it differs, so every table that targets the shared project keeps its digest
    for key in ("databases", "placements"):
        if key in table:
            body[key] = dict(table[key])
    return hashlib.sha256(_canonical(body).encode()).hexdigest()


def compile_plan(table, nonce, owner_id):
    _identity(nonce, "nonce")
    _identity(owner_id, "owner")
    steps = _validate_table(table)
    project = table.get("project", PROJECT)
    database = f"projects/{project}/databases/{DATABASE}"
    databases = {alias: resource.replace("{nonce}", nonce) for alias, resource in table.get("databases", {}).items()}
    if len(set(databases.values()) | {database}) != len(databases) + 1:
        _bad("resolved database declarations repeat")
    caps = dict(table["caps"])
    plan = {
        "kind": "txn-program-plan-v1",
        "program": table["program"],
        "packetName": table["name"],
        "project": project,
        "database": database,
        "nonce": nonce,
        "ownerId": owner_id,
        "documents": {role: f"{databases[table['placements'][role]] if role in table.get('placements', {}) else database}/documents/oracle/{nonce}/{table['slug']}/{role}" for role in table["documents"]},
        "states": list(table["states"]),
        "steps": steps,
        "cases": [step["caseId"] for step in steps if step["caseId"]],
        "maxTokens": table["maxTokens"],
        "maxUnresolvedTokens": 1,
        "releasePolicy": "rollback-zero-before-next-chain",
        "waits": {step["id"]: step["waitSeconds"] for step in steps if "waitSeconds" in step},
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
    if table.get("thresholds"):
        plan["thresholds"] = dict(table["thresholds"])
    if "databases" in table:
        plan["databases"] = databases
    if "placements" in table:
        plan["placements"] = dict(table["placements"])
    return plan


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


def read_time_ago(now, seconds):
    """The timestamp `seconds` before `now` (epoch seconds, a float)."""
    moment = now - seconds
    whole = math.floor(moment)
    # Firestore refuses a read time with sub-microsecond digits, so the time is rounded to the microsecond.
    micros = round((moment - whole) * 1_000_000)
    if micros >= 1_000_000:
        whole, micros = whole + 1, 0
    return {"seconds": str(whole), "nanos": micros * 1000}


def _epoch(timestamp):
    return int(timestamp["seconds"]) + timestamp["nanos"] / 1_000_000_000


def same_request(step, recorded, expected):
    """Whether a recorded request is the declared one. A read time ago was built a moment before the request was dispatched, so the recorded read time may precede the
    one computed from the dispatch time by up to 5 s and never follow it; everything else is compared exactly."""
    if "readAgoSeconds" not in step:
        return recorded == expected

    def strip(request):
        value = copy.deepcopy(request)
        value.pop("readTime", None)
        if "options" in value and "readOnly" in value["options"]:
            value["options"]["readOnly"].pop("readTime", None)
        return value

    def time_of(request):
        return request.get("readTime") or request.get("options", {}).get("readOnly", {}).get("readTime")

    if strip(recorded) != strip(expected) or not isinstance(time_of(recorded), dict) or not isinstance(time_of(expected), dict):
        return False
    return 0 <= _epoch(time_of(expected)) - _epoch(time_of(recorded)) <= 5


def request_for_step(value, step, tokens, table, times=None, now=None):
    """Resolve only a declared slot using already issued private token bindings. `now` (epoch seconds) is needed only by a read time ago."""
    validate_plan(value, table)
    if step not in value["steps"] or not isinstance(tokens, dict):
        raise ValueError("declared step and token bindings required")
    token = None
    if "tokenLiteral" in step:
        token = LITERAL_TOKENS[step["tokenLiteral"]]
    elif step["tokenInput"]:
        if step["tokenInput"] not in tokens:
            raise ValueError("step has no earlier issued token")
        token = canonical_token(tokens[step["tokenInput"]])
    rpc = step["rpc"]
    database = value["databases"][step["onDatabase"]] if "onDatabase" in step else value["database"]
    read_time = None
    if "readAgoSeconds" in step:
        if not isinstance(now, (int, float)) or isinstance(now, bool):
            raise ValueError("step reads a time ago and needs the time now")
        read_time = read_time_ago(now, step["readAgoSeconds"])
    elif "readAt" in step:
        read_time = (times or {}).get(f"{step['readAt']['document']}@{step['readAt']['commit']}")
        if not isinstance(read_time, dict):
            raise ValueError("step reads at a version that has not been acknowledged")
        read_time = {"seconds": read_time["seconds"], "nanos": read_time["nanos"]}
    if rpc == "GetDocument":
        return {"name": value["documents"][step["document"]], **({"transaction": token} if token else {}), **({"readTime": read_time} if read_time else {})}
    if rpc == "BatchGetDocuments":
        return {"database": database, "documents": [value["documents"][role] for role in step["documents"]], **({"transaction": token} if token else {}), **({"readTime": read_time} if read_time else {}), **({"newTransaction": {step["newTransaction"]: {}}} if "newTransaction" in step else {})}
    if rpc == "RunQuery":
        query = {"from": [{"collectionId": table["slug"]}]}
        if "stateEquals" in step["query"]:
            query["where"] = {"fieldFilter": {"field": {"fieldPath": "state"}, "op": "EQUAL", "value": {"stringValue": step["query"]["stateEquals"]}}}
        return {"parent": f"{database}/documents/oracle/{value['nonce']}", "structuredQuery": query, **({"transaction": token} if token else {})}
    if rpc == "Rollback":
        return {"database": database, "transaction": token}
    if rpc == "BeginTransaction":
        mode = step.get("mode", "readWrite")
        if "retryOf" in step:
            if step["retryOf"] not in tokens:
                raise ValueError("step retries a token that was never issued")
            return {"database": database, "options": {"readWrite": {"retryTransaction": canonical_token(tokens[step["retryOf"]])}}}
        return {"database": database, "options": {mode: {"readTime": read_time} if read_time else {}}}
    writes = [{"update": {"name": value["documents"][write["document"]], "fields": marker_fields(value, write["document"], write["state"])}, "currentDocument": {"exists": write["exists"]}} for write in step["writes"]]
    return {"database": database, "writes": writes, **({"transaction": token} if token else {})}


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
