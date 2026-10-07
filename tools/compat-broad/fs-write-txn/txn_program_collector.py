"""A finite closed-graph recording with durable responsibility before each dispatch.

`Ledger` holds every rule about tokens, owned documents and unresolved outcomes, and has no I/O.
The collector drives it while recording; `projection` replays a saved recording through a fresh
one, so a completion claim is only ever what the native rows derive."""

from __future__ import annotations

import copy
import datetime as dt
import json
import math
import re
import threading
import time

from txn_program_program import GraphCursor, canonical_token, compile_plan, corpus_digest, marker_fields, outcome_class, request_for_step, source_digest, validate_plan

RECEIPT_KIND = "txn-program-receipt-v1"
RECORDING_KIND = "txn-program-recording-v1"
# Seconds a recovery waits, after releasing the tokens, for a write of unknown outcome that may still land before it reads the owned documents.
SETTLE_SECONDS = 5
RESOLVED_TOKENS = ("committed", "rolled-back", "released-refused", "released-expired")
# The one refusal that proves a transaction is gone: what production answers for a finished or expired token.
GONE_CODE = 10
GONE_DETAILS = "The referenced transaction has expired or is no longer valid."
# A token that outlived its total lifetime and was refused once as expired is forgotten: its Rollback answers this (P11,
# REST). Production answers the same for a token it never knew, so it finishes a release only after such a refusal.
INVALID_CODE = 3
INVALID_DETAILS = "Invalid transaction."
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


def parse_time(value, transport):
    """A document version stamp or read time as (seconds, nanos), whichever form its transport gives."""
    if isinstance(value, dict):
        check_timestamp(value, "grpc")
        return int(value["seconds"]), value.get("nanos", 0)
    check_timestamp(value, "rest")
    moment, _, fraction = value[:-1].partition(".")
    seconds = int(dt.datetime.fromisoformat(moment + "+00:00").timestamp())
    return seconds, int((fraction + "000000000")[:9])


def interval(previous, current):
    """Seconds between two requests, bounded by the previous one's response and the next one's dispatch (lower), and by
    the previous one's dispatch and the next one's response (upper); both clocks must agree."""
    check_timing(previous); check_timing(current)
    lower = current["dispatchMonotonic"] - previous["responseMonotonic"]
    upper = current["responseMonotonic"] - previous["dispatchMonotonic"]
    if lower < 0 or _utc_seconds(current["dispatchUtc"]) < _utc_seconds(previous["responseUtc"]) or abs(lower - (_utc_seconds(current["dispatchUtc"]) - _utc_seconds(previous["responseUtc"]))) > 0.25 or abs(upper - (_utc_seconds(current["responseUtc"]) - _utc_seconds(previous["dispatchUtc"]))) > 0.25:
        raise ValueError("interval clocks differ or moved backwards")
    return {"lowerSeconds": lower, "upperSeconds": upper}


def wait_projection(entry, thresholds):
    """The part of a wait two independent recordings must agree on: the declared seconds and, against the table's
    total-age threshold, whether the token was certainly younger, certainly older, or neither."""
    shown = {"site": entry["site"], "seconds": entry["seconds"]}
    if "totalAgeInterval" in entry and thresholds:
        limit = thresholds["totalAgeSeconds"]
        age = entry["totalAgeInterval"]
        shown["ageClass"] = "BEFORE" if age["upperSeconds"] < limit else "AFTER" if age["lowerSeconds"] > limit else "INDETERMINATE"
    return shown


def wait_entry(step, previous, timing, tokens):
    """What one wait left behind: the idle bounds before the request, and its token's total age bounds."""
    entry = {"site": step["id"], "seconds": step["waitSeconds"], "previousSite": previous["site"], "previousTiming": copy.deepcopy(previous["timing"]), "currentTiming": copy.deepcopy(timing), "idleInterval": interval(previous["timing"], timing)}
    carried = step["tokenInput"] or step.get("retryOf")   # a retry begin ages the token it names
    if carried:
        entry["tokenRole"] = carried
        entry["totalAgeInterval"] = interval(tokens[carried]["start"], timing)
    if entry["idleInterval"]["lowerSeconds"] < step["waitSeconds"]:
        raise ValueError("a wait did not last as long as declared")
    return entry


def _present(frame, key):
    """Whether a decoded entry sets `key` (a decoder may keep an unset member as null or an empty string)."""
    return frame.get(key) not in (None, "")


def check_order(previous, current):
    """A request is sent only after the answer to the one before it, on both clocks."""
    if current["dispatchMonotonic"] < previous["responseMonotonic"] or _utc_seconds(current["dispatchUtc"]) < _utc_seconds(previous["responseUtc"]) - 0.25:
        raise ValueError("requests overlap or ran out of order")


def check_concurrent_order(before_anchor, current):
    """A request sent while the next one is sent (a concurrent outside writer): it starts after the answer to the request that
    came before that one and ends after it started, on both clocks."""
    if current["responseMonotonic"] < current["dispatchMonotonic"] or current["dispatchMonotonic"] < before_anchor["responseMonotonic"] or _utc_seconds(current["dispatchUtc"]) < _utc_seconds(before_anchor["responseUtc"]) - 0.25:
        raise ValueError("a concurrent request starts before the request that precedes its anchor")


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
            if step.get("retryOf"):
                # The retry is the named token's last use; the token it issues is released right after it.
                self.last_use[step["retryOf"]] = step["id"]
                if step["tokenOutput"]:
                    self.last_use[step["tokenOutput"]] = step["id"]
        self.tokens = {}
        self.docs = {role: {"status": "unexamined", "state": None, "possible": [], "stamp": None} for role in plan["documents"]}
        self.unknown_starts, self.unknown_rollbacks, self.unknown_commits = set(), set(), set()
        self._prior = {}
        self._probes = set()
        self.tried = {role: set() for role in plan["documents"]}
        # Not part of the recorded snapshot: every state a document was acknowledged in, and what each token could see.
        self.history = {role: [] for role in plan["documents"]}
        self.since, self.modes, self.token_time = {}, {}, {}
        self.versions = {role: [] for role in plan["documents"]}
        self.acked_at = {}
        # Tokens some request was refused for as expired or no longer valid (10 with the recorded text). Kept out
        # of the recorded snapshot: replaying the rows rebuilds it.
        self.gone_seen = set()
        # Documents a concurrent outside writer and its anchor both wrote: the writer may have landed before or after the anchor, so a
        # read may show the state before the writer's as well as the writer's, until a later write settles it. Also outside the snapshot.
        self.ambiguous = {}

    def snapshot(self):
        return {
            "tokens": copy.deepcopy(self.tokens),
            "documents": copy.deepcopy(self.docs),
            "unknownStarts": sorted(self.unknown_starts),
            "unknownRollbacks": sorted(self.unknown_rollbacks),
            "unknownCommits": sorted(self.unknown_commits),
        }

    def times(self):
        """The time each commit acknowledged for each document it wrote, keyed by document and the commit's step id."""
        return {key: {"seconds": str(time[0]), "nanos": time[1]} for key, time in self.acked_at.items()}

    def token_values(self):
        return {role: entry["value"] for role, entry in self.tokens.items()}

    def _token_for(self, value):
        for role, entry in self.tokens.items():
            if entry["value"] == value:
                return role, entry
        return None, None

    def _certainly_expired(self, entry, timing):
        """Whether the token is certainly older than the table's declared release age at this request (its dispatch, against the
        answer to its begin, so the bound is a lower one)."""
        limit = (self.plan.get("thresholds") or {}).get("releaseAfterAgeSeconds")
        return limit is not None and interval(entry["start"], timing)["lowerSeconds"] > limit

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
        if method == "BeginTransaction" or method == "BatchGetDocuments" and "newTransaction" in request:
            # A retry begin names the one token it retries, which may still be open (nothing released it before the retry).
            retried = None
            if method == "BeginTransaction":
                named, entry = self._token_for(request["options"].get("readWrite", {}).get("retryTransaction"))
                if entry is not None and entry["state"] == "open":
                    retried = named   # only an open token may stay open beside a retry; one in unconfirmed-release may not
            if any(entry["state"] in ("open", "unconfirmed-release") for role, entry in self.tokens.items() if role != retried):
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
        if method == "BeginTransaction" or method == "BatchGetDocuments" and "newTransaction" in request:
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
                if not (step and step.get("concurrentWith")):
                    # A concurrent writer sent beside its anchor has no state of its own to return to when refused: the anchor may
                    # have changed the document since (the labels it tried still widen what a read may show).
                    self._prior[site][write["document"]] = copy.deepcopy(doc)
                self.tried[write["document"]].add(write["state"])
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
        http = result.get("http")
        if transport == "grpc" and http is not None or transport == "rest" and (type(http) is not int or not 100 <= http <= 599 or (200 <= http < 300) != (code == 0)):
            raise ValueError("HTTP status disagrees with the transport or the code")
        if code == 0 and not isinstance(result.get("response"), dict):
            raise ValueError("native success has no typed response")

    def after(self, site, transport, method, request, step, result, timing):
        self._check_receipt(transport, method, result)
        code = result["code"]
        self._apply(site, transport, method, request, step, result, timing, code)
        if step is not None and code not in step["allow"]:
            raise ValueError(f"outcome {code} at {site} is outside the declared set")

    def _apply(self, site, transport, method, request, step, result, timing, code):
        if code == GONE_CODE and result["details"] == GONE_DETAILS:
            # The token a request names, or the one a retry begin names: either was refused as expired, so a later "Invalid transaction." is its release.
            named = request.get("transaction") or (request.get("options") or {}).get("readWrite", {}).get("retryTransaction")
            gone_role, _entry = self._token_for(named)
            if gone_role is not None:
                self.gone_seen.add(gone_role)
        if method == "BeginTransaction":
            # Validate before releasing the responsibility: a transaction may exist that no role owns yet.
            if code == 0:
                token = canonical_token(result["response"].get("transaction"))
                if token in self.token_values().values():
                    raise ValueError("minted token is not fresh")
                self.tokens[step["tokenOutput"]] = {"value": token, "state": "open", "transport": transport, "start": copy.deepcopy(timing), "lastUse": copy.deepcopy(timing)}
                self.modes[step["tokenOutput"]] = step.get("mode", "readWrite")
                self.since[step["tokenOutput"]] = {role: len(states) for role, states in self.history.items()}
                at = request["options"].get("readOnly", {}).get("readTime")
                if at is not None:
                    self.token_time[step["tokenOutput"]] = parse_time(at, transport)
            self.unknown_starts.discard(site)
            return
        if method == "Commit":
            if code == 0:
                # JSON omits an empty repeated field, so an empty commit may answer without writeResults.
                writes = result["response"].get("writeResults", [])
                if not isinstance(writes, list) or len(writes) != len(request["writes"]) or any(not isinstance(write, dict) for write in writes):
                    raise ValueError("commit lacks its per-write acknowledgements")
                for write in writes:
                    check_timestamp(write.get("updateTime"), transport)
                self.unknown_commits.discard(site)
                for write, acknowledged in zip(step["writes"], writes, strict=True):
                    doc = self.docs[write["document"]]
                    if step.get("concurrentWith"):
                        self.ambiguous[write["document"]] = {doc["state"]} - {None}
                    else:
                        self.ambiguous.pop(write["document"], None)
                    doc.update(status="created", state=write["state"], possible=[write["state"]] + ([doc["state"]] if step.get("concurrentWith") and doc["state"] not in (None, write["state"]) else []))
                    self.history[write["document"]].append(write["state"])
                    stamp = parse_time(acknowledged["updateTime"], transport)
                    self.versions[write["document"]].append((write["state"], stamp))
                    self.acked_at[f"{write['document']}@{site}"] = stamp
                _role, entry = self._token_for(request.get("transaction"))
                if entry is not None:
                    entry["state"] = "committed"
            else:
                self.unknown_commits.discard(site)
                for role, prior in self._prior.pop(site, {}).items():
                    # A refusal publishes nothing, so status and state return; the labels tried stay known in
                    # `tried` (outside the recorded snapshot), so recovery can still delete a partly written document.
                    # A document a refused commit created outright is not covered: that would be a failure of atomicity.
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
                elif (code, result["details"]) == (GONE_CODE, GONE_DETAILS) or (code, result["details"]) == (INVALID_CODE, INVALID_DETAILS) and role in self.gone_seen or self.modes.get(role) == "readOnly":
                    # Production says the transaction no longer exists, so no lock of it can remain; a read-only
                    # transaction holds no lock at all, so any definitive refusal of its release finishes it.
                    entry["state"] = "released-refused"
                elif outcome_class(code) == "REFUSED" and self._certainly_expired(entry, timing):
                    # A table that declares `releaseAfterAgeSeconds` (the age past which production has refused a request as
                    # expired, from a recording) treats a definitive refusal of the release of a token that is certainly older
                    # than that as its release, whatever the code and text: the token is past its lifetime, so it holds no lock.
                    entry["state"] = "released-expired"
                else:
                    # Any other refusal proves nothing: a declared step may try again, a recovery release never repeats.
                    entry["state"] = "open" if step is not None else "unconfirmed-release"
        if code == 0 and method != "BeginTransaction":
            _role, entry = self._token_for(request.get("transaction"))
            if entry is not None:
                entry["lastUse"] = copy.deepcopy(timing)
        if method == "GetDocument":
            self._read(site, transport, request, result, code, step)
        elif method == "BatchGetDocuments":
            self._batch(transport, request, result, code, step, timing)

    def _batch(self, transport, request, result, code, step, timing):
        """One entry per requested document, each found with its acknowledged marker or reported missing."""
        starts = "newTransaction" in request
        if code != 0:
            if starts:
                self.unknown_starts.discard(step["id"])
            return
        frames = result["response"].get("responses")
        seen, minted = set(), None
        if not isinstance(frames, list):
            raise ValueError("batch answer is not a list of entries")
        if starts:
            # The transaction the batch begins arrives once, first: in an entry of its own that names no document, or
            # in the first document's entry.
            head = frames[0] if frames else None
            if not isinstance(head, dict) or not _present(head, "transaction"):
                raise ValueError("the batch that begins a transaction does not answer with the transaction first")
            minted = canonical_token(head["transaction"])
            if minted in self.token_values().values():
                raise ValueError("the batch that begins a transaction minted no fresh transaction")
            # Own the transaction before the entries are judged: a stop from here on can still release it.
            self.tokens[step["tokenOutput"]] = {"value": minted, "state": "open", "transport": transport, "start": copy.deepcopy(timing), "lastUse": copy.deepcopy(timing)}
            self.modes[step["tokenOutput"]] = step["newTransaction"]
            self.since[step["tokenOutput"]] = {role: len(states) for role, states in self.history.items()}
            if not _present(head, "found") and not _present(head, "missing"):
                if {key for key in head if _present(head, key)} - {"transaction", "readTime"}:
                    raise ValueError("the entry that carries the new transaction is neither a bare head nor a document entry")
                frames = frames[1:]
        if len(frames) != len(request["documents"]):
            raise ValueError("batch answer does not carry one entry per requested document")
        for index, frame in enumerate(frames):
            # Native protobuf decoding adds the oneof discriminator `result` and an empty `transaction`.
            if not isinstance(frame, dict) or _present(frame, "found") == _present(frame, "missing") or set(frame) - {"found", "missing", "readTime", "transaction", "result"}:
                raise ValueError("batch entry is neither found nor missing")
            kind = "found" if _present(frame, "found") else "missing"
            if frame.get("result", kind) not in (kind, None):
                raise ValueError("batch entry carries a discriminator that disagrees")
            if _present(frame, "transaction") and not (starts and index == 0 and frame["transaction"] == minted):
                raise ValueError("batch entry carries an unrequested transaction")
            name = frame["found"].get("name") if kind == "found" and isinstance(frame["found"], dict) else frame.get("missing")
            if name not in request["documents"] or name in seen:
                raise ValueError("batch entry names a document that was not requested or repeats")
            seen.add(name)
            role = self._role_of(name)
            visible = self._visible(role, request, step)
            if kind == "found":
                if not visible - {None}:
                    raise ValueError("a document this recording never wrote exists")
                self._owned(role, frame["found"], transport, visible - {None})
            elif None not in visible:
                raise ValueError("an acknowledged document is reported missing")
        if starts:
            self.unknown_starts.discard(step["id"])

    def batch_states(self, request, result):
        """The state each batch-read document showed, by role."""
        states = {}
        for frame in result["response"]["responses"]:
            if not _present(frame, "found") and not _present(frame, "missing"):
                continue
            found = _present(frame, "found")
            name = frame["found"]["name"] if found else frame["missing"]
            states[self._role_of(name)] = frame["found"]["fields"]["state"]["stringValue"] if found else None
        return states

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

    def _state_at(self, role, moment):
        """The state of the latest version acknowledged at or before `moment`, or None if there was none."""
        current = None
        for state, stamp in self.versions[role]:
            if stamp <= moment:
                current = state
        return current

    def _visible(self, role, request, step=None):
        """The states a read may show: the latest, the one at a read time, or for a read-only transaction (and a read-write
        transaction's read the table marks `sinceBegin`) any since it began."""
        doc = self.docs[role]
        if "readTime" in request:
            return {self._state_at(role, parse_time(request["readTime"], "grpc"))}
        token_role, _entry = self._token_for(request.get("transaction"))
        if token_role in self.token_time:
            return {self._state_at(role, self.token_time[token_role])}
        if token_role is None or self.modes.get(token_role) != "readOnly" and not (step and step.get("sinceBegin")):
            return {doc["state"]} | self.ambiguous.get(role, set())
        begun = self.since[token_role][role]
        # A transaction that began before the document existed may also see it absent.
        return set(self.history[role][max(0, begun - 1):]) | ({None} if begun == 0 else set()) or {doc["state"]}

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
        visible = self._visible(role, request, step) - {None}
        if doc["state"] is None or not visible:
            raise ValueError("a document this recording never wrote exists")
        self._owned(role, result["response"], transport, visible)

    def _cleanup_read(self, site, role, transport, result, code):
        doc = self.docs[role]
        if site.startswith("cleanup/read/"):
            if code != 0:
                raise ValueError("owned document is not readable for deletion")
            doc["stamp"] = self._owned(role, result["response"], "grpc", set(doc["possible"]) | {doc["state"]} | self.tried[role])
        elif site.startswith("cleanup/verify/") and code == 5:
            doc["status"] = "confirmed-absent"
        elif site.startswith("cleanup/verify/"):
            raise ValueError("deleted document is not absent")


class Collector:
    def __init__(self, plan, table, budget, wire, bearer, *, save, before_send=lambda: None, monotonic=time.monotonic, observation_deadline=None, utc=utc_now, sleep=time.sleep):
        validate_plan(plan, table)
        self.plan, self.table = copy.deepcopy(plan), table
        self.budget, self.wire, self.bearer, self.save, self.before_send = budget, wire, bearer, save, before_send
        self.monotonic, self.utc, self.sleep = monotonic, utc, sleep
        self.waits = []
        self.ledger = Ledger(self.plan)
        self.observation_deadline = observation_deadline or monotonic() + plan["observationSeconds"]
        self.deadline = self.observation_deadline
        self.rows, self.cleanup_rows = [], []
        self.pending = None
        self.pending_concurrent = None
        self.concurrent = any(step.get("concurrentWith") for step in self.plan["steps"])
        self.started = None
        self.journal_failure = False
        self._last_monotonic = monotonic()
        self.last_timing = None

    def _now(self):
        current = self.monotonic()
        if type(current) not in (int, float) or not math.isfinite(current) or current < self._last_monotonic:
            raise ValueError("clock is invalid or moved backwards")
        self._last_monotonic = current
        return current

    def _state(self):
        return {"kind": "txn-program-responsibility-v1", "plan": self.plan, **self.ledger.snapshot(), "pending": copy.deepcopy(self.pending), **({"pendingConcurrent": copy.deepcopy(self.pending_concurrent)} if self.concurrent else {}), "rows": copy.deepcopy(self.rows), "cleanupRows": copy.deepcopy(self.cleanup_rows), "requests": self.budget.total, **({"waits": copy.deepcopy(self.waits)} if self.plan["waits"] else {})}

    def _persist(self):
        try:
            self.save(self._state())
        except (Exception, KeyboardInterrupt):
            self.journal_failure = True
            self.budget.failed = True
            raise

    def _rpc(self, site, transport, method, request, phase, *, step=None):
        context = self._begin_rpc(site, transport, method, request, phase, step=step)
        result = self.wire.send(transport, method, request, nonce=self.plan["nonce"], owner_id=self.plan["ownerId"], bearer=self.bearer, deadline_ms=context["deadlineMs"])
        return self._end_rpc(context, result)

    def _begin_rpc(self, site, transport, method, request, phase, *, step=None, concurrent=False):
        """Everything before the dispatch: admission, the budget, the responsibility, and the durable journal."""
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
        entry = {"site": site, "rpc": method, "transport": transport}
        if concurrent:
            self.pending_concurrent = entry
        else:
            self.pending = entry
        self._persist()
        self.before_send()
        remaining = self.deadline - self._now()
        if remaining < need:
            raise TimeoutError("dispatch no longer fits after durable journal")
        timing = {"dispatchMonotonic": self._now(), "dispatchUtc": self.utc()}
        return {"site": site, "transport": transport, "method": method, "request": request, "phase": phase, "step": step, "timing": timing, "deadlineMs": int(wanted * 1000), "concurrent": concurrent}

    def _end_rpc(self, context, result, response_timing=None):
        """Everything after the answer: the row, the clock checks and the ledger. A concurrent request carries the clocks read when
        its answer arrived, since it is collected after the request it ran beside."""
        site, transport, method, request, phase, step, timing = (context[key] for key in ("site", "transport", "method", "request", "phase", "step", "timing"))
        concurrent = context["concurrent"]
        timing.update(response_timing or {"responseMonotonic": self._now(), "responseUtc": self.utc()})
        row = {"sequence": len(self.rows) + len(self.cleanup_rows), "phase": phase, "timing": timing, "site": site, "transport": transport, "rpc": method, "caseId": step["caseId"] if step else None, "request": copy.deepcopy(request), "result": copy.deepcopy(result)}
        (self.rows if phase == "observation" else self.cleanup_rows).append(row)
        try:
            # The answer is kept in the rows even when its clocks are refused.
            check_timing(timing)
            if concurrent:
                check_concurrent_order(context["before"], timing)
                # The next request follows the later of the two answers.
                if self.last_timing is None or timing["responseMonotonic"] > self.last_timing["responseMonotonic"]:
                    self.last_timing = copy.deepcopy(timing)
            else:
                if self.last_timing is not None:
                    check_order(self.last_timing, timing)
                self.last_timing = copy.deepcopy(timing)
            self.ledger.after(site, transport, method, request, step, result, timing)
        except (Exception, KeyboardInterrupt):
            self._persist()
            raise
        row["outcomeClass"] = outcome_class(result["code"])
        if concurrent:
            self.pending_concurrent = None
        else:
            self.pending = None
        self._persist()
        return result

    def _wait(self, step):
        """Idle for the declared seconds after a completed request, in one-second slices that re-check the phase."""
        previous = self.rows[-1] if self.rows else None
        if previous is None:
            raise ValueError("a wait needs a preceding request")
        target = self._now() + step["waitSeconds"]
        need = max(13, step["deadlineMs"] / 1000 + 3)
        while self._now() < target:
            self.before_send()
            current = self._now()
            if self.deadline - current < (target - current) + need:
                raise TimeoutError("a wait cannot fit the observation phase")
            if current >= target:
                break
            self.sleep(min(1, target - current))
            if self._now() <= current:
                raise ValueError("the wait clock did not advance")
        if self._now() - target > 1:
            raise TimeoutError("a wait overshot its scheduling slack")
        self._persist()

    def _start_concurrent(self, step):
        """Send an outside writer on its own thread; it may be held by a holder's locks until the anchor step that follows releases them."""
        request = request_for_step(self.plan, step, self.ledger.token_values(), self.table, self.ledger.times())
        context = self._begin_rpc(step["id"], step["transport"], step["rpc"], request, "observation", step=step, concurrent=True)
        context["before"] = copy.deepcopy(self.last_timing) if self.last_timing is not None else {"responseMonotonic": context["timing"]["dispatchMonotonic"], "responseUtc": context["timing"]["dispatchUtc"]}
        box = {}

        def send():
            try:
                box["result"] = self.wire.send(context["transport"], context["method"], request, nonce=self.plan["nonce"], owner_id=self.plan["ownerId"], bearer=self.bearer, deadline_ms=context["deadlineMs"])
            except BaseException as error:  # noqa: BLE001 - carried to the collecting thread
                box["error"] = error
            box["response"] = {"responseMonotonic": self.monotonic(), "responseUtc": self.utc()}

        thread = threading.Thread(target=send, name=f"concurrent-{step['id']}", daemon=True)
        self.started = {"context": context, "thread": thread, "box": box, "limit": context["deadlineMs"] / 1000 + 10}
        thread.start()

    def _finish_concurrent(self):
        """Collect the concurrent writer's answer as its own row, after the anchor's."""
        started, self.started = self.started, None
        if started is None:
            return
        started["thread"].join(started["limit"])
        if started["thread"].is_alive():
            self.started = started
            raise TimeoutError("a concurrent writer did not answer within its deadline; its outcome stays unknown")
        box = started["box"]
        if "error" in box:
            raise box["error"]
        self._end_rpc(started["context"], box["result"], response_timing=box["response"])

    def _settle_concurrent(self):
        """Before the cleanup: wait for a writer still in flight and record its answer if it came, so the cleanup read sees its effect."""
        try:
            self._finish_concurrent()
        except (Exception, KeyboardInterrupt):
            pass

    def _observe(self):
        cursor = GraphCursor(self.plan, self.table)
        steps = self.plan["steps"]
        index = 0
        while index < len(steps):
            declared = steps[index]
            following = steps[index + 1] if index + 1 < len(steps) else None
            concurrent = following if following is not None and following.get("concurrentWith") == declared["id"] else None
            step = cursor.claim(declared["id"])
            if concurrent is not None:
                self._start_concurrent(cursor.claim(concurrent["id"]))
            if "waitSeconds" in step:
                self._wait(step)
                previous = self.rows[-1]
            request = request_for_step(self.plan, step, self.ledger.token_values(), self.table, self.ledger.times())
            self._rpc(step["id"], step["transport"], step["rpc"], request, "observation", step=step)
            if "waitSeconds" in step:
                self.waits.append(wait_entry(step, previous, self.rows[-1]["timing"], self.ledger.tokens))
                self._persist()
            # The holder is released before the writer is joined: a holder whose release was refused and that kept its lock would
            # otherwise hold the writer until its own deadline, and the recording would stop on the writer's timeout.
            for role in self.ledger.pending_release(step):
                site = f"cleanup/token/{role}"
                self._rpc(site, self.ledger.tokens[role]["transport"], "Rollback", self.ledger.release_request(role), "tokenCleanup")
                if self.ledger.tokens[role]["state"] not in ("rolled-back", "released-refused", "released-expired"):
                    raise ValueError("chain release is unconfirmed; next chain forbidden")
            if concurrent is not None:
                self._finish_concurrent()
            index += 2 if concurrent is not None else 1
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
        # A concurrent writer still in flight is held by the holder's locks until the release above; wait for it and record its answer if it came.
        self._settle_concurrent()
        if self.ledger.unknown_commits:
            # A write whose outcome is unknown (a writer that timed out) may still land, held by a lock until the token above was released
            # (P06 recording 2: about 1.2 s after the release); wait a few seconds, within the recovery clock, before the read that decides
            # the delete, so that read is not older than the write.
            for _second in range(SETTLE_SECONDS):
                if self.deadline - self._now() < 20:
                    break
                self.sleep(1)
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
            **({"waits": copy.deepcopy(self.waits)} if self.plan["waits"] else {}),
        }


def projection(receipt, table):
    """Replay every row of a complete recording; only what the rows derive can freeze."""
    if not isinstance(receipt, dict) or receipt.get("kind") != RECORDING_KIND or receipt.get("complete") is not True or receipt.get("graphComplete") is not True or receipt.get("journalFailure") is not False or receipt.get("unrecovered") is not False or receipt.get("failureType") is not None or any(receipt.get(key) for key in ["openTokens", "unknownStarts", "unknownRollbacks", "unknownCommits"]) or receipt.get("cleanup") != {"absent": True}:
        raise ValueError("only complete acquisitions can freeze")
    if table['name'] == 'p17-admin-sdk-retry':
        import subprocess
        from txn_program_cli import source_manifest
        from txn_program_wire import verify_runtime
        import hashlib
        if receipt.get('receiptDigest') != hashlib.sha256(json.dumps({key: value for key, value in receipt.items() if key != 'receiptDigest'}, sort_keys=True, separators=(',', ':'), allow_nan=False, ensure_ascii=False).encode()).hexdigest(): raise ValueError('SDK receipt digest differs')
        runtime = receipt.get('runtimeManifest')
        verify_runtime(runtime)
        if receipt.get('sourceManifest') != source_manifest(table['name']): raise ValueError('SDK source manifest differs')
        plan = compile_plan(table, receipt.get('nonce'), receipt.get('ownerId'))
        if receipt.get('sourceDigest') != plan['sourceDigest'] or receipt.get('corpusDigest') != plan['corpusDigest']: raise ValueError('SDK source binding differs')
        result = subprocess.run([runtime['nodeExecutable'], table['sourceFile'], 'project'], input=json.dumps(receipt).encode(), capture_output=True, env={'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC'}, timeout=30)
        if result.returncode or len(result.stdout) > 65536: raise ValueError('SDK projection refused native evidence')
        return json.loads(result.stdout)
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
    observations, reads, waits = [], [], []
    previous_timing = None
    waiting = None   # the concurrent writer sent beside the anchor just replayed: (its step, its request at dispatch, the timing before the anchor)
    for row in sorted(rows, key=lambda row: row["sequence"]):
        check_timing(row.get("timing"))
        site, transport, method, request, result = row.get("site"), row.get("transport"), row.get("rpc"), row.get("request"), row.get("result")
        if waiting is not None and not owed and row.get("phase") == "observation":
            # The writer's own row: it follows the anchor and the anchor's release rows, and started before the anchor did.
            following, dispatched_request, before_anchor = waiting
            if index >= len(steps) or row != steps[index] or site != following["id"] or method != following["rpc"] or transport != following["transport"] or row.get("caseId") != following["caseId"] or request != dispatched_request:
                raise ValueError("concurrent request graph differs")
            check_concurrent_order(before_anchor, row["timing"])
            ledger.after(site, transport, method, request, following, result, row["timing"])
            if row.get("outcomeClass") != outcome_class(result["code"]):
                raise ValueError("outcome class differs from its code")
            if following["caseId"]:
                observations.append(row)
            if row["timing"]["responseMonotonic"] > previous_timing["responseMonotonic"]:
                previous_timing = row["timing"]
            waiting = None
            index += 1
            continue
        if previous_timing is not None:
            check_order(previous_timing, row["timing"])
        before_anchor = previous_timing
        previous_timing = row["timing"]
        if row.get("phase") == "observation":
            if waiting is not None or owed or queue is not None or index >= len(steps) or row != steps[index]:
                raise ValueError("observation sequence differs")
            declared = plan["steps"][index]
            if site != declared["id"] or method != declared["rpc"] or transport != declared["transport"] or row.get("caseId") != declared["caseId"] or request != request_for_step(plan, declared, ledger.token_values(), table, ledger.times()):
                raise ValueError("closed request graph differs")
            following = plan["steps"][index + 1] if index + 1 < len(plan["steps"]) else None
            if following is not None and following.get("concurrentWith") == declared["id"]:
                # The concurrent outside writer was sent before its anchor, so the ledger takes it on before the anchor and its answer after.
                dispatched_request = request_for_step(plan, following, ledger.token_values(), table, ledger.times())
                ledger.before(following["id"], following["transport"], following["rpc"], dispatched_request, following)
                waiting = (following, dispatched_request, before_anchor if before_anchor is not None else {"responseMonotonic": row["timing"]["dispatchMonotonic"], "responseUtc": row["timing"]["dispatchUtc"]})
            ledger.before(site, transport, method, request, declared)
            ledger.after(site, transport, method, request, declared, result, row["timing"])
            if "waitSeconds" in declared:
                if index == 0:
                    raise ValueError("a wait needs a preceding request")
                waits.append(wait_entry(declared, steps[index - 1], row["timing"], ledger.tokens))
            if row.get("outcomeClass") != outcome_class(result["code"]):
                raise ValueError("outcome class differs from its code")
            if declared["caseId"]:
                observations.append(row)
            if method == "GetDocument" and result["code"] == 0:
                reads.append({"site": site, "code": 0, "state": result["response"]["fields"]["state"]["stringValue"]})
            elif method == "GetDocument":
                reads.append({"site": site, "code": result["code"], "state": None})
            if method == "BatchGetDocuments":
                reads.append({"site": site, "code": result["code"], "documents": ledger.batch_states(request, result) if result["code"] == 0 else None})
            owed = ledger.pending_release(declared)
            index += 1
        elif row.get("phase") == "tokenCleanup":
            if not owed or site != f"cleanup/token/{owed[0]}" or method != "Rollback" or transport != ledger.tokens[owed[0]]["transport"] or request != ledger.release_request(owed[0]):
                raise ValueError("per-chain release proof differs")
            ledger.before(site, transport, method, request, None)
            ledger.after(site, transport, method, request, None, result, row["timing"])
            if ledger.tokens[owed[0]]["state"] not in ("rolled-back", "released-refused", "released-expired"):
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
    if index != len(steps) or waiting is not None or owed or queue or releases != counts["tokenCleanup"] or not ledger.all_absent() or ledger.unresolved_tokens() or observations != receipt.get("observations") or ledger.snapshot()["tokens"] != receipt.get("tokens") or ledger.snapshot()["documents"] != receipt.get("documents") or (waits or receipt.get("waits")) and waits != receipt.get("waits"):
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
        **({"waits": [wait_projection(entry, plan.get("thresholds")) for entry in waits]} if waits else {}),
    }
