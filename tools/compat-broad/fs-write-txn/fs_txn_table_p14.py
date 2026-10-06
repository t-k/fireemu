"""FS-TRANSACTION P14 (stage 2): five conditions no recording covers yet, on the project FS-TRANSACTION owns alone (`fireemu-oracle-txn`, free tier).

This table grants no send permission. Every answer a step may give is wide (a code outside the set stops the recording only for ownership and
cleanup reasons, never because an answer refutes what strict does today); the comparison against fireemu is offline.

Owned documents (eight): `a` and `b` (the write-set and token chains' documents, created in setup), `c` and `d` (a spare each for the REST and the
gRPC write-set chain, created by a writer), `h` (the range-lock chains' in-range document, created in setup with state `q-in`), `p` and `o`
(the REST phantom and outside-range documents, created by a writer) and `p2` (the gRPC phantom, created by a writer).

- write-set-atomicity (P06 again, its second recording had stopped at its 30 s writer deadline): per transport a holder reads `a`; an unrelated writer
  commits `b` and a spare (they are not the holder's read set); the holder is released 45 s in while a two-document writer (`a` and `b`) was sent
  first with a 90 s deadline. Production either refuses that writer (P06 recording 1: 10 "Too much contention", about 21 s) or holds it until the
  release (P06 recording 2): the plain reads of `a` and `b` that follow show whether both or neither changed.
- query-range-lock: a read-write transaction runs the query `state == q-in` and holds it; per chain one outside writer is sent first and the holder is
  released 5 s in. REST: an outside-range control (a new document in state `q-out`) and a phantom (a new document in state `q-in`); gRPC: the phantom
  alone (the representative case). A writer held until the release answers after about 5 s; one that is not answers at once.
- paging-and-cancellation (gRPC): a transaction runs the unfiltered query (more than three documents exist) and the call cancels the stream after the
  first frame; the same token then reads and commits, and a writer to a document of the range, sent first, answers only after that commit.
- read-time-retention: reads 59 and 61 minutes before they are sent (the one-hour retention boundary, no point-in-time recovery): GetDocument,
  BatchGetDocuments and, last, a read-only begin over REST (59 minutes must be accepted, 61 refused: the other answer stops the run), GetDocument and BatchGetDocuments over gRPC. The condition asks only for accepted or refused
  answers ("compare accepted/refused results and configuration"), so a document created in this run is enough and nothing waits an hour.
- token validation: a valid-token control, then a token that does not decode (REST only) and one that decodes and was never issued, on a read, a
  batch read, a commit and a rollback over REST, and the unknown token on a read, a commit and a rollback over gRPC.

Foreign-project and foreign-database tokens need a second database and a second project: they are a separate, later packet."""

from pathlib import Path

WIDE = (0, 3, 5, 9, 10)
PROJECT = "fireemu-oracle-txn"
HOLD_SECONDS = 5
WRITE_SET_HOLD_SECONDS = 45
RETENTION_AGO = {"59": 59 * 60, "61": 61 * 60}
STATES = ("created", "q-in", "q-out", "rest-bc", "rest-ab", "grpc-bc", "grpc-ab", "pg-writer", "tv-rest", "tv-grpc")


def _step(step_id, transport, rpc, role, *, document=None, token_in=None, token_out=None, writes=(), case=None, allow=(0,), deadline=None, wait=None, concurrent_with=None, **extra):
    step = {"id": step_id, "transport": transport, "rpc": rpc, "document": document, "tokenInput": token_in, "tokenOutput": token_out,
            "writes": tuple({"document": name, "state": state, "exists": exists} for name, state, exists in writes),
            "caseId": case, "role": role, "allow": allow}
    if deadline:
        step["deadlineMs"] = deadline
    if wait:
        step["waitSeconds"] = wait
    if concurrent_with:
        step["concurrentWith"] = concurrent_with
    step.update(extra)
    return step


def _writer(step_id, transport, writes, *, deadline=30000, concurrent_with=None):
    return _step(step_id, transport, "Commit", "outside-writer", writes=writes, case=step_id, allow=(0, 10), deadline=deadline, concurrent_with=concurrent_with)


def _read(step_id, transport, document, *, role="observation", token_in=None, case=True, allow=WIDE):
    return _step(step_id, transport, "GetDocument", role, document=document, token_in=token_in, case=step_id if case and role == "observation" else None, allow=allow if role == "observation" else (0,))


def _begin(step_id, transport, token):
    return _step(step_id, transport, "BeginTransaction", "control", token_out=token)


def _query(step_id, transport, *, token_in=None, role="observation", query=None, allow=None, **extra):
    return _step(step_id, transport, "RunQuery", role, token_in=token_in, case=step_id if role == "observation" else None, allow=allow or (WIDE if role == "observation" else (0,)), query=query or {}, **extra)


# ---- write-set-atomicity -------------------------------------------------------------------------------------------------------------------------

def _write_set(transport, spare):
    token = f"{transport}-w"
    return [
        _begin(f"{transport}/w/begin", transport, token),
        _read(f"{transport}/w/read-a", transport, "a", role="control", token_in=token),
        _writer(f"{transport}/w/writer-bc", transport, (("b", f"{transport}-bc", True), (spare, f"{transport}-bc", False))),
        _step(f"{transport}/w/release", transport, "Rollback", "observation", token_in=token, case=f"{transport}/w/release", allow=(0, 10), wait=WRITE_SET_HOLD_SECONDS),
        _writer(f"{transport}/w/writer-ab", transport, (("a", f"{transport}-ab", True), ("b", f"{transport}-ab", True)), deadline=90000, concurrent_with=f"{transport}/w/release"),
        _read(f"{transport}/w/plain-a", transport, "a"),
        _read(f"{transport}/w/plain-b", transport, "b"),
    ]


# ---- query-range-lock and paging-and-cancellation -------------------------------------------------------------------------------------------------

def _range_chain(transport, chain, writer_document, writer_state):
    token = f"{transport}-{chain}"
    return [
        _begin(f"{transport}/{chain}/begin", transport, token),
        _query(f"{transport}/{chain}/query-in", transport, token_in=token, role="control", query={"stateEquals": "q-in"}),
        _step(f"{transport}/{chain}/release", transport, "Rollback", "observation", token_in=token, case=f"{transport}/{chain}/release", allow=(0, 10), wait=HOLD_SECONDS),
        _writer(f"{transport}/{chain}/writer", transport, ((writer_document, writer_state, False),), concurrent_with=f"{transport}/{chain}/release"),
    ]


def _paging():
    token = "grpc-pg"
    return [
        _begin("grpc/pg/begin", "grpc", token),
        _query("grpc/pg/query-cancelled", "grpc", token_in=token, query={}, cancelAfter=1, allow=(1,)),
        _read("grpc/pg/read-after-cancel", "grpc", "a", token_in=token),
        _step("grpc/pg/commit", "grpc", "Commit", "observation", token_in=token, case="grpc/pg/commit", allow=WIDE, wait=HOLD_SECONDS),
        _writer("grpc/pg/writer", "grpc", (("h", "pg-writer", True),), concurrent_with="grpc/pg/commit"),
        _read("grpc/pg/post-read-h", "grpc", "h", role="post-state"),
    ]


# ---- read-time-retention ---------------------------------------------------------------------------------------------------------------------------

def _retention():
    steps = []
    for label, ago in RETENTION_AGO.items():
        steps.append(_step(f"rest/ret/get-{label}", "rest", "GetDocument", "observation", document="a", case=f"rest/ret/get-{label}", allow=WIDE, readAgoSeconds=ago))
        steps.append(_step(f"rest/ret/batch-{label}", "rest", "BatchGetDocuments", "observation", case=f"rest/ret/batch-{label}", allow=WIDE, readAgoSeconds=ago, documents=["a"]))
    for label, ago in RETENTION_AGO.items():
        steps.append(_step(f"grpc/ret/get-{label}", "grpc", "GetDocument", "observation", document="a", case=f"grpc/ret/get-{label}", allow=WIDE, readAgoSeconds=ago))
    steps.append(_step("grpc/ret/batch-61", "grpc", "BatchGetDocuments", "observation", case="grpc/ret/batch-61", allow=WIDE, readAgoSeconds=RETENTION_AGO["61"], documents=["a"]))
    # The two read-only begins come last, with the allow sets of what production is known to do (a begin validates its read time at the begin): 59 minutes accepted, 61 refused.
    # The other answer is a stop, honestly: an accepted 61 minute begin leaves a token the recovery releases and a graph the replay does not accept, a refused 59 minute begin
    # leaves the release below it with no token. Last, a stop costs no other row.
    steps.append(_step("rest/ret/begin-59", "rest", "BeginTransaction", "observation", token_out="ro-59", case="rest/ret/begin-59", allow=(0,), mode="readOnly", readAgoSeconds=RETENTION_AGO["59"]))
    steps.append(_step("rest/ret/release-59", "rest", "Rollback", "observation", token_in="ro-59", case="rest/ret/release-59", allow=WIDE))
    steps.append(_step("rest/ret/begin-61", "rest", "BeginTransaction", "observation", token_out="ro-61", case="rest/ret/begin-61", allow=(3, 5, 9, 10), mode="readOnly", readAgoSeconds=RETENTION_AGO["61"]))
    return steps


# ---- token validation ------------------------------------------------------------------------------------------------------------------------------

def _tokens():
    token = "rest-v"
    steps = [
        _begin("rest/tv/begin", "rest", token),
        _read("rest/tv/read-control", "rest", "a", role="control", token_in=token),
        _step("rest/tv/release", "rest", "Rollback", "observation", token_in=token, case="rest/tv/release", allow=WIDE),
    ]
    for literal in ("malformed", "unknown"):
        steps += [
            _step(f"rest/tv/get-{literal}", "rest", "GetDocument", "observation", document="a", case=f"rest/tv/get-{literal}", allow=WIDE, tokenLiteral=literal),
            _step(f"rest/tv/batch-{literal}", "rest", "BatchGetDocuments", "observation", case=f"rest/tv/batch-{literal}", allow=WIDE, tokenLiteral=literal, documents=["a"]),
            _step(f"rest/tv/commit-{literal}", "rest", "Commit", "observation", writes=(("a", "tv-rest", True),), case=f"rest/tv/commit-{literal}", allow=WIDE, tokenLiteral=literal),
            _step(f"rest/tv/rollback-{literal}", "rest", "Rollback", "observation", case=f"rest/tv/rollback-{literal}", allow=WIDE, tokenLiteral=literal),
        ]
    steps += [
        _step("grpc/tv/get-unknown", "grpc", "GetDocument", "observation", document="a", case="grpc/tv/get-unknown", allow=WIDE, tokenLiteral="unknown"),
        _step("grpc/tv/commit-unknown", "grpc", "Commit", "observation", writes=(("a", "tv-grpc", True),), case="grpc/tv/commit-unknown", allow=WIDE, tokenLiteral="unknown"),
        _step("grpc/tv/rollback-unknown", "grpc", "Rollback", "observation", case="grpc/tv/rollback-unknown", allow=WIDE, tokenLiteral="unknown"),
    ]
    return steps


ROLES = ("a", "b", "c", "d", "h", "p", "o", "p2")

_SETUP = [_step(f"setup/absence-{role}", "grpc", "GetDocument", "control", document=role, allow=(5,)) for role in ROLES] + [
    _step("setup/create-a-b-h", "grpc", "Commit", "control", writes=(("a", "created", False), ("b", "created", False), ("h", "q-in", False))),
]

STEPS = tuple(
    _SETUP
    + _write_set("rest", "c") + _write_set("grpc", "d")
    + _range_chain("rest", "q1", "o", "q-out") + _range_chain("rest", "q2", "p", "q-in")
    + [_query("rest/q/post-query-in", "rest", query={"stateEquals": "q-in"}), _read("rest/q/post-read-p", "rest", "p"), _read("rest/q/post-read-o", "rest", "o")]
    + _range_chain("grpc", "q", "p2", "q-in") + [_query("grpc/q/post-query-in", "grpc", query={"stateEquals": "q-in"})]
    + _paging()
    + _tokens()
    # last: a replay against a local fireemu advances its clock past the hour just before the first of these (a database created at the process start is younger than the
    # time asked for), and a transaction begun after such an advance does not survive it locally; production's database is old, so the recording waits for nothing.
    + _retention()
)

TABLE = {
    "name": "p14-stage2",
    "program": "FS-TRANSACTION-P14-STAGE2",
    "envelopeId": "FS-TRANSACTION-p14-stage2-001",
    "slug": "txn-p14",
    "project": PROJECT,
    "documents": ROLES,
    "states": STATES,
    "steps": STEPS,
    # Observation is one request per step; cleanup reserves 7 per owned document.
    "caps": {"observation": len(STEPS), "tokenCleanup": 9, "documentCleanup": 56, "management": 7, "credential": 2},
    # The two write-set holds (45 s each), the four range and paging holds (5 s each), the writers' own time and every other request at a few seconds.
    "observationSeconds": 1200,
    "recoverySeconds": 300,
    "maxTokens": 9,
    "sourceFile": Path(__file__),
}
