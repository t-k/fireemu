# Firestore request-byte boundary campaign preparation

Condition: `FS-LIMIT-API-REQUEST-BYTES`, the 10,485,760-byte API request limit.
Parent: `FS-DATA-WRITE`. Evidence class of everything below: preparation and
local artifact shadow. No production request has been sent and no parent is
promoted.

The limits catalog `spec/limits/firestore-standard-2026-08-25.json` records this
condition with `maximum: 10485760`, `enforcementStage: request` and, since the
write-path limits lane landed, `implemented: implemented`. Under
`ip-fs-production-compatibility.md:23` the condition needs an implementation plus
an observation. The implementation half is done; this document prepares the
observation half, which is still outstanding.

## What the campaign observes

Three REST `Commit` requests against disjoint owned document sets, one probe at
a time, each probe fully cleaned up before the next one starts.

| Case | Request bytes | Relation to the limit | Production expectation |
| --- | ---: | ---: | --- |
| `FS-LIMIT-API-REQUEST-BYTES-UNDER` | 10,485,759 | one byte below | accepted |
| `FS-LIMIT-API-REQUEST-BYTES-EXACT` | 10,485,760 | exactly the limit | accepted |
| `FS-LIMIT-API-REQUEST-BYTES-OVER` | 10,485,761 | one byte above | refused |

The measured quantity is the raw REST HTTP body in compact UTF-8 bytes,
including JSON syntax. URL and header bytes are outside it. That this is the
metric production enforces on is an **observation hypothesis**, not an
established backend semantic, and the campaign artifact keeps it labelled that
way. The campaign says nothing about gRPC, where protobuf encoding is a
different quantity.

Each probe writes 17 documents, 16 payload documents plus one control document,
each below the 900 KiB preparation safety margin, every write carrying
`currentDocument: {"exists": false}`. The three probes use equal-length scope
labels so the resource names contribute the same byte count.

## Scope that is deliberately not covered

`BatchWrite` is excluded. The reviewed compiler emits only the Commit endpoint
and the collector's transport admits only `documents:commit`. A BatchWrite
boundary needs its own compiler, transport admission and receipt shape, and
adding it here would change the reviewed transport surface. gRPC Commit is
excluded for the separate reason above. Both exclusions carry their reason in
the campaign artifact rather than being silent.

## The refusal shape, as a typed expectation

The over-boundary Commit is expected to be refused before any document is
evaluated. A refusal counts only when the receipt is complete, its raw response
bytes agree with the parsed body, the HTTP status is an integer, and the error
code is an integer equal to that status with `INVALID_ARGUMENT`.

- HTTP 400 with error code 400 and `INVALID_ARGUMENT` is the expected shape.
- HTTP 413 with error code 413 and `INVALID_ARGUMENT` is still a typed refusal,
  but it is classified as a semantic discrepancy and needs owner adjudication
  before the catalog is amended.

None of the following is a refusal proof: an HTTP 200 with or without write
results, a complete receipt whose raw bytes contradict the parsed body, an
incomplete or timed-out receipt, a non-JSON body such as a front-end HTML 413
page, or a connection reset with no response.

This matters because the condition's own entry in the closure audit expects the
refusal to be **transport-level rather than a typed Firestore error**. An untyped
refusal is therefore the likeliest production outcome, and it is never upgraded
to a typed row: an intermediary does not speak for Firestore.

The collector records it as its own outcome, `untyped-transport-refusal`, under
the separate result key `untypedOverRefusal`, with the HTTP status, the content
type and the response bytes verbatim. That outcome grants no cleanup ownership,
so every version-bound delete becomes a zero-wire skip, recovery stays read-only,
and the refusal shape stays unproven. The run is inconclusive on the refusal
shape and conclusive on state: the post-state readback and the absence proofs
still show that the refused request wrote nothing. The owner adjudicates the
recorded status, content type and bytes, and the boundary question needs a second
run once the intermediary is identified.

## Post state and cleanup

Every probe reads back all 17 of its resources after its Commit. An accepted
probe must find each document present with its expected logical field digest and
the exact version the Commit returned. A refused probe must find every one of its
resources absent with a typed `NOT_FOUND`; that readback is the proof that the
refused request wrote nothing.

Cleanup is version bound. A `DELETE` is issued only when this same run holds a
successful conditional-creation proof for that resource and an ownership read
that matches the resource name, the nonce, the expected field digest and that
exact version. Every other path is a zero-wire skip, so a refused or uncertain
probe issues no delete at all. Each resource then requires a typed `NOT_FOUND`
as its final absence proof. A preexisting document under the owned scope is not
owned by this run: the run stops at preflight rather than overwriting or
deleting it.

## Owned scope and nonce

The campaign uses a fresh nonce generated for it and never reused. It appears in
every owned resource path, so it is published with the campaign artifact; it is a
scope label, not a secret. The owned root is
`projects/{project}/databases/{database}/documents/oracle/{nonce}/request-bytes-01`,
with `probe-u01`, `probe-e01` and `probe-o01` beneath it, 51 distinct resources
in total and at most 17 live at any moment.

## Budget, accounting and cost

Two figures, kept apart on purpose. The **forecast** is what the run costs if
production behaves as expected. The **maximum** is what the permission and the
reservation must cover, and it assumes every probe is accepted, including the
over-boundary one. Budgeting the forecast would leave the campaign unable to pay
for the single result it exists to detect.

| Quantity | Forecast | Maximum |
| --- | ---: | ---: |
| Document writes | 34 | 51 |
| Document deletes | 34 | 51 |
| Document reads | 204 | 204 |
| HTTP requests | 258 | 258 |
| Peak coexisting documents | 17 | 17 |
| Cost, USD | 0.00019 | 0.000224 |

An unexpectedly accepted over-boundary Commit creates 17 more documents and
recovers all 51. The collector already does that correctly; the budget now pays
for it. Two figures deliberately do not rise with the outcome. Peak coexisting
documents stays at one probe's set, because each probe is cleaned up before the
next begins. The request count is fixed by the schedule, because a refused
probe's delete slots are consumed as zero-wire skips rather than saved.

The 258 bound is four reads and one delete slot per owned resource plus one
Commit per probe. Every one of the eight accept/refuse combinations of the three
probes fits inside the published maxima, which the validator checks rather than
asserts.

The hard ceiling is 0.50 USD and must clear the maximum, not the forecast. The
network component is zero to the published precision: about 30 MiB is uploaded
and ingress is not billed, and under 1 MiB is returned. The 30 MiB upload is the
unusual quantity here, not the money.

The recovery window reserves 500 seconds, 102 reads and 51 delete slots inside an
1100-second run. The reserve is sized by the maximum, not the forecast: 51
deletes for every document the worst outcome creates, and two reads per owned
resource for an ownership read and an absence proof. The validator enforces
both, and enforces that the hard ceiling clears the maximum cost rather than the
forecast.

The seconds are what the shared Gate charges, computed by calling it rather than
by re-deriving its formula. `shared_gate` charges each slot its own reserved
seconds plus an interval with a floor of 0.25, requires a slot carrying a body to
reserve the transport ceiling, refuses a wall above 1200 seconds, and refuses a
recovery reservation that cannot pay for its slots. At three seconds a small
request:

| Phase | Slots | Reserved |
| --- | ---: | ---: |
| observation, small reads | 102 | 331.50 s |
| observation, boundary Commits | 3 | 180.75 s |
| recovery | 153 | 497.25 s |
| **total** | **258** | **1009.50 s** |

So the recovery reserve is 500 against 497.25 needed, and the wall is 1100
against 1009.50, inside the Gate's 1200 cap. The earlier published pair, 300 and
900, could not carry this: 300 seconds admits at most 1.71 seconds a recovery
slot, and at two seconds the recovery phase alone needs 344.25. That figure was
never stated in the artifact, which is how the published windows and the
runner's reservation came to disagree. The arithmetic is now computed in
`budget.schedulingReservation` by calling the Gate, and a test drives
`shared_gate.create` on this campaign's schedule to prove it admits the published
windows and refuses 900/300, 900/500 and 1100/300.

Three seconds is roughly an order of magnitude over a few-hundred-millisecond
round trip, which is the shape a bound should have. It is also the per-request
timeout for a small read or delete, so a slot cannot outrun its own reservation;
a reservation nothing enforces is a plan, not a bound. The boundary Commits keep
the 60-second transport deadline.

The window opens on any probe that reaches an observation failure, an uncertain
Commit or an interrupted run. Its authority is read-only unless the same run
holds a conditional-creation proof and a matching version-bound ownership read.
It exits when all 51 owned resources return a typed `NOT_FOUND`. On exhaustion
the run stops, records the remaining resources as unresolved and escalates to
the owner; it never widens scope and never retries a Commit.

## Owner preconditions

1. An O7 admission decision binding this campaign artifact digest, the frozen
   source and the credential holder.
2. A bearer token for a principal that can write under the owned scope and
   nothing else it could damage, acquired through the shared Ledger. Neither the
   campaign module nor the compiler ever holds one.
3. All 51 owned resources absent before the run, proven by 51 typed `NOT_FOUND`
   preflight reads. The run stops otherwise.
4. No other campaign writing under the oracle scope for the duration of the run.
5. Acknowledgement of the untyped-refusal risk above, or a collector extension
   first.

## Local shadow, and what it found

The shadow runs the same plan and collector against an owned local fireemu
artifact built from this checkout, through the existing `broad.run` artifact
builder and process supervisor.

| Probe | Request bytes | Local result |
| --- | ---: | --- |
| under | 10,485,759 | HTTP 200, accepted |
| exact | 10,485,760 | HTTP 200, accepted |
| over | 10,485,761 | HTTP 400, refused |

The refusal body is exactly:

```json
{"error":{"code":400,"message":"Request payload size exceeds the limit: 10485760 bytes.","status":"INVALID_ARGUMENT"}}
```

The local runtime enforces the boundary at exactly the catalog maximum and
answers, in the strict profile, the same status, code and message this campaign
expects of production. The bound is applied at each transport's decode boundary
from `API_REQUEST_BYTES` in `crates/fireemu-adapter-grpc/src/serve.rs`, before
the request is parsed, and the limits catalog now records the condition as
implemented.

**That agreement is not confirmation.** The expected production shape is
documented rather than observed: the quotas page states the 10 MiB maximum but
not the answer to exceeding it, and no production receipt for that refusal exists
in this repository. Local agreement removes a known difference and leaves the
question this campaign exists to settle exactly where it was. Only a production
receipt can answer it.

The shape is recorded per transport, because a reader comparing a production
receipt needs the status, the code and the message separately:

| Transport | Status | Code | Message | Observed by |
| --- | --- | --- | --- | --- |
| REST Commit | HTTP 400 | 400 | `Request payload size exceeds the limit: 10485760 bytes.` | this campaign's local shadow |
| gRPC unary, Write stream, WebChannel | none | 3 | the same message | the runtime's own tests, not this campaign |

The gRPC code follows from `google.rpc.Code`, where `INVALID_ARGUMENT` maps to
HTTP 400. This campaign compiles REST bodies only, so it does not observe the
gRPC row; a gRPC boundary needs its own compiler and receipt.

The `emulator` profile keeps the refusal the local runtime answered before the
limits layer implemented this condition, HTTP 413 `request body too large` on
REST and tonic's own `OUT_OF_RANGE` on gRPC. The boundary is identical under both
profiles. That superseded baseline stays on the record, and the shadow keeps its
classification as a **regression** outcome: a strict-profile build answering 413
has lost the implemented shape.

The recorded run is published as
`spec/compatibility/broad-runs/fs-request-bytes-local-shadow.json`, at source
`31a5102c9d357a6b5349f364a3b84a37a21c6a35`, artifact SHA-256
`f493ac8bf8b4bf74642e65f3be97a24e745d16299fcdc3bafd141c01d2f6602e`, nonce `54e96c7d41094fa5928672d4adae6efe`, with supervisor status
`completed`, `recordingComplete` and `stateValidation` true, the owned process
stopped and all listeners closed. It completed 105 observation rows and 153
recovery rows, sent 241 of the 258 bounded requests, and proved all 51 owned
resources absent afterwards. The 17 unsent requests are the over probe's delete
slots, consumed as zero-wire skips because a refused Commit grants no cleanup
ownership. That is also the post-state evidence: the refused request wrote
nothing.

The record carries the three probe outcomes, the refusal bytes verbatim, the
collector summary, the runtime binding and the run's own nonce, so a reader can
recompute the plan and campaign digests rather than trust them. The recorded
classification and the two state gates are recomputed from the recorded
observation, so a hand-edited verdict fails the suite. The shadow uses its own
per-run nonce against `demo-firestore-probe`; it is not the campaign nonce and it
writes nothing to the oracle project.

The refusal shape is compared field by field. `BASELINE_COMPARISON_FIELDS` names
the HTTP status, the error code, the error status and the message, and a
classification that reports a match has compared all four. The collector records
the message alongside the response byte count and digest, so the message a
verdict rests on is the one that was on the wire rather than one recovered from a
sidecar. A refusal at the right boundary whose code, status or message differs
lists the differing fields in `refusalFieldMismatches`, keeps the run's recording
and recovery facts, and sets only `matchesBaseline` false.

The shadow recognises four local outcomes and masks none of them.
`local-shape-matches-production-expectation` is the baseline.
`local-boundary-enforced-shape-differs` is the lost-shape regression above.
`local-boundary-not-enforced` means the bound was removed or raised.
`local-untyped-transport-refusal` covers every complete refusal that is not the
typed over-boundary envelope, including a status outside 400 and 413 such as
500, 429 or 403. Those report `recordingComplete` false and `stateValidation`
true: nothing was written, and the boundary question is unanswered.
`shadow-failure` is not the bucket for an unfamiliar status. It is reached only
by a result the collector could not have produced, and it drives
`stateValidation` false so the supervisor run stays incomplete.

## Per-slot timings, as a floor

The O8 runner reserves a number of seconds for each of the 258 schedule slots.
The three boundary Commits are covered by the 60-second transport deadline
above. The other 255 are small reads and deletes, and nothing measured them.

Both transports now record `elapsedSeconds` on every receipt and the collector
copies it into each row, so every run measures its own slots. On the production
transport the figure spans the whole slot, including the worker process and the
connection, because that is what a reservation pays for. The published record
carries a summary under `slotTimings`, separately for the boundary Commits and
the small requests, with the median, p95, p99 and maximum. Slots consumed as
zero-wire skips are excluded, since they send nothing.

**The published figures are a floor and not an estimate, and the record says so
beside them.** A local shadow runs over loopback against an emulator on the same
machine. In the published run the small-request median is 0.0011 s with a p99 of 0.0115 s, and the
three boundary Commits ran 0.0249 s at the median. That is service time with no
network in it at all; a production small read is an HTTPS round trip and
will be one to two orders of magnitude higher. Citing the local p99 as a
production per-slot figure would be wrong by that margin. It bounds the
reservation from below and nothing more. A real figure needs a production run,
which the production transport can now record.

## Artifacts

- `spec/compatibility/fs-request-bytes-campaign.json`, the campaign artifact.
- `spec/compatibility/fs-request-bytes-cases.json`, the case and expectation view.
- `spec/compatibility/fs-request-bytes-budget.json`, the budget, accounting and cost view.
- `spec/compatibility/broad-runs/fs-request-bytes-local-shadow.json`, the local shadow receipt, including the loopback timing floor.
- `tools/compat-broad/fs-request-bytes-boundary/`, the compiler, collector,
  transports, campaign composer and local shadow.

## What this does not do

This preparation sends no production request, acquires no credential, holds no
reservation and grants no admission. It reduces production-unobserved
`FS-DATA-WRITE` closure conditions by **0**. `FS-DATA-WRITE` is not
`COMPAT_VERIFIED`.
