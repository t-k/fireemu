# Firestore request-byte boundary campaign preparation

Condition: `FS-LIMIT-API-REQUEST-BYTES`, scoped here to strict REST `Commit`
raw body bytes. This campaign now targets 11,534,336 bytes and the adjacent
11,534,337-byte refusal case. The catalog's 10,485,760-byte maximum remains in
force on other request surfaces. Parent: `FS-DATA-WRITE`. This document cites
preserved production evidence but sends no production request and promotes no
parent.

The new campaign artifact and O7 descriptor target the disposable
`fireemu-oracle-sbx/(default)` project. The saved production comparison cited
below is historical evidence from a different project, not a new observation
of the sandbox. It is used only for the concrete request-size/refusal comparison
and does not authorize or constitute a production send.

The limits catalog `spec/limits/firestore-standard-2026-08-25.json` records a
10,485,760-byte maximum for the general request surfaces covered by that
condition. Strict REST `Commit` has a separate 11,534,336-byte raw-body boundary
in this campaign; the limit must not be generalized to WebChannel or gRPC. The
preserved comparison in
[`fs-raw-request-bytes-3d7ceabb8-saved-comparison.json`](../../spec/compatibility/broad-runs/fs-raw-request-bytes-3d7ceabb8-saved-comparison.json)
records an accepted 11 MiB REST write with readback and a typed refusal at 11
MiB plus one byte with its target absent. It does not establish preservation of
the previously accepted document after the refusal or prove a generalized
decoded-byte metric.

## What the campaign observes

Three REST `Commit` requests against disjoint owned document sets, one probe at
a time, each probe fully cleaned up before the next one starts.

| Case | Request bytes | Relation to the limit | Production expectation |
| --- | ---: | ---: | --- |
| `FS-LIMIT-API-REQUEST-BYTES-UNDER` | 11,534,335 | one byte below | accepted |
| `FS-LIMIT-API-REQUEST-BYTES-EXACT` | 11,534,336 | exactly the limit | accepted |
| `FS-LIMIT-API-REQUEST-BYTES-OVER` | 11,534,337 | one byte above | refused |

The measured quantity is the raw REST HTTP body in compact UTF-8 bytes,
including JSON syntax. URL and header bytes are outside it. The saved production
comparison supports the exact 11 MiB and 11 MiB-plus-one cases in its concrete
recipes; the broader claim that this metric governs other REST recipes remains
an **observation hypothesis**. The campaign says nothing about gRPC, where
protobuf encoding is a different quantity.

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
| Data HTTP requests | 258 | 258 |
| Production management requests | 7 | 7 |
| Total production HTTP requests | 265 | 265 |
| Peak coexisting documents | 17 | 17 |
| Cost, USD | 0.00019 | 0.000224 |

An unexpectedly accepted over-boundary Commit creates 17 more documents and
recovers all 51. The collector already does that correctly; the budget now pays
for it. Two figures deliberately do not rise with the outcome. Peak coexisting
documents stays at one probe's set, because each probe is cleaned up before the
next begins. The request count is fixed by the schedule, because a refused
probe's delete slots are consumed as zero-wire skips rather than saved.

The local 258 bound is four reads and one delete slot per owned resource plus one
Commit per probe. Production adds one OAuth tokeninfo call, three metadata reads
before data and three metadata reads after cleanup. Every one of the eight
accept/refuse combinations of the three probes fits inside the published data
maxima, which the validator checks rather than asserts.

The hard ceiling is 0.50 USD and must clear the maximum, not the forecast. The
network component is zero to the published precision: about 33 MiB is uploaded
and ingress is not billed, and under 1 MiB is returned. The 33 MiB upload is the
unusual quantity here, not the money.

The recovery window reserves 550 seconds, 102 reads and 51 delete slots inside a
1150-second run. The reserve is sized by the maximum, not the forecast: 51
deletes for every document the worst outcome creates, and two reads per owned
resource for an ownership read and an absence proof. The validator enforces
both, and enforces that the hard ceiling clears the maximum cost rather than the
forecast.

The seconds are what the shared Gate charges, computed by calling it rather than
by re-deriving its formula. `shared_gate` charges each slot its own reserved
seconds plus an interval with a floor of 0.25, requires a slot carrying a body to
reserve the transport ceiling, refuses a wall above 1200 seconds, and refuses a
recovery reservation that cannot pay for its slots. The Gate reserves three
seconds for a small request:

| Phase | Slots | Reserved |
| --- | ---: | ---: |
| observation, small reads | 102 | 331.50 s |
| observation, boundary Commits | 3 | 180.75 s |
| recovery | 153 | 497.25 s |
| management, before data | 4 | 53.00 s |
| management, after cleanup | 3 | 39.75 s |
| **data total** | **258** | **1009.50 s** |

So the recovery data reserve is 550 against 497.25 needed, and the observation
phase has 53 seconds of management overhead inside its 600-second window. The
full wall is 1150, inside the Gate's 1200 cap. The earlier published pair, 300 and
900, could not carry this: 300 seconds admits at most 1.71 seconds a recovery
slot, and at two seconds the recovery phase alone needs 344.25. That figure was
never stated in the artifact, which is how the published windows and the
runner's reservation came to disagree. The arithmetic is now computed in
`budget.schedulingReservation` by calling the Gate, and a test drives
`shared_gate.create` on this campaign's schedule to prove it admits the published
windows and refuses 900/300, 900/500 and 1100/300.

The enforced small GET and DELETE transport cap is 2.5 seconds total. It covers
plan preparation, conservative pre-dispatch work, worker startup and the network
exchange, including response handling. The runner clamps the effective phase
deadline before dispatch, so a request that starts close to the observation or
recovery boundary cannot spend the next phase's time. The three-second Gate
reservation remains larger than this cap to pay for the conservative slot and
the Gate interval; the reservation and the transport timeout are deliberately
separate quantities. The boundary Commits keep the 60-second transport deadline.

At the enforced 2.5-second cap, 153 recovery slots plus their 0.25-second
interval consume 420.75 seconds, leaving a nominal 79.25-second margin inside
the 550-second recovery reserve before the 39.75 seconds of post-cleanup
management calls. This is a planning margin, not a mathematical
full-cleanup guarantee. If cleanup cannot complete, the run retains ownership,
records unresolved resources and fails closed for owner recovery; it does not
silently release ownership or widen the scope.

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

## Local shadow, and preserved observations

The retained local shadow at
`spec/compatibility/broad-runs/fs-request-bytes-local-shadow.json` is historical:
it ran the former 10 MiB triplet at source commit `b57cb0496`. Its recorded
outcomes and 10 MiB refusal message are preserved as observed; they do not
describe the new 11 MiB input. The current source-bound local result is published
separately at
`spec/compatibility/broad-runs/fs-request-bytes-local-shadow-11mib.json`; it was
run against the committed compiler and local transport inputs at 11,534,335,
11,534,336 and 11,534,337 bytes. Both records remain immutable and distinct.

The current strict REST `:commit` path uses
`MAX_STRICT_COMMIT_RAW_BYTES = 11 * 1024 * 1024`; `API_REQUEST_BYTES` remains 10
MiB for the other surfaces. The unit and loopback transport tests exercise the
new boundary input and 60-second admission ceiling. These local checks do not
create production evidence and do not change the general limits catalog.

The saved production comparison cited above is existing evidence from
`fireemu-35fe6`, not a new production run or a new sandbox observation. It
records the accepted 11 MiB recipe and the typed 400
`INVALID_ARGUMENT` refusal at 11 MiB plus one byte, with the refused target
absent. It did not read the earlier accepted target after the later refusal, so
preservation of that target remains unproven. Its concrete REST recipes do not
establish decoded request-byte behavior or behavior on gRPC, WebChannel, or other
REST operations.

The historical local gRPC refusal row remains 10 MiB: code 3,
`INVALID_ARGUMENT`, with the message `Request payload size exceeds the limit:
10485760 bytes.` That separate observation is not changed by this REST-only
campaign.

The `emulator` profile keeps the refusal the local runtime answered before the
limits layer implemented this condition, HTTP 413 `request body too large` on
REST and tonic's own `OUT_OF_RANGE` on gRPC. The boundary is identical under both
profiles. That superseded baseline stays on the record, and the shadow keeps its
classification as a **regression** outcome: a strict-profile build answering 413
has lost the implemented shape.

<!-- BEGIN generated evidence citation -->

The recorded run is published as
`spec/compatibility/broad-runs/fs-request-bytes-local-shadow-11mib.json`, at source
`db925e4cf6ac974cd5558bde40c48e6380133c8d`, artifact SHA-256
`f60429291f02d6608adfc2f4da7a1d3698c77a96519079e1d09d5112a1be780a`, nonce `232d7c54140c40209ee0330a4400dc3c`.

| Property | Value |
| --- | --- |
| Supervisor status | `completed` |
| Classification | `local-shape-matches-production-expectation` |
| Recording complete | true |
| State validation | true |
| Observation rows | 105 |
| Recovery rows | 153 |
| Requests sent | 241 |
| Every owned resource absent | true |
| Small-request median, p99 | 0.0014 s, 0.0212 s |
| Boundary Commit median | 0.0375 s |

The timings are a loopback floor, not a production estimate; see the
section above. This block is generated from the record, so it cannot
describe a run that is not the published one. Regenerate it with the
command in the lane README.

<!-- END generated evidence citation -->

The record carries the three probe outcomes, the refusal bytes verbatim, the
collector summary, the runtime binding and the run's own nonce, so a reader can
recompute the plan and campaign digests rather than trust them. The recorded
classification and the two state gates are recomputed from the recorded
observation, so a hand-edited verdict fails the suite. The shadow uses its own
per-run nonce against `demo-firestore-probe`; it is not the campaign nonce and it
writes nothing to the oracle project.

A refusal message is bounded where it is published. Production may answer with
a message up to the 2 MiB response cap, while the run's final result is written
under a 128 KiB limit, so the full text stays in the response sidecar and the
result carries its length, its SHA-256, a truncation flag and the sidecar
reference alongside a bounded excerpt. The excerpt is never published under the
`message` key, because a reader finding that key is entitled to treat it as the
whole text. When the message is truncated the comparison moves to the digest, so
a message whose opening bytes match the expected one exactly is still recorded
as a difference. Without this a long message completed every request and proved
every resource absent, and then lost the entire run at the moment of writing the
result.

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
above. The other 255 are small reads and deletes. The Gate reserves three
seconds for each of them, while the transport enforces the 2.5-second total cap
described above. The cap includes preparation and worker/network time, so an
individual wire exchange does not receive the full 2.5 seconds independently.

Both transports now record `elapsedSeconds` on every receipt and the collector
copies it into each row, so every run measures its own slots. On the production
transport the figure spans the whole slot, including the worker process and the
connection, because that is what a reservation pays for. The published record
carries a summary under `slotTimings`, separately for the boundary Commits and
the small requests, with the median, p95, p99 and maximum. Slots consumed as
zero-wire skips are excluded, since they send nothing.

**The published figures are a floor and not an estimate, and the record says so
beside them.** A local shadow runs over loopback against an emulator on the same
machine. The current published b57 run records a small-request median of 0.0012
s with a p99 of 0.0135 s, and the three boundary Commits ran 0.0269 s at the
median. The earlier 1157/e064 run recorded 0.0016 s, 0.0184 s and 0.0350 s at
the corresponding points; those are historical point-in-time figures, not the
current published run. All of these are service times with no network in them at
all; a production small read is an HTTPS round trip and will be one to two
orders of magnitude higher. Citing a local p99 as a production per-slot figure
would be wrong by that margin. It bounds the reservation from below and nothing
more. No production observation or mathematical cleanup guarantee is claimed
here; a real figure needs a production run, which the production transport can
now record.

## Artifacts

- `spec/compatibility/fs-request-bytes-campaign.json`, the campaign artifact.
- `spec/compatibility/fs-request-bytes-cases.json`, the case and expectation view.
- `spec/compatibility/fs-request-bytes-budget.json`, the budget, accounting and cost view.
- `spec/compatibility/broad-runs/fs-request-bytes-local-shadow-11mib.json`, the current source-bound local shadow receipt, including the loopback timing floor.
- `spec/compatibility/broad-runs/fs-request-bytes-local-shadow.json`, the preserved historical 10 MiB receipt.
- `tools/compat-broad/fs-request-bytes-boundary/`, the compiler, collector,
  transports, campaign composer and local shadow.

## What this does not do

This preparation sends no production request, acquires no credential, holds no
reservation and grants no admission. It reduces production-unobserved
`FS-DATA-WRITE` closure conditions by **0**. `FS-DATA-WRITE` is not
`COMPAT_VERIFIED`.
