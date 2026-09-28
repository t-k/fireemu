# FS-TRANSACTION: native idle candidates and provisional local policy

Status: **recorded partial evidence**. The [saved comparison](../../spec/compatibility/broad-runs/fs-transaction-p10-idle-candidate-comparison-v1.json) binds two equal native production projections to a fresh source-bound local artifact. The parent remains IMPLEMENTING, its denominator remains eighteen conditions, and closure review remains PENDING. This evidence grants no production permission.

## Recorded observations

Both production recordings returned OK for all seven native cases. The control requested 55 seconds; three candidate waits requested 65 seconds. The measured native idle intervals for the recipes with 65 seconds of requested idle were approximately 65.4–67.9 seconds. Earlier independent REST recordings accepted their control with 20 seconds of requested idle and refused their recipe with 70 seconds of requested idle after measured waits of approximately 70.00 seconds. These separated samples do not identify an exact shared or transport-specific server expiry boundary.

The successful Get in the case named `retry-after-expiry-touch` did not prove that its production token was expired. Its later retry follows an ordinary successful read and rollback. The repair preserves refusal of genuinely Finished predecessors.

## Local comparison

The new artifact was built from signed source commit `ff4024b8f066e18277834fa82a58059b01f9bc4d`, with artifact SHA-256 `1e45a2c3ddcaf2157bb1d03ada21a0eceb8c89c56bfdf7141054db7938ad47bf` and 444 hashed runtime inputs. Both profiles use identical artifact bytes. Only the declared project namespace is normalized for comparison; wall-clock and controlled-clock provenance remain distinct. Codes, diagnostics and post-state are retained.

| Case | Production, both recordings | New strict | New emulator |
| --- | --- | --- | --- |
| `commit-before-idle` | OK | OK | OK |
| `commit-after-idle` | OK | OK | ABORTED |
| `rollback-first-after-idle` | OK | OK | OK |
| `retry-after-rollback-first` | OK | OK | INVALID_ARGUMENT |
| `get-first-after-idle` | OK | OK | ABORTED |
| `rollback-after-expiry-touch` | OK | OK | OK |
| `retry-after-expiry-touch` | OK | OK | INVALID_ARGUMENT |

Strict matches the complete saved native projection after the declared namespace normalization and provenance distinction. Emulator retains its nominal idle policy of 60 seconds. The pinned official Firestore emulator 1.22.0 transaction-manager bytecode implements idle 60 seconds for ordinary IDLE transactions and total 270 seconds; that source evidence supports retaining the emulator duration, while public first-expiry error mapping, equality and ACTIVE/COMMIT state behavior remain separate unverified boundaries. Fireemu's emulator profile is not a wire observation of the official emulator.

The private controlled-clock counterpart invokes ordinary maintenance on every advance. The repair changes the shared deadline used by admission bookkeeping, pruning, reads, Commit and retention; it does not suppress maintenance. Strict uses a delegated provisional implementation allowance of 10 seconds after the nominal catalogue value of 60 seconds. The resulting local cutoff of 70 seconds is an implementation choice, not a measured server threshold or a proven conservative upper bound. The total deadline of 270 seconds and bounded retry lineage remain independent.

Both profiles also passed the same-instance REST success at 20 seconds and refusal at 70 seconds probe, the retained REST replay of 13 cases against both saved recordings, and the P09 native predecessor replay. Local processes exited normally and the observed owned documents were proved absent. These are bounded regressions on this artifact, not final-artifact closure across the remaining corpus.

## Verification and remaining obligations

Four recorded-candidate regressions first failed on the prior runtime. The repair was checked with direct operations and preceding maintenance. A separate controlled-clock matrix at 69/70/71 seconds protects the provisional local policy without asserting production equality. Six relevant semantic mutations were detected, including upward allowance drift, premature pruning, total-budget relaxation and overbroad Finished retry. Existing later-expiry, lock-release and 269/271 total-budget obligations remain covered.

The workspace profile-pr gate passed 3461 tests; after the descriptive compiled-catalogue note synchronization, the affected core/limits suite passed 349 tests, clippy passed, fourteen Quint models were regenerated, the evidence contract passed, and the three pinned Quint Connect tests passed. Those models verify their existing state-machine properties, not a numerical production idle theorem. Traceability retains its three pre-existing pending artifacts. Two unrelated catalogue-note generation differences remain unchanged from the base and are outside this repair.

P10 adds partial native evidence for idle candidate and RPC-order behavior, and ordinary retry lineage. Exact expiry requires P10-B. Native held-writer progress, the separate wall-clock contention lease, the rejected-commit/rollback chain, the total-lifetime production corpus, the official emulator profile gate, one final artifact across all required recipes and the eighteen-condition closure review remain open. No condition or parent is promoted.
