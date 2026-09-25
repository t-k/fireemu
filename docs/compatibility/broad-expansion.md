# Broader historical comparison and prepared first production batch

No new Firebase production operation was performed. The historical comparison now covers 193 matching rows, up from 106; 26 local invariant checks remain separate, and 23 rows remain indeterminate. The new mapped adapter completed all 46 candidate diagnostics on an owned local artifact and recovered every journaled resource. No new runtime implementation gap was confirmed. Lifetime revision 3 remains a prepared independent investigation; GAP-AUTH-007 and AUTH-U03 remain open.

## Added comparison scope

The expanded historical replay ran at `bf12f6312f52d1009e85db3f1572b3a913b9ac64`, using artifact SHA256 `4f534f6f2ce0e0a94892fe8e8e302346901152834db93ee89671d4c5813305dc`. It reused the original Auth and Firestore production matrices, reconstructed their operation digests, retained the existing session normalization, and loaded the exact historical Firestore index file. The [complete execution manifest](../../spec/compatibility/broad-runs/bf12f631-expanded.json) preserves every current operation and result.

| Additional program | Newly comparable matches | Conditions |
| --- | ---: | --- |
| Historical `writes/transforms` | 18 | Execute the original historical sequence in a separate session/result identity |
| `values/type-order` | 6 | Existing seeded Firestore types and ordering |
| `values/numeric-ties` | 10 | Numeric equality/order boundaries from the saved corpus |
| `queries/filters` | 30 | Existing supported/refused filter combinations and returned document sets |
| `queries/aggregations` | 23 | Existing count/sum/average and validation cases |
| Total added | 87 | Current local execution against usable historical references |

The old transform sequence has 18 steps; the changed current sequence has 20. All 18 old steps matched. The current 20 steps remain independently executed, production-unobserved candidates. No old result was attached to a different operation under the same case ID. The catalog now explicitly lists both execution variants.

The expanded run contains 193 historical matches, 26 local passes and 23 indeterminate rows, with no comparable mismatch or failed invariant. The remaining groups are 20 current transform steps without corresponding production input, two transaction writes without usable responses, and one non-JSON response for an unknown Auth method. The transaction rows are retained for a dedicated contention investigation and excluded from the candidate production batch. Non-JSON response recording remains a separate extension candidate. Neither uncertainty blocks the new ordinary data cases.

The earlier missing-index harness mismatch remains preserved in the first milestone's triage. This expansion found no additional cause requiring a runtime patch or a changed expected response. Historical normalization still loses some identifiers, time and token relationships; 193 matches do not establish whole-service compatibility or current production behavior.

## SDK, Rules and Listen local execution

The same `bf12f631` binary also ran existing `tools/sdk-smoke/client.mjs` and `listener-replacement.mjs` in separate disposable instances. The client script passed all nine checks: anonymous protected/public access, own-profile write/read, another-profile refusal, owner-note creation, wrong-owner refusal, owner-filtered query, denied delete and protected access after sign-out. The listener script observed its expected initial and replacement/update histories. [SDK results and source hashes](../../spec/compatibility/broad-runs/bf12f631-sdk.json) retain these separately from production-reference matches.

These are real Node Firebase SDK checks, with gRPC visible in the client logs. The listener's requested long-polling option does not establish browser WebChannel coverage. The exact callback histories are the existing smoke test's assertions, not a universal ordering rule for concurrent streams. No production Rules, SDK or Listen comparison is claimed. The rules/program assets also have official-emulator references, but that separate REST Rules corpus was inventoried rather than executed in this milestone. Storage/Functions-dependent Rules fixtures, browser reconnect tests, Enterprise and MongoDB remain unexecuted.

The SDK lockfile was installed with `npm ci --ignore-scripts --no-audit --no-fund` in `tools/sdk-smoke`; no lockfile or dependency version was changed. The owned supervisor copied and hash-checked the binary, gave each command a 70-second outer deadline, captured its output and waited for exit. Both commands exited with code 0. The effective commands were:

```sh
"$FIREEMU_BIN" exec --config tools/sdk-smoke/fireemu.smoke.json --project demo-app --only auth,firestore --firestore-port 0 --http-port 0 --hub-port 0 --ui-port 0 --logging-port 0 --log-verbosity silent -- node tools/sdk-smoke/client.mjs
"$FIREEMU_BIN" exec --config /absolute/private/listen.json --project demo-app --only auth,firestore --firestore-port 0 --http-port 0 --hub-port 0 --ui-port 0 --logging-port 0 --log-verbosity silent -- node tools/sdk-smoke/listener-replacement.mjs
```

The listener config selects strict Standard Native and a private `rules.source` file containing only `allow read, write: if true` for `/listener-replacement/{id}`. It is isolated from the client script's principal-specific Rules and all other experiments. No shared Rules configuration was changed.

## Prepared batch and actual mapping validation

The [closed candidate manifest](../../spec/compatibility/broad-batch-candidate.json) contains 19 Auth checks, seven new Firestore checks and the 20 current transform diagnostics. It permits at most three account attempts and eight document targets. It is not a production observation or approval. The [execution envelope](broad-production-envelope.md) explains its narrower allowed subset and remaining owner inputs.

`batch_adapter.py` performs explicit operations instead of invoking the legacy production sessions. The two Firestore programs retain their original collection IDs beneath separate random run parents; the query URL changes parent while `from.collectionId`, limits and operation order remain intact. The only two queries scan a direct collection containing at most one owned document. Collection-group queries, composite-index-dependent expanded query cases, transactions, Rules changes and broad reset/recursive deletion are excluded.

Auth reuses the same scenario through an injected admission-controlled call boundary. Fresh runtime UID/token values are captured, every attempted email is journaled before creation, and privileged account changes verify the exact journaled UID/email pair. Nonce emails and document paths are ownership evidence bound to a private append-only journal; they are not described as immutable server account fields. Unknown creation ownership remains unrecovered rather than authorizing speculative deletion.

The final mapped execution ran at `0a7a55ce8531b696658ac9c17b5ab26ab10273e1`, artifact SHA256 `918381fb5f2358ee6fea4763170464885426f63f9215eea8a23ccfb9e3ad2c07`. It completed 46 rows, used 91 requests/reservations (31 Auth, 60 Firestore, including 29 recovery requests), and reported zero unrecovered resources. The owned parent stopped and all recorded listeners closed. [Full mapped execution](../../spec/compatibility/broad-runs/0a7a55ce-mapped-batch.json) and [46-row local mapping comparison](../../spec/compatibility/broad-runs/0a7a55ce-mapping-comparison.json) are preserved.

The 20 mapped transforms matched the same current local abstract sequence; seven Firestore and 19 Auth invariants passed. This is not 46 additional production matches. The mapping comparator verifies whole-program input identity and the baseline normalizer digest, preserves response types/fields/order and foreign resource names, and labels its output `productionComparison: false`. The two executions use identical runtime source inputs but separately built binaries; the manifests retain their distinct artifact hashes.

The production branch was not run: ADC acquisition, tokeninfo, remote metadata and API-key project lookup, production tariff verification and production recovery are unobserved. Local tests exercise admission/state logic and real bounded HTTP/process behavior; they do not impersonate those production services. The default CLI and CI command only validate the manifest offline.

## Validation and review

The combined suite passed 149 tests at `0a7a55ce`, including 33 broad tests and the existing 116 lifetime tests. The later test-only commit strengthened the existing payload-binding and total-deadline regressions; all 13 batch tests passed again before mutation. The 48-case finite phase/request-budget model passed. Seven source mutants were killed after a passing unchanged copied baseline: administrator-refusal latch, failed-credential reuse, expiry reservation, recovery deadline, candidate input binding, whole-request watchdog and response-size bound. The first mutation pass exposed an insufficient payload-edit test; the test was strengthened before the successful final pass. This is a bounded safety model, not verification of Firebase's full state space.

Ruff, formatting, ty, catalog/history binding, candidate validation and actionlint passed. All four existing lifetime publishers passed `--check` with unchanged subjects. Compatibility CI now includes the batch tests via the broad suite and the offline candidate check, alongside lifetime revisions 1/2/3 and their existing publishers. GitHub CI completion is not asserted here. No full workspace Rust nextest run was performed; there is no runtime Rust change.

Executed verification and reproduction commands include:

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/broad.py --run --output /absolute/private/new-expanded-run
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_local.py --output /absolute/private/new-mapped-batch
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_comparison.py --batch /absolute/private/new-mapped-batch/batch/result.json --baseline spec/compatibility/broad-runs/bf12f631-expanded.json --output /absolute/private/mapping-comparison.json
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/compat-broad tools/auth-pending-lifetime tools/auth-pending-lifetime-boundary tools/auth-pending-lifetime-window -q
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/broad.py --check-catalog
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_adapter.py --manifest spec/compatibility/broad-batch-candidate.json
```

Private output paths above are placeholders for fresh owned directories. Execution SHA, exact source hashes, configuration and inputs are in the linked manifests; the recorded runs are not automatically promoted to later documentation/test commits.

Security review covered the frozen implementation through `0a7a55ce`, including the new mapping comparator separately from runtime behavior. The configured Security Specialist profile file was unavailable; the independent reviewer applied the requested security perspective without claiming to load it.

- Must Fix: none remaining. The initial P1 allowed privileged HTTP401/403 to continue with the rejected credential. The fixed path latches failure immediately and leaves cleanup resources unconfirmed. Real HTTP401/403 regressions assert one transport request, no refresh, incomplete status and retained ownership records; intended unprivileged refusals remain distinct.
- Should Fix: none identified in the scoped final review.
- Notes: review approval is technical only. No owner permission, production result acceptance or revision 3 execution authorization is implied. Current tariffs and approved metadata baselines still need an owner's execution decision.

[Cause-level triage and mutation results](../../spec/compatibility/broad-runs/expansion-triage.json) retain the resolved adapter issue and the remaining investigation units. Further exploration can use the expanded references, while production preparation advances independently of the transaction, non-JSON and MFA investigations.
