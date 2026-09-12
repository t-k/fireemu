# Second broad exploration

The local execution source is `63e270c73d7f52108fb96f9af14414084b821676`. No new production operation, permission, nonce, runtime modification, or production comparator change was made. The first46 results and all earlier evidence remain immutable. This is a candidate exploration result, not approval of a second production batch.

## Results and evidence boundaries

| Execution | Result | Evidence meaning |
| --- | --- | --- |
| New Auth update matrix | 32 safety passes; both accounts recovered | Local safety checks, production behavior unobserved |
| Additional historical Firestore programs | 126 matches, 2 mismatches, 2 indeterminate | Saved production comparison; the two differences do not establish runtime bugs |
| New Firestore boundary programs | 25 recorded steps across six programs; five applicable safety checks passed, one not applicable | Local observations with no invented production response expectation |
| First46 regression | 46 matches; recording and cleanup complete | Separate comparison against the pinned `ab7bd698` production observations |
| Rules access-budget programs | Six matches | Historical official Emulator reference (`firebase-tools`15.28.2), not production |
| SDK explicit Rules / listener replacement | Both scripts passed | Local SDK assertions; listener uses forced long polling |

The second Auth/Firestore process exited1 and `recordingComplete=false`: the two non-JSON Firestore rows are unusable under the existing recorder contract. Usable observations are retained, but the whole run is not promoted to complete. Independent cleanup verification confirmed the parent was absent, all registered listeners were closed, and Auth had no unrecovered accounts. Auth issued302 requests including8 recovery requests; the Firestore session guard counted185 requests including setup/reset work.

The incomplete parent manifest did not retain the temporary binary hash before removing the executable. The second result explicitly leaves `artifactSha256=null`; its frozen source, observer inputs, manifest, operation digests, historical reference, and original private observation hash are retained. A later binary hash is not substituted into this run. The separate first46 regression has its own recorded artifact hash. SDK/Rules used retained artifact `8e433fc24df9585573ce6a213152269de8d51a22d60b1800a4d0e62e0d15508e` from `ed90292a`; its bound runtime inputs were verified equal to the current checkout before use. These are different evidence grades.

Machine-readable records:

- [Second manifest](../../spec/compatibility/broad-second-candidate.json): explicit inputs and seed20260913, distinct from the first46 manifest.
- [Second observations](../../spec/compatibility/broad-runs/63e270c7-second-result.json): normalized Auth operations and A/B before/after state, Firestore comparisons, source and operation digests, incompleteness and cleanup.
- [First46 regression](../../spec/compatibility/broad-runs/63e270c7-first46-regression.json): pinned production and new local identifiers, unchanged original35/11 evidence, current46-match result.
- [Rules and SDK](../../spec/compatibility/broad-runs/63e270c7-local-rules-sdk.json): separate references, profiles, rules, selected programs, source hashes and outcomes.

## Added conditions

Auth varies the authenticated actor and `localId` independently: A/B self or foreign selection, missing selector, null, number, object and array. `displayName` covers missing/null/number/boolean/array/object. Normal display-name changes are mixed with five `emailVerified` shapes, four `customAttributes` shapes and two `disableUser` shapes. Missing/null/numeric/invalid credentials and two legitimate administrator controls are included. This is a selected32-case matrix, not a full Cartesian product.

Every diagnostic starts from distinct, verified A/B display-name sentinels and `emailVerified=false`; both accounts are read immediately before and after. Safety checks cover identity preservation, non-target preservation, refusal atomicity and protected-state preservation for clients. A200 response that ignores a field and a400 refusal may both satisfy safety; neither becomes a production expectation. Snapshot normalization removes absolute timestamps, so equality of these snapshots does not prove that internal token issuance or document versions were unchanged.

Firestore adds IN30/31 values, inclusive/exclusive prefix cursors, ancestor-overlapping update masks with substantive value changes, a stale `updateTime` delete after a successful write, an invalid transform field path, and500/501 transforms. Each program records a normal operation, diagnostic and before/after state (the stale-delete sequence also retains the original read). Locally, IN31, stale delete, invalid path and501 transforms were rejected; the overlapping mask was accepted. These exact responses remain production-unobserved. Refusal atomicity applies only after an actual refusal; the accepted mask receives no false refusal-safety pass. Query programs check state preservation.

The four additional saved-production programs are `queries/projection-and-listing`, `queries/collection-group`, `errors/rest-shapes` and `reads/read-time`. Their original operation sequences are reconstructed from the bound historical source, not matched solely by case ID. The pinned historical index configuration is retained. Standard Native REST administrator results do not establish user Rules, gRPC or SDK compatibility.

Rules adds access counts10/11/12/21, repeated access to one path and an11-access commit. The local SDK smoke checks dynamically loaded Firestore Rules for owner, other user and anonymous contexts; its Storage assertions are recorded separately. Listener replacement checks that a replacement listener receives the initial and subsequent update while the old subscription stays detached. It is a regression continuation, not new resume-token or reconnect coverage.

## Cause-level triage

| First divergent operation | Evidence and classification | Next action |
| --- | --- | --- |
| `queries/collection-group#partition-query` | Saved response is empty; local returns two partition points. A single response is insufficient to establish a fixed expected partition count. | Retain raw mismatch; next local check should reconstruct complete query results from returned cursor ranges without omissions or duplication. Do not force an empty runtime response. |
| `errors/rest-shapes#wrong-project` | Production403 specifically reports that the API is unavailable in `other-project`; local404 reports missing data. Environment prerequisites differ. | Keep environment-dependent difference; do not generalize it into an authorization change or invoke the other project. |
| `errors/rest-shapes#unknown-custom-method` and `#method-not-allowed` | Local404 non-JSON response cannot be compared by this recorder. | Keep both indeterminate and the run incomplete. A future bounded non-JSON recorder change requires separate review. |

The official [partitionQuery contract](https://docs.cloud.google.com/firestore/docs/reference/rest/v1/projects.databases.documents/partitionQuery) defines a maximum requested partition count and allows fewer results, including an empty result for small or unsupported queries. That supports treating the first row as unresolved behavior variability, not proof that either fixed result is universally correct. No confirmed new runtime gap or runtime fix was identified in this execution.

The previous193 historical matches,26 local checks,23 indeterminate rows and46 mapping checks are unchanged. The current transform20 comparison remains part of the separately retained first46 production comparison; it does not rewrite the older transform history. Revision3, GAP-AUTH-007 and AUTH-U03 remain independent investigations.

## Execution and verification

The common new entry is local-only:

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/second_cases.py --output "$NEW_PRIVATE_OUTPUT"
```

The actual run used the port-registry wrapper with service`fireemu-second-broad`, range24000–24999, TTL20m, and output ending`63e270c7-second`. It built the runtime with the existing owned runner. The source was frozen throughout execution and review. Its nonzero result is expected from the retained incomplete collection, not silently ignored.

Additional executed commands:

```sh
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/compat-broad -q
uv tool run ruff check tools/compat-broad/second_cases.py tools/compat-broad/test_second.py tools/compat-broad/broad.py
uv tool run ty check --python tools/compat-inventory/.venv --extra-search-path tools/compat-inventory tools/compat-broad/second_cases.py tools/compat-broad/test_second.py tools/compat-broad/broad.py
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_local.py --output "$FIRST46_PRIVATE_OUTPUT"
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_pair.py --saved-ab7bd698 --local "$FIRST46_PRIVATE_OUTPUT/batch/result.json" --output "$PAIR_RESULT" --check
```

The broad offline suite passed70 tests; Ruff and ty passed. Existing CI discovers the new tests through its unchanged `pytest tools/compat-broad` invocation. Lifetime CI and the four publisher checks were left unchanged; they were not rerun in this milestone. No Rust source changed; a runtime build and the actual local executions above ran, but the full workspace Rust test suite was not rerun.

Rules used the existing `conformance/src/rules-probe/session-programs.mjs` with the six selected inputs in the receipt and `tools/compat-broad/local-guard.mjs`. SDK used `tools/sdk-smoke/rules-unit-testing-explicit-rules.mjs` and `tools/sdk-smoke/listener-replacement.mjs` under the owned executable. The private wrappers only supplied ports, profiles, rules, cleanup and environment. Early wrapper failures preceded SDK execution: control-URL validation, dropped emulator variables and a disabled Hub (`--hub-port 0`). A reserved positive Hub port and explicit validated child environment resolved them. Both SDK scripts and all registered listeners then terminated successfully. These wrapper failures are retained privately and are not counted as runtime failures.

Auth local execution explicitly configures project`fireemu-35fe6` to number`592603257417`. Historical Firestore uses`demo-firestore-probe`. Rules uses`demo-rules-matrix`; SDK uses`demo-app` and a local worker project. These demo projects have an explicit empty `authProjectNumbers` map and retain the project-ID fallback; no oracle number is silently assigned to them.

## Review and next production candidate

Security review concentrated on target UID, administrator fields, failure side effects, collection completeness and owned cleanup. **Must Fix:** none outstanding. Two review findings were fixed before execution: unusable HTTP observations could count as complete, and cleanup failure could escape the exit code. Offline regressions cover both. **Should Fix:** none in the reviewed local-only change. **Notes:** the incomplete-run artifact-provenance limitation above remains explicit; no technical review is a production permission.

The second manifest is a local candidate, with `productionExecutable=false` and no inherited approval. Only the32 new Auth diagnostics and six new Firestore programs need new production observations; reusable historical rows are not automatically included. The existing production adapter and its first46 admission remain unchanged. Before seeking a single batch permission, the candidate still needs an explicit closed production manifest, ownership mapping and query/index-scope review, request/data-scan/cost/recovery bounds, frozen observer and comparison bindings, and a fresh owner-approved period and nonce. No current local safety response is embedded as the expected production output. There is no production execution request hidden in this publication.
