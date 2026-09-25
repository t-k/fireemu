# Initial46 owner decision draft

Current status: API Keys API has now been enabled with owner authorization and its ENABLED state verified. The immediate key-ownership lookup still returned 403, so ownership remains unconfirmed. Successful Database/Auth acquisitions remain recorded and production execution remains unapproved.

The [single decision draft](../../spec/compatibility/broad-runs/a32fa8a7-owner-decision.json) references the immutable a32fa8a7 execution-input package and records the partial authorized metadata acquisition. It is not a production execution permission. Execution source remains a32fa8a7; b76b96b9 remains its original report publication, and subsequent input records do not replace either.

On 2026-09-12 at 13:57:52–13:57:54 UTC, one ADC acquisition and four HTTP requests were performed: tokeninfo 200, project 200, Database 200, Auth configuration 403. No automatic retry followed. API-key ownership was not requested because the Auth read failed and no approved key was available in the environment. No data or configuration mutation occurred. The acquisition stopped in 5.18 seconds, below the authorized 180-second bound.

Database identity was confirmed as project fireemu-35fe6/number 592603257417, database (default), us-central1, Standard Native. The draft contains its UID, full settings projection, acquisition timestamp, exact response-byte SHA256 and canonical parsed-response digest. The unchanged database-settings-v1 contract produced projection digest `1a067449eec406349580f171ae760ac33f5bc6ff0e0a53e00d26096da75e8fe8`. Auth's 403 response digest is refusal evidence, never an Auth configuration digest. Raw responses, especially tokeninfo, remain private.

## Pricing conditions

For the observed Iowa location, published Standard rates are USD 0.03/0.09/0.01 per 100,000 document reads/writes/deletes. Storage is USD 0.000205479/GiB-hour; the calculation conservatively budgets 744 hours. Two index-read batches and 3200 reads, 1600 writes, 200 deletes, 0.062622GiB-month storage and 0.146484GiB egress remain the manifest's limits. Using the maximum published destination egress rateUSD 0.23/GiB avoids assuming a free allowance or a particular destination. These rates are below the manifest's planning ceilings. [Firestore pricing](https://cloud.google.com/firestore/pricing)

Email/password Tier1's highest published paid rate is USD 0.0055/MAU; three users contribute at most USD 0.0165 at that rate, without free quota. [Identity Platform pricing](https://cloud.google.com/identity-platform/pricing)

The conditional total is approximately USD 0.06219 using those rates. The original planning estimate USD 0.30513 and proposed USD 1 cap remain unchanged. Overall tariff approval stays unset: the owner still needs to confirm applicable billing terms, the retrieved Auth configuration and absence of external integrations, and recovery of any retained resources within the stated horizon. The estimate does not cover indefinite unrecovered retention.

## First-window blocker and proposed follow-up

Auth returned a quota-project-required error for the current user ADC. Frozen a32fa8a7's direct REST transport does not supply `x-goog-user-project`. Google documents that this header explicitly selects the quota/billing project for APIs requiring it. [REST authentication](https://docs.cloud.google.com/docs/authentication/rest#user-credentials)

No other project's quota configuration was used, and neither ADC configuration nor IAM was changed. No frozen observer source or comparison contract was changed. A proposal for the two remaining metadata reads explicitly designates fireemu-35fe6 as quota project, retains the 180-second bound and no-retry policy, and remains unapproved. Successful reads alone would not authorize the 46-row production batch. If the frozen production transport needs a header change for these credentials, that small source delta requires its own review and explicit resolution of the frozen execution binding before use.

The production proposal remains 46 rows, three account attempts, eight documents, two queries over at most one owned document each, at most 2400 total requests, 1200 seconds including 300 recovery seconds/requests, and USD 1. Owner identity/reference, dates, unused nonce and production permission remain unset.

## Independent local progress

During the preceding permission wait, four existing gRPC Listen resume tests passed under nextest; 16 other stream tests were filter-skipped. They cover replay since a token, reset/target token rejection, retained versus compacted tokens and version-cap reset. These are local runtime assertions, not production or official-emulator comparisons. The test processes exited. Existing 193 historical matches, 26 local checks, 23 indeterminate comparisons, 46 mapping checks and earlier SDK/Rules/Listen observations retain their separate meanings.

No production-batch recording, cleanup or compatibility verdict exists for this draft. The partial metadata collection is incomplete; it must not be treated as a successful 46-row run.

## Additional authorized read window and current status

A separate 180-second window was explicitly authorized with `x-goog-user-project: fireemu-35fe6` on management requests. At 2026-09-12T14:07:48 UTC, one existing-ADC command and two direct HTTP requests ran: tokeninfo 200 and Auth configuration 200. The collector exited after 2.37 seconds. Project and Database were not reread. ADC's internal network traffic was not separately instrumented; the report distinguishes command invocations from directly issued HTTP requests. No persistent ADC/gcloud settings, IAM or oracle data were changed.

The helper incorrectly required `projects/fireemu-35fe6/config`; the valid response used `projects/592603257417/config`. This is a collection-side validation defect, not an Auth refusal or runtime compatibility gap. Execution stopped before the API-key lookup. No automatic retry or additional oracle request followed. Offline examination matched the response number to the already verified project and confirmed the successful response's canonical Auth digest as `7878eb2600c66f48c82ef55fb8c2443ab15689ea7542a77fbda206da06f817c2`. Its raw-byte digest is `b6e081a061371ee0b1bf4068f417a4274fce7650e768ae36dabf169acb3cae27`. This digest is from HTTP 200, not the earlier 403 response.

The retrieved configuration enables email/password and anonymous sign-in and lists no blocking triggers. Its existing API key is available in the private response, but independent key ownership is still unconfirmed. No token, key value, full Auth configuration or other private response was added to public evidence. The original acquisition report remains unchanged; a separate offline-validation record explains why the Auth body is valid despite the helper's stopped status.

The single decision JSON now combines the successful project/Database and Auth observations, price calculations, immutable source bindings and remaining gaps. It still has no production permission. The remaining metadata operation is one API-key ownership lookup, with fresh credential/expiry verification if separately authorized, without repeating successful project/Database/Auth reads. The prior window is closed rather than extended.

The successful quota-header request does not change frozen a32fa8a7's transport: it still lacks that header. Any necessary production-source delta must be narrowly reviewed and its execution binding explicitly resolved; a32fa8a7 must not be silently substituted. The 46-row batch, resource mutations, revision 3 and other production observations remain unexecuted.

## Final key-only read window: blocked by API availability

A new 180-second key-only window was explicitly authorized after the stopped helper run. At 2026-09-12T14:13:23–14:13:25 UTC, one existing-ADC command and two direct HTTP requests ran: tokeninfo 200 and API-key lookup 403. The management request specified `x-goog-user-project: fireemu-35fe6`. It used the existing key from the private successful Auth response and did not reread project, Database or Auth configuration. The run stopped after 2.7576 seconds.

The lookup returned `PERMISSION_DENIED`, stating that API Keys API had not been used in this project or was disabled. Its raw response hash `39519b2a17edecab25820250ab64c3139ebb0180ecabd66c0fd86fafd0637fcf` is refusal evidence, not ownership confirmation or a settings digest. No retries, API enablement, IAM changes, principal switch, persistent quota configuration or oracle data mutation followed. API-key ownership remains unconfirmed.

The [single decision draft](../../spec/compatibility/broad-runs/a32fa8a7-owner-decision.json) retains all three distinct read windows, successful Database/Auth baselines and hashes, pricing conditions, and this final blocker. All granted read windows have ended. API enablement is explicitly outside the granted scope and requires a separate owner decision; it is not implied by the API's error message. The unchanged frozen production adapter also still needs its quota-header execution binding resolved. Therefore the initial 46-row production batch is not ready for execution permission, and no production-batch recording/cleanup/compatibility result is claimed.


## Owner-authorized API enablement

The owner subsequently asked the assistant to enable the required API. Using the same ADC principal and request-level quota project fireemu-35fe6, one `services.enable` request enabled only `projects/592603257417/services/apikeys.googleapis.com`. One operation poll reported completion and an exact-service readback confirmed `ENABLED`. The operation followed the documented [Service Usage enable method](https://docs.cloud.google.com/service-usage/docs/reference/rest/v1/services/enable); no IAM grants or global credential/quota changes were made.

The action ran at 2026-09-12T14:20:41–14:20:47 UTC and stopped after 8.4051 seconds: one ADC command and five directly issued HTTP requests (tokeninfo, enable, operation poll, service-state readback, key lookup). The private response hashes and per-request quota project are in the single decision draft. Persistent ADC/gcloud configuration hashes were unchanged and the ADC principal matched the prior authorized reads. A narrow independent security review of this enablement scope had no Must Fix or Should Fix findings; it was not a repeated 46-row technical review.

The immediate API-key lookup still returned 403 with the prior API-not-used-or-disabled message. Propagation delay after enablement is possible but has not been established. No failed-request retry occurred, and ownership is not marked confirmed. Service enablement itself succeeded and was left enabled as requested; it was not rolled back because a later lookup remained unconfirmed. No account/document mutation, key creation/regeneration or 46-row production execution occurred. Frozen a32fa8a7 and its execution bindings remain unchanged.


## Post-enablement ownership confirmation

Following the owner's new execution instruction, one bounded key-ownership read completed successfully at 2026-09-12T14:23:29 UTC. The window took 2.8001 seconds, with one existing-ADC acquisition and two direct HTTP requests: tokeninfo 200 and API-key lookup 200. The lookup explicitly used quota project fireemu-35fe6 and confirmed the existing key belongs to project number 592603257417. Its raw-response SHA256 is `882e81125f2cd679a7cac6d30b27449dea81a209b81febbf549b492772568771`. No retries, additional API enablement, persistent credential changes or data mutations occurred. Earlier failures remain historical records; this success does not rewrite them.

Project, Database, Auth configuration and independent API-key ownership are now available in the single decision JSON. The original a32fa8a7 execution package remains immutable. A minimal replacement candidate is being prepared solely to supply and bind the explicit quota header required by the current ADC. Production permission is still absent; the ownership read is not a 46-row batch execution.


## Concrete quota-only execution replacement proposal

Proposed execution commit: `7be6cf08f1e9b1620eb0b7675b8352470b0968f5`. Its [execution input package](../../spec/compatibility/broad-runs/7be6cf08-execution-inputs.json) has observer SHA256 `dcab73c44e07152d21bd22897d18c296908bd2ab88b9eed4a31e41edffc60603`. This is an explicit replacement proposal, not owner approval or an alteration of the original a32fa8a7 package. The manifest, abstract operations, comparison contract and Database projection contract hashes are unchanged. The only transport change supplies `x-goog-user-project: fireemu-35fe6` for remote privileged requests; admission now requires that exact quota project. Local and client requests retain their headers. No ADC/global setting change is involved.

Verification: the broad offline suite passed50 tests; the post-format focused suite passed14 tests; Ruff lint and ty passed. A separate security review of only this delta reported no Must Fix or Should Fix findings. Review did not grant production permission. The previous local46 results remain bound to their old observer; a paired run using this candidate needs its own local result, and none is claimed yet. Lifetime suites, publishers and Rust builds were not repeated for this isolated quota delta.

One owner decision can cover the proposed replacement, the collected Database/Auth baselines, applicable billing conditions and the existing single-run envelope: fireemu-35fe6, Standard `(default)` in us-central1,46 rows,3 account attempts,8 documents,2400 requests maximum,4 sequential starts/second,1200 seconds including300 recovery seconds/requests, and USD1 maximum. Approval must identify the owner/reference and validity window; a fresh nonce is generated and bound before execution. These fields remain unset. There is no permission for automatic reruns, expanded scope, configuration changes or revision3. On approval, local and production execution use the same replacement observer; production preflight must still verify settings, expiry, bindings and the unused nonce before any data operation.


## Authorized7be6cf08 attempt: stopped before data operations

The owner subsequently replied “実行してOK” to the concrete replacement and single-run proposal. That message authorized7be6cf08 for one attempt. A private permission record bound the existing settings, pricing conditions, fixed observer/manifest, a fresh nonce and a one-hour validity window. The nonce was consumed by the adapter. No second attempt was made or remains authorized by that single-run permission.

The invocation exited2 after5.8963 seconds. It obtained one ADC token, verified expiry and issued five direct HTTP requests in total: tokeninfo, project/Database preflight, and the adapter's existing project/Database postflight. The budget counter is6 because it also reserves the credential command. ADC-internal network traffic was not separately instrumented. The postflight is the frozen adapter's final settings check, not a rerun of the data batch.

Both Database responses differed from the approved settings projection only in `etag`; all other retained fields were equal. The approved value was `INvzo7OZ6ZYDMODt3eb7z5YD`, observation value `ILi9sKGh6ZYDMODt3eb7z5YD`, and recovery value `INTxpaKh6ZYDMODt3eb7z5YD`. The contract excludes `earliestVersionTime` but retains `etag`, so admission correctly rejected these inputs under that frozen contract. This observation identifies a projection-contract investigation, not a runtime compatibility gap or proof of the cause of etag changes. No account/document operations or setting mutations were issued. Auth configuration and key ownership checks in this invocation were not reached.

The same fixed observer completed its local46 rows with91 requests (31 Auth,60 Firestore), including29 recovery requests, and no unrecovered resources. The owned process stopped and all recorded listeners closed. This remains local evidence, not46 production matches. The actual production/local comparison CLI exited2: `recordingComplete=false`, `cleanupComplete=true`, `compatibility=indeterminate`, with all46 production rows missing. Production cleanup is vacuous because no owned data creation was attempted; configuration equality remains unconfirmed.

The [execution candidate](../../spec/compatibility/broad-runs/7be6cf08-execution-result.json) records bindings, authorization provenance, observed projections, counts and private artifact hashes. The [comparison](../../spec/compatibility/broad-runs/7be6cf08-production-local-comparison.json) preserves missing rows. Private tokens, keys and full Auth bodies are not published. Prior193 historical matches,26 local invariants,23 indeterminate cases,46 mapping checks, and SDK/Rules/Listen results are unchanged and separate.

Actual entry points executed from the detached7be6cf08 checkout, with private paths abbreviated:

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_adapter.py --manifest spec/compatibility/broad-batch-candidate.json --approval <private>/approval.json --nonce <bound-nonce> --output <private>/production
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_local.py --output <private>/local
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_pair.py --production <private>/production/result.json --local <private>/local/batch/result.json --output <private>/comparison.json --check
```

The production launcher supplied the existing key only through the child environment and captured output privately. The local command ran under portctl; the artifact used OS-assigned ports and the existing ownership-aware shutdown checks. Its internal `cargo build --locked -p fireemu --message-format=json` succeeded. No new source modifications, lifetime suites, mutation campaigns, publishers or Rust regression suites were run in this execution-only step. Before another production proposal, review the meaning of etag and any narrow projection-contract correction offline. Do not update this attempt's expected baseline, suppress the mismatch or retry it automatically.


## Database settings v2: corrected proposal after07feab41

The projection over-bound volatile response metadata. The source fix is frozen at `bc38f392077784509f7fbb8993d5be66c1a8be14`. `database-settings-v2` excludes exactly `earliestVersionTime` and `etag` from settings equality. Complete saved responses and their full-response digests retain both fields. Name, UID, edition, location, settings, unknown fields and field presence/types remain compared. No document updateTime preconditions, concurrency logic, quota headers, independent API-key lookup, IAM, API enablement or runtime implementation changed.

The [separate offline reevaluation](../../spec/compatibility/broad-runs/bc38f392-database-reevaluation.json) uses the saved approval/preflight/postflight responses. Their settings digests differ under v1 and agree under v2. This is a settings-only reevaluation, not a successful old execution:07feab41 and the old approval/observation files remain unchanged, with0 production data rows and incomplete recording. An independent reviewer verified all three fixture bodies against the private saved sources and verified the raw/journal/full-response/v1 projection hashes. The committed fixture and tests also tie reevaluated hashes to the immutable published old evidence.

Validation passed61 broad tests, Ruff and ty. Negative cases change etag together with UID, name, edition, location, type, concurrency, delete protection, updateTime, an unknown field or boolean/numeric type; settings still differ. Two limited in-process contract mutations were killed: retaining etag and also excluding updateTime. No persistent source mutation or oracle call was used. The security delta review reported no Must Fix or Should Fix findings and grants no execution permission.

The new frozen observer completed its [local46 run](../../spec/compatibility/broad-runs/bc38f392-local.json):91 requests (31 Auth,60 Firestore), including29 recovery requests, no unrecovered resources, process stopped and listeners closed. The build and wrapper exited0. This record has the exact new observer and comparison contract for a future paired comparison. It is not a production comparison. Existing193 historical comparisons,26 local invariants,23 indeterminate cases and previous mapping/SDK/Rules/Listen evidence remain separate. No lifetime production observation or existing193-case production acquisition was repeated; this correction introduces no prerequisite for other local exploration.

The [new execution inputs](../../spec/compatibility/broad-runs/bc38f392-execution-inputs.json) and [single owner proposal](../../spec/compatibility/broad-runs/bc38f392-owner-decision.json) bind:

| Input | Value |
| --- | --- |
| Execution commit | `bc38f392077784509f7fbb8993d5be66c1a8be14` |
| Observer SHA256 | `1501aea61749d79d32238b9329f3d75370d9d500322ffab331ec0c8b3505342f` |
| Manifest SHA256, unchanged | `4b6d42bc5acd1a697622b25325ba67620af272d5c44f5d00982dbffe8bb8cc3f` |
| Comparison contract digest | `ec0ef13fc77b6edf0f4940f472267b91b117707b36aac15a00c0a6aea96e89dc` |
| Projection contract digest | `24b4847314fe67940a1e0e8eb53e34e2bd007ef2e1d942639b51564677d30f18` |
| Approved-response v2 settings candidate digest | `31957f98b7ec76e9c2e7a04803772f7270763a8ed62037fbdefa74c2c8f71d33` |
| Proposed unused nonce | `377db86cda534573b00d4422bd81db77` |

The same project fireemu-35fe6, `(default)` Standard Database in us-central1,46 rows,3 account attempts,8 documents,2400 requests maximum,4 sequential starts/second,1200 seconds including300 recovery seconds/requests and USD1 cap apply. The existing Auth baseline and independent key ownership evidence are carried forward as proposed inputs, with their original acquisition times. API Keys API remains enabled. Pricing evidence is reused with its recorded date; no unperformed new price or oracle check is claimed.

The requested new permission covers one preflight, one production batch, owned cleanup, postflight and comparison to this prepared local result, within a proposed one-hour window beginning at approval. Owner identity/reference and actual issued/expiry times remain unset until explicit approval. The old nonce and one-run permission are consumed and are not reused. Preflight must verify current settings against this candidate; it cannot adopt drift automatically. No automatic rerun, expanded resource budget or configuration changes are proposed.

Commands executed for this correction:

```sh
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/compat-broad -q
uv tool run ruff check tools/compat-broad/batch_contract.py tools/compat-broad/test_readiness.py
uv tool run ty check --python tools/compat-inventory/.venv tools/compat-broad/batch_contract.py tools/compat-broad/test_readiness.py
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_adapter.py --manifest spec/compatibility/broad-batch-candidate.json --prepare-inputs <private>/bc38f392-execution-inputs.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_local.py --output <private>/bc38f392-local
```

The local command ran under portctl with the existing owned-process wrapper and OS-assigned listener ports. Initial TDD execution failed on the expected v1/v2 contract difference; the final suite passed after the two-line production-contract correction. No full Rust regression suite, lifetime suite or publisher rerun was performed for this delta. Preparation/publication commits do not replace the stated frozen execution commit.


## Authorized bc38f392 production result

The owner replied “ok” to the v2 frozen proposal, including the one-hour window and proposed unused nonce. The adapter ran exactly once from detached `bc38f392077784509f7fbb8993d5be66c1a8be14`. The permission and nonce were consumed. Full authorization bindings and timings are in the [candidate execution receipt](../../spec/compatibility/broad-runs/bc38f392-execution-result.json); this receipt is not owner approval of the results. No automatic rerun, configuration update, IAM/API enablement action or baseline adoption occurred.

The invocation completed all46 rows in approximately84.7 seconds with exit0. `recordingComplete=true`, `cleanupComplete=true`, and `configurationUnchanged=true`. The budget counted101 operations, including one ADC acquisition reservation:31 Auth,60 Firestore,10 metadata;33 of these were recovery operations. Direct HTTP requests totaled100 (99 recorded service responses plus one tokeninfo); ADC-internal network traffic was not separately instrumented. Eight document targets and three attempted account emails were confirmed absent; two account creations had succeeded and the weak-password attempt had not created an account. No unrecovered resources remain. The frozen preflight/postflight confirmed the v2 Database projection, Auth digest and independent API-key membership. This invocation made no persistent settings changes.

The existing frozen comparator ran against the prepared bc38f392 local46 record: **35 matches and11 mismatches**, with no missing or indeterminate rows. Bindings were valid. Check mode exited1 because `compatibility=mismatch`; that is distinct from collection or cleanup failure. The [comparison JSON](../../spec/compatibility/broad-runs/bc38f392-production-local-comparison.json) and [normalized paired observations](../../spec/compatibility/broad-runs/bc38f392-paired-observations.json) preserve actual production responses, including refusals and unexpected success. No expected values or normalization rules were changed to improve the result.

The11 differing rows are not11 independent bugs. Initial triage identifies five overlapping cause groups:

| Cause candidate | First divergence and observed consequence | Scope and remaining work |
| --- | --- | --- |
| Firestore query error envelope | Negative limit returns400 INVALID_ARGUMENT on both sides; production returns an array containing an error, local returns an error object | Exact one-query input available; review the REST query envelope implementation |
| Auth client update input handling | With a valid token, production ignores client emailVerified and foreign localId selectors while applying displayName to the token owner; local rejects the requests | Two related input-handling branches; subsequent displayName differences inherit these divergences. Do not generalize to custom claims, MFA, OOB, or cross-account authority |
| Auth unauthenticated update error | Production INVALID_REQ_TYPE versus local MISSING_ID_TOKEN for displayName-only update | Exact input available; a route-specific code difference, not permission to relax authentication |
| Auth lookup lastRefreshAt | Production includes the field, local omits it; overlaps lookup rows already affected by displayName | Presence difference is separate; timestamp update semantics and independent minimization remain unknown |
| Refresh project identity | Production project_id is the numeric project number; local uses the project ID | Runtime source returns store.project_id(); investigate environment/model mapping before declaring or fixing a general rule. Never hard-code the oracle number |

The existing source inspection located the client update field/selector refusals and refresh project_id construction in `crates/fireemu-adapter-http/src/identity_toolkit.rs`. This execution step made no runtime fixes or new general semantic claims. The saved concrete inputs and first divergent operations support follow-up minimal regressions and narrow fixes; no additional production acquisition is automatically authorized. A security review is required before changing client update authorization behavior.

Actual execution entry points used private permission/key handling:

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_adapter.py --manifest spec/compatibility/broad-batch-candidate.json --approval <private>/approval.json --nonce 377db86cda534573b00d4422bd81db77 --output <private>/production
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_pair.py --production <private>/production/result.json --local <private>/bc38f392-local/batch/result.json --output <private>/comparison.json --check
```

No local server was started in this production-only step; the prepared local artifact's process and listeners were already stopped. No Rust tests, lifetime tests, publisher checks or new local46 rerun were needed or claimed here. The earlier07feab41 preflight stop remains incomplete, and the old193 historical matches,26 local checks,23 indeterminate cases and SDK/Rules/Listen evidence are not added to or relabeled by this46-row result. Revision3 and TTL investigations remain independent.

## Follow-up runtime corrections

The saved production batch is retained as comparison evidence. [Runtime fixes and the separate re-evaluation](initial46-runtime-fixes.md) record the five cause-level corrections, the fixed `ed90292a` local artifact and46 matches under the explicit new contract. This does not rewrite the original35/11 result or authorize another production execution.
