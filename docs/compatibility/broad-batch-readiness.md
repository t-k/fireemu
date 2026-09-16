# Initial 46 batch readiness

Execution source: `a32fa8a7fa9b2b3f4e286a3d8167723c8c26fcf0`. This milestone performs no new Firebase oracle operations and creates no owner permission. The [single execution-input package](../../spec/compatibility/broad-runs/a32fa8a7-execution-inputs.json) names the frozen commit, complete candidate, observer/manifest/comparison/projection hashes, budgets, cost assumptions, recovery policy and missing owner inputs. Execute from that frozen commit, not a later documentation-only publication commit.

## What is ready

- Database acquisition and configuration approval are separate. Full parsed-response hashes retain acquisition evidence; `database-settings-v1` excludes only `earliestVersionTime` from the approval projection. The same preflight function checks identity, edition, location and remaining settings before observations and after recovery.
- Adapter/local-wrapper failures propagate nonzero exit codes. A complete mismatch is an observation, while missing rows, collection failure or incomplete cleanup cannot become a successful comparison. Pair `--check` additionally requires equality.
- `batch_pair.py` compares the same 46 abstract operations across production/local namespace mappings. It binds actual principal, request method/path/query/body, the expected request for that row, and the versioned normalization implementation. Actual responses are recorded without forcing expected local outcomes. Private raw response journals survive response stop conditions; earlier Auth rows survive later failures.
- Offline preparation emits one unapproved package. Existing CI discovers the projection, exit and pair tests through the broad pytest step; the candidate/catalog checks and lifetime CI remain connected. No dedicated publisher, DSL or UI was added.

## Executed results and limits

| Evidence | Result | Interpretation |
| --- | --- | --- |
| Preserved historical production comparison | 193 matches | Unchanged past reference comparison; not rerun in this narrow milestone |
| Preserved new local checks | 26 pass | Still local invariants, without new production evidence |
| Preserved indeterminate comparison | 23 | Current transforms20, transaction response absence2, Auth non-JSON1 remain separately classified |
| Final owned mapped batch, run1 | 46 recorded; 46 mapping checks pass | New schema2 local recording; not a production comparison |
| Final owned mapped batch, run2 | 46 recorded | Independently built/copied artifact from the same frozen source and a different nonce |
| Pair CLI using two real local row sets plus explicitly synthetic production metadata | 46 match, check exit 0 | Input-fixture validation of namespace/normalization and comparison; no oracle result |
| Additional Rules local execution at 8e603145 | 4 programs, 12 matches to checked-in official-emulator references | REST Rules exploration only; not production, SDK, authenticated-principal or Listen coverage |
| Pytest at final frozen source | 165 passed, no failed/skipped tests | 49 broad tests plus 116 lifetime revision 1/2/3 tests |
| Isolated code mutations at final frozen source | Baseline16 tests pass; all 7 mutants killed | Projection, UID binding, incomplete recording, recovery, check-mode mismatch, query preservation, expected-operation validation |
| Finite models in the test suite | 32 recording/check states and 48 budget states | Bounded models of those contracts, not Firebase's whole state space |
| Existing lifetime publishers | All 4 checks pass | Run at 539f3404; publisher and lifetime source/subjects unchanged afterward |
| Independent final reviews | Must Fix: none; Should Fix: none | Technical review only, not owner execution permission |

Both final local batches sent 91 requests each: Auth 31 and Firestore 60, including 29 recovery requests; metadata 0. Both completed with zero unrecovered resources, exit 0, owned processes stopped and listeners closed. The first artifact SHA256 is `6298740eccf549c33852e202c4cfc938d0916a14b2d2bb42b52d26c311670eb7`; the second is `8ccfe86b290e52377f0e180f3a665eeeb20dc32b65155c077dafa9af2ab68fc9`. These are separately fixed copied binaries from the same source, not an assertion of reproducible binary builds. Build/input hashes, normalized observations, counts and process evidence are in [run1](../../spec/compatibility/broad-runs/a32fa8a7-local.json) and [run2](../../spec/compatibility/broad-runs/a32fa8a7-local-second.json). [Mapping results](../../spec/compatibility/broad-runs/a32fa8a7-mapping.json) and [pair input-fixture results](../../spec/compatibility/broad-runs/a32fa8a7-two-local-input-fixture.json) have distinct meanings.

No new confirmed runtime gap or runtime fix was produced. An independent review found that request normalization dropped query preconditions and allowed equal malformed operations on both sides; both were corrected before final verification. Two local runs exposed unmapped owned provider email fields; the normalizer now maps known email values, with password-provider `rawId` constrained to the supported provider paths. Unknown values, other owners/providers/paths and non-string values remain distinct. Comparator changes were reviewed separately from runtime behavior; no runtime expectations or production observations were changed.

The [additional Rules results](../../spec/compatibility/broad-runs/8e603145-rules-next.json) cover query limits, query resource constraints, create/update/delete method decisions and getAfter commits. They compare status/code/success shape with historical official-emulator references, without independently reconstructing the reference execution provenance. The `mirror-missing` step follows a commit that creates the mirror, so its success is not evidence that an absent mirror is allowed. Denied-write state readback, authenticated Rules, browser SDK, gRPC/Listen reconnect and stream ordering remain unverified here. Prior SDK/Listen local results are retained without promotion into production coverage. Revision3, GAP-AUTH-007 and TTL work remain independent prepared investigations.

## Remaining owner inputs

1. Current Database UID/edition/location/settings projection and its digest, plus the approved Auth configuration digest. No current metadata was fetched in this milestone.
2. Actual target location and applicable current tariffs, with a dated confirmation that they fit the manifest's planning ceilings. The approximately USD0.3052 estimate is an unverified conservative planning estimate, below the proposed USD1 cap; it is not a location-specific quote or billing guarantee.
3. Owner identity and permission reference, explicit approval of the bound request/resource/cost/recovery terms, issued/expiry times within the 24-hour admission window with enough recovery time, and an unused 32-hex nonce. These fields are `null`; no approval has been inferred from technical review.

The prepared input package is rejected as execution permission. A separate owner record must retain its binding fields and explicitly supply the missing values. The adapter checks a clean matching frozen checkout, then enforces the approved projection and API-key project ownership before data operations. Missing access or metadata, rejected credentials, uncertain ownership and budget exhaustion stop the run. Unrecovered resources remain in the private journal for separately scoped recovery. No IAM/configuration changes, new indexes, Rules changes, MFA, SMS or email delivery are included.

## Commands actually executed

Commands below ran in the compatibility worktree at the stated frozen source; output directories were private and outside the checkout. The two final local commands each build, copy, start, execute and stop their owned artifact.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/compat-broad tools/auth-pending-lifetime tools/auth-pending-lifetime-boundary tools/auth-pending-lifetime-window -q
uvx ruff check tools/compat-broad
uvx ty check tools/compat-broad --python tools/compat-inventory/.venv --extra-search-path tools/compat-inventory --output-format concise
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_local.py --output /Users/tk/work/firebase-emulator/docs.local/logs/2026-09-12/batch-pair-a32fa8a7-local
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_local.py --output /Users/tk/work/firebase-emulator/docs.local/logs/2026-09-12/batch-pair-a32fa8a7-local-second
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_comparison.py --batch /Users/tk/work/firebase-emulator/docs.local/logs/2026-09-12/batch-pair-a32fa8a7-local/batch/result.json --baseline spec/compatibility/broad-runs/bf12f631-expanded.json --output /Users/tk/work/firebase-emulator/docs.local/logs/2026-09-12/batch-a32fa8a7-mapping.json --check
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_adapter.py --manifest spec/compatibility/broad-batch-candidate.json --prepare-inputs /Users/tk/work/firebase-emulator/docs.local/logs/2026-09-12/batch-a32fa8a7-inputs.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_pair.py --production /Users/tk/work/firebase-emulator/docs.local/logs/2026-09-12/batch-a32fa8a7-production-input-fixture.json --local /Users/tk/work/firebase-emulator/docs.local/logs/2026-09-12/batch-pair-a32fa8a7-local-second/batch/result.json --output /Users/tk/work/firebase-emulator/docs.local/logs/2026-09-12/batch-a32fa8a7-two-local-input-fixture.json --check
uv run --project tools/compat-inventory --locked --python 3.12 /Users/tk/work/firebase-emulator/docs.local/logs/2026-09-12/batch-pair-mutations.py
```

The production-named input above is explicitly `fixtureOnly=true`: it copies local run1 rows and adds synthetic Database metadata solely to exercise the pair CLI. The original local reports remain unchanged and record `productionExecuted=false`. The original broad catalog and candidate checks were also run, as were `--check` on `publish-auth-pending-lifetime.py`, `publish-auth-pending-lifetime-comparison.py`, `publish-auth-pending-lifetime-boundary.py` and `publish-auth-pending-lifetime-boundary-comparison.py`. The separate Rules command and exact selected programs are recorded in its result manifest. Full Rust workspace tests were not rerun; runtime source was unchanged, and the owned artifact builds succeeded.

## Review record

Must Fix: none remaining. The query-erasure finding at 539f3404 was reproduced, then resolved and re-reviewed at f3137e94.

Should Fix: none remaining. Both-sided invalid request acceptance was resolved through independent expected-request binding. The final narrow rawId normalization delta was independently reviewed at a32fa8a7.

Notes: security review used an independent agent with a security-specialist perspective because the configured specialist profile file was unavailable. Review approval is technical only. Independent re-review ran 28 focused tests, and final delta review ran 11 pair tests plus direct preservation assertions. Local artifacts and raw response journals were not treated as production observations. The existing 193/26/23 evidence categories, prior 46 mapping result, revision 1/2 subjects and revision 3 preparation remain intact.
