# Local expansion after the second broad milestone

The frozen integration execution is `a12183a0e3f872818284fb8420fd35a912a5a02a`. This session made no Google Cloud/Firebase operation, including authentication or metadata reads. Runtime source, the original production35-match/11-mismatch record, the later first46 matches, the old193/26/23/mapping evidence, and the incomplete `63e270c7` run remain unchanged. In particular, no new hash was inserted into that old incomplete run.

## Actual outcomes

| Scope | Outcome | Meaning |
| --- | --- | --- |
| Current second Auth32 | 32 safety passes,302 Auth requests including8 recovery | Local safety, not new production compatibility |
| Current additional historical Firestore | 126 matches,2 mismatches,2 indeterminate;185 session requests including setup | JSON-only comparison to pinned saved production; non-JSON receipt is now complete |
| Current six new Firestore programs | 25 received responses; five applicable state invariants passed, one not applicable | New response expectations remain production-unobserved |
| First46 regression | 46 matches, recording/cleanup complete | Separate comparison against pinned `ab7bd698` observations |
| Partition reconstruction | 30 conditions passed,168 requests; six conditions exercised multiple pages | Local semantic invariant, not fixed partition-count parity |
| Additional verified/anonymous Auth | Eight cases passed,96 requests including11 recovery,24.57 seconds | Signed local principals and preserved account state; production-unobserved |
| Additional Rules SDK | Six refused mutations with unchanged server-read state, followed by successful owner update/delete | Real SDK against local Rules with mock authenticated contexts; not signed Auth or production parity |

The current second run exited0 with `recordingComplete=true` and separately verified cleanup. Its two404 non-JSON responses remain **comparison-indeterminate**, because the historical record cannot establish a compatible body contract. The two raw mismatches also remain visible: partition-point count varies, and the wrong-project production403 describes API availability while the local404 describes missing data. Neither became a confirmed runtime gap. No runtime patch was made.

The partition invariant compares full documents, order and identity occurrence counts before and after all range reads. It covers0/1/2/9/41 documents, requested partition counts1/2/7 and page sizes1/3. All pages are consumed and cursors merged before range queries; the data is not changed between the whole-query and range-query reads. The smallest datasets and the multiple-page cases are retained in the result. Passing these checks does not erase the historical partition-count mismatch or prove behavior for arbitrary query shapes.

The eight additional Auth cases cross initial verified-password versus genuinely signed anonymous signup, self versus foreign `localId`, and requested `emailVerified`true versus false, always mixed with a display-name change. Both account states, provider identity occurrences and credential-field presence/values are checked. The verified-password baseline begins with verification true. The anonymous token is issued with local `session-rsa`, inspected for the expected audience/provider/UID, and accepted by the runtime's token-owner lookup. This is not a claim about production token validation.

An early Auth run stopped because a newly added local assertion treated the provider's display-name mirror as immutable. Readback showed only the requested displayName changed; provider identity fields did not. The assertion was corrected in its own commit, with negative checks for provider identity changes, missing fields and duplicate entries. Refusal atomicity and non-target equality remain strict. Later runs added credential preservation and real HTTP cleanup-failure fixtures. Both failed attempts and successful runs remain private and distinct.

The Rules SDK uses `@firebase/rules-unit-testing` owner/foreign/unauthenticated contexts. Each refused set/update/delete is followed by an owner read with `source: "server"`; the entire original document must remain unchanged. Successful owner update and confirmed deletion are also checked. Earlier Rules/SDK/Listen results remain separate, including listener replacement through forced long polling. This session did not add browser transport, native gRPC, reconnect/resume-token or production Listen coverage.

## What changed in the recorder

A1 now requires a usable successful JSON readback, a document object, the expected document name and a fields object before comparing state. Missing, non-JSON, malformed or foreign readbacks yield `indeterminate`, not a fabricated mutation or a `None == None` pass. Actual changed state still fails an applicable invariant.

A2 saves the artifact hash, frozen commit, runtime/observer inputs and configuration/index identities before starting the owned process. Nonzero exit, timeout and malformed partial results retain that parent provenance. Valid partial historical replay evidence is preserved; child output cannot replace the parent artifact fields. Empty/malformed case lists cannot imply completion. Cleanup/listener verification and final manifest persistence run independently of collection and summary generation.

The same failure tests exposed a macOS cleanup issue: `ps` truncated a path in the executable column. The guard now uses untruncated arguments and a basename column on macOS, retaining exact live-process argv matching. Zombie state is recognized from `stat`; no further signal is sent, and the owning `Popen.wait()` reaps the process. No broad process killing or relaxed live-process ownership check was introduced.

B introduces `bounded-http-v1` in a current local-only session, leaving the historical session and normalizer files untouched. It records status, bounded Content-Type, body kind, received/retained byte counts, full or prefix digest, truncation, and failure category. Raw delivered body bytes stay in private0700 directories and0600 files. Empty/non-JSON responses are received HTTP outcomes; timeout, abort, connection failure, interrupted body and size-limit overflow are not complete receipts. The body limit is2MiB and the per-request deadline is at most5 seconds, within the existing guarded session budget. Digests describe bytes delivered by Fetch, not network framing.

`current-http-legacy-json-v1` only projects completely captured JSON through the byte-preserved historical normalization function. A source-equivalence test protects that bridge. Non-JSON receipt cannot satisfy JSON document readback requirements and is never automatically compared to an old non-JSON body. The new execution manifest has a separate identifier and explicitly inherits no permission.

## Receipts and fixed artifacts

| Receipt | Execution source | Artifact SHA256 |
| --- | --- | --- |
| [Current second](../../spec/compatibility/broad-runs/a12183a0-second-current.json) | `a12183a0` | `313568bbdd584cd528ee70da5db96e34f254b0f27ad795d874a154f4b7e6d6e5` |
| [First46 regression](../../spec/compatibility/broad-runs/a12183a0-first46-regression.json) | `a12183a0` | `d537e52cc8d283c127e3f231b1a95ad5edbf86c03d1a734874873c0936414163` |
| [Partition](../../spec/compatibility/broad-runs/a12183a0-partition.json) | `a12183a0` | `8e433fc24df9585573ce6a213152269de8d51a22d60b1800a4d0e62e0d15508e` |
| [Auth conditions](../../spec/compatibility/broad-runs/ea298952-auth-conditions.json) | isolated `ea298952`, integrated unchanged at `a12183a0` | same retained `8e433f…` artifact |
| [Rules refusal state](../../spec/compatibility/broad-runs/185d7917-rules-refusal-state.json) | isolated `185d7917`, integrated unchanged at `a12183a0` | same retained `8e433f…` artifact |

The retained executable originates from `ed90292a`. Its build-input map was checked against each current runtime input map before reuse and again afterward. It is not substituted for either newly built artifact. Auth runs explicitly map `fireemu-35fe6` to project number`592603257417`; the additional Auth run also declares `session-rsa`. Partition and Rules use isolated demo projects and an explicit empty project-number map. The historical Firestore session project remains `demo-firestore-probe`.

## Verification and reviews

The integrated offline suite passed **108 pytest tests**, including the Node HTTP fixture and partition checks invoked by pytest. Ruff, ty and OxLint passed on the changed files. A1's three guard-removal mutations were detected; Auth's refusal/isolation/credential mutations and partition's content/order mutations were also detected. These are bounded mutation checks, not exhaustive formal verification.

Independent source reviews covered A1/A2, the HTTP recorder/JSON bridge, live-process cleanup identity, Auth target/protected state/recovery and partition reconstruction. Root additionally reviewed the partition finalizer and Rules SDK changes. Review findings about dropped historical fields, malformed child results, provider display-name mirrors and failure finalization were repaired and retested. No outstanding Must Fix remains in the integrated patches; these technical reviews are not owner production approval.

The full Rust workspace suite, lifetime revision1/2/3 suites and the four publisher checks were not rerun in this session. Rust runtime source and those CI steps were not changed. The existing broad CI command automatically includes the new pytest files. Local binary builds, current second execution, partition execution and final first46 comparison actually ran.

Commands used at the frozen integration source, with fresh private output directories:

```sh
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/compat-broad -q
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/second_cases.py --output "$SECOND_OUTPUT"
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/partition.py --binary "$RETAINED_BINARY" --receipt "$RETAINED_RECEIPT" --output "$PARTITION_OUTPUT"
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_local.py --output "$FIRST46_OUTPUT"
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_pair.py --saved-ab7bd698 --local "$FIRST46_OUTPUT/batch/result.json" --output "$COMPARISON_OUTPUT" --check
```

Each server-bearing command was wrapped with the existing port-registry `run` command. The private session log retains exact arguments and paths. Final parent/listener checks found no unrecovered owned runtime resources; reservations were released. The isolated writer worktrees are retained, clean, for resumption.

## Next production subset and resume queue

[The closed subset proposal](../../spec/compatibility/broad-second-production-subset-proposal.json) lists32 Auth diagnostics and13 Firestore steps from three programs: mask overlap, stale delete and invalid transform path. It deliberately excludes query/index-sensitive,500/501-transform, anonymous-ownership and Rules/SDK/Listen work from this initial subset. It is **design-only, not executable or approved**. The existing first46 production admission is unchanged.

The proposal specifies an owned document namespace and bounded request/resource/time targets, but mapping validation, adapter admission, current configuration/location, tariffs, index-storage/egress bounds and the final cost estimate remain unverified. Owner identity, permission reference, time window and nonce remain null. No old permission or nonce can authorize it. Before requesting one owner decision, compile and locally test the closed admission with fresh UID/token/updateTime mappings and calculate its cost bounds. Any required production preflight must wait for a separate explicit permission.

The highest-value next local task is to compile that small subset's ownership mapping against the existing adapter without enabling remote execution. In parallel, extend nearby mask/precondition/transform normal-state checks and listener detach/reconnect invariants using local artifacts. Keep wrong-project API availability as an environment prerequisite, not an implementation patch. Broader anonymous/provider behavior remains production-unobserved. Revision3, GAP-AUTH-007 and AUTH-U03 remain independent; they do not block this queue.
