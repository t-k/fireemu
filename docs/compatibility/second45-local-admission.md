# Second45 local admission and execution proposal

This work keeps the second candidate closed at 32 Auth update diagnostics and 13 Firestore steps: ancestor-overlap masks, stale delete preconditions and invalid transform paths. The historical first 46 receipts and all previous comparison classifications remain unchanged. Production compatibility for these 45 rows is unobserved. No production approval, permission window or production nonce is assigned.

## Request and cost accounting

The existing Auth operation sequence needs 302 requests on its successful collection path: four setup requests, 288 requests for 32 baseline/diagnostic/readback sequences, two additional administrator ownership checks, and eight recovery requests. This is 294 observation requests and eight recovery requests. The baseline calculation includes the ownership lookup before every privileged update; it is not just the 32 diagnostic calls.

The three Firestore sequences require 13 recorded steps, three namespace absence checks, three seeds, and up to nine requests for conditional deletion and absence verification: 28 requests. There are no queries, collection-group scans or partition requests. Each sequence owns one document and confirms its recovery before the next sequence begins. Extra admission or state checks must be included in the actual execution count.

Service totals already include recovery requests. The recovery counter is a phase classification and must not be added to Auth+Firestore+metadata a second time. The proposed caps remain Auth 400, Firestore 100, metadata 100, recovery 60, total 660, with 1200 seconds wall time and 300 seconds reserved for recovery. The local direct/mapped validation runs two independent sides; these are not a single approved production execution.

A conditional terminal-recovery schedule for two known accounts and one document uses at most 11 resource requests. At 12 seconds plus 0.25 seconds spacing each, these reserve 134.75 seconds; one bounded credential acquisition/expiry check reserves 86.25 seconds, and four metadata postflight requests reserve 49 seconds. Their 270-second sum fits the proposed 300-second reserve only under these stated conditions. This is a planning calculation, not a remote execution guarantee; local runs do not issue credential or Cloud metadata requests. Failed acquisition must latch failure rather than start repeated per-resource refreshes.

For a conservative operation-price calculation, count every attempted Firestore document read, write or delete, including rejected diagnostics and absence verification, at the applicable unit tariff rather than assuming refusals or free quota cost nothing. The nominal sequence contains 16 reads, eight writes and four deletes. Auth uses at most two newly active email/password accounts. There are zero query index-entry reads and zero SMS, mail or external-provider operations in this scope.

The formula is `readAttempts*readUnitPrice + writeAttempts*writeUnitPrice + deleteAttempts*deleteUnitPrice + 2*emailPasswordMauPrice + retainedGiBMonths*storagePrice + transferGiB*egressPrice`. Attempt counts come from the full admitted operation trace, including recovery. Existing indexes can contribute storage even without a query; a query-free batch does not prove index-storage cost is zero. Response limits bound retained client data, not necessarily billed network traffic after a failed or interrupted response. Unrecovered resources also need a separately accepted retention/recovery bound.

Official pricing sources checked on 2026-09-13 explain the billing dimensions: [Firestore billing](https://firebase.google.com/docs/firestore/pricing), [location-dependent Firestore tariffs](https://cloud.google.com/firestore/pricing), and [Identity Platform pricing](https://cloud.google.com/identity-platform/pricing). Email/password falls within the monthly-active-user pricing model. This public-source check does not establish the current oracle location, index settings, billing tier or owner acceptance of USD 1. No fresh oracle read was made. A numeric approved upper estimate remains unset until those environment-dependent inputs are confirmed.

## Remaining production decision

A future proposal must bind the reviewed source commit, observer and second45 manifest/operation-comparison contracts; match the live project number, Database settings projection, Auth configuration and API-key ownership; supply location-specific tariffs and storage/egress/recovery assumptions; and receive explicit owner identity, permission reference, window and a fresh unused nonce. No prior first 46 or stopped execution approval is inherited. The executable entry introduced for this milestone is local-only; a future remote entry is a distinct permission and review boundary.

## Executed result

The fixed execution commit is `bd64d7935f039eed02b1dcb3fbb6e806a2507cf9`. The [machine-readable result](../../spec/compatibility/broad-runs/bd64d793-second45-local.json) binds the admission, observer, runtime, configuration and semantic comparison contract. The pair used artifact SHA256 `fe2da11a80e9730b3541075dae88757d9bad1c9855a2360b9a818fe7841fd2da` for both sides. This is a new local receipt; it does not replace any historical receipt.

| Result | Direct | Mapped |
| --- | ---: | ---: |
| Collected diagnostic rows | 45 | 45 |
| Auth requests, including recovery | 302 | 302 |
| Firestore requests, including recovery | 28 | 28 |
| Recovery requests, already included above | 17 | 17 |
| Total adapter requests | 330 | 330 |
| Retained response bytes | 197064 | 198191 |
| Largest response body, bytes | 857 | 857 |
| Collection / cleanup / safety | complete / complete / passed | complete / complete / passed |

All 45 mapping rows matched. Production compatibility remains **unobserved** for these rows. The two sides together took 172.22 seconds including build and process cleanup. Side result-file creation/final-write intervals were 84.444 and 84.302 seconds; these are filesystem wall-time measurements, distinct from the monotonic deadlines enforced by admission. Two additional local control requests verified the owned runtime and rejection of a wrong control token; no Cloud metadata or credential requests occurred.

The first 46 regression ran at the same fixed commit with its separately recorded artifact `cf4f6e1874ef5c84ed4bb6e63f7bf321ea2e3ec2ea3439b5cca1c24948abd3e7`: all 46 rows matched the saved production reference. The original 35 matches / 11 mismatches and subsequent repaired46 comparison remain intact. The existing 193 historical comparisons, 26 local invariants, 23 historical indeterminate cases and earlier SDK/Rules/Listen results were not reclassified or rerun for this result.

The exact executable commands used were the following, with private output paths elided:

```sh
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/compat-broad -q
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/compat-broad/test_second_wire.py -q
/usr/bin/time -p uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/second_mapped.py --output <fresh-private-pair-directory>
/usr/bin/time -p uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_local.py --output <fresh-private-first 46-directory>
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_pair.py --saved-ab7bd698 --local <first 46-directory>/batch/result.json --output <private-comparison.json> --check
```

The integrated suite passed 165 tests with zero failures/skips at `257c88a2`; the only subsequent source change was formatting the JS bridge. Its six real HTTP tests passed again at the final execution commit. Ruff, ty, Node syntax, OxLint and OxFmt passed. Four process-local mutations were killed: disabling typed-operation admission, removing the Auth recovery reservation, accepting a detached trace, and removing recovery grace. No source file was edited while an execution or mutation was running. The existing compatibility CI's `pytest tools/compat-broad` step includes the new tests and the checked-in admission/proposal consistency test.

## Review and failure boundaries

Independent security/correctness review initially required changes. The final reviewed source at `257c88a2` was approved with no remaining Must Fix findings; the final JS formatting change was syntax-checked and exercised through the wire tests and full local pair. The unavailable specialist role file was not represented as an executed review; an independent correctness reviewer applied the security criteria.

- **Must Fix: resolved.** The adapter derives expected operations from its closed internal phase context. The comparator joins every diagnostic and readback to the independently checked full transport schedule and reconstructs stale versions from actual same-trace responses.
- **Must Fix: resolved.** The local pair's outer deadline covers two independently bounded sides, and bounded graceful shutdown preserves a recovery opportunity before verified forced termination. Existing callers retain their default deadlines.
- **Must Fix: resolved.** Known protected baseline drift latches unsafe state; incomplete, unsafe or unrecovered direct execution suppresses the mapped side. Unavailable readback remains indeterminate instead of becoming a runtime-state-change claim.
- **Should Fix: resolved.** Privileged 401/403 responses latch rejected authority; recovery does not keep sending that credential. Complete-pair symmetric mutation fixtures and actual non-JSON, empty 404, interrupted-body and failed-setup fixtures cover the added paths.
- **Notes.** Raw request/response bytes, credential bindings and partial journals remain private. Public digests do not replace or repair missing historical evidence. No runtime patch or newly confirmed production gap resulted from this mapping work.

Both owned runtime processes stopped and all registered listeners closed. All admitted accounts/documents were recovered. No new daemon, port reservation or unrecovered resource remains. The local worktree and private artifacts are retained intentionally for replay.

## Next execution decision

The result's `productionProposal` contains the exact 45 manifest/observer/comparison bindings and unchanged resource/request/time/USD1 ceilings in one place. Current environment checks, location tariffs,storage/egress and unrecovered-resource duration conditions, owner identity, permission reference, permission window and production nonce remain unset. The CLI is still local-only. A successful mapping comparison neither supplies those inputs nor authorizes any production operation.

The next safe local work is separate nearby mask/precondition/transform or listener coverage. It must not enlarge this closed 45 admission. Revision 3, GAP-AUTH-007 and AUTH-U03 remain independent tasks; no MFA/TTL prerequisite was reintroduced.
