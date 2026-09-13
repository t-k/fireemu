# Feature-group development queue

This queue starts from 8f2e4850 and preserves all previous observations and their limitations. Only the coordinator integrates and pushes to `feat/compatibility-inventory`. No new Cloud authentication, reads or data operations are authorized. The prepared G0 frame is independent of the newer development runtime.

| Goal | Finite conditions and evidence | Owner model | State and fixed evidence | Remaining parent scope |
| --- | --- | --- | --- | --- |
| G0 | The two existing BatchWrite recipes; production response and post-state comparison | Coordinator | waiting-owner; fixed a35f85b4 and its existing execution package are unchanged | Owner, window, new nonce, settings/pricing acceptance and recovery owner; exactly two runs, 36 operations, 1,200 seconds, 300-second recovery reserve, one HTTP request at a time |
| G1-local | Unsigned emulator custom-token persistent/session/developer claim overlap; rightful refresh principal/project/tenant bindings; rejected cross-tenant refresh preserves both namespace snapshots | gpt-5.6-luna | done; independent security review and 143 integrated Auth tests at 4d4bd2a0 | Signed/strict verification and unobserved production combinations remain separate |
| G2-local | Failed multiwrite Commit preserves documents/version; local transaction/lock state after failure; rollback releases ownership and permits a subsequent write with verified post-state | gpt-5.6-luna | done; independent review, corrected gRPC paths and integrated core/gRPC tests at 2367e203; repeated related tests at ba38767b/de8a14b8 | Production transaction termination/error precedence and automatic retries remain unobserved; G0 is not duplicated |
| G3-local | Actual Node SDK A-to-B/sign-out events, denied-write full state, listener unsubscribe and replacement-listener propagation | Reused agent; model not exposed | done; independent review and owned SDK run at 2367e203, using the separately recorded a35f85b4 runtime artifact | Browser/WebChannel, cache behavior beyond these assertions, reconnect and production Rules remain separate |
| G4-read | Enterprise owner-authorized gRPC latest collection input, optional single top-level field-reference select, then optional single nonnegative limit; real results and finite refusal/epoch/stream controls | gpt-5.6-luna implementation; coordinator completed missing controls after review escalation | done-local; independent runtime/test/catalog reviews, normal tests and two isolated mutations; integrated de8a14b8 | Enterprise remains partial. No production execution parity; where/functions, nested extraction, metadata expressions, consistency selectors and total-memory bounds are excluded |

## Evidence and limitations

- [G2/G3 results](../../spec/compatibility/broad-runs/2367e203-goals-local.json) retain the superseded ineffective tests, the corrected cases and the actual SDK artifact identity.
- [G1 results](../../spec/compatibility/broad-runs/4d4bd2a0-g1-local.json) distinguish local claim/principal/state invariants from unobserved production behavior.
- [Final integrated results](../../spec/compatibility/broad-runs/de8a14b8-goals-local.json) record exact commands, test/artifact hashes, review outcomes, mutation failures and cleanup. First46 reuses the immutable saved production reference and matches all46 rows. Second45 is a current direct/mapped local regression, with45 mapping matches; it is not a new production comparison. The old32/13 and corrected45 production comparisons remain unchanged.

G4 now returns stored document results rather than reporting every valid pipeline as validation-only. Unsupported selectors/stages/references fail before the guarded scan. The stream emits separate document responses and an explicit empty result, but the existing query path still materializes a result vector: this is not a total-memory guarantee. Local completion of this child does not complete Enterprise.

No confirmed new production gap was discovered in this session. G4's consistency downgrade, overwritten stages, omitted field references, unrequested metadata and missing epoch guard were defects in the developing implementation and were corrected before integration. Existing revision3, GAP-AUTH-007, AUTH-U03 and all historical193/45/46 evidence keep their previous status.

## Dispatch and measured resources

The session exposed four active slots. Two owners were explicitly launched with `gpt-5.6-luna`; a third new thread hit the available thread limit, so an existing agent was reused without claiming its model. Each source owner had a separate feature-based worktree and target/build directories. Heavy compilation was serialized. Mutation used the existing admission tool and disjoint marked output; those artifacts were never used by the normal runners.

G4 required targeted review returns and coordinator escalation for omitted controls. The final review accepted the completed finite controls. Author-reported early G4 elapsed times and coverage were not relied on for final completion. Exact command start/end times are saved where measured; model token cost and unmeasured preparation/analysis/review intervals are not estimated. No new measurement infrastructure was added.

The owned runtime processes/listeners and temporary Goal/mutation worktrees were reclaimed. Commits, raw logs, selected final artifacts and review notes remain in the root private log directory. The a35f85b4 observation checkout remains detached and separate. Earlier worker G2 and superseded G3 binaries were not retained after cleanup; their recorded hashes are not replaced with later builds.

## Next finite cards

These finite children continue independently. Local behavior alone is not a production expectation; completed conditions do not close the parent feature group.

| Goal | User-visible target and finite scope | Evidence / existing entry | Ownership, budget and dependency | Status |
| --- | --- | --- | --- | --- |
| G2-REST-next | Exercise REST transaction Commit failure, explicit rollback and subsequent write with document post-state; distinguish active-transaction policy from atomicity | Existing `src/rest` and `tests/local.rs` transaction assets; reuse G2 gRPC operation sequence; targeted grpc nextest and stored references if equivalent | gpt-5.6-luna owner; coordinator independent review; grpc REST/tests only, no Cloud | done-local at 0fe92867; [80 passed / 1 existing skipped](../../spec/compatibility/broad-runs/0fe92867-g2-rest-local.json); handler-level evidence, transaction policy remains production-unobserved |
| G3-reconnect-next | One bounded real SDK reconnect condition after refused write, with cache/server/listener observations separated | Existing `tools/sdk-smoke/g3-sdk.mjs` and owned `fireemu exec`; retain the external process timeout | Next available owner, SDK smoke only; no Rules production changes, no browser claim | queued; select a genuinely missing local condition before coding |
| G4-scale-next | Assess whether collection result materialization can be reduced without changing stream contents or silently truncating results | Existing guarded latest-query path, query paging assets and the new multi-response controls | Escalated design question; grpc/core query paths, separate worktree/output, one build lease; no new stage or oracle needed for resource invariants | queued; full-result vector remains a known limitation |

To resume, check the feature HEAD and worktree status, read the linked results, then create a feature-based worktree for the selected finite card. Keep a35f85b4 untouched. Do not rerun historical production observations or use old permission/nonces. Run the targeted tests first, seek an independent review at a fixed commit, and run45/46 regressions when runtime changes affect their shared paths. Only the coordinator commits integration results and pushes the feature branch.
