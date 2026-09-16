# Second45 runtime repairs and saved-reference re-evaluation

The original second45 production candidate remains32 matches/13 mismatches under fixed774e9d8b. No additional production operations were made. The [new re-evaluation](../../spec/compatibility/broad-runs/37e4c396-second45-runtime-recomparison.json) compares the same saved production responses with the repaired local implementation under the unchanged comparison contract and observer.

## Repairs

- Client update scalar decoding now rejects the observed malformed localId/displayName/emailVerified/customAttributes shapes with the observed structured INVALID_ARGUMENT response. Numeric displayName0 becomes string0. A decoded localId still never selects a client target; the verified token supplies the UID.
- Client customAttributes strings are refused with INSUFFICIENT_PERMISSION. Null is treated as absent and cannot clear existing claims; ordinary allowed profile changes can proceed. Email verification, existing claims and other protected state remain protected.
- Missing/null idToken in the observed displayName/localId request family produces INVALID_REQ_TYPE. Other authentication routes are not changed.

The runtime change is `31dee8d`; updated expectations and new state regressions are separate commits `2ca689bd` and `37e4c396`. No comparator, corpus input, admission, production permission, OOB/MFA handling or Admin parser was changed. The client shape checks remain after credential verification and before any mutation, preserving existing failed-session precedence. Other numeric values, malformed combinations and precedence interactions are not newly production-observed.

The13 rows fall into three cause groups. Later profile-state differences caused by the diagnostic refusal/success are not separate defects. All13 mismatches disappear under the repaired runtime; no remaining mismatch or indeterminate row is present in this closed45 comparison. This does not resolve independent lifetime or other unobserved work.

## Verification

- New tests initially failed on the old runtime: localIdobject was accepted and absent/nulltoken returned MISSING_ID_TOKEN. The first new test fixture incorrectly used anonymous accounts while expecting an emailVerified field; it was corrected to the observed email/password account model, with assertions retained.
- Identity Toolkit55 tests passed before the review follow-up; the final HTTP adapter run passed291 tests with zero skipped. Clippy for `fireemu-adapter-http --all-targets -- -D warnings` passed. The full workspace test suite was not rerun.
- Three isolated-worktree mutations were killed by assertions: bypassing the shape guard, moving it before credential verification, and restoring the old permission error.
- Independent read-only security review found no Must Fix. Its Should Fix (malformed shape combined with invalid token) was added and reviewed. The requested specialist profile file was unavailable; the reviewer applied the Security Specialist criteria directly. This is technical review, not owner result approval.
- Fixed local execution `2ca689bdd995eb4e3412803b843eb6bc63b02cd7` recorded45 rows with cleanup and listener shutdown confirmed, then compared45/45 under `--check`. Artifact SHA256: `8800114f49ffaa52a99fb8519c10dbb8b6cc91ec2085d4a7770f615c5609d831`.
- The subsequent `37e4c396` commit adds only the security regression; runtime sources and the observer are identical to the45-row execution. First46 was separately rerun at this final test commit and compared against the preserved ab7bd698 reference.

### Preserved local validation failure

The mutation checkout shared a Cargo target directory with integration. A subsequent integration test run reused the last mutation's permission error despite restored clean source:218 passed,2 failed and71 were not run. A first46 artifact from that interval is retained privately but superseded; its46 checks passed but do not exercise that branch. After forcing the tracked adapter source to rebuild, the final291 tests passed and first46 was recorded again to a new directory. No old artifact hash or result was overwritten. Future mutation work must use a separate target directory. The45-row successful artifact predates these mutations.

## Commands and remaining work

Commands used the locked Python3.12 environment for `second_production.py --local-output`, `second_production_pair.py --production <saved-private-result> --local <new-private-local-result> --output <new-comparison> --check`, `batch_local.py --output`, and `batch_pair.py --saved-ab7bd698 --local <new-local-result> --output <new-comparison> --check`. Rust verification used `cargo nextest run -p fireemu-adapter-http --profile pr` and targeted Identity Toolkit filters; mutation commands and private logs are retained in the run queue.

All production accounts/documents were reclaimed, and owned local processes/listeners stopped. The consumed production nonce is not reusable. Owner acceptance of these candidate results remains pending; no further production permission is inferred. Future breadth work can continue locally, with separate observation questions for unmeasured malformed combinations or routes. Revision3, GAP-AUTH-007 and AUTH-U03 remain independent tasks.
