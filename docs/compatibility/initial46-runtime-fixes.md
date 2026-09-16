# Runtime fixes from the saved initial46 production batch

The fixed local artifact at `ed90292a067866999a308f5c9bf029e0846c17b0` matches all46 saved production observations under the explicitly revised comparison contract. Recording and cleanup completed, with zero missing or indeterminate rows. This is an offline re-evaluation against production execution `bc38f392`, published at `ab7bd698`; no new oracle request was made. The original35-match/11-mismatch comparison, responses, hashes, observer and approval history remain unchanged. These new results are candidates, not owner result approval.

[Execution and validation receipt](../../spec/compatibility/broad-runs/ed90292a-runtime-fix-result.json), [new comparison](../../spec/compatibility/broad-runs/ed90292a-saved-production-comparison.json), and [paired normalized observations with original row classifications](../../spec/compatibility/broad-runs/ed90292a-paired-observations.json) preserve both evaluations.

## Five independently addressed causes

| Cause | Runtime correction and regression | Observed effect |
| --- | --- | --- |
| Client update input handling | Verified client token selects the UID; client `localId` never selects a different account. The observed `emailVerified` input is ignored while permitted normal changes apply. Admin/client planning, self-service invalidation and reissuance follow the actual route. Tests use distinct A/B display names, foreign selectors, ordinary attributes, invalid/expired/revoked/disabled credentials, password changes and legitimate admin updates. | Both directly divergent client-update rows now match. Six later display-name differences disappear as consequences of those updates; they are not six independent bugs. |
| Negative-limit runQuery envelope | Only the existing `INVALID_ARGUMENT` negative-limit query error is returned as the observed one-element error array. Zero/positive limits and other API errors retain their behavior. | The single negative-limit row now matches without changing its request or document state. |
| Unauthenticated displayName-only update | The exact one-field client request returns `INVALID_REQ_TYPE`. Other missing-token requests and general authentication handling are not reclassified. | The single unauthenticated-update error row now matches. |
| Last ID-token issuance metadata | `lastRefreshAt` is retained in account state after successful token signing, using the exact refresh-session identity; lookup and failed issuance do not fabricate a time. Delayed issuance cannot update a deleted/recreated UID or activate a duplicate-email owner. Import/export preserve the timestamp. Virtual-clock, failure, refresh and persistence regressions cover these branches. | The field is present in all three observed lookup rows. These rows overlap the display-name consequences above and are not additional independent row failures. |
| Refresh project identity | The optional `daemon.authProjectNumbers` map supplies the numeric refresh `project_id`. JWT audience/issuer remain project IDs. Two independent project mappings, routed/registered/tenant stores, restore and the unset fallback are tested. The local wrapper supplies its actual project mapping as configuration. | The refresh response now matches. An unmapped project retains the existing project-ID fallback rather than inventing a number. |

The timestamp meaning follows the official [Identity Platform UserInfo reference](https://docs.cloud.google.com/identity-platform/docs/reference/rest/v1/UserInfo): the last ID-token issuance time. Runtime tests do not claim exact production timing, propagation bounds or all issuance/error combinations. Client `customAttributes`, MFA, OOB and other unobserved update fields were not generally enabled; existing GAP-AUTH-004/005 regressions remain passing.

The minimal runtime regression entry points are `broad_client_update_uses_verified_owner_and_ignores_observed_admin_fields`, `broad_client_update_failed_credentials_never_apply_regular_attributes`, `broad_display_name_only_update_preserves_production_error_code`, `negative_limit_query_error_is_a_single_array_element`, `broad_last_refresh_tracks_successful_token_issuance_not_reads_or_failures`, `broad_refresh_project_number_is_separate_from_jwt_project_identity`, and `last_token_issuance_round_trips_without_lookup_time_fabrication`. Store tests separately cover namespace mapping, recreated UIDs and duplicate-email ownership.

## Contract and local execution

Runtime changes were committed separately at `d9d66d82`; `49adc117` formats the changes, extracts the new project-number parser without changing validation, and removes a redundant export scope. It also formats earlier tests/inventory code and retains two long stateful MFA tests through the existing targeted lint convention. Comparator/local assertion corrections are the separate `ed90292a` commit. Publication commits do not replace that execution commit.

The old local assumptions that both authenticated updates must be refused and both display names must remain absent were corrected from the saved observations. The46 request bodies, order, principals and namespace relationships remain the same. The Auth scenario source digest changes because its assertions change; the manifest is explicitly regenerated rather than falsely labeled unchanged.

`batch-pair-v2` / `batch-response-v2` add RFC3339 absolute-time normalization only at Auth `users/*/lastRefreshAt`. Field presence, JSON types, calendar validity, timezone offset validity and other locations remain significant. Invalid `+00:60`, `+01:99` and `+24:00` offsets stay visible. The saved-reference entry verifies exact hashes for both published observations and the independent completion/cleanup receipt. It reports the old observer/manifest/contract separately and checks the current local observer/manifest/contract, ordered requests, principals, namespace and completion. The ordinary live-pair entry still requires identical observers. Previously erased token bytes and absolute times cannot be recovered, and are not claimed as newly verified.

| Fixed input or result | Value |
| --- | --- |
| Local execution commit | `ed90292a067866999a308f5c9bf029e0846c17b0` |
| Artifact SHA256 | `8e433fc24df9585573ce6a213152269de8d51a22d60b1800a4d0e62e0d15508e` |
| Observer SHA256 | `3a7001525e2580ab6e0654794fd9c3ab0556d06238163960c700f23816a8c0d7` |
| Manifest digest | `6f0fa73a8fe494709b883c440266c721157d8ec44252fb81c331f2a10642d534` |
| New comparison contract digest | `467df4b222eec0b35a800c5cddc434413711c26400668cd4fddb57bdfed09cea` |
| Local requests | 91:31 Auth,60 Firestore,0 metadata;29 recovery requests included |
| Recording / cleanup / compatibility | Complete / complete /46 matches |
| Owned process / listeners | Stopped / all closed |
| Current transform operations | 20 saved-production matches, separately enumerated in the receipt |

The nineteen current Auth state/identity assertions also pass locally. They are not nineteen additional production observations. The eleven old mismatching rows all match in this re-evaluation; no independent mismatch remains within these46 operations. The old193 historical matches,26 local checks,23 indeterminate histories,46 mapping checks and SDK/Rules/Listen evidence keep their original scopes. The new20-transform comparison does not overwrite the old transform history. GAP-AUTH-007, AUTH-U03 and lifetime revision3 remain independent open work and do not gate other exploration.

## Executed verification and review

- Relevant Rust suites:624 passed,1 skipped at the fixed execution source. The skip is the existing ignored `streams::refresh_tests::fifty_targets_examine_one_changed_document_fifty_times` performance test.
- Targeted config/core/import/export verification:16 passed,394 excluded by the explicit filter. Broad Python:64 passed, including the32-combination recording/check finite model and saved-input/namespace/principal/missing/cleanup negative cases.
- `cargo fmt --all --check`, relevant-package Clippy, Ruff and ty passed. The catalog and candidate preparation checks passed. Full-workspace Rust, lifetime suites and their publishers were not rerun in this runtime-focused phase.
- Security review concentrated on client UID selection, admin-only fields, credential failures and side effects. Its timestamp persistence finding was fixed and re-reviewed. The separate comparator review found an invalid-offset normalization case; the regression failed before the correction and passed afterward. No outstanding Must Fix or Should Fix remains in either review. Review is not production execution permission.

Actual commands were run from the integration checkout; `<private>` below abbreviates `/Users/tk/work/firebase-emulator/docs.local/logs/2026-09-13`:

```sh
cargo nextest run -p fireemu-adapter-http -p fireemu-core-auth -p fireemu-adapter-grpc --profile pr --no-fail-fast
cargo nextest run -p fireemu -p fireemu-core-auth -E 'test(last_token_issuance_round) | test(broad_project_number) | test(auth_project_numbers) | binary(import)' --profile pr
cargo fmt --all --check
cargo clippy -p fireemu-core-auth -p fireemu-adapter-http -p fireemu-adapter-grpc -p fireemu --all-targets -- -D warnings
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/compat-broad -q
uv tool run ruff check tools/compat-broad/batch_pair.py tools/compat-broad/batch_local.py tools/compat-broad/broad_cases.py tools/compat-broad/test_batch_pair.py
uv tool run ty check --python tools/compat-inventory/.venv --extra-search-path tools/compat-inventory tools/compat-broad/batch_pair.py tools/compat-broad/batch_local.py tools/compat-broad/broad_cases.py tools/compat-broad/test_batch_pair.py
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/broad.py --check-catalog
python3 /Users/tk/.agents/skills/port-registry/scripts/portctl.py run --service fireemu-postfix-local46 --range 24000-24999 --ttl 20m -- uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_local.py --output <private>/ed90292a-local46
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/batch_pair.py --saved-ab7bd698 --local <private>/ed90292a-local46/batch/result.json --output <private>/ed90292a-comparison.json --check
```

The local wrapper built and copied the actual artifact using `cargo build --locked -p fireemu --message-format=json`, used OS-assigned listener ports and verified ownership-aware shutdown; portctl released its reservation. Both local wrapper and comparison check exited0. Initial failing TDD checks and review reproductions are retained privately, not counted as successful executions. No further production operation is required to validate the five observed corrections against this saved reference. Unobserved update fields, other error precedence combinations and exact timing remain separate questions; no automatic production retry or expanded execution proposal is introduced here.
