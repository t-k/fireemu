# Authentication account lifecycle

The finite `AUTH-ACCOUNT-LIFECYCLE-1` capability covers the account state transitions exercised by this slice:

- Admin account create, lookup, list, update, disable, re-enable and delete.
- Client account sign-in, lookup and post-update observation.
- Duplicate email refusal without squatting a UID or changing the existing account.
- UID reuse after deletion.
- Anonymous upgrade to email/password and Admin provider linking through the existing public REST routes.

The focused runtime regression is `account_lifecycle_keeps_admin_and_client_post_state_consistent` in `crates/fireemu-adapter-http/tests/identity_toolkit.rs`. Existing conformance fixtures `auth/admin-account-lifecycle` and `auth/client-account-flows` provide pinned official Local Emulator Suite observations for the wider Admin and client flows.

Provider metadata follows the live credential state during this lifecycle. IdP account recycling and explicit password removal select a surviving federated, phone or anonymous provider instead of retaining a stale `password` classification. Export preserves hashless password accounts, including those with linked identities, while the lifecycle transitions retag accounts when the password credential is actually removed. A password account whose hash is not exportable remains classified as `password` across export/import/re-export; the regression coverage is in `crates/fireemu/src/import_export.rs` and `crates/fireemu/tests/import_export.rs`.

The capability is `boundary-conformance`: the local behavior is tested against the official emulator references, while production evidence is not inferred. A production candidate must use the same request inputs and observer identity and must record its evidence separately before it can support a production compatibility claim.

Session cookies, out-of-band actions, MFA and external provider protocol exchange remain separate capabilities.
