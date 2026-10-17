# Authentication account lifecycle

The finite `AUTH-ACCOUNT-LIFECYCLE-1` capability covers the account state transitions exercised by this slice:

- Admin account create, lookup, list, update, disable, re-enable and delete.
- Client account sign-in, lookup and post-update observation.
- Duplicate email refusal without squatting a UID or changing the existing account.
- UID reuse after deletion.
- Anonymous upgrade to email/password and Admin provider linking through the existing public REST routes.

The focused runtime regression is `account_lifecycle_keeps_admin_and_client_post_state_consistent` in `crates/fireemu-adapter-http/tests/identity_toolkit.rs`. Existing conformance fixtures `auth/admin-account-lifecycle` and `auth/client-account-flows` provide pinned official Local Emulator Suite observations for the wider Admin and client flows.

Provider metadata follows the live credential state during this lifecycle. IdP account recycling and explicit password removal select a surviving federated, phone or anonymous provider instead of retaining a stale `password` classification. Export/import preserves native password credentials, including credentials created by Admin and client APIs, updated or reset passwords, and foreign hashes that successful sign-in has converted to native digests. The `fireemuImportedPassword` extension stores the algorithm, digest and salt; newly created passwords are never retained as plaintext or converted into reversible emulator hashes. Existing official-emulator credentials retain their original export representation until a password change replaces it. Fireemu understands this extension; compatibility with the official emulator's importer is not claimed.

Credential persistence is tested through fresh CLI processes and repeated export/import/authentication, and through generated create/change/reset/sign-in/restore operation sequences using the HTTP handlers. Previous and incorrect passwords remain rejected after a change. Exports produced by older versions that omitted a native credential cannot recover that password: an explicit password reset is required. Import never resets credentials automatically.

The capability is `boundary-conformance`: the local behavior is tested against the official emulator references, while production evidence is not inferred. A production candidate must use the same request inputs and observer identity and must record its evidence separately before it can support a production compatibility claim.

Session cookies, out-of-band actions, MFA and external provider protocol exchange remain separate capabilities.
