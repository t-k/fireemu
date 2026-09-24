# Local signed OIDC assertion boundary

`AUTH-FEDERATION-ASSERTION-LOCAL` is partial, with `exact-for-local-semantics` precision. The implemented slice verifies real signed compact RS256 OIDC ID tokens before the existing account flow. It does not treat fixture JSON or a decoded JWT payload as signature evidence.

## Activation and trust

An embedder/test calls `identity_toolkit::handle_with_oidc_trust` with `LocalOidcTrust`. The application request stays the standard `POST /identitytoolkit.googleapis.com/v1/accounts:signInWithIdp` request, with URL-encoded `postBody` containing `providerId`, `id_token` and optionally `nonce`; `idToken` on the outer request selects explicit account linking. Trust is a caller-pinned public JWK bound to a project, optional tenant, provider ID, issuer and client ID. It is never read from the application request or a token header URL. An enabled matching provider configuration must already exist in the selected store.

The shipped daemon and the existing `handle`/`handle_with` entry points retain emulator fixture mode. Provider-config CRUD alone does not enable this verifier. The opt-in handler refuses an unbound provider, SAML fixture, access-token-only credential, nonempty accompanying `access_token`/`refresh_token`, or unsigned assertion instead of falling back to fixture mode. This is internal handler configuration, not an additional client HTTP endpoint.

Verification runs under the selected Auth store lock before transient sweeping, account mutation, blocking hooks or token issuance. It checks compact RS256 signature, matching key ID, issuer, nonempty subject, client audience, authorized party for multiple audiences, expiry, issued-at, optional not-before and nonce. Header critical extensions and alternate payload encoding are refused. No keys are fetched from URLs. A nonempty `access_token` or `refresh_token` accompanying a valid ID token is refused before response credential construction or blocking credential forwarding; absent/empty values remain accepted. `at_hash` validation and OAuth token exchange are not implemented.

## Public contract references

- [Firebase manual OIDC sign-in](https://firebase.google.com/docs/auth/web/openid-connect): a provider ID token can be passed directly to `OAuthProvider.credential` and `signInWithCredential`.
- [Identity Platform accounts.signInWithIdp](https://docs.cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/signInWithIdp): the provider credential arrives in the URL-encoded `postBody`; an Identity Platform `idToken` requests linking.
- [OAuthCredentialOptions.rawNonce](https://firebase.google.com/docs/reference/js/auth.oauthcredentialoptions): the raw nonce is required for a nonce-bearing ID token and its SHA-256 digest must match the token claim.
- [OpenID Connect Core ID Token Validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation): issuer, audience, signature, authorized party, expiry and nonce validation. Replay detection is client-specific, so this slice does not invent a consume-once server policy for manually supplied bearer ID tokens.

Retrieved on 2026-09-14. Installed `@firebase/auth` version 1.13.5 was inspected at `tools/sdk-smoke/node_modules/@firebase/auth/dist/node/totp-B19JzI52.js`: `OAuthProvider.credential` maps `rawNonce` to the credential nonce, and `OAuthCredential.buildRequest` serializes it to `postBody.nonce`; the outer `idToken` is attached for linking. This is SDK source inspection, not an executed SDK or production observation.

## Coverage ledger

All scenarios below are in `crates/fireemu-adapter-http/tests/auth_oidc_assertions.rs`. The signer is the existing RSA implementation with the explicitly public deterministic fixture seed 7331. Only its public JWK enters trust; no production credentials or external IdP are involved.

| Obligation | Test | Evidence and boundary |
| --- | --- | --- |
| Real signature before identity creation | `signed_oidc_refuses_bad_signature_before_account_creation` | A signed token with a modified signature is refused, with no created account. TDD red returned 200 before enforcement. |
| New and repeated identity | `signed_oidc_creates_then_signs_in_to_the_same_account` | Real signatures create one account; repeated valid token resolves that account. This deliberately makes no replay-consumption claim. |
| Claim refusals and state preservation | `signed_oidc_refuses_claim_boundaries_without_mutating_existing_accounts` | Wrong issuer/audience/azp, exp at/before now, nbf/iat after now, malformed time/subject and unbound nonce; account records remain equal and no token is returned. |
| Nonce and accepted boundaries | `signed_oidc_nonce_matches_the_sdk_raw_nonce_hash` | Missing/wrong raw nonce refused, matching SHA-256 accepted; nbf equal to now and multi-audience with matching azp accepted. |
| Explicit link and identity collision | `signed_oidc_links_and_refuses_cross_account_identity_collision_atomically` | Standard outer idToken links; a second account cannot take the identity and both account records remain equal. |
| Trust scope and fixture downgrade | `signed_oidc_rejects_fixture_downgrades_and_wrong_trust_scope` | Project/tenant/provider/issuer/client/kid mismatch, disabled provider and fake JSON/unsigned tokens refused. The dedicated routed-tenant case below covers positive routing. |
| Header and credential restrictions | `signed_oidc_rejects_untrusted_headers_and_access_token_fallback` | Signed wrong-alg/kid/critical/b64 headers, access-token-only and SAML requests refused without a user. |
| Email collision | `signed_oidc_email_collision_requires_confirmation_without_tokens_or_mutation` | Unverified assertion email owned by an account requires confirmation, with no tokens or user mutation. |
| Mixed credentials | `signed_oidc_mixed_access_token_is_refused_before_mutation_or_credential_forwarding` | Nonempty accompanying access token refused before user mutation and a credential-forwarding blocking observer; empty access token accepted and the observer receives only the real ID token. TDD red returned 200 before the guard. |
| Mixed refresh credentials | `signed_oidc_mixed_refresh_token_never_reaches_hooks_or_pending_credentials` | Nonempty accompanying refresh token refused before hooks or mutation for both ordinary and MFA-gated users; no pending credential is created. Empty refresh token accepted; immediate blocking context and retained `PendingSignInCredentials` contain the ID token but no refresh token. TDD red returned 200 before the guard. |
| Tenant success and isolation | `signed_oidc_tenant_routing_succeeds_only_with_the_selected_namespace_pin` | Enabled tenant provider, selected store and matching pin succeed; the returned token carries the tenant. Parent/cross-tenant pins fail and the other stores remain empty. Removing the tenant binding kills this test. |
| Populated refusal state | `signed_oidc_bad_signature_preserves_populated_sessions_transients_and_allocation` | A bad signature with otherwise current claims leaves user/profile/sign-in timestamps, a refresh session, pending MFA, expired-but-unswept OOB/SMS entries and event/notice observations unchanged. Six transient registries stay shared with a pre-request clone; subsequent UID, refresh and SMS allocations match the clone. Moving sweeping before validation kills this test. |
| Existing fixture behavior | `auth_flows` integration suite | Separate emulator fixture regressions; this evidence does not prove signed SAML or production compatibility. |

## Token claims moved from AUTH-CREDENTIAL

AUTH-CREDENTIAL scope decision C7 (owner, 2026-09-24) moves these token-claim conditions here; they are required conditions of this parent and are not verified anywhere else:

- The ID token of an IdP sign-in (`accounts:signInWithIdp`) carries `firebase.identities` for the provider, `firebase.sign_in_provider` and, for SAML, `firebase.sign_in_attributes`, as production issues them.
- A refresh of that session and a session cookie made from it keep those claims.

AUTH-CREDENTIAL's harness (`conformance/src/auth-credential/`) records a token as its header shape and every claim, and can be reused for these rows.

## Evidence limits and parent scope

The finite local policy requires RS256, a matching key ID, RSA keys of 2048–8192 bits, a token at most 64 KiB, integral numeric timestamps, no clock skew, and `iat <= now < exp` with `exp > iat`. Multiple audiences require a matching `azp`; an explicitly supplied `azp` must always match. These are stated local bounds, not measured Firebase error precedence or tolerance claims.

Remaining scope includes daemon trust provisioning, discovery and JWKS refresh/rotation, SDK execution over a listener, successful cross-project assertions, provider case-normalization parity, advanced reauthentication/pending-credential flows, skew and timestamp edge policies, and production error messages/precedence. Signed SAML needs a genuine XMLDSig implementation with canonicalization, wrapping defenses, issuer/audience/recipient/time binding and explicit trusted certificates; current JSON SAML tests are not substitutes. Hosted redirect and authorization-code flows, replay consumption and production oracle questions remain separate. No production or external IdP calls were made.

## Security review

Must Fix: None found in the bounded opt-in signature enforcement. Signature and namespace validation precede existing account dispatch, and the configured handler has no fixture fallback.

Should Fix: Before activating this in the daemon, define secure trust provisioning/rotation and exercise the real SDK and broader cross-project routing. Keep advanced credential flows outside any claimed parity until separately tested.

Notes: The requested `~/.agents/agents/security_specialist.md` was absent; the installed `~/.claude/agents/security-reviewer.md` checklist was used for the implementation review. Trust contains public key material only. The verifier never follows JWT header URLs. Default fixture mode is explicit and remains separate. Independent review of commit `40e636c6` found no Must Fix items and two Should Fix items. Both follow-ups are addressed: mixed access tokens are refused, and tenant success/isolation plus populated refusal state are tested. The tests also verify that active blocking/event/notice observers see no refused-request effects; no pre-existing queued notifications are seeded. A subsequent rereview identified the analogous caller refresh-token boundary, which is now refused and tested for ordinary and MFA-pending paths. The follow-up retains the review requirement before integration.
