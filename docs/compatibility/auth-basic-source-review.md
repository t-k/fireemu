# Auth basic source review and coverage boundaries

Reviewed on 2026-09-10 by Codex. This is an agent-authored interpretation of selected sections, not human approval. The [review record](../../spec/compatibility/evidence/auth-basic/source-review.json) identifies four freshly acquired official pages by raw/body SHA-256, extractor digest, acquisition time and section locator. Full pages remain in the operator cache; these digests do not make source content reconstructible from this repository alone.

This review maps the existing [nine-case observations](auth-basic-evidence.md). It neither changes those observations nor establishes additional successful tests. Slice-local obligation IDs below are review identifiers, not newly registered requirements. All feature-level approval remains pending.

Review clarification for revision 1: `expiryValid` accepts a positive integer string of one to six digits; `"1"`, `"3600"` and `"999999"` all pass. It does not establish a specification-matching lifetime or rejection after expiry. Signup credentials are checked for presence only; the nine-case run uses signin credentials for subsequent requests. The separate [revision 2 receipt](auth-basic-v2.md) adds signup-token usage controls and separates expiry shape from the one-hour expectation. It does not rewrite the original observations.

## Source-to-case mapping

| Obligation / case | Source and interpretation | Coverage boundary |
|---|---|---|
| AUTH-BASIC-SIGNUP / `signup` | [Email/password signup](https://docs.cloud.google.com/identity-platform/docs/use-rest-api#section-create-email-password): successful registration returns account credentials. | Fresh account only; not duplicate signup, provider disablement or abuse limits. |
| AUTH-BASIC-SIGNIN / `signin` | [Password signin](https://docs.cloud.google.com/identity-platform/docs/use-rest-api#section-sign-in-email-password): valid credentials identify the same account. | One successful password; no disabled account or tenant. |
| AUTH-BASIC-LOOKUP / `lookup` | [Client lookup](https://docs.cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/lookup#request-body): the end-user token selects its account. | UID/email/marker match; no exhaustive returned-field validation. |
| AUTH-BASIC-REFUSAL / `wrong-password` | [Privacy-specific behavior](https://docs.cloud.google.com/identity-platform/docs/admin/email-enumeration-protection#overview): invalid credentials receive the generic login error. | Wrong-password branch of AUTH-PRIVACY-001 only. |
| AUTH-BASIC-STATE / `unchanged-state` | [Lookup interface](https://docs.cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/lookup#request-body) supports a before/after harness control. | Selected fields, not all server state. The source does not promise full-state immutability. |
| AUTH-BASIC-REFRESH / `refresh` | [Refresh exchange](https://docs.cloud.google.com/identity-platform/docs/use-rest-api#section-refresh-token): form-encoded renewal yields an ID token for the same UID. | Nonempty tokens, positive expiry and bearer type; no expiry advance, rotation guarantee or project-mismatch test. |
| AUTH-BASIC-REFRESH-LOOKUP / `refreshed-lookup` | [Client lookup](https://docs.cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/lookup#request-body), combined with the exchange, supplies a derived positive control. | Service acceptance of the refreshed token, not independent signature verification. |
| AUTH-BASIC-DELETE / `delete` | [Account deletion](https://docs.cloud.google.com/identity-platform/docs/use-rest-api#section-delete-account): the current account can be deleted with its ID token. | Success status only; token revocation across other services is not measured. |
| AUTH-BASIC-ABSENCE / `deleted-account-absent` | [Admin selectors](https://docs.cloud.google.com/identity-platform/docs/reference/rest/v1/projects.accounts/lookup#request-body) support separate exact UID/email cleanup checks. | A measured cleanup control; not a general consistency or authorization proof. |

The general REST guide lists older distinguishable login errors. The privacy-specific guide supplies the applicable condition for this run: improved email privacy was enabled. Its HTTP400 example and generic `INVALID_LOGIN_CREDENTIALS` behavior support the selected refusal expectation. They do not make unknown-email, enumeration, email-change or linking branches tested.

The state control compares only `localId`, `email`, `displayName`, `emailVerified`, `disabled` and `providerUserInfo`. It does not inspect failed-login counters, audit logs, timestamps, token state or other hidden state. This distinction follows the [actual recorder](../../tools/auth-basic/recorder.py), not an assumed server guarantee.

## Relationship to registered requirements

[AUTH-PRIVACY-001](../../verification/requirements/requirements.json) is a broad privacy requirement; only its wrong-password branch is observed here. INV-AUTH-004 concerns transient credentials, expiry and budgets; none are exercised. INV-AUTH-005 concerns exhaustive route metadata, privilege classes and method handling; merely calling selected routes does not establish it. Those existing obligations and their tests must remain intact.

Signup, signin, lookup, refresh and deletion need atomic requirement registrations before they can be included in a feature-level evidence contract. The current AUTH-USERS and AUTH-TOKENS labels remain unchanged. Registration must preserve the distinction between source-derived behavior, derived positive controls and harness cleanup controls.

## Approval-readiness decision

The original nine projections must not be approved as independently recomputable raw-response evidence. Source mapping is necessary but does not close the evidence gaps:

- Raw Auth responses were intentionally not retained. The public booleans cannot reproduce the recorder's decisions, and cannot be relabeled as raw-response evidence.
- The detailed artifact/process/build receipt is private. A public hash and `ownedProcessVerified` assertion alone do not let a reviewer repeat its identity checks.
- Source-content reconstruction depends on the private cache. Repository-only checks currently validate the observation projections, not this new review record or the cached source bodies.
- Lost-create-response recovery has predicate/model coverage but no actual delayed-response integration observation.

Two follow-up designs are possible. Recommended: define a versioned, explicitly redacted evidence contract with public artifact/configuration/build provenance, structurally validated observations and explicit limits; collect a new separate bundle and bind the eventual approval subject to that bundle, corpus and source review. Alternative: retain the present data indefinitely as informal observations, with no execution approval. Do not recreate discarded raw responses, transfer aggregation approval, or silently overwrite the current nine-case bundle.

The user approved the separately versioned redacted-evidence design after this review. Revision 2 implements that bounded direction; human execution approval remains separate. Approval of a limited redacted-observation scope does not need to wait for complete Auth coverage, but cannot be presented as raw-response or independent signature verification. Token values and recovery journals must remain private or ephemeral. SDK, Rules, MFA, OOB, tenant, public npm and complete Auth compatibility claims remain excluded.
