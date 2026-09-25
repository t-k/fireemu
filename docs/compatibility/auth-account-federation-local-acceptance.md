# AUTH-ACCOUNT / AUTH-FEDERATION — local implementation and acceptance

This document describes a new, **uncompiled and unexecuted native change**, not a
production observation, an O7 permission, or a parent completion decision. The parent
acceptance authority remains `ip-fs-production-compatibility.md`. Old receipts,
capability declarations and approved source/artifact bindings are not promoted by this
work. The Rust changes require the pinned toolchain and all relevant regression lanes.

## Authoritative shape versus local decisions

Sources (read for this change; no API invocation):

- https://docs.cloud.google.com/identity-platform/docs/reference/rest/v1/SqlExpression
- https://docs.cloud.google.com/identity-platform/docs/reference/rest/v1/projects/queryAccounts
- https://docs.cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/signInWithIdp

`SqlExpression` has email, phoneNumber and userId selectors. The reference explicitly
makes email matching case-insensitive and specifies email > phoneNumber > userId
priority. It does not establish all match semantics, combination rules or error
precedence. **Exact matching, a union across expressions, null handling, empty-string
handling, Unicode lowering and rejected unknown fields are explicit local policies,
not observed production parity.** No SQL string is evaluated. LIKE/regex/prefix
search is not claimed. A malformed expression never becomes an unfiltered query.

`pendingToken` is an opaque credential returned by signInWithIdp for repeating an IdP
sign-in or completing account linking. It is distinct from the deprecated
`pendingIdToken`. This work adds bounded **local** pendingToken continuations; it does
not reinterpret the deprecated field, parse a Google-issued token, fetch credentials,
or exchange an external authorization code.

## AUTH-ACCOUNT implementation

Strict-profile account queries decode typed expressions, filter within the already
selected project/tenant, remove duplicate matches, sort, then apply offset/limit.
Count-only results count matching records; paged results retain the pre-existing
page-count rule. All selectors, including ignored lower-priority values, are checked
before selection. A valid empty/null expression list remains an unfiltered query.

Local parser ceilings are 128 expression objects and 4096 UTF-8 bytes per selector.
These are defensive local limits, **not Google quotas**. Empty exact values are not
wildcards; a present empty email does not fall back to a lower-priority userId.

The v7 sort/tie/null policies and both Admin route spellings remain. The default
Firebase-emulator profile preserves its former non-empty-expression refusal; the new
filter semantics are not silently forced onto that profile. Unfiltered count remains
constant-time; paged UID filtering streams matching records, and other sorts hold at
most `min(N, offset+limit)+1` borrowed candidates. Large offset can still retain N keys.

The common local corpus has 42 account inputs; a native handler test runs each on
both route spellings. Python checks validate only the generated inputs and their
local expectations, not AuthStore or REST execution.

## AUTH-FEDERATION implementation

`IdpContinuationPolicy` is separate from query paging. `Disabled` preserves the
emulator response shape and refuses non-null pendingToken instead of ignoring it.
`LocalBounded` is wired into the strict daemon profile and is available to explicit
embedders. Adding this field to AuthState requires Rust embedders constructing a
literal to choose the policy; repository literals have been updated.

An enabled signInWithIdp can retain original requestUri/postBody under an opaque
handle after a successful or needConfirmation response. The cache does not retain a
linking user's `idToken` or the previous caller's response flags. Every continuation
uses the **current** request's link token, permission checks, quota admission and
blocking-hook path. A continuation is reusable before expiry, not one-shot; repeating
it does not extend its lifetime. Lack of cache space omits the optional response field
rather than reporting an error after account mutation or evicting a live credential.

The local limits are 300 seconds, 256 handles per namespace, 65536 bytes of assertion
request plus authority per entry, and 1048576 logical aggregate bytes including
conservative overhead. These are not service quotas or production token lifetimes.
The default snapshot and export views strip this cache. Restore and reset invalidate
it. Debug output reports only count/size, not handles or raw assertions. Heap strings
are not promised to be cryptographically zeroized on release.

Handles bind the namespace, live reset generation, original credential/authority
hash and existing local identifier stream. Including the generation prevents a
rewound snapshot RNG from reassigning an old token. Including assertion material
prevents equal public seeds alone from aliasing different cached signed assertions.
These remain process-local emulator capabilities, not production token verification.

Fixture and caller-pinned signed-OIDC paths have different authority identifiers;
the signed identifier also binds the project, tenant, provider, issuer, audience and
public JWK. A continuation cannot move between these modes or trust pins. Signed
replay re-verifies the original signature and time claims and checks the current
provider configuration. It does not cache a permanent verification success.

The original requestUri must match exactly. Mixing a pendingToken with a fresh
postBody or deprecated pendingIdToken is refused. An unknown token never falls back
to supplied credentials. This is a bounded credential flow, not full createAuthUri
redirect/session/authorization-code support.

SAML handling still accepts only an explicitly fake **JSON** fixture. It now rejects
non-object assertion/subject, empty/non-string/control-character nameId, and malformed
attributeStatements before creating an account. Eleven shared JSON shape inputs are
consumed by a native test. **No XML parser, XML Signature validation, assertion replay
cache, metadata/certificate trust, audience/destination/InResponseTo validation, or
real SAML interoperability is implemented by this change.**

The existing signed OIDC mode is caller-pinned RS256 ID-token verification.
`handle_with` and the daemon still use fixture assertions unless the embedding calls
`handle_with_oidc_trust`; strict mode does not secretly configure a real issuer trust
store. Signed verification is not broadened to unverified access/refresh tokens.

## Required native acceptance (not run in this environment)

Use the repository's pinned Rust toolchain and locked dependencies. Keep new evidence
outside the worktree. Do not push, merge, access production, or replace old receipts.

```sh
cargo test --locked -p fireemu-core-auth --test admin_query_expression --test federation_continuations
cargo test --locked -p fireemu-core-auth --test transient
cargo test --locked -p fireemu-adapter-http --test identity_toolkit --test auth_flows --test auth_oidc_assertions
cargo test --locked -p fireemu-adapter-http --test signing --test app_check --test app_check_auth
cargo test --locked -p fireemu-adapter-ui --test ui
cargo check --locked --workspace --all-targets
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
```

The new tests cover filtering/ordering/count/authorization, typed refusal, namespace
and generation binding, no cached link authority, current blocking/provider checks,
assertion expiry and trust-pin rejection, cache limits, debug redaction and snapshot
invalidation. They must actually compile and run before accepting these claims.
Python execution of the preparation corpus is not a substitute.

## Remaining non-production obligations

| Parent | Still required |
|---|---|
| AUTH-ACCOUNT | Compile/run this change and inherited v7 sorts; reconcile errors found by native tests. Resolve/document match/combination/precedence details against permissible immutable references. Exercise final-artifact lifecycle, import/export/hash, link/unlink, provider/policy, atomicity and client/Admin SDK. |
| AUTH-FEDERATION | Compile/run continuation and existing signed-OIDC tests. Implement remaining real signed-XML SAML and redirect/session/authorization-code flow or retain them as explicit open conditions. Integrate trusted issuer verification beyond the existing bounded embedder path; test all declared providers and link/collision/tenant/policy cases with final artifact and SDK. Deprecated pendingIdToken remains a legacy compatibility question, not the new pendingToken feature. |
| Common | New local native artifact/shadows and exact source/config/collector/comparator bindings; saved immutable production-reference replay without new production requests; full workspace/compatibility/SDK/formal regressions and independent correctness/security review. |

Existing complete or failed observations are not edited to match this source. Native
source changes invalidate earlier local-artifact bindings where their contract says
so. New source hashes alone do not prove a new execution. Parent completion remains
unaccepted; excluded/new production observation is not used as a label for local work.
