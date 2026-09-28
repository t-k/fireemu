# Auth administrator query: local field ordering (offline continuation)

Status: **implementation added, native execution pending**. This does not close
`AUTH-ACCOUNT`, establish production equivalence, or authorize any production request.

## Implemented surface

Strict (`AuthQueryLimits::ProductionBounded`) `accounts:query` now dispatches the
published `NAME`, `CREATED_AT`, `LAST_LOGIN_AT`, and `USER_EMAIL` sorts, in addition to
`USER_ID`/the unspecified default. Both ascending and descending orders apply before
offset/limit. `projects/{project}:queryAccounts` is registered in the central route
table as an alias of the existing administrator operation. It uses the same owner,
origin, method, namespace, and bounded observation label checks. The existing
`projects/{project}/tenants/{tenant}/accounts:query` remains tenant-scoped. Strict
project queries also honor the documented body `tenantId`, reject malformed
selectors and path/query/body conflicts, and never substitute the default store
for a missing requested tenant. Other operations and Firebase-profile selector
rules are unchanged.

`limit` still defaults to 500 and cannot exceed 500 at the adapter boundary.
`recordsCount` is the returned page length when records are requested, and the total
count when `returnUserInfo` is false. The latter still rejects non-null offset/limit.
No new credential, callback, request, index, or persistent state is created by sorting.

The Firebase-emulator profile deliberately keeps its existing UID ordering and
ignored paging/sort fields. No compatibility profile is silently redefined.

## Bounded local implementation and unobserved policy

The core retains the existing local-ID iterator fast path. Other fields scan the
selected immutable store once and keep at most `min(N, offset + limit) + 1` borrowed
candidates. Addition saturates, and an out-of-range offset or zero limit returns
immediately. Neither a full account record nor credential payload is copied into
sorting state. The output page contains borrowed records. Work is O(N log K), where
K is the retained prefix; no claim of an indexed constant-time query is made.

Names and emails use bytewise string ordering. Missing values precede present values
(including the empty string) in ascending order. Equal primary keys use UID as the
tie-breaker; descending reverses the full ordering, including this tie-breaker.
Timestamp keys use the same millisecond truncation as `createdAt`/`lastLoginAt` in the
response, rather than exposing hidden nanosecond differences.

Those collation, missing-value and tie rules are **explicit local policy**. The public
enum descriptions identify the sort fields but do not establish all these edge
cases. They require separately authorized finite production observations before a
parity claim. These rules are not a manufactured oracle.

## Filtering is still incomplete

Nonempty `expression` arrays still return the explicit unsupported response. This
change does not invent AND/OR, wildcard, matching, or historical first-expression
semantics. In strict mode, a non-null, non-array `expression` is now rejected as a
malformed request instead of accidentally becoming an unfiltered query. Missing,
null and empty-array forms retain the previous unfiltered behavior.

## Native regression coverage added (not executed here)

`crates/fireemu-core-auth/tests/admin_query.rs` covers every field and direction,
pages against manually specified whole orders, zero limits, empty stores, saturating
bounds, field updates/deletion, read-only behavior, timestamp precision and selecting
past the first UID page. Adapter tests cover both route spellings, tenant isolation,
count/page distinctions, unsupported filters, Firebase-profile behavior and access
refusals. The route-table test checks alias classification and method refusal.

The environment for this continuation has no Rust compiler or cargo. These Rust
cases have not been compiled or executed. Python/Bash tests of the reporting gate
must not be presented as their execution evidence.

Run in the pinned Rust environment, with a fresh evidence path:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
scripts/local-regression-gate --session auth-query --report docs.local/gates/auth-query-NEW.json -- \
  -p fireemu-core-auth -p fireemu-adapter-http
```

## Public contract consulted (2026-09-19)

- [SortByField](https://docs.cloud.google.com/identity-platform/docs/reference/rest/v1/SortByField)
- [Order](https://docs.cloud.google.com/identity-platform/docs/reference/rest/v1/Order)
- [projects.accounts.query](https://docs.cloud.google.com/identity-platform/docs/reference/rest/v1/projects.accounts/query)
- [projects.queryAccounts](https://docs.cloud.google.com/identity-platform/docs/reference/rest/v1/projects/queryAccounts)
- [QueryUserInfoResponse](https://docs.cloud.google.com/identity-platform/docs/reference/rest/v1/QueryUserInfoResponse)
- [SqlExpression](https://docs.cloud.google.com/identity-platform/docs/reference/rest/v1/SqlExpression)

Reading this public documentation is not a production Identity Platform API call.
