# AUTH-CREDENTIAL-TOKENS-01 preparation

Status: `PREPARATION`. `productionExecuted=false`. Nothing here holds a production receipt, and production-unobserved conditions reduced by this package: 0.

This lane prepares a bounded production observation of the `AUTH-CREDENTIAL` conditions that existing evidence explicitly excludes: refresh-token timestamp preservation, the same-second revocation boundary, session-cookie duration bounds and claim composition, custom-token developer and reserved claims, and ID-token claim precedence. The published [revision 2 session observations](../../../docs/compatibility/auth-session-v2.md) already cover password-change revocation at 0/10/30-second offsets and the malformed and unknown refresh controls; those rows appear here only as controls and are marked with the evidence that already covers them.

## Files

| File | What it holds |
| --- | --- |
| `credential_cases.py` | The 17 observation cases with their expected local results, boundary controls and prior-evidence references. Logical inputs only: no host, key or account identifier. |
| `credential_collector.py` | Redaction, subject comparison, owned-resource tracking, cleanup accounting, the reserved budget and receipt assembly. Imports no network client, so it cannot make a request. |
| `credential_comparator.py` | The `auth-credential-tokens-v1` comparison contract. Fail-closed, and it never claims parity. |
| `credential_plan.py` | The inert campaign manifest: frozen inputs, budget, permission envelope, owner preconditions, cleanup contract and failure rehearsal. |
| `credential_shadow.py` | The local shadow. It owns a `fireemu` process, runs every case against it and records what the local runtime does. Local evidence only. |

## Signing dependence

Eleven of the seventeen cases carry `requiresSigning`. Production custom tokens must be RS256-signed by a service account while local ones are unsigned, and the session-cookie group derives its cookie from the custom-token session, so it depends on signing too. A run without signing access can only cover the refresh and revocation groups.

## Three rules that carry the weight

The local runtime issues unsigned emulator tokens; production issues signed ones. A trust-root difference is therefore expected and is never counted as a semantic difference, though both roots are recorded.

The same-second boundary is classified `EXPECTED_NONDETERMINISM` unless both sides recorded that they pinned it from server-reported values: the token's own `auth_time` read back, `validSince` set to exactly that whole second, and that value confirmed by an admin readback. The comparator checks the recorded seconds rather than the pinning flag, so a row claiming a pinned boundary across a two-second gap is unpinned. Each control declares the outcome it must produce, and both are checked on each side independently before the boundary row is read: two sides that both accepted the older session agree with each other and have placed no boundary, so the row is `INDETERMINATE`. A refusal counts only when it is the expiry the endpoint documents, which for the lookup, session-cookie and refresh operations is a 400 carrying `TOKEN_EXPIRED` or `USER_DISABLED`. An `INVALID_ID_TOKEN`, an unauthenticated caller, a denied permission or a rate limit is recorded and compared as data, but it refuses the call for a reason that has nothing to do with the session's age, so it places no boundary and the row above it stays `INDETERMINATE` however well the two sides agreed.

Time is bounded by deadlines taken from a monotonic reading at the start of the run, not by the durations of the requests that were sent. The observation phase may run until the total less the recovery reserve, five hundred and forty seconds, and the cleanup tail then gets the reserved sixty seconds from the moment it starts, granted absolutely however the observation ended. The campaign is declared as that pair rather than as one total, so a run stopped by its own deadline still deletes the accounts it created; the tail is bounded in turn by its own deadline and the requests held back for it. Every wait is checked against the deadline, so a machine that stalls between two cases opens no further observation; each request is capped to the time its phase has left, so a call started just inside the deadline cannot carry the run past it. A response that did arrive is still returned, because discarding it could lose an account the run just created. The receipt records which phase a deadline stopped, when recovery started and what each limit was.

A receipt says separately whether its recording is complete and whether its cleanup is complete. Every row carries its own observed state, and the comparator derives that from the row rather than from the receipt's boolean, so a case nobody ran can never be classified `MATCH`.

## Running the contract checks

```sh
uv run --python 3.12 --with pytest pytest -q tools/compat-broad/auth-credential-tokens
uvx ruff check tools/compat-broad/auth-credential-tokens
```

## Running the local shadow

The shadow needs a `fireemu` binary built from this checkout. A binary from another commit records that commit's behavior, not this one's.

```sh
cargo build -p fireemu
uv run --python 3.12 python tools/compat-broad/auth-credential-tokens/credential_shadow.py \
  --binary target/debug/fireemu --output /absolute/private/credential-shadow.json
```

It starts one strict Auth-only daemon on an OS-assigned port, refuses any non-loopback target, deletes every account it created and reads both the UID and the address back as absent, then stops the process and reports whether any child survived. It exits non-zero when a case disagrees with its declared expected local result.

## What this package does not do

It performs no production request and acquires no credential. A nonce checked here is syntax only. A well-formed owner permission validated by `credential_plan.validate_permission` is still not permission granted by this repository, and the prepared package is never itself the permission.
