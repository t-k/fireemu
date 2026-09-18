# AUTH-CREDENTIAL-TOKENS-01 preparation

Status: `PREPARATION`. `productionExecuted=false`. Nothing here holds a production receipt, and production-unobserved conditions reduced by this package: 0.

This lane prepares a bounded production observation of the `AUTH-CREDENTIAL` conditions that existing evidence explicitly excludes: refresh-token timestamp preservation, the same-second revocation boundary, session-cookie duration bounds and claim composition, custom-token developer and reserved claims, and ID-token claim precedence. The published [revision 2 session observations](../../../docs/compatibility/auth-session-v2.md) already cover password-change revocation at 0/10/30-second offsets and the malformed and unknown refresh controls; those rows appear here only as controls and are marked with the evidence that already covers them.

## Files

| File | What it holds |
| --- | --- |
| `credential_cases.py` | The 17 observation cases with their expected local results, boundary controls and prior-evidence references. Logical inputs only: no host, key or account identifier. |
| `credential_collector.py` | Redaction, owned-resource tracking, cleanup accounting, enforced budget and receipt assembly. Imports no network client, so it cannot make a request. |
| `credential_comparator.py` | The `auth-credential-tokens-v1` comparison contract. Fail-closed, and it never claims parity. |
| `credential_plan.py` | The inert campaign manifest: frozen inputs, budget, permission envelope, owner preconditions, cleanup contract and failure rehearsal. |
| `credential_shadow.py` | The local shadow. It owns a `fireemu` process, runs every case against it and records what the local runtime does. Local evidence only. |

## Two rules that carry the weight

The local runtime issues unsigned emulator tokens; production issues signed ones. A trust-root difference is therefore expected and is never counted as a semantic difference, though both roots are recorded.

The same-second boundary is classified `EXPECTED_NONDETERMINISM` unless both sides recorded that they pinned it from server-reported values: the token's own `auth_time` read back, `validSince` set to exactly that whole second, and that value confirmed by an admin readback. The boundary row is further reduced to `INDETERMINATE` whenever either neighbouring control failed, because a refusal below and an acceptance above are what place the boundary.

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
