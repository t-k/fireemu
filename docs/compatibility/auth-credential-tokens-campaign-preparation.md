# AUTH-CREDENTIAL token and session-cookie campaign preparation

Status: `PREPARATION`. `productionExecuted=false`. Production-unobserved conditions reduced: 0.

This page prepares a bounded production observation for the `AUTH-CREDENTIAL` conditions that the inventory row still lists as required. Nothing here is a production observation, a comparison result or an approval. No credential was acquired and no production service was contacted. The `AUTH-CREDENTIAL` status in [the goal inventory](ip-fs-production-compatibility.md) stays `IMPLEMENTING`.

## What is already observed, and what is not

The published [revision 2 session observations](auth-session-v2.md) and their [production recheck](auth-session-v2-production-recheck.md) cover a password change revoking frozen ID and refresh credentials at 0, 10 and 30-second offsets, with malformed and unknown refresh controls, across 34 rows that compared as 34 matches. The [continuity control](auth-session-continuity.md) covers the same shapes with no credential mutation. The [MFA pending-credential slice](auth-pending-revocation.md) observed one held pending credential accepted after a `validSince` update two seconds earlier.

Those pages state their own exclusions, and this campaign takes exactly those: the same-second boundary, session cookies, custom tokens, refresh timestamp preservation, and claim precedence. Two rows here repeat existing evidence deliberately, as controls that prove the run reached a real service; they name the page that already covers them.

## The seventeen cases

Cases are grouped, and each group stays contiguous so a partial run is visibly partial. Every row states the expected local result; the production column is `UNOBSERVED` for all seventeen.

| Group | Cases | The question |
| --- | ---: | --- |
| refresh | 3 | Does a refresh exchange keep the originating session's `auth_time` while `iat` and `exp` advance, including on a second exchange? |
| revocation | 3 | What happens to a session whose `auth_time` falls exactly on the recorded `validSince` whole second, with a refusal below and an acceptance above? |
| session-cookie | 7 | Are the five-minute and two-week bounds exact, what does an omitted duration yield, and what claims does the cookie carry? |
| custom-token | 3 | Do developer claims reach the ID token, and are a reserved claim name and an expired custom token refused? |
| claim-precedence | 1 | After an account claim is added under the same name as a session claim, which one does a refresh report? |

## The same-second boundary

This is the condition the inventory row names first, and it is the one a careless run reports wrongly. The design pins the boundary from server-reported values rather than from the collector's own clock: sign in, read the issued token's own `auth_time` back, set `validSince` to exactly that whole second, and confirm the stored value with an admin readback. Only when all three agree is the row a boundary observation.

When the boundary cannot be pinned, the comparison contract classifies the row `EXPECTED_NONDETERMINISM`. That is not a match and not a difference: the run observed something real, but not the boundary. The row is further reduced to `INDETERMINATE` whenever either neighbouring control failed, because a refusal below the boundary and an acceptance above it are what place it at all.

## Trust roots

The local runtime issues unsigned emulator tokens and unsigned session cookies; production issues signed ones. The comparison contract therefore excludes the trust root and the signing algorithm from semantic equality and reports the roots observed on each side separately. A trust-root difference is never counted as a semantic difference, and the campaign makes no claim about signature validity or key rotation on either side.

Absolute server-reported seconds are recorded for review and excluded from equality as well, because two services never agree on a wall-clock second.

## Budget, bounds and cleanup

The run creates at most four throwaway accounts, all carrying the run nonce in their address, and performs at most sixty requests within ten minutes. The request and wall-clock bounds are enforced in code rather than declared, and the cost ceiling is checked when the budget is created.

Identity Platform bills monthly active users rather than requests, and these accounts are deleted inside the run, so the expected charge is zero. The US$0.05 ceiling is a guard against a runaway loop, not a forecast.

Cleanup registers every account before it is used, then deletes each one and reads back both its UID and its address as absent. A delete without a readback is not cleanup, and a cleanup failure fails the run rather than becoming a warning. The campaign changes no project or tenant configuration, so there is nothing to restore.

Five failure modes are rehearsed in the manifest: an exhausted budget, a refused privileged call, a refused cleanup, a process killed between sign-in and cleanup, and a boundary that cannot be pinned.

## Owner preconditions

The campaign cannot run until an owner supplies all of these. The first is the substantial one.

1. A service account in the oracle project able to mint RS256 custom tokens for it, through a key file or `iam.serviceAccounts.signBlob` on itself. Local custom tokens are unsigned, so the custom-token and claim-precedence groups cannot run without it.
2. An OAuth access token scoped for Identity Toolkit, for the privileged account update, lookup and session-cookie calls.
3. A Web API key for the same project, for sign-in and the secure-token exchange.
4. Confirmation that the project's Identity Platform tier makes the budgeted requests non-billable, or an accepted charge.
5. Confirmation that the throwaway address domain is accepted by production sign-up. The local runtime accepting it proves nothing about production.
6. A fresh unused 32-character hexadecimal nonce and a validity window.

An owner permission must use `kind=owner-execution-permission` and carry the campaign, the frozen commit, the manifest digest, the comparison contract, the project identity, the nonce, the validity window, the budget and the recovery terms. The prepared package is never itself the permission, and a nonce checked here proves syntax only.

## Local shadow

The campaign was run in full against a `fireemu` built from this checkout. All seventeen cases agreed with their declared expected local results, the owned process stopped with no surviving child, and all three owned accounts were deleted with both the UID and the address confirmed absent. The record is [`auth-credential-tokens-local-shadow-20260918.json`](../../spec/compatibility/broad-runs/auth-credential-tokens-local-shadow-20260918.json), which binds the artifact digest and the asserted source commit.

This is local evidence and nothing more. It shows the expected local results in the case list are the runtime's actual behavior rather than a reading of the source, which is what makes a future production comparison meaningful. It establishes no production behavior and promotes no group.

One caution belongs on the record. The first shadow attempt used a `fireemu` binary built from the repository's main branch and reported that a refresh advanced `auth_time` along with `iat`. That binary predates `e90f3e27f fix(auth): preserve auth time across refresh`, which is present in this checkout. A parity conclusion drawn from a binary built at a different commit describes that commit, not this one.

## Verification

```sh
uv run --python 3.12 --with pytest pytest -q tools/compat-broad/auth-credential-tokens
uvx ruff check tools/compat-broad/auth-credential-tokens
cargo build -p fireemu
uv run --python 3.12 python tools/compat-broad/auth-credential-tokens/credential_shadow.py \
  --binary target/debug/fireemu --commit "$(git rev-parse HEAD)" \
  --output /absolute/private/credential-shadow.json
```

The tool package and its per-file contract are described in [its README](../../tools/compat-broad/auth-credential-tokens/README.md).
