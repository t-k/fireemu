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

When the boundary cannot be pinned, the comparison contract classifies the row `EXPECTED_NONDETERMINISM`. That is not a match and not a difference: the run observed something real, but not the boundary. Pinning is judged from the recorded seconds rather than from the collector's own claim, so a row reporting `auth_time` and `validSince` two seconds apart is unpinned however it labelled itself.

Each control declares the outcome it must produce: the older session refused below, the newer session accepted above. The comparator checks both on each side independently before it reads the boundary row, and only then checks that the two sides agreed. Two sides that both accepted the older session agree with each other and have placed no boundary at all, so that row is `INDETERMINATE`.

Which refusal counts is part of the control. Identity Toolkit answers `accounts:lookup` and `projects.createSessionCookie`, and the secure-token endpoint answers a refresh, with a 400 carrying `TOKEN_EXPIRED` when the token's `auth_time` precedes `validSince`, and `USER_DISABLED` when the account itself was disabled; those are the refusals that say the presented session is no longer honoured. Every other refusal is about something else. `INVALID_ID_TOKEN` and `INVALID_REFRESH_TOKEN` say the token was never valid, a 401 says the caller was not authenticated, a 403 says a permission was denied, a 429 says the service declined to answer and a 5xx says it failed. Each of those is recorded and compared as data, and none of them places the boundary, so a same-second row that depends on one is `INDETERMINATE` even when both sides refused identically. An operation with no documented expiry refusal places no boundary at all.

## Trust roots

The local runtime issues unsigned emulator tokens and unsigned session cookies; production issues signed ones. The comparison contract therefore excludes the trust root and the signing algorithm from semantic equality and reports the roots observed on each side separately. A trust-root difference is never counted as a semantic difference, and the campaign makes no claim about signature validity or key rotation on either side.

Absolute server-reported seconds are recorded for review and excluded from equality as well, because two services never agree on a wall-clock second.

## Budget, bounds and cleanup

The run creates at most four throwaway accounts, all carrying the run nonce in their address, and performs at most sixty requests within ten minutes. The request and wall-clock bounds are enforced in code rather than declared, and the cost ceiling is checked when the budget is created.

Each request is reserved against the bound before it is sent, so an exhausted budget costs nothing further; the wall time it took is charged afterwards and never discards a response already received, because a sign-up whose result is thrown away leaves a live account nothing knows about. Twelve of the sixty requests and sixty of the six hundred seconds are held back from the run as a recovery reserve, so cleanup can still delete and read back every account whatever stopped the run. The reserve is carved out of the declared total rather than added to it.

The ten minutes are an absolute deadline taken from a monotonic reading when the run starts, not a sum of request durations. Time spent between requests is the campaign's time exactly as a slow response is: a machine that pauses for ten minutes between two cases has spent the bound, and only a deadline can see that. The observation phase runs until the total less the reserve, five hundred and forty seconds; recovery gets the reserved sixty seconds from the moment it starts and never a second past the total, because the total is the bound the run was approved against. Every wait is checked against the phase deadline, so a stall during a wait opens no further observation and hands the run to recovery. Each request is capped to the time its phase has left rather than a fixed transport timeout, so a call started just inside the deadline cannot be what carries the run past it. The receipt records which phase a deadline stopped, at what elapsed time and against what limit, and when recovery began; these are separate members, because reaching the observation deadline and reaching the total are separate facts. A run that has already spent the total deletes nothing, keeps every account it created in its journal and says so in the receipt: an incomplete cleanup with the accounts still listed is the honest outcome, and the journal is the recovery input.

Identity Platform bills monthly active users rather than requests, and these accounts are deleted inside the run, so the expected charge is zero. The US$0.05 ceiling is a guard against a runaway loop, not a forecast.

Whether the recording is complete and whether the cleanup is complete are separate facts on the receipt. A run that stops part way still cleans up after itself, and a clean cleanup has never been evidence that every case was observed, so each row states for itself whether anything was observed and the comparator re-derives that rather than trusting the receipt's own boolean. Rows marked `NOT_RUN` are classified `INDETERMINATE`.

Cleanup registers every account before it is used, then deletes each one and proves absence from a 200 lookup whose result is empty. A refusal carries no result member either, so a non-200 status is never read as absence; any non-200 delete or lookup leaves the account outstanding and the receipt incomplete. An account created by custom-token sign-in has no address, so no address readback is claimed for it. A cleanup failure fails the run rather than becoming a warning. The campaign changes no project or tenant configuration, so there is nothing to restore.

Seven failure modes are rehearsed in the manifest: an exhausted budget, a refused privileged call, a refused cleanup, a process killed between sign-in and cleanup, a boundary that cannot be pinned, a deadline passed during a request or a wait, and a control refused for a reason that is not the documented expiry.

## Owner preconditions

The campaign cannot run until an owner supplies all of these. The first is the substantial one.

1. A service account in the oracle project able to mint RS256 custom tokens for it, through a key file or `iam.serviceAccounts.signBlob` on itself. Local custom tokens are unsigned. Eleven of the seventeen cases depend on this: the custom-token and claim-precedence groups directly, and the whole session-cookie group because it derives its cookie from the custom-token session. Each case carries a `requiresSigning` flag, so the split is mechanical rather than editorial.
2. An OAuth access token scoped for Identity Toolkit, for the privileged account update, lookup and session-cookie calls.
3. A Web API key for the same project, for sign-in and the secure-token exchange.
4. Confirmation that the project's Identity Platform tier makes the budgeted requests non-billable, or an accepted charge.
5. Confirmation that the throwaway address domain is accepted by production sign-up. The local runtime accepting it proves nothing about production.
6. A fresh unused 32-character hexadecimal nonce and a validity window.

An owner permission must use `kind=owner-execution-permission` and carry the campaign, the frozen commit, the manifest digest, the comparison contract, the project identity, the nonce, the validity window, the budget and the recovery terms. The prepared package is never itself the permission, and a nonce checked here proves syntax only.

## Local shadow

The campaign was run in full against a `fireemu` built from this checkout. All seventeen cases agreed with their declared expected local results, and the owned process stopped with none of the children it had before the signal surviving. All three owned accounts were deleted, each proved absent by a 200 lookup with an empty result. Two of them had an address and contributed an address readback; the custom-token account has no address, so none is claimed for it. The record is [`auth-credential-tokens-local-shadow-20260918.json`](../../spec/compatibility/broad-runs/auth-credential-tokens-local-shadow-20260918.json), which binds the artifact digest, the asserted source commit and the collector module digests. It was regenerated after each independent review, most recently after the second, so it records the current code rather than any version reviewed; each earlier run is superseded, not amended. The record now also carries the campaign's deadlines: which phase, if any, one of them stopped, and the elapsed time at which recovery began.

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
