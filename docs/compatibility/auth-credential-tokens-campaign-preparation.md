# AUTH-CREDENTIAL token and session-cookie campaign preparation

Status: `SUPERSEDED`. This preparation was never executed. The disposable Identity Platform sandbox track replaced it on 2026-09-24: [`spec/compatibility/closure/AUTH-CREDENTIAL.json`](../../spec/compatibility/closure/AUTH-CREDENTIAL.json) freezes the parent's conditions, and `conformance/auth-credential-production.json` holds the two production recordings of each program. Every case below is covered there, including the same-second boundary, session-cookie bounds, signed custom tokens (through IAM `signJwt`), refresh `auth_time` preservation and claim precedence. The text below is kept as it was written.

Original status: `PREPARATION`. `productionExecuted=false`. Production-unobserved conditions reduced: 0.

This page prepares a bounded production observation for the `AUTH-CREDENTIAL` conditions that the inventory row still lists as required. Nothing here is a production observation, a comparison result or an approval. No credential was acquired and no production service was contacted. The `AUTH-CREDENTIAL` status in [the goal inventory](ip-fs-production-compatibility.md) stays `IMPLEMENTING`.

## What is already observed, and what is not

The published [revision 2 session observations](auth-session-v2.md) and their [production recheck](auth-session-v2-production-recheck.md) cover a password change revoking frozen ID and refresh credentials at 0, 10 and 30-second offsets, with malformed and unknown refresh controls, across 34 rows that compared as 34 matches. The [continuity control](auth-session-continuity.md) covers the same shapes with no credential mutation. The [MFA pending-credential slice](auth-pending-revocation.md) observed one held pending credential accepted after a `validSince` update two seconds earlier.

Those pages state their own exclusions, and this campaign takes exactly those: the same-second boundary, session cookies, custom tokens, refresh timestamp preservation, and claim precedence. Two rows here repeat existing evidence deliberately, as controls that prove the run reached a real service; they name the page that already covers them.

## The nineteen cases

Cases are grouped, and each group stays contiguous so a partial run is visibly partial. Every row states the expected local result; the production column is `UNOBSERVED` for all nineteen. The last group folds in the two refresh refusal-class rows of TP-AUTH-C-02, each carrying a fresh-session control: after the stale refresh token is refused, a fresh sign-in on the same account is exchanged once more and must be accepted, so the refusal is shown to be about the stale credential rather than about the account. The comparator reads the control on both sides before it reads the refusal code, and a row whose control did not hold on either side is `INDETERMINATE`.

| Group | Cases | The question |
| --- | ---: | --- |
| refresh | 3 | Does a refresh exchange keep the originating session's `auth_time` while `iat` and `exp` advance, including on a second exchange? |
| revocation | 3 | What happens to a session whose `auth_time` falls exactly on the recorded `validSince` whole second, with a refusal below and an acceptance above? |
| session-cookie | 7 | Are the five-minute and two-week bounds exact, what does an omitted duration yield, and what claims does the cookie carry? |
| custom-token | 3 | Do developer claims reach the ID token, and are a reserved claim name and an expired custom token refused? |
| claim-precedence | 1 | After an account claim is added under the same name as a session claim, which one does a refresh report? |
| refresh-refusal | 2 | Which refusal does a stale refresh token receive after an out-of-band password reset, and after an explicit administrative `validSince` two seconds after sign-in? The local strict runtime removes the session in both cases and answers `INVALID_REFRESH_TOKEN`; production is expected to answer `TOKEN_EXPIRED`, and a `DIFFERENT` row here is the finding. |

## The same-second boundary

This is the condition the inventory row names first, and it is the one a careless run reports wrongly. The design pins the boundary from server-reported values rather than from the collector's own clock: sign in, read the issued token's own `auth_time` back, set `validSince` to exactly that whole second, and confirm the stored value with an admin readback. Only when all three agree is the row a boundary observation.

When the boundary cannot be pinned, the comparison contract classifies the row `EXPECTED_NONDETERMINISM`. That is not a match and not a difference: the run observed something real, but not the boundary. Pinning is judged from the recorded seconds rather than from the collector's own claim, so a row reporting `auth_time` and `validSince` two seconds apart is unpinned however it labelled itself.

Each control declares the outcome it must produce: the older session refused below, the newer session accepted above. The comparator checks both on each side independently before it reads the boundary row, and only then checks that the two sides agreed. Two sides that both accepted the older session agree with each other and have placed no boundary at all, so that row is `INDETERMINATE`.

Which refusal counts is part of the control. Identity Toolkit answers `accounts:lookup` and `projects.createSessionCookie`, and the secure-token endpoint answers a refresh, with a 400 carrying `TOKEN_EXPIRED` when the token's `auth_time` precedes `validSince`, and `USER_DISABLED` when the account itself was disabled; those are the refusals that say the presented session is no longer honoured. Every other refusal is about something else. `INVALID_ID_TOKEN` and `INVALID_REFRESH_TOKEN` say the token was never valid, a 401 says the caller was not authenticated, a 403 says a permission was denied, a 429 says the service declined to answer and a 5xx says it failed. Each of those is recorded and compared as data, and none of them places the boundary, so a same-second row that depends on one is `INDETERMINATE` even when both sides refused identically. An operation with no documented expiry refusal places no boundary at all. The codes come from the error tables the Firebase Auth REST API publishes for the Identity Toolkit `accounts:lookup` and `projects.createSessionCookie` methods and for the secure-token `token` exchange; the production run is what confirms them for the oracle project, and a refusal that does not appear there is data rather than a boundary.

## Trust roots

The local runtime issues unsigned emulator tokens and unsigned session cookies; production issues signed ones. The comparison contract therefore excludes the trust root and the signing algorithm from semantic equality and reports the roots observed on each side separately. A trust-root difference is never counted as a semantic difference, and the campaign makes no claim about signature validity or key rotation on either side.

Absolute server-reported seconds are recorded for review and excluded from equality as well, because two services never agree on a wall-clock second.

Every issued token's claim set, its claim names and types at the top level and under `firebase`, is recorded on the row and compared. The local runtime may add `firebase.fireemu_session_epoch`, a private session marker production never issues; the comparator strips it from both sides before judging equality, so a local token carrying it and a production token without it still match on everything else, while any other claim name or type that differs remains a semantic mismatch. The rule is `credential_comparator.strip_local_only_claims`, and the local-only list is `credential_cases.LOCAL_ONLY_CLAIMS`.

## Budget, bounds and cleanup

The run creates at most four throwaway accounts, all carrying the run nonce in their address, and performs at most sixty requests. The time it is approved for is five hundred and forty seconds of observation plus up to sixty seconds of cleanup, which an undisturbed run fits inside ten minutes. The request and wall-clock bounds are enforced in code rather than declared, and the cost ceiling is checked when the budget is created.

Each request is reserved against the bound before it is sent, so an exhausted budget costs nothing further; the wall time it took is charged afterwards and never discards a response already received, because a sign-up whose result is thrown away leaves a live account nothing knows about. Twelve of the sixty requests and sixty of the six hundred seconds are held back from the run as a recovery reserve, so cleanup can still delete and read back every account whatever stopped the run. The reserve is carved out of the declared total rather than added to it.

Those bounds are absolute deadlines taken from a monotonic reading when the run starts, not a sum of request durations. Time spent between requests is the campaign's time exactly as a slow response is: a machine that pauses for ten minutes between two cases has spent the bound, and only a deadline can see that.

The two phases are declared separately rather than as one total, because a clock cannot be held back the way a request counter can. The observation phase runs until the total less the reserve, five hundred and forty seconds. The cleanup tail then gets its sixty seconds from the moment it starts, granted absolutely, however the observation phase ended. A reserve trimmed to what was left of a total would be empty exactly when it is needed most, which is the run that stalled and stopped late with its accounts already created and nothing else to delete them. What an owner approves is therefore a bounded observation plus a bounded tail, and a run stopped by its own deadline still cleans up after itself. The tail is bounded in its turn, by its own deadline and by the twelve requests held back for it, so it cannot become an unbounded run of its own.

Every wait is checked against the phase deadline, so a stall during a wait opens no further observation and hands the run to cleanup. Each request is capped to the time its phase has left rather than a fixed transport timeout, so a call started just inside a deadline cannot be what carries the run past it. The receipt records which phase a deadline stopped, at what elapsed time and against what limit, when cleanup began and where its own window ended; these are separate members, because reaching the observation deadline and running out of cleanup time are separate facts.

Identity Platform bills monthly active users rather than requests, and these accounts are deleted inside the run, so the expected charge is zero. The US$0.05 ceiling is a guard against a runaway loop, not a forecast.

Whether the recording is complete and whether the cleanup is complete are separate facts on the receipt. A run that stops part way still cleans up after itself, and a clean cleanup has never been evidence that every case was observed, so each row states for itself whether anything was observed and the comparator re-derives that rather than trusting the receipt's own boolean. Rows marked `NOT_RUN` are classified `INDETERMINATE`.

Cleanup registers every account before it is used, then deletes each one and proves absence from a 200 lookup whose result is empty. A refusal carries no result member either, so a non-200 status is never read as absence; any non-200 delete or lookup leaves the account outstanding and the receipt incomplete. An account created by custom-token sign-in has no address, so no address readback is claimed for it. A cleanup failure fails the run rather than becoming a warning. The campaign changes no project or tenant configuration, so there is nothing to restore.

Seven failure modes are rehearsed in the manifest: an exhausted budget, a refused privileged call, a refused cleanup, a process killed between sign-in and cleanup, a boundary that cannot be pinned, a deadline passed during a request or a wait, and a control refused for a reason that is not the documented expiry.

## Owner preconditions

The campaign cannot run until an owner supplies all of these. The first is the substantial one.

1. A service account in the oracle project able to mint RS256 custom tokens for it, through a key file or `iam.serviceAccounts.signBlob` on itself. Local custom tokens are unsigned. Eleven of the nineteen cases depend on this: the custom-token and claim-precedence groups directly, and the whole session-cookie group because it derives its cookie from the custom-token session. Each case carries a `requiresSigning` flag, so the split is mechanical rather than editorial.
2. An OAuth access token scoped for Identity Toolkit, for the privileged account update, lookup and session-cookie calls.
3. A Web API key for the same project, for sign-in and the secure-token exchange.
4. Confirmation that the project's Identity Platform tier makes the budgeted requests non-billable, or an accepted charge.
5. Confirmation that the throwaway address domain is accepted by production sign-up. The local runtime accepting it proves nothing about production.
6. A fresh unused 32-character hexadecimal nonce and a validity window.

An owner permission must use `kind=owner-execution-permission` and carry the campaign, the frozen commit, the manifest digest, the comparison contract, the project identity, the nonce, the validity window, the budget and the recovery terms. The prepared package is never itself the permission, and a nonce checked here proves syntax only.

## Local shadow

The campaign was run in full against a `fireemu` built from this checkout. All nineteen cases agreed with their declared expected local results over forty-two requests, and the owned process stopped with none of the children it had before the signal surviving. All three owned accounts were deleted, each proved absent by a 200 lookup with an empty result. Two of them had an address and contributed an address readback; the custom-token account has no address, so none is claimed for it. The current record is [`auth-credential-tokens-local-shadow-20260923.json`](../../spec/compatibility/broad-runs/auth-credential-tokens-local-shadow-20260923.json), which binds the artifact digest, the asserted source commit and the collector module digests, including the ID-token-sub custom identity projection and the `idTokenMatchesAccount` measurement on the three refresh rows. `test_credential_shadow_record.py` fails as soon as a bound module is edited after the run, which is the signal to regenerate it. Earlier records are kept byte-identical as superseded runs; each earlier run is superseded, not amended.

This is local evidence and nothing more. It shows the expected local results in the case list are the runtime's actual behavior rather than a reading of the source, which is what makes a future production comparison meaningful. It establishes no production behavior and promotes no group.

One caution belongs on the record. The first shadow attempt used a `fireemu` binary built from the repository's main branch and reported that a refresh advanced `auth_time` along with `iat`. That binary predates `e90f3e27f fix(auth): preserve auth time across refresh`, which is present in this checkout. A parity conclusion drawn from a binary built at a different commit describes that commit, not this one.

## O8 launch path

The lane declares itself to the shared O8 admission core through `credential_descriptor.py` (a `CampaignDescriptor` with every member real), freezes its inputs and validates the owner permission and approval through `credential_admission.py`, and executes through `credential_o8.py`. The frozen plan is a reference to the shared-Gate plan `credential_gate.py` compiles from the nonce and the signing capability: every request the case runner makes, in order, with `$binding:` placeholders where a value is only known at run time. A facade over the Gate resolves those placeholders from the run's own responses, settles each slot's creation outcome for an account, and records typed deletion and absence evidence per account. No token, key or password enters the Gate journal or any evidence record; a record that would carry one is refused, never redacted. The private Gate snapshot and the responsibility journal do carry the UIDs and owned addresses of the accounts the run created and deleted, by design, so a stopped run can be recovered; the published receipt carries account counts only.

The credential handoff arrives on a private descriptor after admission, reservation and Gate claim, with the shape `{"kind": "auth-credential-handoff-v1", "permissionDigest", "token", "apiKey", "signing"}`. `token` is an OAuth bearer for the principal frozen in the permission, with the cloud-platform scope, and it must carry `firebaseauth.admin` for the privileged `accounts:update`, `accounts:lookup`, `accounts:sendOobCode`, `accounts:delete` and `:createSessionCookie` calls; `apiKey` is the project's Web API key for the end-user calls; `signing` is either `null` or `{"serviceAccount": "fireemu-oracle@fireemu-35fe6.iam.gserviceaccount.com"}`. With signing, the three custom tokens are minted before the data phase through `iamcredentials.googleapis.com` `signBlob` as charged management slots, which needs `iam.serviceAccounts.signBlob` on that service account for the bearer's principal (`roles/iam.serviceAccountTokenCreator` on the service account); no key is fetched or stored. Without signing the plan is frozen without the eleven signing-dependent cases, the run reaches the eight others, and the eleven are recorded as `NOT_RUN` with the reason `signing capability absent`, never as observed. A handoff whose signing declaration disagrees with the frozen plan is refused before any wire call.

The management preflight charges, through the Gate, the tokeninfo attestation of the bearer against the frozen principal, a project identity readback and an Auth admin config readback whose digest the permission froze; after cleanup the Auth config is read back once more. The campaign changes no project, tenant or MFA configuration. The budget is the lane's: sixty requests, of which forty-two are data slots and up to seven are management slots, four accounts, six hundred seconds with a sixty-second cleanup reserve, and the US$0.05 runaway guard as the cost ceiling. A 401 or 403 on a privileged call latches the bearer: no later privileged call, cleanup included, presents it, the receipt names the stop point `credential-refused` and the accounts that remain, and the reservation stays held for the owner. A refusal on an API-key call is the key's, not the bearer's: the observation stops at `api-key-refused` and cleanup still runs with the bearer under the recovery reserve. Exit codes follow the request-byte lane: 0 means verified cleanup and Ledger release, 1 means the run started and did not complete so the reservation is still held and `receipt.json` names the stop point, 2 means admission refused the run before any wire call (a bearer refused at the tokeninfo preflight also exits 2 with the reservation held and no data call sent).

One thing stops a production launch on the current tree. The shared Ledger's reservation admits only Firestore document resources, and the shared Gate's absence proof is a Firestore typed 404, so `Ledger.reserve` refuses this campaign's account-shaped Gate plan with `canonical Firestore resource required` before any Gate or wire is touched; the lane's tests pin that refusal, and pin alongside it that with a two-function extension of the shared modules, applied to the test process only, a hosted run reserves, reaches every case, cleans up every account, finishes the Gate and releases. The extension is a change to shared modules this lane does not own; it is proposed, not made.

## Verification

```sh
uv run --python 3.12 --with pytest pytest -q tools/compat-broad/auth-credential-tokens
uvx ruff check tools/compat-broad/auth-credential-tokens
cargo build -p fireemu
uv run --python 3.12 python tools/compat-broad/auth-credential-tokens/credential_shadow.py \
  --binary target/debug/fireemu --commit "$(git rev-parse HEAD)" \
  --output /absolute/private/credential-shadow.json
```

The launch, once the shared extension has landed and an O7 package has been reviewed and approved, is the request-byte lane's with this lane's files; the handoff is never on the command line:

```sh
uv run --python 3.12 python $FROZEN/tools/compat-broad/auth-credential-tokens/credential_o8.py \
  --inputs <pkg>/auth-credential-frozen-inputs-v1.json --approval $APPROVAL_DIR/auth-credential-o8-approval-v1.json \
  --manifest <pkg>/auth-credential-o8-manifest-v1.json --permission <pkg>/auth-credential-owner-execution-permission-v1.json \
  --source $FROZEN --artifact <retained fireemu> --ledger <canonical shared Ledger root> \
  --output <fresh dir under docs.local/logs/<date>/> --credential-fd 3  3< <private handoff>
```

The tool package and its per-file contract are described in [its README](../../tools/compat-broad/auth-credential-tokens/README.md).
