# Out-of-band action code campaign preparation

Status: `PREPARATION`. This page describes a prepared, credential-free, production-unobserved campaign. No production operation, Cloud read, credential acquisition or receipt rewrite occurred. `AUTH-ACTION` remains `WAITING_ORACLE`, and the number of production-unobserved conditions this page closes is 0.

## What the row still needs

`AUTH-ACTION` covers verify-email, password reset, email link and change operations, and the ownership, consumption, reuse and expiry of the codes that drive them. Its declared blocker is that the delivery-boundary protocol and representative production code transitions remain unobserved. Existing local evidence is separate and unchanged: the OOB authorization boundary in `tools/auth-oob-authorization/README.md`, the code and error shapes in `conformance/fixtures/auth/oob-code-shapes.json`, and the password-reset trigger corpus in `docs/compatibility/auth-pending-trigger-password-reset.md`. None of those observe what a production backend does to a code across the transitions below.

The campaign identity is `AUTH-ACTION-OOB-DELIVERY-BOUNDARY-01`, already recorded as backlog in the O1 Auth core preparation reports. This page moves it from a named backlog entry to a frozen, reviewable package.

## Delivery boundary

Every code is obtained through the privileged `accounts:sendOobCode` call with `returnOobLink: true`. That request needs a Google OAuth credential authorized on the project, returns the code in the response, and sends no message. The client endpoints then apply the code: `accounts:resetPassword` for lookup and consumption, `accounts:update` with an `oobCode` for verification, and `accounts:signInWithEmailLink` for the email link.

Owned addresses use the reserved `example.invalid` top-level domain. A message that was delivered despite the link-return path would still be undeliverable, so the campaign has no mailbox dependency and no messaging tariff. Both the manifest and every receipt record `deliveredMessages: 0`.

## The finite matrix

Twenty-six ordered wire stages run against two throwaway accounts named by a fresh 32-character hexadecimal nonce. `setup` stages establish state, `diagnostic` stages are the observations, and `control` stages are the positive and negative checks that make a diagnostic readable. The local column is what an owned local artifact actually answered in the shadow described below; the production column is what this campaign exists to find out.

| Stage | Basis | Local status | Local error | Production |
| --- | --- | ---: | --- | --- |
| account-a-create | setup | 200 | none | UNOBSERVED |
| account-b-create | setup | 200 | none | UNOBSERVED |
| reset-link-generate | setup | 200 | none | UNOBSERVED |
| reset-code-lookup | diagnostic | 200 | none | UNOBSERVED |
| reset-weak-password | diagnostic | 400 | WEAK_PASSWORD | UNOBSERVED |
| reset-weak-password-retry | control | 200 | none | UNOBSERVED |
| reset-consume | diagnostic | 200 | none | UNOBSERVED |
| reset-reuse | diagnostic | 400 | INVALID_OOB_CODE | UNOBSERVED |
| reset-wrong-code | control | 400 | INVALID_OOB_CODE | UNOBSERVED |
| reset-link-generate-second | setup | 200 | none | UNOBSERVED |
| admin-password-update | setup | 200 | none | UNOBSERVED |
| reset-after-password-change | diagnostic | 200 | none | UNOBSERVED |
| account-a-readback | control | 200 | none | UNOBSERVED |
| verify-link-generate | setup | 200 | none | UNOBSERVED |
| verify-apply | diagnostic | 200 | none | UNOBSERVED |
| verify-reuse | diagnostic | 400 | INVALID_OOB_CODE | UNOBSERVED |
| verify-wrong-code | control | 400 | INVALID_OOB_CODE | UNOBSERVED |
| email-link-generate | setup | 200 | none | UNOBSERVED |
| email-link-signin | diagnostic | 200 | none | UNOBSERVED |
| email-link-reuse | diagnostic | 400 | INVALID_OOB_CODE | UNOBSERVED |
| email-link-generate-second | setup | 200 | none | UNOBSERVED |
| email-link-mismatched-email | control | 400 | INVALID_OOB_CODE | UNOBSERVED |
| deleted-user-link-generate | setup | 200 | none | UNOBSERVED |
| account-b-delete | setup | 200 | none | UNOBSERVED |
| reset-after-delete | diagnostic | 400 | USER_DISABLED | UNOBSERVED |
| link-generate-unknown-email | diagnostic | 200 | none | UNOBSERVED |

Three local answers are the reason the campaign is worth an owner's budget.

- `reset-after-password-change` succeeds locally. A code issued before an administrative password change still applies afterwards. If the production backend binds a reset code to the password it was issued against, this is a compatibility gap that no local test can currently see.
- `reset-after-delete` is refused locally as `USER_DISABLED`. A deleted owner is not a disabled one, and the production error class for this case is unknown.
- `link-generate-unknown-email` answers 200 with no code locally, for an address that never existed. Whether a privileged link-generation request for an unknown address is answered or refused in production is unknown.

A fourth observation is carried by the readback control rather than by a dedicated stage: after a successful password reset, the local runtime reports the account's email as verified. The readback records that state on both sides, so the production answer is compared rather than assumed.

## Token claims moved from AUTH-CREDENTIAL

AUTH-CREDENTIAL scope decision C7 (owner, 2026-09-24) moves these token-claim conditions here; they are required conditions of this parent and are not verified anywhere else:

- The ID token of an email-link sign-in (`accounts:signInWithEmailLink`) carries the claims production issues, including `firebase.sign_in_provider` and the identities of the address.
- A refresh of that session and a session cookie made from it keep them.

AUTH-CREDENTIAL's harness (`conformance/src/auth-credential/`) records a token as its header shape and every claim, and can be reused for these rows.

## Conditions this campaign does not observe

| Condition | Why it is excluded |
| --- | --- |
| Code expiry | The published lifetime is measured in hours, so expiry cannot fit a bounded single-iteration run. It stays a declared unobserved condition; the campaign does not wait. |
| Delivered messages | Every stage uses the link-return path, so no message reaches a delivery network and no mailbox is read. |
| Hosted action page and `continueUrl` | The browser-facing action page, redirect handling and dynamic-link rewriting are a separate boundary with their own transport. |
| Tenant-scoped codes | Tenant routing has its own campaign and configuration. |
| Blocking functions, SDK surfaces, `VERIFY_AND_CHANGE_EMAIL` | Named out of scope in the package; each needs its own matrix. |

## Bounds, budget and owner preconditions

One serialized worker and at most four requests a second, paced by the collector itself rather than merely published, with 26 observation requests inside a 300-second wall bound and four recovery requests inside a separate 180-second reserve. The reserve is independent on purpose: an exhausted observation budget can never stop the owned accounts from being deleted.

Identity Platform charges monthly active users, not action-code requests, and no message is delivered, so the expected metered cost is US$0.00 against a planning ceiling of US$0.02. Both figures are planning values, not an invoice.

The credential this campaign needs is `roles/firebaseauth.admin` on the single approved project, carrying the `identitytoolkit` scope rather than `cloud-platform`, and exercising only `accounts:sendOobCode`, `accounts:update`, `accounts:lookup` and `accounts:delete`. The owner must still supply, at approval time: that credential; confirmation that the project has no blocking function or tenant that changes these routes; acceptance that two accounts are created and deleted inside the approved window; a fresh unused nonce; a source commit with a built artifact digest bound before the local side is recorded; and acceptance that the reserved `example.invalid` domain is usable for sign-up and link generation on the target project. A refusal of that domain stops the run at its first stage and fails closed, which consumes the approved window without producing an observation. The package supplies none of these, and its `ownerInputs` are all unset.

## Recovery contract

Recovery is keyed on the owned address, not on a runtime identifier. It first looks both addresses up in one privileged request, deletes whatever that discovery names, and then requires a second lookup to show both addresses absent. The address is the only ownership key that survives a lost create response: an account the backend stored before the answer was lost has no identifier this collector ever saw, and a recovery keyed on `localId` would silently skip it while reporting proven cleanup. An address the discovery proved absent is never deleted again: a stage removes account B on purpose, and asking the backend to delete it a second time would only collect a refusal for a run that did everything right. Proven absence, not a delete status, is the requirement. A failed lookup, a transport failure, or any address still present leaves `cleanupComplete` false and `absenceProven` false, and the comparator refuses such a receipt a verdict in either direction.

A rehearsal exercised that path and is committed as evidence. With a transport failure injected at the email-link sign-in stage, the run stopped after 18 of 26 stages, both addresses were proven absent, and the owned process exited with its listeners closed. The [rehearsal receipt](../../spec/compatibility/broad-runs/auth-action-codes-oob-boundary-01-local-shadow-rehearsal.json) records it.

## Local shadow

The shadow owns the artifact it measures: it copies the binary into a private directory, starts it with OS-assigned loopback ports and `--only auth`, runs the collector as its child, and then requires the child to be gone, the listeners closed and the artifact bytes unchanged. Credentials and emulator-host variables are stripped from the environment before the artifact starts.

| Item | Value |
| --- | --- |
| Collector source commit | `be4ed3eb8ec27195bca3961ecccb1fbb0e6f83be` |
| Artifact SHA-256 | `bad6b9280e895f90484b5a89056c62ce7c4f3f44e8571891f5175986e99f53a6` (version 0.7.0) |
| Artifact binding | receipt `unbound`; the file is `retained-external` and was not rebuilt from the collector source commit |
| Campaign package SHA-256 | `d2c440583ac4132e6caf0c2ab7c17f85da66fe26d613889c21f127f55b8f23aa` |
| Receipt SHA-256 | `b3aaad333b9df9cd4c551ed7529e54eaa2e2c8deb0f2abc90e3b9af3d42ced7b` |
| Result | 26 stages recorded, cleanup complete, 0 accounts remaining, process exit 0, listeners closed |

The artifact binding is the honest limit of this evidence, and it is now enforced rather than described. The receipt carries the binding kind alongside the digests, the shadow records `unbound` for a binary it did not build, and the comparator refuses a verdict unless the receipt says `built-from-source` and names the same commit twice. Filling a retained digest into the binding can no longer buy a verdict. Rebuilding the artifact from the execution commit remains an owner precondition, not a step this package performed. The shadow never builds anything: its `--built-from-source-commit` option is the caller's assertion about a binary built elsewhere, and without it the receipt says `unbound`.

## Comparator contract

The comparator classifies one local and one production receipt as `MATCH`, `SEMANTIC_MISMATCH` or `INDETERMINATE`. A verdict requires both sides complete and recovered, bound to the same frozen manifest digest, carrying complete source bindings, produced by different runs, and, on the production side, naming an owner permission and recording an executed observation. Everything else is `INDETERMINATE`: an infrastructure, binding or cleanup failure is never reported as a compatibility result.

A verdict also requires both sides to record zero delivered messages and a proven absence: the delivery boundary and the cleanup contract are gate conditions, not prose. A receipt whose stage rows are missing, reordered, mistyped or foreign is classified `INDETERMINATE` rather than allowed to raise. Status, error code, response field presence, request type, verification state, new-user state, whether a code or link was returned, the code's character class, token presence, delivered-message counts and readback counts decide the verdict. Diagnostic prose and the length of a returned code stay visible as informational differences, because neither is part of the contract being compared.

## Reproduction

```sh
uv run --python 3.12 --with pytest pytest -q tools/compat-broad/auth-action-codes
uv run --python 3.12 python tools/compat-broad/auth-action-codes/action_codes_plan.py --nonce <32 hex>
FIREEMU_ACTION_CODES_ARTIFACT=/absolute/path/to/fireemu \
  uv run --python 3.12 --with pytest pytest -q tools/compat-broad/auth-action-codes
```

[Campaign package](../../spec/compatibility/broad-runs/auth-action-codes-oob-boundary-01.json) · [Local shadow evidence](../../spec/compatibility/broad-runs/auth-action-codes-oob-boundary-01-local-shadow.json) · [Lane guide](../../tools/compat-broad/auth-action-codes/README.md).
