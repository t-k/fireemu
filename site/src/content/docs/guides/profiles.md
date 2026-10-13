---
title: Profiles and productionExact
description: Choose between production behavior and official-emulator behavior, and turn on every production check at once.
---

## Compatibility profiles

| Profile | Behavior |
|---|---|
| `strict` | Matches production Firebase behavior and constraints as closely as possible within the supported scope. The default, and recommended, including when migrating from the official emulator. |
| `emulator` | Targets the behavior of a pinned version of the official emulator (`firebase-tools` 15.28.2). Use it only to check alignment with the official emulator, for example as an extra test target. |

The `emulator` profile accepts behavior that production refuses, so a test can pass there and fail against production. Use `strict` for your tests.

```json
{ "schemaVersion": 1, "profile": "strict" }
```

## Development defaults

Fireemu is mostly run by tests, in CI and on a developer's machine. Where production needs setup that a test should not have to do, such as signed tokens, signing keys, or enabling a feature through an Admin API call, the default in both profiles is the development behavior. Each such behavior has its own setting.

To get production's behavior for all of them at once, set `productionExact` to `true` (`strict` profile only). An explicit setting still decides over it:

```json
{
  "schemaVersion": 1,
  "profile": "strict",
  "productionExact": true,
  "auth": { "allowUnsignedCustomTokens": true }
}
```

| Development default | Setting | With `productionExact` |
|---|---|---|
| Unsigned emulator custom tokens are accepted | `auth.allowUnsignedCustomTokens` | Refused |
| Firestore and Storage Security Rules accept `@firebase/rules-unit-testing`'s unsigned mock ID token | `auth.allowUnsignedIdTokens` | Refused, as production refuses an unsigned token |
| Identity-provider sign-in accepts fixture assertions and the sign-in widget | `auth.idpAssertions` (`"fixture"`) | `"signed"`: OIDC ID tokens must verify with an `auth.idpSigners` key, SAML responses with the provider's certificates |
| The Eventarc listener admits any credential or none | `eventarc.authentication` (`"permissive"`) | `"production"`: a missing, malformed or JWT-shaped bearer is refused with production's 401 |
| A query whose composite index is not defined runs, and the missing index is reported on standard error | `firestore.missingIndexes` (`"report"`) | `"refuse"`: refused with `FAILED_PRECONDITION` and the console link |
| A tenant ID can be any readable name, such as `tenant-a` | `auth.tenantIdFormat` (`"readable"`) | `"generated"`: production's generated form, such as `acme-x7k2q` |
| An end user's Firestore `Listen` stream stays open however long it is held | `firestore.listenStreamLifetime` (`"unlimited"`) | `"oneHour"`: ended with `INTERNAL` an hour after it opened |

The startup banner and `fireemu capabilities` report whether `productionExact` is set.

## Choosing a setup

- **Most projects:** `strict` with the development defaults. Your tests run without keys or setup calls, and still meet production's validation, refusals and error shapes.
- **Before a release, or in a separate CI job:** `strict` with `productionExact: true`, to catch what the development defaults let through, such as a missing index.
- **Checking the official emulator:** `emulator`, as an additional target only.
