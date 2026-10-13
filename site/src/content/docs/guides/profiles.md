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

## Where Fireemu departs from production on purpose

Matching production is Fireemu's goal, but not every production behavior is worth reproducing by default. Some only add setup to a test: production needs signed tokens and signing keys, a feature enabled through an Admin API call, or an hour of waiting. Copying them exactly would make Fireemu harder to use in CI and on a developer's machine without catching more bugs.

For these behaviors, the default in both profiles is a development default that works without setup. Each one has its own setting, and each is listed here, so a difference from production is always a documented choice rather than a gap.

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
| A tenant ID can be any readable name, such as `tenant-a` | `auth.tenantIdFormat` (`"readable"`) | `"generated"`: production's generated form, such as `acme-x7k2q` |
| An end user's Firestore `Listen` stream stays open however long it is held | `firestore.listenStreamLifetime` (`"unlimited"`) | `"oneHour"`: ended with `INTERNAL` an hour after it opened |

The startup banner and `fireemu capabilities` report whether `productionExact` is set, and the effective value and source of each setting in the table.

Most projects do not need `productionExact`; it is an advanced switch for a stricter comparison with production. A query whose composite index is not defined is not among these defaults: `strict` refuses it as production does, and `firestore.missingIndexes: "report"` is an explicit opt-out that runs it and reports the missing index on standard error. `productionExact` does not change that key.

### Other development conveniences

These differ from production and are not switched by `productionExact`:

| Development behavior | How to get production's behavior |
|---|---|
| Pub/Sub accepts requests without any credential, so clients that use `PUBSUB_EMULATOR_HOST` work | Set `pubsub.authentication.localBearerToken`; requests without a credential are then refused as production refuses them. See [Pub/Sub and Eventarc](../../products/pubsub-eventarc/#authentication). |
| `localhost` is in the default authorized domains for action-link continue URLs; a new production project may not include it | Declare `auth.authorizedDomains`, which replaces the defaults |
| Storage: a signed URL or a POST policy is accepted with any signature (its expiry and conditions are checked), because verifying one needs the signing service account's key | Not available |
| Storage: the JSON API serves a request that has no credential, or any credential other than a Firebase ID token, as the owner, because a local run cannot judge an access token | Not available |
| Storage: the first write to a bucket nothing declared is served and creates the bucket, with one `note:` line on standard error; production answers 404 | List the bucket in `storage.buckets`; the 404 itself is not available |
| Storage: a bucket-level public grant (IAM `allUsers`) cannot be made through an API | List the bucket in `storage.publicBuckets` |
| Storage: every `Origin` is reflected in the CORS headers, where production needs a CORS configuration on the bucket for browser downloads | Not available |
| Storage: a Security Rule may call `firestore.get()` and `firestore.exists()` without the Firestore access grant production needs for the Storage service agent | Not available |
| Storage: both default bucket names, `<project>.appspot.com` and `<project>.firebasestorage.app`, exist, where a production project has one of them | Not available |

## Choosing a setup

- **Most projects:** `strict` with the development defaults. Your tests run without keys or setup calls, and still meet production's validation, refusals and error shapes.
- **Before a release, or in a separate CI job:** `strict` with `productionExact: true`, to catch what the development defaults let through, such as an unsigned token.
- **Checking the official emulator:** `emulator`, as an additional target only.
