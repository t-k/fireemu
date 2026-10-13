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
| App Check works without registering an app: any well-formed debug token (a UUIDv4) exchanges for any app, so an `enforceAppCheck` callable can be called with no `appCheck` block; a missing or malformed token is still refused | `appCheck.debugTokens` (`"any"`) | `"registered"`: only apps from `appCheck.apps` with a registered debug-token digest exchange, and App Check is not served without an `appCheck` block. An `appCheck` block restores it too |
| Dead-letter forwarding needs neither a project number nor IAM grants | `pubsub.deadLetterAuthorization` (`"implicit"`) | `"iam"`: a message is forwarded only after the Pub/Sub service agent is granted `roles/pubsub.subscriber` on the subscription and `roles/pubsub.publisher` on the dead-letter topic. Naming `pubsub.projectNumbers` selects it too |

The startup banner and `fireemu capabilities` report whether `productionExact` is set, and the effective value and source of each setting in the table.

Most projects do not need `productionExact`; it is an advanced switch for a stricter comparison with production. A query whose composite index is not defined is not among these defaults: `strict` refuses it as production does, and `firestore.missingIndexes: "report"` is an explicit opt-out that runs it and reports the missing index on standard error. `productionExact` does not change that key.

### Other development conveniences

These differ from production and are not switched by `productionExact`:

| Development behavior | How to get production's behavior |
|---|---|
| Pub/Sub accepts requests without any credential, so clients that use `PUBSUB_EMULATOR_HOST` work | Set `pubsub.authentication.localBearerToken`; requests without a credential are then refused as production refuses them. See [Pub/Sub and Eventarc](../../products/pubsub-eventarc/#authentication). |
| `localhost` is in the default authorized domains for action-link continue URLs; a new production project may not include it | Declare `auth.authorizedDomains`, which replaces the defaults |
| A Pub/Sub push endpoint may be plain `http://` on loopback (`127.0.0.1`, `localhost`, `[::1]`); production requires HTTPS | Use a non-loopback `https://` URL in the subscription; Fireemu delivers push messages only to loopback, so there is no setting that makes it reach one |
| `.env.local` in a Functions codebase is applied after `.env` and `.env.<projectId>` although production never deploys it | Put the value in `.env` or `.env.<projectId>` instead; a key that exists only in `.env.local` is unset in production |
| A function that fails with `retry` enabled is retried 4 times in total (`events.maxAttempts`, 10 s to 600 s backoff on the virtual clock), then dead-lettered; production retries for up to 24 hours (second generation) or 7 days (first generation) | Raise `events.maxAttempts`; no value reproduces a time window |
| A function that is not public (`invoker: "private"` or a list of service accounts) and a task-queue function accept any bearer that looks like a signed JWT on the public function URL, because Google's verification of the identity token and of its IAM role cannot run locally. A call without credentials is refused with 403, as production refuses it. The console and the control API call such functions with the control token | There is none; send a call without credentials to see the refusal. `ingressSettings` is not enforced |

## Choosing a setup

- **Most projects:** `strict` with the development defaults. Your tests run without keys or setup calls, and still meet production's validation, refusals and error shapes.
- **Before a release, or in a separate CI job:** `strict` with `productionExact: true`, to catch what the development defaults let through, such as an unsigned token.
- **Checking the official emulator:** `emulator`, as an additional target only.
