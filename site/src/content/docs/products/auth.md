---
title: Authentication
description: Firebase Authentication and Identity Platform locally, including TOTP MFA, multi-tenancy and blocking functions.
---

Fireemu serves Firebase Authentication with the Identity Platform features: multi-factor authentication including TOTP, multi-tenancy, OIDC and SAML providers, and blocking functions. Connect to it at `http://127.0.0.1:9099` (see [Connect your app](../../getting-started/connect/)).

## Configure your project

The `auth` section of `fireemu.json` declares the project configuration your application relies on, so a test does not have to set it through the Admin API every time.

| What you can configure | Settings |
|---|---|
| Enable or disable email/password, anonymous and phone sign-in | `auth.signIn` |
| Test phone numbers and verification codes | `auth.signIn.phoneNumber.testPhoneNumbers` |
| Authorized domains for action-link continue URLs | `auth.authorizedDomains` |
| Accounts that share an email address | `auth.signIn.allowDuplicateEmails` |
| Password requirements and enforcement at sign-in | `auth.passwordPolicy` |
| Multi-factor authentication | `auth.mfa` (and `auth.totp` in the `emulator` profile) |
| Tenants and the multi-tenancy switch | `auth.tenants`, `auth.multiTenant` |
| End-user account creation and deletion | `auth.client.permissions` |
| Email enumeration protection | `auth.improvedEmailPrivacy` |
| Per-project and per-tenant overrides | `auth.passwordPolicyOverrides`, `auth.configOverrides` |
| Blocking functions | `auth.blockingFunctions` |
| OIDC and SAML providers | `auth.providers.oidc`, `auth.providers.saml` |
| Sign-up quota and local quota-exceeded simulation | `auth.quota`, `auth.quotaSimulation` |

This example enables email/password and phone sign-in, disables anonymous sign-in, requires passwords of at least 12 characters with uppercase, lowercase and numeric characters, and prevents users from deleting their own accounts:

```json
{
  "$schema": "https://fireemu.dev/spec/config/fireemu.schema.json",
  "schemaVersion": 1,
  "profile": "strict",
  "auth": {
    "signIn": {
      "allowDuplicateEmails": false,
      "email": { "enabled": true, "passwordRequired": true },
      "anonymous": { "enabled": false },
      "phoneNumber": {
        "enabled": true,
        "testPhoneNumbers": { "+16505550101": "123456" }
      }
    },
    "passwordPolicy": {
      "enforcementState": "ENFORCE",
      "forceUpgradeOnSignin": true,
      "constraints": {
        "minLength": 12,
        "requireUppercase": true,
        "requireLowercase": true,
        "requireNumeric": true
      }
    },
    "client": {
      "permissions": { "disabledUserSignup": false, "disabledUserDeletion": true }
    },
    "improvedEmailPrivacy": true
  }
}
```

## Multi-factor authentication

The official emulator has no TOTP. Fireemu supports TOTP and SMS second factors.

Under `strict`, TOTP is enabled only through the project's MFA configuration, as in production. That configuration is on by default (SMS and TOTP enabled), so enrolling a second factor needs no console toggle, Admin API call or `auth.mfa` block. With `productionExact` a new project starts with MFA off, as production does, and enrollment answers `OPERATION_NOT_ALLOWED` until it is enabled. Declare the configuration with `auth.mfa`, in the shape Identity Platform uses, to mirror your project or to turn MFA off (`{"state": "DISABLED"}`); a declared block always decides:

```json
{
  "schemaVersion": 1,
  "profile": "strict",
  "auth": {
    "mfa": {
      "state": "ENABLED",
      "providerConfigs": [
        { "state": "ENABLED", "totpProviderConfig": { "adjacentIntervals": 1 } }
      ]
    }
  }
}
```

The configuration applies at startup and to every project created afterward, and is validated as the Admin API validates an update; a value production would refuse stops the daemon at startup. A session reset returns the project to it. The accepted TOTP window stays `auth.totp.windowSteps` unless the configuration sets `adjacentIntervals`. A tenant follows its own `mfaConfig`.

## Multi-tenancy

Multi-tenancy is on by default, so the Admin API creates tenants and `auth.tenants` loads without enabling anything first. With `productionExact` a new project starts as production does, with tenants refused until `multiTenant.allowTenants` is enabled through the Admin API or in the file, and `auth.multiTenant.allowTenants: false` turns it off in either case. Each entry of `auth.tenants` is an Admin v2 `Tenant` document plus its `tenantId`:

```json
{
  "schemaVersion": 1,
  "profile": "strict",
  "auth": {
    "multiTenant": { "allowTenants": true },
    "tenants": [
      {
        "tenantId": "tenant-a",
        "displayName": "acme",
        "allowPasswordSignup": true,
        "mfaConfig": { "state": "ENABLED", "enabledProviders": ["PHONE_SMS"] }
      }
    ]
  }
}
```

By default a tenant ID can be any readable name, such as `tenant-a`. With `productionExact` or `auth.tenantIdFormat: "generated"`, it must have the form production generates: the display name, a hyphen and five characters of `a-z0-9`, such as `acme-x7k2q`.

Under the `emulator` profile, a request that names an unknown tenant creates it, as in the official emulator. `strict` refuses such a request, as production does.

## Tokens

| Development default | Setting | With `productionExact` |
|---|---|---|
| Unsigned custom tokens from the Admin SDK in emulator mode are accepted | `auth.allowUnsignedCustomTokens` | Refused; configure `auth.customTokenSigners` with your service accounts' public keys |
| `@firebase/rules-unit-testing`'s unsigned mock ID token is accepted by Firestore and Storage Security Rules | `auth.allowUnsignedIdTokens` | Refused, as production refuses an unsigned token |
| Identity-provider sign-in accepts fixture assertions and the sign-in widget | `auth.idpAssertions` (`"fixture"`) | `"signed"`: OIDC ID tokens must verify with an `auth.idpSigners` key, and SAML responses with the provider's certificates |

Fixture assertions skip only the signature check. Under `strict`, sign-in through an `oidc.*` or `saml.*` provider is still refused when the provider has no configuration (declare it in `auth.providers`, or create it through the Admin API) or is disabled, with production's `OPERATION_NOT_ALLOWED : The identity provider configuration is not found.` or `... is disabled.`. Built-in providers such as `google.com` sign in without a console configuration; see [Other development conveniences](../../guides/profiles/#other-development-conveniences).

The Admin SDK's `verifyIdToken` and `verifySessionCookie` inside a function you run here skip signature verification, because the SDK accepts only unsigned tokens whenever `FIREBASE_AUTH_EMULATOR_HOST` is set (as against the official emulator). A handler that authenticates callers that way therefore accepts a hand-made unsigned token with the right claims, which production refuses, and `auth.idTokenSigning: "session-rsa"` cannot fix it because the SDK then refuses the signed tokens too. Do not rely on a local `verifyIdToken` call to prove that forged tokens are refused; test that path against a deployed function.

## Blocking functions

`beforeUserCreated` and `beforeUserSignedIn` (and their v1 forms) run inside the request, as in production. Under `strict`, `beforeEmailSent` also runs before a password reset or email sign-in mail. They are registered from the loaded Functions codebase. `auth.blockingFunctions` is optional: it selects which discovered function handles `beforeCreate` and `beforeSignIn`, and which credentials are forwarded to it. Giving its `triggers` map turns `beforeEmailSent` off.

## Quota-exceeded behavior

To test sign-up quota errors, set `auth.quotaSimulation`:

```json
{ "mode": "enforce", "defaultQuotaPerHour": 5 }
```

This is a local fixed-window simulation, not Firebase's full quota accounting or abuse prevention.

## Outside the supported scope

Sign-in flows that talk to external identity providers, authorization-code exchange and SAML XML signature verification are outside the supported scope. See [Limitations](../../compatibility/limitations/) and the [configuration schema](../../reference/configuration/) for every setting.
