# Fireemu

Fireemu is a local emulator for testing applications built with Firebase. It aims to match production Firebase behavior as closely as possible, so you can test locally and in CI without using a real Firebase project.

Passing tests against the official emulator does not always mean your application will behave the same way in production. Some features are not supported by the official emulator, and some execution conditions are difficult to reproduce locally. These gaps can leave you relying on a real Firebase project for part of your testing.

Fireemu is being developed to close these gaps. For example, it provides:

- **Validation of configuration required in production:** Fireemu detects issues that the official emulator misses, such as missing Firestore index definitions.
- **Support for features not available in the official emulator:** Fireemu also supports features such as TOTP-based multi-factor authentication.
- **Control over test execution conditions:** You can set an arbitrary time and run scheduled functions to verify their behavior without waiting for the actual scheduled time.

Fireemu is still in development and does not yet reproduce every feature and behavior of production Firebase. Before relying on Fireemu’s test results in CI or other automated workflows, we recommend differential testing against production Firebase services for the features and critical workflows your application uses. Run the same tests against Fireemu and a dedicated Firebase test project, and check for differences in results and behavior that could affect your application. Use a dedicated test project, not your live production project.

See the [capability manifest](crates/fireemu/src/capabilities.json) and [compatibility documentation](docs/compatibility-contract.md) for supported features, known differences, and the status of compatibility verification.

## Quick start

Node.js 20 or newer is required.

```sh
npm install --save-dev fireemu
npx fireemu init

# Start the emulator
# UI (default): http://127.0.0.1:4000
npx fireemu up
```

Open the UI in your browser to inspect and manage data. Press `Ctrl+C` to stop the emulator.

To run the emulator only for the duration of a command, use `exec` instead of `up`.

```sh
# Start the emulator, run a command, and stop when the command exits
npx fireemu exec -- <command>

# Example: run tests
npx fireemu exec -- npm test
```

### Supported platforms

| OS | Architecture |
|---|---|
| macOS 13 or newer | Apple silicon, Intel |
| Linux | x86-64, arm64 |
| Windows 10 or newer | x86-64 |

Running Functions requires `firebase-functions` v6 or v7 in the codebase. 

## Supported scope

Fireemu supports Cloud Firestore, Firebase Authentication (Identity Platform), Cloud Storage for Firebase, Cloud Functions for Firebase, Cloud Pub/Sub, and Eventarc. It also provides a local Firebase App Check implementation and a UI for managing data and viewing logs. 

### Key unsupported features and limitations

| Product | Key unsupported features and limitations |
|---|---|
| Cloud Firestore | The Enterprise Pipeline API supports a limited subset of read operations. Full-text search supports index definition validation, but local search execution is not supported.   |
| Firebase Authentication (Identity Platform) | Authentication flows that communicate with external identity providers, authorization-code exchange, and SAML XML signature verification are outside the supported scope. These are separate from local authentication behavior and provider configuration.  |
| Cloud Storage for Firebase | Object versioning, signed URLs, ACL-based access control, object composition (`compose`), and notification configuration are not supported.  |
| Cloud Functions for Firebase | Triggers that depend on unsupported products, such as Realtime Database (deferred), Remote Config, and Data Connect (deferred), cannot run. Storage archive events do not occur because object versioning is not supported.  |
| Cloud Pub/Sub | Schemas, BigQuery and Cloud Storage subscription delivery, and some APIs such as `UpdateTopic` are not supported.  |
| Firebase App Check | Local testing with debug tokens is supported. Real attestation through Play Integrity, App Attest, DeviceCheck, or reCAPTCHA, and replay protection using limited-use tokens, are not supported.  |

This table highlights key limitations; it is not exhaustive. Check individual API support and conditions with the following command or the [capability manifest](crates/fireemu/src/capabilities.json).

```sh
npx fireemu capabilities
```

See the [Functions support inventory](docs/functions-export-inventory.md) for support by trigger type.

### Unsupported products

Realtime Database, Firebase Hosting, App Hosting, and Data Connect are not currently supported. Firebase Extensions support is not planned. 

## Usage

### Select services

Use `--only` to select the services to start.

```sh
# Start only Firebase Authentication (Identity Platform), Firestore, and Storage
npx fireemu up --only auth,firestore,storage
```

You can also select an individual Functions codebase.

```sh
npx fireemu up --only functions:<codebase>
```

### Run a command

Service selection also works with `exec`.

```sh
npx fireemu exec --only auth,firestore,storage -- npm test
```

`exec` sets the Firebase SDK emulator host environment variables for the child command and returns its exit status. SIGINT and SIGTERM are forwarded to the child command.

The official CLI command names are also available as aliases. 

```sh
npx fireemu emulators:start
npx fireemu emulators:exec -- npm test
```

### UI

The default UI address is `http://127.0.0.1:4000`. Use `--ui-port` to specify a port.

```sh
# Start the UI on port 4001
npx fireemu up --ui-port 4001
```

`exec` does not start the UI by default. Add `--ui` to use it while the command runs.

```sh
npx fireemu exec --ui -- npm test
```

Use `--ui-port 0` to disable the UI. When automatic UI startup cannot bind the default port, the emulator starts without the UI. Check the startup output if the UI is unavailable.  

When a Functions codebase is loaded, the Functions page shows registered functions, triggers, invocation results, and logs. You can run scheduled functions immediately or advance the virtual clock to their next scheduled execution. 

### Export data

To save data from a running emulator, run the following command in another terminal.

```sh
npx fireemu emulators:export ./emulator-data
```

On Windows, `emulators:export` and `--export-on-exit` are not currently available. Import and other emulator functionality remain available.

On Unix-like systems, the destination and its ancestor directories are subject to ownership and permission restrictions. Use a dedicated, non-shared directory rather than `/tmp` or a shared directory. 

### Troubleshooting

For startup or installation problems, inspect the environment and bundled files with:

```sh
npx fireemu doctor
```

The command reports information about the Fireemu binary, UI, Functions runner, and Node.js, and suggests remedies when it finds missing components or problems. 

## Configuration

### Initial setup and reusing `firebase.json`

`fireemu init` creates `fireemu.json` in the current directory. The interactive setup lets you choose a compatibility profile and whether to reuse an existing `firebase.json`.

When reusing `firebase.json`, Fireemu references the file rather than copying its settings. Rules, indexes, Functions codebases, and emulator ports are read from it each time Fireemu starts.

Use the non-interactive form for CI or scripted setup.

```sh
npx fireemu init --yes
```

An existing `fireemu.json` is not overwritten unless `--force` is supplied.

### Compatibility profiles

| Profile | Behavior |
|---|---|
| `strict` | Matches production Firebase behavior and constraints as closely as possible within the supported scope. This is the default profile |
| `emulator` | Targets the behavior of a pinned version of the official emulator. Known differences are documented in the compatibility documentation |

Use `strict` when testing against production Firebase behavior. Add `emulator` to your test targets when you also need to check alignment with the official emulator.

Under the `emulator` profile, a request that names a tenant the project does not have creates that tenant, and the number of tenants is not limited, as in the official emulator. The `strict` profile refuses such a request, as production does. A request that Fireemu refuses (a wrong credential, a browser page without the control token on the emulator routes, App Check, an unknown API key) creates nothing. As in the official emulator, a plain `GET` without an `Origin` header to a tenant route of `127.0.0.1` creates the tenant, so any web page you visit while the emulator runs can add tenants to it (not read them); use the `strict` profile where that matters.

### Basic configuration

The initial configuration selects Standard edition Firestore with the Native API.

```json
{
  "$schema": "https://fireemu.dev/spec/config/fireemu.schema.json",
  "schemaVersion": 1,
  "profile": "strict",
  "firestore": {
    "edition": "standard",
    "apiMode": "native"
  }
}
```

You can specify the configuration file with `--config`.

```sh
npx fireemu up --config ./fireemu.json
```

Keep Fireemu-specific settings in a Fireemu configuration file containing `"schemaVersion": 1`, rather than in `firebase.json`. See the [configuration schema](spec/config/fireemu.schema.json) for all available settings. 

### Firebase Authentication (Identity Platform) configuration

The `auth` section of `fireemu.json` lets you configure sign-in methods, password policies, account permissions, and other authentication settings. Match your application’s configuration to test registration, sign-in, and account management behavior.

| What you can configure | Main settings |
|---|---|
| Enable or disable email/password, anonymous, and phone sign-in | `auth.signIn` |
| Test phone numbers and verification codes | `auth.signIn.phoneNumber.testPhoneNumbers` |
| Handling of accounts that share an email address | `auth.signIn.allowDuplicateEmails` |
| Password length and character requirements, and policy enforcement at sign-in | `auth.passwordPolicy` |
| TOTP-based multi-factor authentication | `auth.totp` |
| Tenants that exist when the daemon starts, and the multi-tenancy switch | `auth.tenants`, `auth.multiTenant` |
| Restrictions on end-user account creation and deletion | `auth.client.permissions` |
| Email enumeration protection | `auth.improvedEmailPrivacy` |
| Project- and tenant-specific password policies and account permissions | `auth.passwordPolicyOverrides`, `auth.configOverrides` |
| Blocking functions before account creation or sign-in, and credential forwarding to those functions | `auth.blockingFunctions` |
| Public keys for verifying custom tokens and OIDC ID tokens | `auth.customTokenSigners`, `auth.idpSigners` |
| Sign-up quota configuration and local quota-exceeded simulation | `auth.quota`, `auth.quotaSimulation` |

See the [configuration schema](spec/config/fireemu.schema.json) for the format and accepted values of each setting.  

#### Example configuration

This example enables email/password and phone sign-in while disabling anonymous sign-in. It requires passwords of at least 12 characters containing uppercase letters, lowercase letters, and numbers, and prevents users from deleting their own accounts. Phone sign-in uses a configured test phone number and verification code.

```json
{
  "$schema": "https://fireemu.dev/spec/config/fireemu.schema.json",
  "schemaVersion": 1,
  "profile": "strict",
  "firestore": {
    "edition": "standard",
    "apiMode": "native"
  },
  "auth": {
    "signIn": {
      "allowDuplicateEmails": false,
      "email": {
        "enabled": true,
        "passwordRequired": true
      },
      "anonymous": {
        "enabled": false
      },
      "phoneNumber": {
        "enabled": true,
        "testPhoneNumbers": {
          "+16505550101": "123456"
        }
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
      "permissions": {
        "disabledUserSignup": false,
        "disabledUserDeletion": true
      }
    },
    "improvedEmailPrivacy": true
  }
}
```

For an existing `fireemu.json`, add the settings you need to its `auth` section. Adjust the values to match your application’s requirements.   

#### Project- and tenant-specific settings

Use `auth.passwordPolicyOverrides` to specify different password policies for individual projects or tenants. Use `auth.configOverrides` to customize account creation and deletion permissions and email enumeration protection.

These settings are separate from creating the project or tenant. Naming a tenant in the configuration does not create it.  

#### Enable multi-tenancy

Under the `strict` profile, enable `multiTenant.allowTenants` through the Admin API before using multi-tenancy. See the [compatibility documentation](docs/compatibility-contract.md) for the supported Admin API scope. 

#### Start with tenants

Instead of creating tenants through the Admin API in every session, declare the default project's tenants and the multi-tenancy switch in the file. Each entry of `auth.tenants` is an Admin v2 `Tenant` document plus its `tenantId`, which has the form production generates, the display name, a hyphen, and five characters of `a-z0-9`:

```json
{
  "schemaVersion": 1,
  "profile": "strict",
  "auth": {
    "multiTenant": { "allowTenants": true },
    "tenants": [
      {
        "tenantId": "acme-x7k2q",
        "displayName": "acme",
        "allowPasswordSignup": true,
        "mfaConfig": { "state": "ENABLED", "enabledProviders": ["PHONE_SMS"] }
      }
    ]
  }
}
```

- A document is read by the code the Admin tenant create route reads one with, so a value production refuses stops the daemon at startup. The tenants are created empty, in file order, and settings such as `mfaConfig` and `passwordPolicyConfig` come from the document. The file is stricter than the route in the `emulator` profile: it also refuses an unknown member and a missing or invalid `displayName`, as production does.
- A declared tenant has what an Admin create with that document gives: an omitted `allowPasswordSignup`, `enableEmailLinkSignin` or `enableAnonymousUser` is off and multi-factor is off. A tenant the `emulator` profile creates on the way for a request that names an unknown id gets the official emulator's defaults instead (all three on, `PHONE_SMS` multi-factor), so declare what your test needs.
- Under the `strict` profile tenants are created only in a project that allows them, as in production, so `auth.tenants` needs `auth.multiTenant.allowTenants: true` (the daemon refuses to start otherwise). The `emulator` profile takes tenants without the switch.
- The default project and every session project (`POST /v1/sessions`) start with the declared switch and tenants. `POST /v1/sessions/{session}/reset` (the default session's included) creates them again, empty, and returns the switch to the declared value; without these keys a reset leaves an Admin-set switch alone. A namespace the `emulator` profile routes by the first Admin request for an unknown project id holds no tenants at all, so nothing is seeded there.
- With `--import`, an imported tenant is authoritative for its id, and a declared tenant the import did not carry is still created. If you keep re-importing your own export (`--import dir --export-on-exit dir`), an edit to a declared tenant is therefore ignored once its exported copy exists: the daemon prints a warning naming the tenant when the imported settings differ from the declared ones. The switch is the other way round: a declared `allowTenants` wins over the import. After a reset the declared version of a tenant comes back, not the imported one.

#### Test quota-exceeded behavior

Use `auth.quotaSimulation` to test sign-up quota-exceeded behavior locally. For example, set `auth.quotaSimulation` to:

```json
{
  "mode": "enforce",
  "defaultQuotaPerHour": 5
}
```

This is a local fixed-window simulation. It does not reproduce Firebase’s full quota accounting or abuse-prevention systems.  

### Configure execution time

Set the emulator’s starting time with `daemon.clockStart`. Configure the clock, time zone, and other scheduling behavior in the `scheduler` section. This lets you test scheduled functions independently of the actual time.

See the [configuration schema](spec/config/fireemu.schema.json) for available settings and values. 

## Compatibility and limitations

### Differences from production Firebase

Fireemu aims to match production Firebase behavior, but a successful local operation does not guarantee the same result in production.

The local runtime does not reproduce real quota accounting, billing, IAM, organization policies, regional or network differences, or service rollouts. Local performance measurements also do not predict production latency or throughput.

Security Rules and API behavior are implemented using documentation and observations of Firebase’s actual behavior. Changes in Firebase or untested conditions may introduce differences that have not yet been recorded.

### Comparison with the official emulator

The official emulator comparison baseline is `firebase-tools 15.28.2`.

Fireemu is compatible with the listed Local Emulator Suite products as shipped by firebase-tools 15.28.2 -- Cloud Firestore, Firebase Authentication, Cloud Storage for Firebase, Cloud Functions, Cloud Pub/Sub and Eventarc, with Security Rules on the Firestore and Storage surfaces -- under the `emulator` compatibility profile and the evidence recorded in `spec/compatibility/contract.json`; it makes no complete-suite and no unqualified superset claim while Realtime Database, Firebase Hosting, App Hosting and Data Connect are deferred and Firebase Extensions is not planned.

The `strict` and `emulator` profiles differ in some behaviors to serve their respective purposes. Where the official emulator and production Firebase disagree, Fireemu also adopts production behavior in some cases and records the difference.

Check support for the specific APIs and conditions your application uses, rather than relying on product names alone. The [compatibility contract](spec/compatibility/contract.json) records scope and known differences. The [compatibility documentation](docs/compatibility-contract.md) explains the verification process and how to interpret its records. 

### Changes between versions

Configuration and behavior may change between releases. See the [CHANGELOG](CHANGELOG.md) for release changes.

## Performance

Fireemu is compared with the official Firestore emulator using the same SDK workloads. Both run sequentially on the same GitHub Actions Linux runner, with Fireemu using the `emulator` profile. The benchmark also validates operation results.

The following results come from one `standard` run at commit `f3b942c`. Ratios are calculated from five measured pairs; absolute values depend on the execution environment.

| Metric | Official emulator | Fireemu | Comparison |
|---|---:|---:|---:|
| Startup until the SDK can use Firestore | 3,043 ms | 140 ms | 21.6× faster |
| Idle memory with an empty database (PSS) | 390 MiB | 11 MiB | About 1/34 the memory |
| Peak memory during a trial (cgroup) | 849 MiB | 79 MiB | About 1/10.7 the memory |
| Firestore throughput across 22 workloads | — | — | 1.1× to 5.2× higher |

The 95% confidence interval for the startup-time ratio is `[21.4, 21.8]`. For the peak-memory ratio, calculated as official emulator divided by Fireemu, it is `[10.2, 11.1]`.

See [benchmark.yml](.github/workflows/benchmark.yml) for the workflow and [`tools/bench/`](tools/bench/) for the benchmark implementation. 

## Reporting issues and contributing

When reporting an issue, include the Fireemu and Firebase SDK versions, the profile used, the Firebase product involved, and a minimal reproduction.

For compatibility issues, also state whether you are comparing against the actual Firebase service or the official emulator, along with the expected and actual results. Remove credentials and personal information before sharing configuration files or logs.

See the [development guide](docs/development.md) for build and test instructions.

## License

Fireemu is licensed under the [Apache License 2.0](LICENSE). Third-party notices are listed in [THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt).
