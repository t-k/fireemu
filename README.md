# Fireemu

[![npm](https://img.shields.io/npm/v/fireemu)](https://www.npmjs.com/package/fireemu)

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
# UI (default): http://127.0.0.1:4000/ui/
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

`up` and `exec` read `fireemu.toml` (or an existing `fireemu.json`) from the current directory, or, when there is none, the nearest `firebase.json` (see [Which configuration files are loaded](#which-configuration-files-are-loaded)). The first lines of the startup output name the files that were loaded and say, for Firestore and Storage, whether Security Rules are loaded.

Every command documents its options: run `npx fireemu --help` for the commands and `npx fireemu <command> --help` (or `npx fireemu help <command>`) for the options of one, for example `npx fireemu exec --help`. After `--`, `exec` passes `--help` to your command.

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
| Cloud Storage for Firebase | Signed-URL and POST-policy signatures are not verified (their expiry and conditions are), object ACLs other than `allUsers` read are not enforced, and IAM and bucket-level public access are not modeled. Object composition (`compose`) and notification configuration are not supported.  |
| Cloud Functions for Firebase | Triggers that depend on unsupported products, such as Realtime Database (deferred), Remote Config, and Data Connect (deferred), cannot run. Storage archive events occur only for a bucket whose versioning was enabled, and their shape is unrecorded.  |
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

`fireemu config show` prints every configuration key in schema order with its effective value and source, using the same configuration discovery as `fireemu up`. Use `--config <path>` or `--firebase-json <path>` to select files, and `--json` for records containing `key`, `value`, `source`, and the schema description. Sources distinguish explicit values, defaults, `productionExact`, derived values, and unset keys. When the runtime does not expose a value, the command uses its explicit file value, its schema default (marked `default (schema)`), or `(unset)` (`null` with source `unset` in JSON). A key the configuration accepts but the daemon does not read (for example `bind`, `limits.catalog`, `firestore.textSearch.*`, `rules.staticLimitChecks`, `auth.enabled` and `trace.*`) has the source `accepted, no effect`: its value is shown as written, or `(unset)`, never as if it were in effect, and a configuration that sets one prints a `note:` line at start-up. `firebaseJson` shows the Firebase configuration file actually selected, including one chosen with `--firebase-json`.

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

The default UI address is `http://127.0.0.1:4000/ui/`. Use `--ui-port` to specify a port.

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

For clock-sensitive and parallel integration tests, [test clocks and independent worlds](docs/test-worlds.md) describes explicit Node Date/timer/Cloud Tasks policies and the `fireemu/testing` helper. Separate worlds isolate their clocks, Rules, Functions and service state, including when they use the same project ID.

### Export data

To save data from a running emulator, run the following command in another terminal.

```sh
npx fireemu emulators:export ./emulator-data
```

On Windows, `emulators:export` and `--export-on-exit` are not currently available. Import and other emulator functionality remain available.

On Unix-like systems, the destination and its ancestor directories are subject to ownership and permission restrictions. Use a dedicated, non-shared directory rather than `/tmp` or a shared directory. 

On macOS, an ancestor directory with an ACL is refused when the ACL has an `allow` entry for anyone but the owner, root or the user running the export, whatever permissions the entry shows (the kernel grants rights that `ls -le` does not list). `deny` entries are accepted, so a standard home directory (which carries `group:everyone deny delete`) and the folders below it work. When an export is refused for an ACL, the message names the entry; remove it (`chmod -a`) or export to another directory, for example one under `$TMPDIR`. Check an ancestor with `/bin/ls -led <directory>`. A destination on a volume that ignores ownership (exFAT and FAT sticks and cards, or an external APFS volume with "Ignore ownership on this volume" turned on) is refused, because the owner and the mode of its directories do not show who can change them; export to a volume that enforces ownership. A volume without atomic directory rename (exFAT, FAT, some network filesystems) cannot publish an export either: use a directory on an APFS volume.

### Keep data between runs

`--import <dir>` loads an export at startup, and `--export-on-exit` (without a directory of its own) writes the state back to the same directory when the run ends:

```sh
npx fireemu exec --import ./emulator-data --export-on-exit -- npm test
```

- An empty `--import` directory starts with no data, so the first run of a new volume needs no separate command. A missing directory is refused (a mistyped path must not start an empty suite), unless it is also where `--export-on-exit` writes. A directory that holds anything but no `firebase-export-metadata.json` is refused.
- A failed `--export-on-exit` is printed as an `error:` line, and the run exits 1 when the command succeeded (a failing command keeps its own exit code). The official CLI only warns and exits 0; Fireemu differs so that a CI job that depends on the saved data cannot pass without it.
- The export directory may be a volume mount point, for example a container volume mounted at `/data`. A mount point cannot be replaced by an atomic rename, so the export is staged inside it and moved into place, the old `firebase-export-metadata.json` leaving first and the new one arriving last. That replacement is not atomic: an interrupted export leaves a directory without the manifest, which `--import` refuses instead of loading part of it. Any other directory is still replaced atomically.

### Troubleshooting

For startup or installation problems, inspect the environment and bundled files with:

```sh
npx fireemu doctor
```

The command reports information about the Fireemu binary, UI, Functions runner, and Node.js, and suggests remedies when it finds missing components or problems. 

## Configuration

### Initial setup and reusing `firebase.json`

`fireemu init --reference` also writes `fireemu.reference.toml`, a commented reference generated from the schema. With an existing `fireemu.json`, it writes `fireemu.reference.jsonc` instead, so reference keys match the configuration format. Fireemu never loads this file. The normal `fireemu.toml` stays minimal: copying a reference key into it makes that key explicit, which stops `productionExact` from switching it. Keys without defaults, keys whose presence selects behavior, keys governed by `productionExact`, and keys accepted for forward compatibility that currently have no effect (marked as such in their comment) stay commented out. Combine `--reference` with `--profile` or `--firebase-json` when initializing; with an existing `fireemu.toml` or `fireemu.json` and neither of those options, only the reference is written. Existing output files require `--force` to replace.

`fireemu init` creates `fireemu.toml` in the current directory. The interactive setup lets you choose a compatibility profile and whether to reuse an existing `firebase.json`.

When reusing `firebase.json`, Fireemu references the file rather than copying its settings. Rules, indexes, Functions codebases, and emulator ports are read from it each time Fireemu starts.

Use the non-interactive form for CI or scripted setup.

```sh
npx fireemu init --yes
```

An existing `fireemu.toml` is not overwritten unless `--force` is supplied. An existing `fireemu.json` is preserved, including with `--force`; remove it before creating `fireemu.toml`.

### Which configuration files are loaded

`up`, `exec`, `emulators:start` and `emulators:exec` choose their configuration files as follows.

1. `--config <file>` and `--firebase-json <file>` load exactly the files they name, and nothing is searched for. `--config` parses a `.toml` path as TOML (case-insensitive, including `.TOML`) and every other extension as JSON. A TOML configuration must set `schemaVersion = 1`; it is never read as a `firebase.json`, which is JSON only. `--firebase-json` always reads JSON.
2. Otherwise, the single `fireemu.toml` or `fireemu.json` in the current directory is loaded as if it were passed with `--config`. If both files exist, startup is refused: remove one or select a file with `--config`. Its `firebaseJson` entry, resolved relative to the loaded file, names the `firebase.json` to load. A `firebase.json` beside a `fireemu.toml` without a `firebaseJson` entry is not loaded, and the startup output says so. Neither `fireemu.toml` nor `fireemu.json` in a parent directory is used, because the paths it contains are relative to the current directory. Relative paths inside a canonical file (`rules.source`, `storage.rules`, `functions.source`, `firestore.indexFile` and the other file settings) are read from the working directory, whichever directory the file is in; only `firebaseJson` and the paths inside a `firebase.json` are read from the file's own directory.
3. Otherwise, the nearest `firebase.json` is loaded as if it were passed with `--firebase-json`: the one in the current directory, else the first one found in a parent directory, as the Firebase CLI finds it. Its paths and the `.firebaserc` beside it are read from its directory.
4. Otherwise, the built-in defaults apply, and no Security Rules are loaded.

`--no-config-discovery` skips steps 2 and 3. The `config:` line of the startup output names the files that were loaded.

A discovered file can name Functions code to run and the rules to enforce, so on Unix the search checks who owns what it finds, as git checks repository ownership. The Firebase CLI does not check this. The trusted owners are you (the effective user), root, and, when you run as root through `sudo`, the user in `SUDO_UID`.

- A `fireemu.toml`, `fireemu.json` or `firebase.json` whose owner is not trusted, or that any user can write, is skipped. Group write is allowed, so files created under a user-private-group umask (002, the Debian and Ubuntu default) are loaded.
- A `.firebaserc` names only project and target aliases, never code or rules, so its owner is not checked. It is skipped only when it, or its directory, can be written by any user.
- The search stops before a parent directory whose owner is not trusted or that any user can write, such as `/tmp`. It also stops, without a warning, at a parent it cannot inspect, such as one you may not enter.
- The owner of the current directory is not checked, because you chose to run there. A current directory that any user can write is not searched at all.
- A symbolic link is judged by the file it points to. The directory that holds the target is not checked.
- Each candidate is opened once. Its owner and mode are checked on the open file before anything is read, and its text is then read from the same file. A discovered file larger than 16 MiB is refused with an error.

A skipped file or directory is named in a warning, and the run continues as if nothing had been found. To load a file anyway, name it with `--config` or `--firebase-json`. To silence the warning, pass `--no-config-discovery`. Errors in a discovered file say that the search found the file.

Two common setups run into this rule:

- A root container with a bind-mounted checkout. Examples are GitHub Actions `container:` jobs and `docker run -v "$PWD":/app` as root. The `fireemu.toml` and `firebase.json` there are owned by a host user that the container's root does not trust, so they are skipped. Use the explicit flags, or `chown` the checkout. The `.firebaserc` still names the project. Rootless Podman maps your user to the container's root, so it is not affected.
- `sudo`. Files owned by the user that `sudo` names in `SUDO_UID` are trusted.

On Windows, ownership is not checked.

If you relied on the old behavior, where a `firebase.json` next to your tests was ignored, pass `--no-config-discovery`. Discovery means that the project ID comes from the `.firebaserc` beside the discovered `firebase.json`, that its emulator ports, Hub, UI and single-project settings apply, and that a `functions` entry starts the Functions runtime. `fireemu capabilities` also reports the profile of a discovered `fireemu.toml`.

### Security Rules that are not loaded

Under the `strict` profile, a project without Security Rules behaves as a production project without a rules release: every client request to Firestore is refused with `PERMISSION_DENIED`, and every end-user request to Storage is refused with production's 400 "bucket has not been set up" answer. The Admin SDK and other owner credentials are not affected. The `emulator` profile allows every Firestore request, and every Storage request for a `demo-*` project, as the official emulator does.

The answers keep production's wording, which does not mention Fireemu. The startup output therefore has a `firestore rules:` and a `storage rules:` line that say when no rules are loaded and how to load them, and the first refused request for each database and bucket (up to 32 of each) prints a warning to standard error. Name the rules files in `firebase.json` (`firestore.rules`, `storage.rules`) or in `fireemu.toml` (`rules.source`, `storage.rules`).

### Why a request was denied

A Security Rules denial is answered with production's wording (Firestore's `PERMISSION_DENIED` "Missing or insufficient permissions.", Storage's 403), which does not say which rule refused. Fireemu therefore prints each denial of an end-user request to standard error, with every `allow` condition the request evaluated and what it evaluated to:

```text
note: firestore: Security Rules denied get on "notes/n1" in "database (default)" (request.auth.uid "bob"): no allow statement evaluated to true; line 5:22 `request.auth.uid == resource.data.owner` was false
```

- Set `rules.denialLog` to `"off"` in `fireemu.toml` to silence these lines (for example in a suite that asserts many denials). The answer to the client is the same either way.
- When the UI is running, its Rules page lists the decided requests from the start of the run, with what every expression evaluated to. The same trace is served by `GET /v1/sessions/default/rules/requests` on the control API.

### Compatibility profiles

| Profile | Behavior |
|---|---|
| `strict` | Matches production Firebase behavior and constraints as closely as possible within the supported scope. This is the default profile. Recommended, including when migrating from the official emulator |
| `emulator` | Targets the behavior of a pinned version of the official emulator. Known differences are documented in the compatibility documentation. Use it only to check alignment with the pinned official emulator (for example as an extra test target); it is not needed for a migration |

Use `strict` for your tests, also when you are moving a project over from the Firebase Local Emulator Suite. `strict` is recommended; `emulator` is only for checking alignment with the pinned official emulator (for example as an extra test target). It accepts behavior that production refuses, so a test can pass there and fail against production.

#### Development defaults and `productionExact`

Fireemu is mostly run by tests, in CI and on a developer's machine. Where production needs setup that a test should not have to do (signed tokens, signing keys, enabling a feature through an Admin API call), the default in both profiles is the development behavior, and each such behavior has its own configuration key. To get production's behavior for all of them at once, set `productionExact` to `true` (strict profile only); an explicit key still decides over it:

```toml
schemaVersion = 1
profile = "strict"
productionExact = true

[auth]
allowUnsignedCustomTokens = true
```

JSON also works: existing `fireemu.json` files and `--config <path>.json` remain supported.

| Development default | Key | With `productionExact` |
|---|---|---|
| Unsigned emulator custom tokens are accepted | `auth.allowUnsignedCustomTokens` | refused |
| Firestore and Storage Security Rules accept `@firebase/rules-unit-testing`'s unsigned mock ID token (`authenticatedContext()`, the client SDK's `mockUserToken`) | `auth.allowUnsignedIdTokens` | mock-token fallback disabled; normally verified fireemu-issued tokens still accepted |
| Identity-provider sign-in accepts the fixture assertions and the sign-in widget (`/emulator/auth/handler`), for built-in, `oidc.*` and `saml.*` providers; under `strict` an `oidc.*` or `saml.*` provider must still be configured and enabled (`auth.providers` or the Admin API), as production requires | `auth.idpAssertions` (`"fixture"`) | `"signed"`: OIDC ID tokens must verify with an `auth.idpSigners` key, SAML responses with the provider's certificates, and the fixture and built-in providers are refused |
| The strict Eventarc listener admits any credential or none, so the Admin SDK publishes with a fake credential (see [Eventarc authentication](docs/eventarc-authentication.md)) | `eventarc.authentication` (`"permissive"`) | `"production"`: a missing, malformed or JWT-shaped bearer is refused with production's 401 |
| A tenant of `auth.tenants` can have any readable id, such as `tenant-a` | `auth.tenantIdFormat` (`"readable"`) | the id must have production's generated form, the display name, a hyphen and five characters of `a-z0-9` (`"generated"`) |
| Multi-tenancy is on: the Admin API creates tenants and `auth.tenants` loads without an `updateConfig` call | `auth.multiTenant.allowTenants` (`true`) | unset until it is enabled, as in a new production project: tenant routes are refused and `auth.tenants` needs `allowTenants: true` |
| Multi-factor authentication is on, SMS and TOTP, without a console toggle, an `updateConfig` call or an `auth.mfa` block | `auth.mfa` (`state: "ENABLED"`, `PHONE_SMS` and TOTP) | off until enabled, as in a new production project: enrollment is refused with `OPERATION_NOT_ALLOWED : SMS based MFA not enabled.` or `TOTP based MFA not enabled.` |
| An end user's native gRPC `Listen` stream stays open however long it is held. `POST /v1/firestore/listen:expire` on the control API ends every held end-user stream at once, with production's status, to test a client's reconnect | `firestore.listenStreamLifetime` (`"unlimited"`) | ended with `INTERNAL` an hour after it opened, as production ends it (`"oneHour"`) |
| App Check is served without registering an app: any well-formed debug token (a UUIDv4) exchanges for any app, so an `enforceAppCheck` callable works with no `appCheck` block and a missing or malformed token is still refused | `appCheck.debugTokens` (`"any"`) | only registered apps and digests exchange (`"registered"`); an `appCheck` block asks for this too |
| Dead-letter forwarding needs neither a project number nor IAM grants | `pubsub.deadLetterAuthorization` (`"implicit"`) | forwarded only after the service agent holds `roles/pubsub.subscriber` on the subscription and `roles/pubsub.publisher` on the dead-letter topic (`"iam"`); naming `pubsub.projectNumbers` selects it |

The start banner and `fireemu capabilities` report whether `productionExact` is set.

Under the `emulator` profile, a request that names a tenant the project does not have creates that tenant, and the number of tenants is not limited, as in the official emulator. The `strict` profile refuses such a request, as production does. A request that Fireemu refuses (a wrong credential, a browser page without the control token on the emulator routes, App Check, an unknown API key) creates nothing. As in the official emulator, a plain `GET` without an `Origin` header to a tenant route of `127.0.0.1` creates the tenant, so any web page you visit while the emulator runs can add tenants to it (not read them); use the `strict` profile where that matters.

### Migrating from the Firebase Local Emulator Suite

Keep `profile = "strict"` (the default of `fireemu init`), and point fireemu at your existing `firebase.json` with `npx fireemu init --firebase-json firebase.json` or `--firebase-json` on the command line. Replace `firebase emulators:exec` with `fireemu exec` and `firebase emulators:start` with `fireemu up`; the official command names `emulators:exec` and `emulators:start` also work.

When a test fails under `strict` but passed on the official emulator, it is usually behavior the application would also meet in production. Fix the test or the application, or relax only the specific setting below instead of switching the whole profile.

- **Unsigned emulator ID tokens** (`@firebase/rules-unit-testing` `authenticatedContext()`, the client SDK's `mockUserToken`) work under `strict` by default. Set `auth.allowUnsignedIdTokens` to `false` to disable their fallback on the Security Rules surfaces. For a refusal test, use the SDK helper's default `iat: 0` / `exp: 3600` with a clock after expiry; fireemu-issued tokens that pass normal verification are still accepted. Use `auth.idTokenSigning = "session-rsa"` to refuse all unsigned ID tokens.
- **Composite indexes** are validated as production does: a query whose index is not defined (or is still building, or was deleted) is refused with `FAILED_PRECONDITION` and the console link to the index. Declare the index a query needs in `firestore.indexes.json`, referenced from `firebase.json`. To run such a query anyway and have each missing index reported once per database on stderr (with production's refusal text and the `firestore.indexes.json` entry), set `firestore.missingIndexes` to `"report"`; `productionExact` does not change this key.
- **Settings that mirror your production project.** Set them to match it instead of switching the profile:

| Setting | What it does under `strict` |
|---|---|
| `auth.improvedEmailPrivacy` | Email enumeration protection, on for a new production project. Set `false` only if your production project turned it off; sign-ins then answer `EMAIL_NOT_FOUND` and `INVALID_PASSWORD` as the official Auth emulator does |
| `auth.mfa` | Your project's multi-factor configuration (an object, see [Enable multi-factor authentication at start](#enable-multi-factor-authentication-at-start)). `strict` starts with SMS and TOTP enabled as a development default, `productionExact` starts with multi-factor off as a new production project does, and the official emulator has no TOTP at all. A declared block always decides, so `auth.mfa.state = "DISABLED"` makes enrollment fail as it does in a project that never enabled it |
| `firestore.enforceLimits` | Production always enforces the Standard edition query limits. `false` lets queries pass that production refuses, so leave it on unless you have a specific reason. Under `strict` it switches only the query limits |

### Basic configuration

The initial configuration selects Standard edition Firestore with the Native API.

```toml
#:schema https://fireemu.dev/spec/config/fireemu.schema.json
schemaVersion = 1
profile = "strict"

[firestore]
edition = "standard"
apiMode = "native"
```

You can also name the configuration file with `--config`.

```sh
npx fireemu up --config ./fireemu.toml
```

Keep Fireemu-specific settings in a Fireemu configuration file containing `schemaVersion = 1`, rather than in `firebase.json`. See the [configuration schema](spec/config/fireemu.schema.json) for all available settings.

### Firebase Authentication (Identity Platform) configuration

The `auth` section of `fireemu.toml` lets you configure sign-in methods, password policies, account permissions, and other authentication settings. Match your application’s configuration to test registration, sign-in, and account management behavior.

| What you can configure | Main settings |
|---|---|
| Enable or disable email/password, anonymous, and phone sign-in | `auth.signIn` |
| Test phone numbers and verification codes | `auth.signIn.phoneNumber.testPhoneNumbers` |
| Initial authorized domains for action-link continue URLs | `auth.authorizedDomains` |
| Handling of accounts that share an email address | `auth.signIn.allowDuplicateEmails` |
| Password length and character requirements, and policy enforcement at sign-in | `auth.passwordPolicy` |
| TOTP-based multi-factor authentication | `auth.totp` |
| Initial multi-factor authentication (MFA) configuration of a project, such as enabling TOTP under the `strict` profile | `auth.mfa` |
| Tenants that exist when the daemon starts, and the multi-tenancy switch | `auth.tenants`, `auth.multiTenant` |
| Restrictions on end-user account creation and deletion | `auth.client.permissions` |
| Email enumeration protection | `auth.improvedEmailPrivacy` |
| Project- and tenant-specific password policies and account permissions | `auth.passwordPolicyOverrides`, `auth.configOverrides` |
| Blocking functions before account creation or sign-in, and credential forwarding to those functions | `auth.blockingFunctions` |
| Initial custom OIDC and SAML provider resources | `auth.providers.oidc`, `auth.providers.saml` |
| Accept unsigned emulator custom tokens (default `true` in both profiles, `false` with `productionExact`) | `auth.allowUnsignedCustomTokens` |
| Allow unsigned mock ID token fallback after normal verification fails in Firestore and Storage Security Rules (default `true` in both profiles, `false` with `productionExact`; normally verified fireemu-issued tokens remain accepted) | `auth.allowUnsignedIdTokens` |
| Accept the fixture identity-provider assertions and sign-in widget (`"fixture"`, the default in both profiles), or verify signed assertions as production does (`"signed"`, `strict` only; the default with `productionExact` or `auth.idpSigners`) | `auth.idpAssertions` |
| Public keys for verifying custom tokens and OIDC ID tokens | `auth.customTokenSigners`, `auth.idpSigners` |
| Sign-up quota configuration and local quota-exceeded simulation | `auth.quota`, `auth.quotaSimulation` |

Unsigned custom tokens minted by the Firebase Admin SDK in emulator mode are accepted by default, including with the recommended `strict` profile and with `auth.customTokenSigners` configured. To require signed custom tokens, set `auth.allowUnsignedCustomTokens` to `false` and configure `auth.customTokenSigners` with the service accounts' public JWK sets. The setting applies only to custom-token sign-in; strict claim checks and signed-token verification still apply. In the `emulator` profile, setting it to `false` also disables JSON fake custom tokens.

The unsigned mock ID token of `@firebase/rules-unit-testing` is accepted by default when Firestore and Storage Security Rules are evaluated, including with the `strict` profile. This is the token `authenticatedContext()` and the client SDKs' `mockUserToken` option send (`createMockUserToken` in `@firebase/util`). Normal verification runs first. Only after it fails can the mock-token fallback accept a token. Under `strict` that fallback accepts only the exact SDK shape: a JWT whose header is exactly `{"alg":"none","type":"JWT"}` and whose signature is empty. `request.auth` is built from the token's claims, as the official emulator builds it, when the token names a subject (`sub`) and its audience (`aud`) is the project the request goes to. Its `exp` is not checked, because the SDK sets `iat: 0` and `exp: 3600` by default. Every other token is verified as before, expiry included. That covers the unsigned ID tokens fireemu itself issues (their header carries `typ`, not `type`), and a token that claims a signature that does not verify is still refused. The `emulator` profile accepts any unsigned token, as the official emulator does, and its Storage also accepts another project's token. Set `auth.allowUnsignedIdTokens` to `false` (in either profile) or set `productionExact` to disable this fallback. Neither setting refuses fireemu-issued unsigned ID tokens that pass normal verification. Changing only an issued token's header to the SDK shape can still pass normal verification of its payload; it is not a refusal test. For a refusal test, use `createMockUserToken` with its default `iat: 0` / `exp: 3600`, or construct that exact header and empty signature with those times, a subject and the routed project as audience, and run with a clock after expiry (including Firestore's 30-second allowance). A session with `auth.idTokenSigning = "session-rsa"` accepts no unsigned token. The setting does not affect callable Functions, Identity Toolkit or App Check.

See the [configuration schema](spec/config/fireemu.schema.json) for the format and accepted values of each setting.  

Declare `auth.authorizedDomains`, for example `["localhost", "app.test"]`, to set the initial project-wide list in either profile. The list replaces the defaults, so include `localhost` if your tests use it. An empty list authorizes no host under `strict`; an absent or `null` setting keeps the existing defaults (`localhost` and the project's `firebaseapp.com` and `web.app` domains). Validation uses the Admin API's rules for the selected profile, including its conversion of numeric and boolean entries to strings and omission of `null` entries; use strings when writing the list. Fireemu intentionally keeps `localhost` in its defaults for development. The [recorded production sandbox baseline](conformance/auth-action-production.json) does not include it; new production projects may also omit it. This default is a Fireemu-only convenience, and declaring the list replaces it. Tenant-scoped strict action links currently check the tenant's default domains rather than this project declaration; support for the parent project's live list is pending.

An Admin update changes the live list. A session reset restores the declared list, when present, and preserves an Admin-written list when no initial list was declared. Projects created later receive the declaration word for word, independently of the default project's live list; listing a particular project's `firebaseapp.com` or `web.app` domain therefore gives later projects that same domain. Clearing accounts leaves the live list alone. Auth export/import carries accounts without the domain list or its declaration. The `emulator` profile accepts the setting and exposes the list, while continuing to allow action-link continue URLs outside it.

Declare project OIDC and SAML resources with `auth.providers.oidc` and `auth.providers.saml`, using the Admin v2 resource fields and an ID-only `name` such as `oidc.fixture` or `saml.fixture`. Full resource names are refused. For example, `auth.providers.oidc = [{ name = "oidc.fixture", enabled = true, clientId = "local-client", issuer = "https://issuer.test", responseType = { idToken = true } }]` initializes that provider in both profiles. By default both profiles accept the fixture assertions the official emulator accepts (a JSON or unsigned ID token, a JSON SAML response, the sign-in widget); the emulator profile accepts them whether or not the provider is declared, and the strict profile refuses an `oidc.*` or `saml.*` provider that is not declared (or is disabled), as production does. With `auth.idpAssertions` set to `"signed"` (or `productionExact`, or `auth.idpSigners` present), strict OIDC sign-in needs matching public issuer keys in `auth.idpSigners`; no key is fetched. Strict SAML then uses the declared provider certificates and retains its existing assertion checks.

Each declared array replaces that provider kind; `[]` explicitly starts it empty, while an absent or `null` kind declares no initial resources. Admin operations change live resources until a session reset restores the declared kinds. Later session and routed projects inherit the declaration independently of the default project's live changes. Tenant resources and built-in providers remain separate. Clearing accounts preserves live resources; snapshots and Auth export/import transfer no provider resources or declarations. The emulator profile continues to accept its unsigned fixture credentials without requiring configured or enabled provider resources. These declarations require a canonical document with `schemaVersion = 1`; a Firebase deployment `auth.providers` section without that version remains deployment data and installs no provider seeds.

#### Example configuration

This example enables email/password and phone sign-in while disabling anonymous sign-in. It requires passwords of at least 12 characters containing uppercase letters, lowercase letters, and numbers, and prevents users from deleting their own accounts. Phone sign-in uses a configured test phone number and verification code.

```toml
#:schema https://fireemu.dev/spec/config/fireemu.schema.json
schemaVersion = 1
profile = "strict"

[firestore]
edition = "standard"
apiMode = "native"

[auth]
improvedEmailPrivacy = true

[auth.signIn]
allowDuplicateEmails = false

[auth.signIn.email]
enabled = true
passwordRequired = true

[auth.signIn.anonymous]
enabled = false

[auth.signIn.phoneNumber]
enabled = true

[auth.signIn.phoneNumber.testPhoneNumbers]
"+16505550101" = "123456"

[auth.passwordPolicy]
enforcementState = "ENFORCE"
forceUpgradeOnSignin = true

[auth.passwordPolicy.constraints]
minLength = 12
requireUppercase = true
requireLowercase = true
requireNumeric = true

[auth.client.permissions]
disabledUserSignup = false
disabledUserDeletion = true
```

For an existing `fireemu.toml`, add the settings you need to its `auth` section. Adjust the values to match your application’s requirements.

#### Project- and tenant-specific settings

Use `auth.passwordPolicyOverrides` to specify different password policies for individual projects or tenants. Use `auth.configOverrides` to customize account creation and deletion permissions and email enumeration protection.

These settings are separate from creating the project or tenant. Naming a tenant in `auth.configOverrides` or `auth.passwordPolicyOverrides` does not create it (declare it in `auth.tenants` to have it created).  

#### Enable multi-factor authentication at start

Under the `strict` profile, TOTP is enabled only through the project's MFA configuration, as in production, so `auth.totp` alone enables nothing there. By default that configuration is on (SMS and TOTP enabled), so a test needs nothing to enrol a second factor; `productionExact` starts a project with multi-factor off, as production does until it is enabled. Use `auth.mfa` to declare the configuration in the file instead of calling the Admin API in every session, to turn multi-factor off (`auth.mfa.state = "DISABLED"`), or to enable only what your production project does. It has the shape Identity Platform uses (`state`, `enabledProviders`, and `providerConfigs` with `totpProviderConfig.adjacentIntervals`):

```toml
schemaVersion = 1
profile = "strict"

[auth.mfa]
state = "ENABLED"

[[auth.mfa.providerConfigs]]
state = "ENABLED"

[auth.mfa.providerConfigs.totpProviderConfig]
adjacentIntervals = 1
```

- The configuration applies when the daemon starts, in both profiles, and to every project created afterward (not the default project's current value). It is validated as the Admin API validates an update of `mfa`, and a value production would refuse stops the daemon at startup.
- Nothing else changes. An Admin API update replaces the current configuration, and disabling MFA refuses TOTP as production does. A tenant follows its own `mfaConfig`, not this setting. The accepted TOTP window stays `auth.totp.windowSteps` unless the configuration sets `adjacentIntervals`.
- `POST /v1/sessions/{session}/reset` returns the project to the declared configuration, or to the default (SMS and TOTP enabled) when none is declared. Under `productionExact` without `auth.mfa`, a reset leaves a configuration set through the Admin API alone, as it does the rest of the project configuration. `DELETE /emulator/v1/projects/{project}/accounts` clears accounts only.
- An export does not carry the project's `mfa` configuration, so an imported project keeps its own `auth.mfa` or Admin-set configuration.
- The `emulator` profile keeps `auth.totp` working. Under `strict`, `auth.totp` is enough by default; under `productionExact`, or with an `auth.mfa` that leaves TOTP off, it prints a startup warning naming `auth.mfa`.

#### Enable multi-tenancy

Multi-tenancy works by default under both profiles: a new project allows tenants, so the Admin API creates them and `auth.tenants` loads without `multiTenant.allowTenants`. `productionExact` (`strict` only) starts a project as production does, with the switch unset until it is enabled through the Admin API, or with `auth.multiTenant` in the file (see "Start with tenants" below). A declared `allowTenants: false` always turns it off. See the [compatibility documentation](docs/compatibility-contract.md) for the supported Admin API scope. 

#### Start with tenants

Instead of creating tenants through the Admin API in every session, declare the default project's tenants and the multi-tenancy switch in the file. Each entry of `auth.tenants` is an Admin v2 `Tenant` document plus its `tenantId`. By default the id can be any readable name that starts with a letter and holds letters, digits and hyphens (up to 63 characters), such as `tenant-a`. With `productionExact` or `auth.tenantIdFormat: "generated"` it must have the form production generates, the display name, a hyphen, and five characters of `a-z0-9`, such as `acme-x7k2q`:

```toml
schemaVersion = 1
profile = "strict"

[auth.multiTenant]
allowTenants = true

[[auth.tenants]]
tenantId = "tenant-a"
displayName = "acme"
allowPasswordSignup = true

[auth.tenants.mfaConfig]
state = "ENABLED"
enabledProviders = ["PHONE_SMS"]
```

- A document is read by the code the Admin tenant create route reads one with, so a value production refuses stops the daemon at startup. The tenants are created empty, in file order, and settings such as `mfaConfig` and `passwordPolicyConfig` come from the document. The file is stricter than the route in the `emulator` profile: it also refuses an unknown member and a missing or invalid `displayName`, as production does.
- A declared tenant has what an Admin create with that document gives: an omitted `allowPasswordSignup`, `enableEmailLinkSignin` or `enableAnonymousUser` is off and multi-factor is off. A tenant the `emulator` profile creates on the way for a request that names an unknown id gets the official emulator's defaults instead (all three on, `PHONE_SMS` multi-factor), so declare what your test needs.
- Under the `strict` profile tenants are created only in a project that allows them, as in production. A new project allows them by default; with `productionExact`, or with `allowTenants: false` declared, `auth.tenants` needs `auth.multiTenant.allowTenants: true` (the daemon refuses to start otherwise). The `emulator` profile takes tenants without the switch.
- The default project and every session project (`POST /v1/sessions`) start with the declared switch and tenants. `POST /v1/sessions/{session}/reset` (the default session's included) creates them again, empty, and returns the switch to the declared value; without these keys a reset leaves an Admin-set switch alone. A namespace the `emulator` profile creates for an unknown project id (as the official emulator does) starts with the declared switch and tenants too: it is created by the requests that already created one (a user, a provider or a project setting written there) and by a request that writes a tenant there (creating one, or naming one that does not exist yet), not by a read alone. A session created for that project id (`POST /v1/sessions`) replaces the namespace, tenants included, and starts with the declared ones.
- With `--import`, an imported tenant is authoritative for its id, and a declared tenant the import did not carry is still created. If you keep re-importing your own export (`--import dir --export-on-exit dir`), an edit to a declared tenant is therefore ignored once its exported copy exists: the daemon prints a warning naming the tenant when the imported tenant's document differs from the declared one (every setting the file can declare is compared). The switch is the other way round: a declared `allowTenants` wins over the import. After a reset the declared version of a tenant comes back, not the imported one.

#### Test quota-exceeded behavior

Use `auth.quotaSimulation` to test sign-up quota-exceeded behavior locally. For example, add these settings to `fireemu.toml`:

```toml
[auth.quotaSimulation]
mode = "enforce"
defaultQuotaPerHour = 5
```

This is a local fixed-window simulation. It does not reproduce Firebase’s full quota accounting or abuse-prevention systems.  

### Configure execution time

Set the emulator’s starting time with `daemon.clockStart`. Configure the clock, time zone, and other scheduling behavior in the `scheduler` section. This lets you test scheduled functions independently of the actual time. If the Functions event queue is full (4,096 active events or 64 MiB), a scheduled run that comes due stays due and runs once room frees, and a manual run answers `429 RESOURCE_EXHAUSTED` without being queued. The clock can also move backwards (`clock:set` with `"allowBackwards": true`, or **Allow moving backwards** on the Runtime page). In the `emulator` profile, ID tokens stay usable after a rewind, as with the official emulator, which does not check their issue time. In the `strict` profile, Authentication (`INVALID_ID_TOKEN`), Cloud Firestore and Cloud Storage refuse an ID token issued after the new time until the clock reaches its issue time again. In both profiles an expired token is still refused. A rewind to before an account was created, or before its tokens were revoked, makes even a new sign-in's token count as revoked; move the clock forward again or reset the session instead. Conversely, a revocation or password change made after a rewind does not revoke tokens issued at later times on the timeline: the `emulator` profile accepts them at once, and `strict` accepts them once the clock reaches their issue time. Move the clock forward past their issue time before revoking, or reset the session.

A schedule is driven by the virtual clock alone: real time passing runs nothing. Each clock move (`clock:advance`, `clock:advanceTo`, `clock:set` or the Runtime page) makes every occurrence in `(previous time, new time]` due, so an occurrence exactly at the new time is included and one exactly at the previous time is not. `scheduler.catchUp` decides what runs: `all` runs each one (at most `scheduler.maxCatchUpRuns` per job and clock move, the rest stays due and runs as room frees), `latest` runs the newest and `none` runs none, and both record one `skipped: catch-up` summary per job and clock move that drops runs. A rewind never replays: occurrences the schedule already passed are not run again when the clock moves forward over them, and the schedule resumes once the clock passes the last occurrence it ran or still owes (its cursor). After a rewind below that point, runs still owed from a backlog or held for room stay owed but do not come due again until the clock passes it. A session reset or a snapshot restore starts every schedule from the clock's current time instead, so after a rewind the occurrences between that time and a later one are due again. `scheduler.overlap` (`allow`, `skip`, `queue`, `reject`, `skip-in-flight`) applies to scheduler runs and manual runs alike, except `skip-in-flight`, which never refuses a manual run. Unset, the strict profile uses `skip-in-flight`: an occurrence is dropped (recorded as `skipped: in flight`) while a handler of the function that started before the clock move is still executing, as production's Cloud Scheduler did, and the occurrences of one clock move do not count against each other; the emulator profile uses `allow`. A function counts as busy while any of its runs is queued or running, including a run that is waiting to be retried, so under `skip` and `reject` a retry still pending can suppress the next occurrence; fireemu does not distinguish a retry attempt from an overlapping run here. With `catchUp: all`, one clock move over several occurrences of the same function overlaps itself, so `skip` keeps the oldest of them and `reject` counts the rest as rejections.

A manual run (`POST /v1/sessions/{session}/functions/{name}:run`) enqueues one run of a scheduled function stamped with the current virtual time. It does not consume the next occurrence, which still comes due and is subject to `scheduler.overlap` like any run. It answers `400 INVALID_ARGUMENT` for an unknown function, a function that is not scheduled, an overlap policy refusal, or a runtime that is shutting down, and `429 RESOURCE_EXHAUSTED` when the event queue is full. This is fireemu's own control, not a claim about production's run-now.

On a task-queue function (`onTaskDispatched`), the same `POST /v1/sessions/{session}/functions/{name}:run` releases the Cloud Tasks that wait for their `scheduleTime`: all of them, or the one named by a `{"task": "<task id>"}` body (404 when no waiting task has that id). Under the strict profile a task enqueued with a `scheduleTime` waits for it, so this is how a test runs a task due in an hour without moving the clock; a released task still obeys the queue's rate and concurrency limits. The Functions page of the Emulator UI lists the waiting tasks with their due time and a **Run now** button.

See the [configuration schema](spec/config/fireemu.schema.json) for available settings and values. 

### Firestore history limits

Like production, Fireemu keeps every version of a document written in the last hour, so a `read_time` read, a read-only transaction or a resumed listener can see it. A test that updates the same documents many times therefore holds many versions in memory. These limits are local; production has none of them:

- Each database retains at most 1 GiB of logical history bytes and 1,000,000 versions, each session 1 GiB and 1,000,000 versions, and the daemon 4 GiB and 4,000,000 versions. Logical bytes follow Firestore's storage size model and are not the process's memory, which can be several times larger.
- On a pinned clock (`daemon.clockStart`), time does not pass on its own, so a database keeps at most 1,024 versions of any one document. This limit works like `maxVersionsPerPath` below: once a document goes past it, older snapshots are released for the whole database.
- A commit that would cross a limit is refused whole with `RESOURCE_EXHAUSTED` and the message `Firestore retained history capacity is exhausted`.

Versions older than an hour are released by the next commit after the clock passes them. To use less memory, lower the limits in the `firestore.history` section:

```toml
schemaVersion = 1

[firestore]
edition = "standard"
apiMode = "native"

[firestore.history]
maxVersionsPerPath = 16
maxBytes = 268435456
```

- `maxVersionsPerPath` (1 to 1,000,000) sets the most versions of one document a database keeps, on either clock, in place of the defaults above.
- `maxBytes` (1 MiB to 1 GiB) lowers the logical history bytes one database retains. An import (`--import`) is not checked against it: a larger import starts with a `warning:` line naming the database, its bytes and the limit (a snapshot restore above it logs the same line), and every later write that would grow the history is refused with `RESOURCE_EXHAUSTED`.

Without these keys the defaults apply.

The version cap applies to each document separately, but its effect reaches the whole database. Snapshots stay exact for every document, so once any document has more versions than the cap, the database keeps no snapshot older than that document's oldest kept version. After that:

- A `read_time` read older than that point is refused with `FAILED_PRECONDITION` (`The requested 'read_time' is no longer retained by this database.`). So is a new read-only transaction at such a `read_time` (`read_time is no longer retained by this database`).
- A transaction already open on an older snapshot fails its next read or commit with `ABORTED` (`The referenced transaction has expired or is no longer valid.`), even if it only touches other documents.
- A listener resuming from an older point is reset and sent the full result again.

Client SDKs retry `ABORTED` transactions. One frequently updated document under a small cap can therefore keep aborting unrelated transactions. Avoid very small caps: choose a cap above the number of times any document is updated while your longest transaction is open.

To see how much history a running daemon holds, run `fireemu doctor --connect <control URL>`. Its `history.*` lines report the retained versions and logical bytes against the session and daemon limits, and how many bytes the next compaction would release.

### Storage stored-byte limit

The Storage emulator keeps every object in memory, and by default nothing bounds how much. To cap it, set `storage.maxStoredBytes` (bytes, at least 1). Production has no such limit; it is local to Fireemu:

```toml
schemaVersion = 1

[storage]
maxStoredBytes = 1073741824
```

- Each object counts its bytes once, and a copy counts again. Replacing an object counts only the difference in size.
- An upload, a resumable upload's final request or a copy that would grow the total past the limit is refused with HTTP 402 and the message `storage.maxStoredBytes limit exceeded` (in the JSON API, with the reason `storageCapacityExceeded`). There is no `Retry-After`. Delete objects to make room. The Firebase client SDKs report a 402 at once as `storage/quota-exceeded` without retrying; the Cloud Storage client libraries do not retry it either.
- A write that does not grow the total, such as an equal or smaller replacement, always passes, even while the store holds more than the limit (after an import, a restore or a lowered limit).
- A refused write changes nothing. A resumable upload stays open: its offset does not advance, so you can send the same final chunk again after making room, or cancel the upload.
- An import (`--import`) and a snapshot restore are not checked against the limit. An import above it starts with a `warning:` line naming the stored bytes and the limit, and a snapshot restore above it logs the same line.

`fireemu doctor --connect <control URL>` reports the stored bytes as `objects.bytes` against this limit.

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

### Network exposure of the Storage port

Like the official emulator, the Storage port reflects the requested object name in the HTML body of its 404 for a missing media read (`text/html`, as production answers). A web page opened on the developer's machine could therefore run script on that origin. Keep the emulator bound to localhost, which is the default, and do not expose the Storage port to other hosts or networks. The strict profile sends no `X-Content-Type-Options: nosniff` on the JSON API answers where production sends none, so it does not add that defence in depth; the emulator profile keeps the official emulator's header.

### Run in a container

By default every listener is on loopback, which a published container port cannot reach. To serve the emulators to the host or to other containers, opt in with `network.allowNonLoopbackHosts` in `fireemu.toml` and give the product emulators a host in `firebase.json`:

```toml
schemaVersion = 1
firebaseJson = "firebase.json"

[network]
allowNonLoopbackHosts = true
```

```json
{ "emulators": { "firestore": { "host": "0.0.0.0", "port": 8080 }, "auth": { "host": "0.0.0.0", "port": 9099 } } }
```

- Only Firestore, Auth, Storage, Functions, Eventarc, Cloud Tasks and Pub/Sub may listen off loopback. The Hub, the UI and the Logging emulator stay on loopback. Auth, whose port also serves the control API, listens on loopback or on every interface (`0.0.0.0` or `::`), not on one other address.
- The emulators serve without a credential, so the start prints a `warning:` line for each listener off loopback. Any client that reaches a published port can do what a local client can on the product APIs, including the Admin SDK's `Bearer owner` credential and the Auth emulator's own routes. Publish the ports only to a network you trust.
- Fireemu's own controls answer loopback peers only and return 403 to any other peer: the control API (`/v1/` and `/health/` on the Auth port), App Check debug-token management, and the routes that load Security Rules or clear Firestore data (what `@firebase/rules-unit-testing`'s `loadFirestoreRules`, `loadStorageRules` and `clearFirestore` call). Run the code that uses them in the emulator's network namespace: inside the container, or in a container that shares it (a Podman pod, `--network container:<name>`).
- Because a forwarder inside that namespace (`kubectl port-forward`, a sidecar proxy) connects from loopback, every control API request also needs `Authorization: Bearer <control token>` once the option is on, from a process as from a page; only `/health/` is exempt. The routes that load Security Rules or clear Firestore data are not held to the token, so `@firebase/rules-unit-testing` keeps working; a client that reaches the emulator through such a forwarder can call them, as it could on the official emulator. `fireemu exec` gives its command the token in `FIREEMU_CONTROL_TOKEN`, and `fireemu/testing` and the UI send it.
- Browser pages must still come from a loopback origin (`http://localhost:...`), so a page served from another host cannot use the exposed ports.
- A listener on `0.0.0.0` or `::` is advertised as `127.0.0.1` or `::1` in the environment and the Hub, as the official CLI does.

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
