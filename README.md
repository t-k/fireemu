# Fireemu

[![npm](https://img.shields.io/npm/v/fireemu)](https://www.npmjs.com/package/fireemu)

Fireemu is a local emulator for testing applications built with Firebase. It aims to match production Firebase behavior as closely as possible, so you can test locally and in CI without using a real Firebase project.

Passing tests against the official emulator does not always mean your application will behave the same way in production. Fireemu is being developed to close that gap. For example, it provides:

- **Validation of configuration required in production:** Fireemu detects issues that the official emulator misses, such as missing Firestore index definitions.
- **Support for features not available in the official emulator:** Fireemu also supports features such as TOTP-based multi-factor authentication.
- **Control over test execution conditions:** You can set an arbitrary time and run scheduled functions to verify their behavior without waiting for the actual scheduled time.

Fireemu is still in development and does not yet reproduce every feature and behavior of production Firebase. Before relying on its results in CI, run the same tests against Fireemu and a dedicated Firebase test project (not your live production project) for the features and critical workflows your application uses, and check for differences.

**Documentation:** <https://t-k.github.io/fireemu/>

## Quick start

Node.js 20 or newer is required. Fireemu runs on macOS 13 or newer (Apple silicon, Intel), Linux (x86-64, arm64) and Windows 10 or newer (x86-64). Running Functions requires `firebase-functions` v6 or v7 in the codebase.

```sh
npm install --save-dev fireemu
npx fireemu init

# Start the emulator
# UI (default): http://127.0.0.1:4000/ui/
npx fireemu up
```

Press `Ctrl+C` to stop the emulator. To run the emulator only for the duration of a command, use `exec`. It sets the Firebase SDK emulator host environment variables for the command and returns its exit status:

```sh
npx fireemu exec -- npm test

# Start only some services
npx fireemu exec --only auth,firestore,storage -- npm test
```

The official command names `emulators:start` and `emulators:exec` work as aliases. `up` and `exec` read `fireemu.toml` (or an existing `fireemu.json`) from the current directory, or, when there is none, the nearest `firebase.json`; the first lines of the startup output name the files that were loaded. Run `npx fireemu --help` and `npx fireemu <command> --help` for every option, and `npx fireemu doctor` if the emulator does not start.

See [Install and run](https://t-k.github.io/fireemu/getting-started/install/), [Connect your app](https://t-k.github.io/fireemu/getting-started/connect/) and [Migrate from the Local Emulator Suite](https://t-k.github.io/fireemu/getting-started/migrate/).

### Testing helpers

The npm package also ships `fireemu/testing`, which starts independent emulator worlds with their own daemon, ports, clock and data for parallel integration tests, and `fireemu/control`, a client for the control API:

```js
import { withTestWorld } from 'fireemu/testing';

await withTestWorld(
  { services: ['auth', 'firestore'], clockStart: '2026-01-31T23:59:00Z' },
  async (world) => {
    await world.clock.advance(60_000);
    await world.run(process.execPath, ['./test.mjs']);
  },
);
```

See [Time and scheduled functions](https://t-k.github.io/fireemu/guides/time/) and [test clocks and independent worlds](docs/test-worlds.md).

## Supported scope

| Product | Summary | Documentation |
|---|---|---|
| Cloud Firestore | Standard and Enterprise editions, composite index validation, Security Rules; the Enterprise Pipeline API supports a subset of read operations, and text search is a local lexical engine | [Cloud Firestore](https://t-k.github.io/fireemu/products/firestore/) |
| Firebase Authentication (Identity Platform) | Sign-in methods, TOTP and SMS multi-factor authentication, multi-tenancy, OIDC and SAML providers, blocking functions; flows that talk to external identity providers are outside the scope | [Authentication](https://t-k.github.io/fireemu/products/auth/) |
| Cloud Storage for Firebase | Firebase and JSON APIs, Security Rules; signed-URL signatures, IAM, `compose` and notification configuration are outside the scope | [Cloud Storage](https://t-k.github.io/fireemu/products/storage/) |
| Cloud Functions for Firebase | HTTP, callable, event, task-queue, blocking and scheduled functions on a virtual clock | [Cloud Functions](https://t-k.github.io/fireemu/products/functions/) |
| Cloud Pub/Sub and Eventarc | Topics, subscriptions, push and pull delivery, dead-letter topics and StreamingPull; Eventarc custom events for Functions | [Pub/Sub and Eventarc](https://t-k.github.io/fireemu/products/pubsub-eventarc/) |
| Firebase Realtime Database (an open gap: no parity claim against the official emulator) | REST, realtime protocol, Security Rules, export and import; production parity is verified for the recorded cases only | [Realtime Database (open gap)](https://t-k.github.io/fireemu/products/realtime-database/) |
| Firebase App Check | Local testing with debug tokens; no real attestation providers or replay protection | [App Check](https://t-k.github.io/fireemu/products/app-check/) |

Firebase Hosting, App Hosting and Data Connect are deferred (not currently supported), and Firebase Extensions support is not planned. Fireemu also provides a UI for managing data and viewing logs.

This table is a summary, not an exhaustive list. See [Limitations](https://t-k.github.io/fireemu/compatibility/limitations/), the [capability manifest](crates/fireemu/src/capabilities.json) (also printed by `npx fireemu capabilities`) and the [Functions support inventory](docs/functions-export-inventory.md) for individual APIs and conditions.

## Compatibility

Fireemu has two compatibility profiles:

| Profile | Behavior |
|---|---|
| `strict` | Matches production Firebase behavior and constraints as closely as possible within the supported scope. This is the default profile. Recommended, including when migrating from the official emulator |
| `emulator` | Targets the behavior of a pinned version of the official emulator. Use it only to check alignment with the pinned official emulator (for example as an extra test target); it is not needed for a migration |

Where production needs setup that a test should not have to do (signed tokens, signing keys, enabling a feature through an Admin API call), both profiles use a documented development default with its own setting, and `productionExact = true` restores production's behavior for all of them. See [Profiles and productionExact](https://t-k.github.io/fireemu/guides/profiles/).

Each area is compared with recordings from real Firebase projects. The [compatibility tables](https://t-k.github.io/fireemu/compatibility/) list the areas verified against production, and the [compatibility documentation](docs/compatibility-contract.md) explains the verification process and how to read its records.

### Comparison with the official emulator

The official emulator comparison baseline is `firebase-tools 15.28.2`.

Fireemu is compatible with the listed Local Emulator Suite products as shipped by firebase-tools 15.28.2 -- Cloud Firestore, Firebase Authentication, Cloud Storage for Firebase, Cloud Functions, Cloud Pub/Sub and Eventarc, with Security Rules on the Firestore and Storage surfaces -- under the `emulator` compatibility profile and the evidence recorded in `spec/compatibility/contract.json`; it makes no complete-suite and no unqualified superset claim while the Realtime Database is served without a parity claim (an open gap), Firebase Hosting, App Hosting and Data Connect are deferred and Firebase Extensions is not planned.

The [compatibility contract](spec/compatibility/contract.json) records scope and known differences. A successful local operation does not guarantee the same result in production: Fireemu does not reproduce real quota accounting, billing, IAM, organization policies, regional or network differences, or service rollouts.

## Configuration

`npx fireemu init` creates a minimal `fireemu.toml`:

```toml
#:schema https://raw.githubusercontent.com/t-k/fireemu/main/spec/config/fireemu.schema.json
schemaVersion = 1
profile = "strict"

[firestore]
edition = "standard"
apiMode = "native"
```

Keep Fireemu-specific settings in `fireemu.toml` and point it at your existing `firebase.json` (`npx fireemu init --firebase-json firebase.json`), whose rules, indexes, Functions codebases and ports are read on every start. `npx fireemu config show` prints every key with its effective value and source.

- [Configuration files](https://t-k.github.io/fireemu/guides/configuration/): which files are loaded and the ownership checks on discovered files
- [Configuration schema](https://t-k.github.io/fireemu/reference/configuration/): every section, and the [JSON Schema](spec/config/fireemu.schema.json)
- Guides: [Security Rules](https://t-k.github.io/fireemu/guides/security-rules/), [Time and scheduled functions](https://t-k.github.io/fireemu/guides/time/), [Export and import data](https://t-k.github.io/fireemu/guides/data/), [Emulator UI](https://t-k.github.io/fireemu/guides/ui/), [CI and containers](https://t-k.github.io/fireemu/guides/ci-and-containers/), [Troubleshooting](https://t-k.github.io/fireemu/guides/troubleshooting/)
- [CLI reference](https://t-k.github.io/fireemu/reference/cli/)

Keep the emulator bound to localhost (the default); see [CI and containers](https://t-k.github.io/fireemu/guides/ci-and-containers/) before exposing ports to other hosts.

## Performance

In the benchmark against the official Firestore emulator, Fireemu starts about 21.6 times faster and uses about 1/34 of the idle memory. See [Performance](https://t-k.github.io/fireemu/compatibility/performance/) for the method and the full results.

## Changes between versions

Configuration and behavior may change between releases. See the [CHANGELOG](CHANGELOG.md).

## Reporting issues and contributing

When reporting an issue, include the Fireemu and Firebase SDK versions, the profile used, the Firebase product involved, and a minimal reproduction. For compatibility issues, also state whether you are comparing against the actual Firebase service or the official emulator, along with the expected and actual results. Remove credentials and personal information before sharing configuration files or logs.

See the [development guide](docs/development.md) for build and test instructions.

## License

Fireemu is licensed under the [Apache License 2.0](LICENSE). Third-party notices are listed in [THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt).
