# fireemu

An experimental local runtime for testing Firebase SDK and Functions code.

Some Firebase failures are easy to miss locally. A query may need a composite index in production even though it passes against the official emulator. Production limits may reject a request that looked fine during development. Finding those problems only after running against a real Firebase project makes the feedback loop slow and can leave test data behind.

fireemu was built for two jobs:

- catch selected production-facing problems earlier, including missing Firestore indexes and production limit violations;
- keep local test runs fast, with no JVM emulator to start and a single command that starts the services, runs the test command, and shuts everything down.

fireemu is experimental. It is not a replacement for the official Firebase Emulator Suite or for testing against a real Firebase project. Use it as an additional test target, keep the official emulator in your test matrix, and verify important flows against production before shipping.

## Quick start

Node.js 20 or newer is required. For Functions, an explicit `functions.runner` command wins and `FIREEMU_NODE` is an exact executable override. On Unix, automatic selection probes the first Node executable on `PATH` plus installed runtimes under `VOLTA_HOME` before loading user code. This limits automatic execution to normal command resolution and explicitly configured version-manager storage. For a Node 20 or newer request, candidates that can synchronously load an ES module from CommonJS are ranked first; the `firebase.json` runtime major, `package.json` `engines.node`, and stable discovery order then break ties. A loader-capable local fallback may therefore use a different major when the requested candidate lacks that loading capability, and the mismatch is reported. A malformed engine constraint still fails before loading. The runner never evaluates user code under one automatic candidate and retries it under another. On Windows, `FIREEMU_NODE` is used directly when set and otherwise the first `node` on `PATH` is used, matching the previous runner behavior; use `functions.runner` when an exact Windows runtime is required.

```sh
npm install --save-dev fireemu
npx fireemu init
npx fireemu doctor
npx fireemu exec -- npm test
```

`npx fireemu init` creates `fireemu.json` in the current directory. In a terminal, a short wizard asks which compatibility profile to use and whether to reuse an existing `firebase.json`.

The recommended `strict` profile enables additional validation, including checks intended to expose some failures that the official emulator does not report. Choose the `firebase` profile when matching the pinned official emulator is more important.

If `firebase.json` exists, `init` references it instead of copying its settings. Rules, indexes, Functions codebases, and emulator ports are loaded from that file each time fireemu starts.

For CI or scripted setup, use the non-interactive form:

```sh
npx fireemu init --yes
```

An existing `fireemu.json` is left untouched unless `--force` is supplied. Other useful options are `--profile strict|firebase`, `--firebase-json <path>`, `--interactive`, and `--no-interactive`.

The generated configuration uses Standard edition Firestore with the Native API:

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

See the [configuration schema](spec/config/fireemu.schema.json) for the complete set of options.

## Installation

Install fireemu as a development dependency:

```sh
npm install --save-dev fireemu
```

The npm package installs the binary for the current platform as an optional dependency. There is no install script, and no component is downloaded after npm finishes resolving the package.

| Platform | Architecture |
| --- | --- |
| macOS 13 or newer | Apple silicon, Intel |
| Linux | x86-64, arm64 |
| Windows 10 or newer | x86-64 |

Linux packages are statically linked. Java is not required. Running a Functions codebase requires Node.js and `firebase-functions` v6 or v7 in that codebase.

Release archives and SHA-256 checksums are also available from [GitHub Releases](https://github.com/reckona/fireemu/releases).

## Usage

Start the configured services until interrupted:

```sh
npx fireemu up
```

Start the services, run a test command, and stop the services when the command exits:

```sh
npx fireemu exec -- npm test
npx fireemu exec -- npx vitest run
```

`exec` returns the child command's exit status and forwards SIGINT and SIGTERM. It also exports the emulator host variables used by Firebase SDKs.

The official CLI spellings are available as aliases:

```sh
npx fireemu emulators:start
npx fireemu emulators:exec -- npm test
```

Limit a run to selected services with `--only`:

```sh
npx fireemu exec --only auth,firestore,storage -- npm test
```

Common commands:

| Command | Purpose |
| --- | --- |
| `fireemu init` | Create `fireemu.json` through a short wizard or non-interactively |
| `fireemu up` | Start the configured services |
| `fireemu exec -- <command>` | Start the services, run one command, then stop |
| `fireemu emulators:export <dir>` | Export data from a running suite |
| `fireemu doctor` | Check the installed binary, Node.js, UI, and Functions runner |
| `fireemu capabilities` | Print the current capability manifest |

On Windows, `emulators:export` and `--export-on-exit` currently fail before writing any path. Import and the rest of the emulator runtime remain available. Atomic export publication will be enabled when the Windows implementation can provide the same identity-bound replacement and cleanup guarantees as the Unix implementation.

On Unix, export publication also refuses a destination below any namespace ancestor that is owned by another user, writable by the group or other users, or, on macOS, carries an extended ACL. Choose a dedicated directory below a private namespace rather than `/tmp` or a shared project directory. This restriction ensures that cleanup can remove only the private stage identity created by the current process.

## Supported features

The following is a product-level summary, not a claim that every API and edge case is implemented.

| Product | Current scope |
| --- | --- |
| Cloud Firestore | Native-mode gRPC, REST, and WebChannel access; transactions, queries, listeners, indexes, limits, and Security Rules |
| Firebase Authentication | Client and Admin REST surfaces, emulator actions, custom tokens, email and phone flows, MFA, tenants, and fixture identity providers |
| Cloud Storage for Firebase | Firebase and JSON object APIs, resumable uploads, generations, listing, and Security Rules |
| Cloud Functions for Firebase | v2 HTTP, callable, Firestore, Storage, and scheduled functions through the bundled Node.js runner |
| Cloud Pub/Sub | The documented gRPC subset used by the supported Functions flows |
| Emulator logging | The EmulatorLog WebSocket with bounded local history |
| Firebase App Check | A fireemu-specific local implementation; this is not an official Emulator Suite parity claim |
| Emulator UI | A fireemu UI for supported data and controls; official UI workflow parity is not claimed |

Run `fireemu capabilities` or inspect the [Capability Manifest](crates/fireemu/src/capabilities.json) before depending on a specific API. Each capability records whether it is implemented, partial, validation-only, or unsupported.

## Gap from production Firebase

fireemu aims to catch selected failures before a production run, but it does not reproduce the Firebase backend.

- Strict mode checks known Firestore index and request-limit cases, but it cannot guarantee that every request accepted locally will be accepted by production.
- Real quota accounting, billing, IAM, organization policy, regional behavior, network conditions, and service rollouts are outside the local runtime.
- Security Rules and SDK behavior are implemented against documented and measured behavior, but the hosted services remain the source of truth.
- Performance results from a loopback process do not predict production latency or throughput.

These are the gaps currently known and documented by the project, not an exhaustive list. Firebase changes independently, and unrecorded differences may exist. Test important workflows against a real Firebase project before release.

## Gap from the official Firebase Emulator Suite

fireemu is compatible with the listed Local Emulator Suite products as shipped by firebase-tools 15.28.2 -- Cloud Firestore, Firebase Authentication, Cloud Storage for Firebase, Cloud Functions and Cloud Pub/Sub, with Security Rules on the Firestore and Storage surfaces -- under the `firebase` compatibility profile and the evidence recorded in `spec/compatibility/contract.json`; it makes no complete-suite and no unqualified superset claim while Realtime Database, Firebase Hosting, App Hosting and Data Connect are deferred, Firebase Extensions is not planned, and the Emulator UI, the Emulator Hub, Eventarc and Cloud Tasks remain open gaps.

In practical terms:

- the `firebase` profile targets the behavior of the pinned Firebase Emulator Suite release, while `strict` deliberately adds refusals and validation;
- fireemu serves its own UI, but does not claim workflow parity with the official Emulator Suite UI;
- Eventarc and Cloud Tasks remain unsupported gaps;
- Realtime Database, Firebase Hosting, App Hosting, and Data Connect are deferred and not served;
- Firebase Extensions is not planned.

This list reflects differences known to the project at the current compatibility baseline. It may be incomplete. The [Compatibility Contract](spec/compatibility/contract.json) is the authoritative machine-readable scope, and [the compatibility contract guide](docs/compatibility-contract.md) explains how claims are tied to tests and conformance evidence.

## Why use both profiles?

The two profiles answer different questions:

| Profile | Question it helps answer |
| --- | --- |
| `strict` | Can this test expose selected production-facing mistakes earlier? |
| `firebase` | Does this behavior match the pinned official emulator closely enough for the declared capability? |

`npx fireemu init` recommends `strict`. Use both profiles in CI when both questions matter.

## Project status

fireemu is under active development and has not reached a stable compatibility promise. Configuration, unsupported behavior, and edge-case semantics may change between releases.

Bug reports that include the Firebase product, SDK version, fireemu profile, and a minimal reproduction are especially useful. When reporting a compatibility problem, note whether the reference behavior came from production Firebase or the official emulator; they do not always behave the same way.

## License

fireemu is licensed under the [Apache License 2.0](LICENSE). Third-party notices are listed in [THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt).
