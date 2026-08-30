# fireemu

A deterministic, test-only local runtime for Firebase SDK and Functions code, written in Rust.

`fireemu` is not a faster re-implementation of the Firebase Emulator Suite. Its core is a
deterministic state machine that detects missing Firestore indexes, production limit violations
and inefficient queries locally; isolates state, events, time and Function execution per project
so parallel tests stay deterministic; runs scheduled Functions against a virtual clock and offers
`await-idle` instead of `sleep`; reproduces retries, duplicate delivery, delays and conflicts as
seeded fault injection; and never claims compatibility it cannot show -- every feature is declared
in a Capability Manifest with an explicit precision.

The real `firebase-admin`, `firebase` (Node and browser) and `firebase/firestore/lite` SDKs run
against it unchanged.

## Install

```sh
npm install -D fireemu
npx fireemu doctor
```

```sh
pnpm add -D fireemu        # or: pnpm dlx fireemu doctor
yarn add -D fireemu
```

Nothing is downloaded at install time and there is no install script. `fireemu` is a small Node
launcher; the daemon for your platform arrives as an optional dependency
(`@fireemu/darwin-arm64` and friends), so npm installs exactly one binary and skips the rest.
An install that resolved from a cache or a private registry is a complete, offline installation.

## Use

```sh
npx fireemu up --firestore-port 8080 --http-port 9099 --storage-port 9199
```

`exec` is the `firebase emulators:exec` equivalent: it serves the same, runs a command with the
emulator host variables once every listener is bound, stops everything when the command exits and
exits with its status.

```sh
npx fireemu exec --firebase-json firebase.json --project my-app --only auth,firestore,storage -- vitest run
```

The command receives `FIRESTORE_EMULATOR_HOST`, `FIREBASE_AUTH_EMULATOR_HOST`,
`FIREBASE_STORAGE_EMULATOR_HOST` / `STORAGE_EMULATOR_HOST`, `GOOGLE_CLOUD_PROJECT` /
`GCLOUD_PROJECT`, and `FIREEMU_CONTROL_TOKEN` / `FIREEMU_CONTROL_URL` for the control API.

An Emulator UI is compiled into the binary and served at `http://127.0.0.1:4000/ui`
(`--ui-port 0` turns it off).

## Supported platforms

| Package | OS | Arch | Built for |
| --- | --- | --- | --- |
| `@fireemu/darwin-arm64` | macOS 13+ | Apple silicon | `aarch64-apple-darwin` |
| `@fireemu/darwin-x64` | macOS 13+ | Intel | `x86_64-apple-darwin` |
| `@fireemu/linux-x64` | Linux (any libc) | x86-64 | `x86_64-unknown-linux-musl`, static |
| `@fireemu/linux-arm64` | Linux (any libc) | arm64 | `aarch64-unknown-linux-musl`, static |
| `@fireemu/win32-x64` | Windows 10+ | x86-64 | `x86_64-pc-windows-msvc` |

The Linux builds are statically linked against musl, so they run on any distribution and inside
distroless and Alpine containers.

## Prerequisites

- **Node 20 or newer** to run the launcher, and to run a Functions codebase. Nothing else needs
  Node; Firestore, Auth, Storage and the UI are served by the binary itself.
- **No Java.** Unlike the Firebase Emulator Suite, `fireemu` runs no JVM emulator.
- For `--functions <dir>`: the codebase's own `node_modules`, with `firebase-functions` v6 or v7
  and `firebase-admin`. `npx fireemu doctor` prints the range the bundled runner supports.

## Check an installation

```sh
npx fireemu doctor
```

It reports the version and platform of the installed binary, whether the Emulator UI is compiled
in, where the Node runner was found and which `firebase-functions` majors it instruments, the Node
version, and that no JVM is required. Anything missing comes with a remediation line, and a broken
installation exits non-zero so a setup script can gate on it. The report carries versions and paths
only -- never tokens, keys, or the contents of a configuration file.

## Upgrade, uninstall, offline

- **Upgrade**: `npm install -D fireemu@<version>`. The launcher pins its platform packages to its
  own exact version, so `fireemu@1.2.3` can only resolve `@fireemu/linux-x64@1.2.3` -- an upgrade
  moves the binary and the launcher together, never one without the other.
- **Uninstall**: `npm uninstall fireemu`. Nothing is installed outside `node_modules`: no cache
  directory, no global binary, no downloaded component.
- **Offline**: `npm install --offline` works once the tarballs are in the npm cache, and so does
  installing from a private registry that mirrors the `fireemu` and `@fireemu` packages. Warm a
  cache with `npm install` on a machine of the same platform, or vendor the tarballs with
  `npm pack`.
- **A vendored or self-built binary**: set `FIREEMU_BINARY_PATH` to it and the launcher runs that
  instead of resolving a platform package.
- **If the binary is missing**: the launcher says which package it looked for and what is
  published. The usual cause is an install that skipped optional dependencies
  (`--omit=optional`, `--no-optional`, or a lockfile built on another platform).

## Documentation and source

<https://github.com/reckona/fireemu>

## License

Apache-2.0
