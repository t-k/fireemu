# Apple SDK smoke on macOS

This SwiftPM executable exercises Firebase Apple SDK **12.18.0** against local fireemu and **firebase-tools 15.28.2**. It uses native macOS clients, including Firestore's C++ gRPC implementation, without a simulator. All dependency revisions are committed in `Package.resolved` and `package-lock.json`.

Use Xcode 26.2 or newer and `xcrun swift`. The SDK requires Swift tools 6.1. This tool targets macOS 13 or newer. No Firebase project, credential, configuration plist, developer signing identity or production request is needed. The executable accepts only a `demo-` project and explicit IPv4 loopback/localhost emulator endpoints. All four products call their `useEmulator` APIs before operations. Firestore also explicitly disables TLS, because the pinned Apple SDK's emulator method sets its host without disabling TLS.

## Run

From this directory:

```sh
xcrun swift package --cache-path .cache resolve
git diff --exit-code -- Package.resolved
xcrun swift build --jobs 2 --disable-automatic-resolution --cache-path .cache
xcrun swift test --jobs 2 --disable-automatic-resolution --cache-path .cache
python3 -m unittest test_run.py
cargo build --locked -p fireemu --manifest-path ../../Cargo.toml --jobs 2
../../target/debug/fireemu exec --project demo-app --no-config-discovery --firebase-json firebase.json --only auth,firestore,storage,database --firestore-port 0 --http-port 0 --storage-port 0 --database-port 0 --hub-port 0 --logging-port 0 --log-verbosity silent -- python3 run.py --binary .build/debug/sdk-smoke-swift --output logs/fireemu
```

The output directory must not exist. Each case runs in a fresh process with a 30-second deadline and emits a sanitized JSON result. The aggregate fails if any required case is missing, failed or blocked. A blocked SDK case is not a pass. A fresh emulator owns the fixture lifetime, and `fireemu exec` closes it after the runner exits. Local parallel sessions should use a port registry; fireemu's zero ports request OS-assigned ports.

For the official comparison, install the tool's independent locked dependencies, reserve the ports in `firebase.json` or change them to your reserved ports, then run:

```sh
npm ci --ignore-scripts --cache .cache/npm
export XDG_CONFIG_HOME="$PWD/.cache/config"
export FIREBASE_EMULATORS_PATH="$PWD/.cache/emulators"
export GOOGLE_APPLICATION_CREDENTIALS="$PWD/.cache/no-credentials.json"
export FIREBASE_CLI_DISABLE_UPDATE_CHECK=true
export JAVA_TOOL_OPTIONS=-Xmx512m
node_modules/.bin/firebase emulators:exec --project demo-app --config firebase.json --only auth,firestore,storage,database 'python3 run.py --binary .build/debug/sdk-smoke-swift --output logs/official'
```

Use Java 21 and Node 24.14.0. Keep emulator diagnostic logs private; only `cases.jsonl` and `summary.json` are intended for sharing. The SDK's generated account identifiers and tokens are never included in these results. Download URL redirects are refused, and the destination must match the configured local Storage endpoint.

## Case inventory

| Product | Cases | Required observation |
| --- | --- | --- |
| Firestore | `write-read`, `transforms`, `query` | Exact server-read values, resolved timestamp and ordered query IDs |
| Firestore | `listener`, `transaction`, `offline-resume`, `batch-delete` | Server snapshots, committed independent reads, a pending offline snapshot followed by server acknowledgement, final batch state |
| Firestore | `rules-anonymous-denied`, `rules-owner`, `rules-signout` | Public access and explicit permission denials; owner-filtered results |
| Auth | `signup`, `signin`, `refresh` | Account creation, matching identity after sign-in and usable refreshed token claims |
| Storage | `upload-download`, `metadata`, `resumable`, `download-url`, `list-delete` | Exact bytes, metadata changes, completed transport progress and payload size, local URL, object absence after delete |
| Storage | `rules-denied` | Anonymous upload and cross-owner read denials |
| Realtime Database | `set-read`, `listener`, `transaction`, `on-disconnect` | Independent value reads, listener updates, committed increment and acknowledged disconnect action observed by a second connection |

Storage transport progress includes protocol overhead: a 600000-byte payload was reported as 600134 transport bytes. The smoke checks completed transport progress against its own reported total, while independently requiring a 600000-byte payload and exact download contents. This demonstrates the SDK upload-task protocol, not pause/resume or recovery across process restarts.

Admin-only operations, phone/browser-provider Auth flows and browser persistence behavior are outside this finite client smoke. No production parity is claimed from an emulator comparison.

## macOS Auth limitation

The unsigned command-line package currently encounters `FIRAuthErrorDomain` code `17995` (`keychainError`) after local account creation. This occurs against the official emulator too. Firebase documents that macOS Auth requires a provisioned signed app with the Keychain Sharing capability. This smoke does not obtain a developer identity, edit the user's keychain, patch the SDK or replace Auth calls with REST.

Consequently, the three Auth cases and the Auth-dependent `firestore.rules-owner`, `firestore.rules-signout` and `storage.rules-denied` cases report **blocked**. Sign-in, token refresh and the authenticated assertions are unverified when their signup prerequisite fails. The independent anonymous-denial assertions still execute. A provisioned macOS test application is required to complete these six cases; the plain SwiftPM executable deliberately retains the failing status.

References: [Firebase's macOS Keychain requirement](https://firebase.google.com/support/release-notes/ios#version_1050_-_february_7_2023), [Apple platform support](https://firebase.google.com/docs/ios/learn-more), [pinned SwiftPM requirements](https://github.com/firebase/firebase-ios-sdk/blob/12.18.0/SwiftPackageManager.md).

## Manual workflow and cost bound

`.github/workflows/sdk-smoke-swift.yml` runs only through manual dispatch. It is not a release gate. It uses one macOS 26 runner with Xcode 26.6, two build jobs and a **45-minute wall-clock limit** per dispatch. Both backends run even if one reports blocked cases. Only sanitized case summaries are uploaded; the workflow fails unless both complete successfully.

A cold hosted run is provisionally budgeted at 20–35 runner minutes, capped at 45; this estimate has not been measured on Actions. On the local Xcode 26.6/Swift 6.3.3 host, the isolated fireemu build took 48.06 seconds, the first successful incremental SDK build took 4.33 seconds after dependency compilation, and the corrected official 23-case invocation took 1.842 seconds, excluding emulator startup/download. Its result was 17 passed and six Auth-dependent cases blocked. Local timings are not hosted-runner billing estimates. Fresh SDK artifacts occupied about 2.7 GiB and the initial fireemu target about 2.1 GiB before Rust test compilation.
