# FlutterFire macOS client smoke

This manual smoke exercises the real FlutterFire plugins against local fireemu and official Firebase emulators. It contains the same 23 client cases as the Swift smoke plus Dart Timestamp/FieldValue round trips and Firestore/Realtime Database stream error delivery. It is not a release gate and does not establish production parity.

## Toolchain

Use Flutter 3.41.5 (Dart 3.11.3), Xcode 26.6, CocoaPods 1.16.2, Node 22.22.0 and Java 21.0.10+7. The manual workflow downloads the ARM64 Flutter release archive and verifies its SHA256. Direct FlutterFire versions are exact in `pubspec.yaml`; native Firebase is pinned to 12.9.0 through CocoaPods. All dependencies and build artifacts belong to this checkout.

The manual workflow has one macOS job capped at 60 minutes. The initial cold native build took approximately 17 minutes locally; the complete cold CI estimate remains 35–55 minutes and has not been measured on GitHub Actions. Allow approximately 25 GiB of additional local disk space, with at least 80 GiB remaining free. No Android SDK, device or simulator is required.

## macOS permissions

The generated application retains App Sandbox and uses local ad-hoc signing. Both entitlement files include outgoing network access for loopback connections. Debug/profile JIT and incoming tool connections retain the Flutter template permissions.

Firebase Authentication on macOS requires Keychain Sharing. Its restricted entitlement requires a provisioning profile; ad-hoc signing does not establish access. This tool does not read developer credentials, create profiles or change the global Keychain. If the SDK returns the Keychain prerequisite failure, Auth and dependent ownership cases report `blocked` and the aggregate fails. Independent unauthenticated product cases still run.

## Results

Every required case must appear exactly once. A missing, blocked or failed case prevents success. Public reports contain fixed case names, status and sanitized classifications, never identity/token values or raw SDK errors. Each case has a 30-second deadline and each application run has an outer deadline. The two emulator backends run sequentially with isolated data. A failure on both backends requires SDK/harness/platform investigation; a fireemu-only mismatch is a candidate emulator defect.

## Local invocation

Unpack the checksum-verified Flutter archive into `.toolchain/flutter`, following the workflow setup steps. Use the existing CocoaPods CLI only after confirming `pod --version` is `1.16.2`; application Pods and their cache remain local to this directory.

```sh
export PATH="$PWD/.toolchain/flutter/bin:$PATH"
export PUB_CACHE="$PWD/.pub-cache"
flutter pub get --enforce-lockfile
npm ci --ignore-scripts
flutter test test
python3 -m unittest discover -s test -p '*_test.py'
PATH="$PWD/scripts:$PATH" flutter build macos --debug --target integration_test/smoke_test.dart
python3 run.py --backend both --fireemu ../../target/debug/fireemu
```

Build `fireemu` from this checkout with `cargo build --locked -p fireemu --jobs 2` first. Reserve the ports declared in `firebase.json` when sharing a development machine. The runner uses a fresh emulator data directory for each backend, owns child process groups, and keeps unfiltered logs only in ignored `reports/*.raw.log`. Only the sanitized JSON summaries are uploaded by CI.

The main-integrated macOS rerun recorded the same 27 case/status/classification results on fireemu and the official emulators: 21 cases were `passed/ok`, and six were `blocked/macos-keychain-provisioning`. The blocked cases are `auth.signup`, `auth.signin`, `auth.refresh`, `firestore.rules-owner`, `firestore.rules-signout` and `storage.rules-denied`.

The credential-free macOS comparison covers those 21 successes and the exact matching Keychain-dependent constraints. The six blocked cases remain non-passing, and the full smoke aggregate still fails. This comparison does not establish Auth compatibility for a provisioned application, 27 passing cases or production parity. The rerun used the integrated main runtime without a temporary patch.
