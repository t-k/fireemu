# Dart Functions runtime assessment

## Decision

Keep Dart runner work at the assessment stage. In firebase-tools **15.28.2**, `dart3` is explicitly experimental, and the public `dartfunctions` experiment is disabled by default. The official server SDK, **firebase_functions 0.8.0**, also describes its status as experimental. HTTP and callable endpoints have a production support classification, but that narrower classification does not make the overall Dart runtime stable. This assessment adds no runner, toolchain installation, CI job, or compatibility completion claim.

The evidence below is a static review of the pinned CLI and official package documentation. It is not a successful Dart deployment, emulator execution, or production parity observation.

## Upstream identity and stability

The pinned [runtime table](https://github.com/firebase/firebase-tools/blob/v15.28.2/src/deploy/functions/runtimes/supported/types.ts) gives `dart3` the `experimental` status. The [experiment registry](https://github.com/firebase/firebase-tools/blob/v15.28.2/src/experiments.ts) defines `dartfunctions` as public with `default: false`. The Dart delegate asserts that this experiment is enabled before accepting a Dart codebase.

[firebase_functions 0.8.0](https://pub.dev/packages/firebase_functions/versions/0.8.0) is the server SDK for defining Firebase functions in Dart, published by `firebase.google.com` and maintained in [firebase/firebase-functions-dart](https://github.com/firebase/firebase-functions-dart). It provides `runFunctions` and function registration APIs. It is distinct from the Flutter client package `cloud_functions`, which invokes callable functions. The official package metadata lists the Dart SDK constraint as `^3.11.0`. Package version and CLI version are separate pins; the CLI does not establish which server SDK version a project resolves.

## Discovery and build

The pinned [Dart runtime delegate](https://github.com/firebase/firebase-tools/blob/v15.28.2/src/deploy/functions/runtimes/dart/index.ts) implements this sequence:

1. Recognize a codebase by `pubspec.yaml`, require the experiment, and select the configured runtime or the latest Dart runtime when omitted.
2. Probe `dart --version` and check that `pubspec.yaml` and the fixed entry point `bin/server.dart` are readable. A missing executable produces a Dart SDK/PATH diagnostic. If `.dart_tool/package_config.json` is absent, run `dart pub get`.
3. Run `dart run build_runner build --delete-conflicting-outputs` during the build phase, unless the delegate's watch mode is active. Emulator mode skips native compilation after this generation step.
4. Discover endpoints from source-root `functions.yaml` using the shared YAML discovery path. If the file is absent, run `dart run build_runner build` with the supplied discovery environment, then read the file again. Fail if it remains absent. Outside emulator discovery, convert `gcfv2` endpoint platform values to `run`.

The [version feature selector](https://github.com/firebase/firebase-tools/blob/v15.28.2/src/deploy/functions/runtimes/dart/features.ts) reads the root package's `languageVersion` from `.dart_tool/package_config.json`. Below language version 3.13, the CLI minimum SDK is 3.9.0 and deployment builds a Linux x64 executable using `dart compile exe bin/server.dart -o bin/server --target-os=linux --target-arch=x64`. At language version 3.13 or later, the minimum SDK is 3.13.0 and the build uses `dart build cli --target bin/server.dart --target-os linux --target-arch x64`, with executable path `build/cli/linux_x64/bundle/bin/server`. These CLI thresholds do not override the server package's own SDK constraint.

## Emulator startup, routing and reload

The pinned [Functions emulator](https://github.com/firebase/firebase-tools/blob/v15.28.2/src/emulator/functionsEmulator.ts), in `startDart`, starts `dart run --no-serve-devtools bin/server.dart` in the function source directory. It passes `HOST=127.0.0.1` and a selected `PORT`, and removes `FUNCTION_TARGET` and `FUNCTION_SIGNATURE_TYPE` from the supplied runtime environment before merging with the parent process environment. It communicates with the child through a TCP connection. `--inspect-functions` is ignored with a warning for Dart.

The Dart server receives function-specific paths: background dispatch posts to `/<entryPoint>`, while HTTP forwarding prefixes the function entry point to the remaining request path. This differs from assuming a separate server root for each function.

For reloads, the emulator starts `dart run build_runner watch --delete-conflicting-outputs`. The delegate recognizes successful build output and invokes a callback; the emulator debounces trigger reloads. The delegate returns a cleanup callback that sends SIGTERM to its build-runner process. Reading that cleanup path is not evidence that reload and shutdown leave no descendant processes behind.

## Trigger support

The pinned [trigger support classifier](https://github.com/firebase/firebase-tools/blob/v15.28.2/src/deploy/functions/runtimes/dart/triggerSupport.ts) distinguishes the following tiers. These are upstream classifications, not fireemu support claims or recorded production results.

| Trigger category | Classification in firebase-tools 15.28.2 |
| --- | --- |
| HTTP and callable, excluding task queues | Production |
| Firestore, Realtime Database and Storage events | Emulator only |
| Scheduled functions, blocking Identity functions and task queues | Experimental |
| Pub/Sub, Eventarc, Auth, Firebase Alerts, Remote Config and Test Lab events | Experimental |
| Unrecognized event types | Experimental fallback |

The official [server SDK trigger guide](https://github.com/firebase/firebase-functions-dart/blob/main/doc/triggers.md) also describes these tiers. Its HTTPS APIs include `onRequest`, `onCall` and `onCallWithData`; Firestore, Realtime Database and Storage offer event registration APIs. The guide says experimental APIs are implemented but currently unsupported in the emulator and production. It also requires URL-based client invocation for Dart callables rather than standard name-based lookup. This guide follows upstream `main`; the CLI classifications above remain pinned to 15.28.2.

## Verification boundary and remaining work

This assessment was checked against the installed firebase-tools package manifest reporting 15.28.2, its source files, the matching public tag, and official SDK package metadata and documentation. No Dart fixture was built or run. Discovery execution, HTTP/callable invocation, event delivery, reload, shutdown, and missing-toolchain behavior have not been tested in fireemu. Neither compatibility profile gains Dart support from this document, and production behavior remains unobserved.

If upstream stability changes, reassess the runtime and SDK versions before proposing implementation. A subsequent implementation would need a pinned toolchain and real fixtures covering discovery, invocation, reload, shutdown, a missing-toolchain diagnostic, and process cleanup. Those checks remain future work; documentation review does not substitute for them.
