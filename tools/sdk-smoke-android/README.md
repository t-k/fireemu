# Android Firebase client SDK smoke

This Kotlin tool exercises the real Android Firestore, Authentication, Storage and Realtime Database clients against local emulators. It uses Firebase BoM 35.1.0 (Firestore 27.1.0, Auth 25.0.0, Storage 23.0.0, Database 23.0.0), Gradle 8.14.6, AGP 8.13.2, Kotlin 2.3.0 and AndroidX Test runner 1.7.0. Dependencies and their checksums are committed. No production project, downloaded Firebase configuration or developer signing identity is required. The build generates an isolated disposable debug signing key under the ignored tool cache.

## Why instrumentation

Robolectric 4.17 can execute Firestore and Database round trips, but its host-JDK HTTP stack differs from Android. Storage 23.0.0 looks up the upload URL by the exact header name `X-Goog-Upload-URL`; the official emulator emits lowercase `x-goog-upload-url`. Android uses a case-insensitive header map, while OpenJDK uses a case-sensitive map. The unmodified SDK therefore needs Android instrumentation for this smoke. `SmokeCases` contains the shared case bodies; the optional Robolectric network runner is diagnostic and is excluded from normal acceptance. It does not replace SDK traffic with REST or normalize headers through a proxy.

## Build and run

Use Java 21 and a local Android SDK with platform 36, build-tools 35.0.0, platform-tools, command-line tools and an emulator. The local Apple Silicon device image is `system-images;android-34;default;arm64-v8a` revision 2, with emulator 36.4.10. Linux CI uses the API 34/default/x86_64 image revision 4 with emulator 37.2.13 (archive build16740729). The workflow verifies the SHA-1 checksums published in Google's repository metadata; this is not a claim of SHA-256 artifact verification. AVD data, Android preferences, Gradle caches, emulator downloads, debug signing and the ADB server belong to this tool's temporary or ignored directories. Existing SDK packages are read only.

```sh
cd tools/sdk-smoke-android
./gradle.sh testDebugUnitTest --tests dev.fireemu.smoke.GuardTest --tests dev.fireemu.smoke.CaseReportTest assembleDebugAndroidTest
npm ci --ignore-scripts --no-audit --no-fund
python3 run.py run --sdk "$ANDROID_HOME" --portctl /path/to/portctl.py --backend official
python3 run.py run --sdk "$ANDROID_HOME" --portctl /path/to/portctl.py --backend fireemu --fireemu ../../target/debug/fireemu
```

Build fireemu from the same checkout with `cargo build --locked -p fireemu` first. On Linux add `--arch x86_64`. Local runs require the port-registry CLI; an isolated CI job may omit it and use OS-selected ports. Both backends bind loopback. The Android client alone translates validated host loopback endpoints to 10.0.2.2, the Android Emulator's host-loopback alias. Cleartext traffic is enabled only in the test APK. No fireemu security default changes.

Each invocation creates one disposable AVD, caps it at 2 GiB and 2 cores, starts an isolated ADB server and selects only that emulator serial. Boot has a 3-minute deadline; the backend/client has a 12-minute outer deadline and each case has a 30-second deadline. The launcher monitors its owned process tree against an 8 GiB RSS limit and stops owned processes by verified PID and command. It removes the AVD and preserves local diagnostics under `build/diagnostics`. Only the sanitized JSON files under `reports` should be uploaded or shared; raw logs can contain local paths and fixture identities.

## Required cases

| Product | Assertions |
| --- | --- |
| Firestore | Exact write/server-read fields; increment, array union and timestamp transforms; filtered/ordered/limited query results; initial and changed server listener snapshots; transaction commit checked by another client; pending offline write followed by server acknowledgement; batch set/delete; anonymous denial, owner-only writes/query and denial after sign-out. |
| Auth | Email/password sign-up, sign-out/sign-in identity continuity and forced refresh with matching identity claims. Tokens and identities are not printed. |
| Storage | Non-ASCII object path with exact uploaded/downloaded bytes; metadata read/update; 600000-byte resumable upload with progress and final byte equality; validated local download URL; list/delete/not-found; anonymous and cross-owner denial. Resumable completion does not claim explicit pause/resume coverage. |
| Database | Set and independently read value; initial and changed listener values; committed increment transaction checked by another client; acknowledged onDisconnect registration followed by observation from a second connected client. |

All 23 fixed case IDs are required. A failed prerequisite produces a visible blocked result; failed, missing or blocked cases fail acceptance. Unit tests cover endpoint refusal, explicit device routing and complete result accounting. The same cases and rules run sequentially against fireemu and firebase-tools 15.28.2. A fireemu-only failure is a candidate emulator defect; a failure on both backends needs SDK/harness investigation. Neither comparison establishes production parity, which remains unobserved.

## Manual CI and limits

The workflow is manual-dispatch only and is not a release gate. One Linux job has a 45-minute cap; estimated cold build and two emulator runs take 20–35 minutes, pending measured CI evidence. Local execution results and unresolved cases are reported in the pull request. No device/image presence check is treated as proof that the image boots or that SDK operations pass.

## Recorded compatibility limitation

The initial same-checkout fireemu run reported17 passed cases, an Auth sign-up failure and5 blocked Auth-dependent cases, while all23 passed against the official emulators. Android Auth25.0.0 uses legacy Identity Toolkit routes for sign-up, password verification and account lookup. The smoke requires the runtime aliases supplied by PR122; it does not duplicate that runtime patch. The pull request distinguishes the base-runtime result from any temporary integration verification with that dependency.
