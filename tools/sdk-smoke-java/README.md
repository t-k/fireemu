# Java Admin SDK smoke

Exercises a running `fireemu` with the Java Admin SDK: `com.google.firebase:firebase-admin`
9.11.0, which brings `google-cloud-firestore` 3.47.0 and `google-cloud-storage` 2.73.0.

```sh
cd tools/sdk-smoke-java
./gradlew test installDist          # offline guard tests, then the runnable smoke
cd "$(mktemp -d)"                   # no fireemu config is discovered here
fireemu exec --project demo-app --hub-port 0 -- \
  /path/to/fireemu/tools/sdk-smoke-java/build/install/sdk-smoke-java/bin/sdk-smoke-java
fireemu exec --config /path/to/fireemu/tools/sdk-smoke-java/fireemu.strict.json \
  --project demo-app --hub-port 0 -- \
  /path/to/fireemu/tools/sdk-smoke-java/build/install/sdk-smoke-java/bin/sdk-smoke-java
```

The JVM is started directly by `fireemu exec` (not through `./gradlew run`, whose daemon may
hold another environment). The `sdk-smoke-java` workflow runs exactly these steps. Exit status:
0 when every step passed, 1 when one failed, 2 when the guard refused to start.

`fireemu.strict.json` names the strict profile explicitly; the default configuration is the
same profile. The smoke needs an unpinned clock (`verifyIdToken` checks `exp` and `iat`
against the JVM's clock), so it does not reuse `tools/sdk-smoke/fireemu.smoke.json`.

## What it covers

- Firestore (`FirestoreClient`, gRPC): create (and `ALREADY_EXISTS` on a second create), get,
  update, merge set, delete; `where > … orderBy … desc limit 2` on one field (served by the
  automatic single-field index, so the strict profile needs no composite index); a
  read-then-write transaction; a batch of set, set, update and delete; a collection snapshot
  listener that receives one `ADDED` change after its empty initial snapshot.
- Auth (`FirebaseAuth`): create, get, get by email, custom claims; a custom token exchanged at
  `accounts:signInWithCustomToken` and the resulting ID token verified; an ID token from
  `accounts:signInWithPassword` verified with and without `checkRevoked`; delete, then
  `USER_NOT_FOUND`. The sign-in calls are the REST calls a client SDK makes, since the Admin SDK
  has none.
- Storage (`google-cloud-storage`, JSON API): upload with the SDK defaults; upload, download,
  metadata read and delete; a metadata update (`storage.update`).

## Emulator routing and the guard

`EmulatorGuard` runs before any SDK class is touched and refuses to start unless each variable
below is a loopback `host:port` (`127.0.0.0/8` or `[::1]`, port 1 to 65535) with no scheme,
path or userinfo. Host names, `localhost` included, are refused.

| Variable | Read by (sources of the versions above) | Required |
| --- | --- | --- |
| `FIRESTORE_EMULATOR_HOST` | `com.google.cloud.firestore.FirestoreOptions` (`FIRESTORE_EMULATOR_SYSTEM_VARIABLE`, `Builder.build()`) | yes |
| `FIREBASE_AUTH_EMULATOR_HOST` | `com.google.firebase.auth.internal.Utils.AUTH_EMULATOR_HOST` | yes |
| `FIREBASE_DATABASE_EMULATOR_HOST` | `com.google.firebase.database.util.EmulatorHelper` | no: `exec` sets it only when the Realtime Database runs, and the smoke never opens it |
| `FIREBASE_STORAGE_EMULATOR_HOST` | this smoke (see below) | yes |

`google-cloud-storage` 2.73.0 reads no emulator variable at all, and firebase-admin's
`StorageClient` builds `StorageOptions` with no host, so it always targets
`storage.googleapis.com`. The smoke therefore never uses `StorageClient`; it builds
`StorageOptions` itself with `setHost("http://" + FIREBASE_STORAGE_EMULATOR_HOST)` and
`NoCredentials`. `STORAGE_EMULATOR_HOST`, which `exec` also exports, is read by no Java code
on the classpath.

No credential is configured. `FirebaseOptions` requires one, so the smoke passes a
`GoogleCredentials` wrapping the literal access token `owner`; while
`FIREBASE_AUTH_EMULATOR_HOST` is set the Admin SDK replaces it with its own
`EmulatorCredentials` for Auth and Firestore anyway (`ImplFirebaseTrampolines.getCredentials`).

## Known mismatches

A step listed in `JavaAdminSmoke.KNOWN_MISMATCHES` must fail with the recorded text: if it
fails differently, or passes, the run fails, so an entry is removed as soon as fireemu changes.
The step after each covers the rest of the flow on a path that avoids the mismatch. They are
findings for fireemu, not fixed here:

1. **Custom token exchange.** In emulator mode firebase-admin signs custom tokens with
   `CryptoSigners.EmulatorCryptoSigner`, whose signature is empty, under the header
   `FirebaseTokenFactory` always writes (`alg: RS256`). fireemu's development exception for
   unsigned custom tokens (`auth.allowUnsignedCustomTokens`, default true) accepts `alg: none`
   only (`fireemu_core_auth::jwt::decode_token`), so the token is refused with
   `INVALID_CUSTOM_TOKEN` in both profiles (`INVALID_CUSTOM_TOKEN : Invalid assertion format`
   under `"profile": "emulator"`). The official Auth emulator accepts any `alg` with a warning
   (firebase-tools `src/emulator/auth/operations.ts`, `signInWithCustomToken`).
2. **Upload with the SDK defaults.** google-api-client compresses request bodies unless told
   not to (`AbstractGoogleClientRequest.disableGZipContent` is false by default and
   `buildHttpRequest` then sets `GZipEncoding`), so `storage.create` sends the multipart body
   with `Content-Encoding: gzip`. fireemu parses the compressed bytes as the multipart body and
   answers `400 Payload size invalid. Expected 2-3 payloads. Actual size: 0` (`Unexpected number
   of parts in request body` under the emulator profile). With
   `BlobTargetOption.disableGzipContent()` the same upload succeeds.
3. **Metadata update.** `storage.update` is a JSON API `PATCH`. The default transport,
   `NetHttpTransport` (`HttpTransportOptions.DefaultHttpTransportFactory`), does not support
   `PATCH` (`SUPPORTED_METHODS`), so google-api-client's `MethodOverride` sends `POST` with
   `X-HTTP-Method-Override: PATCH`. fireemu's JSON API object route answers `501 Not
   Implemented`; it honours the override only on the Firebase Storage API's `PUT`.

## Supply chain

- `gradle/wrapper/gradle-wrapper.properties` carries `distributionSha256Sum` for Gradle 9.8.2
  (`https://services.gradle.org/distributions/gradle-9.8.2-bin.zip.sha256`), and the CI job
  checks the committed wrapper jar against
  `https://services.gradle.org/distributions/gradle-9.8.2-wrapper.jar.sha256`.
- `gradle/verification-metadata.xml` holds the SHA-256 of every resolved artifact, POMs, Gradle
  module files and BOMs included; Gradle fails the build on any artifact that is missing from it
  or does not match. After changing a dependency, regenerate it from an empty Gradle home so no
  cached artifact is skipped:
  `GRADLE_USER_HOME="$(mktemp -d)" ./gradlew --write-verification-metadata sha256 build installDist`,
  and review the diff.
