# Go Admin SDK smoke

Exercise a running `fireemu` with the Go Admin SDK, `firebase.google.com/go/v4`, using
Firestore through `cloud.google.com/go/firestore` and Storage through
`cloud.google.com/go/storage`. Exact versions are locked in `go.mod` and `go.sum`, and the
`toolchain` line pins the Go release CI installs.

What it covers:

- Firestore: set, get, update and delete; a query with `where`, `orderBy` and `limit` (the
  inequality and the order are on the same field, so the automatic single-field index serves it
  and the strict profile needs no composite index); a transaction; an atomic `WriteBatch`; a
  query snapshot iterator that receives exactly one `DocumentAdded` change.
- Auth: create a user, get it by email, set custom claims, create a custom token, exchange it
  through the Auth emulator's `accounts:signInWithCustomToken`, verify the resulting ID token,
  delete the user.
- Storage: upload, download, read metadata, delete.

No credential is used. With the emulator variables set, each SDK runs in its emulator mode:
Auth sends a static `owner` token, Firestore sends `Bearer owner`, and Storage sends no
`Authorization` header. The app also passes `option.WithoutAuthentication()` so no other path
looks up Application Default Credentials.

## Guard

`guard.go` refuses to start (exit 2) unless every emulator host variable these SDKs read is set
and names a loopback host (`localhost`, `127.0.0.0/8` or `::1`) with a numeric port and no
userinfo. `guard_test.go` tests it offline (`go test ./...`). The variables, as read by the
versions in `go.mod`:

| Variable | Read by | Accepted form |
|---|---|---|
| `FIRESTORE_EMULATOR_HOST` | `cloud.google.com/go/firestore` `client.go` (`newClient`) | `host:port` |
| `FIREBASE_AUTH_EMULATOR_HOST` | `firebase.google.com/go/v4` `auth/auth.go` (`emulatorHostEnvVar`), which builds `http://<value>/identitytoolkit.googleapis.com` | `host:port` |
| `STORAGE_EMULATOR_HOST` | `cloud.google.com/go/storage` `storage.go` and `http_client.go` (`NewClient`) | `host:port` or `http://host:port` |
| `FIREBASE_STORAGE_EMULATOR_HOST` | `firebase.google.com/go/v4` `storage/storage.go` (`NewClient`), copied into `STORAGE_EMULATOR_HOST` when that one is empty | `host:port` |
| `STORAGE_EMULATOR_HOST_GRPC` (checked only when set) | `cloud.google.com/go/storage` `grpc_client.go` (`NewGRPCClient`; not used here) | `host:port` |
| `FIREBASE_DATABASE_EMULATOR_HOST` (checked only when set) | `firebase.google.com/go/v4` `db/db.go` (not used here) | `host:port` |

Because userinfo is refused, the smoke does not run while Storage App Check is `enforced`
with `appCheck.storageServerRequests = "capability"`: then `fireemu exec` puts a capability in
the userinfo of `STORAGE_EMULATOR_HOST`.

## Running

```sh
cargo build -p fireemu
(cd tools/sdk-smoke-go && go test ./... && go build -o "$TMPDIR/sdk-smoke-go" .)
# Default configuration (the strict profile with its development defaults).
target/debug/fireemu exec --project demo-app --hub-port 0 -- "$TMPDIR/sdk-smoke-go"
# Strict exact configuration.
target/debug/fireemu exec --config tools/sdk-smoke-go/fireemu.strict.json --project demo-app --hub-port 0 -- "$TMPDIR/sdk-smoke-go"
```

`fireemu.strict.json` is the strict profile with `productionExact`, plus
`auth.allowUnsignedCustomTokens`. That combination is the example in the profiles guide. The
override is needed because the Go SDK in emulator mode can only mint unsigned (`alg: none`)
custom tokens (`auth/token_generator.go`, `emulatedSigner`), and production refuses those.
The smoke does not use `tools/sdk-smoke/fireemu.smoke.json`: that file pins the daemon clock with
`daemon.clockStart`, but the Go SDK stamps custom tokens with the wall clock (`auth/auth.go`,
`CustomTokenWithClaims`, `internal.SystemClock`) and checks ID token `iat` and `exp` against it
(`auth/token_verifier.go`, `verifyContent`).

Each step prints `ok` or `FAIL` with the error. Every step runs even if an earlier one fails,
and the command exits 1 if any step failed.
