# SDK smoke test

Exercises a running `firebase-testd` with the real `firebase-admin` SDK (Firestore over gRPC,
Auth over the Identity Toolkit REST subset).

```sh
cargo run -p firebase-testd -- up --firestore-port 8080 --http-port 9099 &
cd tools/sdk-smoke && npm install
FIRESTORE_EMULATOR_HOST=127.0.0.1:8080 FIREBASE_AUTH_EMULATOR_HOST=127.0.0.1:9099 \
  GOOGLE_CLOUD_PROJECT=demo-app npm run smoke
```

Exit code 0 means every check passed; the JSON output lists each check.
