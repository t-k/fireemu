# SDK smoke tests

Exercise a running `firebase-testd` with the real Firebase SDKs.

- `smoke.mjs`: `firebase-admin` (Firestore over gRPC with `Bearer owner`, Auth over the
  Identity Toolkit REST subset).
- `client.mjs`: the `firebase` client SDK (Auth sign-up, Firestore `Listen` / `Write`
  streams) with Security Rules loaded through the control API.
- `lite.mjs`: `firebase/firestore/lite` (REST only) with Security Rules.

```sh
cargo run -p firebase-testd -- up --firestore-port 8080 --http-port 9099 &
cd tools/sdk-smoke && npm install
export FIRESTORE_EMULATOR_HOST=127.0.0.1:8080 FIREBASE_AUTH_EMULATOR_HOST=127.0.0.1:9099 GOOGLE_CLOUD_PROJECT=demo-app
npm run smoke        # firebase-admin
npm run smoke:client # firebase client SDK + rules
npm run smoke:lite   # Firestore Lite (REST) + rules
```

Exit code 0 means every check passed; the JSON output lists each check.
