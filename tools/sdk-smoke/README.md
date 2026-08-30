# SDK smoke tests

Exercise a running `firebase-testd` with the real Firebase SDKs.

- `smoke.mjs`: `firebase-admin` (Firestore over gRPC with `Bearer owner`, Auth over the
  Identity Toolkit REST subset).
- `client.mjs`: the `firebase` client SDK (Auth sign-up, Firestore `Listen` / `Write`
  streams) with Security Rules loaded through the control API.
- `lite.mjs`: `firebase/firestore/lite` (REST only) with Security Rules.
- `storage.mjs`: `firebase-admin` storage (JSON API) and `firebase/storage` (Firebase
  protocol, resumable uploads) with Storage Rules; needs `FIREBASE_STORAGE_EMULATOR_HOST`.
- `functions.mjs`: the functions in `functions-project/` (firebase-functions v2: Firestore
  and Storage triggers, `onSchedule`, `onRequest`, `onCall`, retries) driven through
  `awaitIdle` and the virtual clock; start the daemon with
  `--functions tools/sdk-smoke/functions-project --functions-port 5001` and set
  `FTD_FUNCTIONS_HOST=127.0.0.1:5001`. Run it on a fresh daemon (it fills the database).
- `web/index.html`: the browser build of the web SDK (WebChannel transport). Serve the
  directory (`python3 -m http.server 8765 --bind 127.0.0.1` in `web/`) and open
  `http://127.0.0.1:8765/index.html?fs=<firestore port>&auth=<http port>&token=<FTD_CONTROL_TOKEN>`; the page prints
  its checks as JSON. `FTD_TRACE_WEBCHANNEL=1` on the daemon traces the channel protocol.

```sh
# one-shot: firebase-testd exec --firestore-port 8080 --http-port 9099 --storage-port 9199 -- npm run smoke
cargo run -p firebase-testd -- up --firestore-port 8080 --http-port 9099 &
cd tools/sdk-smoke && npm install
export FIRESTORE_EMULATOR_HOST=127.0.0.1:8080 FIREBASE_AUTH_EMULATOR_HOST=127.0.0.1:9099 GOOGLE_CLOUD_PROJECT=demo-app
npm run smoke        # firebase-admin
npm run smoke:client # firebase client SDK + rules
npm run smoke:lite   # Firestore Lite (REST) + rules
```

Exit code 0 means every check passed; the JSON output lists each check.
