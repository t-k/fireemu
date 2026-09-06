# Authentication production matrix

Identity Toolkit REST programs (`src/auth-probe/programs.mjs`) run against production Authentication, the official Auth emulator (`auth-matrix.json`) and fireemu. Regenerate with `pnpm -C conformance auth-probe:production` (needs `FIREEMU_PRODUCTION_PROJECT` and `FIREEMU_PRODUCTION_API_KEY`).

## Evidence

Fireemu observation: live artifact fireemu (sha256-8861e36d7ce77769fde04c62a885d81adc9999b76385799a98e7ec019a882b99), source a5ec2cf8243ee628bcaedb7b048b3c6a5b2329a0, profile firebase.
Inputs: corpus sha256-91b279e3be6b07f85859b3ce9e402382d9b0935907acd59b8a44d8d4c0ec6281, SDK lock sha256-a1287b8bf5d8ef937b0bd82d7cec0df65abe3fe8f6669a4d2e3d927874291432.
Official emulator values: stored expectation from auth-matrix.json (sha256-0bc921cb2cdc6ec865a2f089856135e1d26ad0469f254d06cd8a6fda778c5470).
Evidence status: verified.

| status | rows | meaning |
| --- | --- | --- |
| parity | 14 | production, the official emulator and fireemu agree |
| fireemu-matches-production | 8 | fireemu follows production where the official emulator differs |
| fireemu-divergence | 0 | production and the official emulator agree; fireemu differs |
| emulators-diverge-from-production | 1 | both emulators agree with each other but not with production |
| three-way-difference | 0 | all three differ |

## Rows that are not parity

| row | status | production | official emulator | fireemu |
| --- | --- | --- | --- | --- |
| password/sign-up-and-sign-in#sign-in | fireemu-matches-production | {"status":200,"code":"OK","body":{"kind":"<kind>","localId":"<localId>","email":"fireemu-a | {"status":200,"code":"OK","body":{"kind":"<kind>","registered":true,"localId":"<localId>", | {"status":200,"code":"OK","body":{"displayName":"","email":"fireemu-auth-probe-<run>-prima |
| password/sign-up-and-sign-in#wrong-password | fireemu-matches-production | {"status":400,"code":"INVALID_LOGIN_CREDENTIALS"} | {"status":400,"code":"INVALID_PASSWORD"} | {"status":400,"code":"INVALID_LOGIN_CREDENTIALS"} |
| password/sign-up-and-sign-in#unknown-email | fireemu-matches-production | {"status":400,"code":"INVALID_LOGIN_CREDENTIALS"} | {"status":400,"code":"EMAIL_NOT_FOUND"} | {"status":400,"code":"INVALID_LOGIN_CREDENTIALS"} |
| password/sign-up-and-sign-in#lookup | fireemu-matches-production | {"status":200,"code":"OK","body":{"kind":"<kind>","users":[{"localId":"<localId>","email": | {"status":200,"code":"OK","body":{"kind":"<kind>","users":[{"localId":"<localId>","emailVe | {"status":200,"code":"OK","body":{"kind":"<kind>","users":[{"email":"fireemu-auth-probe-<r |
| password/sign-up-and-sign-in#update-display-name | fireemu-matches-production | {"status":200,"code":"OK","body":{"kind":"<kind>","localId":"<localId>","email":"fireemu-a | {"status":200,"code":"OK","body":{"kind":"<kind>","localId":"<localId>","emailVerified":fa | {"status":200,"code":"OK","body":{"displayName":"Probe User","email":"fireemu-auth-probe-< |
| password/sign-up-and-sign-in#sign-in-after-delete | fireemu-matches-production | {"status":400,"code":"INVALID_LOGIN_CREDENTIALS"} | {"status":400,"code":"EMAIL_NOT_FOUND"} | {"status":400,"code":"INVALID_LOGIN_CREDENTIALS"} |
| tokens/errors#unknown-method | emulators-diverge-from-production | {"status":404,"code":"non-json"} | {"status":404,"code":"Not"} | {"status":404,"code":"Not"} |
| tokens/errors#password-reset-for-unknown-email | fireemu-matches-production | {"status":200,"code":"OK","body":{"kind":"<kind>","email":"fireemu-auth-probe-<run>-nobody | {"status":400,"code":"EMAIL_NOT_FOUND"} | {"status":200,"code":"OK","body":{"email":"fireemu-auth-probe-<run>-nobody@example.com","k |
| tokens/errors#mfa-enrollment-start-without-token | fireemu-matches-production | {"status":400,"code":"INVALID_ID_TOKEN"} | {"status":400,"code":"MISSING_ID_TOKEN"} | {"status":400,"code":"INVALID_ID_TOKEN"} |
