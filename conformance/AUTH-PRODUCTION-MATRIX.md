# Authentication production matrix

Identity Toolkit REST programs (`src/auth-probe/programs.mjs`) run against production Authentication, the official Auth emulator (`auth-matrix.json`) and fireemu. Regenerate with `pnpm -C conformance auth-probe:production` (needs `FIREEMU_PRODUCTION_PROJECT` and `FIREEMU_PRODUCTION_API_KEY`).

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
