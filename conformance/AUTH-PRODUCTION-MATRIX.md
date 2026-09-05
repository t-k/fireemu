# Authentication production matrix

Identity Toolkit REST programs (`src/auth-probe/programs.mjs`) run against production Authentication, the official Auth emulator (`auth-matrix.json`) and fireemu. Regenerate with `pnpm -C conformance auth-probe:production` (needs `FIREEMU_PRODUCTION_PROJECT` and `FIREEMU_PRODUCTION_API_KEY`).

| status | rows | meaning |
| --- | --- | --- |
| parity | 13 | production, the official emulator and fireemu agree |
| fireemu-matches-production | 0 | fireemu follows production where the official emulator differs |
| fireemu-divergence | 1 | production and the official emulator agree; fireemu differs |
| emulators-diverge-from-production | 7 | both emulators agree with each other but not with production |
| three-way-difference | 2 | all three differ |

## Rows that are not parity

| row | status | production | official emulator | fireemu |
| --- | --- | --- | --- | --- |
| password/sign-up-and-sign-in#sign-in | emulators-diverge-from-production | {"status":200,"code":"OK","body":{"kind":"<kind>","localId":"<localId>","email":"fireemu-a | {"status":200,"code":"OK","body":{"kind":"<kind>","registered":true,"localId":"<localId>", | {"status":200,"code":"OK","body":{"email":"fireemu-auth-probe-<run>-primary@example.com"," |
| password/sign-up-and-sign-in#wrong-password | emulators-diverge-from-production | {"status":400,"code":"INVALID_LOGIN_CREDENTIALS"} | {"status":400,"code":"INVALID_PASSWORD"} | {"status":400,"code":"INVALID_PASSWORD"} |
| password/sign-up-and-sign-in#unknown-email | emulators-diverge-from-production | {"status":400,"code":"INVALID_LOGIN_CREDENTIALS"} | {"status":400,"code":"EMAIL_NOT_FOUND"} | {"status":400,"code":"EMAIL_NOT_FOUND"} |
| password/sign-up-and-sign-in#lookup | three-way-difference | {"status":200,"code":"OK","body":{"kind":"<kind>","users":[{"localId":"<localId>","email": | {"status":200,"code":"OK","body":{"kind":"<kind>","users":[{"localId":"<localId>","emailVe | {"status":200,"code":"OK","body":{"kind":"<kind>","users":[{"disabled":false,"email":"fire |
| password/sign-up-and-sign-in#update-display-name | three-way-difference | {"status":200,"code":"OK","body":{"kind":"<kind>","localId":"<localId>","email":"fireemu-a | {"status":200,"code":"OK","body":{"kind":"<kind>","localId":"<localId>","emailVerified":fa | {"status":200,"code":"OK","body":{"displayName":"Probe User","email":"fireemu-auth-probe-< |
| password/sign-up-and-sign-in#sign-in-after-delete | emulators-diverge-from-production | {"status":400,"code":"INVALID_LOGIN_CREDENTIALS"} | {"status":400,"code":"EMAIL_NOT_FOUND"} | {"status":400,"code":"EMAIL_NOT_FOUND"} |
| anonymous/lifecycle#lookup-anonymous | fireemu-divergence | {"status":200,"code":"OK","body":{"kind":"<kind>","users":[{"localId":"<localId>"}]}} | {"status":200,"code":"OK","body":{"kind":"<kind>","users":[{"localId":"<localId>"}]}} | {"status":200,"code":"OK","body":{"kind":"<kind>","users":[{"disabled":false,"emailVerifie |
| tokens/errors#unknown-method | emulators-diverge-from-production | {"status":404,"code":"non-json"} | {"status":404,"code":"Not"} | {"status":404,"code":"Not"} |
| tokens/errors#password-reset-for-unknown-email | emulators-diverge-from-production | {"status":200,"code":"OK","body":{"kind":"<kind>","email":"fireemu-auth-probe-<run>-nobody | {"status":400,"code":"EMAIL_NOT_FOUND"} | {"status":400,"code":"EMAIL_NOT_FOUND"} |
| tokens/errors#mfa-enrollment-start-without-token | emulators-diverge-from-production | {"status":400,"code":"INVALID_ID_TOKEN"} | {"status":400,"code":"MISSING_ID_TOKEN"} | {"status":400,"code":"MISSING_ID_TOKEN"} |
