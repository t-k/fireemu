# FS-DATA-WRITE historical production regression

The FS-DATA-WRITE closure condition `FS-DATA-WRITE/final-artifact-regression` reruns the historical Firestore production matrix against the final release artifact with `pnpm -C conformance firestore:check-production`. The command compares the pinned historical production recording (`conformance/firestore-production-matrix.json`) with a fresh fireemu run in the emulator profile (`conformance/firestore-probe.fireemu.json`), and fails on any new mismatch or new indeterminate row. The run, its artifact and its counts are recorded in `spec/compatibility/closure/evidence/FS-DATA-WRITE-historical-regression.json`.

This page gives, for each row that is not a match, the existing public evidence that explains it. It adds no new observation. The evidence file also lists, for a row production answered with 200, the rows where the same API is compared on the release artifact (`comparedElsewhere`), and the closure review names any that are not (`followUps` in `spec/compatibility/closure/FS-DATA-WRITE.json`).

## Rows of the local-only program `emulator/routes` (15 rows)

The program `emulator/routes` has area `emulator` (`conformance/src/firestore-probe/programs.mjs:1357`). Rows of that area are local-only (`conformance/src/firestore-probe/run.mjs:488`), and a local-only row is classified `excluded-local-only`, an explicit exclusion rather than a production comparison (`conformance/src/evidence.mjs:249`). The production matrix records each of these rows with that status. The production matrix excludes these rows whatever the production answer is; the historical regression still compares them and carries them as known mismatches. The production answer below is the one recorded in the matrix.

| row | production answer | production matrix row | production recording |
| --- | --- | --- | --- |
| `emulator/routes#clear-database` | 404 non-json | `conformance/FIRESTORE-PRODUCTION-MATRIX.md:138` | `conformance/firestore-production-matrix.json:31178` |
| `emulator/routes#cleared-document-is-gone` | 200 OK | `conformance/FIRESTORE-PRODUCTION-MATRIX.md:139` | `conformance/firestore-production-matrix.json:31196` |
| `emulator/routes#cleared-subcollection-is-gone` | 200 OK | `conformance/FIRESTORE-PRODUCTION-MATRIX.md:140` | `conformance/firestore-production-matrix.json:31223` |
| `emulator/routes#clear-unknown-database` | 404 non-json | `conformance/FIRESTORE-PRODUCTION-MATRIX.md:141` | `conformance/firestore-production-matrix.json:31250` |
| `emulator/routes#put-rules-that-do-not-compile` | 404 non-json | `conformance/FIRESTORE-PRODUCTION-MATRIX.md:143` | `conformance/firestore-production-matrix.json:31286` |
| `emulator/routes#put-rules-with-a-warning` | 404 non-json | `conformance/FIRESTORE-PRODUCTION-MATRIX.md:144` | `conformance/firestore-production-matrix.json:31304` |
| `emulator/routes#put-rules-without-files` | 404 non-json | `conformance/FIRESTORE-PRODUCTION-MATRIX.md:145` | `conformance/firestore-production-matrix.json:31322` |
| `emulator/routes#put-rules-restores-open-rules` | 404 non-json | `conformance/FIRESTORE-PRODUCTION-MATRIX.md:146` | `conformance/firestore-production-matrix.json:31340` |
| `emulator/routes#commit-on-the-named-database-route` | 404 NOT_FOUND | `conformance/FIRESTORE-PRODUCTION-MATRIX.md:150` | `conformance/firestore-production-matrix.json:31419` |
| `emulator/routes#named-database-document` | 404 NOT_FOUND | `conformance/FIRESTORE-PRODUCTION-MATRIX.md:151` | `conformance/firestore-production-matrix.json:31451` |
| `emulator/routes#default-database-is-separate` | 200 OK | `conformance/FIRESTORE-PRODUCTION-MATRIX.md:152` | `conformance/firestore-production-matrix.json:31487` |
| `emulator/routes#clear-named-database` | 404 non-json | `conformance/FIRESTORE-PRODUCTION-MATRIX.md:153` | `conformance/firestore-production-matrix.json:31514` |
| `emulator/routes#list-databases` | 200 OK | `conformance/FIRESTORE-PRODUCTION-MATRIX.md:156` | `conformance/firestore-production-matrix.json:31568` |
| `emulator/routes#get-database` | 200 OK | `conformance/FIRESTORE-PRODUCTION-MATRIX.md:157` | `conformance/firestore-production-matrix.json:31608` |
| `emulator/routes#get-named-database` | 404 NOT_FOUND | `conformance/FIRESTORE-PRODUCTION-MATRIX.md:158` | `conformance/firestore-production-matrix.json:31644` |

Three of these rows address a named database the recording never created: `emulator/routes#commit-on-the-named-database-route`, `emulator/routes#named-database-document`, `emulator/routes#get-named-database`. Production refused them with NOT_FOUND; the emulator profile materializes a named database on first touch, as the official emulator does, while the strict profile refuses it (ticket FS-CONFIG-RT-001, `docs/compatibility/fs-config-lifecycle-classification.md:127`).

## Environment-dependent difference (1 row)

`errors/rest-shapes#wrong-project`: production answered 403 PERMISSION_DENIED (`conformance/FIRESTORE-PRODUCTION-MATRIX.md:126`, `conformance/firestore-production-matrix.json:23005`), classified `emulators-diverge-from-production`: the official emulator and fireemu both answer 404. The second broad exploration explains it: production reports that the API is unavailable in `other-project`, while the local answer reports missing data, so the environment prerequisites differ; the difference is kept and is not turned into an authorization change (`docs/compatibility/second-broad-exploration.md:44`).

## Indeterminate row (1 row)

`transactions/lifecycle#phantom-write`: the single production attempt timed out (0 no-response; `conformance/FIRESTORE-PRODUCTION-MATRIX.md:122`, `conformance/firestore-production-matrix.json:22443`) and is recorded as unverified; re-attempting it needs a query-shaped collector (`docs/compatibility/fs-transaction-next-campaign-preparation.md:445`).
