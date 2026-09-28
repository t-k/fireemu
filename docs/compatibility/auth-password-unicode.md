# Unicode password upper-bound observations

Status: candidate, not approved. Eight input observations with validated credential/state and cleanup controls; not raw responses or independent token verification.

Eight generated password upper-bound inputs, each with a distinct dedicated account, under the recorded minimum 6 / maximum 4096 policy. End-user REST, no tenant, owned strict artifact versus production. Redacted observations of acceptance/refusal plus branch-specific credential/state controls; no human approval, no universal Unicode rule or SDK/Rules/expiry claim.

| Input | Scalars | UTF-8 bytes | UTF-16 units | Local outcome / error | Production outcome / error | Same projection |
|---|---:|---:|---:|---|---|---|
| ascii-at | 4096 | 4096 | 4096 | accepted / none | accepted / none | True |
| ascii-over | 4097 | 4097 | 4097 | refused / PASSWORD_DOES_NOT_MEET_REQUIREMENTS | refused / PASSWORD_DOES_NOT_MEET_REQUIREMENTS | True |
| bmp-byte-at | 2064 | 4096 | 2064 | accepted / none | accepted / none | True |
| bmp-byte-over | 2065 | 4098 | 2065 | accepted / none | accepted / none | True |
| astral-unit-at | 2064 | 8160 | 4096 | accepted / none | accepted / none | True |
| astral-unit-over | 2065 | 8164 | 4098 | accepted / none | refused / PASSWORD_DOES_NOT_MEET_REQUIREMENTS | False |
| bmp-scalar-at | 4096 | 8160 | 4096 | accepted / none | accepted / none | True |
| bmp-scalar-over | 4097 | 8162 | 4097 | refused / PASSWORD_DOES_NOT_MEET_REQUIREMENTS | refused / PASSWORD_DOES_NOT_MEET_REQUIREMENTS | True |

Review subject (unapproved): `9c0364b6cabdf9497c243db1956655e9d455a08578b0ce1f58bd39d5aa9dcfbf`.

local: counting hypotheses consistent with these eight outcomes: scalars.
production: counting hypotheses consistent with these eight outcomes: utf16Units.

These are finite-pattern inferences, not proof of a universal counting rule. Each password contains a private random 32-character ASCII prefix and one repeated suffix character: ASCII a, U+00E9 or U+10400. Separate accounts/runs are not strict causal experiments. Combining marks, normalization, grapheme clusters, isolated surrogates, minimum-length behavior and all Unicode strings remain untested.

Before update, signup and signin credentials work, including the fixed baseline refresh token and derived ID lookup. After acceptance, the exact generated password signs in and update-issued ID/refresh tokens work. After refusal, the unchanged baseline ID, baseline refresh token and original password work. Selected account lookup fields are compared throughout. An incomplete flow, unknown/authentication error or cleanup failure is not a valid length observation; private diagnostics are retained.

A policy-related HTTP 400 refusal is recorded as an observed outcome, not scored against an assumed counting rule. Its exact allowlisted error is compared across targets, as are all public row checks and expiry values. Every token control requires returned lifetime 3600 and same-account fields; no elapsed-expiry or independent-signature claim follows.

Each account is created only after a private exclusive journal and independent absence preflight, identified by random email/marker plus saved/read-back UID, and deleted with UID/email absence confirmation. The suite stops on any incomplete sample. Owned artifact/config hashes, parent/child identity, process exit and listener closure are validated. Production project/policy configuration is read before/after without writes.

[Receipt](../../spec/compatibility/evidence/auth-password-unicode/receipt.json) · [Source mapping](../../spec/compatibility/evidence/auth-password-unicode/source-review.json). Old observations, source reviews and approvals remain unchanged; none transfer to this subject.
