# Unicode password upper-bound observations

Status: candidate, not approved. Three input observations with validated credential/state and cleanup controls; not raw responses or independent token verification.

Three generated password upper-bound inputs, each with a distinct dedicated account, under the recorded minimum 6 / maximum 4096 policy. End-user REST, no tenant, owned strict artifact versus production. Redacted observations of acceptance/refusal plus branch-specific credential/state controls; no human approval, no universal Unicode rule or SDK/Rules/expiry claim.

| Input | Scalars | UTF-8 bytes | UTF-16 units | Local outcome / error | Production outcome / error | Same projection |
|---|---:|---:|---:|---|---|---|
| astral-4095 | 2064 | 8157 | 4095 | accepted / none | accepted / none | True |
| astral-4096 | 2064 | 8160 | 4096 | accepted / none | accepted / none | True |
| astral-4097 | 2065 | 8161 | 4097 | refused / PASSWORD_DOES_NOT_MEET_REQUIREMENTS | refused / PASSWORD_DOES_NOT_MEET_REQUIREMENTS | True |

Review subject (unapproved): `3b300cebcbddac2db8528f4c9f9ca29b1b767932ce47aede41ee4e6e6946121c`.

local: counting hypotheses consistent with these three outcomes: utf16Units.
production: counting hypotheses consistent with these three outcomes: utf16Units.

These are finite-pattern inferences, not proof of a universal counting rule. Each password contains a private random 32-character ASCII prefix and a U+10400 suffix repeated 2031 or 2032 times, followed by zero or one ASCII a. Separate accounts/runs are not strict causal experiments. Combining marks, normalization, grapheme clusters, isolated surrogates, minimum-length behavior and all Unicode strings remain untested.

Before update, signup and signin credentials work, including the fixed baseline refresh token and derived ID lookup. After acceptance, the exact generated password signs in and update-issued ID/refresh tokens work. After refusal, the unchanged baseline ID, baseline refresh token and original password work. Selected account lookup fields are compared throughout. An incomplete flow, unknown/authentication error or cleanup failure is not a valid length observation; private diagnostics are retained.

A policy-related HTTP 400 refusal is recorded as an observed outcome, not scored against an assumed counting rule. Its exact allowlisted error is compared across targets, as are all public row checks and expiry values. Every token control requires returned lifetime 3600 and same-account fields; no elapsed-expiry or independent-signature claim follows.

Each account is created only after a private exclusive journal and independent absence preflight, identified by random email/marker plus saved/read-back UID, and deleted with UID/email absence confirmation. The suite stops on any incomplete sample. Owned artifact/config hashes, parent/child identity, process exit and listener closure are validated. Production project/policy configuration is read before/after without writes.

[Receipt](../../spec/compatibility/evidence/auth-password-unicode-boundary/receipt.json) · [Source mapping](../../spec/compatibility/evidence/auth-password-unicode-boundary/source-review.json). Old observations, source reviews and approvals remain unchanged; none transfer to this subject.
