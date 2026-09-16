# Update field authorization regression

This correction is separate from the approved maximum-password observations. Their receipt, source review, subject and recorded artifact remain unchanged. It is a current-handler regression, not a new production-observation receipt or a claim that all Authentication authorization paths are verified.

The [Identity Platform accounts.update reference](https://docs.cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/update) requires privileged Google OAuth credentials when specifying `customAttributes`, `emailVerified`, `mfa` or `linkProviderUserInfo`. An end-user ID token proves account identity but does not grant permission to set those fields.

`update()` now rejects the presence of any of these four fields on an unprivileged route before consuming an OOB code or applying any state change. Presence includes null, empty objects/claims and false. Administrative context comes from the authenticated Admin route dispatch, never from a body field. Normal profile updates and OOB-only email verification remain supported.

| Regression | Obligation |
|---|---|
| `end_user_update_rejects_admin_fields_atomically_by_presence` | Both profiles; 13 value variants covering the four fields; mixed displayName updates reject without changing the complete account lookup projection; authenticated Admin setup and normal profile updates succeed |
| `admin_fields_rejection_does_not_consume_an_oob_code` | Each forbidden field mixed with an OOB action rejects before mutation or code consumption; the same code subsequently verifies email successfully when used alone |
| Existing maximum-password and localId-selection regressions | Preserve the independent length boundary and account-selection authorization checks |

Before the fix, both new tests failed because requests returned HTTP 200 instead of refusal. After the fix, the core-auth and adapter-http suites passed. A mutation allowing null-valued forbidden fields was rejected by the new tests. The CI workflow executes the two new handler tests and the existing maximum boundary test on current sources.

The local refusal uses `OPERATION_NOT_ALLOWED`. No production request was made for this correction, so exact production error-body parity for these rejected inputs is not claimed. Other Auth endpoints and permissions are outside this bounded regression. The approved maximum21 observations are checked separately by `tools/compat-history/maximum_history.py` at their fixed source anchor; historical checks do not retest them on the new artifact.
