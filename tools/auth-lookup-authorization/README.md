# End-user lookup and administrator lookup authorization

The local accounts:lookup handler now selects its authorization path from authenticated dispatch, not the number of search criteria. End-user requests always verify their ID token, preserve the lookup-specific USER_NOT_FOUND classification for a validated deleted subject, and return only that verified subject. The presence of localId, email, phoneNumber or federatedUserId on this path is refused, including empty arrays, null and malformed values. A body admin flag or emulator owner header cannot turn the end-user handler into Admin lookup.

The project-scoped Admin route retains its existing administrator credential check before dispatch and supports its existing identifier searches. In local regression tests the established emulator owner credential is used; this is not a new test of Google IAM/OAuth validation.

This follows the [Identity Platform lookup authorization distinction](https://docs.cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/lookup): end-user lookup retrieves the end user's account, whereas authenticated Admin lookup may select matching accounts. The local fix verifies a token before refusing supplied administrative selectors; it returns OPERATION_NOT_ALLOWED for a valid token plus a selector. No production requests were made to establish exact error-code or precedence parity for these selector combinations.

## Regression coverage

The existing pure HTTP handler integration test lookup_authorization_separates_end_user_identity_from_admin_selectors covers both profiles, four supported selector types, populated/empty/null/malformed selector values, missing/malformed/caller/target ID tokens, forged body role flags, end-user requests with the local owner header, Admin requests without a valid administrator credential, positive Admin searches, positive token-only self lookup and deleted token-only USER_NOT_FOUND. The target has populated phone and federated identities, so the positive controls prove those lookup selectors actually resolve it.

These are current-runtime regressions, not new production observations or an approval of all Authentication authorization. The previous twelve deleted-credential observations and their limited human approval remain unchanged. tools/compat-history/lookup_history.py checks that approved recheck at its fixed source; CI separately runs the current lookup regression. No historical approval is transferred to a new artifact.
