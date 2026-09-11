# Phone MFA refusal and retry

This local correction delays credential consumption until request matching succeeds. It is not a new production observation or approval.

The HTTP handler now checks an SMS code without consuming it, validates its MFA purpose and exact pending credential, and consumes the code after successful core finalization. The core finalizer checks that both the pending credential and requested phone factor exist before removing the pending credential and its owner index. Existing request serialization, SMS expiry validation and transient expiry sweeping remain unchanged.

## Local coverage

- Two independent pending credentials for the same account are created by real password sign-ins. An SMS session from A combined with pending B is refused without losing the SMS code, changing the pending count or emitting a notice. A can then use that same code and obtain an ID token that retrieves the original account. Both profiles are tested without blocking hooks.
- Successful retry consumes the SMS code immediately, checked directly in the store before request-level sweeping can mask a missing consumption. Reusing the completed combination is refused.
- A core finalization request naming an absent factor preserves its pending credential; a retry naming the existing factor succeeds and removes that pending credential.
- A valid plain phone sign-in code is refused by the MFA finalizer, and a valid MFA sign-in code is refused by the plain phone sign-in, each with `INVALID_SESSION_INFO`. Neither refusal removes a code, changes the pending count or emits a notice. Both codes then succeed for their own purpose and are consumed exactly once. This regression was added after the fix and passed against it; it fails when the finalizer consumes the code before checking its purpose.

- Expiry boundaries on the virtual clock, through the HTTP handlers and their request-level sweep: an MFA SMS code is accepted exactly at its lifetime and refused one second later with `INVALID_SESSION_INFO` while the pending credential survives, so the same pending credential can start a fresh code and finalize with it; the expired code stays dead. A pending credential is accepted exactly at its lifetime and gone one second later, together with its code, so both finalize and start are refused. Off-by-one mutations of the SMS and pending boundaries fail this test.

These tests are selected by `pending_retry` in the HTTP `auth_flows` and core `mfa` test binaries and run in compatibility CI. The first two regressions failed against the previous implementation: the SMS listing became empty after a pending mismatch, and the pending owner disappeared after a missing-factor refusal.

The guarantee is limited to the tested pre-finalization refusals. It does not promise rollback for every subsequent token issuance or signing failure, all disabled/revoked/expired-user transitions, expiry of pending credentials whose code was issued by a different request than the one being finalized, the enrollment purpose against the finalizer, tenant boundaries, or production error precedence. Existing historical evidence and approvals are preserved and checked at their pinned sources. The broader MFA/Auth audit remains incomplete.
