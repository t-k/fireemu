# Held MFA pending credential across password-reset: revision 1 (history)

Status: superseded historical record, not approved as current. This revision-1 observation is retained as history; the full receipt, comparison and approvals live in git at commit `8d3a5ca7` under `spec/compatibility/evidence/auth-pending-trigger-password-reset/`. The current record is revision 2 (`auth-pending-trigger-password-reset.md`), which records each token field of the transition response separately.

Recorded 2026-09-12. The held MFA pending credential and SMS session created before the transition were presented afterwards: held start accepted / none, held finalize accepted / none. The transition itself: accepted / none, tokensReturned False.

Revision 1 recorded the transition's token response only as a single `tokensReturned` derived from the ID token. Revision 2 records the ID token, refresh token and expiry presence separately; that is why this observation was re-run rather than edited in place. The held credential survived the transition, matching fireemu.

The revision-1 production observation and its scoped approval remain valid in history; they are not re-validated here.
