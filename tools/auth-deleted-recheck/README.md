# Deleted-account credential recheck

This recheck keeps the original mismatching observation immutable and compares a new owned local artifact with exactly the saved production record. It does not make new production requests or inherit approval.

## Runtime correction and retention

Lookup maps the existing validated-token UnknownUser result to USER_NOT_FOUND only on the observed accounts:lookup route. Decode, issuer, audience, tenant and expiry checks retain their order. Other ID-token API routes are not given a new blanket error mapping.

When a user is deleted, currently registered refresh sessions become rejection-only SHA-256 identities. The deletion set contains no raw token, UID, password or claims. It is distinct from live sessions and checked before session acceptance, including the compatibility path without revocation enforcement. Recreating the same UID cannot revive those refresh credentials. Arbitrary or modified refresh input remains INVALID_REFRESH_TOKEN. Ordinary explicit refresh-session removal is unchanged; a token removed before deletion has no deletion record.

Routing recognizes deletion identities in their owning project/tenant without treating ownership as authentication. Ambiguous legacy identities remain ambiguous. Reset clears the set, same-namespace snapshots preserve it, and cross-namespace restoration clears it. Restoring an earlier snapshot intentionally restores that earlier state; this is not deletion persistence across rollback or restart. No new durable tombstone export format is introduced.

There is no TTL or silent eviction: changing the error after an arbitrary interval would lose compatibility information. The set therefore grows with deleted registered credentials until reset. transient_bytes accounts for 96 estimated bytes per digest, including tree overhead, but this is an estimate, not a hard live-memory admission limit. Copies share the set until mutation. Operators of long-lived high-churn sessions must include this growth in capacity planning.

## Verification boundary

Local regressions cover deleted versus unknown input, an unaffected account, expiry precedence, fixed refresh credentials after UID recreation, namespace routing, snapshot/reset behavior and 4,096 bounded lifecycle traces. Existing disabled/revocation tests remain distinct. These tests do not establish production account-recreation behavior, universal ID-token non-revival across UID reuse, all API routes, SDK/checkRevoked, Rules, propagation timing or fault recovery.

The saved production run used password signin, fixed ID-token lookup, then fixed refresh and derived lookup in each phase. The recheck retains that order and compares all public case fields except bounded elapsedMs. The same input classifications are used, not identical secret credentials.

Run the new local observation with the unchanged tools/auth-deleted/deleted_owned.py recorder, then publish it with tools/publish-auth-deleted-recheck.py. The old diagnostic, disable/re-enable recheck and its approval are checked by tools/compat-history/deleted_history.py at their fixed historical source, separately from current runtime regressions.
