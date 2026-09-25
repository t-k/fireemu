# Two-party Auth ownership regressions

These are local in-process handler tests in both profiles, not production observations or new execution approvals. No runtime behavior or historical evidence is changed.

| Obligation | Check |
| --- | --- |
| A's phone enrollment code cannot enroll B | B's finalize is refused; code listing, notices and both account records stay unchanged |
| Refusal must not burn A's code | A finalizes with the exact same session and code after B's refusal |
| B cannot remove A's factor | B's withdraw is refused and both account records remain unchanged |
| A can still remove the factor | A withdraws with the enrollment response token; lookup shows no remaining factor |
| An existing IdP fixture identity cannot be transferred to B | A links first, B's link is refused, both account records stay unchanged |
| The IdP fixture still authenticates A | Sign-in with the same fixture returns A's UID and its issued token retrieves A |

Run `cargo nextest run --locked -p fireemu-adapter-http --test auth_flows two_party`. Compatibility CI runs the same named tests with Cargo. Existing eligibility, normal enrollment and fixture tests are intentionally retained as overlapping coverage.

IdP assertions remain fake JWT fixtures, not real provider signature validation or OAuth/OIDC/SAML exchanges. The scenarios do not cover all tenant boundaries, expired/revoked identities, TOTP cross-account flows, concurrent requests, or every MFA continuation state. Passing these tests does not complete the Auth authorization audit.
