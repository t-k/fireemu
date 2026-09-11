# OOB credential issuance authorization

This is a local authorization regression fix, not a new production observation or an approval of all Authentication behavior. Existing observations and approvals remain unchanged.

## Boundary

`accounts:sendOobCode` on the EndUser route must not return an OOB credential merely because the request contains `returnOobLink: true`. The handler rejects that request before creating a code or emitting a delivery notice. For `VERIFY_EMAIL` and `VERIFY_AND_CHANGE_EMAIL`, it verifies the end-user ID token and selects that token's account, never an arbitrary email supplied alongside it. Missing, null, malformed, or incorrectly typed tokens cannot fall back to an email lookup.

Ordinary `PASSWORD_RESET` and `EMAIL_SIGNIN` delivery remains available without an ID token. These responses do not contain the code or link. Normal verification delivery remains available with a valid ID token. Local emulator inspection and credential notices remain separate emulator facilities; this change does not turn the emulator into a production security perimeter.

Project- and tenant-scoped Admin link generators continue through the existing Admin credential guard. The dispatch supplies the privilege distinction; a body `admin` flag or an owner header on the EndUser route cannot change it. The local Admin credential is the existing emulator owner credential, not newly implemented Google IAM/OAuth validation.

The [official sendOobCode reference](https://docs.cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/sendOobCode) requires an appropriately privileged Google OAuth credential to return the link and requires an ID token for verification requests outside that privileged generation case. This correction enforces that authorization distinction. It does not claim production parity for error codes, validation order, or every optional field. Locally, unauthorized link-return requests receive HTTP 400 / `OPERATION_NOT_ALLOWED`; token errors retain the existing verifier's classification. `returnOobLink: false` continues to select ordinary delivery.

## Coverage ledger

| Obligation | Local regression |
| --- | --- |
| No EndUser credential return | Four OOB types, absent/malformed/valid token, body Admin spoof, both profiles |
| No email fallback for verification | Both verification types with absent/null/boolean/malformed token, both profiles |
| No issuance side effects on refusal | Outstanding codes, emitted credential notices and both selected account records remain unchanged |
| Ordinary delivery remains usable | All four OOB types; verification selects the token's owner despite a different request email |
| Admin generation remains usable | All four types through the authenticated project route; absent credentials and user bearer tokens refused |
| Route cannot be promoted by request data | Owner header on EndUser route does not enable link return |
| Action-code behavior remains usable | Existing verification/change-email application and refusal-without-code-consumption tests retained |

The tests are in `crates/fireemu-adapter-http/tests/auth_flows.rs`, selected by `oob_authorization`, and run in compatibility CI. They use real in-process handlers and stores, not mocked authentication. They do not constitute a fresh live Firebase comparison, a full HTTP-server transport test, or exhaustive coverage of every Auth route.

Historical evidence checks use their pinned historical sources. Current runtime regressions are separate; passing historical checks does not prove that the current runtime repeats all historical observations.
