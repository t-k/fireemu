# Bounded Auth password change observations

This versioned recorder captures twelve end-user email/password REST cases without publishing reusable credentials. It does not modify earlier recorders, receipts or approvals. The source review and publisher are separate bound inputs. New receipts remain candidates until independently reviewed and explicitly approved for their exact subject.

The flow proves the original password by signin, changes it using that fresh ID token, uses the returned ID token and refresh token, rejects the old password, signs in with the replacement password and compares selected fields for the same UID. End-user deletion is followed by exact UID and email absence checks. Admin APIs establish ownership and perform fallback cleanup only.

## Safety and scope

- Production is fixed to `fireemu-35fe6` / `592603257417`. No tenant is specified. Email/password and improved email privacy must be enabled; blocking hooks must be absent.
- Creation requires omitted admin `passwordPolicyConfig` plus explicit client `getPasswordPolicy` readback: schema 1, ENFORCE, minimum 6 and maximum 4096. Missing admin configuration is not interpreted as OFF. Other policies are a recorder preflight blocker, not a runtime compatibility conclusion. No configuration is changed.
- Both passwords are independent 47-character values containing uppercase, lowercase, numeric and non-alphanumeric characters. They are held only in memory. The public receipt does not contain passwords, tokens, password hashes, UID or email.
- Journal intent precedes signup. Marker/email plus independent UID lookup establish ownership, which is persisted privately and reread before mutation. Cleanup verifies UID/email and persists recovered UID before deletion. A reused email with another UID is refused. Unknown UID plus absent email is unresolved, not successful cleanup.
- Existing-account cleanup does not depend on password-policy eligibility or knowing either password. Recovery still requires project/configuration identity and ownership checks.
- The local runner builds and copies the artifact, owns its strict process, checks control-token isolation, hash/config stability, exit code and closed listeners. Ports are OS-assigned via port 0. It does not attach to an external daemon.

## Execution

From the repository root, use new private output directories outside tracked paths:

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-password/password_owned.py --output /absolute/private/new-local
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-password/password_recorder.py --production --output /absolute/private/new-production
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-password/password_recorder.py --production --recover /absolute/private/new-production/recovery.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/publish-auth-password.py --local /absolute/private/new-local/local.json --production /absolute/private/new-production/observation.json
```

Production execution requires operator-authorized ADC and project readback permissions. Keep recovery journals private until cleanup is resolved. Boundary errors retain exception classes only. Publishing requires complete observations and refuses to overwrite an existing receipt. It does not turn semantic disagreement into agreement or grant approval.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-password -q
AUTH_PASSWORD_LIVE_LOCAL=1 uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-password -q
uv run --project tools/compat-inventory --locked --python 3.12 tools/publish-auth-password.py --check
```

## Evidence limits

Five token-returning cases check expiry format separately from 3600-second agreement. The record is sanitized recorder testimony, not independently reconstructable raw responses or JWT verification. Selected fields are localId, email, emailVerified, displayName, photoUrl and disabled; missing/null/type distinctions are preserved privately. Credential metadata and login timestamps are not compared as immutable state.

Old-token revocation timing, elapsed expiry, recent-login time boundaries, password-policy boundaries, password reset, SDK, MFA, tenants and full Auth/public npm compatibility remain unverified by this slice. Successful normal cleanup does not prove fault-injected recovery. Pure mutation tests exercise the validator; they do not simulate a faulty Firebase server accepting the old password or rejecting the replacement password.
