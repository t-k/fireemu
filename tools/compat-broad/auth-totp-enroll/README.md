# AUTH-MFA-TOTP-ENROLL-RETRY-01 offline preparation

This package prepares a bounded local shadow for the TOTP enrollment retry boundary. It covers one verified account and one enrollment session: start, one wrong OTP, retry with the correct OTP, and replay after success. The negative controls cover an unverified account and a wrong tenant selector.

`totp_plan.py` emits an inert 15-operation manifest with a fresh nonce, a 10-minute wall-time limit, and a USD 2.00 cost ceiling. The manifest is `PREPARED_NOT_READY`; it has no production authorization, credentials, or executable production transport.

`totp_shadow.py` uses an in-memory state machine and RFC 6238-compatible code generation. `run()` writes a stage checkpoint and a secret-free result under a newly created output directory. It performs no network access, delivery, credential acquisition, or production request.

`totp_comparator.py` compares saved response rows after projecting secret, OTP, password, and token values to length and digest. Incomplete recording is `INCONCLUSIVE`; a cleanup-only difference is `CLEANUP_DIFF`; response/status differences are `DIFF`. A matching result is local comparator output only and does not establish production parity.

Run the focused checks with:

```bash
uv run --project tools/compat-inventory --locked pytest tools/compat-broad/auth-totp-enroll
uv run --project tools/compat-inventory --locked ruff check tools/compat-broad/auth-totp-enroll
```
