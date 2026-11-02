# Python Admin SDK smoke tests

Exercise a running `fireemu` with the real Python Admin SDK: `firebase-admin` and
`google-cloud-firestore`, pinned with hashes in `requirements.txt` (generated from `requirements.in`
with `uv pip compile requirements.in --python-version 3.12 --generate-hashes`).

- `test_firestore.py`: set / get / update / delete, a `where` / `order_by` / `limit` query, a batch,
  a `@firestore.transactional` transaction, `on_snapshot` receiving an update and unsubscribing,
  and the `ArrayUnion`, `Increment` and `SERVER_TIMESTAMP` transforms (gRPC).
- `test_auth.py`: `create_user` / `get_user` / `update_user` / `delete_user`,
  `set_custom_user_claims`, `list_users`, `create_custom_token`, and `verify_id_token` on an ID
  token from a password sign-in through the Identity Toolkit endpoint the emulator serves.
- `test_storage.py`: `upload_from_string`, `download_as_bytes`, metadata, delete (GCS JSON API).

The suite reads the emulator endpoints the clients use, `FIRESTORE_EMULATOR_HOST`,
`FIREBASE_AUTH_EMULATOR_HOST` and `STORAGE_EMULATOR_HOST` (the Storage client takes its endpoint
from this one, with the `http://` scheme), refuses to start unless each is a loopback `host:port`
without userinfo (`emulator_guard.py`, tested offline in `test_guard.py`), and gives the Admin SDK
an anonymous credential, so it never reaches Google. Run it under
`fireemu exec`, with the default profile and with `fireemu.strict.json`:

```sh
python3 -m venv .venv && .venv/bin/pip install --require-hashes -r tools/sdk-smoke-python/requirements.txt
fireemu exec --project demo-app --hub-port 0 -- .venv/bin/python -m pytest tools/sdk-smoke-python
fireemu exec --config tools/sdk-smoke-python/fireemu.strict.json --project demo-app --hub-port 0 -- .venv/bin/python -m pytest tools/sdk-smoke-python
```

The `sdk-smoke-python` job in `.github/workflows/ci.yml` runs both on Python 3.12.
