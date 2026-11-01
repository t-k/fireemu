"""firebase_admin.auth against fireemu's Identity Toolkit REST surface."""

import json
import os
import urllib.request

from firebase_admin import auth


def sign_in(email, password):
    """Signs in through the Identity Toolkit endpoint the emulator serves, as a client SDK does."""
    host = os.environ["FIREBASE_AUTH_EMULATOR_HOST"]
    request = urllib.request.Request(
        f"http://{host}/identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=fake-api-key",
        data=json.dumps(
            {"email": email, "password": password, "returnSecureToken": True}
        ).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def test_user_lifecycle_and_custom_claims(app, unique):
    email = f"py-{unique}@example.com"
    user = auth.create_user(email=email, password="correct-horse", display_name="Ada", app=app)
    try:
        fetched = auth.get_user(user.uid, app=app)
        assert (fetched.email, fetched.display_name) == (email, "Ada")
        auth.update_user(user.uid, display_name="Grace", disabled=False, app=app)
        assert auth.get_user(user.uid, app=app).display_name == "Grace"
        auth.set_custom_user_claims(user.uid, {"admin": True, "tier": 2}, app=app)
        assert auth.get_user(user.uid, app=app).custom_claims == {"admin": True, "tier": 2}
        assert auth.get_user_by_email(email, app=app).uid == user.uid
    finally:
        auth.delete_user(user.uid, app=app)
    try:
        auth.get_user(user.uid, app=app)
    except auth.UserNotFoundError:
        pass
    else:
        raise AssertionError("a deleted user is still found")


def test_list_users(app, unique):
    uids = [
        auth.create_user(email=f"py-list-{unique}-{i}@example.com", app=app).uid
        for i in range(3)
    ]
    try:
        listed = {user.uid for user in auth.list_users(max_results=2, app=app).iterate_all()}
        assert set(uids) <= listed
    finally:
        for uid in uids:
            auth.delete_user(uid, app=app)


def test_create_custom_token(app, unique):
    token = auth.create_custom_token(f"py-custom-{unique}", {"role": "tester"}, app=app)
    assert isinstance(token, bytes)
    header, payload, _ = token.split(b".")
    assert header and payload


def test_verify_id_token_from_an_emulator_sign_in(app, unique):
    email = f"py-verify-{unique}@example.com"
    user = auth.create_user(email=email, password="correct-horse", app=app)
    try:
        auth.set_custom_user_claims(user.uid, {"admin": True}, app=app)
        signed_in = sign_in(email, "correct-horse")
        decoded = auth.verify_id_token(signed_in["idToken"], app=app)
        assert decoded["uid"] == user.uid
        assert decoded["email"] == email
        assert decoded["admin"] is True
    finally:
        auth.delete_user(user.uid, app=app)
