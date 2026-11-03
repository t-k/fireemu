"""Callable App Check: the Admin SDK verifies the token against the App Check emulator's keys.

SECURITY-SENSITIVE. A Python callable checks the `X-Firebase-AppCheck` header itself, in the SDK's wrapper, with
`firebase_admin.app_check.verify_token` (`firebase_functions/private/util.py`), which fetches Google's JWKS. The
Python SDK has no switch to skip that check (Node's `skipTokenVerification`), and the daemon's callable trust
boundary does not apply to it, so the runner makes the SDK's own check meaningful locally:

- when the daemon names the App Check emulator's JWKS (`FIREEMU_APP_CHECK_JWKS_URL`, a loopback address), the
  Admin SDK's App Check service is replaced, before any user code runs, by one that fetches keys from it alone, so
  only a token the emulator's key signed verifies, and the runner tells the daemon the callables do not consume tokens (`consumeAppCheckToken:
  disabled`, true: the SDK verifies with `consume=False`), which lets the daemon forward the header;
- otherwise nothing is changed and the runner says nothing, so the daemon keeps removing the header before the
  function and the SDK never fetches a key from Google.

Anything but a loopback `http` URL is refused, so a stray value cannot make the runner fetch keys from elsewhere.
"""

import ipaddress
from urllib.parse import urlsplit

URL_VARIABLE = "FIREEMU_APP_CHECK_JWKS_URL"
_LOOPBACK_NAMES = frozenset(("localhost",))


def jwks_url(environ) -> str | None:
    """The App Check emulator's JWKS URL from the daemon's environment, or None when it is absent or not loopback."""
    value = environ.get(URL_VARIABLE)
    if not value or not isinstance(value, str):
        return None
    try:
        parts = urlsplit(value)
        port = parts.port  # raises for a port out of range
        host = parts.hostname
    except ValueError:
        return None
    if parts.scheme != "http" or host is None or parts.username is not None or parts.password is not None:
        return None
    if parts.fragment or not parts.path.startswith("/") or len(parts.path) < 2 or port is None:
        return None
    if host not in _LOOPBACK_NAMES:
        try:
            if not ipaddress.ip_address(host).is_loopback:
                return None
        except ValueError:
            return None
    return value


_REQUIRED_ATTRIBUTES = ("_JWKS_URL", "_APP_CHECK_HEADERS", "_decode_and_verify", "_has_valid_token_headers", "verify_token")


def _emulator_service(stock, url: str):
    """The Admin SDK's App Check service, keyed to `url` and without credentials or a way to reach Google.

    The stock service builds an authorised HTTP client in its constructor (`app.credential.get_credential()`), which
    only limited-use consumption uses; a runner has no Google credential, so the stock service cannot even verify.
    This one is the same verifier (`verify_token`, the header and signature checks are the SDK's own methods) with
    the key URL fixed and consumption refused, so no code path of it can send a request anywhere but `url`.
    """
    from firebase_admin import exceptions
    from jwt import PyJWKClient

    class EmulatorAppCheckService(stock):
        _JWKS_URL = url

        def __init__(self, app):
            project_id = app.project_id
            if not project_id:
                raise ValueError(
                    "A project ID must be specified to access the App Check service. Either set the projectId "
                    "option, use service account credentials, or set the GOOGLE_CLOUD_PROJECT environment variable."
                )
            self._project_id = project_id
            self._scoped_project_id = "projects/" + project_id
            self._jwks_client = PyJWKClient(self._JWKS_URL, lifespan=21600, headers=self._APP_CHECK_HEADERS)
            self._http_client = None

        def _verify_replay_protection(self, token):
            raise exceptions.FailedPreconditionError(
                "limited-use App Check token consumption is not available in fireemu (APP_CHECK_REPLAY_UNSUPPORTED)"
            )

    return EmulatorAppCheckService


def install_jwks_hook(url: str) -> bool:
    """Replaces the Admin SDK's App Check service with one keyed to `url`. False when this SDK is not the one that
    replacement was written for (the runner then announces nothing, and the daemon keeps removing the header)."""
    from firebase_admin import app_check

    stock = getattr(app_check, "_AppCheckService", None)
    if stock is None or not isinstance(getattr(stock, "_JWKS_URL", None), str):
        return False
    if not all(hasattr(stock, name) for name in _REQUIRED_ATTRIBUTES):
        return False
    app_check._AppCheckService = _emulator_service(stock, url)
    return True


def install_from_environment(environ) -> bool:
    """Installs the hook when the daemon named a loopback JWKS URL; True when the SDK now verifies against it."""
    url = jwks_url(environ)
    return url is not None and install_jwks_hook(url)
