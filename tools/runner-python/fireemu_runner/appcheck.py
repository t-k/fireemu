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

The runner fetches the keys itself (`LoopbackKeyClient`) instead of leaving it to PyJWT's `PyJWKClient`, whose
redirect and proxy behaviour depends on the PyJWT version (2.13.0, which the SDK's constraints allow, follows
redirects). The client connects to a loopback address it resolved and checked, ignores proxy variables, treats every
redirect as a failure, and bounds time and size. What the Python SDK checks of a token is the stock SDK's, plus what
the emulator always does and the stock SDK leaves optional (`exp`, the exact issuer).

Differences from Node, which the Functions page states: the Python SDK verifies against the keys alone, so it has no
check of the daemon's current project epoch or app state (the Node callable trust boundary has one), and it is not
instrumented, so it has no start-up self-test. The PyJWT floor below is the lowest version the tests ran against.
"""

import http.client
import ipaddress
import json
import re
import socket
import threading
import time
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


MIN_PYJWT = (2, 10, 1)
_REQUIRED_ATTRIBUTES = ("_JWKS_URL", "_APP_CHECK_HEADERS", "_decode_and_verify", "_has_valid_token_headers", "verify_token")
_ISSUER = re.compile(r"https://firebaseappcheck\.googleapis\.com/([0-9]+)")


def _pyjwt_supported() -> bool:
    import jwt

    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", str(getattr(jwt, "__version__", "")))
    return match is not None and tuple(int(part) for part in match.groups()) >= MIN_PYJWT


def _loopback_addresses(host: str, port: int) -> list[str]:
    """The loopback addresses `host` names. Every address a name resolves to must be loopback, or none is used."""
    literal = host.strip("[]")
    try:
        addresses = [ipaddress.ip_address(literal)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as error:
            raise OSError(f"cannot resolve {host}") from error
        addresses = [ipaddress.ip_address(info[4][0].split("%")[0]) for info in infos]
    if not addresses or not all(address.is_loopback for address in addresses):
        raise OSError(f"{host} is not a loopback address")
    return [str(address) for address in addresses]


class LoopbackKeyClient:
    """Fetches and caches the App Check emulator's signing keys from one loopback URL, and nowhere else.

    Same contract as `jwt.PyJWKClient.get_signing_key_from_jwt` (the object it returns has a `.key`), without any of
    its transport: no redirect is followed (a 3xx is a failure), no proxy variable is read, the connection goes to a
    loopback address the client resolved and checked itself, and time and size are bounded. A failure means no key,
    so the token does not verify.
    """

    def __init__(self, url, *, timeout=5.0, max_bytes=256 * 1024, lifespan=21600, refresh_interval=1.0, headers=None):
        self._url = url
        self._timeout = timeout
        self._max_bytes = max_bytes
        self._lifespan = lifespan
        self._refresh_interval = refresh_interval
        self._headers = dict(headers or {})
        self._lock = threading.Lock()
        self._keys = {}
        self._fetched_at = None
        self._attempted_at = None

    def _connect(self, addresses, port):
        """A connection to the first of the checked loopback addresses that accepts one (`localhost` may list `::1`)."""
        last = OSError("no address")
        for address in addresses:
            try:
                return socket.create_connection((address, port), timeout=self._timeout)
            except OSError as error:
                last = error
        raise last

    def _fetch(self):
        parts = urlsplit(self._url)
        host, port = parts.hostname, parts.port
        if parts.scheme != "http" or host is None or port is None:
            raise OSError("the key URL is not a loopback http URL")
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        addresses = _loopback_addresses(host, port)
        connection = http.client.HTTPConnection(host, port, timeout=self._timeout)
        try:
            connection.sock = self._connect(addresses, port)
            connection.request("GET", path, headers={"Accept": "application/json", "Connection": "close", **self._headers})
            response = connection.getresponse()
            if response.status != 200:
                raise OSError(f"the key server answered {response.status}")
            body = response.read(self._max_bytes + 1)
            if len(body) > self._max_bytes:
                raise OSError("the key set is larger than the bound")
        finally:
            connection.close()
        document = json.loads(body)
        listed = document.get("keys") if isinstance(document, dict) else None
        if not isinstance(listed, list):
            raise ValueError("the key set has no keys list")
        import jwt

        keys = {}
        for entry in listed:
            if isinstance(entry, dict) and entry.get("kty") == "RSA" and isinstance(entry.get("kid"), str):
                try:
                    keys[entry["kid"]] = jwt.PyJWK(entry)
                except Exception:  # a key that cannot be built is no key
                    continue
        return keys

    def get_signing_key_from_jwt(self, token):
        import jwt
        from jwt.exceptions import PyJWKClientError

        kid = jwt.get_unverified_header(token).get("kid")
        if not isinstance(kid, str) or not kid:
            raise PyJWKClientError("the token has no key id")
        with self._lock:
            now = time.monotonic()
            stale = self._fetched_at is None or now - self._fetched_at > self._lifespan
            if kid in self._keys and not stale:
                return self._keys[kid]
            if self._attempted_at is None or now - self._attempted_at >= self._refresh_interval:
                self._attempted_at = now
                try:
                    self._keys = self._fetch()
                    self._fetched_at = now
                except Exception as error:
                    self._keys, self._fetched_at = {}, None
                    raise PyJWKClientError("the App Check keys could not be fetched") from error
            if kid not in self._keys:
                raise PyJWKClientError(f"unable to find a signing key that matches {kid!r}")
            return self._keys[kid]


def _emulator_service(stock, url: str):
    """The Admin SDK's App Check service, keyed to `url` and without credentials or a way to reach Google.

    The stock service builds an authorised HTTP client in its constructor (`app.credential.get_credential()`), which
    only limited-use consumption uses; a runner has no Google credential, so the stock service cannot even verify.
    This one is the same verifier (`verify_token`, the header and signature checks are the SDK's own methods) with
    the keys fetched by `LoopbackKeyClient`, consumption refused, and two claim checks the emulator always satisfies.
    The audience rule stays the stock SDK's (`projects/<projectId>`).
    """
    from firebase_admin import exceptions

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
            self._jwks_client = LoopbackKeyClient(self._JWKS_URL, lifespan=21600, headers=self._APP_CHECK_HEADERS)
            self._http_client = None

        def _decode_and_verify(self, token, signing_key):
            payload = super()._decode_and_verify(token, signing_key)
            exp = payload.get("exp")
            if isinstance(exp, bool) or not isinstance(exp, (int, float)):
                raise ValueError('The provided App Check token has no "exp" (expiration) claim.')
            issuer = payload.get("iss")
            match = _ISSUER.fullmatch(issuer) if isinstance(issuer, str) else None
            if match is None:
                raise ValueError('The provided App Check token has an incorrect "iss" (issuer) claim.')
            audience = payload.get("aud")
            audiences = [audience] if isinstance(audience, str) else audience if isinstance(audience, list) else []
            numbers = [item[len("projects/"):] for item in audiences if isinstance(item, str) and item.startswith("projects/") and item[len("projects/"):].isdigit()]
            if any(number != match.group(1) for number in numbers):
                raise ValueError('The provided App Check token has a project number in "aud" that is not its issuer\'s.')
            subject = payload.get("sub")
            if not isinstance(subject, str) or not subject:
                # The stock SDK refuses a missing one and lets an empty one through.
                raise ValueError('The provided App Check token has no "sub" (app ID) claim.')
            return payload

        def _verify_replay_protection(self, token):
            raise exceptions.FailedPreconditionError(
                "limited-use App Check token consumption is not available in fireemu (APP_CHECK_REPLAY_UNSUPPORTED)"
            )

    return EmulatorAppCheckService


def install_jwks_hook(url: str) -> bool:
    """Replaces the Admin SDK's App Check service with one keyed to `url`. False when this SDK is not the one that
    replacement was written for, or PyJWT is older than the tested floor (the runner then announces nothing, and the
    daemon keeps removing the header)."""
    from firebase_admin import app_check

    stock = getattr(app_check, "_AppCheckService", None)
    if stock is None or not isinstance(getattr(stock, "_JWKS_URL", None), str):
        return False
    if not all(hasattr(stock, name) for name in _REQUIRED_ATTRIBUTES) or not _pyjwt_supported():
        return False
    app_check._AppCheckService = _emulator_service(stock, url)
    return True


def install_from_environment(environ) -> bool:
    """Installs the hook when the daemon named a loopback JWKS URL; True when the SDK now verifies against it."""
    url = jwks_url(environ)
    return url is not None and install_jwks_hook(url)
