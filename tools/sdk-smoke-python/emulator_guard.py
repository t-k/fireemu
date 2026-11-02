"""Refuses to run unless every emulator endpoint the Admin SDK clients read is a loopback address.

The clients read these variables (firebase-admin 7.7.0, google-cloud-firestore 2.34.1,
google-cloud-storage 3.17.1; `fireemu exec` exports each of them):

- FIRESTORE_EMULATOR_HOST: bare `host:port`, a gRPC insecure channel.
- FIREBASE_AUTH_EMULATOR_HOST: bare `host:port`, used for REST calls and emulated token checks.
- STORAGE_EMULATOR_HOST: `http://host:port`. The Storage client takes it as the endpoint, and
  without it would fall back to API_ENDPOINT_OVERRIDE or to storage.googleapis.com.

FIREBASE_STORAGE_EMULATOR_HOST is exported too, but no Python client reads it.

Error messages name the variable and never echo its value: under App Check capability mode
`fireemu exec` puts a per-run secret into the userinfo of STORAGE_EMULATOR_HOST.
"""

import re
import urllib.parse

REQUIRED_HOSTS = (
    "FIRESTORE_EMULATOR_HOST",
    "FIREBASE_AUTH_EMULATOR_HOST",
    "STORAGE_EMULATOR_HOST",
)
LOOPBACK_HOSTNAMES = frozenset({"127.0.0.1", "localhost", "::1"})
_PORT = re.compile(r"[0-9]{1,5}")


def _loopback(name, value, *, scheme):
    """Returns (hostname, port) for an authority that must be a loopback emulator, else raises."""
    if scheme:
        if not value.startswith("http://"):
            raise ValueError(f"{name} must be an http:// URL")
        text = value
    else:
        if "://" in value:
            raise ValueError(f"{name} must be a bare host:port, without a scheme")
        text = "http://" + value
    try:
        parts = urllib.parse.urlsplit(text)
        hostname = parts.hostname
        port_text = parts.netloc.rpartition(":")[2]
    except ValueError as error:
        raise ValueError(f"{name} is not a valid authority") from error
    if "@" in parts.netloc or parts.username is not None or parts.password is not None:
        raise ValueError(f"{name} must not carry userinfo")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError(f"{name} must be an authority only, without a path, query or fragment")
    if hostname not in LOOPBACK_HOSTNAMES:
        raise ValueError(f"{name} must name a loopback host (127.0.0.1, localhost or ::1)")
    if not _PORT.fullmatch(port_text):
        raise ValueError(f"{name} must have a numeric port")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError(f"{name} must have a port between 1 and 65535")
    return hostname, port


def emulator_endpoints(environ):
    """Returns the validated loopback endpoints of REQUIRED_HOSTS, or raises ValueError."""
    missing = [name for name in REQUIRED_HOSTS if not environ.get(name, "").strip()]
    if missing:
        raise ValueError(
            "run this suite under `fireemu exec` (missing " + ", ".join(missing) + ")"
        )
    return {
        name: _loopback(name, environ[name], scheme=name == "STORAGE_EMULATOR_HOST")
        for name in REQUIRED_HOSTS
    }
