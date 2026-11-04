"""Observation fixture for the Python Functions blocking-function sandbox check (identity sandbox project).

One function, `pcblock`, with the trigger of `identity_fn.before_user_created`. It prints two lines per delivery, `PYBLOCK_FRAME <json>`, and
returns no decision, so the sign-up goes through:

- `blocking-raw`: the request as it reached the function, before the SDK touches it (header names, content type, the
  top-level keys of the body, and the names and the safe values of the claims of the token the body carries, read
  without checking its signature). The token itself, the signature and the IP address are never printed.
- `blocking-sdk`: the event the SDK handed to the handler after it verified the token (production verifies against Google's
  certificates; the emulator does not).

A delivery the SDK refuses (a token it cannot verify) shows only the raw line and a Python error in the logs. Nothing here writes to any
service, and no credential is printed.
"""

import base64
import dataclasses
import datetime
import importlib.metadata
import json

import flask
from firebase_functions import identity_fn

MARK = "PYBLOCK_FRAME "
PACKAGES = ("firebase-functions", "functions-framework", "flask", "werkzeug", "firebase-admin", "PyJWT", "gunicorn")
SHOWN_HEADERS = ("content-type", "content-length", "user-agent", "host", "accept-encoding", "x-forwarded-proto")
SAFE_CLAIMS = ("iss", "aud", "event_type", "locale", "sign_in_method", "tenant_id")


def _versions():
    found = {}
    for name in PACKAGES:
        try:
            found[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            found[name] = None
    return found


def _emit(kind, **members):
    frame = {
        "function": "pcblock",
        "kind": kind,
        "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "versions": _versions(),
        **members,
    }
    print(MARK + json.dumps(frame, sort_keys=True, default=str), flush=True)


def _segment(part):
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def _address_view(value):
    """Only whether an address is there and which family it is; never the address."""
    if not isinstance(value, str) or not value:
        return None
    return "ipv6" if ":" in value else "ipv4"


def _token_view(token):
    """The shape of the token without its signature: segment count, header names, claim names and a few safe values."""
    if not isinstance(token, str):
        return {"kind": type(token).__name__}
    parts = token.split(".")
    view = {"kind": "str", "segments": len(parts)}
    try:
        header = _segment(parts[0])
        payload = _segment(parts[1])
    except Exception as error:  # not a JWT
        view["error"] = type(error).__name__
        return view
    record = payload.get("user_record") if isinstance(payload.get("user_record"), dict) else {}
    view.update(
        {
            "header": {"alg": header.get("alg"), "typ": header.get("typ"), "has_kid": "kid" in header, "names": sorted(header)},
            "claim_names": sorted(payload),
            "claims": {name: payload[name] for name in SAFE_CLAIMS if name in payload},
            "ip_family": _address_view(payload.get("ip_address")),
            "user_agent_present": isinstance(payload.get("user_agent"), str),
            "user_record_names": sorted(record),
            "uid": record.get("uid"),
            "email": record.get("email"),
            "timing": {name: payload[name] for name in ("iat", "exp") if isinstance(payload.get(name), (int, float))},
        }
    )
    return view


def _request_view(request):
    headers = {name.lower(): value for name, value in request.headers.items()}
    authorization = headers.get("authorization")
    body = request.get_json(silent=True)
    data = body.get("data") if isinstance(body, dict) else None
    return {
        "method": request.method,
        "path": request.path,
        "header_names": sorted(headers),
        "headers": {name: value for name, value in headers.items() if name in SHOWN_HEADERS},
        "authorization": None
        if authorization is None
        else {"scheme": authorization.split(" ", 1)[0], "segments": len(authorization.split(" ", 1)[-1].split("."))},
        "body_keys": sorted(body) if isinstance(body, dict) else None,
        "data_keys": sorted(data) if isinstance(data, dict) else None,
        "token": _token_view(data.get("jwt") if isinstance(data, dict) else None),
    }


def _plain(value):
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {field.name: _plain(getattr(value, field.name)) for field in dataclasses.fields(value)}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (datetime.datetime, datetime.date)):
        return value.isoformat()
    return value


def _observe(event):
    data = _plain(event.data)
    _emit(
        "blocking-sdk",
        event_type=event.event_type,
        event_id_present=bool(event.event_id),
        locale=event.locale,
        ip_family=_address_view(event.ip_address),
        user_agent_present=bool(event.user_agent),
        timestamp=_plain(event.timestamp),
        additional_user_info=_plain(event.additional_user_info),
        credential=None if event.credential is None else sorted(_plain(event.credential)),
        email_type=_plain(event.email_type),
        sms_type=_plain(event.sms_type),
        uid=data.get("uid") if isinstance(data, dict) else None,
        data_names=sorted(data) if isinstance(data, dict) else None,
        data=data,
    )
    return None


_observe.__name__ = "pcblock_sdk"
# Kept in a dict so that the module has no second exported function: serving picks up module-level callables with an endpoint.
_HELD = {"sdk": identity_fn.before_user_created(region="us-central1")(_observe)}


def pcblock(request):
    """The SDK function, behind a line that records the request before the SDK reads it."""
    _emit("blocking-raw", request=_request_view(request))
    return _HELD["sdk"](request)


pcblock.__firebase_endpoint__ = dataclasses.replace(_HELD["sdk"].__firebase_endpoint__, entryPoint="pcblock")
_required = getattr(_HELD["sdk"], "__required_apis", None)
if _required is not None:
    setattr(pcblock, "__required_apis", _required)
