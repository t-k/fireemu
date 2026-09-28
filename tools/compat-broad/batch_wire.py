"""One bounded worker request. Secrets arrive on stdin, never command arguments."""

# ruff: noqa: BLE001 -- Worker errors never serialize request secrets.
import hashlib
import json
import math
import sys
import urllib.error
import urllib.request


def _decode_json_response(payload: bytes):
    """Decode one finite UTF-8 JSON value without silently replacing keys.

    A fully received HTTP body can still be unusable as typed API evidence.
    Keep this helper self-contained: this file is also a standalone worker
    (and the limits transport is included in the closed O8 archive).
    """
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON response key")
            result[key] = value
        return result

    def finite_float(value):
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError("non-finite JSON response number")
        return parsed

    def reject_constant(_value):
        raise ValueError("non-standard JSON response constant")

    return json.loads(
        payload.decode("utf-8"), object_pairs_hook=unique_object,
        parse_float=finite_float, parse_constant=reject_constant,
    )


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("redirect forbidden")


def _read_bounded_response(response, method):
    """Return decoded body bytes only with a checked HTTP message boundary.

    read(n) can return a short Content-Length body without IncompleteRead. JSON
    decoding that prefix does not establish HTTP completion (RFC 9112 section
    6.3). This observer accepts only one unambiguous length or the stdlib's
    supported chunked/close-delimited framing. Equal duplicate lengths are
    deliberately rejected rather than normalized by this closed transport.
    """
    payload = b""
    try:
        lengths = response.headers.get_all("Content-Length", [])
        codings = response.headers.get_all("Transfer-Encoding", [])
        if codings and (
            lengths or len(codings) != 1 or codings[0].lower() != "chunked"
        ):
            raise ValueError("unsupported or ambiguous response framing")
        expected = None
        if lengths:
            value = lengths[0].strip(" \t")
            if len(lengths) != 1 or not value or any(c not in "0123456789" for c in value):
                raise ValueError("invalid response length")
            expected = int(value)
        payload = response.read(65537)
        if len(payload) > 65536:
            return payload, "size-limit"
        if (
            expected is not None
            and method != "HEAD"
            and response.status != 304
            and len(payload) != expected
        ):
            return payload, "body-interrupted"
    except Exception as error:
        return getattr(error, "partial", payload)[:65537], "body-interrupted"
    return payload, None


def main():
    value = json.load(sys.stdin)
    body = value["body"]
    data = None if body is None else body.encode()
    request = urllib.request.Request(
        value["url"], data=data, headers=value["headers"], method=value["method"]
    )
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}))
    try:
        response = opener.open(request, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        status = response.status
        if not isinstance(status, int):
            raise TypeError("missing HTTP status")
        if value.get("receipt"):
            payload, failure = _read_bounded_response(response, value["method"])
            if 300 <= status < 400:
                failure = "redirect"
            complete = failure is None
            retained = payload[:65536]
            try:
                parsed = _decode_json_response(retained)
                kind = "json"
            except (ValueError, UnicodeDecodeError, RecursionError):
                parsed = None
                kind = "empty" if not retained else "non-json"
            content_type = response.headers.get("Content-Type", "")[:512]
            print(
                json.dumps(
                    {
                        "body": parsed,
                        "http": {
                            "contract": "bounded-http-v1",
                            "status": status,
                            "contentType": content_type,
                            "contentTypeTruncated": len(
                                response.headers.get("Content-Type", "")
                            )
                            > 512,
                            "bodyKind": kind,
                            "complete": complete,
                            "failure": failure,
                            "receivedBytes": len(payload),
                            "retainedBytes": len(retained),
                            "bodySha256": hashlib.sha256(retained).hexdigest(),
                            "digestScope": "full" if complete else "prefix",
                            "truncated": len(payload) > 65536,
                        },
                    }
                )
            )
            return
        payload, failure = _read_bounded_response(response, value["method"])
        if failure is not None or 300 <= status < 400:
            raise ValueError("incomplete, oversized or redirected response")
        try:
            parsed = _decode_json_response(payload)
        except (ValueError, UnicodeDecodeError, RecursionError):
            parsed = {"nonJson": payload[:1024].decode(errors="replace")}
        print(json.dumps([status, parsed, response.headers.get("Content-Type", "")]))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.exit(2)
