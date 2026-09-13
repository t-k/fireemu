"""One bounded worker request. Secrets arrive on stdin, never command arguments."""

# ruff: noqa: BLE001 -- Worker errors never serialize request secrets.
import hashlib
import json
import sys
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("redirect forbidden")


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
            payload = b""
            failure = None
            try:
                payload = response.read(65537)
                if len(payload) > 65536:
                    failure = "size-limit"
                length = response.headers.get("Content-Length")
                if (
                    length is not None
                    and len(payload) != int(length)
                    and failure is None
                ):
                    failure = "body-interrupted"
            except Exception as error:
                payload = getattr(error, "partial", b"")[:65537]
                failure = "body-interrupted"
            if 300 <= status < 400:
                failure = "redirect"
            complete = failure is None
            retained = payload[:65536]
            try:
                parsed = json.loads(retained)
                kind = "json"
            except (ValueError, UnicodeDecodeError):
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
        payload = response.read(65537)
        if len(payload) > 65536 or 300 <= status < 400:
            raise ValueError("oversized or redirected response")
        try:
            parsed = json.loads(payload)
        except (ValueError, UnicodeDecodeError):
            parsed = {"nonJson": payload[:1024].decode(errors="replace")}
        print(json.dumps([status, parsed, response.headers.get("Content-Type", "")]))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.exit(2)
