"""One bounded worker request. Secrets arrive on stdin, never command arguments."""

# ruff: noqa: BLE001 -- Worker errors never serialize request secrets.
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
