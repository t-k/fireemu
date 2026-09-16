"""Capture official sitemap/Discovery inventories without claiming semantic review.

Network acquisition is explicit. Check mode is offline and never changes snapshots.
Raw acquisition bytes remain in a caller-selected local cache; only indexes and digests
are published. A finite sitemap snapshot is not a guarantee that every official URL exists
in the sitemap, or that its content has been reviewed.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path

HOSTS = {
    "firebase.google.com",
    "docs.cloud.google.com",
    "cloud.google.com",
    "identitytoolkit.googleapis.com",
    "firestore.googleapis.com",
    "securetoken.googleapis.com",
}
SITEMAPS = [
    f"https://{host}/sitemap.xml"
    for host in ["firebase.google.com", "docs.cloud.google.com", "cloud.google.com"]
]
DISCOVERY = {
    "identitytoolkit-v1": "https://identitytoolkit.googleapis.com/$discovery/rest?version=v1",
    "identitytoolkit-v2": "https://identitytoolkit.googleapis.com/$discovery/rest?version=v2",
    "firestore-v1": "https://firestore.googleapis.com/$discovery/rest?version=v1",
    "securetoken-v1": "https://securetoken.googleapis.com/$discovery/rest?version=v1",
}
EXTRACTOR = "article-text-v1"
MAX_BYTES = 64 * 1024 * 1024


def now() -> str:
    return datetime.now(UTC).isoformat()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_url(url: str) -> str | None:
    if any(ord(c) < 33 or c in '<>[]()\\"|`' for c in url):
        return None
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc not in HOSTS:
        return None
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if set(query) - {"hl", "version"} or query.get("hl", ["en"]) != ["en"]:
        return None
    if "version" in query and (
        not parsed.hostname or not parsed.hostname.endswith("googleapis.com")
    ):
        return None
    host = (
        "docs.cloud.google.com"
        if parsed.netloc == "cloud.google.com"
        else parsed.netloc
    )
    return urllib.parse.urlunsplit(
        (
            "https",
            host,
            parsed.path.rstrip("/") or "/",
            urllib.parse.urlencode({"version": query["version"][0]})
            if "version" in query
            else "",
            "",
        )
    )


def in_scope(url: str) -> bool:
    parsed = urllib.parse.urlsplit(url)
    path = parsed.path.lower()
    if parsed.netloc == "firebase.google.com":
        if any(
            path == prefix or path.startswith(prefix + "/")
            for prefix in ["/docs/auth", "/docs/firestore", "/docs/rules"]
        ):
            return True
        if path.startswith("/docs/reference/"):
            return any(
                word in path
                for word in ["auth", "firestore", "securityrules", "security-rules"]
            )
        return path in [
            "/docs/emulator-suite/connect_auth",
            "/docs/emulator-suite/connect_firestore",
            "/support/release-notes/js",
            "/support/release-notes/admin/node",
            "/support/release-notes/android",
            "/support/release-notes/ios",
        ]
    return parsed.netloc == "docs.cloud.google.com" and (
        path.startswith(("/firestore/", "/identity-platform/"))
    )


def sitemap_entries(data: bytes) -> tuple[bool, list[str]]:
    root = ET.fromstring(data)
    kind = root.tag.rsplit("}", 1)[-1]
    if kind not in {"sitemapindex", "urlset"}:
        raise ValueError("not a sitemap")
    return kind == "sitemapindex", [
        node.text.strip()
        for node in root.iter()
        if node.tag.rsplit("}", 1)[-1] == "loc" and node.text
    ]


class Article(HTMLParser):
    """Retain article text, including tables, warnings and code, in encounter order."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.active = False
        self.ignored = 0
        self.parts: list[str] = []
        self.sections: list[str] = []
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "article":
            self.active = True
        if not self.active:
            return
        if tag in {"script", "style"}:
            self.ignored += 1
        if tag in {"h1", "h2", "h3", "h4", "p", "tr", "li", "pre", "br", "td", "th"}:
            self.parts.append("\n")
        if tag in {"h2", "h3", "h4"} and values.get("id"):
            self.sections.append(str(values["id"]))
        if tag == "a" and values.get("href"):
            self.links.append(str(values["href"]))

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"} and self.ignored:
            self.ignored -= 1
        if tag == "article":
            self.active = False
        if self.active and tag in {
            "h1",
            "h2",
            "h3",
            "h4",
            "p",
            "tr",
            "li",
            "pre",
            "td",
            "th",
        }:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self.active and not self.ignored:
            self.parts.append(data)


def extract_page(html: str) -> dict:
    parser = Article()
    parser.feed(html)
    text = "\n".join(
        line.rstrip() for line in "".join(parser.parts).splitlines() if line.strip()
    )
    if not text:
        raise ValueError("no article body; not counted as extracted")
    return {
        "text": text,
        "sections": list(dict.fromkeys(parser.sections)),
        "links": list(dict.fromkeys(parser.links)),
        "extractor": EXTRACTOR,
    }


def discovery_surfaces(document: dict) -> list[dict]:
    found: dict[tuple[str, str], dict] = {}

    def add(locator: str, kind: str) -> None:
        found[(locator, kind)] = {
            "locator": locator,
            "kind": kind,
            "transport": "REST",
            "classification": "unknown",
            "requirements": [],
        }

    def fields(value: dict, path: str) -> None:
        for name, field in value.get("properties", {}).items():
            locator = f"{path}/properties/{name}"
            add(locator, "field")
            fields(field, locator)
        for name in ["items", "additionalProperties"]:
            if isinstance(value.get(name), dict):
                add(f"{path}/{name}", "field")
                fields(value[name], f"{path}/{name}")
        for name in value.get("enum", []):
            add(f"{path}/enum/{name}", "enum")

    def resources(value: dict) -> None:
        for method in value.get("methods", {}).values():
            locator = method["id"]
            add(locator, "method")
            for role in ["request", "response"]:
                if role in method:
                    add(f"{locator}/{role}", role)
                    fields(method[role], f"{locator}/{role}")
            for name, param in method.get("parameters", {}).items():
                add(f"{locator}/parameters/{name}", "field")
                fields(param, f"{locator}/parameters/{name}")
        for child in value.get("resources", {}).values():
            resources(child)

    resources(document)
    for name, schema in document.get("schemas", {}).items():
        add(f"schemas/{name}", "schema")
        fields(schema, f"schemas/{name}")
    for name, parameter in document.get("parameters", {}).items():
        add(f"parameters/{name}", "field")
        fields(parameter, f"parameters/{name}")
    return [found[key] for key in sorted(found)]


class OfficialRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if canonical_url(newurl) is None:
            raise ValueError("redirect outside official acquisition allowlist")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def acquire(url: str, cache: Path) -> tuple[bytes, dict]:
    if canonical_url(url) is None:
        raise ValueError("URL outside official acquisition allowlist")
    key = digest(url.encode())
    raw = cache / f"{key}.body"
    metadata = cache / f"{key}.json"
    if raw.exists() and metadata.exists():
        data = raw.read_bytes()
        record = json.loads(metadata.read_text())
        if record["url"] != url or record["sha256"] != digest(data):
            raise ValueError("corrupt acquisition cache")
        return data, record
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "fireemu-compatibility-inventory/1.0",
            "Accept-Language": "en",
            "Accept-Encoding": "gzip",
        },
    )
    with urllib.request.build_opener(OfficialRedirect()).open(
        request, timeout=40
    ) as response:
        if response.headers.get("Content-Encoding", "").lower() == "gzip":
            with gzip.GzipFile(fileobj=response) as decoded:
                data = decoded.read(MAX_BYTES + 1)
        else:
            data = response.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError("response exceeds acquisition budget")
        record = {
            "url": url,
            "finalUrl": response.url,
            "fetchedAt": now(),
            "sha256": digest(data),
            "bytes": len(data),
        }
    raw.write_bytes(data)
    metadata.write_text(json.dumps(record, indent=2) + "\n")
    return data, record


def acquire_sitemap(url: str, cache: Path) -> tuple[dict, bool, list[str]]:
    # Futures retain their result until consumed; never retain every raw XML tree.
    data, record = acquire(url, cache)
    is_index, links = sitemap_entries(data)
    if is_index:
        if any(canonical_url(link) is None for link in links):
            raise ValueError("invalid sitemap child URL")
        return record, True, links
    selected = {canonical_url(link) for link in links}
    return record, False, sorted(link for link in selected if link and in_scope(link))


def capture(output: Path, cache: Path, seed: Path) -> None:
    if output.exists():
        raise ValueError(
            "snapshot already exists; record into a new candidate directory"
        )
    cache.mkdir(parents=True, exist_ok=True)
    records: list[dict] = []
    failures: list[dict] = []
    pages: dict[str, set[str]] = {}
    seen: set[str] = set()
    pending = set(SITEMAPS)
    with ThreadPoolExecutor(max_workers=4) as pool:
        while pending:
            urls = sorted(pending - seen)
            if not urls:
                break
            if len(seen) + len(urls) > 400:
                raise ValueError("sitemap expansion exceeds bounded inventory budget")
            seen.update(urls)
            pending = set()
            futures = {pool.submit(acquire_sitemap, url, cache): url for url in urls}
            for completed, future in enumerate(as_completed(futures), 1):
                url = futures.pop(future)
                try:
                    record, is_index, links = future.result()
                    records.append(record)
                    for link in links:
                        canonical = canonical_url(link)
                        if is_index:
                            if canonical is None:
                                raise ValueError("invalid sitemap child URL")
                            # Preserve sitemap host: cloud and docs.cloud publish different indexes.
                            pending.add(link)
                        elif canonical and in_scope(canonical):
                            pages.setdefault(canonical, set()).add(url)
                except (OSError, ValueError, ET.ParseError) as error:
                    failures.append(
                        {
                            "url": url,
                            "state": "unavailable",
                            "reason": type(error).__name__,
                            "httpStatus": error.code
                            if isinstance(error, urllib.error.HTTPError)
                            else None,
                        }
                    )
                if completed % 20 == 0:
                    print(
                        f"sitemaps: {completed}/{len(urls)} in batch; {len(pages)} canonical URLs",
                        flush=True,
                    )
            print(
                f"sitemaps: {len(seen)} attempted; {len(pages)} canonical in-scope URLs",
                flush=True,
            )
    definitions = []
    for name, url in DISCOVERY.items():
        try:
            raw, record = acquire(url, cache)
            document = json.loads(raw)
            definitions.append(
                {
                    "id": name,
                    "url": url,
                    "revision": document.get("revision"),
                    "sha256": record["sha256"],
                    "surfaces": discovery_surfaces(document),
                }
            )
            records.append(record)
        except (OSError, ValueError, KeyError) as error:
            failures.append(
                {"url": url, "state": "unavailable", "reason": type(error).__name__}
            )
    extracted = []
    for source in json.loads(seed.read_text())["sources"]:
        url = canonical_url(source["url"])
        if url is None or "googleapis.com" in url:
            continue
        if in_scope(url):
            pages.setdefault(url, set()).add("seed")
        try:
            raw, record = acquire(url, cache)
            article = extract_page(raw.decode("utf-8"))
            # The full body is kept only in the local cache for review, not republished.
            body = article.pop("text")
            (cache / f"{record['sha256']}.article.txt").write_text(body)
            links = [
                canonical_url(urllib.parse.urljoin(url, link))
                for link in article.pop("links")
            ]
            for link in links:
                if link and in_scope(link):
                    pages.setdefault(link, set()).add(url)
            extracted.append(
                {
                    "url": url,
                    "review": "extracted-unreviewed",
                    "bodySha256": digest(body.encode()),
                    **article,
                }
            )
            records.append(record)
        except (OSError, ValueError, UnicodeError) as error:
            failures.append(
                {"url": url, "state": "unavailable", "reason": type(error).__name__}
            )
    output.mkdir(parents=True)
    components = {
        "catalog.json": {
            "schemaVersion": 1,
            "capturedAt": now(),
            "scope": "Firebase Auth/Firestore/Rules guides and related SDK references; Cloud Firestore and Identity Platform; English canonical URLs in the captured sitemaps plus seed-page links",
            "status": "incomplete" if failures else "enumerated-sitemap-snapshot",
            "reviewed": 0,
            "pages": [
                {"url": url, "discoveredIn": sorted(origins), "review": "discovered"}
                for url, origins in sorted(pages.items())
            ],
            "failures": failures,
        },
        "discovery.json": {"schemaVersion": 1, "definitions": definitions},
        "extracted.json": {"schemaVersion": 1, "pages": extracted},
        "acquisitions.json": {
            "schemaVersion": 1,
            "requests": sorted(records, key=lambda r: r["url"]),
        },
    }
    manifest = {
        "schemaVersion": 1,
        "generator": "tools/compat-inventory/capture.py",
        "generatorSha256": digest(Path(__file__).read_bytes()),
        "files": {},
    }
    for name, value in components.items():
        data = (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()
        (output / name).write_bytes(data)
        manifest["files"][name] = digest(data)
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    check(output)
    print(
        json.dumps(
            {
                "pages": len(pages),
                "discoverySurfaces": sum(len(d["surfaces"]) for d in definitions),
                "extracted": len(extracted),
                "failures": len(failures),
            }
        )
    )


def check(directory: Path) -> None:
    manifest = json.loads((directory / "manifest.json").read_text())
    expected = {"catalog.json", "discovery.json", "extracted.json", "acquisitions.json"}
    if manifest.get("schemaVersion") != 1 or set(manifest.get("files", {})) != expected:
        raise ValueError("invalid snapshot manifest")
    for name in expected:
        if digest((directory / name).read_bytes()) != manifest["files"][name]:
            raise ValueError(f"snapshot drift: {name}")
    catalog = json.loads((directory / "catalog.json").read_text())
    urls = [row["url"] for row in catalog["pages"]]
    if (
        not urls
        or len(set(urls)) != len(urls)
        or any(canonical_url(url) != url or not in_scope(url) for url in urls)
    ):
        raise ValueError("invalid or duplicate catalog URL")
    if catalog["reviewed"] != 0 or any(
        row["review"] != "discovered" for row in catalog["pages"]
    ):
        raise ValueError("acquisition is not completed review")
    for definition in json.loads((directory / "discovery.json").read_text())[
        "definitions"
    ]:
        keys = [(row["locator"], row["kind"]) for row in definition["surfaces"]]
        if not keys or len(set(keys)) != len(keys):
            raise ValueError("empty or duplicate Discovery surfaces")
        if any(
            row["classification"] != "unknown" or row["requirements"]
            for row in definition["surfaces"]
        ):
            raise ValueError("extraction cannot silently create requirement mappings")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--cache", type=Path)
    parser.add_argument(
        "--seed", type=Path, default=Path("spec/compatibility/sources/index.json")
    )
    args = parser.parse_args()
    if args.check:
        check(args.check)
    elif args.output and args.cache:
        capture(args.output, args.cache, args.seed)
    else:
        parser.error("use --check or both --output and --cache")


if __name__ == "__main__":
    main()
