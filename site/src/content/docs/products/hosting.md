---
title: Firebase Hosting
description: Serve one Firebase Hosting site locally from firebase.json, with redirects, rewrites, headers, clean URLs, localization and rewrites to local functions.
---

Fireemu serves one Firebase Hosting site from the `hosting` entry of `firebase.json`: static files, redirects, rewrites, custom headers, clean URLs, trailing-slash handling and localized content. A rewrite can send a request to a function of a Functions codebase in the same run. Hosting is served **without a completed production parity claim**: the `emulator` profile is compared offline with `firebase-tools` 15.28.2 on a finite set of cases, and the `strict` profile is compared with two production recordings whose review is pending (see [Profiles](#profiles) and [Verification status](#verification-status)).

Hosting is available since v0.45.0. Behaviour that changed in a later release is listed under [Changes in v0.47.0](#changes-in-v0470) below.

## Start Hosting

Hosting starts when `firebase.json` has a `hosting` object with a `public` directory. No other setting is needed:

```json
{
  "hosting": {
    "public": "public"
  }
}
```

```sh
npx fireemu up
```

- The default port is 5000. If the port is busy and you did not configure one, Fireemu searches upward and never takes 5001, as `firebase-tools` does. A port you set is never moved. Set it with `emulators.hosting.port` in `firebase.json`, `daemon.hostingPort` in a Fireemu configuration file, or `--hosting-port`.
- The Emulator Hub lists the bound address under `hosting` (`GET /emulators` on the Hub).
- `--only` selects services as for the other products: `--only hosting` serves only Hosting and refuses to start when there is no `hosting.public`. A run that does not name Hosting keeps starting when its `hosting` entry is one Fireemu cannot serve (for example a list of sites), notes the entry and does not start Hosting; add `hosting` to `--only` to make that an error.
- `hosting.public` is resolved from the directory of `firebase.json`. A missing directory is not an error, as in `firebase-tools`: the site starts and answers 404.

## What `firebase.json` can set

These keys of the `hosting` object are honored:

| Key | Behaviour |
|---|---|
| `public` | The directory served. Required. Files are opened through a retained handle to that directory; a symbolic link that leaves it, a nonregular file and a request path with a backslash, a colon or `..` are refused (answered as not found). |
| `ignore` | Glob patterns of files that are absent on every route, matched the way `firebase-tools` matches them when it chooses the files to deploy. `**/firebase-debug.log`, `**/firebase-debug.*.log` and `.firebase/*` are always ignored, because `firebase deploy` never uploads them. |
| `redirects` | Checked in order before any file is served. A rule has `source`, `glob` or `regex`, a `destination` and a `type` (default 301). `:name` captures in a `source` fill the same names in the `destination`. The query string is kept. |
| `rewrites` | Used when no file matches. `source`, `glob` or `regex` choose the request; the target is a `destination` file, a `function`, or a `run` service (see [Rewrites to functions](#rewrites-to-functions)). The first matching rule wins. |
| `headers` | Rules with `source`, `glob` or `regex` and a `headers` list of `key` and `value`. They are added to responses for files and rewrites. |
| `cleanUrls` | `/about.html` redirects (301) to `/about`, and `/about` serves `about.html`. |
| `trailingSlash` | `true` adds a trailing slash to directory URLs, `false` removes it (301), and unset leaves a directory URL without a slash redirecting to the one with it unless `cleanUrls` is on. |
| `i18n` | `{ "root": "/locales" }` (any spelling of the slashes: `locales`, `/locales/`) serves `locales/<language>_<country>/…`, `locales/ALL_<country>/…`, `locales/<language>_ALL/…` and `locales/<language>/…` before the plain path, chosen from `Accept-Language` and the `X-Country-Code` header, or from the `firebase-language-override` and `firebase-country-override` cookies. |

Behaviour of a request, in order:

1. Requests for `/__/firebase/init.json` and `/__/firebase/init.js` are answered first: `init.json` holds the project ID and a non-secret local API key (`fireemu-local-only`), and `init.js?useEmulator=true` also points the Firebase SDKs at the emulators of this run (Authentication, Firestore, Functions, Storage and the Realtime Database, when they run). Under `emulator` they take precedence over a catch-all redirect; under `strict` they are answered after the redirects, as production answered (see [Profiles](#profiles)).
2. A matching entry of `redirects` answers with its status and a `Location`.
3. A file is served when one matches, including `index.html` for a directory; `HEAD` is answered with the headers only. Responses carry `ETag`, `Last-Modified` and `Content-Length`, and the body is streamed from the open file. The `Content-Type` comes from the extension (compared without regard to case) in the table of `mime-types` 2.1.35 over `mime-db` 1.52.0, which is what the `firebase-tools` emulator uses, including its charsets (`application/javascript; charset=utf-8`, `text/css; charset=utf-8`, `image/svg+xml` without one). A compressible type also gets `Vary: Accept-Encoding`, as the emulator's compression does.
4. A matching entry of `rewrites` answers: a `destination` file is served with 200 (a rewrite to `/404.html` answers 404), and a `function` or `run` rule is forwarded to the local Functions runtime.
5. Otherwise `404.html` from the public directory is served with status 404 or, without one, a built-in "Cannot GET" page.

`/__/firebase/<version>/<file>` (the hosted Firebase SDK scripts) is answered with 503, because Fireemu never downloads them: use a bundled SDK or a copy you serve yourself.

## Rewrites to functions

A rewrite with a `function` or `run` target is forwarded to the Functions emulator of the same run, which must have a codebase loaded:

```json
{
  "hosting": {
    "public": "public",
    "rewrites": [
      { "source": "/api/**", "function": "api" },
      { "source": "/images/**", "function": { "functionId": "resize", "region": "europe-west1" } },
      { "source": "/service/**", "run": { "serviceId": "api", "region": "us-central1" } },
      { "source": "**", "destination": "/index.html" }
    ]
  }
}
```

- The function ID is the string after `function`, its `functionId`, or the `serviceId` of `run`. The region is the target's `region`, else the rule's, else `us-central1`.
- A `run` rewrite goes to the local function with the same ID as the Cloud Run service; Fireemu never looks up a Cloud Run service.
- The request keeps its method, path, query and headers; the body is limited to 32 MiB. Fireemu adds `x-original-url` and `x-forwarded-host`. A response without `Cache-Control` gets `private`, and `Vary` is set to `Accept-Encoding, Authorization, Cookie`.
- Without a loaded Functions codebase the rewrite answers 503, and an upstream that cannot be reached answers 502. There is no fallback to a deployed function.

## Profiles

Hosting answers differently under the two compatibility profiles, and `productionExact` changes nothing for it. The `emulator` profile answers as the `firebase-tools` 15.28.2 emulator does. The `strict` profile, the default, answers as Firebase Hosting answered the 201 requests of the production corpus (two recordings on disposable preview channels, listed in [Verification status](#verification-status)). Where `strict` differs from the `emulator` profile:

| Area | `strict` | `emulator` |
|---|---|---|
| Response headers | Files carry `Cache-Control: max-age=3600` (unless a `headers` rule sets one), `Accept-Ranges: bytes`, `Vary: x-fh-requested-host, accept-encoding` and a quoted SHA-256 `ETag`. The `Vary` of an `i18n` site's files begins with `accept-language, x-country-code`. Redirects carry the headers your rules set. | `ETag` and `Last-Modified` only, and `Vary: Accept-Encoding` for compressible types. |
| `Content-Type` | JSON types without a charset (`application/json`, `application/manifest+json`), `.js` and `.mjs` as `text/javascript; charset=utf-8`, `.ico` as `image/x-icon`, an unknown extension or none as `text/plain; charset=utf-8`. | The `mime-types` table of the emulator; an unknown extension is `application/octet-stream`. |
| Conditional and range requests | `If-None-Match` and `If-Modified-Since` answer 304 (with the `Cache-Control` of the file only); a single `Range` answers 206 with `Content-Range`. `OPTIONS` on a file answers an empty 200 with `Allow: GET, HEAD, OPTIONS`. | The whole file. |
| `/404.html` | A request for `/404.html` serves the file with 200; any other missing path serves it with 404. | Both answer 404. |
| Redirects | The body is `text/plain`. Each captured path part is percent-decoded before it is put in the `Location` (`%2f` becomes `/`, then runs of slashes fold), and the query string is appended as sent. A parameter name is letters and `_`: `:id2` is the parameter `id` followed by a `2`. | `text/html` body, captured parts stay encoded (`%2f` becomes `%252f`), the query is re-encoded, and `:id2` is a parameter name. |
| Reserved paths | `/__/auth/handler` answers 200 outside the redirects; `/__/firebase/init.json` and `init.js` are subject to them, and are cacheable files (`ETag`, `Last-Modified`, the headers your rules set). | `init.json` and `init.js` come before the redirects; `/__/auth/handler` is not served. |
| `appAssociation: "AUTO"` | `/.well-known/assetlinks.json` and `/.well-known/apple-app-site-association` are generated (`[]` and an empty `applinks` document). | Not served. |
| `i18n` | The country comes from the request's origin in production, so the `X-Country-Code` header and the `firebase-country-override` cookie are **ignored**; `Accept-Language` is read with its quality values (`de;q=0.9, fr;q=0.8` finds `fr` when there is no `de`); the `firebase-language-override` cookie is honored. | The country header and cookie are honored; quality values are not read. |
| Globs of `headers`, `rewrites` and `redirects` | A dot file matches `*` and `**`, and the empty part after a trailing slash matches `*` and the patterns that can match nothing. | Dot files and the empty part do not match, as in the pinned `superstatic`. |
| Malformed percent escape | `400` with the plain text `400 Bad Request`, sent chunked. | `400` with `Malformed URL`. |

Known differences that `strict` does not reproduce are listed in the [closure record](https://github.com/fireemu/fireemu/blob/main/conformance/src/hosting-production/known-differences.json): gzip and Brotli content encoding, the body of production's own 404 page (a longer HTML page), the hosted SDK files under `/__/firebase/<version>/`, the `init.json` keys beyond `apiKey` and `projectId`, the `Strict-Transport-Security` header of https and the preview channel's `X-Robots-Tag`, and production's 302 to an internal origin for a request for a parent directory (`strict` refuses with 404 and never leaves `public`).

## Not supported

- More than one site: a `hosting` list, `site` and `target`. A list is refused with `hosting must be one site object; multiple sites are not implemented` when Hosting is named in `--only`.
- `hosting.source` (web frameworks) and any site without `public`.
- App Hosting. `--only apphosting` is refused as deferred; see [Limitations](../../compatibility/limitations/).
- Keys other than those in the table above are not acted on. `appAssociation: "AUTO"` generates the two association documents under `strict` only; a file you place in `public` is served like any other.
- The hosted SDK scripts under `/__/firebase/<version>/`, deployed Cloud Run services and deployed functions (no live fallback).
- A file with no extension, or an extension that `mime-types` does not know, is served as `application/octet-stream`. The `firebase-tools` emulator sends the literal text `false` as its `Content-Type` there, and production's behaviour was not recorded. The `Content-Type` of a custom header rule replaces the one Fireemu chooses.

## Changes in v0.47.0

These changes are in v0.47.0 and later; v0.45.0 and v0.46.0 behaved differently (see the [changelog](https://github.com/fireemu/fireemu/blob/main/CHANGELOG.md)):

- An `i18n.root` written with a leading or trailing slash (`/locales`, the form Firebase's documentation shows) finds the same files as `locales`, and an empty root is no root, as in `superstatic`. Before, only a root without a leading slash worked.
- Content types come from the `mime-types`/`mime-db` table of the `firebase-tools` emulator (generated from it), with its `Vary: Accept-Encoding` rule. Before, a short built-in table served every other extension, such as `.woff2`, `.gif` or `.ico`, as `application/octet-stream` and `.js` as `text/javascript`.
- `ignore` patterns ignore case the way `firebase-tools` does on macOS and Windows (a JavaScript regular expression with the `i` flag, as the `glob` package compiles them); on Linux they stay case-sensitive.
- `headers`, `rewrites` and glob `redirects` sources treat a run of slashes as one, and a pattern also matches a path with one trailing slash, as the pinned `superstatic` does. A percent-encoded alias such as `/%64ata.json` still does not get a header rule, as in the pinned emulator.
- A rule whose `source` is empty matches nothing and falls through to its `regex`, as `superstatic` does.

## Verification status

The `HOSTING` area of the [compatibility tables](../../compatibility/#production-verification) is **In progress**: production was observed twice with the same 201 requests (static files, redirects, rewrites, glob matching, headers and caching, clean URLs, trailing slashes, localization, reserved paths, content types, compression, app association), on preview channels of a disposable site, never on a live channel. The two recordings agree with each other on every request except a production-internal redirect host, and the `strict` profile agrees with both on every request except the known differences above; the review that promotes the area has not run. `emulator` makes no production claim. The offline conformance suite still compares Fireemu with `firebase-tools` 15.28.2 on a finite corpus, including over 3,000 generated rows of the real file listing used for `ignore`. Treat a Hosting test that passes here as a check of your `firebase.json` and routing: preview channel answers are not the live channel's.
