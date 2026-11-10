---
title: Firebase Hosting
description: Serve one Firebase Hosting site locally from firebase.json, with redirects, rewrites, headers, clean URLs, localization and rewrites to local functions.
---

Fireemu serves one Firebase Hosting site from the `hosting` entry of `firebase.json`: static files, redirects, rewrites, custom headers, clean URLs, trailing-slash handling and localized content. A rewrite can send a request to a function of a Functions codebase in the same run. Hosting is served **without a production parity claim**: the behaviour is compared offline with `firebase-tools` 15.28.2 on a finite set of cases, and production observations are still pending (see [Verification status](#verification-status)).

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

1. Requests for `/__/firebase/init.json` and `/__/firebase/init.js` are answered first: `init.json` holds the project ID and a non-secret local API key (`fireemu-local-only`), and `init.js?useEmulator=true` also points the Firebase SDKs at the emulators of this run (Authentication, Firestore, Functions, Storage and the Realtime Database, when they run). They take precedence over a catch-all redirect, as Firebase Hosting's published priority says; the official emulator applies redirects first.
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

Hosting behaves the same under `strict` and `emulator`, and `productionExact` changes nothing for it: there is no development default to turn off, and Hosting does not depend on the compatibility profile. See [Profiles and productionExact](../../guides/profiles/).

## Not supported

- More than one site: a `hosting` list, `site` and `target`. A list is refused with `hosting must be one site object; multiple sites are not implemented` when Hosting is named in `--only`.
- `hosting.source` (web frameworks) and any site without `public`.
- App Hosting. `--only apphosting` is refused as deferred; see [Limitations](../../compatibility/limitations/).
- Keys other than those in the table above are not acted on, for example `appAssociation`: Fireemu serves no `/.well-known/` association files for it, and a file you place in `public` is served like any other.
- The hosted SDK scripts under `/__/firebase/<version>/`, deployed Cloud Run services and deployed functions (no live fallback).
- A file with no extension, or an extension that `mime-types` does not know, is served as `application/octet-stream`. The `firebase-tools` emulator sends the literal text `false` as its `Content-Type` there, and production's behaviour was not recorded. The `Content-Type` of a custom header rule replaces the one Fireemu chooses.

## Changes in v0.47.0

These changes are in v0.47.0 and later; v0.45.0 and v0.46.0 behaved differently (see the [changelog](https://github.com/t-k/fireemu/blob/main/CHANGELOG.md)):

- An `i18n.root` written with a leading or trailing slash (`/locales`, the form Firebase's documentation shows) finds the same files as `locales`, and an empty root is no root, as in `superstatic`. Before, only a root without a leading slash worked.
- Content types come from the `mime-types`/`mime-db` table of the `firebase-tools` emulator (generated from it), with its `Vary: Accept-Encoding` rule. Before, a short built-in table served every other extension, such as `.woff2`, `.gif` or `.ico`, as `application/octet-stream` and `.js` as `text/javascript`.
- `ignore` patterns ignore case the way `firebase-tools` does on macOS and Windows (a JavaScript regular expression with the `i` flag, as the `glob` package compiles them); on Linux they stay case-sensitive.
- `headers`, `rewrites` and glob `redirects` sources treat a run of slashes as one, and a pattern also matches a path with one trailing slash, as the pinned `superstatic` does. A percent-encoded alias such as `/%64ata.json` still does not get a header rule, as in the pinned emulator.
- A rule whose `source` is empty matches nothing and falls through to its `regex`, as `superstatic` does.

## Verification status

The `HOSTING` area of the [compatibility tables](../../compatibility/#production-verification) is **In progress**: every condition is unverified because no production observation has been recorded yet. The offline conformance suite compares Fireemu with `firebase-tools` 15.28.2 on a finite corpus (static files, redirects, rewrites, glob matching, headers, clean URLs, trailing slashes, localization and ignore patterns), including over 3,000 generated rows of the real file listing used for `ignore`. It makes no production request. Where that corpus and production could differ, the compatibility tables and [Limitations](../../compatibility/limitations/) say so; treat a Hosting test that passes here as a check of your `firebase.json` and routing, not as proof of production behaviour.
