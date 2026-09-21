# fireemu-sdk-smoke-browser

Automated real-browser execution of the pages under `tools/sdk-smoke/web/`.
Those pages import the browser build of the pinned firebase JS SDK
(`https://www.gstatic.com/firebasejs/12.18.0/`), whose Firestore transport is
WebChannel, so this is the only lane in the repository where WebChannel framing,
long polling and the streamed backchannel are actually exercised. Node runs of
the same SDK use gRPC and say nothing about this path.

Everything runs against an owned `fireemu exec` child on OS-assigned loopback
ports. No script here has a production mode.

## Why a separate package

`tools/sdk-smoke/package-lock.json` is a bound input of the Listen campaign
record (`campaign.py` publishes its digest, and the Node local shadow binds
`campaign.py`). Adding Playwright there would force the campaign record and the
Node shadow to be regenerated for a devDependency that the Node lane never
executes. This package owns its own lockfile instead; it pins only `playwright`.

The firebase SDK itself is not an npm dependency here: the pages load the
official browser bundles from gstatic, exactly as a deployed web application
does, and `sdk-pins.test.mjs` in `tools/sdk-smoke` already asserts that every
page imports release `12.18.0`. Each receipt records the SHA-256 of the three
bundles the browser actually executed and the `SDK_VERSION` the bundle reports,
so the executed code is bound even though it is not vendored. The runs need
network access to gstatic and nothing else outside loopback.

## Setup

```sh
cd tools/sdk-smoke-browser
npm ci
npx playwright install chromium   # only if the Chromium revision is missing
```

Playwright's browser cache (`~/Library/Caches/ms-playwright` on macOS,
`~/.cache/ms-playwright` on Linux) is shared with `ui/`, which pins the same
Playwright release, so a checkout that already runs the UI end-to-end tests has
the browser.

## Smoke pages: `run-browser.mjs`

Drives `listener-lifecycle.html` and then `listen-reconnect.html` (the latter
installs its own rules through the control route, so it runs last) and prints
one JSON document with each page's verdict, its result object and the
WebChannel request log the browser saw.

```sh
cargo build -p fireemu
target/debug/fireemu exec \
  --firebase-json tools/sdk-smoke/listener-lifecycle.firebase.json \
  --project demo-app --only firestore,auth \
  --firestore-port 0 --http-port 0 --hub-port 0 --ui-port 0 --logging-port 0 \
  --log-verbosity silent -- \
  node tools/sdk-smoke-browser/run-browser.mjs --output smoke-pages.json
```

The checked-in result is `spec/compatibility/fs-listen-sdk-browser-smoke-pages.json`.

The child-scoped control token (`FIREEMU_CONTROL_TOKEN`) never enters a page
URL. The listen-reconnect page needs one privileged operation, installing its
ruleset, so the runner exposes a one-shot `__fireemuInstallRules(source)`
binding, performs the `PUT /v1/rules` itself with the bearer token and hands
the page back `{ ok, status }` only. (Opened by hand without the runner, the
page still accepts `?token=` as `tools/sdk-smoke/README.md` describes.) Every
error that could reach stderr, `pageErrors` or the receipt passes through
`safeText`, which replaces the token and every URL query string, because
Playwright quotes the navigation URL in its failure diagnostics.
`run-browser.test.mjs` forces both a navigation failure and a page error with
a dummy token, in-process and as a child process, and asserts the token is
absent from stdout, stderr and the receipt.

## Listen catalog: `listen_browser_adapter.mjs`

`tools/compat-broad/fs-listen-resume/listen_browser_adapter.mjs` runs the
fourteen frozen `FS-LISTEN-SDK` cases through `web/listen-catalog.html`. The
page loads `listen_collector.mjs` byte-identical from the lane directory (the
static server mounts it under `/collector/`; an import map supplies a browser
SHA-256 for the collector's single `node:crypto` import), so the normalised
event rows have the same shape as the Node receipt by construction. The adapter
runs the catalog twice, one throwaway account each:

- `long-polling`: `experimentalForceLongPolling: true`; every backchannel
  response closes immediately (`CI=1`).
- `streaming`: auto-detection off, long polling off; one chunked backchannel
  per session stays open (`CI=0`).

```sh
O6_REPO_ROOT="$PWD" \
  O6_LISTEN_CAMPAIGN_PATH="$PWD/spec/compatibility/fs-listen-sdk-browser-local-shadow-campaign.json" \
  O6_LISTEN_SDK_VERSION=12.18.0 GOOGLE_CLOUD_PROJECT=demo-o6 \
  O6_LISTEN_FIREEMU_BINARY="$PWD/target/debug/fireemu" \
  O6_LISTEN_FIREEMU_COMMIT="$(git rev-parse HEAD)" O6_LISTEN_SOURCE_COMMIT="$(git rev-parse HEAD)" \
  O6_LISTEN_RULES_PATH="$PWD/tools/compat-broad/fs-listen-resume/fs-listen-sdk.rules" \
  target/debug/fireemu exec \
  --firebase-json tools/compat-broad/fs-listen-resume/fs-listen-sdk.firebase.json \
  --project demo-o6 --only firestore,auth \
  --firestore-port 0 --http-port 0 --hub-port 0 --ui-port 0 --logging-port 0 \
  --log-verbosity silent -- \
  node tools/compat-broad/fs-listen-resume/listen_browser_adapter.mjs > browser-shadow.json
```

`O6_LISTEN_BROWSER_MODES` selects a subset of the modes; `O6_LISTEN_JOURNAL_DIR`
(single mode only) writes the same responsibility journal as the Node adapter.
The checked-in result is `spec/compatibility/fs-listen-sdk-browser-local-shadow.json`,
bound by `test_o6_listen_sdk_browser_local_shadow.py`. Each per-mode receipt
inside it passes `local_shadow_check.mjs` unchanged.

## Static server boundary

`browser_harness.mjs` serves the mounted directories on 127.0.0.1 read-only.
A request passes two gates: the decoded path may not contain `.`/`..`
segments or a backslash and must resolve lexically under its mount, and the
real path of the target (every symlink followed, including intermediate
directories) must stay under the real path of the mount root fixed at start.
The file is then opened by that real path with `O_NOFOLLOW`, so the path
that was checked is the path that is read; a symlink out of the mount is a
bodiless 404. `run-browser.test.mjs` covers file and directory escapes, a
mount root that is itself a symlink and the in-mount positive controls.

## Process hygiene

Both runners own their Chromium and their static server and close them in a
`finally` on every exit path; the emulator is owned by the enclosing
`fireemu exec`, which exits when the runner does. `run-browser.test.mjs` launches
a marked Chromium through the harness and asserts with `pgrep` that nothing
survives `close()`.

## Tests

```sh
cd tools/sdk-smoke-browser && npm test
node --test tools/compat-broad/fs-listen-resume/listen_browser_adapter.test.mjs
```
