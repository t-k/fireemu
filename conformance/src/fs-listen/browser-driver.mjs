// The browser process of the L2 recording (FS-LISTEN-SDK): one headless Chromium that runs the SDK
// cases of packet L1 in the Web SDK 12.18.0 browser bundles, once for each transport mode in turn
// (a fresh context and a fresh run id per mode). Same protocol as sdk-driver.mjs.
//
//   env AFC_SDK_CONFIG  { mode: "production"|"local", wireCap, connectionCap, originPort,
//                         web: { apiKey, projectId, authDomain }, authEmulator?,
//                         firestoreEmulator?: { host, port } }
//   stdin, one line     { run, modes: ["long-polling", "streaming"], accounts: { a, b } }
//   stdout              JSON lines; the last is { event: "receipt", receipt: { modes: {...} } }
//
// The page lives at http://localhost:<originPort>/ and is answered here by the browser's request
// hook, not by a server: nothing listens. The origin is the one the API key is restricted to.
// Every other request of the page goes through the wire ledger: an allowed host (the three
// Google APIs in production, the emulator's host:port locally), a request cap per mode, and the
// SHA-256 of its bearer. The SDK bundles are the gstatic URLs of 12.18.0, answered from the
// pinned npm package, so nothing is fetched from a CDN. A request to anything else is aborted
// and the run ends.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

import { webChannelBearer } from "../auth-fs-cross/browser-driver.mjs";
import { createWireLedger, PRODUCTION_HOSTS } from "../auth-fs-cross/sdk-wire.mjs";
import { MODE_SETTINGS, modeRun } from "./browser-modes.mjs";
import { bandOf } from "./sdk-deps.mjs";
import { sdkCases } from "./sdk-cases.mjs";
import { DEADLINE_MS, CLEANUP_MS } from "./sdk-run.mjs";

const require = createRequire(import.meta.url);
const HERE = dirname(fileURLToPath(import.meta.url));
const FIREBASE = dirname(require.resolve("firebase/package.json"));
const VERSION = JSON.parse(readFileSync(join(FIREBASE, "package.json"), "utf8")).version;
const GSTATIC = `https://www.gstatic.com/firebasejs/${VERSION}/`;
const COLLECTOR = join(HERE, "../../../tools/compat-broad/fs-listen-resume/listen_collector.mjs");
const SHA256_SHIM = join(HERE, "../../../tools/sdk-smoke/web/listen-catalog-sha256.js");
/** The bundles the page may load, by file name. */
export const BUNDLES = ["firebase-app.js", "firebase-auth.js", "firebase-firestore.js"];

const sha256 = (data) => createHash("sha256").update(data).digest("hex");
const emit = (event) => process.stdout.write(`${JSON.stringify(event)}\n`);

/** The origin the page is served from and the key is restricted to. */
export const originOf = (port) => `http://localhost:${port}`;

/** The hosts (with ports) the page may reach beyond its own origin. */
export function allowedHosts(config) {
  if (config.mode !== "local") return PRODUCTION_HOSTS;
  const { host, port } = config.firestoreEmulator;
  return [new URL(config.authEmulator).host, `${host}:${port}`];
}

const PAGE = `<!doctype html><meta charset="utf-8"><title>listen</title>
<script type="importmap">{"imports":{"node:crypto":"/lib/sha256.js"}}</script>
<script type="module" src="/lib/browser-page.mjs"></script>`;

/** The files the page may load, by path. */
export const FILES = {
  "/": { type: "text/html", body: PAGE },
  "/lib/sha256.js": { type: "text/javascript", file: SHA256_SHIM },
  "/lib/collector/listen_collector.mjs": { type: "text/javascript", file: COLLECTOR },
  ...Object.fromEntries(
    [
      "browser-page.mjs",
      "browser-modes.mjs",
      "sdk-run.mjs",
      "sdk-deps-core.mjs",
      "sdk-deps-browser.mjs",
    ].map((name) => [`/lib/${name}`, { type: "text/javascript", file: join(HERE, name) }]),
  ),
};

/**
 * Chromium's arguments. A page answered by the request hook is not in the loopback address space,
 * so Chromium would refuse its requests to the emulator on 127.0.0.1 (local network access); a
 * local run switches that check off. A production run does not: its page only reaches the Google
 * hosts.
 */
export function browserArgs(config) {
  return config.mode === "local"
    ? ["--disable-features=LocalNetworkAccessChecks,BlockInsecurePrivateNetworkRequests"]
    : [];
}

/** What one Listen channel request says about the transport: its `CI` parameter. */
export function listenChannelCi(url) {
  const parsed = new URL(url);
  if (!parsed.pathname.includes("/google.firestore.v1.Firestore/Listen/channel")) return null;
  return parsed.searchParams.get("CI") ?? "none";
}

async function runMode({ browser, config, run, mode, accounts, cases }) {
  const origin = originOf(config.originPort);
  const context = await browser.newContext();
  const page = await context.newPage();
  const ci = {};
  let listenChannel = 0;
  const ledger = createWireLedger({
    // The first refusal is reported once, then the run ends: a page would retry at once.
    onRefuse: ({ host, path, reason }) => {
      emit({ event: "wire-refused", mode, host, path, reason });
      setImmediate(() => process.exit(3));
    },
    hosts: allowedHosts(config),
    cap: config.wireCap ?? 100,
    connectionCap: config.connectionCap ?? 20,
    onConnection: ({ n, host }) => emit({ event: "connection", mode, n, host }),
    onRecord: ({ n, host, path }) => emit({ event: "wire", mode, n, host, path }),
  });
  try {
    // Each distinct network connection a response came over counts once.
    const cdp = await context.newCDPSession(page);
    await cdp.send("Network.enable");
    const connectionIds = new Set();
    cdp.on("Network.responseReceived", ({ response }) => {
      if (response.url.startsWith(`${origin}/`) || response.url.startsWith(GSTATIC)) return;
      const id = response.connectionId;
      if (!id || connectionIds.has(id)) return;
      connectionIds.add(id);
      try {
        ledger.connection(new URL(response.url).host);
      } catch {
        // The ledger reported the refusal and ends the run.
      }
    });
    await page.route("**/*", async (route) => {
      const request = route.request();
      const url = request.url();
      if (url.startsWith(`${origin}/`)) {
        const entry = FILES[new URL(url).pathname];
        if (!entry || request.method() !== "GET") return route.fulfill({ status: 404, body: "" });
        return route.fulfill({
          status: 200,
          contentType: entry.type,
          headers: { "cache-control": "no-store" },
          body: entry.body ?? readFileSync(entry.file),
        });
      }
      if (url.startsWith(GSTATIC)) {
        const file = url.slice(GSTATIC.length);
        if (!BUNDLES.includes(file)) {
          try {
            ledger.admit("www.gstatic.com", `/${file}`);
          } catch {
            return route.abort("blockedbyclient");
          }
        }
        return route.fulfill({
          status: 200,
          contentType: "text/javascript",
          body: readFileSync(join(FIREBASE, file)),
        });
      }
      const parsed = new URL(url);
      const headers = request.headers();
      try {
        ledger.admit(
          parsed.host,
          parsed.pathname,
          headers.authorization ?? webChannelBearer(url, request.postData()) ?? undefined,
        );
      } catch {
        return route.abort("blockedbyclient");
      }
      const value = listenChannelCi(url);
      if (value !== null) {
        listenChannel += 1;
        ci[value] = (ci[value] ?? 0) + 1;
      }
      return route.continue();
    });
    page.on("requestfailed", (request) => {
      const parsed = new URL(request.url());
      emit({
        event: "request-failed",
        mode,
        host: parsed.host,
        path: parsed.pathname,
        reason: request.failure()?.errorText ?? "unknown",
      });
    });
    page.on("console", (message) => {
      if (message.type() === "error")
        emit({ event: "page-error", mode, message: message.text().slice(0, 300) });
    });
    page.on("pageerror", (error) =>
      emit({ event: "page-error", mode, message: String(error.message) }),
    );
    await page.goto(`${origin}/`);
    await page.waitForSelector("body[data-ready=true]", { state: "attached", timeout: 30_000 });
    const modeRunId = modeRun(run, mode);
    const input = {
      mode,
      run: modeRunId,
      base: bandOf(modeRunId),
      accounts,
      cases,
      web: config.web,
      local: config.mode === "local",
      authEmulator: config.authEmulator,
      firestoreEmulator: config.firestoreEmulator,
    };
    const receipt = await Promise.race([
      page.evaluate((value) => window.listenRun(value), input),
      new Promise((_, reject) =>
        setTimeout(
          () => reject(new Error("browser run exceeded its deadline")),
          DEADLINE_MS + CLEANUP_MS + 60_000,
        ).unref(),
      ),
    ]);
    return {
      mode,
      run: modeRunId,
      receipt,
      transport: {
        requests: ledger.records.length,
        listenChannel,
        ci,
        connections: ledger.connections(),
      },
    };
  } finally {
    await context.close().catch(() => {});
  }
}

async function main() {
  const config = JSON.parse(process.env.AFC_SDK_CONFIG);
  if (!Number.isInteger(config.originPort) || config.originPort < 1)
    throw new Error("originPort is required");
  const { run, modes, accounts } = await new Promise((resolve) =>
    createInterface({ input: process.stdin }).once("line", (line) => resolve(JSON.parse(line))),
  );
  for (const mode of modes) if (!MODE_SETTINGS[mode]) throw new Error(`unknown mode ${mode}`);
  const cases = sdkCases();
  const browser = await chromium.launch({ headless: true, args: browserArgs(config) });
  const results = {};
  try {
    for (const mode of modes) {
      try {
        results[mode] = await runMode({ browser, config, run, mode, accounts, cases });
      } catch (error) {
        results[mode] = { mode, run: modeRun(run, mode), error: String(error?.message ?? error) };
      }
    }
  } finally {
    await browser.close().catch(() => {});
  }
  emit({
    event: "receipt",
    receipt: {
      sdkVersion: VERSION,
      bundles: BUNDLES.map((file) => [file, sha256(readFileSync(join(FIREBASE, file)))]),
      modes: results,
    },
  });
  setTimeout(() => process.exit(0), 50);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    emit({ event: "driver-error", message: String(error?.message ?? error) });
    setTimeout(() => process.exit(1), 50);
  });
}
