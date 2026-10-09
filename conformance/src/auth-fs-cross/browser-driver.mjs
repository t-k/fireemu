// One Web SDK 12.18.0 client in headless Chromium (AUTH-FS-CROSS stage 2, the two conditions X3
// requires a real browser for). Same protocol as sdk-driver.mjs: one JSON command per line on
// stdin, one JSON event per line on stdout, secrets on stdin or in the environment, never argv.
//
// The page is served from 127.0.0.1 by this process. Its SDK bundles are the gstatic URLs of
// 12.18.0, answered here from the pinned npm package, so nothing is fetched from a CDN. Every
// other request of the page goes through the wire ledger: an allowed host (the three Google APIs
// in production, the emulator's host:port locally), a request cap, and the SHA-256 of its
// bearer, taken from the Authorization header or from WebChannel's `$httpHeaders` parameter.
// Anything else is aborted and reported.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

import {
  createWireLedger,
  createS5bAdmission,
  PRODUCTION_HOSTS,
  transactionMethod,
  transactionWireEvidence,
  TRANSACTION_BODY_LIMIT,
} from "./sdk-wire.mjs";

const require = createRequire(import.meta.url);
const HERE = dirname(fileURLToPath(import.meta.url));
const FIREBASE = dirname(require.resolve("firebase/package.json"));
const VERSION = JSON.parse(readFileSync(join(FIREBASE, "package.json"), "utf8")).version;
const GSTATIC = `https://www.gstatic.com/firebasejs/${VERSION}/`;
/** The bundles the page may load, by file name. */
export const BUNDLES = ["firebase-app.js", "firebase-auth.js", "firebase-firestore.js"];

const sha256 = (text) => createHash("sha256").update(text).digest("hex");
const emit = (event) => process.stdout.write(`${JSON.stringify(event)}\n`);

/** The Authorization value in an encoded header block (`Name:value` lines), if any. */
function authorizationIn(block) {
  const line = String(block)
    .split(/\r?\n/)
    .find((l) => /^authorization:/i.test(l));
  return line ? line.slice(line.indexOf(":") + 1).trim() : null;
}

/**
 * The bearer a WebChannel request carries: in its `$httpHeaders` URL parameter, or, as the SDK
 * opens its channels (`encodeInitMessageHeaders`), in a parameter of its form-encoded body.
 */
export function webChannelBearer(url, body = null) {
  const inUrl = new URL(url).searchParams.get("$httpHeaders");
  if (inUrl) return authorizationIn(inUrl);
  if (!body) return null;
  for (const [, value] of new URLSearchParams(body)) {
    const found = authorizationIn(value);
    if (found) return found;
  }
  return null;
}

/** The hosts (with ports) the page may reach beyond its own server. */
export function allowedHosts(config) {
  if (config.s5bAdmission !== undefined) return ["firestore.googleapis.com"];
  if (config.mode !== "local") return PRODUCTION_HOSTS;
  const { host, port } = config.firestoreEmulator;
  return [new URL(config.authEmulator).host, `${host}:${port}`];
}

const PAGE = `<!doctype html><meta charset="utf-8"><title>afc</title><script type="module" src="/browser-page.mjs"></script>`;
const FILES = {
  "/": { type: "text/html", body: PAGE },
  "/browser-page.mjs": { type: "text/javascript", file: join(HERE, "browser-page.mjs") },
  "/sdk-operations.mjs": { type: "text/javascript", file: join(HERE, "sdk-operations.mjs") },
};

async function main() {
  const config = JSON.parse(process.env.AFC_SDK_CONFIG);
  const tokenOwner = new Map();
  const admission = config.s5bAdmission === undefined ? null : createS5bAdmission(config, emit);
  const capture = (config.mode === "local" || admission) && config.transactionCapture === true;
  if (admission && !capture) throw new Error("S5b production capture is required");
  const capturedRequests = new Map();
  const pendingCapture = new Set();
  // Replaced once the browser is up; before that there is nothing to close but the process.
  let close = async (code) => process.exit(code);
  const ledger = createWireLedger({
    // The first refusal is reported once, then the client ends: a page would retry at once.
    onRefuse: ({ host, path, reason }) => {
      emit({ event: "wire-refused", host, path, reason });
      setImmediate(() => close(3));
    },
    hosts: allowedHosts(config),
    cap: config.wireCap ?? 100,
    // Connections the browser opens beyond the page's own server, counted from CDP.
    connectionCap: config.connectionCap ?? 20,
    onConnection: ({ n, host }) => emit({ event: "connection", n, host }),
    onRecord: ({ n, host, path, bearer }) =>
      emit({
        event: "wire",
        n,
        host,
        path,
        principal: bearer === null ? null : (tokenOwner.get(bearer) ?? "unknown"),
      }),
  });

  const server = createServer((request, response) => {
    const entry = FILES[new URL(request.url, "http://x").pathname];
    if (!entry || request.method !== "GET") {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(200, { "content-type": entry.type, "cache-control": "no-store" });
    response.end(entry.body ?? readFileSync(entry.file));
  });
  const fixedPort = admission ? Number(new URL(config.origin).port) : 0;
  if (
    admission &&
    (!/^http:\/\/127\.0\.0\.1:[1-9]\d{0,4}$/.test(config.origin ?? "") || fixedPort > 65535)
  )
    throw new Error("S5b fixed browser origin differs");
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(fixedPort, "127.0.0.1", resolve);
  });
  const origin = `http://127.0.0.1:${server.address().port}`;

  const browser = await chromium.launch({
    headless: true,
    ...(admission ? { executablePath: config.chromiumExecutable } : {}),
  });
  const context = await browser.newContext();
  const page = await context.newPage();
  let closing = false;
  close = async (code = 0) => {
    if (closing) return;
    closing = true;
    await Promise.allSettled(pendingCapture);
    await browser.close().catch(() => {});
    server.close();
    process.exit(code);
  };
  process.stdin.on("close", () => close(0));
  process.on("SIGTERM", () => close(0));

  // Each distinct network connection a response came over counts once; a refusal ends the client.
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
      // The ledger reported the refusal and ends the client.
    }
  });

  const served = new Set();
  await page.route("**/*", async (route) => {
    const request = route.request();
    const url = request.url();
    if (url.startsWith(`${origin}/`)) return route.continue();
    if (url.startsWith(GSTATIC)) {
      const file = url.slice(GSTATIC.length);
      if (!BUNDLES.includes(file)) {
        // Not an allowed host of the ledger: refused, reported and the client ends.
        try {
          ledger.admit("www.gstatic.com", `/${file}`);
        } catch {
          return route.abort("blockedbyclient");
        }
      }
      const body = readFileSync(join(FIREBASE, file));
      if (!served.has(file)) {
        served.add(file);
        emit({ event: "bundle", file, version: VERSION, sha256: sha256(body) });
      }
      return route.fulfill({ status: 200, contentType: "text/javascript", body });
    }
    const parsed = new URL(url);
    const headers = request.headers();
    try {
      const body = request.postData();
      const record = ledger.admit(
        parsed.host,
        parsed.pathname,
        headers.authorization ?? webChannelBearer(url, body) ?? undefined,
      );
      if (admission) {
        if (typeof body !== "string" || Buffer.byteLength(body) > TRANSACTION_BODY_LIMIT)
          throw new Error("S5b browser request missing or capped");
        await admission.beforeTransaction({
          method: transactionMethod(parsed.pathname),
          request: JSON.parse(body),
          record,
        });
      }
      if (capture && transactionMethod(parsed.pathname))
        capturedRequests.set(request, {
          n: record.n,
          method: transactionMethod(parsed.pathname),
          body,
        });
    } catch {
      // The ledger reported the first refusal and ends the client.
      return route.abort("blockedbyclient");
    }
    return route.continue();
  });
  page.on("response", (response) => {
    const request = response.request();
    const observed = capturedRequests.get(request);
    if (!observed) return;
    capturedRequests.delete(request);
    const task = (async () => {
      let timer;
      try {
        const body = await Promise.race([
          response.body(),
          new Promise((_, reject) => {
            timer = setTimeout(() => reject(new Error("capture timeout")), 2000);
          }),
        ]);
        if (body.length > TRANSACTION_BODY_LIMIT) throw new Error("capture cap");
        emit({
          event: "transaction-wire",
          n: observed.n,
          ...transactionWireEvidence(
            observed.method,
            observed.body,
            body.toString("utf8"),
            response.status(),
          ),
        });
      } catch {
        emit({
          event: "transaction-wire",
          n: observed.n,
          method: observed.method,
          complete: false,
          reason: "capture-failed",
        });
      } finally {
        clearTimeout(timer);
      }
    })();
    pendingCapture.add(task);
    task.finally(() => pendingCapture.delete(task));
  });
  page.on("requestfailed", (request) => {
    const observed = capturedRequests.get(request);
    if (!observed) return;
    capturedRequests.delete(request);
    emit({
      event: "transaction-wire",
      n: observed.n,
      method: observed.method,
      complete: false,
      reason: "request-failed",
    });
  });
  await page.exposeFunction("afcToken", (hash, uid) => {
    tokenOwner.set(hash, uid);
  });
  await page.exposeFunction("afcEmit", async (event) => {
    if (capture && event?.event === "result") await Promise.allSettled(pendingCapture);
    if (event?.event === "page-closed") return close(0);
    return emit(event);
  });
  await page.addInitScript((value) => {
    window.afcConfig = value;
  }, config);
  page.on("pageerror", (error) => emit({ event: "page-error", message: String(error.message) }));
  await page.goto(`${origin}/`);
  if (admission) {
    const browserSession = await browser.newBrowserCDPSession();
    const processes = await browserSession.send("SystemInfo.getProcessInfo");
    if (
      !Array.isArray(processes.processInfo) ||
      processes.processInfo.length > 20 ||
      processes.processInfo.some((value) => !Number.isInteger(value.id) || value.id < 1)
    )
      throw new Error("S5b bounded browser process identities missing");
    emit({
      event: "browser-processes",
      origin,
      driverPid: process.pid,
      processes: processes.processInfo.map(({ id, type }) => ({ pid: id, type })),
    });
    await browserSession.detach();
  }

  createInterface({ input: process.stdin }).on("line", (line) => {
    let command;
    try {
      command = JSON.parse(line);
    } catch {
      return emit({ event: "result", id: null, ok: false, error: "unparsable command" });
    }
    if (admission?.accept(command)) return;
    // Dispatched, not awaited: a paused transaction must not block the command resuming it.
    return page
      .evaluate((c) => window.afcRun(c), command)
      .catch((error) =>
        emit({ event: "result", id: command.id, ok: false, code: "harness", error: error.message }),
      );
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    emit({ event: "driver-error", message: String(error?.message ?? error) });
    process.exit(1);
  });
}
