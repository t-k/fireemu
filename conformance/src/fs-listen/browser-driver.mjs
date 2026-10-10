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
import { execFileSync } from "node:child_process";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

import { webChannelBearer } from "../auth-fs-cross/browser-driver.mjs";
import { createWireLedger, PRODUCTION_HOSTS } from "../auth-fs-cross/sdk-wire.mjs";
import { MODE_SETTINGS, modeRun, L3_IDS, L3_PHASES, l3Problems } from "./browser-modes.mjs";
import { bandOf } from "./sdk-deps.mjs";
import { sdkCases } from "./sdk-cases.mjs";
import { DEADLINE_MS, CLEANUP_MS, STEP_TIMEOUT_MS } from "./sdk-run.mjs";
import { captureFrames, WIRE_BYTES, WIRE_FRAMES } from "./frames.mjs";

export { captureFrames, WIRE_BYTES, WIRE_FRAMES } from "./frames.mjs";

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

const valueMask = (value) =>
  value.replace(/[A-Z]/g, "X").replace(/[a-z]/g, "x").replace(/[0-9]/g, "0");
/** Value-only masks retain the JSON layout and the token's alphabet and length. */
export function maskWire(text) {
  return text
    .replace(
      /("(?:resumeToken|SID|gsessionid|key|apiKey|password|authorization|Authorization|sessionId)"\s*:\s*")((?:\\.|[^"\\])*)("|$)/g,
      (_, before, value, after) => before + valueMask(value) + after,
    )
    .replace(
      /(\["c",\s*")([^"]+)("|$)/g,
      (_, before, value, after) => before + valueMask(value) + after,
    );
}

/** The official SDK's form-encoded forward-channel messages. */
export function outgoingTargets(body) {
  const targets = [];
  for (const [name, value] of new URLSearchParams(body)) {
    if (!/^req\d+___data__$/.test(name)) continue;
    const message = JSON.parse(value);
    if (message.addTarget)
      targets.push({
        targetId: message.addTarget.targetId,
        resumeToken: message.addTarget.resumeToken ?? null,
        readTime: message.addTarget.readTime ?? null,
      });
  }
  return targets;
}

async function runMode({ browser, config, run, mode, accounts, cases }) {
  const origin = originOf(config.originPort);
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
  const ci = {};
  const contexts = new Set();
  const pages = new Map();
  const wire = [];
  const sessions = new Map();
  const tokens = new Map();
  const connectionIds = new Set();
  const contextIds = new Map();
  const cleanup = { complete: true, outcomes: [] };
  const l3 = { seeds: [], phases: [], cleanup };
  let receipt;
  let listenChannel = 0;
  let stopped = false;
  let capturing = false;
  let totalBytes = 0;
  let totalFrames = 0;
  let queuedBytes = 0;
  let sequence = 0;
  let timer;
  const started = Date.now();
  const label = (map, value) => {
    if (!value) return null;
    if (!map.has(value)) map.set(value, map.size + 1);
    return map.get(value);
  };
  const token = (value) =>
    value
      ? { relation: label(tokens, value), masked: valueMask(value), length: value.length }
      : null;
  const ledger = createWireLedger({
    hosts: allowedHosts(config),
    cap: config.wireCap ?? 100,
    connectionCap: config.connectionCap ?? 20,
    onRefuse: ({ host, path, reason }) => {
      stopped = true;
      emit({ event: "wire-refused", mode, host, path, reason });
      for (const context of contexts) void context.close();
    },
    onConnection: ({ n, host }) => emit({ event: "connection", mode, n, host }),
    onRecord: ({ n, host, path }) => emit({ event: "wire", mode, n, host, path }),
  });
  const check = () => {
    if (stopped || ledger.closed() || Date.now() - started >= DEADLINE_MS)
      throw new Error("observation stopped at its cap or deadline");
  };
  const closeContext = async (context, name) => {
    try {
      await context.close();
      contexts.delete(context);
      cleanup.outcomes.push({ name, closed: true });
    } catch {
      cleanup.complete = false;
      cleanup.outcomes.push({ name, closed: false });
    }
  };
  const hookContext = async (context) => {
    if (stopped) {
      await context.close();
      throw new Error("observation already stopped");
    }
    contexts.add(context);
    contextIds.set(context, contextIds.size + 1);
    // Keep terminate evidence outside the CDP target destroyed by reload or close.
    const terminates = new WeakMap();
    context.on("request", (request) => {
      if (!capturing || listenChannelCi(request.url()) === null) return;
      const url = new URL(request.url());
      if (url.searchParams.get("TYPE") !== "terminate") return;
      const session = sessions.get(url.searchParams.get("SID"));
      if (!l3.closeSession || session !== l3.closeSession) return;
      let state;
      try {
        state = pages.get(request.frame().page());
      } catch {
        /* An unload request can outlive its frame; the SID still identifies it. */
      }
      const bytes = Buffer.byteLength(request.postData() ?? "");
      totalBytes += bytes;
      const event = {
        event: ++sequence,
        elapsedMs: Date.now() - started,
        phase: state?.phase,
        page: state?.name,
        method: request.method(),
        path: url.pathname,
        session: label(sessions, url.searchParams.get("SID")),
        sessionMask: valueMask(url.searchParams.get("SID") ?? ""),
        terminate: true,
        dispatched: true,
        outcome: "unknown",
        status: null,
        requestBodyBytes: bytes,
        bodyBytes: 0,
        targets: [],
        boundaries: [],
        boundaryComplete: false,
        overflow: totalBytes + queuedBytes > WIRE_BYTES,
      };
      wire.push(event);
      terminates.set(request, event);
    });
    context.on("response", (response) => {
      const event = terminates.get(response.request());
      if (event) event.status = response.status();
    });
    context.on("requestfinished", (request) => {
      const event = terminates.get(request);
      if (event) event.outcome = "completed";
    });
    context.on("requestfailed", (request) => {
      const event = terminates.get(request);
      if (event)
        event.outcome =
          request.failure()?.errorText === "net::ERR_ABORTED" ? "cancelled" : "unknown";
    });
    // Context routing also covers unload requests and replacement tabs.
    await context.route("**/*", async (route) => {
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
      if (url.startsWith(GSTATIC) && BUNDLES.includes(url.slice(GSTATIC.length)))
        return route.fulfill({
          status: 200,
          contentType: "text/javascript",
          body: readFileSync(join(FIREBASE, url.slice(GSTATIC.length))),
        });
      const parsed = new URL(url);
      try {
        ledger.admit(
          parsed.host,
          parsed.pathname,
          request.headers().authorization ?? webChannelBearer(url, request.postData()) ?? undefined,
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
    return context;
  };
  const attach = async (context, page, phase) => {
    const state = { phase };
    pages.set(page, state);
    const cdp = await context.newCDPSession(page);
    const requests = new Map();
    await cdp.send("Network.enable");
    const update = (held) => {
      const raw = Buffer.concat(held.raw).toString("utf8");
      const parsed = captureFrames(raw);
      const handshake = parsed.frames.find((f) => Array.isArray(f.message) && f.message[0] === "c");
      if (handshake && typeof handshake.message[1] === "string") {
        held.event.session = label(sessions, handshake.message[1]);
        held.event.sessionMask = valueMask(handshake.message[1]);
      }
      held.event.bodyBytes = Buffer.byteLength(raw);
      held.event.body = maskWire(raw);
      held.event.frameComplete = parsed.complete;
      held.event.overflow ||= parsed.overflow ?? false;
      held.event.decodeError ||= parsed.decodeError ?? false;
      held.event.boundaries = parsed.frames
        .filter(
          (f) =>
            f.message?.targetChange &&
            (f.message.targetChange.resumeToken || f.message.targetChange.readTime),
        )
        .map((f) => ({
          sequence: f.sequence,
          endByte: f.endByte,
          targetIds: f.message.targetChange.targetIds ?? [],
          type: f.message.targetChange.targetChangeType ?? "NO_CHANGE",
          resumeToken: token(f.message.targetChange.resumeToken),
          readTime: f.message.targetChange.readTime ?? null,
        }));
      held.event.boundaryComplete =
        held.event.boundaries.some((b) => b.readTime) &&
        !held.event.overflow &&
        !held.event.decodeError;
      if (held.event.boundaryComplete && held.event.boundaryBodyBytes == null)
        held.event.boundaryBodyBytes = held.event.boundaries.find((b) => b.readTime).endByte;
      totalFrames += parsed.frames.length - held.frames;
      held.frames = parsed.frames.length;
      if (totalFrames > WIRE_FRAMES) {
        held.event.overflow = true;
        held.event.boundaryComplete = false;
      }
    };
    const append = (held, data) => {
      if (!data || held.event.overflow) return;
      const bytes = Buffer.from(data, "base64");
      totalBytes += bytes.length;
      if (totalBytes > WIRE_BYTES) {
        held.event.overflow = true;
        held.event.boundaryComplete = false;
        return;
      }
      held.raw.push(bytes);
      update(held);
    };
    cdp.on("Network.requestWillBeSent", ({ requestId, request }) => {
      if (!capturing || listenChannelCi(request.url) === null) return;
      const url = new URL(request.url);
      if (
        url.searchParams.get("TYPE") === "terminate" &&
        l3.closeSession &&
        sessions.get(url.searchParams.get("SID")) === l3.closeSession
      )
        return;
      const event = {
        event: ++sequence,
        elapsedMs: Date.now() - started,
        phase: state.phase,
        page: state.name,
        method: request.method,
        path: url.pathname,
        session: label(sessions, url.searchParams.get("SID")),
        sessionMask: valueMask(url.searchParams.get("SID") ?? ""),
        terminate: url.searchParams.get("TYPE") === "terminate",
        dispatched: true,
        outcome: "unknown",
        status: null,
        bodyBytes: 0,
        targets: [],
        boundaries: [],
        boundaryComplete: false,
      };
      try {
        const bytes = Buffer.byteLength(request.postData ?? "");
        totalBytes += bytes;
        if (totalBytes + queuedBytes > WIRE_BYTES) throw new Error("wire byte cap");
        event.targets = outgoingTargets(request.postData ?? "").map((t) => ({
          ...t,
          resumeToken: token(t.resumeToken),
        }));
        event.requestBodyBytes = bytes;
        // Retain the official add-target JSON layout, never authentication form fields.
        event.addTargetBodies = [...new URLSearchParams(request.postData ?? "")]
          .filter(([k, v]) => /^req\d+___data__$/.test(k) && JSON.parse(v).addTarget)
          .map(([, v]) => maskWire(v));
      } catch {
        event.decodeError = true;
        event.overflow = totalBytes + queuedBytes > WIRE_BYTES;
      }
      wire.push(event);
      requests.set(requestId, { event, raw: [], frames: 0, streaming: false, pending: [] });
    });
    cdp.on("Network.responseReceived", async ({ requestId, response }) => {
      if (response.url.startsWith(`${origin}/`) || response.url.startsWith(GSTATIC)) return;
      const id = response.connectionId;
      if (id && !connectionIds.has(`${contextIds.get(context)}:${id}`)) {
        connectionIds.add(`${contextIds.get(context)}:${id}`);
        try {
          ledger.connection(new URL(response.url).host);
        } catch {
          /* The ledger stops observation. */
        }
      }
      const held = requests.get(requestId);
      if (!held) return;
      held.event.status = response.status;
      held.event.contentLength =
        Object.entries(response.headers).find(([k]) => k.toLowerCase() === "content-length")?.[1] ??
        null;
      held.awaiting = true;
      try {
        const result = await cdp.send("Network.streamResourceContent", { requestId });
        held.streaming = true;
        append(held, result.bufferedData);
      } catch {
        held.event.captureUnavailable = true;
      }
      held.awaiting = false;
      for (const data of held.pending) {
        queuedBytes -= Buffer.from(data, "base64").length;
        append(held, data);
      }
      held.pending = [];
    });
    cdp.on("Network.dataReceived", ({ requestId, data }) => {
      const held = requests.get(requestId);
      if (held && data) {
        if (held.awaiting) {
          const bytes = Buffer.from(data, "base64").length;
          if (totalBytes + queuedBytes + bytes > WIRE_BYTES) {
            held.event.overflow = true;
            held.event.boundaryComplete = false;
          } else {
            queuedBytes += bytes;
            held.pending.push(data);
          }
        } else append(held, data);
      }
    });
    cdp.on("Network.loadingFinished", async ({ requestId }) => {
      const held = requests.get(requestId);
      if (!held) return;
      held.event.outcome = "completed";
      if (!held.streaming) {
        try {
          const body = await cdp.send("Network.getResponseBody", { requestId });
          append(held, body.base64Encoded ? body.body : Buffer.from(body.body).toString("base64"));
        } catch {
          held.event.captureUnavailable = true;
        }
      }
      update(held);
    });
    cdp.on("Network.loadingFailed", ({ requestId, canceled }) => {
      const held = requests.get(requestId);
      if (held) held.event.outcome = canceled ? "cancelled" : "unknown";
    });
    // SDK errors are codes/checkpoints; console text can contain credential-bearing URLs.
    page.on("pageerror", () =>
      emit({ event: "page-error", mode, message: "page JavaScript failed" }),
    );
    return state;
  };
  const load = async (page) => {
    check();
    await page.goto(`${origin}/`);
    await page.waitForSelector("body[data-ready=true]", {
      state: "attached",
      timeout: STEP_TIMEOUT_MS,
    });
  };
  const newPage = async (context, name, phase, extra = {}) => {
    check();
    const page = await context.newPage();
    const state = await attach(context, page, phase);
    state.name = name;
    await load(page);
    state.l3Owned = true;
    await page.evaluate((c) => window.listenL3Init(c), { ...input, ...extra });
    return page;
  };
  const waitSnapshot = async (page, offline = false) => {
    await page.waitForFunction(
      (offline) => {
        const c = window.listenL3Checkpoint();
        if (c.errors.length) throw new Error("listener failed");
        const s = c.snapshots.at(-1);
        return (
          s &&
          s.fromCache === offline &&
          !s.hasPendingWrites &&
          (offline || s.docs.join() === "alpha,beta")
        );
      },
      offline,
      { timeout: STEP_TIMEOUT_MS },
    );
  };
  const checkpoint = async (page, phase, offline = false) => {
    const value = {
      phase,
      elapsedMs: Date.now() - started,
      wireThroughEvent: sequence,
      ...(await page.evaluate(() => window.listenL3Checkpoint())),
      playwrightOffline: offline,
    };
    l3.phases.push(value);
    emit({ event: "l3-checkpoint", mode, phase, checkpoint: value });
    return value;
  };
  const stopPage = async (page, name, clear = false) => {
    pages.get(page).stopAttempted = true;
    try {
      const outcome = await page.evaluate((clear) => window.listenL3Stop(clear), clear);
      cleanup.outcomes.push({ name, ...outcome });
    } catch {
      cleanup.complete = false;
      cleanup.outcomes.push({ name, closed: false });
    }
  };
  const waitWire = async (phase, pageName) => {
    const until = Date.now() + STEP_TIMEOUT_MS;
    while (Date.now() < until) {
      check();
      if (wire.some((e) => e.phase === phase && e.page === pageName && e.boundaryComplete)) return;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw new Error(`missing wire boundary: ${phase}`);
  };
  const observe = async () => {
    const context = await hookContext(await browser.newContext());
    const catalogPage = await context.newPage();
    await attach(context, catalogPage, "catalog");
    await load(catalogPage);
    receipt = await catalogPage.evaluate((value) => window.listenRun(value), input);
    await catalogPage.close();
    capturing = true;
    const a = await newPage(context, "A", "before-reload");
    for (const name of ["alpha", "beta"]) {
      l3.seeds.push(await a.evaluate((name) => window.listenL3Seed(name), name));
      emit({ event: "l3-seeds", mode, seeds: l3.seeds });
    }
    const b = await newPage(context, "B", "control-start");
    for (const page of [a, b]) {
      await page.evaluate(() => window.listenL3Subscribe());
      await waitSnapshot(page);
    }
    await checkpoint(b, "control-start");
    await checkpoint(a, "before-reload");
    // Keep the old session identity in the parent before the page loses its state.
    l3.reloadSession = wire.filter((e) => e.page === "A" && e.session).at(-1)?.session ?? null;
    await a.reload();
    pages.get(a).phase = "after-reload";
    await a.waitForSelector("body[data-ready=true]", {
      state: "attached",
      timeout: STEP_TIMEOUT_MS,
    });
    await a.evaluate((c) => window.listenL3Init(c), input);
    await a.evaluate(() => window.listenL3Subscribe());
    await waitSnapshot(a);
    await checkpoint(a, "after-reload");
    await checkpoint(a, "before-close");
    l3.closeSession = wire.filter((e) => e.page === "A" && e.session).at(-1)?.session ?? null;
    pages.get(a).phase = "before-close";
    const closed = a.waitForEvent("close", { timeout: STEP_TIMEOUT_MS });
    await Promise.all([closed, a.close({ runBeforeUnload: true })]);
    l3.closeOutcome = "closed";
    const a2 = await newPage(context, "A2", "replacement");
    await a2.evaluate(() => window.listenL3Subscribe());
    await waitSnapshot(a2);
    await checkpoint(a2, "replacement");
    await checkpoint(b, "control-end");
    const terminateUntil = Date.now() + STEP_TIMEOUT_MS;
    while (
      Date.now() < terminateUntil &&
      wire.some((e) => e.terminate && e.session === l3.closeSession && e.outcome === "unknown")
    ) {
      check();
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    l3.controlCompleted = true;
    await stopPage(a2, "A2");
    await stopPage(b, "B");
    await closeContext(context, "memory lifecycle context");

    const profile = mkdtempSync(join(HERE, `.l3-profile-${mode}-`));
    l3.profile = { disposable: true, sameProfile: true, processExited: false, deleted: false };
    try {
      check();
      const warm = await hookContext(
        await chromium.launchPersistentContext(profile, {
          headless: true,
          args: browserArgs(config),
        }),
      );
      const warmPage = await newPage(warm, "warm", "warm", { persistent: true });
      await warmPage.evaluate(() => window.listenL3Subscribe());
      await waitSnapshot(warmPage);
      await waitWire("warm", "warm");
      await warmPage.evaluate(() => window.listenL3Read());
      await checkpoint(warmPage, "warm");
      await stopPage(warmPage, "warm");
      await closeContext(warm, "warm Chromium");
      // Verify the owned profile's process disappeared before reusing its storage.
      l3.profile.processExited =
        !contexts.has(warm) &&
        !execFileSync("ps", ["-axo", "pid=,comm=,args="], { encoding: "utf8" })
          .split("\n")
          .some((line) => line.includes(`--user-data-dir=${profile}`) && /[Cc]hrom/.test(line));
      if (!l3.profile.processExited) throw new Error("warm Chromium did not exit");
      check();
      const restart = await hookContext(
        await chromium.launchPersistentContext(profile, {
          headless: true,
          args: browserArgs(config),
        }),
      );
      const restartPage = await newPage(restart, "restart", "restarted-offline", {
        persistent: true,
        offline: true,
      });
      await restart.setOffline(true);
      await restartPage.evaluate(() => window.listenL3Read());
      await restartPage.evaluate(() => window.listenL3Subscribe());
      await waitSnapshot(restartPage, true);
      await checkpoint(restartPage, "restarted-offline", true);
      pages.get(restartPage).phase = "restarted-online";
      await restart.setOffline(false);
      await restartPage.evaluate(() => window.listenL3Online());
      await waitSnapshot(restartPage);
      await waitWire("restarted-online", "restart");
      await checkpoint(restartPage, "restarted-online");
      await stopPage(restartPage, "restart", true);
      await closeContext(restart, "restarted Chromium");
    } finally {
      // Stop all clients before removing the profile, including a failed initialization.
      for (const [page, state] of pages)
        if (state.l3Owned && !state.stopAttempted && !page.isClosed())
          await stopPage(page, state.name, true);
      for (const context of contexts) await closeContext(context, "failed persistent context");
      const owned = execFileSync("ps", ["-axo", "pid=,comm=,args="], { encoding: "utf8" })
        .split("\n")
        .filter((line) => line.includes(`--user-data-dir=${profile}`) && /[Cc]hrom/.test(line));
      if (owned.length) {
        cleanup.complete = false;
        for (const line of owned) {
          try {
            process.kill(Number(line.trim().split(/\s+/)[0]), "SIGTERM");
          } catch {
            /* Already exited. */
          }
        }
        await new Promise((resolve) => setTimeout(resolve, 1000));
        const remaining = execFileSync("ps", ["-axo", "pid=,comm=,args="], { encoding: "utf8" })
          .split("\n")
          .filter((line) => line.includes(`--user-data-dir=${profile}`) && /[Cc]hrom/.test(line));
        for (const line of remaining) {
          try {
            process.kill(Number(line.trim().split(/\s+/)[0]), "SIGKILL");
          } catch {
            /* Already exited. */
          }
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      const alive = execFileSync("ps", ["-axo", "pid=,comm=,args="], { encoding: "utf8" })
        .split("\n")
        .some((line) => line.includes(`--user-data-dir=${profile}`) && /[Cc]hrom/.test(line));
      cleanup.outcomes.push({
        name: "persistent Chromium process",
        closed: !alive,
        forced: owned.length > 0,
      });
      if (alive || contexts.size) cleanup.complete = false;
      else
        try {
          rmSync(profile, { recursive: true });
          l3.profile.deleted = true;
        } catch {
          cleanup.complete = false;
        }
    }
    const cold = await hookContext(await browser.newContext());
    const coldPage = await newPage(cold, "cold", "cold-offline", { offline: true });
    await cold.setOffline(true);
    await coldPage.evaluate(() => window.listenL3Read());
    await coldPage.evaluate(() => window.listenL3Subscribe());
    await waitSnapshot(coldPage, true);
    await checkpoint(coldPage, "cold-offline", true);
    pages.get(coldPage).phase = "cold-online";
    await cold.setOffline(false);
    await coldPage.evaluate(() => window.listenL3Online());
    await waitSnapshot(coldPage);
    await waitWire("cold-online", "cold");
    await checkpoint(coldPage, "cold-online");
    await stopPage(coldPage, "cold");
    await closeContext(cold, "cold context");
  };
  const observation = observe();
  try {
    await Promise.race([
      observation,
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          stopped = true;
          reject(new Error("browser observation exceeded 15 minutes"));
        }, DEADLINE_MS);
      }),
    ]);
  } catch (error) {
    l3.thrown = String(error?.code ?? error?.name ?? "step-failed");
    if (!receipt) throw Object.assign(new Error(l3.thrown), { refused: ledger.closed() });
  } finally {
    stopped = true;
    clearTimeout(timer);
    await Promise.race([
      (async () => {
        for (const [page, state] of pages)
          if (state.l3Owned && !state.stopAttempted && !page.isClosed())
            await stopPage(page, state.name);
        await Promise.all(
          [...contexts].map((context) => closeContext(context, "remaining context")),
        );
        await observation.catch(() => {});
      })(),
      new Promise((resolve) =>
        setTimeout(() => {
          if (contexts.size) cleanup.complete = false;
          resolve();
        }, CLEANUP_MS).unref(),
      ),
    ]);
  }
  for (const id of L3_IDS) {
    const evidence = {
      phases: L3_PHASES[id]
        .map((phase) => l3.phases.find((p) => p.phase === phase))
        .filter(Boolean),
    };
    if (id === "201C")
      evidence.uninterrupted = l3.controlCompleted === true && evidence.phases.length === 2;
    if (["201", "202"].includes(id)) {
      evidence.markers =
        id === "201"
          ? ["checkpoint", "reload", "server"]
          : ["checkpoint", "close", "new-tab", "server"];
      evidence.oldSession = id === "201" ? l3.reloadSession : l3.closeSession;
      evidence.newSession =
        wire
          .filter(
            (e) =>
              e.page === (id === "201" ? "A" : "A2") &&
              e.phase === (id === "201" ? "after-reload" : "replacement") &&
              e.session,
          )
          .at(-1)?.session ?? null;
      evidence.terminate = wire.filter((e) => e.terminate && e.session === evidence.oldSession);
    }
    if (id === "202") evidence.closeOutcome = l3.closeOutcome;
    if (["203", "203C"].includes(id)) {
      evidence.cacheMode = id === "203" ? "persistent" : "memory";
      evidence.sameProfile = l3.profile?.sameProfile ?? false;
      evidence.processExited = l3.profile?.processExited ?? false;
      evidence.wire = wire.filter((e) => L3_PHASES[id].includes(e.phase));
    }
    const failures = l3Problems(id, evidence);
    if (l3.thrown && evidence.phases.length !== L3_PHASES[id].length)
      failures.push(`step-threw:${l3.thrown}`);
    receipt.cases.push({
      caseId: `FS-LISTEN-SDK-${id}`,
      complete: failures.length === 0,
      failures,
      observed: [evidence],
      comparedFields: Object.keys(evidence),
      invariantViolations: [],
      listenersClosed: cleanup.complete,
    });
  }
  receipt.l3 = l3;
  receipt.teardown.push(...cleanup.outcomes.map((o) => ({ client: o.name, closed: o.closed })));
  receipt.cleanup.complete &&= cleanup.complete;
  return {
    mode,
    run: modeRunId,
    receipt,
    transport: {
      requests: ledger.records.length,
      listenChannel,
      ci,
      connections: ledger.connections(),
      refused: ledger.closed(),
      wire,
      retainedBytes: totalBytes,
      retainedFrames: totalFrames,
    },
  };
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
  const browser = await chromium.launch({
    headless: true,
    args: ["--enable-automation", ...browserArgs(config)],
  });
  let profile;
  const results = {};
  try {
    const browserCdp = await browser.newBrowserCDPSession();
    const command = await browserCdp.send("Browser.getBrowserCommandLine");
    profile = command.arguments
      .find((arg) => arg.startsWith("--user-data-dir="))
      ?.slice("--user-data-dir=".length);
    for (const mode of modes) {
      try {
        results[mode] = await runMode({ browser, config, run, mode, accounts, cases });
      } catch (error) {
        results[mode] = {
          mode,
          run: modeRun(run, mode),
          error: String(error?.name ?? "driver-error"),
          refused: error?.refused === true,
        };
      }
      if (results[mode].refused || results[mode].transport?.refused) break;
    }
  } finally {
    let closed = true;
    await browser.close().catch(() => {
      closed = false;
    });
    if (profile) {
      const owned = execFileSync("ps", ["-axo", "pid=,comm=,args="], { encoding: "utf8" })
        .split("\n")
        .filter((line) => line.includes(`--user-data-dir=${profile}`) && /[Cc]hrom/.test(line));
      if (owned.length) closed = false;
      // The profile and Chromium command identity were checked before signalling each PID.
      for (const line of owned) {
        const pid = Number(line.trim().split(/\s+/)[0]);
        try {
          process.kill(pid, "SIGTERM");
        } catch {
          /* Already exited. */
        }
      }
      if (owned.length) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
        const remaining = execFileSync("ps", ["-axo", "pid=,comm=,args="], { encoding: "utf8" })
          .split("\n")
          .filter((line) => line.includes(`--user-data-dir=${profile}`) && /[Cc]hrom/.test(line));
        for (const line of remaining) {
          const pid = Number(line.trim().split(/\s+/)[0]);
          try {
            process.kill(pid, "SIGKILL");
          } catch {
            /* Already exited. */
          }
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
        const stillAlive = execFileSync("ps", ["-axo", "pid=,comm=,args="], { encoding: "utf8" })
          .split("\n")
          .some((line) => line.includes(`--user-data-dir=${profile}`) && /[Cc]hrom/.test(line));
        emit({
          event: "browser-cleanup",
          mode: "shared",
          forced: true,
          processExited: !stillAlive,
        });
      }
    } else closed = false;
    for (const result of Object.values(results))
      if (result.receipt) {
        result.receipt.teardown.push({ client: "shared Chromium", closed });
        result.receipt.cleanup.complete &&= closed;
        result.receipt.l3.cleanup.complete &&= closed;
      }
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
