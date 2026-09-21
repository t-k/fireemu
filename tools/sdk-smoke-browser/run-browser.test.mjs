// Tests for the browser runner plumbing. They open no emulator and touch no
// Firebase project; the one test that launches Chromium does so only to prove
// the harness closes it again.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { createRequire } from "node:module";

import { createHash as browserCreateHash } from "../sdk-smoke/web/listen-catalog-sha256.js";
import {
  classifyWebChannelRequest,
  closeAll,
  compactWebChannelRows,
  launchChromium,
  resolveMounted,
  serveStatic,
  summarizeWebChannel,
} from "./browser_harness.mjs";
import { PAGES, parseArgs } from "./run-browser.mjs";

const HERE = path.dirname(new URL(import.meta.url).pathname);
const WEB = path.join(HERE, "..", "sdk-smoke", "web");

test("the browser SHA-256 shim matches node:crypto across block boundaries and UTF-8", () => {
  const samples = ["", "abc", "x".repeat(55), "y".repeat(56), "z".repeat(63), "w".repeat(64),
    "v".repeat(65), "u".repeat(1000), "o6_listen/uid/runs/" + "a".repeat(32) + "/docs/alpha",
    "日本語のパス/ドキュメント", randomBytes(300).toString("base64")];
  for (const sample of samples) {
    assert.equal(
      browserCreateHash("sha256").update(sample).digest("hex"),
      createHash("sha256").update(sample).digest("hex"),
      `length ${sample.length}`,
    );
  }
  assert.equal(
    browserCreateHash("sha256").update("ab").update("c").digest("hex"),
    createHash("sha256").update("abc").digest("hex"),
  );
  assert.throws(() => browserCreateHash("md5"), /unsupported digest/);
  assert.throws(() => browserCreateHash("sha256").digest("base64"), /unsupported digest encoding/);
});

test("the catalog page pins the same Firebase release and maps node:crypto for the collector", async () => {
  const script = await readFile(path.join(WEB, "listen-catalog.js"), "utf8");
  const versions = [...script.matchAll(/gstatic\.com\/firebasejs\/(\d+\.\d+\.\d+)\//g)].map((m) => m[1]);
  assert.ok(versions.length >= 3);
  assert.deepEqual([...new Set(versions)], ["12.18.0"]);
  assert.match(script, /from "\/collector\/listen_collector\.mjs"/);
  const html = await readFile(path.join(WEB, "listen-catalog.html"), "utf8");
  const importMap = JSON.parse(/<script type="importmap">([\s\S]*?)<\/script>/.exec(html)[1]);
  assert.deepEqual(importMap, { imports: { "node:crypto": "./listen-catalog-sha256.js" } });
});

test("mount resolution never leaves a mounted directory", () => {
  const mounts = { "/": "/srv/web", "/collector/": "/srv/lane" };
  assert.equal(resolveMounted(mounts, "/index.html"), path.resolve("/srv/web/index.html"));
  assert.equal(resolveMounted(mounts, "/collector/listen_collector.mjs"),
    path.resolve("/srv/lane/listen_collector.mjs"));
  for (const bad of ["/../etc/passwd", "/collector/../../etc/passwd", "/%2e%2e/x", "/a\\..\\b",
    "/x\0y", "relative", "/%zz", "/./x"]) {
    assert.equal(resolveMounted(mounts, bad), null, bad);
  }
});

test("the static server serves only known file types under the mounts", async () => {
  const base = mkdtempSync(path.join(tmpdir(), "fireemu-web-"));
  const root = path.join(base, "web");
  mkdirSync(root);
  writeFileSync(path.join(base, "outside.html"), "must not be served");
  // fetch() normalises dot segments before sending, so raw paths go through http.request.
  const rawStatus = (origin, rawPath) =>
    new Promise((resolve, reject) => {
      const request = httpRequest(`${origin}${rawPath}`, (response) => {
        response.resume();
        response.on("end", () => resolve(response.statusCode));
      });
      request.on("error", reject);
      request.end();
    });
  try {
    writeFileSync(path.join(root, "page.html"), "<p>hi</p>");
    writeFileSync(path.join(root, "secret.txt"), "not served");
    mkdirSync(path.join(root, "sub"));
    writeFileSync(path.join(root, "sub", "m.mjs"), "export const x = 1;");
    const server = await serveStatic({ "/": root });
    try {
      const page = await fetch(`${server.origin}/page.html`);
      assert.equal(page.status, 200);
      assert.match(page.headers.get("content-type"), /text\/html/);
      assert.equal(await page.text(), "<p>hi</p>");
      const module = await fetch(`${server.origin}/sub/m.mjs`);
      assert.equal(module.status, 200);
      assert.match(module.headers.get("content-type"), /text\/javascript/);
      assert.equal((await fetch(`${server.origin}/secret.txt`)).status, 404);
      assert.equal(await rawStatus(server.origin, "/../outside.html"), 404);
      assert.equal(await rawStatus(server.origin, "/%2e%2e/outside.html"), 404);
      assert.equal(await rawStatus(server.origin, "/..%2foutside.html"), 404);
      assert.equal((await fetch(`${server.origin}/missing.html`)).status, 404);
      assert.equal((await fetch(`${server.origin}/page.html`, { method: "POST" })).status, 405);
    } finally {
      await server.close();
    }
    await assert.rejects(fetch(`${server.origin}/page.html`));
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("WebChannel requests are classified by role without recording session data", () => {
  const base = "http://127.0.0.1:8080/google.firestore.v1.Firestore/Listen/channel";
  const handshake = classifyWebChannelRequest({ url: `${base}?VER=8&RID=1&CVER=22&t=1`, method: "POST" }, 8080);
  assert.deepEqual(handshake, { stream: "Listen", method: "POST", role: "handshake", hasSession: false, ci: null, retry: 1 });
  const forward = classifyWebChannelRequest({ url: `${base}?VER=8&SID=abc&RID=2&AID=3`, method: "POST" }, 8080);
  assert.equal(forward.role, "forward");
  assert.equal(forward.hasSession, true);
  assert.ok(!JSON.stringify(forward).includes("abc"));
  const back = classifyWebChannelRequest({ url: `${base}?VER=8&SID=abc&RID=rpc&AID=3&CI=0&TYPE=xmlhttp`, method: "GET" }, 8080);
  assert.equal(back.role, "backchannel");
  assert.equal(back.ci, 0);
  const terminate = classifyWebChannelRequest({ url: `${base}?SID=abc&RID=4&TYPE=terminate`, method: "POST" }, 8080);
  assert.equal(terminate.role, "terminate");
  const write = classifyWebChannelRequest({ url: base.replace("Listen", "Write") + "?VER=8&RID=1", method: "POST" }, 8080);
  assert.equal(write.stream, "Write");
  assert.equal(classifyWebChannelRequest({ url: base, method: "POST" }, 9090), null);
  assert.equal(classifyWebChannelRequest({ url: "http://127.0.0.1:8080/v1/rules", method: "PUT" }, 8080), null);
  assert.equal(classifyWebChannelRequest({ url: "https://www.gstatic.com/firebasejs/x.js", method: "GET" }, 8080), null);
  assert.equal(classifyWebChannelRequest({ url: "not a url", method: "GET" }, 8080), null);
});

test("the request summary separates long-polled from streamed backchannels", () => {
  const rows = [
    { atMs: 1, stream: "Listen", method: "POST", role: "handshake", ci: null, status: 200 },
    { atMs: 2, stream: "Listen", method: "GET", role: "backchannel", ci: 1, status: 200 },
    { atMs: 3, stream: "Listen", method: "GET", role: "backchannel", ci: 0, status: 200 },
    { atMs: 4, stream: "Write", method: "POST", role: "forward", ci: null, status: 200 },
    { atMs: 5, stream: "Write", method: "POST", role: "terminate", ci: null, status: null },
  ];
  assert.deepEqual(summarizeWebChannel(rows), {
    requests: 5, listen: 3, write: 2, handshakes: 1, forward: 1, backchannel: 2, terminate: 1,
    backchannelCi: { streamed: 1, longPolled: 1 },
  });
  assert.deepEqual(compactWebChannelRows(rows, 2), [
    [1, "Listen", "POST", "handshake", null, 200],
    [2, "Listen", "GET", "backchannel", 1, 200],
  ]);
});

test("runner arguments require loopback endpoints, a demo project and known pages", () => {
  const env = { FIRESTORE_EMULATOR_HOST: "127.0.0.1:8080", FIREBASE_AUTH_EMULATOR_HOST: "127.0.0.1:9099",
    GOOGLE_CLOUD_PROJECT: "demo-app", FIREEMU_CONTROL_TOKEN: "t" };
  const options = parseArgs([], env);
  assert.deepEqual(options.pages, ["listener-lifecycle", "listen-reconnect"]);
  assert.equal(options.firestorePort, 8080);
  assert.deepEqual(parseArgs(["--pages", "listen-reconnect"], env).pages, ["listen-reconnect"]);
  assert.throws(() => parseArgs(["--pages", "index"], env), /unique subset/);
  assert.throws(() => parseArgs(["--pages", "listen-reconnect,listen-reconnect"], env), /unique subset/);
  assert.throws(() => parseArgs(["--bogus"], env), /unknown argument/);
  assert.throws(() => parseArgs([], { ...env, FIRESTORE_EMULATOR_HOST: "localhost:8080" }), /127\.0\.0\.1/);
  assert.throws(() => parseArgs([], { ...env, FIRESTORE_EMULATOR_HOST: "firestore.googleapis.com:443" }), /127\.0\.0\.1/);
  assert.throws(() => parseArgs([], { ...env, GOOGLE_CLOUD_PROJECT: "real-project" }), /demo project/);
  for (const spec of Object.values(PAGES)) assert.ok(existsSync(path.join(WEB, spec.file)), spec.file);
  // The control token is page input, never part of the runner's own output shape.
  assert.ok(!Object.keys(PAGES["listener-lifecycle"].query(options)).includes("token"));
});

test("closeAll closes every resource and reports the first failure", async () => {
  const order = [];
  await assert.rejects(
    closeAll([async () => order.push("a"), async () => { order.push("b"); throw new Error("b failed"); },
      async () => order.push("c")]),
    /b failed/,
  );
  assert.deepEqual(order, ["c", "b", "a"]);
});

const chromiumInstalled = () => {
  try {
    const { chromium } = createRequire(path.join(HERE, "noop.cjs"))("playwright");
    return existsSync(chromium.executablePath());
  } catch {
    return false;
  }
};

test("a launched Chromium is gone after close (process hygiene)", { skip: !chromiumInstalled() && "playwright chromium is not installed" }, async () => {
  const marker = `fireemu-hygiene-${randomBytes(6).toString("hex")}`;
  const running = () => {
    try {
      return execFileSync("pgrep", ["-f", marker], { encoding: "utf8" }).trim().split("\n").filter(Boolean);
    } catch {
      return [];
    }
  };
  const chromium = await launchChromium(HERE, { userDataMarker: marker });
  assert.equal(chromium.name, "chromium");
  assert.match(chromium.version, /^\d+\./);
  assert.ok(running().length >= 1, "the browser process should carry the marker while open");
  await chromium.close();
  const deadline = Date.now() + 10_000;
  while (running().length > 0 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 100));
  assert.deepEqual(running(), [], "no Chromium process may survive close()");
});
