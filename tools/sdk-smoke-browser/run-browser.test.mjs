// Tests for the browser runner plumbing. They open no emulator and touch no
// Firebase project; the one test that launches Chromium does so only to prove
// the harness closes it again.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { cpSync, existsSync, mkdtempSync, promises as fs, rmSync, symlinkSync, writeFileSync, mkdirSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

import { createHash as browserCreateHash } from "../sdk-smoke/web/listen-catalog-sha256.js";
import {
  classifyWebChannelRequest,
  closeAll,
  compactWebChannelRows,
  launchChromium,
  openMounted,
  parseWebChannelRow,
  resolveMounted,
  resolveMountedEntry,
  serveStatic,
  summarizeWebChannel,
} from "./browser_harness.mjs";
import { PAGES, parseArgs } from "./run-browser.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WEB = path.join(HERE, "..", "sdk-smoke", "web");
// A checkout path with a space, a non-ASCII character and a percent sign: a
// module directory derived from `import.meta.url` without decoding breaks here.
const AWKWARD_SEGMENTS = ["x y", "日本語%20"];

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
  assert.deepEqual(resolveMountedEntry(mounts, "/collector/x.mjs"),
    { prefix: "/collector/", root: path.resolve("/srv/lane"), target: path.resolve("/srv/lane/x.mjs") });
});

test("openMounted follows symlinks only as far as the real mount root", async () => {
  const base = mkdtempSync(path.join(tmpdir(), "fireemu-web-"));
  try {
    const root = path.join(base, "web");
    mkdirSync(root);
    mkdirSync(path.join(base, "outside"));
    writeFileSync(path.join(root, "a.json"), "{}");
    writeFileSync(path.join(base, "outside", "b.json"), "{}");
    symlinkSync(path.join("..", "outside", "b.json"), path.join(root, "b.json"));
    symlinkSync(path.join("..", "outside"), path.join(root, "dir"));
    const realRoot = await fs.realpath(root);
    const inside = await openMounted(realRoot, path.join(root, "a.json"));
    assert.equal(inside.size, 2);
    await inside.handle.close();
    assert.equal(await openMounted(realRoot, path.join(root, "b.json")), null);
    assert.equal(await openMounted(realRoot, path.join(root, "dir", "b.json")), null);
    assert.equal(await openMounted(realRoot, path.join(root, "missing.json")), null);
    assert.equal(await openMounted(realRoot, root), null, "a directory is not served");
    // The root must be the real root: a lexical root would let a symlinked
    // temporary directory prefix disagree with the resolved target.
    assert.equal(await openMounted(path.join(base, "elsewhere"), path.join(root, "a.json")), null);
  } finally {
    rmSync(base, { recursive: true, force: true });
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

test("the static server refuses symlinks that leave the mount", async () => {
  const base = mkdtempSync(path.join(tmpdir(), "fireemu-web-"));
  const root = path.join(base, "web");
  const outside = path.join(base, "outside");
  mkdirSync(root);
  mkdirSync(outside);
  const body = async (origin, urlPath) => {
    const response = await fetch(`${origin}${urlPath}`);
    return { status: response.status, text: await response.text() };
  };
  try {
    writeFileSync(path.join(outside, "leak.json"), '{"leak":true}');
    writeFileSync(path.join(outside, "leak.html"), "<p>leak</p>");
    writeFileSync(path.join(root, "inside.json"), '{"inside":true}');
    mkdirSync(path.join(root, "real-dir"));
    writeFileSync(path.join(root, "real-dir", "nested.json"), '{"nested":true}');
    // A file symlink out of the mount, a directory symlink out of the mount and
    // a symlink that stays inside the mount.
    symlinkSync(path.join("..", "outside", "leak.json"), path.join(root, "linked.json"));
    symlinkSync(path.join("..", "outside"), path.join(root, "linked-dir"));
    symlinkSync(path.join(base, "outside"), path.join(root, "linked-abs-dir"));
    symlinkSync("inside.json", path.join(root, "alias.json"));
    symlinkSync("real-dir", path.join(root, "alias-dir"));
    const server = await serveStatic({ "/": root });
    try {
      // Positive controls: regular files and symlinks that stay inside are served.
      assert.deepEqual(await body(server.origin, "/inside.json"), { status: 200, text: '{"inside":true}' });
      assert.deepEqual(await body(server.origin, "/real-dir/nested.json"), { status: 200, text: '{"nested":true}' });
      assert.deepEqual(await body(server.origin, "/alias.json"), { status: 200, text: '{"inside":true}' });
      assert.deepEqual(await body(server.origin, "/alias-dir/nested.json"), { status: 200, text: '{"nested":true}' });
      // Escapes: every response is a bodiless refusal.
      for (const escape of ["/linked.json", "/linked-dir/leak.json", "/linked-dir/leak.html", "/linked-abs-dir/leak.json"]) {
        const response = await body(server.origin, escape);
        assert.equal(response.status, 404, escape);
        assert.ok(!response.text.includes("leak"), escape);
      }
    } finally {
      await server.close();
    }
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("a mount root reached through a symlink still serves its own files", async () => {
  const base = mkdtempSync(path.join(tmpdir(), "fireemu-web-"));
  const real = path.join(base, "real-web");
  const link = path.join(base, "link-web");
  mkdirSync(real);
  writeFileSync(path.join(real, "page.html"), "<p>via link</p>");
  writeFileSync(path.join(base, "outside.html"), "leak");
  symlinkSync(path.join("..", "outside.html"), path.join(real, "escape.html"));
  symlinkSync("real-web", link);
  try {
    const server = await serveStatic({ "/": link });
    try {
      const page = await fetch(`${server.origin}/page.html`);
      assert.equal(page.status, 200);
      assert.equal(await page.text(), "<p>via link</p>");
      const escape = await fetch(`${server.origin}/escape.html`);
      assert.equal(escape.status, 404);
      assert.ok(!(await escape.text()).includes("leak"));
    } finally {
      await server.close();
    }
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
    "1 Listen POST handshake - 200",
    "2 Listen GET backchannel 1 200",
  ]);
  assert.deepEqual(parseWebChannelRow("5 Write POST terminate - -"),
    { atMs: 5, stream: "Write", method: "POST", role: "terminate", ci: null, status: null });
  assert.deepEqual(compactWebChannelRows(rows).map(parseWebChannelRow),
    rows.map(({ atMs, stream, method, role, ci, status }) => ({ atMs, stream, method, role, ci, status })));
  assert.throws(() => parseWebChannelRow("too short"), /malformed/);
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

test("the runner derives its directories from a checkout path with a space, a Japanese character and a percent sign", async () => {
  // Node resolves module paths through realpath, so compare with the real temporary directory.
  const base = await fs.realpath(mkdtempSync(path.join(tmpdir(), "fireemu-awkward-")));
  const tools = path.join(base, ...AWKWARD_SEGMENTS, "tools");
  try {
    mkdirSync(path.join(tools, "sdk-smoke-browser"), { recursive: true });
    for (const file of ["run-browser.mjs", "browser_harness.mjs"]) {
      cpSync(path.join(HERE, file), path.join(tools, "sdk-smoke-browser", file));
    }
    cpSync(WEB, path.join(tools, "sdk-smoke", "web"), { recursive: true });
    mkdirSync(path.join(tools, "compat-broad", "fs-listen-resume"), { recursive: true });
    cpSync(path.join(HERE, "..", "compat-broad", "fs-listen-resume", "listen_collector.mjs"),
      path.join(tools, "compat-broad", "fs-listen-resume", "listen_collector.mjs"));
    const copied = path.join(tools, "sdk-smoke-browser", "run-browser.mjs");
    const runner = await import(pathToFileURL(copied).href);
    const options = runner.parseArgs([], { FIRESTORE_EMULATOR_HOST: "127.0.0.1:8080",
      FIREBASE_AUTH_EMULATOR_HOST: "127.0.0.1:9099", GOOGLE_CLOUD_PROJECT: "demo-app" });
    assert.equal(options.playwrightDir, path.join(tools, "sdk-smoke-browser"));
    assert.equal(options.webDir, path.join(tools, "sdk-smoke", "web"));
    assert.ok(existsSync(options.playwrightDir));
    assert.ok(existsSync(options.webDir));
    // The runner's own static server starts from the derived directory.
    const server = await serveStatic({ "/": options.webDir });
    try {
      assert.equal((await fetch(`${server.origin}/listen-reconnect.html`)).status, 200);
    } finally {
      await server.close();
    }
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
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
