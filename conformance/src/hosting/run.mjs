/** Offline comparison of the pinned Hosting implementation stack and fireemu. */
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFile, writeFile, mkdtemp, mkdir, rm, utimes } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import http from "node:http";
import vm from "node:vm";
import { createHash } from "node:crypto";
import net from "node:net";
import { spawn } from "node:child_process";

const fixtureRoot = fileURLToPath(new URL("../../hosting-fixtures/", import.meta.url));
const corpus = JSON.parse(await readFile(resolve(fixtureRoot, "cases.json"), "utf8"));
const require = createRequire(import.meta.url);
const firebasePackage = require.resolve("firebase-tools/package.json");
const officialRequire = createRequire(firebasePackage);
const officialRoot = dirname(firebasePackage);
const initTemplate = await readFile(resolve(officialRoot, "templates/hosting/init.js"), "utf8");
const initJson = JSON.stringify({ apiKey: "fireemu-local-only", projectId: "demo-hosting" });
const initScript = (emulators) =>
  initTemplate
    .replace("/*--CONFIG--*/", `var firebaseConfig = ${initJson};`)
    .replace("/*--EMULATORS--*/", `var firebaseEmulators = ${emulators};`);
const syntheticInit = {
  json: initJson,
  js: initScript("undefined"),
  emulatorsJs: initScript("{}"),
};
const selectedHeaders = [
  "content-type",
  "cache-control",
  "location",
  "etag",
  "x-fixture",
  "vary",
  "last-modified",
];
const listen = async (server) => {
  await new Promise((yes, no) => {
    server.once("error", no);
    server.listen(0, "127.0.0.1", yes);
  });
  return server.address().port;
};
const close = async (server) => {
  server.closeAllConnections?.();
  await new Promise((yes) => server.close(yes));
};

export async function noEgressProof() {
  // A literal external address avoids DNS and credentials. The container must use --network none.
  const result = await new Promise((yes) => {
    const socket = net.connect({ host: "192.0.2.1", port: 443 });
    socket.setTimeout(1000);
    socket.once("connect", () => {
      socket.destroy();
      yes("CONNECTED");
    });
    socket.once("error", (e) => yes(e.code));
    socket.once("timeout", () => {
      socket.destroy();
      yes("TIMEOUT");
    });
  });
  assert.notEqual(result, "CONNECTED", "external network is reachable");
  assert.equal(
    process.env.HOSTING_NETWORK_NONE,
    "1",
    "run in an independently inspected network-none container",
  );
  return { destination: "192.0.2.1:443", result };
}

export async function request(port, test) {
  return new Promise((yes, no) => {
    const req = http.request(
      {
        hostname: "127.0.0.1",
        port,
        path: test.path,
        method: test.method,
        headers: { "accept-encoding": "identity", ...test.headers },
        timeout: 5000,
      },
      (res) => {
        const chunks = [];
        let size = 0;
        res.on("data", (c) => {
          size += c.length;
          if (size > 65536) req.destroy(new Error("response bound exceeded"));
          else chunks.push(c);
        });
        res.on("end", () =>
          yes({
            id: test.id,
            status: res.statusCode,
            headers: Object.fromEntries(
              selectedHeaders
                .filter((k) => res.headers[k] !== undefined)
                .map((k) => [k, res.headers[k]]),
            ),
            body: Buffer.concat(chunks).toString("utf8"),
          }),
        );
      },
    );
    req.on("error", no);
    req.on("timeout", () => req.destroy(new Error("request deadline")));
    req.end(test.body);
  });
}

async function official() {
  assert.equal(JSON.parse(await readFile(firebasePackage, "utf8")).version, "15.28.2");
  const manifest = JSON.parse(await readFile(resolve(fixtureRoot, "manifest.json"), "utf8"));
  for (const path of manifest.files.filter((p) => p.startsWith("public")))
    await utimes(resolve(fixtureRoot, path), 946684800, 946684800);
  const { server } = officialRequire("superstatic");
  const { initMiddleware } = require(resolve(officialRoot, "lib/hosting/initMiddleware.js"));
  const { functionsProxy } = require(resolve(officialRoot, "lib/hosting/functionsProxy.js"));
  const { default: runProxy } = require(resolve(officialRoot, "lib/hosting/cloudRunProxy.js"));
  const { EmulatorRegistry } = require(resolve(officialRoot, "lib/emulator/registry.js"));
  const { configMatcher } = officialRequire("superstatic/lib/utils/patterns.js");
  const upstream = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    res.setHeader("content-type", "application/json");
    res.end(
      JSON.stringify({ method: req.method, path: req.url, body: Buffer.concat(chunks).toString() }),
    );
  });
  const upstreamPort = await listen(upstream);
  EmulatorRegistry.set("functions", { getInfo: () => ({ host: "127.0.0.1", port: upstreamPort }) });
  const options = { project: "demo-hosting", targets: ["functions"] };
  const rows = [];
  try {
    for (const [name, config] of Object.entries(corpus.configs)) {
      const app = await new Promise((yes, no) => {
        const listener = server({
          port: 0,
          config: structuredClone(config),
          cwd: fixtureRoot,
          hostname: "127.0.0.1",
          stack: "strict",
          compression: true,
          before: { files: initMiddleware(syntheticInit) },
          rewriters: { function: functionsProxy(options), run: runProxy(options) },
        }).listen(() => yes(listener));
        listener.once("error", no);
      });
      const port = app.address().port;
      try {
        for (const test of corpus.cases.filter((c) => c.config === name))
          rows.push(await request(port, test));
      } finally {
        await close(app);
      }
    }
    const globs = JSON.parse(await readFile(resolve(fixtureRoot, "glob-cases.json"), "utf8")).map(
      (c) => Object.assign({}, c, { matches: configMatcher(c.path, { source: c.pattern }) }),
    );
    return { rows, globs };
  } finally {
    EmulatorRegistry.clear("functions");
    await close(upstream);
  }
}

async function fireemu(binary) {
  const rows = [];
  for (const [name, config] of Object.entries(corpus.configs)) {
    const temp = await mkdtemp(resolve(tmpdir(), "hosting-"));
    await mkdir(resolve(temp, "home"));
    const ready = resolve(temp, "ready.json");
    // The official-emulator fixtures describe the emulator profile; the strict profile answers as
    // Hosting production does (conformance/src/hosting-production).
    await writeFile(
      resolve(temp, "profile.json"),
      JSON.stringify({ schemaVersion: 1, profile: "emulator" }),
    );
    await writeFile(
      resolve(temp, "firebase.json"),
      JSON.stringify({
        hosting: { ...config, public: resolve(fixtureRoot, config.public) },
        ...(name === "default" ? { functions: { source: resolve(fixtureRoot, "functions") } } : {}),
        emulators: {
          functions: { port: 0 },
          hosting: { port: 0 },
          ui: { enabled: false },
          logging: { port: 0 },
          hub: { port: 0 },
        },
      }),
    );
    const child = spawn(
      binary,
      [
        "up",
        "--config",
        resolve(temp, "profile.json"),
        "--only",
        name === "default" ? "hosting,functions" : "hosting",
        "--project",
        "demo-hosting",
        "--firebase-json",
        resolve(temp, "firebase.json"),
        "--ready-file",
        ready,
        "--owner-stdin",
        "--log-verbosity",
        "quiet",
      ],
      {
        env: { PATH: process.env.PATH, HOME: resolve(temp, "home") },
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    let stderr = "";
    child.stderr.on("data", (c) => (stderr += c));
    child.stdout.resume();
    try {
      let descriptor;
      for (let i = 0; i < 200; i++) {
        if (child.exitCode !== null)
          throw new Error(`Hosting must start: exit=${child.exitCode}: ${stderr}`);
        try {
          descriptor = JSON.parse(await readFile(ready, "utf8"));
          break;
        } catch {}
        await new Promise((r) => setTimeout(r, 50));
      }
      assert.ok(descriptor, "Hosting readiness deadline");
      const port = Number(new URL(descriptor.hostingUrl).port);
      for (const test of corpus.cases.filter((c) => c.config === name)) {
        const row = await request(port, test);
        rows.push(row);
        console.log(JSON.stringify({ actual: row }));
      }
    } finally {
      child.stdin.end();
      await Promise.race([
        new Promise((r) => child.once("exit", r)),
        new Promise((r) => setTimeout(r, 5000)),
      ]);
      if (child.exitCode === null) {
        child.kill("SIGTERM");
        await new Promise((r) => child.once("exit", r));
      }
      await rm(temp, { recursive: true, force: true });
    }
  }
  return rows;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const proof = await noEgressProof();
  if (process.argv[2] === "official") {
    const result = await official();
    await writeFile(
      resolve(fixtureRoot, "official.json"),
      JSON.stringify(
        {
          pin: "firebase-tools@15.28.2",
          stack:
            "actual superstatic strict + Hosting init/functions/run middleware and init template, synthetic project config",
          inputs: {
            runnerSha256: createHash("sha256")
              .update(await readFile(fileURLToPath(import.meta.url)))
              .digest("hex"),
            corpusSha256: createHash("sha256")
              .update(await readFile(resolve(fixtureRoot, "cases.json")))
              .digest("hex"),
            lockSha256: createHash("sha256")
              .update(await readFile(resolve(fixtureRoot, "../pnpm-lock.yaml")))
              .digest("hex"),
          },
          noEgress: proof,
          rows: result.rows,
        },
        null,
        2,
      ) + "\n",
      { flag: "wx" },
    );
    await writeFile(
      resolve(fixtureRoot, "official-globs.json"),
      JSON.stringify(result.globs, null, 2) + "\n",
      { flag: "wx" },
    );
    console.log(
      JSON.stringify({ rows: result.rows.length, globCases: result.globs.length, noEgress: proof }),
    );
  } else if (process.argv[2] === "fireemu") {
    const actual = await fireemu(resolve(process.argv[3]));
    const expected = JSON.parse(await readFile(resolve(fixtureRoot, "official.json"), "utf8")).rows;
    const normalize = (row) => {
      if (!["reserved-js", "reserved-emulator-js"].includes(row.id)) return row;
      const calls = [];
      vm.runInNewContext(
        row.body,
        { firebase: { initializeApp: (c) => calls.push(c) }, console: { log: () => {} } },
        { timeout: 100 },
      );
      return { ...row, body: JSON.stringify(calls) };
    };
    for (const row of actual)
      assert.deepEqual(normalize(row), normalize(expected.find((e) => e.id === row.id)), row.id);
    console.log(JSON.stringify({ pass: actual.length, noEgress: proof }));
  } else throw new Error("usage: run.mjs official | fireemu <binary>");
}
