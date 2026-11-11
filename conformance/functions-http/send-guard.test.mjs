import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { captureFetch } from "./bearer-observation.mjs";
import { createBudget } from "./harness.mjs";
import {
  acquireToken,
  cli,
  createControl,
  createUser,
  isHarmlessCommand,
  PRIVATE_ROOT,
} from "./production.mjs";
import { productionDeps } from "./bearer-observation.mjs";
import { createTransport } from "./callable-ingress/rerecord.mjs";
import {
  SEND_FLAG,
  assertNotNativeRequest,
  assertPrivatePathAllowed,
  assertProductionSend,
  guardedFetch,
  guardedModules,
  guardedRequest,
  isLoopbackUrl,
} from "./send-guard.mjs";
import { runCases } from "./session.mjs";

// No test in this repository sets FIREEMU_PRODUCTION_SEND: these tests prove that, without it, every client
// that can reach a real service refuses before it sends anything.
const REFUSED = /refused; FIREEMU_PRODUCTION_SEND=1 is set by a launch script only/;

test("the flag is a launch script's alone: only the exact value 1 allows a send", () => {
  assert.equal(SEND_FLAG, "FIREEMU_PRODUCTION_SEND");
  assert.equal(process.env[SEND_FLAG], undefined, "the test run itself carries no send flag");
  assert.doesNotThrow(() => assertProductionSend("x", { FIREEMU_PRODUCTION_SEND: "1" }));
  for (const value of [undefined, "", "0", "true", "yes", " 1", "11"]) {
    assert.throws(() => assertProductionSend("x", { FIREEMU_PRODUCTION_SEND: value }), REFUSED);
  }
  assert.throws(() => assertProductionSend("x", {}), /^Error: x: refused/);
});

test("loopback URLs are this machine; anything else, and anything unparsable, is not", () => {
  for (const url of ["http://127.0.0.1:1/", "http://localhost/", "http://[::1]:8080/x"])
    assert.equal(isLoopbackUrl(url), true, url);
  for (const url of [
    "https://run.googleapis.com/",
    "http://127.0.0.1.example.com/",
    "http://localhost.example.com/",
    "http://10.0.0.1/",
    "not a url",
    "",
  ])
    assert.equal(isLoopbackUrl(url), false, url);
});

test("the guarded fetch refuses a real host without the flag, before any send, and names the host", async () => {
  await assert.rejects(
    guardedFetch("https://identitytoolkit.googleapis.com/v1/accounts:signUp"),
    REFUSED,
  );
  await assert.rejects(
    guardedFetch("https://nonexistent.invalid/"),
    /fetch nonexistent\.invalid: refused/,
  );
});

test("the guarded fetch lets a loopback server through and ignores a global fetch a test replaced", async () => {
  const server = http.createServer((req, res) => res.end("local"));
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  const original = globalThis.fetch;
  const seen = [];
  try {
    globalThis.fetch = async (url) => {
      seen.push(String(url));
      return new Response("stub");
    };
    const response = await guardedFetch(`http://127.0.0.1:${server.address().port}/`);
    assert.equal(await response.text(), "local", "the module's own fetch served it, not the stub");
    // a real host is refused whatever globalThis.fetch is: there is no allowance by object identity
    await assert.rejects(guardedFetch("https://run.googleapis.com/"), REFUSED);
    await assert.rejects(guardedFetch("https://run.invalid/"), REFUSED);
    assert.deepEqual(seen, [], "the replaced fetch was never called");
  } finally {
    globalThis.fetch = original;
    server.closeAllConnections?.();
    await new Promise((done) => server.close(done));
  }
});

test("node:http(s) requests are refused for a real host, with the default or a custom agent, before any socket", () => {
  const options = { hostname: "never.invalid", path: "/", method: "GET" };
  for (const protocol of ["https:", "http:"]) {
    assert.throws(() => guardedRequest(protocol, options), REFUSED, protocol);
    const module = guardedModules[protocol];
    assert.throws(() => module.request(options), REFUSED, `${protocol} module request`);
    const agent = new module.Agent({ keepAlive: true, maxSockets: 1 });
    assert.throws(() => module.request({ ...options, agent }), REFUSED, `${protocol} custom agent`);
    assert.throws(
      () => module.request({ host: "never.invalid", path: "/", agent }, () => {}),
      REFUSED,
      `${protocol} host form`,
    );
    agent.destroy();
  }
  // a missing host cannot slip through as "this machine"
  assert.throws(() => guardedRequest("https:", { path: "/" }), REFUSED);
  assert.throws(() => guardedRequest("http:", { hostname: "", path: "/" }), REFUSED);
});

test("node:http requests to this machine are served, through the guarded module and its own agent", async () => {
  const server = http.createServer((req, res) => res.end("local"));
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  const agent = new guardedModules["http:"].Agent({ keepAlive: false });
  try {
    const body = await new Promise((resolveBody, reject) => {
      const request = guardedModules["http:"].request(
        { hostname: "127.0.0.1", port: server.address().port, path: "/", agent },
        (res) => {
          const chunks = [];
          res.on("data", (chunk) => chunks.push(chunk));
          res.on("end", () => resolveBody(Buffer.concat(chunks).toString()));
        },
      );
      request.once("error", reject);
      request.end();
    });
    assert.equal(body, "local");
  } finally {
    agent.destroy();
    server.closeAllConnections?.();
    await new Promise((done) => server.close(done));
  }
});

test("the host a request really connects to is the one checked: node prefers hostname over host", () => {
  for (const protocol of ["https:", "http:"]) {
    // node connects to `hostname` when both are given, so a loopback `host` must not vouch for another `hostname`
    assert.throws(
      () => guardedRequest(protocol, { hostname: "never.invalid", host: "127.0.0.1", path: "/" }),
      REFUSED,
      `${protocol} hostname wins`,
    );
    assert.throws(
      () => guardedRequest(protocol, { hostname: "never.invalid", host: "localhost", path: "/" }),
      REFUSED,
    );
  }
});

test("the `host` form of a loopback request is served, and https really uses TLS", async () => {
  const server = http.createServer((req, res) => res.end("plain"));
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  const port = server.address().port;
  const get = (protocol, options) =>
    new Promise((resolveBody, reject) => {
      const request = guardedRequest(protocol, { path: "/", port, ...options }, (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => resolveBody(Buffer.concat(chunks).toString()));
      });
      request.once("error", reject);
      request.end();
    });
  try {
    assert.equal(await get("http:", { host: "127.0.0.1", agent: false }), "plain");
    // the https path speaks TLS: a plain-HTTP server cannot answer it (the http module would be served)
    await assert.rejects(get("https:", { hostname: "127.0.0.1", agent: false }));
  } finally {
    server.closeAllConnections?.();
    await new Promise((done) => server.close(done));
  }
});

test("the real request functions are refused as a transport's replacement; a double is accepted", () => {
  const double = { Agent: class {}, request: () => ({}) };
  assert.doesNotThrow(() => assertNotNativeRequest({ "https:": double, "http:": double }));
  for (const real of [http.request, https.request]) {
    assert.throws(
      () => assertNotNativeRequest({ "https:": { Agent: https.Agent, request: real } }),
      /real node:http\(s\) request is refused/,
    );
    assert.throws(
      () =>
        createTransport({
          delayMs: 0,
          modules: { "https:": { Agent: https.Agent, request: real }, "http:": double },
        }),
      /real node:http\(s\) request is refused/,
    );
  }
  assert.throws(
    () => assertNotNativeRequest({ "https:": { request: () => ({}) } }),
    /need an Agent and a request/,
  );
  assert.throws(
    () => assertNotNativeRequest({ "https:": { Agent: class {} } }),
    /need an Agent and a request/,
  );
});

test("every production client refuses without the flag: ADC refresh, REST control, Auth sign-up, the Firebase CLI", async () => {
  const adc = { refresh_token: "r", client_id: "c", client_secret: "s" };
  const budget = createBudget();
  await assert.rejects(acquireToken(adc, budget, "token"), REFUSED);
  const control = createControl(adc, budget);
  await assert.rejects(
    control("GET", "https://cloudfunctions.googleapis.com/v2/projects/p"),
    REFUSED,
  );
  await assert.rejects(
    createUser("k".repeat(24), budget, "/nonexistent", "program-x"),
    /ENOENT|refused/,
  );
  // createUser journals first, then sends: with no run directory it stops at the journal, and with one it refuses.
  const { mkdtemp, rm } = await import("node:fs/promises");
  const dir = await mkdtemp(join(tmpdir(), "send-guard-"));
  try {
    await assert.rejects(createUser("k".repeat(24), createBudget(), dir, "program-x"), REFUSED);
    await assert.rejects(
      cli(["deploy"], "/adc", createBudget(), "cliDeploy", dir, undefined),
      REFUSED,
    );
    // a harmless command is not the real CLI: it is not refused by the guard
    await assert.rejects(
      cli(["deploy"], "/adc", createBudget(), "cliDeploy", dir, undefined, [
        process.execPath,
        "-e",
        "process.exit(1)",
      ]),
      /failed or attempted API enablement/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("the default fetch of the session and of the capture is the guarded one", async () => {
  const program = {
    id: "p",
    cases: [
      { id: "c", target: "http", request: { method: "GET", path: "/" }, capture: "complete" },
    ],
  };
  await assert.rejects(
    runCases(program, { http: "https://example.invalid/fn" }, {}, createBudget()),
    REFUSED,
  );
  await assert.rejects(
    captureFetch({ onCapture: () => {} })("https://example.invalid/", {
      method: "GET",
      headers: {},
    }),
    REFUSED,
  );
});

test("the invocation transport refuses a real host without the flag, on https and http, and serves this machine", async () => {
  const transport = createTransport({ delayMs: 0 });
  const init = { method: "POST", headers: { "content-type": "application/json" }, body: "{}" };
  try {
    await assert.rejects(
      transport.fetchImpl("https://fireemucallableprobe-abc-uc.a.run.app/", init),
      REFUSED,
    );
  } finally {
    transport.close();
  }
  for (const url of ["https://never.invalid/", "http://never.invalid/"]) {
    const each = createTransport({ delayMs: 0 });
    try {
      await assert.rejects(each.fetchImpl(url, init), REFUSED, url);
    } finally {
      each.close();
    }
  }
  const server = http.createServer((req, res) => res.end("ok"));
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  const local = createTransport({ delayMs: 0 });
  try {
    const response = await local.fetchImpl(`http://127.0.0.1:${server.address().port}/`, init);
    assert.equal(await response.text(), "ok");
  } finally {
    local.close();
    server.closeAllConnections?.();
    await new Promise((done) => server.close(done));
  }
});

test("the bearer recorder's production dependencies send through the guard", async () => {
  const deps = productionDeps({ caps: { upload: 1 } });
  await assert.rejects(deps.fetchImpl("https://never.invalid/", { method: "GET" }), REFUSED);
  assert.equal(deps.fetchImpl, guardedFetch);
});

test("the Firebase CLI is refused unless the command is a harmless child of this node", () => {
  assert.equal(isHarmlessCommand([process.execPath, "-e", "0"]), true);
  assert.equal(
    isHarmlessCommand([process.execPath, join(tmpdir(), "x.mjs")]),
    false,
    "a missing file",
  );
  assert.equal(
    isHarmlessCommand([process.execPath, "deploy"]),
    false,
    "a CLI verb is not a script",
  );
  for (const command of [
    undefined,
    [],
    ["firebase", "deploy"],
    ["/usr/local/bin/firebase"],
    [process.execPath],
    [process.execPath, "/etc/hosts"],
    [
      process.execPath,
      resolve(
        dirname(fileURLToPath(import.meta.url)),
        "../../node_modules/firebase-tools/lib/bin/firebase.js",
      ),
    ],
    ["/bin/sh", "-e"],
  ])
    assert.equal(isHarmlessCommand(command), false, JSON.stringify(command));
});

const HERE = dirname(fileURLToPath(import.meta.url));

function sources(dir = HERE) {
  const found = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name === "fixtures") continue;
    const path = join(dir, entry.name);
    if (entry.isDirectory()) found.push(...sources(path));
    else if (entry.name.endsWith(".mjs") && !entry.name.endsWith(".test.mjs")) found.push(path);
  }
  return found;
}

const codeLines = (text) => text.split("\n").filter((line) => !/^\s*(\/\/|\*|\/\*)/u.test(line));

test("no production source of this directory calls the network except through send-guard.mjs", () => {
  const offenders = [];
  for (const path of sources()) {
    const name = relative(HERE, path);
    if (name === "send-guard.mjs") continue;
    for (const line of codeLines(readFileSync(path, "utf8"))) {
      if (
        /node:(https?|net|tls|http2|dgram|dns)\b/u.test(line) ||
        /(?<![\w.$])fetch\s*\(/u.test(line) ||
        /globalThis\.fetch|\bnativeFetch\b|\bXMLHttpRequest\b|\bWebSocket\b|\bEventSource\b/u.test(
          line,
        ) ||
        /\bimport\s*\(\s*["']node:(https?|net|tls|http2|dgram|dns)\b/u.test(line)
      )
        offenders.push(`${name}: ${line.trim()}`);
    }
  }
  assert.deepEqual(offenders, []);
});

test("only the known files start a child process, and the real Firebase CLI's spawn checks the flag", () => {
  const spawners = sources()
    .filter((path) =>
      /(?<![.\w$])(spawn|execFile|execFileSync|exec|execSync|fork)\s*\(/u.test(
        codeLines(readFileSync(path, "utf8")).join("\n"),
      ),
    )
    .map((path) => relative(HERE, path))
    .toSorted();
  assert.deepEqual(spawners, [
    "bearer-observation.mjs",
    "callable-ingress/observation.mjs",
    "callable-ingress/rerecord.mjs",
    "production.mjs",
    "run.mjs",
    "upload-probe.mjs",
  ]);
  const production = readFileSync(join(HERE, "production.mjs"), "utf8");
  const spawn = production.indexOf("const child = spawn(\n    command[0]");
  const guard = production.indexOf('assertProductionSend("the Firebase CLI")');
  assert.ok(guard > 0 && spawn > guard, "the CLI guard comes before the CLI spawn");
});

test("a private path outside the mutation work copy is refused while the harness runs, and allowed otherwise", () => {
  const work = mkdtempSync(join(tmpdir(), "guard-work-"));
  try {
    const env = { FIREEMU_MUTATION_WORK: work };
    assertPrivatePathAllowed("/anywhere/at/all", {});
    assertPrivatePathAllowed("/anywhere/at/all", { FIREEMU_MUTATION_WORK: "" });
    assert.doesNotThrow(() => assertPrivatePathAllowed(work, env));
    assert.doesNotThrow(() => assertPrivatePathAllowed(join(work, "docs.local/runs/x"), env));
    // a symlink inside the work copy that points out of it does not make the target inside
    symlinkSync("/etc", join(work, "link-out"));
    assert.throws(
      () => assertPrivatePathAllowed(join(work, "link-out/hosts"), env),
      /outside the mutation work copy is refused/,
    );
    for (const outside of [
      "/etc/hosts",
      join(homedirOf(), ".config/gcloud/application_default_credentials.json"),
      resolve(work, ".."),
      `${work}-sibling/file`,
      join(work, "..", "elsewhere"),
      join(work, "a/../../escape"),
    ])
      assert.throws(
        () => assertPrivatePathAllowed(outside, env),
        /outside the mutation work copy is refused/,
        outside,
      );
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});

function homedirOf() {
  return process.env.HOME || tmpdir();
}

test("the work copy is judged by its real path, and a work copy that does not exist yet by where it would be", () => {
  const base = mkdtempSync(join(tmpdir(), "guard-real-"));
  try {
    const real = join(base, "real");
    mkdirSync(real);
    symlinkSync(real, join(base, "alias"));
    // a work copy named through a symlink: a file inside it, named by its real path, is inside
    assert.doesNotThrow(() =>
      assertPrivatePathAllowed(join(real, "docs.local/x"), {
        FIREEMU_MUTATION_WORK: join(base, "alias"),
      }),
    );
    assert.doesNotThrow(() =>
      assertPrivatePathAllowed(join(base, "alias/docs.local/x"), { FIREEMU_MUTATION_WORK: real }),
    );
    // a work copy that does not exist yet: only its own subtree is inside, not the directory around it
    const env = { FIREEMU_MUTATION_WORK: join(base, "not-yet") };
    assert.doesNotThrow(() => assertPrivatePathAllowed(join(base, "not-yet/a/b"), env));
    assert.throws(
      () => assertPrivatePathAllowed(join(base, "other/file"), env),
      /outside the mutation work copy/,
    );
    assert.throws(
      () => assertPrivatePathAllowed(join(base, "not-yet-sibling/x"), env),
      /outside the mutation work copy/,
    );
    assert.throws(
      () => assertPrivatePathAllowed(join(base, "x"), env),
      /outside the mutation work copy/,
    );
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("with the harness variable set, production.mjs refuses a private root and private files outside the work copy", () => {
  const work = mkdtempSync(join(tmpdir(), "guard-work-"));
  const elsewhere = mkdtempSync(join(tmpdir(), "guard-else-"));
  const run = (workDir, code) =>
    execFileSync(process.execPath, ["--input-type=module", "-e", code], {
      cwd: HERE,
      encoding: "utf8",
      env: {
        PATH: process.env.PATH ?? "",
        FIREEMU_MUTATION_WORK: workDir,
        HOME: elsewhere,
        // outside every work copy the tests make, whatever the temp directory is
        FIREEMU_OWNER_ADC: "/usr/share/fireemu-guard-test/adc.json",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
  try {
    // the private root of the real repository is outside an unrelated work copy: importing fails closed
    assert.throws(
      () => run(work, `await import(${JSON.stringify(join(HERE, "production.mjs"))})`),
      (error) => /outside the mutation work copy is refused/.test(String(error.stderr)),
    );
    // with the work copy being the repository's parent (where the private root is), the root is allowed but a
    // file elsewhere is not, for the owner credential and for the project identity alike
    const parent = dirname(PRIVATE_ROOT);
    const code = `
      const production = await import(${JSON.stringify(join(HERE, "production.mjs"))});
      const results = [];
      for (const attempt of [
        () => production.ownerAdc(),
        () => production.readPrivateProjectIdentity(${JSON.stringify("/usr/share/fireemu-guard-test/identity")}, "x"),
      ]) {
        try { await attempt(); results.push("allowed"); } catch (error) { results.push(String(error.message)); }
      }
      console.log(JSON.stringify(results));
    `;
    const out = JSON.parse(run(parent, code).trim().split("\n").at(-1));
    assert.equal(out.length, 2);
    for (const message of out) assert.match(message, /outside the mutation work copy is refused/);
  } finally {
    rmSync(work, { recursive: true, force: true });
    rmSync(elsewhere, { recursive: true, force: true });
  }
});

test("named fixtures are deleted by codebase-qualified ids only (see production.test.mjs for the arguments)", () => {
  const source = readFileSync(join(HERE, "production.mjs"), "utf8");
  assert.doesNotMatch(source, /"functions:delete",\s*spec\.functionName/u);
});
