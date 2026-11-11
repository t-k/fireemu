// Guards against a test or a mutation run reaching the real service (coordinator safety notice, 2026-11-11).
// The first three tests run everywhere. The last one runs under the mutation harness only
// (NEGCACHE_MUTATION=1) and asserts the isolation the harness promises before any mutant runs.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import http from "node:http";
import https from "node:https";

import { assertCredentialsAllowed, assertSendAllowed, productionSendApproved } from "./guard.mjs";
import { main, SEND_FLAG, SEND_FLAG_VALUE } from "./run.mjs";
import { createTransport } from "./transport.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const id = "abcdef123456";

test("the flag predicate: loopback needs nothing, every other host needs the exact flag", () => {
  for (const host of ["127.0.0.1", "::1", "localhost"])
    assert.doesNotThrow(() => assertSendAllowed(host, {}));
  for (const host of [
    "pubsub.googleapis.com",
    "example.com",
    "192.0.2.1",
    "127.0.0.2",
    "LOCALHOST",
    "",
  ])
    assert.throws(() => assertSendAllowed(host, {}), /production send flag/, host);
  assert.throws(
    () => assertSendAllowed("pubsub.googleapis.com", { [SEND_FLAG]: "1" }),
    /production send flag/,
  );
  assert.throws(
    () => assertSendAllowed("pubsub.googleapis.com", { [SEND_FLAG]: "launch-scrip" }),
    /production send flag/,
  );
  assert.doesNotThrow(() =>
    assertSendAllowed("pubsub.googleapis.com", { [SEND_FLAG]: SEND_FLAG_VALUE }),
  );
  assert.throws(() => assertCredentialsAllowed({}), /credentials/);
  assert.throws(() => assertCredentialsAllowed({ [SEND_FLAG]: "x" }), /credentials/);
  assert.doesNotThrow(() => assertCredentialsAllowed({ [SEND_FLAG]: SEND_FLAG_VALUE }));
  assert.equal(productionSendApproved({}), false);
  assert.equal(productionSendApproved({ [SEND_FLAG]: SEND_FLAG_VALUE }), true);
});

test("this process has no flag", () => {
  assert.equal(process.env[SEND_FLAG], undefined);
  assert.equal(productionSendApproved(), false);
});

for (const host of ["pubsub.googleapis.com", "example.invalid"])
  for (const protocol of ["https", "http"])
    for (const connPolicy of ["pool", "dedicated", "fresh"])
      test(`a ${protocol} ${connPolicy} send to ${host} is refused before any socket is opened`, async (t) => {
        const calls = [];
        for (const lib of [https, http])
          t.mock.method(
            lib,
            "request",
            (...args) => (calls.push(args), assert.fail("a request was made")),
          );
        const transport = createTransport({
          getToken: () => "token-value",
          clock: { now: () => 0 },
          protocol,
          host,
          port: 443,
        });
        t.after(() => transport.close());
        await assert.rejects(
          transport.send(
            { method: "GET", path: "/v1/x" },
            { conn: "c", connPolicy, timeoutMs: 50 },
          ),
          (error) => {
            assert.match(error.message, /production send flag/);
            assert.ok(!error.message.includes("token-value"));
            return true;
          },
        );
        assert.equal(calls.length, 0);
      });

test("a gRPC send, with the default client or an injected call, is refused before anything runs", async () => {
  let injected = 0;
  const base = {
    getToken: () => "t",
    clock: { now: () => 0 },
    host: "pubsub.googleapis.com",
    port: 443,
  };
  const request = { grpc: true, path: "projects/p/subscriptions/s" };
  await assert.rejects(
    createTransport(base).send(request, { timeoutMs: 50 }),
    /production send flag/,
  );
  const withCall = createTransport({ ...base, grpcCall: async () => (injected++, { code: "OK" }) });
  await assert.rejects(withCall.send(request, { timeoutMs: 50 }), /production send flag/);
  assert.equal(injected, 0);
});

test("a real transport injected into record or a2 cannot send either: the first send is refused and nothing is written to the network", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "nc-guard-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.writeFileSync(
    path.join(root, "lock"),
    JSON.stringify({ pid: process.pid, packetId: "PUBSUB-NEGCACHE" }),
  );
  fs.writeFileSync(path.join(root, "packet"), "packet");
  for (const lib of [https, http])
    t.mock.method(lib, "request", () => assert.fail("a request was made"));
  const transport = createTransport({ getToken: () => "t", clock: { now: () => 0 } });
  t.after(() => transport.close());
  await assert.rejects(
    main(["record", "--run-id", id, "--out", "out", "--lock", "lock", "--packet", "packet"], {
      root,
      env: {},
      token: "t",
      transport,
      sourceHead: "h",
      print() {},
    }),
    /production send flag/,
  );
});

test("the credential helper is a production client: it is refused without the flag even when a transport and a token are injected elsewhere", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "nc-guard-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.writeFileSync(
    path.join(root, "lock"),
    JSON.stringify({ pid: process.pid, packetId: "PUBSUB-NEGCACHE" }),
  );
  fs.writeFileSync(path.join(root, "packet"), "packet");
  const transport = { send: async () => assert.fail("sent"), close() {} };
  await assert.rejects(
    main(["record", "--run-id", id, "--out", "out", "--lock", "lock", "--packet", "packet"], {
      root,
      env: {},
      transport,
      sourceHead: "h",
      print() {},
    }),
    /production send flag/,
  );
});

test("record and a2 refuse to start real clients without the flag, before any credential is read", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "nc-guard-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.writeFileSync(
    path.join(root, "lock"),
    JSON.stringify({ pid: process.pid, packetId: "PUBSUB-NEGCACHE" }),
  );
  fs.writeFileSync(path.join(root, "packet"), "packet");
  let credentialsAsked = 0;
  const deps = {
    root,
    env: {},
    print() {},
    createCredentials: () => (credentialsAsked++, async () => "t"),
  };
  await assert.rejects(
    main(["record", "--run-id", id, "--out", "out", "--lock", "lock", "--packet", "packet"], deps),
    new RegExp(SEND_FLAG),
  );
  fs.mkdirSync(path.join(root, "from"));
  await assert.rejects(
    main(["a2", "--run-id", id, "--from", "from", "--out", "o2", "--lock", "lock"], deps),
    new RegExp(SEND_FLAG),
  );
  // A wrong value is no flag either.
  await assert.rejects(
    main(["record", "--run-id", id, "--out", "out", "--lock", "lock", "--packet", "packet"], {
      ...deps,
      env: { [SEND_FLAG]: "1" },
    }),
    new RegExp(SEND_FLAG),
  );
  assert.equal(credentialsAsked, 0);
  assert.equal(SEND_FLAG_VALUE, "launch-script");
});

test("no test sets the production flag", () => {
  for (const file of fs
    .readdirSync(here)
    .filter((f) => f.endsWith(".test.mjs") && f !== "guard.test.mjs")) {
    const text = fs.readFileSync(path.join(here, file), "utf8");
    assert.ok(
      !text.includes(SEND_FLAG) && !text.includes(SEND_FLAG_VALUE),
      `${file} mentions the production flag`,
    );
    assert.ok(!text.includes("allowProduction"), `${file} asks for a production transport`);
  }
});

test(
  "under the mutation harness: an empty temp HOME, no credentials, its own git root",
  { skip: process.env.NEGCACHE_MUTATION !== "1" && "runs under the mutation harness only" },
  () => {
    const home = process.env.HOME;
    // HOME and TMPDIR are siblings inside the slot: an empty home next to the slot's temp directory.
    assert.ok(home && path.isAbsolute(home), "HOME must be set");
    assert.equal(
      path.dirname(fs.realpathSync(home)),
      path.dirname(fs.realpathSync(os.tmpdir())),
      "HOME and TMPDIR must be siblings in the slot",
    );
    assert.ok(
      !path.resolve(home).startsWith(process.env.NEGCACHE_REAL_HOME ?? "/nonexistent/"),
      "HOME must not be the real home",
    );
    assert.deepEqual(fs.readdirSync(home), [], "HOME must be empty");
    for (const name of Object.keys(process.env)) {
      assert.ok(
        !/^(GOOGLE_APPLICATION_CREDENTIALS|FIREBASE_TOKEN|CLOUDSDK_.*|GCLOUD_.*|GOOGLE_CLOUD_.*)$/.test(
          name,
        ),
        `${name} must not be set`,
      );
    }
    assert.ok(!process.env[SEND_FLAG]);
    assert.ok(!fs.existsSync(path.join(home, ".config", "gcloud")));
    // The work copy is its own git root, and no ancestor directory holds the private docs.local.
    const top = fs.realpathSync(
      execFileSync("git", ["rev-parse", "--show-toplevel"], { cwd: here, encoding: "utf8" }).trim(),
    );
    assert.ok(here.startsWith(top), "git root must contain the work copy");
    assert.ok(!fs.existsSync(path.join(top, "docs.local")));
    for (let dir = here; dir !== path.dirname(dir); dir = path.dirname(dir))
      assert.ok(!fs.existsSync(path.join(dir, "docs.local")), `${dir} contains docs.local`);
    assert.ok(
      !fs.realpathSync(here).includes(`${path.sep}.worktree${path.sep}`),
      "the work copy must be outside the repository",
    );
  },
);

const sandboxed = process.env.NEGCACHE_SANDBOX === "1";
const skipUnlessSandboxed = !sandboxed && "runs under the mutation harness's OS sandbox only";

test(
  "sandbox: network and file barrier (outbound is refused by the OS, loopback works, the real docs.local and HOME are untouchable)",
  { skip: skipUnlessSandboxed },
  async () => {
    const connect = (host, port) =>
      new Promise((resolve) => {
        const socket = net.connect({ host, port, timeout: 3000 });
        socket.on("connect", () => (socket.destroy(), resolve("connected")));
        socket.on("timeout", () => (socket.destroy(), resolve("timeout")));
        socket.on("error", (error) => resolve(error.code));
      });
    // Non-routable documentation addresses: a refusal by the sandbox is EPERM at once; nothing real is addressed.
    for (const host of ["192.0.2.1", "198.51.100.7", "203.0.113.9"])
      assert.equal(await connect(host, 443), "EPERM", host);
    assert.equal(await connect("::ffff:192.0.2.1", 443), "EPERM");
    // A name lookup plus an HTTPS request to the real service never produces a response.
    const outcome = await new Promise((resolve) => {
      const request = https.get(
        { host: "pubsub.googleapis.com", path: "/", timeout: 3000 },
        (response) => (response.resume(), resolve(`response ${response.statusCode}`)),
      );
      request.on("error", (error) => resolve(error.code));
      request.on("timeout", () => (request.destroy(), resolve("timeout")));
    });
    assert.ok(["EPERM", "ENOTFOUND", "EAI_AGAIN", "ECONNREFUSED"].includes(outcome), outcome);
    // Loopback still works (the transport tests depend on it).
    const server = http.createServer((req, res) => res.end("ok"));
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    assert.equal(await connect("127.0.0.1", server.address().port), "connected");
    await new Promise((resolve) => server.close(resolve));

    const realDocs = process.env.NEGCACHE_REAL_DOCS_LOCAL;
    const realHome = process.env.NEGCACHE_REAL_HOME;
    assert.ok(
      realDocs &&
        path.isAbsolute(realDocs) &&
        fs.existsSync(realDocs.replace(/\/docs\.local$/, "")),
      `private root ${realDocs}`,
    );
    assert.ok(realHome && path.isAbsolute(realHome));
    assert.notEqual(path.resolve(realHome), path.resolve(process.env.HOME));
    const code = (fn) => {
      try {
        fn();
        return "allowed";
      } catch (error) {
        return error.code;
      }
    };
    assert.equal(
      code(() => fs.writeFileSync(path.join(realDocs, "negcache-sandbox-probe"), "x")),
      "EPERM",
    );
    assert.equal(
      code(() => fs.mkdirSync(path.join(realDocs, "negcache-sandbox-probe-dir"))),
      "EPERM",
    );
    assert.equal(
      code(() => fs.appendFileSync(path.join(realDocs, "runs", "sandbox-ledger.jsonl"), "{}\n")),
      "EPERM",
    );
    assert.equal(
      code(() => fs.readdirSync(realDocs)),
      "EPERM",
    );
    assert.equal(
      code(() => fs.readFileSync(path.join(realDocs, "sandbox-oracles.md"))),
      "EPERM",
    );
    assert.equal(
      code(() => fs.writeFileSync(path.join(realHome, ".negcache-sandbox-probe"), "x")),
      "EPERM",
    );
    assert.equal(
      code(() => fs.readdirSync(path.join(realHome, ".config"))),
      "EPERM",
    );
    assert.equal(
      code(() => fs.writeFileSync(path.join(os.tmpdir(), "negcache-sandbox-probe"), "x")),
      "allowed",
    );
    assert.equal(
      code(() => fs.writeFileSync(path.join(here, "..", "negcache-sandbox-probe"), "x")),
      "allowed",
    );
    // Nothing above left a file in the real tree.
    assert.ok(!fs.existsSync(path.join(realDocs, "negcache-sandbox-probe")));
  },
);

test("sandbox: a spawned child inherits the barrier", { skip: skipUnlessSandboxed }, () => {
  const out = execFileSync(
    process.execPath,
    [
      "-e",
      "const net=require('node:net');const s=net.connect({host:'192.0.2.1',port:443});s.on('error',e=>{console.log(e.code);process.exit(0)});s.on('connect',()=>{console.log('connected');process.exit(0)});setTimeout(()=>{console.log('timeout');process.exit(0)},3000)",
    ],
    { encoding: "utf8" },
  ).trim();
  assert.equal(out, "EPERM");
});

test("an allowProduction option stands in for nothing: the transport still refuses without the flag", async (t) => {
  for (const lib of [https, http])
    t.mock.method(lib, "request", () => assert.fail("a request was made"));
  const transport = createTransport({
    getToken: () => "t",
    clock: { now: () => 0 },
    allowProduction: true,
  });
  t.after(() => transport.close());
  await assert.rejects(
    transport.send({ method: "GET", path: "/" }, { conn: "c", connPolicy: "pool", timeoutMs: 50 }),
    /production send flag/,
  );
});
