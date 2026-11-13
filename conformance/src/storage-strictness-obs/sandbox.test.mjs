// OS-level barrier checks for mutation and test runs of this recorder (lane guide section 5). They run only under
// docs.local/tools/mutant-sandbox/run, which sets NEGCACHE_SANDBOX=1; the mutation harness refuses to start unless
// they pass unskipped. Ported from conformance/src/pubsub-negcache/guard.test.mjs with the Storage hosts.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";

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
        { host: "storage.googleapis.com", path: "/", timeout: 3000 },
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
