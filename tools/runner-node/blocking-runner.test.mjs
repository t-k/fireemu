// Execute the actual runner entry point over real loopback HTTP. The tiny Express
// and HttpsError adapters below are *test doubles*, not the installed SDK/Express.
// These tests cover the runner's own dispatch/error/serialization, not SDK parity.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const runner = fileURLToPath(new URL("./index.mjs", import.meta.url));
const secret = "fixture-runner-secret";
const expressSource = `
module.exports = function express() {
  let handler;
  const app = (req, res) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      try { req.body = JSON.parse(Buffer.concat(chunks).toString() || '{}'); }
      catch { res.statusCode = 400; res.end('{}'); return; }
      req.get = name => req.headers[name.toLowerCase()];
      const p = req.url.split('?')[0].split('/');
      req.params = {project:p[1],region:p[2],name:p[3]};
      res.status = code => { res.statusCode=code; return res; };
      res.json = body => { res.setHeader('Content-Type','application/json'); res.end(JSON.stringify(body)); return res; };
      res.send = body => { res.end(String(body)); return res; };
      handler(req,res,()=>{ if (!res.writableEnded) {res.statusCode=500; res.end('{}');} });
    });
  };
  app.use = () => {};
  app.all = (_route, fn) => { handler=fn; };
  return app;
};
for (const name of ['json','text','raw','urlencoded']) module.exports[name] = () => () => {};
`;
const httpsSource = `
class HttpsError extends Error {
  constructor(code,message) {
    super(message); this.code=code;
    this.httpErrorCode = {
      'permission-denied':{canonicalName:'PERMISSION_DENIED',status:403},
      'invalid-argument':{canonicalName:'INVALID_ARGUMENT',status:400},
    }[code];
  }
}
module.exports={HttpsError};
`;
const functionsSource = `
const { HttpsError } = require('firebase-functions/https');
function handle(user) {
  if (user.mode === 'normal') return {displayName:'Guest',disabled:false};
  if (user.mode === 'undefined') return {displayName:undefined,emailVerified:true};
  if (user.mode === 'toJSON') return {customClaims:{toJSON:()=>({firebase:'invalid'})}};
  if (user.mode === 'size') return {customClaims:{toJSON:()=>({value:'x'.repeat(1000)})}};
  if (user.mode === 'throwing-result') return {get customClaims(){throw Error('fixture-private');}};
  if (user.mode === 'message') {
    const e=new HttpsError('permission-denied','safe'); let calls=0;
    Object.defineProperty(e,'message',{get(){return ++calls<=2?'safe':'fixture-private\\nunsafe';}});
    throw e;
  }
  if (user.mode === 'throwing-error') {
    const e=new HttpsError('permission-denied','safe');
    Object.defineProperty(e,'code',{get(){throw Error('fixture-private');}});
    Object.defineProperty(e,'stack',{get(){throw Error('fixture-private');}});
    throw e;
  }
  return;
}
function v1(){}; v1.run=(user)=>handle(user);
v1.__endpoint={platform:'gcfv1',blockingTrigger:{eventType:'beforeSignIn'}};
function v2(){}; v2.run=(event)=>handle(event.data);
v2.__endpoint={platform:'gcfv2',blockingTrigger:{eventType:'beforeSignIn'}};
async function http(req,res) {
  if (req.body?.data?.user?.mode === 'normal') {res.status(200).json({ok:true});return;}
  handle(req.body.data.user);
}
http.__endpoint={platform:'gcfv2',httpsTrigger:{}};
module.exports={v1,v2,http};
`;

async function fixture(source) {
  async function put(path, value) {
    const target = join(source, path);
    await mkdir(resolve(target, ".."), { recursive: true });
    await writeFile(target, value);
  }
  await put("package.json", JSON.stringify({ private: true, main: "index.cjs" }));
  await put("index.cjs", functionsSource);
  await put("node_modules/express/package.json", JSON.stringify({ name: "express", version: "5.0.0", main: "index.cjs" }));
  await put("node_modules/express/index.cjs", expressSource);
  await put("node_modules/firebase-functions/package.json", JSON.stringify({
    name: "firebase-functions", version: "7.3.2", main: "index.cjs",
    exports: { ".": "./index.cjs", "./https": "./https.cjs", "./v2/options": "./options.cjs" },
  }));
  await put("node_modules/firebase-functions/index.cjs", "module.exports={};");
  await put("node_modules/firebase-functions/https.cjs", httpsSource);
  await put("node_modules/firebase-functions/options.cjs", "exports.getGlobalOptions=()=>({});");
}

function hello(child) {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    const timer = setTimeout(() => reject(Error("runner hello timeout")), 4000);
    child.stdout.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length > 1024 * 1024) { clearTimeout(timer); reject(Error("runner output cap")); return; }
      for (;;) {
        const newline = buffer.indexOf(10);
        if (newline < 0) return;
        const length = Number(buffer.subarray(0, newline).toString("ascii"));
        if (!Number.isSafeInteger(length) || length < 0 || length > 1024 * 1024) {
          clearTimeout(timer); reject(Error("bad runner frame")); return;
        }
        if (buffer.length < newline + 1 + length) return;
        const frame = JSON.parse(buffer.subarray(newline + 1, newline + 1 + length).toString("utf8"));
        buffer = buffer.subarray(newline + 1 + length);
        if (frame.type === "hello") { clearTimeout(timer); resolve(frame); }
      }
    });
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
    child.once("exit", () => { clearTimeout(timer); reject(Error("runner exited before hello")); });
  });
}

function call(port, name, mode, suppliedSecret = secret) {
  return new Promise((resolve, reject) => {
    const req = request({ hostname: "127.0.0.1", port, method: "POST",
      path: `/demo-blocking-boundary/us-central1/${name}`,
      headers: { "content-type": "application/json", "x-fireemu-runner-secret": suppliedSecret },
    }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        resolve({ status: res.statusCode, text, body: res.headers["content-type"]?.includes("application/json") ? JSON.parse(text) : null });
      });
      res.on("error", reject);
    });
    req.setTimeout(1500, () => req.destroy(Error("fixture HTTP timeout")));
    req.on("error", reject);
    req.end(JSON.stringify({ data: { user: { mode }, context: {} } }));
  });
}

async function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = once(child, "exit");
  child.stdin.end();
  const timer = setTimeout(() => child.kill("SIGKILL"), 1000);
  try { await exited; } finally { clearTimeout(timer); }
}

test("actual runner blocking dispatch preserves a validated response and survives thrown accessors", { timeout: 20000 }, async (t) => {
  const source = await mkdtemp(join(tmpdir(), "fireemu-blocking-boundary-"));
  let child;
  try {
    await fixture(source);
    child = spawn(process.execPath, [runner, "--source", source], {
      env: { PATH: process.env.PATH, GCLOUD_PROJECT: "demo-blocking-boundary", FIREEMU_RUNNER_SECRET: secret },
      stdio: ["pipe", "pipe", "pipe"],
    });
    child.stderr.on("data", () => {});
    const started = await hello(child);
    assert.equal(started.manifest.functions.length, 3);
    assert.ok(Number.isInteger(started.httpPort));
    const port = started.httpPort;
    await t.test("ordinary HTTP rejection survives a throwing error stack", async () => {
      const reply = await call(port, "http", "throwing-error");
      assert.equal(reply.status, 500);
      assert.equal(reply.text, "internal error");
      assert.equal(child.exitCode, null);
    });
    await t.test("ordinary HTTP runner remains available after rejection", async () => {
      const reply = await call(port, "http", "normal");
      assert.equal(reply.status, 200);
      assert.deepEqual(reply.body, {ok: true});
    });
    await t.test("proxy authentication still rejects the wrong secret", async () => {
      assert.equal((await call(port, "v2", "normal", "wrong")).status, 403);
    });
    for (const generation of ["v1", "v2"]) {
      await t.test(`${generation}: undefined is omitted, explicit false is retained`, async () => {
        const reply = await call(port, generation, "undefined");
        assert.equal(reply.status, 200);
        assert.deepEqual(reply.body, { userRecord: { emailVerified: true, updateMask: "emailVerified" } });
      });
      for (const mode of ["toJSON", "size", "throwing-result"]) {
        await t.test(`${generation}: ${mode} result is rejected through the HTTP route`, async () => {
          const reply = await call(port, generation, mode);
          assert.equal(reply.status, 400);
          assert.equal(reply.body.error.status, "INVALID_ARGUMENT");
          assert.equal(reply.text.includes("fixture-private"), false);
        });
      }
      await t.test(`${generation}: changing error getter cannot change public text`, async () => {
        const reply = await call(port, generation, "message");
        assert.equal(reply.status, 403);
        assert.equal(reply.body.error.message, "safe");
      });
      await t.test(`${generation}: throwing code and stack still yield a bounded fallback`, async () => {
        const reply = await call(port, generation, "throwing-error");
        assert.equal(reply.status, 503);
        assert.equal(reply.body.error.status, "UNAVAILABLE");
        assert.equal(reply.text.includes("fixture-private"), false);
      });
      await t.test(`${generation}: runner remains alive and serves a subsequent success`, async () => {
        assert.equal(child.exitCode, null);
        const reply = await call(port, generation, "normal");
        assert.equal(reply.status, 200);
        assert.deepEqual(reply.body, { userRecord: { displayName: "Guest", disabled: false, updateMask: "displayName,disabled" } });
      });
    }
  } finally {
    if (child) await stop(child);
    await rm(source, { recursive: true, force: true });
  }
});
