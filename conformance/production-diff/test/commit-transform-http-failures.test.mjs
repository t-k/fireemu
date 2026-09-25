// Actual child module, network guard, plan compiler, registry and publication code.
// Only the remote daemon is a scripted loopback HTTP fixture. No cloud I/O or native fireemu.
import assert from "node:assert/strict";
import { test } from "node:test";
import { promises as fs } from "node:fs";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { COMMIT_TRANSFORM_CASE as entry } from "../registry.mjs";
import { compilePlan } from "../commit-transform-plan.mjs";
import { sha256 } from "../core.mjs";
import { runProcess, cleanEnvironment } from "../io.mjs";

async function exercise(scenario) {
  const root = await fs.mkdtemp(join(tmpdir(), "pilot-http-failure-"));
  const requests = [];
  const docs = new Map();
  const started = performance.now();
  let faultAt = null;
  let faultClosedAt = null;
  let injected = false;
  const server = createServer(async (req, res) => {
    try {
      const path = new URL(req.url, "http://127.0.0.1");
      const resource = path.pathname.slice("/v1/".length);
      requests.push({ method: req.method, path: req.url });
      let text = "";
      for await (const chunk of req) text += chunk;
      const body = text ? JSON.parse(text) : null;
      const send = (status, value) => {
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify(value));
      };
      const shouldInject =
        !injected &&
        (scenario === "uncertain-write" ? req.method === "PATCH" : requests.length === 1);
      if (shouldInject) {
        injected = true;
        faultAt = performance.now();
        res.once("close", () => {
          faultClosedAt = performance.now();
        });
        if (scenario === "invalid-utf8") {
          res.writeHead(404, { "content-type": "application/json" });
          res.end(
            Buffer.concat([
              Buffer.from('{"error":{"status":"NOT_FOUND","message":"'),
              Buffer.from([0x80]),
              Buffer.from('"}}'),
            ]),
          );
          return;
        }
        if (scenario === "invalid-json") {
          res.writeHead(404);
          res.end("{");
          return;
        }
        if (scenario === "stalled-headers") return;
        if (scenario === "dribbling-body") {
          res.writeHead(404, { "content-type": "application/json" });
          res.write('{"error":');
          const interval = setInterval(() => res.write(" "), 50);
          res.once("close", () => clearInterval(interval));
          return;
        }
        if (scenario === "uncertain-write") {
          docs.set(resource, {
            name: resource,
            fields: body.fields,
            updateTime: "2026-01-01T00:00:00Z",
          });
          return; // Applied, but no acknowledgement: never infer rollback or retry.
        }
      }
      if (req.method === "PATCH") {
        const doc = { name: resource, fields: body.fields, updateTime: "2026-01-01T00:00:00Z" };
        docs.set(resource, doc);
        return send(200, doc);
      }
      if (req.method === "DELETE") {
        docs.delete(resource);
        return send(200, {});
      }
      if (req.method === "POST") {
        return send(200, { writeResults: [], commitTime: "2026-01-01T00:00:00Z" });
      }
      const doc = docs.get(resource);
      return doc ? send(200, doc) : send(404, { error: { status: "NOT_FOUND" } });
    } catch {
      res.destroy();
    }
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  try {
    const plan = compilePlan(entry.project, entry.database, entry.nonce);
    await fs.writeFile(join(root, "program.json"), JSON.stringify(plan));
    const processResult = await runProcess(
      process.execPath,
      [fileURLToPath(new URL("../commit-transform-session.mjs", import.meta.url))],
      {
        cwd: root,
        timeoutMs: 14000,
        env: {
          ...cleanEnvironment(root),
          PILOT_RUN_DIR: root,
          PILOT_CASE_ID: entry.id,
          GOOGLE_CLOUD_PROJECT: entry.project,
          FIRESTORE_EMULATOR_HOST: `127.0.0.1:${server.address().port}`,
        },
      },
    );
    const readOptional = async (path) => {
      try {
        return await fs.readFile(join(root, path));
      } catch (error) {
        if (error.code === "ENOENT") return null;
        throw error;
      }
    };
    const sessionBytes = await readOptional("session-result.json");
    const localBytes = await readOptional("local.json");
    const session = sessionBytes && JSON.parse(sessionBytes);
    const local = localBytes && JSON.parse(localBytes);
    return {
      processResult,
      session,
      local,
      localBytes,
      requests,
      remaining: [...docs.keys()],
      elapsedMs: performance.now() - started,
      connectionMs: faultAt !== null && faultClosedAt !== null ? faultClosedAt - faultAt : null,
    };
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    await fs.rm(root, { recursive: true, force: true });
  }
}

function incomplete(r, failure) {
  assert.equal(r.processResult.reason, null, "the supervisor must not be what stops the request");
  assert.equal(r.processResult.code, 2);
  assert.equal(r.processResult.state, "stopped");
  assert.ok(r.session, "failure must be published before the parent deadline");
  assert.equal(r.session.completed, false);
  assert.equal(r.session.failure, failure);
  assert.equal(r.session.productionRequests, 0);
  assert.equal(r.session.localSha256, sha256(r.localBytes));
  assert.equal(r.local.rows.length, r.session.requestCount);
  assert.equal(r.processResult.log.length, 0, "raw response data must not leak to stderr");
}

for (const [scenario, failure] of [
  ["invalid-utf8", "response-invalid-utf8"],
  ["invalid-json", "non-json-response"],
])
  test(`child rejects ${scenario}, preserves a receipt and never proceeds to writes`, async () => {
    const r = await exercise(scenario);
    incomplete(r, failure);
    assert.deepEqual(r.local.rows, []);
    assert.deepEqual(r.remaining, []);
    assert.equal(r.session.cleanup.state, "confirmed");
    assert.equal(r.session.cleanup.requests, 2);
    assert.deepEqual(r.session.cleanup.absent, [...entry.ownedDocuments]);
    assert.equal(r.requests.length, 3);
    assert.ok(r.requests.every((q) => q.method === "GET"));
  });

for (const scenario of ["stalled-headers", "dribbling-body", "uncertain-write"])
  test(`real request deadline: ${scenario}`, { timeout: 20000 }, async (t) => {
    const r = await exercise(scenario);
    t.diagnostic(
      JSON.stringify({
        scenario,
        connectionMs: r.connectionMs,
        elapsedMs: r.elapsedMs,
        processReason: r.processResult.reason,
        requests: r.requests.length,
        failure: r.session?.failure,
      }),
    );
    incomplete(r, "request-timeout");
    assert.ok(r.connectionMs !== null && r.connectionMs >= 8500 && r.connectionMs < 13000);
    if (scenario === "uncertain-write") {
      assert.equal(r.session.cleanup.state, "unconfirmed");
      assert.equal(r.session.cleanup.failure, "cleanup-absence-unconfirmed");
      assert.deepEqual(r.remaining, [entry.ownedDocuments[0]]);
      assert.equal(r.requests.filter((q) => q.method === "PATCH").length, 1);
      assert.equal(r.requests.filter((q) => q.method === "DELETE").length, 0);
      assert.equal(
        r.local.rows.length,
        2,
        "the unacknowledged write cannot become an observed row",
      );
    } else {
      assert.equal(r.session.cleanup.state, "confirmed");
      assert.deepEqual(r.session.cleanup.absent, [...entry.ownedDocuments]);
      assert.equal(r.requests.length, 3);
      assert.ok(r.requests.every((q) => q.method === "GET"));
    }
  });
