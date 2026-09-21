// Runs the actual commit-transform-session.mjs child script against an in-memory HTTP fixture
// that implements just enough of the Commit field-transform contract to drive it through the
// full 17-row plan. This verifies wiring/sequencing/cleanup/version-binding, not fireemu itself
// (see docs.local raw notes for the real native-binary replay).
import assert from "node:assert/strict";
import { test } from "node:test";
import { promises as fs } from "node:fs";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { COMMIT_TRANSFORM_CASE } from "../registry.mjs";
import { compilePlan } from "../commit-transform-plan.mjs";
import { runProcess, cleanEnvironment } from "../io.mjs";

const entry = COMMIT_TRANSFORM_CASE;
const MAX_TRANSFORMS = 500;

function makeFixture() {
  const docs = new Map();
  let clock = 0;
  const stamp = () => `2026-01-02T03:04:${String(5 + clock++).padStart(2, "0")}Z`;
  return createServer(async (req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    let text = "";
    for await (const part of req) text += part;
    const body = text ? JSON.parse(text) : {};
    const send = (status, result) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(result));
    };
    const notFound = (resource) =>
      send(404, {
        error: { code: 404, status: "NOT_FOUND", message: `document ${resource} not found` },
      });
    const resource = url.pathname.replace(/^\/v1\//, "");
    if (url.pathname.endsWith(":commit") && req.method === "POST") {
      const perDocument = new Map();
      for (const write of body.writes) {
        const target = write.transform.document;
        perDocument.set(
          target,
          (perDocument.get(target) ?? 0) + write.transform.fieldTransforms.length,
        );
      }
      for (const [target, count] of perDocument)
        if ((docs.get(target)?.transformCount ?? 0) + count > MAX_TRANSFORMS)
          return send(400, {
            error: {
              code: 400,
              status: "INVALID_ARGUMENT",
              message: "cannot have more than 500 field transforms on a single document",
            },
          });
      const commitTime = stamp();
      const writeResults = body.writes.map((write) => {
        const target = write.transform.document;
        const doc = docs.get(target);
        const applied = write.transform.fieldTransforms.length;
        doc.transformCount = (doc.transformCount ?? 0) + applied;
        for (const t of write.transform.fieldTransforms)
          doc.fields[t.fieldPath] = { integerValue: "1" };
        doc.updateTime = commitTime;
        return {
          updateTime: commitTime,
          transformResults: write.transform.fieldTransforms.map(() => ({ integerValue: "1" })),
        };
      });
      return send(200, { commitTime, writeResults });
    }
    if (req.method === "GET") {
      const doc = docs.get(resource);
      return doc
        ? send(200, {
            name: resource,
            fields: doc.fields,
            createTime: doc.createTime,
            updateTime: doc.updateTime,
          })
        : notFound(resource);
    }
    if (req.method === "PATCH" && url.searchParams.get("currentDocument.exists") === "false") {
      const t = stamp();
      docs.set(resource, {
        fields: structuredClone(body.fields),
        createTime: t,
        updateTime: t,
        transformCount: 0,
      });
      return send(200, { name: resource, fields: body.fields, createTime: t, updateTime: t });
    }
    if (req.method === "DELETE") {
      docs.delete(resource);
      return send(200, {});
    }
    return send(500, {
      error: { code: 500, status: "INTERNAL", message: "unhandled fixture request" },
    });
  });
}

async function exercise() {
  const root = await fs.mkdtemp(join(tmpdir(), "pilot-commit-session-"));
  const requests = [];
  const server = makeFixture();
  server.on("request", (req) => requests.push({ method: req.method, url: req.url }));
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    const plan = compilePlan(entry.project, entry.database, entry.nonce);
    await fs.writeFile(join(root, "program.json"), JSON.stringify(plan));
    const processResult = await runProcess(
      process.execPath,
      [fileURLToPath(new URL("../commit-transform-session.mjs", import.meta.url))],
      {
        cwd: root,
        timeoutMs: 15000,
        env: {
          ...cleanEnvironment(root),
          PILOT_RUN_DIR: root,
          PILOT_CASE_ID: entry.id,
          GOOGLE_CLOUD_PROJECT: entry.project,
          FIRESTORE_EMULATOR_HOST: `127.0.0.1:${server.address().port}`,
        },
      },
    );
    const session = JSON.parse(
      await fs.readFile(join(root, "session-result.json")).catch(() => "null"),
    );
    const localBytes = await fs.readFile(join(root, "local.json")).catch(() => null);
    return {
      processResult,
      session,
      local: localBytes ? JSON.parse(localBytes) : null,
      requests,
    };
  } finally {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
    await fs.rm(root, { recursive: true, force: true });
  }
}

test("executes all 17 rows in order, MATCHing the documented contract end to end", async () => {
  const r = await exercise();
  assert.equal(r.processResult.code, 0, r.processResult.log.toString());
  assert.equal(r.session.completed, true);
  assert.equal(r.session.requestCount, 17);
  assert.deepEqual(
    r.session.requests.map((x) => x.phase),
    entry.stepIds,
  );
  assert.equal(r.local.rows.length, 17);
  const accepted = r.local.rows.find((row) => row.stepId === "commit-transform:exact-500");
  assert.equal(accepted.status, 200);
  assert.equal(accepted.body.writeResults.length, 2);
  const refused = r.local.rows.find((row) => row.stepId === "commit-transform:over-501");
  assert.equal(refused.status, 400);
  assert.equal(refused.body.error.message, entry.refusedCommitMessage);
});

test("cleanup confirms both owned documents absent after the plan's own recovery phase", async () => {
  const r = await exercise();
  assert.deepEqual(r.session.cleanup, {
    state: "confirmed",
    absent: [...entry.ownedDocuments],
    requests: 2,
  });
});

test("the conditional delete is bound to the immediately preceding ownership read's updateTime", async () => {
  const r = await exercise();
  const deleteRow = r.local.rows.find(
    (row) => row.stepId === "cleanup-conditional-delete:exact-500",
  );
  const readRow = r.local.rows.find((row) => row.stepId === "cleanup-ownership-read:exact-500");
  assert.ok(deleteRow.path.includes("currentDocument.updateTime="));
  assert.equal(
    decodeURIComponent(deleteRow.path.split("currentDocument.updateTime=")[1]),
    readRow.body.updateTime,
  );
});

test("wrong project is rejected before any HTTP call", async () => {
  const root = await fs.mkdtemp(join(tmpdir(), "pilot-commit-session-"));
  const server = makeFixture();
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    const plan = compilePlan(entry.project, entry.database, entry.nonce);
    await fs.writeFile(join(root, "program.json"), JSON.stringify(plan));
    const processResult = await runProcess(
      process.execPath,
      [fileURLToPath(new URL("../commit-transform-session.mjs", import.meta.url))],
      {
        cwd: root,
        timeoutMs: 5000,
        env: {
          ...cleanEnvironment(root),
          PILOT_RUN_DIR: root,
          PILOT_CASE_ID: entry.id,
          GOOGLE_CLOUD_PROJECT: "some-other-project",
          FIRESTORE_EMULATOR_HOST: `127.0.0.1:${server.address().port}`,
        },
      },
    );
    assert.notEqual(processResult.code, 0);
  } finally {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
    await fs.rm(root, { recursive: true, force: true });
  }
});
