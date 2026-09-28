// Runs the byte-pinned *existing recorder*, but with an in-memory HTTP fixture.
// This verifies integration/wire guards, NOT fireemu runtime or production parity.
import assert from "node:assert/strict";
import { test } from "node:test";
import { promises as fs } from "node:fs";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { CASE } from "../registry.mjs";
import { blobSha, compareRecords } from "../core.mjs";
import { comparatorModuleSource, importText } from "../legacy.mjs";
import { runProcess, cleanEnvironment } from "../io.mjs";
import { verifySession } from "../pilot.mjs";
import { programFixture, matrixFixture } from "./fixtures.mjs";
import { selectProduction } from "../core.mjs";
const upstream =
  process.env.PILOT_TEST_UPSTREAM_DIR ??
  fileURLToPath(new URL("../../src/firestore-probe/", import.meta.url));
const sessionBytes = await fs.readFile(join(upstream, "session.mjs"));
const credentialBytes = await fs.readFile(join(upstream, "credentials.mjs"));
assert.equal(
  blobSha(sessionBytes),
  CASE.sessionBlob,
  "recorder bytes must be the actual reviewed upstream bytes",
);
assert.equal(blobSha(credentialBytes), CASE.credentialsBlob);
const { compareProductionToFireemu: comparator } = await importText(
  comparatorModuleSource(
    await fs.readFile(new URL("legacy-comparator.excerpt.txt", import.meta.url), "utf8"),
  ),
);

async function exercise(options = {}) {
  const root = await fs.mkdtemp(join(tmpdir(), "pilot-recorder-"));
  const rows = [];
  const docs = new Map();
  let resets = 0;
  const server = createServer(async (req, res) => {
    let text = "";
    for await (const part of req) text += part;
    rows.push({
      path: req.url,
      method: req.method,
      authorization: req.headers.authorization ?? null,
    });
    let body = {};
    try {
      body = text ? JSON.parse(text) : {};
    } catch {}
    const send = (status, result) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(result));
    };
    const error = (status, code) =>
      send(status, { error: { code: status, status: code, message: "fixture diagnostic" } });
    const name = req.url.replace("/v1/", "");
    if (req.url.startsWith("/emulator/") && req.method === "DELETE") {
      resets++;
      if (options.resetFailure && resets === 1) return error(503, "UNAVAILABLE");
      if (!(options.cleanupFailure && resets > 1)) docs.clear();
      return send(200, {});
    }
    if (req.method === "PATCH") {
      const document = {
        name,
        fields: body.fields,
        createTime: "2026-01-02T03:04:05Z",
        updateTime: "2026-01-02T03:04:05Z",
      };
      docs.set(name, document);
      return send(200, document);
    }
    if (req.method === "GET")
      return docs.has(name) ? send(200, docs.get(name)) : error(404, "NOT_FOUND");
    if (req.url.endsWith(":batchWrite")) {
      if ("transaction" in body) return error(400, "INVALID_ARGUMENT");
      if (body.writes?.length === 0) return send(200, {});
      if (options.partialWrite)
        docs.set(body.writes[0].update.name, {
          ...body.writes[0].update,
          createTime: "2026-01-02T03:04:05Z",
          updateTime: "2026-01-02T03:04:05Z",
        });
      return error(400, options.errorCode ?? "INVALID_ARGUMENT");
    }
    return error(500, "INTERNAL");
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    await fs.mkdir(join(root, "legacy"));
    await fs.writeFile(join(root, "legacy/session.mjs"), sessionBytes);
    await fs.writeFile(join(root, "legacy/credentials.mjs"), credentialBytes);
    const program = programFixture();
    if (options.inputDrift) program.steps[0].body.writes.pop();
    await fs.writeFile(join(root, "program.json"), JSON.stringify(program));
    await fs.writeFile(join(root, "programs.json"), JSON.stringify([program]));
    const processResult = await runProcess(
      process.execPath,
      [fileURLToPath(new URL("../local-session.mjs", import.meta.url))],
      {
        cwd: root,
        timeoutMs: 5000,
        env: {
          ...cleanEnvironment(root),
          PILOT_RUN_DIR: root,
          GOOGLE_CLOUD_PROJECT: CASE.project,
          FIRESTORE_EMULATOR_HOST: `127.0.0.1:${server.address().port}`,
          // Deliberately poisoned selectors: the wrapper must overwrite them before import.
          FIRESTORE_PROBE_TARGET: "production",
          FIRESTORE_PROBE_HOST: "firestore.googleapis.com",
          FIRESTORE_PROBE_TOKEN: "sentinel-never-sent",
          FIRESTORE_PROBE_SCHEME: "https",
        },
      },
    );
    const session = JSON.parse(
      await fs.readFile(join(root, "session-result.json")).catch(() => "null"),
    );
    const bytes = await fs.readFile(join(root, "local.json")).catch(() => null);
    return {
      processResult,
      session,
      actual: bytes ? JSON.parse(bytes) : null,
      bytes,
      rows,
      compare: bytes
        ? compareRecords({
            entry: CASE,
            program: programFixture(),
            production: selectProduction(matrixFixture(), CASE),
            actual: JSON.parse(bytes),
            comparator,
          })
        : null,
    };
  } finally {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
    await fs.rm(root, { recursive: true, force: true });
  }
}

test("actual legacy recorder completes 7 planned + 5 cleanup HTTP calls over loopback", async () => {
  const r = await exercise();
  assert.equal(r.processResult.code, 0, r.processResult.log.toString());
  assert.equal(r.session.completed, true);
  assert.equal(r.rows.length, 12);
  assert.deepEqual(r.session.cleanup, {
    state: "confirmed",
    absent: [...CASE.ownedDocuments],
    requests: 5,
  });
  verifySession(r.session, { entry: CASE, program: programFixture() }, r.bytes);
  assert.equal(r.compare.verdict, "MATCH");
});
test("ambient production selectors do not send production credentials or paths", async () => {
  const r = await exercise();
  assert.equal(r.processResult.code, 0);
  assert.ok(
    r.rows.every((row) => row.authorization === null || row.authorization === "Bearer owner"),
  );
  assert.equal(r.rows.filter((row) => row.path.includes(":listCollectionIds")).length, 0);
});
test("actual recorder + comparator detect a partial write despite the refusal", async () => {
  const r = await exercise({ partialWrite: true });
  assert.equal(r.processResult.code, 0);
  assert.equal(r.compare.verdict, "MISMATCH");
  assert.equal(r.compare.rows.find((x) => x.stepId === "one-was-written").comparison, "MISMATCH");
});
test("actual recorder + comparator detect a changed canonical error", async () => {
  const r = await exercise({ errorCode: "FAILED_PRECONDITION" });
  assert.equal(r.compare.verdict, "MISMATCH");
});
test("reset failure does not become a valid recording", async () => {
  const r = await exercise({ resetFailure: true });
  assert.notEqual(r.processResult.code, 0);
  assert.equal(r.session.completed, false);
  assert.equal(r.actual, null);
});
test("unconfirmed cleanup is an explicit failure", async () => {
  const r = await exercise({ cleanupFailure: true });
  assert.notEqual(r.processResult.code, 0);
  assert.equal(r.session.cleanup.state, "unconfirmed");
});
test("mutated program is rejected before any HTTP", async () => {
  const r = await exercise({ inputDrift: true });
  assert.notEqual(r.processResult.code, 0);
  assert.equal(r.rows.length, 0);
  assert.equal(r.session, null);
});
test("local binding rejects a changed recording hash", async () => {
  const r = await exercise();
  const b = Buffer.from(r.bytes.toString().replace("INVALID_ARGUMENT", "PERMISSION_DENIED"));
  assert.throws(
    () => verifySession(r.session, { entry: CASE, program: programFixture() }, b),
    /local-record-binding/,
  );
});

test("cleanup covers every possible target, including refused creates", () => {
  const program = programFixture();
  const names = new Set(program.seed.map((s) => s.path.split("/documents/")[1]));
  for (const step of program.steps) {
    for (const w of step.body?.writes ?? []) {
      const name = w.update?.name ?? w.delete ?? w.transform?.document;
      if (name) names.add(name.split("/documents/")[1]);
    }
  }
  assert.deepEqual([...names].sort(), [...CASE.ownedDocuments].sort());
});
