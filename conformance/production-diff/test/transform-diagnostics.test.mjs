import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { compareDiagnosticRows, supplementResult, parseDiagnosticArgs,
  PROGRAM_ID, TRANSFORM_CASE_ID, DIAGNOSTIC_STEPS } from "../check-transform-diagnostics.mjs";
import { comparatorModuleSource, importText } from "../legacy.mjs";

// These two strings are copied from the saved production column, NOT its emulator column.
// The fixture is NOT acquisition evidence: the CLI independently pins the complete matrix.
const messages = ["Input must be a number.", "a delete must not specify a update transform."];
function data() {
  const production = { id: PROGRAM_ID, steps: {} };
  const actual = { [PROGRAM_ID]: { steps: {} } };
  for (const [index, stepId] of DIAGNOSTIC_STEPS.entries()) {
    const row = { status: 400, code: "INVALID_ARGUMENT", message: messages[index] };
    production.steps[stepId] = { production: row, emulator: { ...row, message: "not-an-oracle" }, fireemu: { ...row, message: "old" } };
    actual[PROGRAM_ID].steps[stepId] = { ...row };
  }
  return { production, actual };
}
function primary(verdict = "MATCH", complete = true) {
  return { schema: "fireemu-production-diff-result-v1", caseId: TRANSFORM_CASE_ID,
    productionExecuted: false, complete, gatePassed: complete && verdict === "MATCH",
    comparison: { verdict } };
}

test("the old status/code comparison misses both known diagnostic differences", async () => {
  const text = await readFile(new URL("./legacy-comparator.excerpt.txt", import.meta.url), "utf8");
  const pure = comparatorModuleSource(text);
  assert.equal(sha256(pure), "efa1ff6f51d740033eb9d73e3306208630afaf487b54157ce5b4c91d15ea24c2");
  const { compareProductionToFireemu } = await importText(pure);
  const { production, actual } = data();
  actual[PROGRAM_ID].steps[DIAGNOSTIC_STEPS[0]].message = "increment operand must be numeric";
  actual[PROGRAM_ID].steps[DIAGNOSTIC_STEPS[1]].message = "transforms on a delete";
  const original = compareProductionToFireemu({ production: { programs: [production] }, fireemu: actual,
    programDefinitions: [{ id: PROGRAM_ID, steps: DIAGNOSTIC_STEPS.map((id) => ({ id })) }] });
  assert.equal(original.matches, 2);
  const diagnostics = compareDiagnosticRows(production, actual);
  assert.deepEqual(diagnostics.counts, { match: 0, mismatch: 2, indeterminate: 0 });
  assert.equal(supplementResult(primary(), diagnostics, {}).verdict, "MISMATCH");
});

test("both repaired messages match the saved production values", () => {
  const { production, actual } = data();
  const result = supplementResult(primary(), compareDiagnosticRows(production, actual), { localSha256: "test-only" });
  assert.equal(result.verdict, "MATCH");
  assert.equal(result.gatePassed, true);
  assert.equal(result.productionExecuted, false);
  assert.equal(result.parentPromotion, false);
  assert.equal(result.conditionAcceptance, false);
});

for (const [name, changed] of [["case", "input must be a number."], ["punctuation", "Input must be a number"],
  ["space", "Input must be a number. "], ["emulator text", "Input must be int64 or double."],
  ["empty", ""], ["numeric", 1], ["boolean", true], ["null", null], ["missing", undefined]]) {
  test(`message ${name} is a real diagnostic difference`, () => {
    const { production, actual } = data();
    const row = actual[PROGRAM_ID].steps[DIAGNOSTIC_STEPS[0]];
    if (changed === undefined) delete row.message; else row.message = changed;
    const comparison = compareDiagnosticRows(production, actual);
    assert.equal(comparison.verdict, "MISMATCH");
    assert.deepEqual(comparison.counts, { match: 1, mismatch: 1, indeterminate: 0 });
  });
}
for (const [name, mutate] of [
  ["missing row", (x) => { delete x[PROGRAM_ID].steps[DIAGNOSTIC_STEPS[0]]; }],
  ["timeout", (x) => { Object.assign(x[PROGRAM_ID].steps[DIAGNOSTIC_STEPS[0]], { status: 0, code: "no-response" }); }],
  ["seed failure", (x) => { x[PROGRAM_ID].seedError = "failed"; }],
  ["missing program", (x) => { delete x[PROGRAM_ID]; }],
  ["boolean status", (x) => { x[PROGRAM_ID].steps[DIAGNOSTIC_STEPS[0]].status = true; }],
  ["string status", (x) => { x[PROGRAM_ID].steps[DIAGNOSTIC_STEPS[0]].status = "400"; }],
  ["missing marker", (x) => { x[PROGRAM_ID].steps[DIAGNOSTIC_STEPS[0]].missing = true; }],
]) {
  test(`${name} never becomes a completed mismatch`, () => {
    const { production, actual } = data(); mutate(actual);
    const comparison = compareDiagnosticRows(production, actual);
    const result = supplementResult(primary(), comparison, {});
    assert.equal(result.verdict, "INDETERMINATE");
    assert.equal(result.complete, false);
    assert.equal(result.gatePassed, false);
  });
}
for (const [field, value] of [["status", 409], ["code", "FAILED_PRECONDITION"]]) {
  test(`a completed different ${field} remains a mismatch`, () => {
    const { production, actual } = data(); actual[PROGRAM_ID].steps[DIAGNOSTIC_STEPS[0]][field] = value;
    assert.equal(compareDiagnosticRows(production, actual).verdict, "MISMATCH");
  });
}
for (const [name, mutate] of [
  ["missing production side", (p) => { delete p.steps[DIAGNOSTIC_STEPS[0]].production; }],
  ["missing production message", (p) => { delete p.steps[DIAGNOSTIC_STEPS[0]].production.message; }],
  ["empty production message", (p) => { p.steps[DIAGNOSTIC_STEPS[0]].production.message = ""; }],
  ["wrong production status", (p) => { p.steps[DIAGNOSTIC_STEPS[0]].production.status = 200; }],
]) {
  test(`${name} is not repaired from emulator/local values`, () => {
    const { production, actual } = data(); mutate(production);
    assert.throws(() => compareDiagnosticRows(production, actual), /diagnostic-production-row/);
  });
}

test("matching diagnostics do not hide an existing primary mismatch", () => {
  const { production, actual } = data();
  const result = supplementResult(primary("MISMATCH"), compareDiagnosticRows(production, actual), {});
  assert.equal(result.verdict, "MISMATCH"); assert.equal(result.complete, true); assert.equal(result.gatePassed, false);
});
test("matching diagnostics do not close an incomplete primary comparison", () => {
  const { production, actual } = data();
  const result = supplementResult(primary("INDETERMINATE", false), compareDiagnosticRows(production, actual), {});
  assert.equal(result.verdict, "INDETERMINATE"); assert.equal(result.complete, false);
});
test("contradictory primary success is refused", () => {
  const { production, actual } = data(); const p = primary("MISMATCH"); p.gatePassed = true;
  assert.throws(() => supplementResult(p, compareDiagnosticRows(production, actual), {}), /diagnostic-primary-result/);
});
test("arbitrary local message contents do not leak into the diagnostic report", () => {
  const { production, actual } = data(); actual[PROGRAM_ID].steps[DIAGNOSTIC_STEPS[0]].message = "SECRET_TEST_SENTINEL";
  const result = compareDiagnosticRows(production, actual);
  assert.equal(JSON.stringify(result).includes("SECRET_TEST_SENTINEL"), false);
  assert.match(result.rows[0].observed.messageSha256, /^[0-9a-f]{64}$/);
});
test("the recorded publication labels never determine the verdict", () => {
  const { production, actual } = data();
  for (const row of Object.values(production.steps)) { row.status = "three-way-difference"; row.emulator = null; row.fireemu = null; }
  assert.equal(compareDiagnosticRows(production, actual).verdict, "MATCH");
});
for (const args of [[], ["--repo", "/x"], ["--endpoint", "https://firestore.googleapis.com"],
  ["--repo", "/x", "--repo", "/x", "--run-dir", "/r", "--out", "/o"],
  ["--repo", "/x", "--run-dir", "/r", "--out"]]) {
  test(`reject invalid CLI ${JSON.stringify(args)}`, () => assert.throws(() => parseDiagnosticArgs(args), /diagnostic-arguments/));
}
test("CLI accepts a repository, retained run and new output only", () => {
  assert.deepEqual(parseDiagnosticArgs(["--repo", "/repo", "--run-dir", "/run", "--out", "/out"]), { repo: "/repo", runDir: "/run", out: "/out" });
});
test("actual command help does not require a saved receipt or execute anything", () => {
  const output = execFileSync(process.execPath, [fileURLToPath(new URL("../check-transform-diagnostics.mjs", import.meta.url)), "--help"], { encoding: "utf8", timeout: 5000 });
  assert.match(output, /STORED-TRANSFORM-RUN/);
});

// Actual HTTP + the unchanged legacy recorder. The server is an explicit test double,
// not fireemu or production. This checks that the two short diagnostic strings survive
// the recorder's own normalization, rather than manufacturing a successful replay.
import { createServer } from "node:http";
import { once } from "node:events";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { blobSha, sha256 } from "../core.mjs";

for (const repaired of [false, true]) {
  test(`real recorder preserves ${repaired ? "corrected" : "old"} messages over HTTP`, async () => {
    const directory = await mkdtemp(join(tmpdir(), "transform-diagnostics-"));
    const server = createServer(async (req, res) => {
      for await (const ignored of req) void ignored;
      if (req.method === "DELETE") { res.end("{}"); return; }
      const index = calls++;
      const selected = repaired ? messages : ["increment operand must be numeric", "transforms on a delete"];
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { code: 400, status: "INVALID_ARGUMENT", message: selected[index] } }));
    });
    let calls = 0;
    try {
      server.listen(0, "127.0.0.1"); await once(server, "listening");
      const legacyDir = join(directory, "legacy"); await mkdir(legacyDir);
      for (const [name, expected] of [
        ["session.mjs", "f0cccf31eab09845e25ff4a9d356d347b04d721d"],
        ["credentials.mjs", "683058133f9912ce88ef0bec9a1c011c97cd055d"],
      ]) {
        const bytes = await readFile(new URL(`../../src/firestore-probe/${name}`, import.meta.url));
        assert.equal(blobSha(bytes), expected);
        await writeFile(join(legacyDir, name), bytes);
      }
      const doc = "projects/PROJECT/databases/(default)/documents/tf/doc";
      const invalidWrites = [
        { update: { name: doc, fields: {} }, updateMask: { fieldPaths: [] },
          updateTransforms: [{ fieldPath: "n", increment: { stringValue: "1" } }] },
        { delete: doc, updateTransforms: [{ fieldPath: "at", setToServerValue: "REQUEST_TIME" }] },
      ];
      const program = { id: PROGRAM_ID, area: "writes", seed: [],
        steps: DIAGNOSTIC_STEPS.map((id, index) => ({ id, method: "POST",
          path: "/v1/projects/PROJECT/databases/(default)/documents:commit",
          body: { writes: [invalidWrites[index]] } })) };
      const input = join(directory, "programs.json"); const output = join(directory, "local.json");
      await writeFile(input, JSON.stringify([program]));
      await promisify(execFile)(process.execPath, [join(legacyDir, "session.mjs")], {
        env: { PATH: process.env.PATH, HOME: directory,
          FIRESTORE_PROBE_HOST: `127.0.0.1:${server.address().port}`,
          FIRESTORE_PROBE_PROJECT: "demo-firestore-probe", FIRESTORE_PROBE_TARGET: "local",
          FIRESTORE_PROBE_SCHEME: "http", FIRESTORE_PROBE_TOKEN: "owner",
          FIRESTORE_PROBE_IN: input, FIRESTORE_PROBE_OUT: output, FIRESTORE_PROBE_TIMEOUT_MS: "2000" },
        timeout: 5000, maxBuffer: 65536,
      });
      const observed = JSON.parse(await readFile(output, "utf8"));
      assert.equal(calls, 2);
      const { production } = data();
      const compared = compareDiagnosticRows(production, observed);
      assert.equal(compared.verdict, repaired ? "MATCH" : "MISMATCH");
      assert.equal(compared.counts[repaired ? "match" : "mismatch"], 2);
    } finally {
      server.closeAllConnections();
      await new Promise((done) => server.close(done));
      await rm(directory, { recursive: true, force: true });
    }
  });
}
