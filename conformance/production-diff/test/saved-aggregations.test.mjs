// FS-EVID-AGGREGATIONS-029. A synthetic HTTP peer tests adapter wiring, NOT
// Firestore semantics. The real pinned recorder, parent verifier and comparator
// execute without substitutes. The fixture below MUST NEVER become an Oracle.
import assert from "node:assert/strict";
import { test } from "node:test";
import { promises as fs } from "node:fs";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CASE, CASES, AGGREGATIONS_CASE as entry, selectCase } from "../registry.mjs";
import { blobSha, digestJson, sha256, validateProgram, selectProduction,
  compareRecords, resultEnvelope, gateExitCode } from "../core.mjs";
import { comparatorModuleSource, importText, prepare, stageLegacy } from "../legacy.mjs";
import { cleanEnvironment } from "../io.mjs";
import { verifySession, parseArgs, main, configForCase } from "../pilot.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const program = JSON.parse(await fs.readFile(join(HERE, "fixtures/saved-aggregations-program.json"), "utf8"));
const pure = comparatorModuleSource(await fs.readFile(join(HERE, "legacy-comparator.excerpt.txt"), "utf8"));
assert.equal(sha256(pure), entry.comparatorSliceSha256);
const { compareProductionToFireemu: comparator } = await importText(pure);
const TIME = "2026-01-02T03:04:05.123456Z";
const prefix = `/v1/projects/${entry.project}/databases/(default)/documents`;
const substitute = v => v === undefined ? undefined : JSON.parse(JSON.stringify(v).replaceAll("PROJECT", entry.project));
const integer = v => ({ integerValue: String(v) });
const double = v => ({ doubleValue: v });

// These are EXPLICITLY SYNTHETIC test values. Tests assert transport retention,
// value/type distinctions and mismatch detection, not these values as production truth.
const syntheticFields = {
  "count-all": { count: integer(6) },
  "count-up-to": { c: integer(2) },
  "count-with-filter": { count: integer(2) },
  "count-with-limit": { count: integer(3) },
  "count-with-offset": { count: integer(2) },
  "count-empty": { count: integer(0) },
  "sum-integers": { sum: double(9.223372036854776e18) },
  "sum-mixed-numbers": { sum: double("NaN") },
  "sum-doubles-only": { sum: double(4) },
  "sum-empty": { sum: integer(0) },
  "sum-missing-field": { sum: integer(0) },
  "sum-overflow-saturates-or-promotes": { sum: double(9.223372036854776e18) },
  "avg-integers": { avg: double(1.5) },
  "avg-with-nan": { avg: double("NaN") },
  "avg-empty": { avg: { nullValue: null } },
  "several-aggregations": { total: integer(4), sum_n: integer(6), avg_d: double("NaN"), capped: integer(1) },
  "count-collection-group": { count: integer(6) },
  "count-with-cursor": { count: integer(4) },
  "count-beside-a-sum-over-a-missing-field": { total: integer(4), sum_d: double("NaN") },
  "count-beside-an-avg-over-a-missing-field": { total: integer(4), avg_d: double("NaN") },
};
const refusalIds = ["duplicate-alias", "no-aggregations", "sum-on-name"];
function response(id, options = {}) {
  if (options.unavailable === id) return { status: 503, body: { error: { code: 503, status: "UNAVAILABLE", message: "synthetic service failure" } } };
  if (refusalIds.includes(id)) return { status: 400, body: { error: { code: 400, status: "INVALID_ARGUMENT", message: `synthetic refusal ${id}` } } };
  assert.ok(Object.hasOwn(syntheticFields, id));
  const fields = structuredClone(syntheticFields[id]);
  if (options.wrongSum && id === "sum-overflow-saturates-or-promotes") fields.sum = integer("9223372036854775807");
  return { status: 200, body: [{ result: { aggregateFields: fields }, readTime: TIME }] };
}
function reference() {
  const steps = Object.fromEntries(entry.stepIds.map(id => {
    const { status, body } = response(id);
    const row = body.error ? { status, code: body.error.status, message: body.error.message }
      : { status, code: "OK", body: JSON.parse(JSON.stringify(body).replaceAll(TIME, "<now>")) };
    return [id, { production: row }];
  }));
  return { programs: [{ id: entry.programId, area: "queries", steps }] };
}
const actualControl = () => ({ [entry.programId]: { steps: Object.fromEntries(
  Object.entries(reference().programs[0].steps).map(([id, value]) => [id, structuredClone(value.production)])) } });
const compare = actual => compareRecords({ entry, program, production: reference(), actual, comparator });
function matrixControl() {
  return { version: 1, evidence: { verified: true, validation: [], observations: { production: {
    observation: { side: "production", mode: "live", database: { type: "FIRESTORE_NATIVE", databaseEdition: "STANDARD" } },
    source: { gitSha: entry.observedSource, trackedTreeClean: true }, inputs: { corpusDigest: entry.corpusDigest },
  } } }, ...reference() };
}
const fieldsAt = (local, id) => local[entry.programId].steps[id].body[0].result.aggregateFields;

test("aggregation replay pins the historical index file without changing other cases", () => {
  const aggregationConfig = configForCase(entry);
  assert.equal(aggregationConfig.firestore.indexFile, "firestore.indexes.json");
  assert.equal(configForCase(CASE).firestore.indexFile, undefined);
  assert.equal(aggregationConfig.firestore.apiMode, "native");
  assert.equal(aggregationConfig.profile, "strict");
  assert.equal(entry.indexFilePath, "conformance/firestore.indexes.json");
  assert.equal(entry.indexFileBytes, 2484);
  assert.equal(entry.indexFileSha256, "sha256-8a4d4bd7a72c3ce2bed4e0f8c4adc0cdb3a7c428477578295e44a11ae063d01c");
});
test("aggregation preparation refuses drifted historical index provenance", async () => {
  const repo = resolve(HERE, "../../..");
  await assert.rejects(
    prepare(repo, { ...entry, indexFileSha256: "sha256-" + "0".repeat(64) }),
    /index-file/,
  );
});
test("aggregation preparation stages the byte-exact historical index file", async () => {
  const repo = resolve(HERE, "../../..");
  const prepared = await prepare(repo, entry);
  const directory = await fs.mkdtemp(join(tmpdir(), "fireemu-agg-index-"));
  try {
    await stageLegacy(prepared, join(directory, "legacy"), directory);
    assert.deepEqual(await fs.readFile(join(directory, "firestore.indexes.json")), prepared.indexBytes);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

// Registry/input boundaries: preserving the exact OLD request program is essential.
test("all 23 steps, six seeds, setup and cleanup bind to FS-QUERY-INDEX", () => {
  assert.equal(selectCase(entry.id), entry); assert.equal(selectCase(), CASE);
  assert.equal(entry.parent, "FS-QUERY-INDEX"); assert.equal(entry.adapter, "batch-write");
  assert.equal(entry.sessionScript, "local-session.mjs"); assert.equal(entry.profile, "strict");
  assert.equal(entry.programArea, "queries"); assert.equal(entry.seedCount, 6);
  assert.equal(digestJson(program), entry.programDigest); assert.equal(validateProgram(program, entry), program);
  assert.equal(program.steps.length, 23); assert.equal(program.seed.length, 6);
  assert.deepEqual(program.seed.map(s => s.path.split("/documents/")[1]), entry.ownedDocuments);
  assert.deepEqual(entry.sessionSetupPhases, ["reset", ...Array(6).fill("seed")]);
  assert.equal(entry.cleanupResetRequests, 1);
  for (const v of [entry, entry.stepIds, entry.ownedDocuments, entry.sessionSetupPhases]) assert.ok(Object.isFrozen(v));
});
test("same immutable recorder, comparator and production matrix pins; no new oracle", () => {
  for (const k of ["observedSource", "matrixPath", "matrixBlob", "corpusBlob", "corpusDigest", "comparatorSliceSha256", "sessionBlob", "credentialsBlob", "evidenceKind", "oracleKind"]) assert.equal(entry[k], CASE[k]);
  assert.equal(entry.rawTimestampResponseSteps, undefined);
  assert.equal(entry.generatedDocumentSteps, undefined);
});
test("named cases are not silently repaired or strengthened beyond their input", () => {
  assert.equal(program.seed[4].fields.n.integerValue, "9223372036854775807");
  assert.equal(program.seed[5].fields.k.stringValue, "z");
  const q = id => program.steps.find(s => s.id === id).body.structuredAggregationQuery;
  assert.deepEqual(q("avg-integers").structuredQuery.where.fieldFilter.value.arrayValue.values, [{ stringValue: "x" }, { stringValue: "f" }]);
  assert.deepEqual(q("duplicate-alias").aggregations.map(a => a.alias), ["x", "x"]);
  assert.deepEqual(q("no-aggregations").aggregations, []);
  assert.equal(q("sum-on-name").aggregations[0].sum.field.fieldPath, "__name__");
  assert.equal(q("count-up-to").aggregations[0].count.upTo, "2");
  assert.equal(q("count-collection-group").structuredQuery.from[0].allDescendants, true);
  assert.ok(program.seed.every(s => s.path.split("/documents/")[1].split("/").length === 2));
});
for (const [name, mutate] of [
  ["wrong area", p => { p.area = "writes"; }],
  ["missing seed", p => { p.seed.pop(); }],
  ["extra seed", p => { p.seed.push(structuredClone(p.seed[0])); }],
  ["rounded max integer", p => { p.seed[4].fields.n.integerValue = "9223372036854775808"; }],
  ["missing step", p => { p.steps.pop(); }],
  ["reordered steps", p => { p.steps.reverse(); }],
  ["changed count cap", p => { p.steps[1].body.structuredAggregationQuery.aggregations[0].count.upTo = "3"; }],
  ["changed cursor", p => { p.steps[17].body.structuredAggregationQuery.structuredQuery.startAt.before = false; }],
  ["foreign database", p => { p.steps[0].path = p.steps[0].path.replace("(default)", "other"); }],
  ["different principal", p => { p.steps[0].owner = false; }],
]) test(`input mutation is refused: ${name}`, () => {
  const altered = structuredClone(program); mutate(altered);
  assert.throws(() => validateProgram(altered, entry), /program-/);
});
test("CLI lists and selects aggregation; older cases remain registered", async () => {
  assert.equal(parseArgs(["plan", "--case", entry.id]).case, entry.id);
  const log = console.log; let text;
  try { console.log = s => { text = s; }; assert.equal(await main(["list"]), 0); } finally { console.log = log; }
  assert.deepEqual(JSON.parse(text).cases.map(c => c.id), CASES.map(c => c.id));
  assert.equal(CASES.filter(c => c.id === entry.id).length, 1);
});
test("selection ignores emulator/local columns and historical summary labels", () => {
  const matrix = matrixControl();
  for (const row of Object.values(matrix.programs[0].steps)) {
    row.fireemu = { status: 200, code: "OK", body: "wrong" };
    row.emulator = { status: 503, code: "UNAVAILABLE" };
    row.status = "unverified";
  }
  assert.deepEqual(selectProduction(matrix, entry), reference());
});
for (const [name, mutate] of [
  ["unverified evidence", m => { m.evidence.verified = false; }],
  ["nonproduction mode", m => { m.evidence.observations.production.observation.mode = "stored"; }],
  ["different source", m => { m.evidence.observations.production.source.gitSha = "0".repeat(40); }],
  ["different corpus", m => { m.evidence.observations.production.inputs.corpusDigest = "sha256-" + "0".repeat(64); }],
  ["duplicate program", m => { m.programs.push(structuredClone(m.programs[0])); }],
  ["missing row", m => { delete m.programs[0].steps[entry.stepIds[0]]; }],
  ["missing production column", m => { const r = m.programs[0].steps[entry.stepIds[0]]; r.fireemu = r.production; delete r.production; }],
  ["unanswered response", m => { m.programs[0].steps[entry.stepIds[0]].production.status = 0; }],
]) test(`invalid oracle projection is refused: ${name}`, () => {
  const m = matrixControl(); mutate(m); assert.throws(() => selectProduction(m, entry), /oracle-/);
});
for (const [name, mutate] of [
  ["count", l => { fieldsAt(l, "count-all").count.integerValue = "5"; }],
  ["value type", l => { fieldsAt(l, "count-all").count = double(6); }],
  ["count cap alias", l => { fieldsAt(l, "count-up-to").count = fieldsAt(l, "count-up-to").c; delete fieldsAt(l, "count-up-to").c; }],
  ["numeric result", l => { fieldsAt(l, "avg-integers").avg.doubleValue = 2; }],
  ["NaN retained", l => { fieldsAt(l, "avg-with-nan").avg = { nullValue: null }; }],
  ["empty sum type", l => { fieldsAt(l, "sum-empty").sum = double(0); }],
  ["empty avg", l => { fieldsAt(l, "avg-empty").avg = integer(0); }],
  ["overflow saturates instead of observed type", l => { fieldsAt(l, "sum-overflow-saturates-or-promotes").sum = integer("9223372036854775807"); }],
  ["combined field missing", l => { delete fieldsAt(l, "several-aggregations").sum_n; }],
  ["missing-field count interaction", l => { fieldsAt(l, "count-beside-a-sum-over-a-missing-field").total.integerValue = "6"; }],
  ["wrong refusal", l => { l[entry.programId].steps["duplicate-alias"].code = "FAILED_PRECONDITION"; }],
  ["unexpected extra result", l => { l[entry.programId].steps["count-all"].body.push({ result: { aggregateFields: { count: integer(2) } } }); }],
]) test(`unchanged comparator detects synthetic discrepancy: ${name}`, () => {
  const l = actualControl(); mutate(l); const result = compare(l);
  assert.equal(result.verdict, "MISMATCH"); assert.equal(result.counts.mismatch, 1);
});
for (const [name, mutate] of [
  ["missing case", l => { delete l[entry.programId].steps[entry.stepIds[0]]; }],
  ["non-JSON response", l => { l[entry.programId].steps[entry.stepIds[0]] = { status: 200, code: "non-json" }; }],
  ["no HTTP reply", l => { l[entry.programId].steps[entry.stepIds[0]] = { status: 0, code: "no-response" }; }],
  ["failed setup", l => { l[entry.programId].seedError = "synthetic"; }],
]) test(`missing usable data stays INDETERMINATE: ${name}`, () => {
  const l = actualControl(); mutate(l); assert.equal(compare(l).verdict, "INDETERMINATE");
});

// Real network only to an ephemeral loopback peer. Ambient proxy/ADC/production
// variables are deliberately poisoned; the child must still use only this peer.
async function wire(options = {}) {
  const dir = await fs.mkdtemp(join(tmpdir(), "fireemu-agg-029-"));
  const requests = [], errors = []; let resets = 0, sequence = 0, child;
  const resetPath = `/emulator/v1/projects/${entry.project}/databases/(default)/documents`;
  const server = createServer(async (req, res) => {
    const send = (status, value, raw = false) => { res.writeHead(status, { "content-type": "application/json" }); res.end(raw ? value : JSON.stringify(value)); };
    try {
      const chunks = []; for await (const chunk of req) chunks.push(chunk);
      const raw = Buffer.concat(chunks).toString(); const body = raw ? JSON.parse(raw) : undefined;
      requests.push({ method: req.method, path: req.url, body });
      if (req.method === "DELETE" && req.url === resetPath) { assert.equal(req.headers.authorization, undefined); resets++; return send(200, {}); }
      assert.equal(req.headers.authorization, "Bearer owner");
      if (resets === 2) {
        assert.equal(req.method, "GET"); const path = req.url.split("/documents/")[1];
        assert.ok(entry.ownedDocuments.includes(path));
        if (options.cleanupRemaining && path === "agg/f") return send(200, { name: prefix.slice(4) + "/agg/f" });
        return send(404, { error: { code: 404, status: "NOT_FOUND" } });
      }
      assert.equal(resets, 1);
      if (sequence < 6) {
        const seed = program.seed[sequence++]; assert.equal(req.method, "PATCH");
        assert.equal(req.url, substitute(seed.path)); assert.deepEqual(body, { fields: substitute(seed.fields) });
        if (options.seedFailure && sequence === 3) return send(503, { error: { code: 503, status: "UNAVAILABLE" } });
        return send(200, { name: substitute(seed.path).slice(4), updateTime: TIME });
      }
      const step = program.steps[sequence++ - 6]; assert.ok(step);
      assert.equal(req.method, "POST"); assert.equal(req.url, prefix + ":runAggregationQuery");
      assert.deepEqual(body, substitute(step.body));
      if (options.nonJson && step.id === "count-all") return send(200, "not-json", true);
      const r = response(step.id, options); return send(r.status, r.body);
    } catch (error) { errors.push(String(error)); return send(500, { error: { code: 500, status: "INTERNAL" } }); }
  });
  try {
    await fs.mkdir(join(dir, "legacy"));
    for (const [name, pin] of [["session.mjs", entry.sessionBlob], ["credentials.mjs", entry.credentialsBlob]]) {
      const bytes = await fs.readFile(resolve(HERE, "../../src/firestore-probe", name));
      assert.equal(blobSha(bytes), pin); await fs.writeFile(join(dir, "legacy", name), bytes);
    }
    const p = structuredClone(program); if (options.inputDrift) p.steps[0].body.structuredAggregationQuery.structuredQuery.limit = 1;
    await fs.writeFile(join(dir, "program.json"), JSON.stringify(p));
    await fs.writeFile(join(dir, "programs.json"), JSON.stringify([p]));
    server.listen(0, "127.0.0.1"); await once(server, "listening");
    const stderr = [];
    child = spawn(process.execPath, [resolve(HERE, "../local-session.mjs")], { cwd: dir,
      env: { ...cleanEnvironment(dir), PILOT_RUN_DIR: dir, PILOT_CASE_ID: entry.id,
        GOOGLE_CLOUD_PROJECT: entry.project, FIRESTORE_EMULATOR_HOST: `127.0.0.1:${server.address().port}`,
        FIRESTORE_PROBE_HOST: "example.invalid", FIRESTORE_PROBE_TARGET: "production",
        FIRESTORE_PROBE_TOKEN: "SYNTHETIC_NEVER_SEND", FIRESTORE_PROBE_SCHEME: "https" },
      stdio: ["ignore", "ignore", "pipe"],
    });
    child.stderr.on("data", bytes => stderr.push(bytes));
    let expired = false; const timer = setTimeout(() => { expired = true; child.kill("SIGKILL"); }, 12000);
    let exit; try { [exit] = await once(child, "close"); } finally { clearTimeout(timer); }
    assert.equal(expired, false, "test watchdog is not product success");
    const read = name => fs.readFile(join(dir, name), "utf8").then(JSON.parse).catch(() => null);
    return { exit, requests, errors, session: await read("session-result.json"), local: await read("local.json"),
      localBytes: await fs.readFile(join(dir, "local.json")).catch(() => null), stderr: Buffer.concat(stderr).toString() };
  } finally {
    if (child && child.exitCode === null && child.signalCode === null) { child.kill("SIGKILL"); await once(child, "close").catch(() => {}); }
    server.closeAllConnections(); await new Promise(done => server.close(done));
    await fs.rm(dir, { recursive: true, force: true });
  }
}
function envelope(r) {
  return resultEnvelope({ entry, comparison: compare(r.local), execution: {
    state: r.session.completed ? "completed" : "failed", cleanup: r.session.cleanup,
    process: { state: "stopped" },
  }, provenance: { testOnly: true } });
}
test("real recorder performs all 37 requests and preserves types, aliases and refused rows", { timeout: 15000 }, async () => {
  const r = await wire(); assert.equal(r.exit, 0, r.stderr); assert.deepEqual(r.errors, []);
  assert.equal(r.requests.length, 37); assert.equal(r.session.requestCount, 30);
  assert.equal(r.session.completed, true); assert.equal(r.session.cleanup.requests, 7);
  assert.equal(r.session.cleanup.state, "confirmed"); assert.deepEqual(r.session.cleanup.absent, entry.ownedDocuments);
  assert.deepEqual(r.session.requests.map(row => row.phase), [...entry.sessionSetupPhases, ...entry.stepIds]);
  assert.equal(r.session.productionRequests, 0); assert.equal(r.session.localSha256, sha256(r.localBytes));
  verifySession(r.session, { entry, program }, r.localBytes);
  assert.equal(fieldsAt(r.local, "avg-with-nan").avg.doubleValue, "NaN");
  assert.deepEqual(fieldsAt(r.local, "avg-empty").avg, { nullValue: null });
  assert.equal(r.local[entry.programId].steps["count-all"].body[0].readTime, "<now>");
  for (const id of refusalIds) assert.equal(r.local[entry.programId].steps[id].code, "INVALID_ARGUMENT");
  const result = envelope(r); assert.equal(result.comparison.counts.match, 23); assert.equal(gateExitCode(result), 0);
  assert.equal(result.parent, "FS-QUERY-INDEX"); assert.equal(result.parentPromotion, false); assert.equal(result.productionExecuted, false);
  const tampered = structuredClone(r.session); tampered.cleanup.absent.pop();
  assert.throws(() => verifySession(tampered, { entry, program }, r.localBytes), /local-cleanup-binding/);
});
test("real recorder completes a semantic disagreement without converting it to missing data", { timeout: 15000 }, async () => {
  const r = await wire({ wrongSum: true }); assert.equal(r.exit, 0, r.stderr); assert.deepEqual(r.errors, []);
  verifySession(r.session, { entry, program }, r.localBytes);
  const result = envelope(r); assert.equal(result.comparison.verdict, "MISMATCH"); assert.equal(result.comparison.counts.mismatch, 1);
  assert.equal(result.complete, true); assert.equal(gateExitCode(result), 1);
});
test("same service failure is captured, not replaced with a fabricated aggregate", { timeout: 15000 }, async () => {
  const r = await wire({ unavailable: "count-all" }); assert.equal(r.exit, 0, r.stderr);
  assert.deepEqual(r.errors, []); assert.equal(r.local[entry.programId].steps["count-all"].status, 503);
  assert.equal(compare(r.local).verdict, "MISMATCH"); assert.equal(r.session.cleanup.state, "confirmed");
});
test("non-JSON success cannot pass the final comparison", { timeout: 15000 }, async () => {
  const r = await wire({ nonJson: true }); assert.deepEqual(r.errors, []);
  assert.equal(r.session.completed, true); const result = envelope(r);
  assert.equal(result.comparison.verdict, "INDETERMINATE"); assert.equal(gateExitCode(result), 2);
});
test("cleanup failure retains INDETERMINATE even when all 23 synthetic replies match", { timeout: 15000 }, async () => {
  const r = await wire({ cleanupRemaining: true }); assert.notEqual(r.exit, 0); assert.deepEqual(r.errors, []);
  assert.equal(compare(r.local).counts.match, 23); assert.equal(r.session.cleanup.state, "unconfirmed");
  assert.equal(envelope(r).comparison.verdict, "INDETERMINATE"); assert.equal(gateExitCode(envelope(r)), 2);
});
test("seed failure never proceeds to aggregations and cleanup covers all declared seed paths", { timeout: 15000 }, async () => {
  const r = await wire({ seedFailure: true }); assert.notEqual(r.exit, 0); assert.deepEqual(r.errors, []);
  assert.equal(r.session.completed, false); assert.equal(r.session.cleanup.state, "confirmed");
  assert.deepEqual(r.session.cleanup.absent, entry.ownedDocuments);
  assert.equal(r.requests.filter(row => row.path.endsWith(":runAggregationQuery")).length, 0);
  assert.throws(() => verifySession(r.session, { entry, program }, r.localBytes), /local-request-count/);
});
test("source drift fails before first network operation", { timeout: 15000 }, async () => {
  const r = await wire({ inputDrift: true }); assert.notEqual(r.exit, 0);
  assert.equal(r.requests.length, 0); assert.equal(r.session, null);
});
