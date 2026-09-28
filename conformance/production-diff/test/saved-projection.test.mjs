// FS-EVID-PROJECTION-LISTING-027. The HTTP peer is a SYNTHETIC protocol fixture.
// It is neither Firestore nor a production Oracle. The pinned real recorder,
// transport, parent verifier and original comparator are used without mocks.
import assert from "node:assert/strict";
import { test } from "node:test";
import { promises as fs } from "node:fs";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CASE, CASES, TRANSFORMS_CASE, PRECONDITIONS_CASE, PROJECTION_CASE as entry, selectCase } from "../registry.mjs";
import { blobSha, digestJson, sha256, validateProgram, selectProduction, resolveRecordedPath,
  compareRecords, resultEnvelope, gateExitCode } from "../core.mjs";
import { comparatorModuleSource, importText } from "../legacy.mjs";
import { cleanEnvironment } from "../io.mjs";
import { verifySession, parseArgs, main } from "../pilot.mjs";
const HERE = dirname(fileURLToPath(import.meta.url));
const program = JSON.parse(await fs.readFile(join(HERE, "fixtures/saved-projection-program.json"), "utf8"));
const pure = comparatorModuleSource(await fs.readFile(join(HERE, "legacy-comparator.excerpt.txt"), "utf8"));
assert.equal(sha256(pure), entry.comparatorSliceSha256);
const { compareProductionToFireemu: comparator } = await importText(pure);
const PAGE_TOKEN = "fixture+slash/equals= space?amp&#%日本語";
const TIME = "2026-01-02T03:04:05.123456Z";
const PREFIX = `projects/${entry.project}/databases/(default)/documents/`;
const sub = value => value === undefined ? undefined :
  JSON.parse(JSON.stringify(value).replaceAll("PROJECT", entry.project));
const a = { name: PREFIX + "prj/a", fields: { a: { integerValue: "1" }, b: { mapValue: { fields: { c: { integerValue: "2" }, d: { integerValue: "3" } } } }, e: { arrayValue: { values: [{ integerValue: "1" }] } } }, createTime: TIME, updateTime: TIME };
const b = { name: PREFIX + "prj/b", fields: { a: { integerValue: "2" } }, createTime: TIME, updateTime: TIME };
const x = { name: PREFIX + "prj/missing-parent/sub/x", fields: { z: { integerValue: "1" } }, createTime: TIME, updateTime: TIME };
const missing = { name: PREFIX + "prj/missing-parent" };
const noFields = ({ fields, ...doc }) => doc;
const onlyA = doc => ({ ...noFields(doc), fields: { a: doc.fields.a } });
const queryRows = docs => docs.map(document => ({ document, readTime: TIME }));
// Explicit local protocol responses, not copied from the saved production matrix.
function reply(id, { missingToken = false, corruptBody = false, token = PAGE_TOKEN } = {}) {
  let body;
  switch (id) {
    case "select-fields": body = queryRows([{ ...onlyA(a), fields: { a: a.fields.a, b: { mapValue: { fields: { c: a.fields.b.mapValue.fields.c } } } } }, onlyA(b)]); break;
    case "select-missing-field": body = queryRows([noFields(a), noFields(b)]); break;
    case "select-with-empty-list": body = queryRows([a, b]); break;
    case "list-documents": body = { documents: [a, b] }; break;
    case "list-documents-page-size-one": body = { documents: [a], ...(missingToken ? {} : { nextPageToken: token }) }; break;
    case "list-documents-next-page": body = { documents: [b] }; break;
    case "list-documents-with-mask": body = { documents: [onlyA(a), onlyA(b)] }; break;
    case "list-documents-descending": body = { documents: [b, a] }; break;
    case "list-documents-show-missing":
    case "list-missing-parents": body = { documents: [a, b, missing] }; break;
    case "list-subcollection-of-missing-parent": body = { documents: [x] }; break;
    case "list-empty-collection": body = {}; break;
    case "list-collection-ids-root": body = { collectionIds: ["prj"] }; break;
    case "list-collection-ids-of-a-missing-document": body = { collectionIds: ["sub"] }; break;
    case "list-collection-ids-paged": body = { collectionIds: ["prj"] }; break;
    case "get-with-mask": body = { ...noFields(a), fields: { b: { mapValue: { fields: { d: a.fields.b.mapValue.fields.d } } }, e: a.fields.e } }; break;
    case "get-missing-parent-document": return { status: 404, body: { error: { code: 404, status: "NOT_FOUND", message: "synthetic missing parent" } } };
    case "batch-get-mixed": body = [{ found: onlyA(b), readTime: TIME }, { missing: PREFIX + "prj/none", readTime: TIME }, { found: onlyA(a), readTime: TIME }]; break;
    default: throw new Error("unknown synthetic step");
  }
  body = structuredClone(body);
  if (corruptBody && id === "select-fields") body[0].document.fields.b.mapValue.fields.c.integerValue = "999";
  return { status: 200, body };
}
function normalized(value, key = "") {
  if (typeof value === "string") return value === TIME ? "<now>" : key === "nextPageToken" ? "<token>" : value;
  if (Array.isArray(value)) return value.map(item => normalized(item));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, normalized(v, k)]));
  return value;
}
function syntheticReference() {
  return { programs: [{ id: entry.programId, area: "queries", steps: Object.fromEntries(entry.stepIds.map(id => {
    const r = reply(id);
    return [id, { production: r.body.error ? { status: r.status, code: r.body.error.status, message: r.body.error.message } : { status: r.status, code: "OK", body: normalized(r.body) } }];
  })) }] };
}
const comparison = actual => compareRecords({ entry, program, production: syntheticReference(), actual, comparator });
const localFromReference = () => ({ [entry.programId]: { steps: Object.fromEntries(Object.entries(syntheticReference().programs[0].steps).map(([id, r]) => [id, structuredClone(r.production)])) } });
function syntheticMatrix() {
  return { version: 1, evidence: { verified: true, validation: [], observations: { production: {
    observation: { side: "production", mode: "live", database: { type: "FIRESTORE_NATIVE", databaseEdition: "STANDARD" } },
    source: { gitSha: entry.observedSource, trackedTreeClean: true }, inputs: { corpusDigest: entry.corpusDigest },
  } } }, ...syntheticReference() };
}

test("registration pins all 18 read steps and all three seeds", () => {
  assert.equal(selectCase(entry.id), entry);
  assert.equal(digestJson(program), entry.programDigest);
  assert.equal(validateProgram(program, entry), program);
  assert.equal(program.steps.length, 18); assert.equal(program.seed.length, 3);
  assert.equal(program.steps.at(-1).id, "batch-get-mixed");
  assert.equal(entry.parent, "FS-DATA-WRITE");
  assert.deepEqual(entry.sessionSetupPhases, ["reset", "seed", "seed", "seed"]);
  for (const key of ["matrixBlob", "observedSource", "corpusBlob", "corpusDigest", "comparatorSliceSha256", "sessionBlob", "credentialsBlob"]) assert.equal(entry[key], CASE[key]);
  for (const value of [entry, entry.stepIds, entry.ownedDocuments, entry.sessionSetupPhases]) assert.ok(Object.isFrozen(value));
});
for (const [label, mutate] of [
  ["area", p => { p.area = "writes"; }],
  ["missing seed", p => { p.seed.pop(); }],
  ["extra seed", p => { p.seed.push(structuredClone(p.seed[0])); }],
  ["seed content", p => { p.seed[0].fields.a.integerValue = "9"; }],
  ["missing step", p => { p.steps.pop(); }],
  ["order", p => { p.steps.reverse(); }],
  ["fixed token", p => { p.steps[5].path = p.steps[5].path.replace(/\{\{.*\}\}/, "fixed"); }],
]) test(`input drift is refused: ${label}`, () => {
  const p = structuredClone(program); mutate(p); assert.throws(() => validateProgram(p, entry), /program-/);
});
test("legacy cases keep their one-seed writes-only defaults", () => {
  for (const e of [CASE, TRANSFORMS_CASE, PRECONDITIONS_CASE]) {
    assert.equal(e.programArea, undefined); assert.equal(e.seedCount, undefined);
    assert.throws(() => validateProgram({ ...program, id: e.programId }, e), /program-identity/);
  }
  assert.equal(selectCase(), CASE);
});
test("production selection preserves queries area and never selects emulator/fireemu", () => {
  const m = syntheticMatrix();
  for (const row of Object.values(m.programs[0].steps)) { row.emulator = { status: 500, code: "INTERNAL" }; row.fireemu = { status: 500, code: "INTERNAL" }; }
  assert.deepEqual(selectProduction(m, entry), syntheticReference());
});
for (const [label, mutate] of [
  ["local oracle", m => { m.evidence.observations.production.observation.side = "fireemu"; }],
  ["no live observation", m => { m.evidence.observations.production.observation.mode = "stored"; }],
  ["source changed", m => { m.evidence.observations.production.source.gitSha = "0".repeat(40); }],
  ["corpus changed", m => { m.evidence.observations.production.inputs.corpusDigest = "other"; }],
  ["missing row", m => { delete m.programs[0].steps[entry.stepIds[0]]; }],
  ["incomplete row", m => { m.programs[0].steps[entry.stepIds[0]].production = { missing: true }; }],
]) test(`synthetic selector negative: ${label}`, () => {
  const m = syntheticMatrix(); mutate(m); assert.throws(() => selectProduction(m, entry), /oracle-/);
});
test("raw page-token is encoded once; query delimiters cannot alter the route", () => {
  const p = resolveRecordedPath(program.steps[5].path, new Map([[entry.stepIds[4], { nextPageToken: PAGE_TOKEN }]]));
  assert.equal(p, "/v1/projects/PROJECT/databases/(default)/documents/prj?pageSize=1&pageToken=" + encodeURIComponent(PAGE_TOKEN));
  const parsed = new URL("http://127.0.0.1:1234" + p);
  assert.equal(parsed.searchParams.get("pageToken"), PAGE_TOKEN);
  assert.deepEqual([...parsed.searchParams.keys()], ["pageSize", "pageToken"]);
  assert.equal(parsed.hash, "");
});
test("raw apostrophe token differs from canonical URL text without changing its value", () => {
  const token = "cursor'next";
  const raw = resolveRecordedPath(program.steps[5].path, new Map([[entry.stepIds[4], { nextPageToken: token }]]));
  const parsed = new URL("http://127.0.0.1:1234" + raw);
  assert.notEqual(raw, parsed.pathname + parsed.search);
  assert.equal(parsed.searchParams.get("pageToken"), token);
});
test("path references preserve pre-escaped bytes instead of decoding twice", () => {
  assert.equal(resolveRecordedPath("/x?token={{step.nextPageToken}}", new Map([["step", { nextPageToken: "%2F%26" }]])), "/x?token=%252F%2526");
});
test("literal paths are unchanged; transaction shorthand and nested array reference work", () => {
  assert.equal(resolveRecordedPath("/unchanged?q=a%20b", new Map()), "/unchanged?q=a%20b");
  const raw = new Map([["step", { transaction: "raw/+", rows: [{ token: "nest /" }] }]]);
  assert.equal(resolveRecordedPath("/x?t={{step}}&p={{step.rows.0.token}}", raw), "/x?t=raw%2F%2B&p=nest%20%2F");
});
for (const [label, value] of [["empty", ""], ["null", null], ["array", ["token"]], ["object", { token: "x" }], ["number", 0], ["boolean", false]]) test(`path token is not coerced: ${label}`, () => {
  assert.throws(() => resolveRecordedPath("/x?p={{step.nextPageToken}}", new Map([["step", { nextPageToken: value }]])), /recorder-path-reference-invalid/);
});
for (const [label, refs] of [["future", new Map()], ["missing", new Map([["step", {}]])], ["inherited", new Map([["step", Object.create({ nextPageToken: "hidden" })]])]]) test(`path reference is unavailable: ${label}`, () => {
  assert.throws(() => resolveRecordedPath("/x?p={{step.nextPageToken}}", refs), /recorder-reference-unavailable/);
});
test("CLI lists/selects the new case and preserves the default", async () => {
  assert.equal(parseArgs(["plan", "--case", entry.id]).case, entry.id);
  assert.equal(parseArgs(["plan"]).case, CASE.id);
  const save = console.log; let out;
  try { console.log = s => { out = s; }; assert.equal(await main(["list"]), 0); } finally { console.log = save; }
  assert.deepEqual(JSON.parse(out).cases.map(c => c.id), CASES.map(c => c.id));
});
for (const [label, mutate] of [
  ["nested projection value", s => { s["select-fields"].body[0].document.fields.b.mapValue.fields.c.integerValue = "900"; }],
  ["projection leakage", s => { s["select-fields"].body[0].document.fields.b.mapValue.fields.d = { integerValue: "3" }; }],
  ["wrong next page", s => { s["list-documents-next-page"].body.documents[0].name = PREFIX + "prj/a"; }],
  ["descending order", s => { s["list-documents-descending"].body.documents.reverse(); }],
  ["missing virtual parent", s => { s["list-documents-show-missing"].body.documents.pop(); }],
  ["get mask leakage", s => { s["get-with-mask"].body.fields.a = { integerValue: "1" }; }],
  ["BatchGet missing name", s => { s["batch-get-mixed"].body[1].missing = PREFIX + "prj/other"; }],
  ["wrong subcollection", s => { s["list-collection-ids-of-a-missing-document"].body.collectionIds = ["other"]; }],
]) test(`original comparator detects synthetic semantic difference: ${label}`, () => {
  const local = localFromReference(); mutate(local[entry.programId].steps);
  const r = comparison(local); assert.equal(r.verdict, "MISMATCH"); assert.equal(r.counts.mismatch, 1);
});
test("missing observations stay INDETERMINATE", () => {
  const local = localFromReference(); delete local[entry.programId].steps[entry.stepIds.at(-1)];
  assert.equal(comparison(local).verdict, "INDETERMINATE");
});

async function wire(options = {}) {
  const dir = await fs.mkdtemp(join(tmpdir(), "fireemu-projection-027-"));
  const requests = [], errors = []; let resets = 0, count = 0, child;
  const resetPath = `/emulator/v1/projects/${entry.project}/databases/(default)/documents`;
  const server = createServer(async (req, res) => {
    const send = (status, body) => { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };
    try {
      const chunks = []; for await (const chunk of req) chunks.push(chunk);
      const raw = Buffer.concat(chunks).toString(); const body = raw ? JSON.parse(raw) : undefined;
      requests.push({ method: req.method, path: req.url, body });
      if (req.method === "DELETE" && req.url === resetPath) { assert.equal(req.headers.authorization, undefined); resets++; return send(200, {}); }
      assert.equal(req.headers.authorization, "Bearer owner");
      if (resets === 2) {
        assert.equal(req.method, "GET");
        const path = req.url.split("/documents/")[1]; assert.ok(entry.ownedDocuments.includes(path));
        if (options.cleanupRemaining && path === "prj/missing-parent/sub/x") return send(200, x);
        return send(404, { error: { code: 404, status: "NOT_FOUND" } });
      }
      assert.equal(resets, 1);
      if (count < program.seed.length) {
        const seed = program.seed[count++]; assert.equal(req.method, "PATCH");
        assert.equal(req.url, sub(seed.path)); assert.deepEqual(body, { fields: sub(seed.fields) });
        return send(200, { name: seed.path.slice(4), updateTime: TIME });
      }
      const spec = program.steps[count++ - program.seed.length]; assert.ok(spec);
      let expectedPath = sub(spec.path);
      // Independent finite handoff check, not the implementation's resolver.
      if (spec.id === "list-documents-next-page") {
        const rawPath = `/v1/projects/${entry.project}/databases/(default)/documents/prj?pageSize=1&pageToken=${encodeURIComponent(options.token ?? PAGE_TOKEN)}`;
        const canonical = new URL(`http://127.0.0.1${rawPath}`);
        expectedPath = canonical.pathname + canonical.search;
      }
      assert.equal(req.method, spec.method); assert.equal(req.url, expectedPath);
      assert.deepEqual(body, sub(spec.body));
      const r = reply(spec.id, options); return send(r.status, r.body);
    } catch (error) { errors.push(String(error)); return send(500, { error: { code: 500, status: "INTERNAL" } }); }
  });
  try {
    await fs.mkdir(join(dir, "legacy"));
    for (const [name, pin] of [["session.mjs", entry.sessionBlob], ["credentials.mjs", entry.credentialsBlob]]) {
      const bytes = await fs.readFile(resolve(HERE, "../../src/firestore-probe", name));
      assert.equal(blobSha(bytes), pin); await fs.writeFile(join(dir, "legacy", name), bytes);
    }
    const p = structuredClone(program); if (options.drift) p.steps[0].body.structuredQuery.limit = 1;
    await fs.writeFile(join(dir, "program.json"), JSON.stringify(p));
    await fs.writeFile(join(dir, "programs.json"), JSON.stringify([p]));
    server.listen(0, "127.0.0.1"); await once(server, "listening");
    const stderr = [];
    child = spawn(process.execPath, [resolve(HERE, "../local-session.mjs")], { cwd: dir,
      env: { ...cleanEnvironment(dir), PILOT_RUN_DIR: dir, PILOT_CASE_ID: entry.id,
        GOOGLE_CLOUD_PROJECT: entry.project, FIRESTORE_EMULATOR_HOST: `127.0.0.1:${server.address().port}` },
      stdio: ["ignore", "ignore", "pipe"],
    });
    child.stderr.on("data", bytes => stderr.push(bytes));
    let expired = false; const watchdog = setTimeout(() => { expired = true; child.kill("SIGKILL"); }, 12000);
    let exit; try { [exit] = await once(child, "close"); } finally { clearTimeout(watchdog); }
    assert.equal(expired, false, "test watchdog is not a successful product timeout");
    const read = name => fs.readFile(join(dir, name), "utf8").then(JSON.parse).catch(() => null);
    return { exit, requests, errors, session: await read("session-result.json"), local: await read("local.json"),
      localBytes: await fs.readFile(join(dir, "local.json")).catch(() => null), stderr: Buffer.concat(stderr).toString() };
  } finally {
    if (child && child.exitCode === null && child.signalCode === null) { child.kill("SIGKILL"); await once(child, "close").catch(() => {}); }
    server.closeAllConnections(); await new Promise(done => server.close(done));
    await fs.rm(dir, { recursive: true, force: true });
  }
}

test("real recorder completes 18 steps, carries raw page token and verifies all five cleanup paths", { timeout: 15000 }, async () => {
  const r = await wire(); assert.equal(r.exit, 0, r.stderr); assert.deepEqual(r.errors, []);
  assert.equal(r.requests.length, 28); assert.equal(r.session.requestCount, 22);
  assert.equal(r.session.cleanup.requests, 6); assert.equal(r.session.cleanup.state, "confirmed");
  assert.deepEqual(r.session.cleanup.absent, entry.ownedDocuments);
  assert.equal(r.session.completed, true); assert.equal(r.session.productionRequests, 0);
  assert.deepEqual(r.session.requests.map(row => row.phase), [...entry.sessionSetupPhases, ...entry.stepIds]);
  const sent = r.session.requests.find(row => row.phase === "list-documents-next-page");
  assert.equal(new URL("http://127.0.0.1" + sent.path).searchParams.get("pageToken"), PAGE_TOKEN);
  assert.equal(r.local[entry.programId].steps["list-documents-page-size-one"].body.nextPageToken, "<token>");
  assert.equal(r.local[entry.programId].steps["list-collection-ids-root"].code, "OK");
  assert.equal(r.session.localSha256, sha256(r.localBytes));
  verifySession(r.session, { entry, program }, r.localBytes);
  const compared = comparison(r.local); assert.equal(compared.verdict, "MATCH"); assert.equal(compared.counts.match, 18);
});
test("missing raw page token never sends a normalized/fabricated token; cleanup still runs", { timeout: 15000 }, async () => {
  const r = await wire({ missingToken: true }); assert.notEqual(r.exit, 0); assert.deepEqual(r.errors, []);
  assert.equal(r.session.completed, false); assert.equal(r.session.cleanup.state, "confirmed");
  assert.ok(!r.requests.some(req => req.path.includes("pageToken=")));
  assert.equal(comparison(r.local).verdict, "INDETERMINATE");
});
test("path-like token stays in its one query parameter, never changes origin or route", { timeout: 15000 }, async () => {
  const token = "https://elsewhere.invalid/path?x=1&y=2#frag";
  const r = await wire({ token }); assert.equal(r.exit, 0, r.stderr); assert.deepEqual(r.errors, []);
  const sent = r.session.requests.find(row => row.phase === "list-documents-next-page");
  const url = new URL("http://127.0.0.1" + sent.path); assert.equal(url.pathname, `/v1/projects/${entry.project}/databases/(default)/documents/prj`);
  assert.equal(url.searchParams.get("pageToken"), token); assert.equal(url.hash, "");
});
for (const token of ["cursor'next", "quote'&x=1"]) test(`apostrophe token is accepted by the wire recorder: ${token}`, { timeout: 15000 }, async () => {
  const r = await wire({ token }); assert.equal(r.exit, 0, r.stderr); assert.deepEqual(r.errors, []);
  const sent = r.session.requests.find(row => row.phase === "list-documents-next-page");
  assert.ok(sent);
  const url = new URL("http://127.0.0.1" + sent.path);
  assert.equal(url.searchParams.get("pageToken"), token);
  assert.equal(r.session.completed, true); assert.equal(r.session.cleanup.state, "confirmed");
});
test("complete synthetic mismatch stays MISMATCH rather than being swallowed by the runner", { timeout: 15000 }, async () => {
  const r = await wire({ corruptBody: true }); assert.equal(r.exit, 0, r.stderr); assert.deepEqual(r.errors, []);
  verifySession(r.session, { entry, program }, r.localBytes);
  const compared = comparison(r.local); assert.equal(compared.verdict, "MISMATCH"); assert.equal(compared.counts.mismatch, 1);
});
test("remaining descendant after reset cannot produce an accepted result", { timeout: 15000 }, async () => {
  const r = await wire({ cleanupRemaining: true }); assert.notEqual(r.exit, 0); assert.deepEqual(r.errors, []);
  assert.equal(r.session.completed, true); assert.equal(r.session.cleanup.state, "unconfirmed");
  const result = resultEnvelope({ entry, comparison: comparison(r.local), provenance: { syntheticProtocolFixture: true },
    execution: { state: "completed", cleanup: r.session.cleanup, process: { state: "stopped" } } });
  assert.equal(result.complete, false); assert.equal(result.comparison.verdict, "INDETERMINATE"); assert.equal(gateExitCode(result), 2);
});
test("input drift is refused before network traffic", { timeout: 15000 }, async () => {
  const r = await wire({ drift: true }); assert.notEqual(r.exit, 0); assert.equal(r.requests.length, 0); assert.equal(r.session, null);
});
test("parent verifier rejects a missing seed observation or missing descendant absence", { timeout: 15000 }, async () => {
  const r = await wire(); assert.equal(r.exit, 0, r.stderr);
  const first = structuredClone(r.session); first.requests.splice(2, 1); first.requestCount--;
  assert.throws(() => verifySession(first, { entry, program }, r.localBytes), /local-request-count/);
  const second = structuredClone(r.session); second.cleanup.absent = second.cleanup.absent.filter(p => p !== "prj/missing-parent/sub/x"); second.cleanup.requests--;
  assert.throws(() => verifySession(second, { entry, program }, r.localBytes), /local-cleanup-binding/);
});
