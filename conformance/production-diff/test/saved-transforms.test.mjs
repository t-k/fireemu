// The HTTP peer below replays SAVED decisions. It is not fireemu or production.
// Real pinned session/credential code, HTTP I/O and comparator are exercised.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { CASE, CASES, selectCase } from "../registry.mjs";
import { blobSha, sha256, digestJson, validateProgram, compareRecords, resultEnvelope, gateExitCode } from "../core.mjs";
import { comparatorModuleSource, importText } from "../legacy.mjs";
import { cleanEnvironment } from "../io.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(await fs.readFile(join(HERE, "fixtures/saved-transforms.json"), "utf8"));
const CASE_ID = "fs.transforms.saved-20260907.v1";
const pure = comparatorModuleSource(await fs.readFile(join(HERE, "legacy-comparator.excerpt.txt"), "utf8"));
assert.equal(sha256(pure), CASE.comparatorSliceSha256);
const { compareProductionToFireemu: comparator } = await importText(pure);
const entry = () => selectCase(CASE_ID);
const localFromFixture = () => ({
  [fixture.program.id]: {
    steps: Object.fromEntries(Object.entries(fixture.production.programs[0].steps)
      .map(([id, row]) => [id, structuredClone(row.production)])),
  },
});
const compare = (actual, program = fixture.program) => compareRecords({
  entry: entry(), program, production: fixture.production, actual, comparator,
});

test("registered transforms select the entire historical 18-step program", () => {
  const e = entry();
  assert.equal(e.parent, "FS-DATA-WRITE");
  assert.equal(e.evidenceKind, "saved-production-reference");
  assert.equal(e.oracleKind, "legacy-normalized-production-observation");
  assert.equal(e.profile, "strict");
  assert.equal(e.adapter, "batch-write");
  assert.equal(e.sessionScript, "local-session.mjs");
  assert.equal(CASES.filter(c => c.id === CASE_ID).length, 1);
  assert.equal(validateProgram(fixture.program, e).steps.length, 18);
  assert.deepEqual(e.stepIds, fixture.program.steps.map(s => s.id));
  assert.deepEqual(e.sessionSetupPhases, ["reset", "seed"]);
  assert.equal(fixture.program.seed.length, 1);
});

test("the new case reuses all original production and recorder pins", () => {
  for (const key of ["matrixPath", "matrixBlob", "observedSource", "corpusPath", "corpusBlob", "corpusDigest", "comparatorPath", "comparatorSliceSha256", "sessionPath", "sessionBlob", "credentialsPath", "credentialsBlob"])
    assert.equal(entry()[key], CASE[key], key);
  assert.equal(fixture.source.matrixBlob, entry().matrixBlob);
  assert.equal(fixture.source.corpusBlob, entry().corpusBlob);
  assert.equal(fixture.source.observedSource, entry().observedSource);
  assert.equal(digestJson(fixture.production), "31c0907b8df21b139ea0b0a4aa8f0f02f1db8655f54a196ba425a1074099ed67");
});

test("legacy default case remains the default; new case cannot mutate it", () => {
  assert.equal(selectCase(), CASE);
  assert.equal(CASE.programId, "writes/batch-write");
  assert.equal(CASE.stepIds.length, 5);
  for (const value of [entry(), entry().stepIds, entry().ownedDocuments]) assert.ok(Object.isFrozen(value));
  assert.notEqual(entry().stepIds, CASE.stepIds);
  assert.throws(() => selectCase("unregistered-transform"), /unknown-case/);
});

test("the owned set covers every literal document the program may address", () => {
  const names = new Set();
  for (const seed of fixture.program.seed) names.add(seed.path.split("/documents/")[1]);
  for (const step of fixture.program.steps) {
    if (step.method === "GET") names.add(step.path.split("/documents/")[1]);
    for (const write of step.body?.writes ?? []) {
      const name = write.update?.name ?? write.transform?.document ?? write.delete;
      if (name) names.add(name.split("/documents/")[1]);
    }
  }
  assert.deepEqual([...names].sort(), [...entry().ownedDocuments].sort());
  assert.equal(names.size, 6);
});

test("maximum/minimum remains an observed refusal, not a successful maximum/minimum test", () => {
  const rows = fixture.production.programs[0].steps;
  assert.deepEqual(rows["maximum-and-minimum"].production, { status: 400, code: "INVALID_ARGUMENT" });
  assert.deepEqual(rows["read-after-max-min"].production, rows["read-after-increments"].production);
  assert.ok(entry().notEstablished.some(s => s.startsWith("Successful maximum/minimum")));
});

test("matching saved-decision control covers 14 successful and four refused responses", () => {
  const result = compare(localFromFixture());
  assert.deepEqual(result.counts, { match: 18, mismatch: 0, indeterminate: 0 });
  assert.equal(result.verdict, "MATCH");
  const rows = Object.values(fixture.production.programs[0].steps).map(s => s.production);
  assert.equal(rows.filter(r => r.code === "OK").length, 14);
  assert.equal(rows.filter(r => r.code !== "OK").length, 4);
});

for (const [label, id, change] of [
  ["wrong increment", "read-after-increments", r => { r.body.fields.n.integerValue = "4"; }],
  ["partial write on refusal", "read-after-max-min", r => { r.body.fields.n.integerValue = "100"; }],
  ["integer/double type drift", "read-after-increments", r => { r.body.fields.n = { doubleValue: 3 }; }],
  ["array element order", "read-after-array-transforms", r => { r.body.fields.tags.arrayValue.values.reverse(); }],
  ["numeric element left in array", "read-after-array-transforms", r => { r.body.fields.tags.arrayValue.values.push({ doubleValue: 1 }); }],
  ["int64 saturation overflow", "read-saturated", r => { r.body.fields.n.integerValue = "9223372036854775808"; }],
  ["NaN changed to null", "increment-on-nan", r => { r.body.writeResults[0].transformResults[0] = { nullValue: null }; }],
  ["same-field results swapped", "two-transforms-on-one-field-in-one-write", r => { r.body.writeResults[0].transformResults.reverse(); }],
  ["duplicate transform applied once", "read-dup", r => { r.body.fields.n.integerValue = "2"; }],
  ["refusal code drift", "increment-with-non-numeric-operand", r => { r.code = "FAILED_PRECONDITION"; }],
  ["refusal status drift", "transform-write-with-exists-precondition", r => { r.status = 400; }],
]) test(`saved comparison detects ${label}`, () => {
  const actual = localFromFixture();
  change(actual[fixture.program.id].steps[id]);
  const result = compare(actual);
  assert.equal(result.verdict, "MISMATCH");
  assert.deepEqual(result.counts, { match: 17, mismatch: 1, indeterminate: 0 });
  assert.equal(result.rows.find(r => r.stepId === id).comparison, "MISMATCH");
});

test("error wording remains explicitly outside this old recorder comparison contract", () => {
  const actual = localFromFixture();
  actual[fixture.program.id].steps["maximum-and-minimum"].message = "different wording";
  assert.equal(compare(actual).verdict, "MATCH");
});

for (const [label, change] of [
  ["missing row", steps => { delete steps["read-dup"]; }],
  ["extra row", steps => { steps["not-in-program"] = { status: 200, code: "OK", body: {} }; }],
  ["transport failure", steps => { steps["read-dup"] = { status: 0, code: "probe-error" }; }],
]) test(`incomplete ${label} is not an accepted mismatch or match`, () => {
  const actual = localFromFixture(); change(actual[fixture.program.id].steps);
  const result = compare(actual);
  assert.equal(result.verdict, "INDETERMINATE");
  assert.ok(result.counts.indeterminate > 0);
});

test("changing the malformed historical field path is input drift, not a corpus repair", () => {
  const program = structuredClone(fixture.program);
  program.steps[2].body.writes[0].updateTransforms[3].fieldPath = "`max-missing`";
  assert.throws(() => compare(localFromFixture(), program), /program-input-drift/);
});

test("changing or splitting the operation order is refused", () => {
  const program = structuredClone(fixture.program);
  program.steps.reverse();
  assert.throws(() => compare(localFromFixture(), program), /program-step-set/);
});

function envelope(comparison, state = "confirmed") {
  return resultEnvelope({entry:entry(), comparison, execution:{state:"completed",cleanup:{state},process:{state:"stopped"}},provenance:{testFixture:true}});
}
test("an exact response match does not hide uncertain cleanup", () => {
  const result = envelope(compare(localFromFixture()), "unconfirmed");
  assert.equal(result.complete, false); assert.equal(result.gatePassed, false); assert.equal(gateExitCode(result), 2);
});

// Execute the actual pinned recorder, not a replacement implementation. The
// fixture HTTP server verifies every request and replays only the viewed saved
// decisions. It deliberately makes no emulator implementation/parity claim.
async function runWireFixture({ mutate = null, cleanupFail = false, caseId = CASE_ID, drift = false } = {}) {
  const directory = await fs.mkdtemp(join(tmpdir(), "fireemu-saved-transforms-"));
  const requests = [], errors = [];
  let count = 0, resetCount = 0, child;
  const program = structuredClone(fixture.program);
  if (drift) program.steps[0].body.writes[0].updateTransforms[1].increment.integerValue = "999";
  const expectedEntry = entry();
  const project = expectedEntry.project;
  const subst = value => JSON.parse(JSON.stringify(value).replaceAll("PROJECT",project));
  const reset = `/emulator/v1/projects/${project}/databases/(default)/documents`;
  const decisions = Object.values(fixture.production.programs[0].steps).map(r => structuredClone(r.production));
  if (mutate) mutate(decisions);
  const send = (res,status,body) => { res.writeHead(status,{"content-type":"application/json"});res.end(JSON.stringify(body).replaceAll("<now>", "2026-01-02T03:04:05.123456Z")); };
  const server = createServer(async (req,res) => {
    try {
      const chunks=[];for await (const chunk of req) chunks.push(chunk);
      const text=Buffer.concat(chunks).toString(); const body=text ? JSON.parse(text) : undefined;
      requests.push({method:req.method,path:req.url,body});
      if (req.method === "DELETE" && req.url === reset) {
        resetCount++;
        assert.equal(req.headers.authorization,undefined);
        if (resetCount === 2) assert.equal(count, fixture.program.steps.length + 1);
        return send(res,200,{});
      }
      assert.equal(req.headers.authorization,"Bearer owner");
      if (resetCount === 2) {
        const path=req.url.split("/documents/")[1];assert.ok(expectedEntry.ownedDocuments.includes(path));
        return cleanupFail && path === "tf/doc" ? send(res,200,{name:path}) : send(res,404,{error:{code:404,status:"NOT_FOUND"}});
      }
      assert.equal(resetCount,1);
      if (count === 0) {
        const seed=fixture.program.seed[0];assert.equal(req.method,"PATCH");assert.equal(req.url,seed.path.replaceAll("PROJECT",project));
        assert.deepEqual(body,{fields:subst(seed.fields)});count++;
        return send(res,200,{name:`projects/${project}/databases/(default)/documents/tf/doc`,fields:subst(seed.fields)});
      }
      const spec=fixture.program.steps[count-1], row=decisions[count-1];assert.ok(spec);
      assert.equal(req.method,spec.method);assert.equal(req.url,spec.path.replaceAll("PROJECT",project));
      assert.deepEqual(body,spec.body === undefined ? undefined : subst(spec.body));count++;
      return row.code === "OK" ? send(res,row.status,row.body) : send(res,row.status,{error:{code:row.status,status:row.code,message:"test fixture: historical wording not compared"}});
    } catch(error) { errors.push(String(error)); send(res,500,{error:{code:500,status:"INTERNAL"}}); }
  });
  try {
    await fs.mkdir(join(directory,"legacy"));
    for (const [name,pin] of [["session.mjs",expectedEntry.sessionBlob],["credentials.mjs",expectedEntry.credentialsBlob]]) {
      const raw=await fs.readFile(resolve(HERE,"../../src/firestore-probe",name));
      assert.equal(blobSha(raw),pin);await fs.writeFile(join(directory,"legacy",name),raw);
    }
    await fs.writeFile(join(directory,"program.json"),JSON.stringify(program));
    await fs.writeFile(join(directory,"programs.json"),JSON.stringify([program]));
    server.listen(0,"127.0.0.1");await once(server,"listening");
    const address=server.address(); const stderr=[];
    child=spawn(process.execPath,[resolve(HERE,"../local-session.mjs")],{
      cwd:directory,env:{...cleanEnvironment(directory),PILOT_RUN_DIR:directory,PILOT_CASE_ID:caseId,GOOGLE_CLOUD_PROJECT:project,FIRESTORE_EMULATOR_HOST:`127.0.0.1:${address.port}`},stdio:["ignore","ignore","pipe"],
    });
    child.stderr.on("data",b=>stderr.push(b));
    const timer=setTimeout(()=>child.kill("SIGKILL"),15000);
    let code;try { [code]=await once(child,"close"); } finally { clearTimeout(timer); }
    const read=async name=>fs.readFile(join(directory,name),"utf8").then(JSON.parse).catch(()=>null);
    return {code,requests,errors,session:await read("session-result.json"),actual:await read("local.json"),stderr:Buffer.concat(stderr).toString()};
  } finally {
    if (child && child.exitCode === null && child.signalCode === null) { child.kill("SIGKILL");await once(child,"close").catch(()=>{}); }
    server.closeAllConnections();await new Promise(done=>server.close(done));
    await fs.rm(directory,{recursive:true,force:true});
  }
}

test("actual pinned recorder replays all 18 saved decisions and checks absence of six documents", { timeout: 20000 }, async () => {
  const run=await runWireFixture();
  assert.equal(run.code,0,run.stderr);assert.deepEqual(run.errors,[]);
  assert.equal(run.requests.length,27);assert.equal(run.session.requestCount,20);
  assert.deepEqual(run.session.requests.map(r=>r.phase),["reset","seed",...entry().stepIds]);
  assert.equal(run.session.caseId,CASE_ID);assert.equal(run.session.programDigest,entry().programDigest);
  assert.equal(run.session.productionRequests,0);assert.equal(run.session.completed,true);
  assert.deepEqual(run.session.cleanup,{state:"confirmed",absent:entry().ownedDocuments,requests:7});
  assert.deepEqual(compare(run.actual).counts,{match:18,mismatch:0,indeterminate:0});
  assert.equal(envelope(compare(run.actual)).parentPromotion,false);
});

test("actual recorder preserves a wrong applied increment as a semantic mismatch", { timeout: 20000 }, async () => {
  const run=await runWireFixture({mutate:rows=>{rows[1].body.fields.n.integerValue="4";}});
  assert.equal(run.code,0,run.stderr);assert.deepEqual(run.errors,[]);
  assert.deepEqual(compare(run.actual).counts,{match:17,mismatch:1,indeterminate:0});
});

test("actual recorder does not promote a match when cleanup absence fails", { timeout: 20000 }, async () => {
  const run=await runWireFixture({cleanupFail:true});
  assert.equal(run.code,2,run.stderr);assert.deepEqual(run.errors,[]);
  assert.equal(run.session.cleanup.state,"unconfirmed");
  assert.equal(gateExitCode(envelope(compare(run.actual),run.session.cleanup.state)),2);
});

for (const [label, options, diagnostic] of [
  ["unknown case", {caseId:"unregistered"}, /unknown-case/],
  ["G0 in REST recorder", {caseId:"fs.g0.saved-68012694.v1"}, /wrong-local-session-adapter/],
  ["Commit-limit in REST recorder", {caseId:"fs.commit-transform-limits.saved-031c74bfe.v1"}, /wrong-local-session-adapter/],
  ["changed program", {drift:true}, /program-input-drift/],
]) test(`actual recorder rejects ${label} before any HTTP request`, { timeout: 20000 }, async () => {
  const run=await runWireFixture(options);
  assert.notEqual(run.code,0);assert.equal(run.requests.length,0);assert.match(run.stderr,diagnostic);
});
