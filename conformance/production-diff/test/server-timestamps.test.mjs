// Tests use explicit protocol fixtures, never a production run or native fireemu.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { CASE, TRANSFORMS_CASE as ENTRY } from "../registry.mjs";
import { blobSha, sha256, compareRecords } from "../core.mjs";
import { comparatorModuleSource, importText } from "../legacy.mjs";
import { cleanEnvironment } from "../io.mjs";
import { parseTimestamp, inspectTimestampSession, diagnosticExitCode, parseArgs, main } from "../check-server-timestamps.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(await fs.readFile(join(HERE, "fixtures/saved-transforms.json"), "utf8"));
const pure = comparatorModuleSource(await fs.readFile(join(HERE, "legacy-comparator.excerpt.txt"), "utf8"));
assert.equal(sha256(pure), CASE.comparatorSliceSha256);
const { compareProductionToFireemu: comparator } = await importText(pure);
const compare = actual => compareRecords({ entry: ENTRY, program: fixture.program,
  production: fixture.production, actual, comparator });
const CASE_ID = ENTRY.id;
const entry = () => ENTRY;

function syntheticSession(timestamp = "2026-01-02T03:04:05.123Z") {
  const prefix = `/v1/projects/${ENTRY.project}/databases/(default)/documents`;
  const requests = [{ phase: "reset", method: "DELETE", status: 200 },
    { phase: "seed", method: "PATCH", status: 200 }];
  for (const spec of fixture.program.steps) {
    const saved = fixture.production.programs[0].steps[spec.id].production;
    const raw = JSON.stringify(saved.body ?? { error: { code: saved.status, status: saved.code } })
      .replaceAll("<now>", timestamp);
    requests.push({ phase: spec.id, method: spec.method,
      path: spec.path.replaceAll("PROJECT", ENTRY.project), status: saved.status,
      responseSha256: sha256(raw),
      ...(ENTRY.rawTimestampResponseSteps.includes(spec.id) ? { rawResponseText: raw } : {}) });
  }
  return { schema: "fireemu-production-diff-session-v1", caseId: ENTRY.id,
    programDigest: ENTRY.programDigest, productionRequests: 0, requestCount: requests.length,
    requests, completed: true, failure: null,
    cleanup: { state: "confirmed", requests: 7, absent: [...ENTRY.ownedDocuments] } };
}
function editRaw(session, id, change) {
  const row = session.requests.find(r => r.phase === id);
  const body = JSON.parse(row.rawResponseText); change(body);
  row.rawResponseText = JSON.stringify(body); row.responseSha256 = sha256(row.rawResponseText);
}

for (const [name, timestamp, nanos, aligned] of [
  ["whole-second", "1970-01-01T00:00:00Z", "0", true],
  ["millisecond", "1970-01-01T00:00:00.123Z", "123000000", true],
  ["microsecond", "1970-01-01T00:00:00.123456Z", "123456000", false],
  ["nanosecond", "1970-01-01T00:00:00.000000001Z", "1", false],
  ["padded-ms", "1970-01-01T00:00:00.123000000Z", "123000000", true],
  ["one-digit", "1970-01-01T00:00:00.1Z", "100000000", true],
  ["two-digits", "1970-01-01T00:00:00.01Z", "10000000", true],
  ["positive-offset", "1970-01-01T09:00:00.123+09:00", "123000000", true],
  ["negative-offset", "1969-12-31T19:00:00.123-05:00", "123000000", true],
  ["before-epoch", "1969-12-31T23:59:59.999999999Z", "-1", false],
  ["before-epoch-ms", "1969-12-31T23:59:59.999Z", "-1000000", true],
  ["minimum", "0001-01-01T00:00:00Z", "-62135596800000000000", true],
  ["maximum", "9999-12-31T23:59:59.999999999Z", "253402300799999999999", false],
  ["lowercase", "1970-01-01t00:00:00.123z", "123000000", true],
]) test(`timestamp parser preserves exact ${name}`, () => {
  assert.deepEqual(parseTimestamp(timestamp), { unixNanos: nanos, millisecondAligned: aligned });
});

for (const [name, value] of [
  ["normalized", "<now>"], ["null", null], ["number", 123], ["object", {}],
  ["year-zero", "0000-01-01T00:00:00Z"], ["bad-leap-day", "2026-02-29T00:00:00Z"],
  ["day-overflow", "2026-04-31T00:00:00Z"], ["bad-month", "2026-13-01T00:00:00Z"],
  ["hour-overflow", "2026-01-01T24:00:00Z"], ["leap-second", "2026-01-01T00:00:60Z"],
  ["minute-overflow", "2026-01-01T00:60:00Z"], ["fraction-long", "2026-01-01T00:00:00.1234567890Z"],
  ["empty-fraction", "2026-01-01T00:00:00.Z"], ["no-zone", "2026-01-01T00:00:00"],
  ["bad-offset", "2026-01-01T00:00:00+24:00"], ["bad-offset-minute", "2026-01-01T00:00:00+00:60"],
  ["unknown-offset", "2026-01-01T00:00:00-00:00"],
  ["range-underflow", "0001-01-01T00:00:00+01:00"], ["range-overflow", "9999-12-31T23:59:59-01:00"],
  ["whitespace", " 2026-01-01T00:00:00Z"],
]) test(`timestamp parser refuses ${name}`, () => assert.throws(() => parseTimestamp(value), /timestamp-/));

test("an actual leap day parses; different text can represent the same nanosecond", () => {
  assert.equal(parseTimestamp("2024-02-29T00:00:00Z").millisecondAligned, true);
  assert.deepEqual(parseTimestamp("1970-01-01T00:00:00.123Z"), parseTimestamp("1970-01-01T09:00:00.123000000+09:00"));
});

test("only the two generated values and five readbacks are checked", () => {
  const report = inspectTimestampSession(syntheticSession());
  assert.equal(report.verdict, "CONFORMS");
  assert.deepEqual(report.counts, { conforms: 7, violates: 0, indeterminate: 0 });
  assert.equal(report.rawResponsesParsed, 7);
  assert.equal(report.productionComparison, "NOT_PERFORMED");
  assert.equal(report.compatibilityVerified, false); assert.equal(report.parentPromotion, false);
  assert.equal(report.productionExecuted, false);
});

test("microsecond server timestamps violate the documented precision even with consistent reads", () => {
  const report = inspectTimestampSession(syntheticSession("2026-01-02T03:04:05.123456Z"));
  assert.equal(report.verdict, "VIOLATES");
  assert.deepEqual(report.counts, { conforms: 5, violates: 2, indeterminate: 0 });
  assert.equal(report.precision.every(r => r.verdict === "VIOLATES"), true);
});

test("no floor/Date rounding hides one nanosecond of readback drift", () => {
  const session = syntheticSession();
  editRaw(session, "read-after-increments", body => { body.fields.at.timestampValue = "2026-01-02T03:04:05.123000001Z"; });
  const report = inspectTimestampSession(session);
  assert.equal(report.verdict, "VIOLATES"); assert.equal(report.counts.violates, 1);
});

test("equivalent UTC/offset spellings are equal, not a time mismatch", () => {
  const session = syntheticSession();
  editRaw(session, "read-after-increments", body => { body.fields.at.timestampValue = "2026-01-02T12:04:05.123000000+09:00"; });
  assert.equal(inspectTimestampSession(session).verdict, "CONFORMS");
});

test("metadata and ordinary timestamp fields keep micro/nanosecond values unmodified", () => {
  const session = syntheticSession();
  for (const id of ENTRY.rawTimestampResponseSteps) editRaw(session, id, body => {
    for (const key of ["commitTime", "createTime", "updateTime"]) body[key] = "2026-01-02T03:04:05.123456789Z";
    if (body.fields) body.fields.ordinary = { timestampValue: "2026-01-02T03:04:05.123456Z" };
  });
  assert.equal(inspectTimestampSession(session).verdict, "CONFORMS");
  assert.ok(session.requests.find(r => r.phase === "read-after-increments").rawResponseText.includes("123456789Z"));
});

test("timestamps in different commits need not differ or strictly increase", () => {
  const session = syntheticSession();
  editRaw(session, "transform-only-write-creates", body => { body.writeResults[0].transformResults[1].timestampValue = "2026-01-02T03:04:04.999Z"; });
  editRaw(session, "read-transform-created", body => { body.fields.at.timestampValue = "2026-01-02T03:04:04.999Z"; });
  assert.equal(inspectTimestampSession(session).verdict, "CONFORMS");
});

for (const [name, change] of [
  ["old-record-without-raw", s => { for (const row of s.requests) delete row.rawResponseText; }],
  ["tampered-response", s => { s.requests[2].rawResponseText += " "; }],
  ["normalized-placeholder", s => { editRaw(s, "server-timestamp-and-increments", b => { b.writeResults[0].transformResults[0].timestampValue = "<now>"; }); }],
  ["wrong-document", s => { editRaw(s, "read-after-increments", b => { b.name += "-other"; }); }],
  ["wrong-method", s => { s.requests[2].method = "GET"; }],
  ["wrong-route", s => { s.requests[2].path += "?other=true"; }],
  ["non-success", s => { s.requests[2].status = 503; }],
  ["invalid-json", s => { s.requests[2].rawResponseText = "{"; s.requests[2].responseSha256 = sha256("{"); }],
  ["array-body", s => { s.requests[2].rawResponseText = "[]"; s.requests[2].responseSha256 = sha256("[]"); }],
  ["raw-error-on-200", s => { editRaw(s, "server-timestamp-and-increments", b => { b.error = {}; }); }],
  ["missing-at", s => { editRaw(s, "read-after-increments", b => { delete b.fields.at; }); }],
  ["wrong-time-type", s => { editRaw(s, "read-after-increments", b => { b.fields.at.timestampValue = 123; }); }],
  ["case-binding", s => { s.caseId = CASE.id; }],
  ["program-binding", s => { s.programDigest = "0".repeat(64); }],
  ["production-label", s => { s.productionRequests = 1; }],
  ["incomplete-execution", s => { s.completed = false; }],
  ["failed-execution", s => { s.failure = "request-timeout"; }],
  ["cleanup-unknown", s => { s.cleanup.state = "unconfirmed"; }],
  ["cleanup-document", s => { s.cleanup.absent[0] = "tf/foreign"; }],
  ["cleanup-count", s => { s.cleanup.requests = 6; }],
  ["request-count", s => { s.requestCount = 19; }],
  ["missing-request", s => { s.requests.pop(); }],
  ["duplicate-request", s => { s.requests[3] = structuredClone(s.requests[2]); }],
  ["request-order", s => { [s.requests[2], s.requests[3]] = [s.requests[3], s.requests[2]]; }],
]) test(`unusable ${name} is INDETERMINATE, not conforming or a semantic violation`, () => {
  const session = syntheticSession(); change(session);
  const report = inspectTimestampSession(session);
  assert.equal(report.verdict, "INDETERMINATE"); assert.ok(report.evidenceIssues.length > 0);
});

test("reporting does not mutate inputs, and mixed violations retain diagnostics without acceptance", () => {
  const session = syntheticSession("2026-01-02T03:04:05.123456Z");
  delete session.requests[3].rawResponseText;
  const before = structuredClone(session);
  const result = inspectTimestampSession(session);
  assert.deepEqual(session, before); assert.equal(result.verdict, "INDETERMINATE");
  assert.equal(result.counts.violates, 2); assert.ok(result.counts.indeterminate > 0);
});

test("primary mismatches/incompleteness cannot be promoted by conforming timestamp checks", () => {
  for (const [primary, verdict, expected] of [[0,"CONFORMS",0],[1,"CONFORMS",1],[2,"CONFORMS",2],
    [0,"VIOLATES",1],[1,"VIOLATES",1],[2,"VIOLATES",2],[0,"INDETERMINATE",2],[1,"INDETERMINATE",2]])
    assert.equal(diagnosticExitCode(primary,{verdict}),expected);
  assert.throws(() => diagnosticExitCode(-1,{verdict:"CONFORMS"}), /timestamp-primary-exit/);
  for (const report of [null, {}, {verdict:"MATCH"}, {verdict:true}])
    assert.throws(() => diagnosticExitCode(0,report), /timestamp-diagnostic-verdict/);
});

test("CLI has no production endpoint option and requires a fresh distinct output location", () => {
  assert.ok(parseArgs(["--run-dir","/tmp/a","--out","/tmp/b"]).repo);
  for (const args of [[],["--run-dir","a"],["--run-dir","a","--out","a"],
    ["--run-dir","a","--out","b","--out","c"],["--run-dir","a","--out","b","--endpoint","https://example.invalid"]])
    assert.throws(() => parseArgs(args), /timestamp-arguments/);
});

test("CLI refuses missing recording before attempting a primary comparison", async () => {
  const dir = await fs.mkdtemp(join(tmpdir(),"fireemu-time-missing-"));
  try {
    await assert.rejects(main(["--run-dir",join(dir,"missing"),"--out",join(dir,"out")]));
    await assert.rejects(fs.stat(join(dir,"out")));
  } finally { await fs.rm(dir,{recursive:true,force:true}); }
});

// Real child/HTTP; peer values are explicit fixture data, not native behavior.
async function runWireFixture({ mutate = null, cleanupFail = false, caseId = CASE_ID, drift = false, timestamp = "2026-01-02T03:04:05.123456Z" } = {}) {
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
  const send = (res,status,body) => { res.writeHead(status,{"content-type":"application/json"});res.end(JSON.stringify(body).replaceAll("<now>", timestamp)); };
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


for (const [label, timestamp, verdict, violated] of [
  ["milliseconds", "2026-01-02T03:04:05.123Z", "CONFORMS", 0],
  ["microseconds", "2026-01-02T03:04:05.123456Z", "VIOLATES", 2],
  ["padded-milliseconds", "2026-01-02T03:04:05.123000000Z", "CONFORMS", 0],
]) test(`actual HTTP recorder preserves ${label} while normalized comparison stays 18 MATCH`, {timeout:20000}, async () => {
  const run = await runWireFixture({timestamp});
  assert.equal(run.code,0,run.stderr); assert.deepEqual(run.errors,[]);
  assert.equal(run.requests.length,27); assert.equal(run.session.requestCount,20);
  assert.equal(run.session.cleanup.requests,7); assert.equal(run.session.productionRequests,0);
  assert.equal(run.session.requests.filter(r => Object.hasOwn(r,"rawResponseText")).length,7);
  assert.equal(compare(run.actual).verdict,"MATCH");
  const report=inspectTimestampSession(run.session);
  assert.equal(report.verdict,verdict); assert.equal(report.counts.violates,violated);
  assert.equal(report.rawResponsesParsed,7); assert.equal(report.productionComparison,"NOT_PERFORMED");
});

test("actual recorder's normalizer erases readback drift; raw diagnostic detects it", {timeout:20000}, async () => {
  const run=await runWireFixture({timestamp:"2026-01-02T03:04:05.123Z",mutate:rows=>{
    rows[1].body.fields.at.timestampValue="2026-01-02T03:04:05.124Z";
  }});
  assert.equal(run.code,0,run.stderr); assert.deepEqual(run.errors,[]);
  assert.equal(compare(run.actual).verdict,"MATCH");
  const report=inspectTimestampSession(run.session);
  assert.equal(report.verdict,"VIOLATES"); assert.equal(report.counts.violates,1);
  assert.equal(report.readbacks.find(r=>r.stepId==="read-after-increments").verdict,"VIOLATES");
});

test("actual recorder's uncertain cleanup is not bypassed by precise timestamps", {timeout:20000}, async () => {
  const run=await runWireFixture({timestamp:"2026-01-02T03:04:05.123Z",cleanupFail:true});
  assert.equal(run.code,2); assert.equal(run.session.cleanup.state,"unconfirmed");
  assert.equal(inspectTimestampSession(run.session).verdict,"INDETERMINATE");
});
