import assert from "node:assert/strict";
import { test } from "node:test";
import {
  mkdtempSync,
  writeFileSync,
  readFileSync,
  rmSync,
  mkdirSync,
  chmodSync,
  realpathSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import {
  validateProjectedRows,
  replayWithWire,
  sessionConfiguration,
  runExecSession,
  comparisonFromEvidence,
  loadInputs,
  exportComparison,
  deriveLocalBudget,
  selectSessionProject,
  sessionEndpoint,
  buildExecArgs as buildSessionExecArgs,
} from "./run.mjs";
const hash = (x) => createHash("sha256").update(x).digest("hex");
const journal = "a".repeat(64),
  source = { journalSha256: journal, n: 1, originalResponseBytesPresent: true, absentFields: [] };
function row(n = 1, raw = true) {
  const text = '{"channels":[]}\n';
  return {
    n,
    case: "channel-lifecycle",
    op: "listChannels",
    at: "2026-10-09T00:00:00.000Z",
    ms: 0,
    request: { method: "GET", path: "/v1/projects/unit-project/locations/us-central1/channels" },
    response: {
      status: 200,
      body: { channels: [] },
      ...(raw
        ? {
            bodyBase64: Buffer.from(text).toString("base64"),
            bodyBytes: Buffer.byteLength(text),
            bodySha256: hash(text),
            originalBodySha256: journal,
            headers: {
              "content-type": "application/json",
              "content-length": String(Buffer.byteLength(text)),
            },
          }
        : {}),
    },
    projectionSource: {
      ...source,
      n,
      originalResponseBytesPresent: raw,
      absentFields: raw
        ? []
        : [
            "response.bodyBase64",
            "response.bodyBytes",
            "response.bodySha256",
            "response.originalBodySha256",
            "response.headers",
          ],
    },
  };
}
test("native rows bind ordinal, sanitized native bytes and explicit absence", () => {
  assert.equal(validateProjectedRows([row()], { journalSha256: journal }).length, 1);
  assert.equal(
    validateProjectedRows([row(1, false)], { journalSha256: journal })[0].projectionSource
      .originalResponseBytesPresent,
    false,
  );
});
for (const [name, change] of [
  ["hash", (r) => (r.response.bodySha256 = "0".repeat(64))],
  ["length", (r) => r.response.bodyBytes++],
  ["ordinal", (r) => r.projectionSource.n++],
  ["journal", (r) => (r.projectionSource.journalSha256 = "b".repeat(64))],
  ["fabricated bytes", (r) => (r.projectionSource.originalResponseBytesPresent = false)],
  ["missing cadence", (r) => delete r.ms],
  ["nonfinite cadence", (r) => (r.ms = Infinity)],
  ["decoded body", (r) => (r.response.body = { channels: [{}] })],
])
  test(`native validation rejects ${name}`, () => {
    const r = row();
    change(r);
    assert.throws(() => validateProjectedRows([r], { journalSha256: journal }));
  });
test("raw replay preserves verdicts and cloned reply bytes without appending facets", async () => {
  const r = row();
  const text = '{"channels":[]}\n';
  const reply = new Response(text, {
    headers: { "content-type": "application/json", "content-length": String(text.length) },
  });
  const report = await replayWithWire([r], {
    base: "http://127.0.0.1:9999",
    fetchImpl: async () => reply,
  });
  assert.equal(report.results[0].verdict, "match");
  assert.equal(report.wire[0].responseBase64, Buffer.from(text).toString("base64"));
  assert.equal(report.wire[0].n, 1);
  assert.equal(report.wire[0].originalNativeBodySha256, journal);
  assert.equal(report.facetProofs, undefined);
});
test("cadence precedes creation of each request timeout", async () => {
  const r1 = row(),
    r2 = row(2);
  r2.at = "2026-10-09T00:00:00.030Z";
  let calls = 0;
  const report = await replayWithWire([r1, r2], {
    base: "http://127.0.0.1:9999",
    fetchImpl: async (_, init) => {
      assert.equal(init.signal.aborted, false);
      calls++;
      return new Response('{"channels":[]}\n');
    },
  });
  assert.equal(calls, 2);
  assert.ok(report.wire[1].startedMonotonicMs - report.wire[0].startedMonotonicMs >= 25);
});
test("remote endpoint and redirects fail closed", async () => {
  await assert.rejects(replayWithWire([row()], { base: "https://example.com" }));
  const reply = new Response("{}");
  Object.defineProperty(reply, "redirected", { value: true });
  const r = await replayWithWire([row()], {
    base: "http://127.0.0.1:9999",
    fetchImpl: async () => reply,
  });
  assert.equal(r.results[0].verdict, "diverge");
  assert.equal(r.wire[0].failure !== undefined, true);
});
test("seven distinct ports, mock credential facts and packaged runner configure an actual exec", () => {
  const config = sessionConfiguration({
    project: "unit-project",
    ports: [10001, 10002, 10003, 10004, 10005, 10006, 10007],
    runner: "/unit/runner-node/index.mjs",
    guard: "/unit/offline.cjs",
    fixture: "/unit/neutral",
  });
  assert.equal(config.tasksPort, 10007);
  assert.equal(config.fireemu.daemon.uiPort, 0);
  assert.equal(config.firebase.functions[0].source, "/unit/neutral");
  assert.deepEqual(config.fireemu.functions.runner.slice(-1), ["/unit/runner-node/index.mjs"]);
  assert.ok(config.fireemu.eventarc.oauthCredentials[hash("ya29.replay-token")]);
  assert.equal(config.fireemu.daemon.authProjectNumbers["unit-project"], "123456789012");
  assert.throws(() =>
    sessionConfiguration({
      project: "p",
      ports: Array(7).fill(1),
      runner: "r",
      guard: "g",
      fixture: "f",
    }),
  );
});
test("export stays pending even when a raw row and an allowed facet succeed", () => {
  const evidence = {
    complete: true,
    artifactSha256: "c".repeat(64),
    sessions: [
      {
        phase: "raw",
        label: "B",
        report: {
          complete: true,
          total: { match: 1 },
          results: [{ n: 1, verdict: "match" }],
          wire: [],
        },
      },
      {
        phase: "facets",
        label: "B",
        report: { complete: true, proofs: [{ key: "B27", complete: true }], exchanges: [] },
      },
    ],
    inputPins: {},
    sourcePins: {},
    runnerPins: {},
    fixturePins: {},
  };
  const c = comparisonFromEvidence(evidence);
  assert.equal(c.kind, "eventarc-production-comparison-v1");
  assert.ok(c.rows.every((x) => x.status === "PENDING"));
  assert.equal(c.raw[0].results[0].verdict, "match");
  assert.equal(c.facets[0].proofs[0].complete, true);
  assert.ok(c.pending.includes("C102/C110 native continuation tails"));
});
test("missing inputs rejected before any binary process", () => {
  const dir = mkdtempSync(join(tmpdir(), "ea-missing-"));
  try {
    assert.throws(() => loadInputs(dir));
  } finally {
    rmSync(dir, { recursive: true });
  }
});
test("incomplete evidence cannot be exported", () => {
  assert.throws(() => comparisonFromEvidence({ complete: false }));
});
test("harmless native Node child timeout closes pipes and its owned process group", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "ea-child-"));
  t.after(() => rmSync(dir, { recursive: true }));
  const binary = join(dir, "child");
  writeFileSync(
    binary,
    `#!${process.execPath}\nprocess.stdout.write('started');setInterval(()=>{},1000);\n`,
  );
  chmodSync(binary, 0o700);
  const r = await runExecSession({
    binary,
    args: [],
    cwd: dir,
    env: { PATH: process.env.PATH },
    timeoutMs: 150,
    graceMs: 200,
  });
  t.diagnostic(JSON.stringify({ kind: "harmless-owned-process-receipt", ...r }));
  assert.equal(r.timedOut, true);
  assert.equal(r.processGroupAbsent, true);
  assert.equal(r.identity.status, "VERIFIED");
});
test("harmless native child startup failure is retained and cleaned", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "ea-exit-"));
  t.after(() => rmSync(dir, { recursive: true }));
  const binary = join(dir, "child");
  writeFileSync(binary, `#!${process.execPath}\nsetTimeout(()=>process.exit(7),100);\n`);
  chmodSync(binary, 0o700);
  const r = await runExecSession({
    binary,
    args: [],
    cwd: dir,
    env: { PATH: process.env.PATH },
    timeoutMs: 1000,
    graceMs: 200,
  });
  t.diagnostic(JSON.stringify({ kind: "harmless-owned-process-receipt", ...r }));
  assert.equal(r.exitCode, 7);
  assert.equal(r.processGroupAbsent, true);
});
test("exec argv binds installed artifact configuration and seven owned ports", async () => {
  const { buildExecArgs } = await import("./run.mjs");
  const args = buildExecArgs({
    work: "/unit/work",
    project: "unit-project",
    tasksPort: 10007,
    guard: "/unit/guard.cjs",
    session: "/unit/session.json",
  });
  assert.ok(args.includes("--tasks-port"));
  assert.ok(args.includes("functions,eventarc"));
  assert.equal(args[args.indexOf("--tasks-port") + 1], "10007");
  assert.ok(args.includes("--session"));
  assert.ok(!args.some((x) => x.includes("clock:advance")));
});
test("unknown or changed evidence pins cannot export", () => {
  const dir = mkdtempSync(join(tmpdir(), "ea-export-"));
  try {
    const binary = join(dir, "binary"),
      input = join(dir, "input"),
      path = join(dir, "evidence.json");
    writeFileSync(binary, "actual");
    writeFileSync(input, "changed");
    writeFileSync(
      path,
      JSON.stringify({
        complete: true,
        artifactSha256: hash("actual"),
        sourcePins: { [input]: hash("old") },
        sessions: [],
      }),
    );
    assert.throws(() =>
      exportComparison({ binary, evidencePath: path, output: join(dir, "out.json") }),
    );
    assert.equal(readFileSync(binary, "utf8"), "actual");
  } finally {
    rmSync(dir, { recursive: true });
  }
});
test("public facet provenance contains portable bound names while raw capture bytes stay exact", () => {
  const path = "/private/input/B.jsonl",
    native = hash("native"),
    raw = Buffer.from("exact raw\n").toString("base64");
  const e = {
    complete: true,
    artifactSha256: journal,
    physicalInputPins: { [path]: native },
    inputPins: { "B.jsonl": native },
    sourcePins: {},
    runnerPins: {},
    fixturePins: {},
    sessions: [
      {
        phase: "raw",
        label: "B",
        report: {
          complete: true,
          results: [],
          wire: [{ responseBase64: raw, path: "/v1/projects/p/locations/l/channels" }],
        },
      },
      {
        phase: "facets",
        label: "B",
        report: {
          complete: true,
          proofs: [{ source: { path, sha256: native, n: 27 }, complete: true }],
          exchanges: [{ source: { path, sha256: native, n: 27 }, response: { base64: raw } }],
        },
      },
    ],
  };
  const c = comparisonFromEvidence(e);
  assert.equal(
    c.facets[0].proofs[0].source.path,
    "conformance/src/eventarc-production/fixtures/ad/B.jsonl",
  );
  assert.equal(c.raw[0].wire[0].responseBase64, raw);
  assert.equal(c.facets[0].exchanges[0].response.base64, raw);
  assert.ok(!JSON.stringify(c).includes("/private/input"));
  e.sessions[1].report.proofs[0].source.sha256 = "f".repeat(64);
  assert.throws(() => comparisonFromEvidence(e));
});
test("projected native byte validation rejects every generated byte corruption", () => {
  for (let seed = 0; seed < 32; seed++) {
    const r = row(),
      bytes = Buffer.from(r.response.bodyBase64, "base64");
    bytes[seed % bytes.length] ^= 1 + (seed % 127);
    r.response.bodyBase64 = bytes.toString("base64");
    assert.throws(() => validateProjectedRows([r], { journalSha256: journal }));
  }
});
test("nonmonotonic original client starts are refused without a request", async () => {
  const a = row(),
    b = row(2);
  b.ms = 1;
  assert.throws(() => validateProjectedRows([a, b], { journalSha256: journal }), /nonmonotonic/);
  let called = false;
  await assert.rejects(
    replayWithWire([a, b], {
      base: "http://127.0.0.1:9999",
      fetchImpl: async () => {
        called = true;
        return new Response("{}");
      },
    }),
  );
  assert.equal(called, false);
});
test("parsed-only absence must include originalBodySha256 and cannot fabricate that field", () => {
  const r = row(1, false);
  r.projectionSource.absentFields = r.projectionSource.absentFields.filter(
    (x) => x !== "response.originalBodySha256",
  );
  assert.throws(() => validateProjectedRows([r], { journalSha256: journal }));
  const s = row(1, false);
  s.response.originalBodySha256 = journal;
  assert.throws(() => validateProjectedRows([s], { journalSha256: journal }));
});
test("harmless parent exit cannot leave an owned pipe-holding descendant", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "ea-grandchild-"));
  t.after(() => rmSync(dir, { recursive: true }));
  const binary = join(dir, "child");
  writeFileSync(
    binary,
    `#!${process.execPath}\nconst {spawn}=require('node:child_process');spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:['ignore',1,2]});setTimeout(()=>process.exit(0),150);\n`,
  );
  chmodSync(binary, 0o700);
  const r = await runExecSession({
    binary,
    args: [],
    cwd: dir,
    env: { PATH: process.env.PATH },
    timeoutMs: 300,
    graceMs: 200,
  });
  t.diagnostic(JSON.stringify({ kind: "harmless-owned-process-receipt", ...r }));
  assert.equal(r.timedOut, true);
  assert.equal(r.processGroupAbsent, true);
  assert.ok(r.descendants.every((x) => x.status === "VERIFIED"));
});
test(
  "transport ignoring abort still produces a bounded raw failure",
  { timeout: 200 },
  async () => {
    const r = await replayWithWire([row()], {
      base: "http://127.0.0.1:9999",
      requestTimeoutMs: 10,
      fetchImpl: async () => new Promise(() => {}),
    });
    assert.equal(r.complete, false);
    assert.equal(r.results[0].verdict, "diverge");
    assert.match(r.wire[0].failure.message, /timeout/);
  },
);
test("native spawn failure remains UNKNOWN and cannot become successful proof", async () => {
  const r = await runExecSession({
    binary: "/missing-eventarc-test-binary",
    args: [],
    cwd: tmpdir(),
    env: { PATH: process.env.PATH },
    timeoutMs: 100,
    graceMs: 50,
  });
  assert.equal(r.identity.status, "UNKNOWN");
  assert.equal(r.failure.name, "Error");
  assert.notEqual(r.exitCode, 0);
});
function facetFixture(t) {
  const dir = mkdtempSync(join(tmpdir(), "ea-facet-"));
  t.after(() => rmSync(dir, { recursive: true }));
  const collection = "projects/unit-project/locations/us-central1/channels",
    time = "2026-10-09T00:00:00.000000000Z",
    channel = {
      name: `${collection}/a`,
      uid: "00000000-0000-4000-8000-000000000001",
      createTime: time,
      updateTime: time,
      pubsubTopic: "projects/unit-project/topics/eventarc-a-123",
      state: "ACTIVE",
    };
  const operation = (verb = "create", done = false) => ({
    name: `${collection.replace(/channels$/, "operations")}/operation-1234567890123-abcdef0123456-12345678-${verb === "create" ? "abcdef01" : "abcdef02"}`,
    metadata: {
      "@type": "type.googleapis.com/google.cloud.eventarc.v1.OperationMetadata",
      createTime: time,
      ...(done ? { endTime: time } : {}),
      target: channel.name,
      verb,
      requestedCancellation: false,
      apiVersion: "v1",
    },
    done,
    ...(done
      ? {
          response:
            verb === "create"
              ? { "@type": "type.googleapis.com/google.cloud.eventarc.v1.Channel", ...channel }
              : {
                  "@type": "type.googleapis.com/google.cloud.eventarc.v1.Channel",
                  name: channel.name,
                  state: "INACTIVE",
                  pubsubTopic: "",
                },
        }
      : {}),
  });
  const rows = [
    {
      n: 16,
      request: {
        method: "POST",
        path: `/v1/${collection}?channelId=a`,
        body: { name: channel.name },
      },
      response: { status: 200, body: operation() },
    },
    {
      n: 26,
      request: { method: "GET", path: `/v1/${collection}` },
      response: { status: 200, body: { channels: [channel] } },
    },
    {
      n: 27,
      request: { method: "GET", path: `/v1/${collection}?pageSize=1` },
      response: { status: 200, body: { channels: [channel] } },
    },
    {
      n: 202,
      request: { method: "DELETE", path: `/v1/${channel.name}` },
      response: { status: 200, body: operation("delete") },
    },
  ];
  const text = rows.map((x) => JSON.stringify(x)).join("\n") + "\n",
    path = join(dir, "B.jsonl");
  writeFileSync(path, text);
  const absent = { error: { code: 404, status: "NOT_FOUND", message: "absent" } };
  const script = [
    operation(),
    operation("create", true),
    channel,
    { channels: [channel] },
    { channels: [channel] },
    { channels: [channel] },
    operation("delete"),
    operation("delete", true),
    [absent, 404],
    [absent, 404],
    [absent, 404],
  ];
  const inputs = {
    corpora: { B: { path, sha256: hash(text) } },
    plan: {
      corpora: {
        B: {
          setupN: [16],
          walks: [{ rootN: 27, inventoryN: 26, setupThroughN: 16 }],
          terminalN: [202],
        },
      },
    },
  };
  const calls = [];
  return {
    inputs,
    script,
    calls,
    channel,
    fetchImpl: async (url, init) => {
      calls.push({ path: new URL(url).pathname + new URL(url).search, method: init.method });
      assert.ok(script.length, "unexpected request");
      const x = script.shift();
      if (x instanceof Error) throw x;
      const [body, status] = Array.isArray(x) ? x : [x, 200];
      const responseText = JSON.stringify(body) + "\n";
      return new Response(responseText, {
        status,
        headers: {
          "content-type": "application/json; charset=UTF-8",
          "content-length": String(Buffer.byteLength(responseText)),
        },
      });
    },
  };
}
test("facet producer binds setup, own walk and own delete before separately captured cleanup", async (t) => {
  const { collectFacets } = await import("./run.mjs"),
    f = facetFixture(t);
  const r = await collectFacets(f.inputs, "B", "http://127.0.0.1:9999", { fetchImpl: f.fetchImpl });
  assert.equal(r.complete, true);
  assert.deepEqual(
    r.proofs.map((x) => x.key),
    ["B27", "B202"],
  );
  assert.equal(r.exchanges.length, 9);
  assert.equal(r.cleanupExchanges.length, 2);
  assert.equal(f.script.length, 0);
  assert.equal(r.cleanup[0].complete, true);
  assert.equal(r.proofs[0].caseId, "list-channels");
  assert.equal(r.proofs[0].transport, "rest");
});
test("facet failure is retained and cannot hide owned-target cleanup", async (t) => {
  const { collectFacets } = await import("./run.mjs"),
    f = facetFixture(t);
  f.script.splice(
    4,
    7,
    new Error("walk transport failure"),
    [{ error: { code: 404, status: "NOT_FOUND", message: "absent" } }, 404],
    [{ error: { code: 404, status: "NOT_FOUND", message: "absent" } }, 404],
  );
  const r = await collectFacets(f.inputs, "B", "http://127.0.0.1:9999", { fetchImpl: f.fetchImpl });
  assert.equal(r.complete, false);
  assert.equal(r.failure.message, "walk transport failure");
  assert.equal(r.cleanup[0].complete, true);
  assert.equal(r.exchanges.at(-1).failure !== undefined, true);
});
test("completed export refuses missing actual raw/facet sessions before writing", () => {
  const dir = mkdtempSync(join(tmpdir(), "ea-incomplete-set-"));
  try {
    const binary = join(dir, "binary"),
      pin = join(dir, "pin"),
      path = join(dir, "evidence.json"),
      output = join(dir, "out.json");
    writeFileSync(binary, "binary");
    writeFileSync(pin, "pin");
    const bound = { [pin]: hash("pin") };
    writeFileSync(
      path,
      JSON.stringify({
        kind: "eventarc-installed-check-v1",
        complete: true,
        artifactSha256: hash("binary"),
        sourcePins: bound,
        fixturePins: bound,
        runnerPins: bound,
        physicalInputPins: bound,
        sessionPins: bound,
        sessions: [],
      }),
    );
    assert.throws(
      () => exportComparison({ binary, evidencePath: path, output }),
      /actual session set/,
    );
    assert.throws(() => readFileSync(output));
  } finally {
    rmSync(dir, { recursive: true });
  }
});
test("offline guard refuses remote fetch, DNS and sockets before transport", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "ea-guard-"));
  t.after(() => rmSync(dir, { recursive: true }));
  const { offlineGuardSource } = await import("./run.mjs");
  const guard = join(dir, "guard.cjs"),
    binary = join(dir, "child");
  writeFileSync(guard, offlineGuardSource);
  writeFileSync(
    binary,
    `#!${process.execPath}\nconst assert=require('node:assert/strict');require(${JSON.stringify(guard)});assert.throws(()=>fetch('https://example.com'));assert.throws(()=>require('node:dns').lookup('example.com',()=>{}));const s=new(require('node:net').Socket);assert.throws(()=>s.connect(443,'example.com'));s.destroy();\n`,
  );
  chmodSync(binary, 0o700);
  const r = await runExecSession({
    binary,
    args: [],
    cwd: dir,
    env: { PATH: process.env.PATH },
    timeoutMs: 1000,
    graceMs: 200,
  });
  t.diagnostic(JSON.stringify({ kind: "harmless-offline-guard-process-receipt", ...r }));
  assert.equal(r.exitCode, 0);
  assert.equal(r.processGroupAbsent, true);
});
function exportFixture(t) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "ea-export-bound-")));
  t.after(() => rmSync(dir, { recursive: true }));
  const binary = join(dir, "binary"),
    runner = join(dir, "runner-node", "index.mjs"),
    input = join(dir, "input.json"),
    evidencePath = join(dir, "check.json"),
    output = join(dir, "comparison.json");
  mkdirSync(dirnameForTest(runner), { recursive: true });
  writeFileSync(binary, "unit binary digest fixture; never executed");
  writeFileSync(runner, "// Unit runner digest fixture; never executed.\n");
  writeFileSync(input, "unit input digest fixture");
  const pin = (p) => ({ [p]: hash(readFileSync(p)) }),
    sourcePath = new URL("./run.mjs", import.meta.url).pathname;
  const e = {
    schemaVersion: 1,
    kind: "eventarc-installed-check-v1",
    complete: true,
    artifactSha256: hash(readFileSync(binary)),
    sourcePins: pin(sourcePath),
    fixturePins: pin(input),
    physicalInputPins: pin(input),
    runnerPins: pin(runner),
    inputPins: {},
    sessions: [],
    sessionPins: {},
  };
  for (const [phase, labels] of [
    ["raw", ["A1", "A2", "B", "C", "D"]],
    ["facets", ["B", "C", "D"]],
  ])
    for (const label of labels) {
      const id = `${phase}-${label}-unit`,
        work = join(dir, id);
      mkdirSync(work);
      const report = {
          complete: true,
          ...(phase === "raw"
            ? { results: [], wire: [], total: {} }
            : { proofs: [], exchanges: [] }),
        },
        reportPath = join(work, "report.json"),
        receiptPath = join(work, "process-receipt.json");
      writeFileSync(reportPath, JSON.stringify(report));
      writeFileSync(
        receiptPath,
        JSON.stringify({
          identity: { status: "VERIFIED" },
          exitCode: 0,
          processGroupAbsent: true,
          timedOut: false,
        }),
      );
      Object.assign(e.sessionPins, pin(reportPath), pin(receiptPath));
      e.sessions.push({
        id,
        phase,
        label,
        report,
        processReceiptSha256: hash(readFileSync(receiptPath)),
      });
    }
  const persist = () => writeFileSync(evidencePath, JSON.stringify(e));
  persist();
  return { dir, binary, evidencePath, output, e, persist };
}
function dirnameForTest(path) {
  return join(path, "..");
}
test("empty serialization fixture cannot satisfy strict semantic export", (t) => {
  const f = exportFixture(t);
  assert.throws(() => exportComparison(f), /missing genuine native projection/);
});
test("changed embedded wire/report cannot substitute for the physical check report", (t) => {
  const f = exportFixture(t);
  f.e.sessions[0].report.wire = [{ responseBase64: Buffer.from("substituted").toString("base64") }];
  f.persist();
  assert.throws(() => exportComparison(f), /changed embedded actual report/);
});
test("foreign installed artifact cannot reuse complete evidence", (t) => {
  const f = exportFixture(t);
  writeFileSync(f.binary, "different artifact");
  assert.throws(() => exportComparison(f), /different installed artifact/);
});
test("foreign native authority is rejected before any projection body is read", () => {
  const dir = mkdtempSync(join(tmpdir(), "ea-foreign-input-"));
  try {
    writeFileSync(
      join(dir, "provenance.json"),
      JSON.stringify({
        kind: "eventarc-native-projection-v1",
        schemaVersion: 1,
        originalAuthority: { indexSha256: "f".repeat(64), mapSha256: "f".repeat(64) },
        numericAlias: "123456789012",
        corpora: [],
      }),
    );
    writeFileSync(
      join(dir, "witness-plan.json"),
      JSON.stringify({ kind: "eventarc-own-witness-plan-v1", corpora: {} }),
    );
    assert.throws(() => loadInputs(dir), /native corpus authority/);
  } finally {
    rmSync(dir, { recursive: true });
  }
});
test("missing selected witness roots cannot become a successful empty facet session", () => {
  const dir = mkdtempSync(join(tmpdir(), "ea-witness-plan-"));
  try {
    const records = {
        A1: "d011709742b6",
        A2: "9e560c404162",
        B: "43a83839852f",
        C: "fe404dee592e",
        D: "bd0b44db5477",
      },
      corpora = [];
    for (const label of Object.keys(records)) {
      const text = JSON.stringify(row()) + "\n";
      writeFileSync(join(dir, label + ".jsonl"), text);
      corpora.push({
        label,
        source: { recording: records[label], journalSha256: journal },
        projection: {
          file: label + ".jsonl",
          sha256: hash(text),
          rows: 1,
          nativeRows: 1,
          ordinals: [1],
        },
      });
    }
    writeFileSync(
      join(dir, "provenance.json"),
      JSON.stringify({
        kind: "eventarc-native-projection-v1",
        originalAuthority: {
          indexSha256: "c7c78acb381ddff43292160092ac6ab613ce73646dc96ccc7bc7f9559b07eaef",
          mapSha256: "795debdc480c709a6ddc86d78b7a7627117a86cdbbc207f046b4766c3d104eae",
        },
        numericAlias: "123456789012",
        corpora,
      }),
    );
    writeFileSync(
      join(dir, "witness-plan.json"),
      JSON.stringify({
        kind: "eventarc-own-witness-plan-v1",
        corpora: Object.fromEntries(
          ["B", "C", "D"].map((label) => [
            label,
            {
              projectionSha256: corpora.find((c) => c.label === label).projection.sha256,
              setupN: [],
              walks: [],
              terminalN: [],
            },
          ]),
        ),
      }),
    );
    assert.throws(() => loadInputs(dir), /selected witness plan/);
  } finally {
    rmSync(dir, { recursive: true });
  }
});
test("projection retains parent and recipe row keys without claiming semantic export", (t) => {
  const f = exportFixture(t),
    c = comparisonFromEvidence(f.e);
  assert.equal(c.parent, "EVENTARC");
  assert.ok(
    c.rows.every(
      (r) =>
        typeof r.row === "string" &&
        r.row.startsWith("eventarc/") &&
        r.row.endsWith("#" + r.caseId),
    ),
  );
  assert.equal(new Set(c.rows.map((r) => r.row + "/" + r.transport)).size, c.rows.length);
  assert.deepEqual(c.summary, { PENDING: c.rows.length });
  assert.match(c.fixtureSha256, /^[a-f0-9]{64}$/);
});

function budgetInputs() {
  const spans = [235957, 227158, 404024, 730708, 316279];
  return {
    corpora: Object.fromEntries(
      ["A1", "A2", "B", "C", "D"].map((label, i) => {
        const first = row(1),
          last = row(2);
        last.at = new Date(Date.parse(first.at) + spans[i]).toISOString();
        return [label, { rows: [first, last] }];
      }),
    ),
  };
}
test("local budget retains eight session ceilings and exact original cadence", () => {
  const budget = deriveLocalBudget(budgetInputs());
  assert.equal(budget.exactRawCadenceMs, 1914126);
  assert.equal(budget.overallMs, 7360000);
  assert.equal(budget.sessions.length, 8);
  assert.ok(budget.sessions.every((s) => s.timeoutMs === 900000));
  assert.equal(
    budget.sessions.find((s) => s.label === "C" && s.phase === "raw").remainingWorkAllowanceMs,
    139292,
  );
});
test("local budget rejects the old aggregate cap and even one missing millisecond", () => {
  assert.throws(() => deriveLocalBudget(budgetInputs(), 1800000), /local budget infeasible/);
  assert.throws(() => deriveLocalBudget(budgetInputs(), 7359999), /local budget infeasible/);
  assert.equal(deriveLocalBudget(budgetInputs(), 7360000).overallMs, 7360000);
});
test("local budget rejects a raw cadence that cannot fit its unchanged session ceiling", () => {
  const inputs = budgetInputs();
  inputs.corpora.C.rows[1].at = new Date(
    Date.parse(inputs.corpora.C.rows[0].at) + 870001,
  ).toISOString();
  assert.throws(() => deriveLocalBudget(inputs), /raw C budget infeasible/);
});
test("local budget rejects nonfinite caps and does not silently extend a requested cap", () => {
  for (const cap of [Infinity, NaN, -1, 7360000.5, 7360001])
    assert.throws(() => deriveLocalBudget(budgetInputs(), cap), /finite local budget cap/);
});

test("original native rows select the declared named daemon authority without changing requests", () => {
  const inputs = loadInputs();
  let count = 0;
  for (const [label, corpus] of Object.entries(inputs.corpora)) {
    const before = structuredClone(corpus.rows);
    assert.equal(corpus.rows[0].n, 1);
    assert.match(corpus.rows[0].request.path, /^\/v1\/projects\/123456789012\/services\//);
    const project = selectSessionProject(corpus.rows);
    assert.equal(project, "fireemu-oracle-idp", label);
    const config = sessionConfiguration({
      project,
      ports: [32001, 32002, 32003, 32004, 32005, 32006, 32007],
      runner: "runner",
      guard: "guard",
      fixture: "fixture",
    });
    assert.equal(config.fireemu.daemon.authProject, project);
    assert.equal(config.fireemu.daemon.authProjectNumbers[project], "123456789012");
    const args = buildSessionExecArgs({
      work: "work",
      project,
      tasksPort: config.tasksPort,
      guard: "guard",
      session: "session",
    });
    assert.equal(args[args.indexOf("--project") + 1], project);
    assert.deepEqual(corpus.rows, before);
    count += corpus.rows.length;
  }
  assert.equal(count, 1043);
});

test("named authority refuses missing and foreign-only paths while retaining adversarial order", () => {
  const named = "/v1/projects/fireemu-oracle-idp/locations/us-central1/channels";
  const foreign = "/v1/projects/fireemu-no-such-project-0/locations/us-central1/channels";
  const numeric = "/v1/projects/123456789012/services/eventarcpublishing.googleapis.com";
  const rows = (paths) => paths.map((path) => ({ request: { path } }));
  for (const paths of [
    [],
    [numeric],
    [foreign],
    ["/elsewhere"],
    ["/v1/projects/fireemu-oracle-idp-suffix/locations/us-central1/channels"],
  ])
    assert.throws(() => selectSessionProject(rows(paths)), /public named project authority/);
  for (let i = 0; i < 32; i++) {
    const paths = i % 2 ? [numeric, foreign, named] : [foreign, numeric, named];
    const input = rows(paths),
      before = structuredClone(input);
    assert.equal(selectSessionProject(input), "fireemu-oracle-idp");
    assert.deepEqual(input, before);
  }
});

test("actual full Eventarc URL enters the session unchanged with strict numeric loopback", () => {
  const actual = "http://127.0.0.1:54126";
  assert.equal(sessionEndpoint(actual), actual);
  const url = new URL(sessionEndpoint(actual));
  assert.equal(url.origin, actual);
  assert.equal(url.hostname, "127.0.0.1");
  assert.equal(url.pathname, "/");
  assert.equal(sessionEndpoint("http://[::1]:54126"), "http://[::1]:54126");
});

test("session endpoint rejects doubled scheme and every nonnative URL shape before wire", () => {
  for (const value of [
    undefined,
    "",
    "http://http://127.0.0.1:54126",
    "http://localhost:54126",
    "http://example.com:54126",
    "https://127.0.0.1:54126",
    "http://user:secret@127.0.0.1:54126",
    "http://127.0.0.1:54126/path",
    "http://127.0.0.1:54126/?query",
    "http://127.0.0.1:54126/#fragment",
    "127.0.0.1:54126",
  ])
    assert.throws(() => sessionEndpoint(value));
});

test("SDK promotion retains original envelope checks rather than accepting HTTP-only publication", async () => {
  const { checkWire } = await import("./probe-sdk.mjs");
  const rows = readFileSync(new URL("./fixtures/ad/B.jsonl", import.meta.url), "utf8")
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  const relative = rows.find((entry) => entry.n === 157);
  assert.equal(relative.op, "sdk.publishEvents");
  const body = structuredClone(relative.request.body);
  const generated = checkWire(body, relative.request.body);
  assert.equal(generated.length, 1);
  for (const modify of [
    (value) => {
      value.events = [];
    },
    (value) => {
      value.events[0].id = "not-a-generated-id";
    },
    (value) => {
      value.events[0].attributes.time.ceTimestamp = "yesterday";
    },
    (value) => {
      value.events[0].source = "different";
    },
  ]) {
    const changed = structuredClone(body);
    modify(changed);
    assert.throws(() => checkWire(changed, relative.request.body));
  }
});

test(
  "retained SDK lifecycle checks reject terminal identity, pending and live-after-delete drift",
  { skip: !process.env.EVENTARC_ORIGINAL_SDK_REPORT },
  async () => {
    const { validateRetainedProofs } = await import("./lifecycle-evidence.mjs");
    const original = JSON.parse(readFileSync(process.env.EVENTARC_ORIGINAL_SDK_REPORT, "utf8"));
    validateRetainedProofs(original);
    for (const modify of [
      (value) => {
        value.exchanges[value.proofs[0].terminalExchange].body.name += "x";
      },
      (value) => {
        value.exchanges[value.proofs[0].terminalExchange].body.done = false;
      },
      (value) => {
        value.exchanges[value.proofs[1].readbackExchange].response.status = 200;
      },
      (value) => {
        value.proofs = [];
      },
    ]) {
      const changed = structuredClone(original);
      modify(changed);
      // Rebind physical fields so each counter reaches the semantic assertions.
      for (const exchange of changed.exchanges) {
        const bytes = Buffer.from(JSON.stringify(exchange.body));
        exchange.response.base64 = bytes.toString("base64");
        exchange.response.bytes = bytes.length;
        exchange.response.sha256 = hash(bytes);
        exchange.response.headers["content-length"] = String(bytes.length);
        exchange.response.text = bytes.toString();
      }
      assert.throws(() => validateRetainedProofs(changed));
    }
  },
);

test(
  "bound SDK notes reject changed outcomes, forwards and HTTP-only reports",
  { skip: !process.env.EVENTARC_ORIGINAL_SDK_REPORT || !process.env.EVENTARC_ORIGINAL_SDK_NATIVE },
  async () => {
    const { loadSdkInput, validateSdkReport } = await import("./probe-sdk.mjs");
    const input = loadSdkInput({
      path: process.env.EVENTARC_ORIGINAL_SDK_NATIVE,
      sha256: hash(readFileSync(process.env.EVENTARC_ORIGINAL_SDK_NATIVE)),
      sdkDir: "unused",
    });
    const original = JSON.parse(readFileSync(process.env.EVENTARC_ORIGINAL_SDK_REPORT, "utf8"));
    validateSdkReport(original, input);
    for (const modify of [
      (value) => {
        value.calls[1].outcome.threw = true;
      },
      (value) => {
        value.sdkWire[1].request.body.events[0].source = "different";
      },
      (value) => {
        value.sdkWire[1].response.status = 404;
      },
      (value) => {
        value.calls = [];
      },
      (value) => {
        value.fixtureOnly = true;
      },
      (value) => {
        value.sdkResolved = {};
      },
    ]) {
      const changed = structuredClone(original);
      modify(changed);
      for (const wire of changed.sdkWire) {
        const bytes = Buffer.from(JSON.stringify(wire.response.body));
        wire.response.bodyBase64 = bytes.toString("base64");
        wire.response.bodyBytes = bytes.length;
        wire.response.bodySha256 = hash(bytes);
        wire.response.headers["content-length"] = String(bytes.length);
      }
      assert.throws(() => validateSdkReport(changed, input));
    }
  },
);

test("production single and three event wire drift cannot hide behind fixed pending rows", async () => {
  const { validatePublishParity } = await import("./run.mjs");
  const rows = readFileSync(new URL("./fixtures/ad/B.jsonl", import.meta.url), "utf8")
    .split("\n")
    .filter(Boolean)
    .map(JSON.parse);
  const native = rows.filter((entry) => [81, 82].includes(entry.n));
  const wire = native.map((entry) => {
    const bytes = Buffer.from(JSON.stringify(entry.response.body));
    return {
      n: entry.n,
      status: entry.response.status,
      responseBase64: bytes.toString("base64"),
      responseBytes: bytes.length,
      responseSha256: hash(bytes),
    };
  });
  validatePublishParity(native, wire);
  for (const modify of [
    (value) => {
      value[0].status = 404;
    },
    (value) => {
      const bytes = Buffer.from('{"incorrect":true}');
      value[1].responseBase64 = bytes.toString("base64");
      value[1].responseBytes = bytes.length;
      value[1].responseSha256 = hash(bytes);
    },
    (value) => {
      value.pop();
    },
    (value) => {
      value.push(structuredClone(value[0]));
    },
  ]) {
    const changed = structuredClone(wire);
    modify(changed);
    assert.throws(() => validatePublishParity(native, changed));
  }
});

const retainedBodyCache = new Map();
function retainedBytes(path) {
  const key = String(path);
  if (!retainedBodyCache.has(key)) retainedBodyCache.set(key, readFileSync(path));
  return retainedBodyCache.get(key);
}
function connectedSemanticFixture(t) {
  const f = exportFixture(t),
    directory = join(f.dir, "ad");
  mkdirSync(directory);
  for (const name of [
    "provenance.json",
    "witness-plan.json",
    "A1.jsonl",
    "A2.jsonl",
    "B.jsonl",
    "C.jsonl",
    "D.jsonl",
  ])
    writeFileSync(
      join(directory, name),
      retainedBytes(new URL(`./fixtures/ad/${name}`, import.meta.url)),
    );
  writeFileSync(
    join(directory, "sdk-outcomes.json"),
    retainedBytes(process.env.EVENTARC_SDK_OUTCOMES),
  );
  const inputs = loadInputs(directory);
  f.e.inputPins = inputs.pins;
  f.e.physicalInputPins = Object.fromEntries(
    Object.keys(inputs.pins).map((name) => [
      join(directory, name),
      hash(readFileSync(join(directory, name))),
    ]),
  );
  const sdk = JSON.parse(retainedBytes(process.env.EVENTARC_ORIGINAL_SDK_REPORT));
  // Genuine retained bodies; supervision below is a unit-test double, never a historical outer verdict.
  for (const entry of f.e.sessions) {
    if (entry.phase === "raw") {
      const native = inputs.corpora[entry.label].rows.filter((row) => row.response && row.request);
      entry.report.wire = native.map((row) => {
        const historical = entry.label === "C" && [182, 183, 307].includes(row.n);
        const bytes = Buffer.from(JSON.stringify(historical ? {} : row.response.body));
        return {
          n: row.n,
          method: row.request.method,
          path: row.request.path,
          status: historical ? 200 : row.response.status,
          responseBase64: bytes.toString("base64"),
          responseBytes: bytes.length,
          responseSha256: hash(bytes),
        };
      });
    }
    if (entry.phase === "facets") {
      const name = { B: "facets-B-FEq3is", C: "facets-C-TXzo23", D: "facets-D-DkMbM6" }[
        entry.label
      ];
      entry.report = JSON.parse(
        retainedBytes(join(process.env.EVENTARC_ORIGINAL_FACET_DIR, name, "report.json")),
      );
      if (entry.label === "B") entry.report.sdk = structuredClone(sdk);
      const visit = (value) => {
        if (!value || typeof value !== "object") return;
        for (const [key, item] of Object.entries(value)) {
          if (
            ["source", "inventorySource", "createSource", "deleteSource"].includes(key) &&
            item?.path
          ) {
            f.e.physicalInputPins[item.path] = item.sha256;
          } else visit(item);
        }
      };
      visit(entry.report);
    }
  }
  f.rebind = () => {
    for (const entry of f.e.sessions) {
      const path = Object.keys(f.e.sessionPins).find((path) =>
        path.endsWith(`/${entry.id}/report.json`),
      );
      writeFileSync(path, JSON.stringify(entry.report));
      f.e.sessionPins[path] = hash(readFileSync(path));
    }
    f.persist();
  };
  f.rebind();
  return f;
}
const connectedEnabled = !!(
  process.env.EVENTARC_ORIGINAL_FACET_DIR &&
  process.env.EVENTARC_ORIGINAL_SDK_REPORT &&
  process.env.EVENTARC_SDK_OUTCOMES
);
test(
  "genuine retained original semantics connect strict export to release consumer with pending rows",
  { skip: !connectedEnabled },
  async (t) => {
    const { compareLaneExport } = await import("../release-strict-regression.mjs");
    const f = connectedSemanticFixture(t),
      comparison = exportComparison(f);
    assert.deepEqual(compareLaneExport(comparison, comparison, comparison.artifactSha256), []);
    assert.ok(
      comparison.semanticInputs.rawComparands.B.some(
        (row) => row.n === 35 && row.op === "listChannels",
      ),
      "genuine numeric alias LIST retained",
    );
    assert.equal(comparison.rows.length, 70);
    assert.ok(comparison.rows.every((row) => row.status === "PENDING"));
  },
);

test(
  "connected semantic export rejects rehashed wire, SDK and lifecycle counterexamples",
  { skip: !connectedEnabled },
  async (t) => {
    const { compareLaneExport } = await import("../release-strict-regression.mjs");
    const f = connectedSemanticFixture(t),
      expected = exportComparison(f),
      original = structuredClone(f.e.sessions);
    const raw = (value) =>
      value.find((entry) => entry.phase === "raw" && entry.label === "B").report;
    const facet = (value) =>
      value.find((entry) => entry.phase === "facets" && entry.label === "B").report;
    const sdk = (value) => facet(value).sdk;
    const terminal = (report) =>
      report.proofs.find((proof) => proof.kind === "own-operation-terminal");
    const cases = [
      [
        "numeric alias wrong topic project",
        (value) => {
          const wire = raw(value).wire.find((wire) => wire.n === 35);
          const body = JSON.parse(Buffer.from(wire.responseBase64, "base64").toString());
          body.channels[0].pubsubTopic = body.channels[0].pubsubTopic.replace(
            /^projects\/[^/]+\//,
            "projects/foreign/",
          );
          const bytes = Buffer.from(JSON.stringify(body));
          Object.assign(wire, {
            responseBase64: bytes.toString("base64"),
            responseBytes: bytes.length,
            responseSha256: hash(bytes),
          });
        },
      ],
      ...[
        ["unexpected resource", { channels: [{ name: "foreign" }] }],
        ["unexpected field", { extra: true }],
        ["unexpected type", []],
        ["unexpected status", null],
      ].map(([name, body]) => [
        "empty LIST " + name,
        (value) => {
          const report = value.find(
            (entry) => entry.phase === "raw" && entry.label === "A1",
          ).report;
          const wire = report.wire.find((wire) => wire.n === 6);
          if (body === null) wire.status = 404;
          else {
            const bytes = Buffer.from(JSON.stringify(body));
            Object.assign(wire, {
              responseBase64: bytes.toString("base64"),
              responseBytes: bytes.length,
              responseSha256: hash(bytes),
            });
          }
        },
      ]),
      [
        "successful raw lifecycle type",
        (value) => {
          const candidate = expected.semanticInputs.rawComparands.B.find(
            (native) => native.op === "getChannel" && native.response.status === 200,
          );
          assert.ok(candidate, "successful native lifecycle comparand retained");
          const report = value.find((entry) => entry.phase === "raw" && entry.label === "B").report;
          const wire = report.wire.find((wire) => wire.n === candidate.n);
          const body = JSON.parse(Buffer.from(wire.responseBase64, "base64").toString());
          body.uid = 42;
          const bytes = Buffer.from(JSON.stringify(body));
          Object.assign(wire, {
            responseBase64: bytes.toString("base64"),
            responseBytes: bytes.length,
            responseSha256: hash(bytes),
          });
        },
      ],
      [
        "successful raw operation identity",
        (value) => {
          const candidate = expected.semanticInputs.rawComparands.B.find(
            (native) => native.op === "getOperation" && native.response.status === 200,
          );
          assert.ok(candidate, "successful native operation comparand retained");
          const report = value.find((entry) => entry.phase === "raw" && entry.label === "B").report;
          const wire = report.wire.find((wire) => wire.n === candidate.n);
          const body = JSON.parse(Buffer.from(wire.responseBase64, "base64").toString());
          body.metadata.target += "-foreign";
          const bytes = Buffer.from(JSON.stringify(body));
          Object.assign(wire, {
            responseBase64: bytes.toString("base64"),
            responseBytes: bytes.length,
            responseSha256: hash(bytes),
          });
        },
      ],
      [
        "lifecycle auth/error response remains nonexempt",
        (value) => {
          const candidate = Object.values(expected.semanticInputs.rawComparands)
            .flat()
            .find((native) => native.op === "getChannel" && native.response.status !== 200);
          assert.ok(candidate, "native auth/error comparand retained");
          const report = value.find(
            (entry) =>
              entry.phase === "raw" &&
              entry.report.wire.some(
                (wire) => wire.n === candidate.n && wire.status === candidate.response.status,
              ),
          ).report;
          report.wire.find((wire) => wire.n === candidate.n).status = 200;
        },
      ],
      [
        "single publish status",
        (value) => {
          raw(value).wire.find((wire) => wire.n === 81).status = 404;
        },
      ],
      [
        "three publish body",
        (value) => {
          const bytes = Buffer.from('{"unexpected":true}');
          Object.assign(
            raw(value).wire.find((wire) => wire.n === 82),
            {
              responseBase64: bytes.toString("base64"),
              responseBytes: bytes.length,
              responseSha256: hash(bytes),
            },
          );
        },
      ],
      [
        "SDK relative outcome",
        (value) => {
          sdk(value).calls[1].outcome.threw = true;
        },
      ],
      [
        "SDK relative forward",
        (value) => {
          sdk(value).sdkWire[1].request.body.events[0].source = "different";
        },
      ],
      [
        "HTTP-only evidence",
        (value) => {
          delete facet(value).sdk;
        },
      ],
      [
        "ownwalk missing member",
        (value) => {
          const report = facet(value),
            proof = report.proofs.find((proof) => proof.kind === "own-cursor-walk");
          report.exchanges[proof.pages.at(-1)].body.channels.pop();
        },
      ],
      [
        "ownwalk duplicate",
        (value) => {
          const report = facet(value),
            proof = report.proofs.find((proof) => proof.kind === "own-cursor-walk");
          report.exchanges[proof.pages.at(-1)].body.channels[0] = structuredClone(
            report.exchanges[proof.pages[0]].body.channels[0],
          );
        },
      ],
      [
        "ownwalk count",
        (value) => {
          facet(value).proofs.find((proof) => proof.kind === "own-cursor-walk").resourceCount++;
        },
      ],
      [
        "terminal identity",
        (value) => {
          const report = facet(value),
            proof = terminal(report);
          report.exchanges[proof.terminalExchange].body.name += "x";
        },
      ],
      [
        "nonterminal operation",
        (value) => {
          const report = facet(value),
            proof = terminal(report);
          report.exchanges[proof.terminalExchange].body.done = false;
        },
      ],
      [
        "deleted resource200",
        (value) => {
          const report = facet(value),
            proof = terminal(report);
          report.exchanges[proof.readbackExchange].response.status = 200;
        },
      ],
      [
        "missing selected lifecycle case",
        (value) => {
          facet(value).proofs.pop();
        },
      ],
      [
        "nonexempt gap",
        (value) => {
          const report = value.find((entry) => entry.phase === "raw" && entry.label === "C").report;
          report.wire.find((wire) => wire.n === 184).status = 200;
        },
      ],
    ];
    for (const [name, modify] of cases) {
      f.e.sessions = structuredClone(original);
      modify(f.e.sessions);
      for (const entry of f.e.sessions.filter((entry) => entry.phase === "facets")) {
        for (const report of [entry.report, entry.report.sdk].filter(Boolean))
          for (const exchange of report.exchanges) {
            const bytes = Buffer.from(JSON.stringify(exchange.body));
            Object.assign(exchange.response, {
              base64: bytes.toString("base64"),
              bytes: bytes.length,
              sha256: hash(bytes),
              text: bytes.toString(),
            });
            exchange.response.headers["content-length"] = String(bytes.length);
          }
      }
      f.rebind();
      assert.throws(() => exportComparison(f), undefined, name);
    }
    for (const [name, modify] of [
      [
        "missing historical disclosure",
        (value) => {
          value.limitations.historicalPublish404.cases.pop();
        },
      ],
      [
        "widened historical exemption",
        (value) => {
          value.limitations.historicalPublish404.cases.push("C184");
        },
      ],
      [
        "missing mock-auth qualification",
        (value) => {
          delete value.limitations.mockCredentialCatalog;
        },
      ],
      [
        "SDK outer IdentityRefused retained",
        (value) => {
          value.sdk.supervision = {
            complete: false,
            failure: { name: "IdentityRefused" },
            ownedAbsence: false,
            ownershipUnresolved: true,
          };
        },
      ],
    ]) {
      const changed = structuredClone(expected);
      modify(changed);
      assert.notDeepEqual(compareLaneExport(expected, changed, expected.artifactSha256), [], name);
    }
  },
);

test("generated publish mutations preserve hash integrity while violating production parity", async () => {
  const { validatePublishParity } = await import("./run.mjs");
  const rows = JSON.parse("[]");
  rows.push(
    ...retainedBytes(new URL("./fixtures/ad/B.jsonl", import.meta.url))
      .toString()
      .split("\n")
      .filter(Boolean)
      .map(JSON.parse)
      .filter((row) => [81, 82].includes(row.n)),
  );
  let state = 0x13579bdf;
  for (let trial = 0; trial < 32; trial++) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    const wire = rows.map((row) => {
      const bytes = Buffer.from(JSON.stringify(row.response.body));
      return {
        n: row.n,
        status: row.response.status,
        responseBase64: bytes.toString("base64"),
        responseBytes: bytes.length,
        responseSha256: hash(bytes),
      };
    });
    if (state & 1) wire.reverse();
    validatePublishParity(rows, wire);
    const selected = wire[state % 2];
    if (trial % 2) selected.status = 201 + (state % 399);
    else {
      const bytes = Buffer.from(JSON.stringify({ mutation: state }));
      Object.assign(selected, {
        responseBase64: bytes.toString("base64"),
        responseBytes: bytes.length,
        responseSha256: hash(bytes),
      });
    }
    assert.throws(() => validatePublishParity(rows, wire), undefined, `seeded trial ${trial}`);
  }
});

test("direct check loads its explicit native input directory before any binary invocation", async (t) => {
  const { spawnSync } = await import("node:child_process");
  const directory = mkdtempSync(join(tmpdir(), "ea-explicit-input-"));
  t.after(() => rmSync(directory, { recursive: true }));
  const selected = join(directory, "selected");
  mkdirSync(selected);
  const result = spawnSync(
    process.execPath,
    [
      new URL("./run.mjs", import.meta.url).pathname,
      "check",
      "--binary",
      join(directory, "nonexistent-binary"),
      "--out",
      join(directory, "out"),
      "--input-directory",
      selected,
    ],
    { encoding: "utf8", timeout: 5000 },
  );
  assert.equal(result.status, 1);
  assert.ok(result.stderr.includes(join(selected, "provenance.json")), result.stderr);
});

function rehashSemanticSessions(f) {
  for (const entry of f.e.sessions) {
    if (entry.phase === "raw") continue;
    for (const report of [entry.report, entry.report.sdk].filter(Boolean))
      for (const exchange of report.exchanges) {
        const bytes = Buffer.from(JSON.stringify(exchange.body));
        Object.assign(exchange.response, {
          base64: bytes.toString("base64"),
          bytes: bytes.length,
          sha256: hash(bytes),
          text: bytes.toString(),
        });
        exchange.response.headers["content-length"] = String(bytes.length);
      }
  }
  f.rebind();
}
function replaceRawBody(wire, body) {
  const bytes = Buffer.from(JSON.stringify(body));
  Object.assign(wire, {
    responseBase64: bytes.toString("base64"),
    responseBytes: bytes.length,
    responseSha256: hash(bytes),
  });
}
test(
  "reviewed lifecycle variants and every intermediate response connect export and consumer",
  { skip: !connectedEnabled },
  async (t) => {
    const { compareLaneExport } = await import("../release-strict-regression.mjs");
    const f = connectedSemanticFixture(t),
      expected = exportComparison(f),
      original = structuredClone(f.e.sessions);
    const raw = () => f.e.sessions.find((x) => x.phase === "raw" && x.label === "B").report;
    const facet = () => f.e.sessions.find((x) => x.phase === "facets" && x.label === "B").report;
    const native = expected.semanticInputs.rawComparands.B;
    const resources = native
      .flatMap((x) => x.response.body?.channels ?? [x.response.body?.response, x.response.body])
      .filter((x) => x?.state === "ACTIVE");
    const unfinished = native.find(
      (x) =>
        ["createChannel", "getOperation"].includes(x.op) &&
        x.response.status === 200 &&
        x.response.body.done === false &&
        resources.some((r) => r.name === x.response.body.metadata.target),
    );
    assert.ok(unfinished, "original unfinished operation with pinned terminal authority");
    const terminalBody = () => {
      const b = structuredClone(unfinished.response.body);
      b.metadata = { ...b.metadata };
      const { createTime, target, verb, requestedCancellation, apiVersion } = b.metadata;
      b.metadata = {
        "@type": b.metadata["@type"],
        createTime,
        endTime: createTime,
        target,
        verb,
        requestedCancellation,
        apiVersion,
      };
      b.done = true;
      b.response = {
        "@type": "type.googleapis.com/google.cloud.eventarc.v1.Channel",
        ...structuredClone(resources.find((r) => r.name === target)),
      };
      return b;
    };
    const page = native.find(
      (x) =>
        x.op === "listChannels" &&
        x.response.body?.nextPageToken &&
        x.response.body.channels.length &&
        Object.values(expected.semanticInputs.lifecycleInventories.B)
          .flat()
          .some((r) => !x.response.body.channels.some((c) => c.name === r.name)),
    );
    assert.ok(page, "original page with complete native inventory");
    const moved = Object.values(expected.semanticInputs.lifecycleInventories.B)
      .flat()
      .find((r) => !page.response.body.channels.some((c) => c.name === r.name));
    const tail = native.find(
      (x) =>
        x.op === "listChannels" &&
        new URLSearchParams(x.request.path.split("?")[1]).get("pageToken") &&
        Array.isArray(x.response.body?.channels) &&
        !Object.hasOwn(x.response.body, "nextPageToken") &&
        Object.values(expected.semanticInputs.lifecycleInventories.B)
          .flat()
          .some((r) => !x.response.body.channels.some((c) => c.name === r.name)),
    );
    assert.ok(tail, "genuine terminal continuation page");
    const tailMoved = Object.values(expected.semanticInputs.lifecycleInventories.B)
      .flat()
      .find((r) => !tail.response.body.channels.some((c) => c.name === r.name));
    const positive = [
      [
        "changed terminal continuation page",
        () => {
          const body = structuredClone(tail.response.body);
          body.channels = [structuredClone(tailMoved)];
          replaceRawBody(
            raw().wire.find((w) => w.n === tail.n),
            body,
          );
        },
      ],
      [
        "changed done timing",
        () =>
          replaceRawBody(
            raw().wire.find((w) => w.n === unfinished.n),
            terminalBody(),
          ),
      ],
      [
        "changed native page placement",
        () => {
          const body = structuredClone(page.response.body);
          body.channels = [structuredClone(moved)];
          replaceRawBody(
            raw().wire.find((w) => w.n === page.n),
            body,
          );
          const report = facet(),
            walk = report.proofs.find((p) => p.kind === "own-cursor-walk");
          const a = report.exchanges[walk.pages[0]],
            b = report.exchanges[walk.pages.at(-1)];
          [a.body.channels[0], b.body.channels[0]] = [b.body.channels[0], a.body.channels[0]];
        },
      ],
    ];
    for (const [name, modify] of positive) {
      f.e.sessions = structuredClone(original);
      modify();
      rehashSemanticSessions(f);
      const actual = exportComparison(f);
      assert.deepEqual(compareLaneExport(expected, actual, expected.artifactSha256), [], name);
    }
    const pairedReport = () =>
      f.e.sessions.find(
        (entry) =>
          entry.phase === "facets" &&
          entry.report.proofs.some((p) => p.kind === "paired-own-operation-terminals"),
      ).report;
    const paired = () =>
      pairedReport().proofs.find((p) => p.kind === "paired-own-operation-terminals");
    const intermediate = () => {
      const report = facet(),
        p = report.proofs.find(
          (p) =>
            p.kind === "own-operation-terminal" &&
            report.exchanges.some(
              (e) =>
                e.id > p.issuedExchange &&
                e.id < p.terminalExchange &&
                e.request.path === `/v1/${p.name}` &&
                !e.body.done,
            ),
        );
      assert.ok(p, "retained genuine nonterminal poll");
      return report.exchanges.find(
        (e) =>
          e.id > p.issuedExchange &&
          e.id < p.terminalExchange &&
          e.request.path === `/v1/${p.name}` &&
          !e.body.done,
      );
    };
    const negatives = [
      [
        "terminal wrong topic authority",
        () => {
          const b = terminalBody();
          b.response.pubsubTopic = b.response.pubsubTopic.replace(
            /^projects\/[^/]+\//,
            "projects/foreign/",
          );
          replaceRawBody(
            raw().wire.find((w) => w.n === unfinished.n),
            b,
          );
        },
      ],
      [
        "terminal extra nested field",
        () => {
          const b = terminalBody();
          b.response.unexpected = true;
          replaceRawBody(
            raw().wire.find((w) => w.n === unfinished.n),
            b,
          );
        },
      ],
      [
        "terminal missing nested field",
        () => {
          const b = terminalBody();
          delete b.response.uid;
          replaceRawBody(
            raw().wire.find((w) => w.n === unfinished.n),
            b,
          );
        },
      ],
      [
        "LIST extra nested field",
        () => {
          const b = structuredClone(page.response.body);
          b.channels[0].unexpected = true;
          replaceRawBody(
            raw().wire.find((w) => w.n === page.n),
            b,
          );
        },
      ],
      [
        "LIST missing nested field",
        () => {
          const b = structuredClone(page.response.body);
          delete b.channels[0].uid;
          replaceRawBody(
            raw().wire.find((w) => w.n === page.n),
            b,
          );
        },
      ],
      [
        "LIST foreign inventory member",
        () => {
          const b = structuredClone(page.response.body);
          b.channels[0].name += "-foreign";
          replaceRawBody(
            raw().wire.find((w) => w.n === page.n),
            b,
          );
        },
      ],
      [
        "retained detached intermediate exchange",
        () => {
          const row = intermediate();
          row.request.path = "/v1/foreign";
          row.derivedFrom = null;
          row.body = { unexpected: true };
        },
      ],
      [
        "retained intermediate malformed body",
        () => {
          intermediate().body = { unexpected: true };
        },
      ],
      [
        "retained intermediate status",
        () => {
          intermediate().response.status = 404;
        },
      ],
      [
        "retained intermediate own path",
        () => {
          intermediate().request.path += "/foreign";
        },
      ],
      [
        "retained intermediate metadata continuity",
        () => {
          intermediate().body.metadata.createTime = "2000-01-01T00:00:00.000000000Z";
        },
      ],
      [
        "retained intermediate chronology",
        () => {
          intermediate().sentMonotonicMs = 0;
          intermediate().receivedMonotonicMs = 0;
        },
      ],
      [
        "retained terminal extra nested field",
        () => {
          const p = paired();
          assert.ok(p);
          pairedReport().exchanges[p.createTerminalExchange].body.response.unexpected = true;
        },
      ],
      [
        "paired unfinished channel status",
        () => {
          const p = paired();
          assert.ok(p);
          pairedReport().exchanges[p.start.channelExchange].response.status = 404;
        },
      ],
      [
        "paired unfinished channel shape",
        () => {
          const p = paired();
          assert.ok(p);
          pairedReport().exchanges[p.start.channelExchange].body.unexpected = true;
        },
      ],
      [
        "paired unfinished channel path",
        () => {
          const p = paired();
          assert.ok(p);
          pairedReport().exchanges[p.start.channelExchange].request.path += "/foreign";
        },
      ],
      [
        "paired unfinished operation status",
        () => {
          const p = paired();
          assert.ok(p);
          pairedReport().exchanges[p.start.operationExchange].response.status = 404;
        },
      ],
      [
        "paired unfinished operation createTime",
        () => {
          const p = paired();
          assert.ok(p);
          pairedReport().exchanges[p.start.operationExchange].body.metadata.createTime =
            "2000-01-01T00:00:00.000000000Z";
        },
      ],
    ];
    for (const [name, modify] of negatives) {
      f.e.sessions = structuredClone(original);
      modify();
      rehashSemanticSessions(f);
      assert.throws(() => exportComparison(f), undefined, name);
      const actual = comparisonFromEvidence(f.e, expected.semanticInputs);
      assert.notDeepEqual(compareLaneExport(expected, actual, expected.artifactSha256), [], name);
    }
  },
);
