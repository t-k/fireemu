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
test("export reads the same pinned check without spawning and stays pending", (t) => {
  const f = exportFixture(t),
    c = exportComparison(f);
  assert.equal(c.raw.length, 5);
  assert.equal(c.facets.length, 3);
  assert.ok(c.rows.every((r) => r.status === "PENDING"));
  assert.equal(c.checkEvidenceSha256, hash(readFileSync(f.evidencePath)));
  assert.ok(!JSON.stringify(c).includes(f.dir));
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
test("case exports use the existing parent and recipe row keys with pending summaries", (t) => {
  const f = exportFixture(t),
    c = exportComparison(f);
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

test("supplement loader binds the fixed52 projection and preserves recorded SDK classification", async () => {
  const m = await import("./run.mjs");
  assert.equal(typeof m.loadNativeSupplement, "function");
  const input = m.loadNativeSupplement();
  assert.equal(input.rows.length, 52);
  assert.equal(input.rows[24].case, "native-c307");
  assert.equal(input.rows[24].step, "s01-1");
  assert.equal(input.rows[24].projectionSource.derivedClassification.case, "admin-sdk-publish");
  assert.deepEqual(input.selectors.publishN, [23, 24, 25, 26, 27, 28]);
  assert.equal(
    input.journalSha256,
    "54765255731c0e0622a102abac4cd8e84e484ea9002a492de7113205b8cfb153",
  );
});
test("supplement producer is distinct from original check and enforces its finite budget", async () => {
  const m = await import("./run.mjs");
  assert.equal(typeof m.deriveSupplementBudget, "function");
  const b = m.deriveSupplementBudget(m.loadNativeSupplement());
  assert.equal(b.sessionMs, 900000);
  assert.equal(b.teardownMs, 12500);
  assert.equal(b.overallMs, 972500);
  assert.throws(
    () => m.deriveSupplementBudget(m.loadNativeSupplement(), 912500),
    /supplement budget infeasible/,
  );
  assert.throws(() => m.deriveSupplementBudget(m.loadNativeSupplement(), Infinity));
});

function nativeSupplementWorld(publishText = "{}\n") {
  const rows = readFileSync(
    new URL("./fixtures/native-supplement/recorded.jsonl", import.meta.url),
    "utf8",
  )
    .trim()
    .split("\n")
    .map(JSON.parse);
  const native = new Map(rows.map((r) => [r.n, r]));
  const channels = structuredClone(native.get(35).response.body.channels).toReversed();
  const deleted = new Set(),
    calls = [];
  let publish = 0;
  const fetchImpl = async (url, init) => {
    const u = new URL(url),
      path = u.pathname + u.search;
    calls.push({ path, method: init.method });
    let body,
      status = 200;
    if (init.method === "POST" && u.pathname.endsWith(":publishEvents")) {
      const n = 23 + publish++,
        expected = native.get(n);
      assert.equal(path, expected.request.path);
      assert.deepEqual(JSON.parse(init.body), expected.request.body, "actual native publish body");
      body = {};
    } else if (init.method === "POST") {
      const expected = [8, 13, 18].map((n) => native.get(n)).find((r) => r.request.path === path);
      assert.ok(expected, "unplanned create");
      assert.deepEqual(JSON.parse(Buffer.from(init.body).toString()), expected.request.body);
      body = expected.response.body;
    } else if (init.method === "DELETE") {
      const expected = [43, 46, 49]
        .map((n) => native.get(n))
        .find((r) => `/v1/${r.response.body.metadata.target}` === path);
      assert.ok(expected, "unowned cleanup");
      deleted.add(expected.response.body.metadata.target);
      body = expected.response.body;
    } else if (u.pathname.includes("/operations/")) {
      const expected = [10, 15, 20].map((n) => native.get(n)).find((r) => r.request.path === path);
      assert.ok(expected, "unissued operation");
      body = expected.response.body;
    } else if (u.pathname.includes("/channels/")) {
      const target = u.pathname.slice(4);
      if (deleted.has(target)) {
        status = 404;
        body = { error: { code: 404, status: "NOT_FOUND", message: "absent" } };
      } else {
        body = channels.find((c) => c.name === target);
        assert.ok(body, "foreign get");
      }
    } else {
      assert.equal(init.method, "GET");
      const size = Number(u.searchParams.get("pageSize"));
      if (size === 10) body = { channels };
      else {
        assert.ok([1, 2].includes(size));
        const token = u.searchParams.get("pageToken");
        const offset = token ? Number(Buffer.from(token, "base64url").toString().split(":")[1]) : 0;
        assert.equal(token, offset ? Buffer.from(`${size}:${offset}`).toString("base64url") : null);
        body = { channels: channels.slice(offset, offset + size) };
        if (offset + size < channels.length)
          body.nextPageToken = Buffer.from(`${size}:${offset + size}`).toString("base64url");
      }
    }
    const text =
      init.method === "POST" && u.pathname.endsWith(":publishEvents")
        ? publishText
        : JSON.stringify(body) + "\n";
    return new Response(text, {
      status,
      headers: {
        "content-type": "application/json; charset=UTF-8",
        "content-length": String(Buffer.byteLength(text)),
      },
    });
  };
  return { native, channels, calls, fetchImpl };
}
test("supplement actual-shape model binds six publication wires and both full own-cursor walks", async () => {
  const m = await import("./run.mjs");
  assert.equal(typeof m.collectNativeSupplement, "function");
  const world = nativeSupplementWorld();
  const report = await m.collectNativeSupplement(
    m.loadNativeSupplement(),
    "http://127.0.0.1:9999",
    { fetchImpl: world.fetchImpl },
  );
  assert.equal(
    report.complete,
    true,
    JSON.stringify({
      failure: report.failure,
      cleanupFailures: report.cleanup.filter((c) => !c.complete).map((c) => c.failure),
    }),
  );
  assert.equal(report.kind, "eventarc-native-supplement-facets-v1");
  assert.equal(report.localSDKCall, false);
  assert.deepEqual(
    report.publications.wire.map((r) => r.n),
    [23, 24, 25, 26, 27, 28],
  );
  assert.ok(report.publications.results.every((r) => r.verdict === "match"));
  assert.deepEqual(
    report.proofs.map((p) => p.key),
    [
      "N1.publish.23",
      "N1.publish.24",
      "N1.publish.25",
      "N1.publish.26",
      "N1.publish.27",
      "N1.publish.28",
      "N1.walk.36",
      "N1.walk.39",
    ],
  );
  assert.equal(report.proofs[2].transport, "sdk-wire");
  assert.equal(report.proofs[2].localSDKCall, false);
  assert.ok(report.proofs.every((p) => p.status === "PENDING"));
  assert.ok(report.cleanup.every((p) => p.complete));
  assert.equal(report.cleanup.length, 3);
  assert.equal(report.proofs[6].resourceCount, 3);
  assert.equal(report.proofs[7].resourceCount, 3);
  assert.equal(report.publications.wire[0].responseBytes, 3);
  assert.equal(Object.hasOwn(world.native.get(23).response.headers, "content-length"), false);
  assert.equal(report.publications.wire[0].headers["content-length"], "3");
  assert.equal(report.publications.wire[0].physicalHeaderComparison.verdict, "DIVERGE");
  assert.ok(
    report.publications.wire[0].physicalHeaderComparison.differences.some(
      (d) => d.header === "content-length" && d.nativePresent === false && d.actualPresent === true,
    ),
  );
  assert.equal(report.proofs[0].physicalHeaderVerdict, "DIVERGE");
  assert.equal(report.publications.wire[0].responseBase64, Buffer.from("{}\n").toString("base64"));
  assert.ok(
    report.publications.wire.at(-1).startedMonotonicMs -
      report.publications.wire[0].startedMonotonicMs >=
      5900,
  );
  assert.ok(report.exchanges.filter((x) => x.derivedFrom !== null).length);
});
test("supplement setup failure remains incomplete and cannot fabricate publication proofs", async () => {
  const m = await import("./run.mjs");
  assert.equal(typeof m.collectNativeSupplement, "function");
  const world = nativeSupplementWorld();
  let count = 0;
  const report = await m.collectNativeSupplement(
    m.loadNativeSupplement(),
    "http://127.0.0.1:9999",
    {
      fetchImpl: async (...args) => {
        if (count++ === 0) throw new Error("supplement transport failed");
        return world.fetchImpl(...args);
      },
    },
  );
  assert.equal(report.complete, false);
  assert.match(report.failure.message, /supplement transport failed/);
  assert.equal(report.proofs.length, 0);
  assert.equal(report.exchanges[0].failure.message, "supplement transport failed");
});

function supplementalCopy(t, mutate, repin = false) {
  const dir = mkdtempSync(join(tmpdir(), "ea-supplement-input-"));
  t.after(() => rmSync(dir, { recursive: true }));
  const rows = readFileSync(
    new URL("./fixtures/native-supplement/recorded.jsonl", import.meta.url),
    "utf8",
  )
    .trim()
    .split("\n")
    .map(JSON.parse);
  const provenance = JSON.parse(
    readFileSync(new URL("./fixtures/native-supplement/provenance.json", import.meta.url), "utf8"),
  );
  mutate(rows, provenance);
  const bytes = Buffer.from(rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
  if (repin) provenance.projection.sha256 = hash(bytes);
  writeFileSync(join(dir, "recorded.jsonl"), bytes);
  writeFileSync(join(dir, "provenance.json"), JSON.stringify(provenance) + "\n");
  return dir;
}
for (const [name, mutate] of [
  ["wrong native authority", (_, p) => (p.source.journalSha256 = "0".repeat(64))],
  ["foreign selector", (_, p) => (p.selectors.publishN[0] = 22)],
  ["missing tail selector", (_, p) => p.selectors.walks[0].pageN.pop()],
  ["recorded SDK classification", (rows) => (rows[24].case = "admin-sdk-publish")],
  ["recorded SDK step", (rows) => (rows[24].step = "native-25")],
  ["invented original step", (rows) => (rows[0].step = "native-1")],
  ["duplicate ordinal", (rows) => (rows[1].n = 1)],
  ["dropped row", (rows) => rows.pop()],
  ["reordered rows", (rows) => ([rows[0], rows[1]] = [rows[1], rows[0]])],
  [
    "native full-field mutation",
    (rows) => {
      const r = rows[34];
      r.response.body.channels[0].state = "INACTIVE";
      const bytes = Buffer.from(JSON.stringify(r.response.body) + "\n");
      r.response.bodyBase64 = bytes.toString("base64");
      r.response.bodyBytes = bytes.length;
      r.response.bodySha256 = hash(bytes);
    },
  ],
])
  test(`supplement loader refuses ${name} even with a rewritten projection digest`, async (t) => {
    const m = await import("./run.mjs");
    const dir = supplementalCopy(t, mutate, true);
    assert.throws(() => m.loadNativeSupplement(dir));
  });
test("supplement-only budget refusal occurs before binary lookup or spawn", async () => {
  const m = await import("./run.mjs");
  assert.equal(typeof m.checkNativeSupplement, "function");
  await assert.rejects(
    m.checkNativeSupplement({
      binary: "/missing/never-spawn",
      out: "/missing/never-write",
      budgetMs: 912500,
    }),
    /supplement budget infeasible/,
  );
});

test("supplement public facet references retain exact binding without private input paths", async () => {
  const m = await import("./run.mjs");
  assert.equal(typeof m.publicSupplementReport, "function");
  const input = m.loadNativeSupplement();
  const boundSource = {
    path: input.path,
    sha256: input.sha256,
    n: 36,
    requestSha256: "a".repeat(64),
  };
  const report = {
    proofs: [
      {
        source: boundSource,
        inventorySource: { ...boundSource, n: 35 },
        nativeAfterSource: { ...boundSource, n: 41 },
        nativePageSources: [boundSource],
      },
    ],
    exchanges: [
      {
        source: boundSource,
        request: { path: "/v1/projects/unit/locations/us-central1/channels?pageSize=1" },
      },
    ],
  };
  const output = m.publicSupplementReport(report, input);
  assert.equal(
    output.proofs[0].source.path,
    "conformance/src/eventarc-production/fixtures/native-supplement/recorded.jsonl",
  );
  assert.equal(output.proofs[0].nativePageSources[0].sha256, input.sha256);
  assert.ok(!JSON.stringify(output).includes(input.path));
  assert.equal(report.proofs[0].source.path, input.path);
  assert.throws(() =>
    m.publicSupplementReport({ source: { ...boundSource, sha256: "b".repeat(64) } }, input),
  );
  assert.throws(() =>
    m.publicSupplementReport({ source: { ...boundSource, path: "/private/foreign.jsonl" } }, input),
  );
});

test("supplement finite budget boundary property rejects every smaller allowance", async () => {
  const m = await import("./run.mjs"),
    input = m.loadNativeSupplement();
  for (const value of [0, -1, 1, 60000, 900000, 912500, 972499, 972501, NaN, Infinity, 1.5])
    assert.throws(() => m.deriveSupplementBudget(input, value));
  assert.equal(m.deriveSupplementBudget(input, 972500).overallMs, 972500);
  const changed = structuredClone(input);
  changed.rows[27].at = "2026-10-10T00:00:00.000Z";
  assert.throws(() => m.deriveSupplementBudget(changed), /session budget infeasible/);
});

test("supplement retains physical body layout D without changing the original semantic comparator", async () => {
  const m = await import("./run.mjs"),
    world = nativeSupplementWorld("{}");
  const report = await m.collectNativeSupplement(
    m.loadNativeSupplement(),
    "http://127.0.0.1:9999",
    { fetchImpl: world.fetchImpl },
  );
  assert.equal(report.complete, true, JSON.stringify(report.failure));
  assert.ok(report.publications.results.every((r) => r.verdict === "match"));
  assert.equal(report.publications.wire[0].responseBytes, 2);
  assert.equal(report.publications.wire[0].physicalBodyComparison.nativeBytes, 3);
  assert.equal(report.publications.wire[0].physicalBodyComparison.verdict, "DIVERGE");
  assert.equal(report.publications.wire[0].responseBase64, Buffer.from("{}").toString("base64"));
  assert.equal(report.proofs[0].physicalBodyVerdict, "DIVERGE");
  assert.ok(report.proofs.every((p) => p.status === "PENDING"));
});
test("supplement wrong publish status cannot complete selected semantic proofs", async () => {
  const m = await import("./run.mjs"),
    world = nativeSupplementWorld();
  const report = await m.collectNativeSupplement(
    m.loadNativeSupplement(),
    "http://127.0.0.1:9999",
    {
      fetchImpl: async (url, init) => {
        const original = await world.fetchImpl(url, init);
        return new URL(url).pathname.endsWith(":publishEvents")
          ? new Response("{}\n", {
              status: 400,
              headers: { "content-type": "application/json; charset=UTF-8", "content-length": "3" },
            })
          : original;
      },
    },
  );
  assert.equal(report.complete, false);
  assert.match(report.failure.message, /publication divergence/);
  assert.equal(report.proofs.length, 0);
  assert.ok(report.publications.results.every((r) => r.verdict === "diverge"));
  assert.equal(report.publications.wire[0].status, 400);
  assert.ok(report.cleanup.every((p) => p.complete));
});
