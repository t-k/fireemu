import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  compareDelivery,
  compareDeclaredAnswer,
  loadHRecording,
  main,
  replayH,
  writeEvidence,
} from "./h-compare.mjs";

const native = JSON.parse(
  readFileSync(new URL("./fixtures/h-fe/h-readiness.json", import.meta.url)),
);
const object = native.find((r) => r.run === "H1-v5" && r.case === "object");
const frames = object.handlerFrames;
const observation = {
  case: "object",
  known: true,
  status: 200,
  body: { events: frames.map(({ frame }) => ({ id: frame.event.id, source: frame.event.source })) },
};
const capture = { complete: true, finalRead: true, frames };

function cleanupRecording(t, overrides = {}) {
  const directory = mkdtempSync(join(tmpdir(), "fireemu-h-cleanup-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const runId = "a1b2c3d4e5f6";
  const state = {
    manifest: { runId, project: "demo-h", recording: "h2-a" },
    publishes: [observation],
    capture: { ...capture, complete: false, finalRead: false },
    evidence: { complete: false },
    cleanupReady: false,
    closureReady: false,
    ...overrides,
  };
  const files = {
    [`issued-${runId}.jsonl`]: JSON.stringify({ kind: "h-run-end", value: state }) + "\n",
    [`capture-${runId}.jsonl`]:
      JSON.stringify({
        op: "publishEvents",
        request: {
          path: "/v1/projects/demo-h/locations/us-central1/channels/unit:publishEvents",
          body: state.publishes[0].body,
        },
        response: { status: state.publishes[0].status, body: {} },
      }) + "\n",
    "summary.json": JSON.stringify(state) + "\n",
  };
  for (const [name, bytes] of Object.entries(files)) writeFileSync(join(directory, name), bytes);
  const receipt = {
    event: "cleanup-verified",
    taskId: "PUBSUB-EVENTARC",
    project: "demo-h",
    runId,
    envelopeId: `EVENTARC-H2-${runId}`,
    runDir: directory,
    sandboxAtBaseline: true,
  };
  const close = join(directory, "cleanup-close.json");
  const save = (value = receipt) => writeFileSync(close, JSON.stringify(value, null, 2) + "\n");
  save();
  return { directory, receipt, close, save, files };
}

test("coordinator cleanup closure binds its exact bytes without completing observations", (t) => {
  const f = cleanupRecording(t);
  const original = loadHRecording(f.directory);
  assert.equal(original.production.closed, false);
  const h = loadHRecording(f.directory, f.close);
  assert.equal(h.production.closed, true);
  assert.notEqual(h.production.sha256, original.production.sha256);
  const bytes = readFileSync(f.close);
  assert.equal(h.production.cleanupClose.bytes, bytes.toString());
  assert.equal(h.production.cleanupClose.sha256, createHash("sha256").update(bytes).digest("hex"));
  assert.equal(h.production.cleanupClose.path, f.close);
  assert.deepEqual(h.capture, original.capture);
  assert.deepEqual(h.observations, original.observations);
  assert.equal(
    compareDelivery({ ...observation, known: false }, capture, capture).verdict,
    "NOT_COMPARABLE",
  );
  for (const name of ["no-time", "ce-bytes"])
    assert.equal(
      compareDelivery({ ...h.observations[0], case: name }, h.capture, capture).verdict,
      "NOT_COMPARABLE",
    );
  for (const [name, contents] of Object.entries(f.files))
    assert.equal(readFileSync(join(f.directory, name), "utf8"), contents);
});

test("cleanup closure rejects missing or mismatched ownership and baseline bindings", (t) => {
  const f = cleanupRecording(t);
  for (const key of Object.keys(f.receipt)) {
    for (const value of [undefined, key === "sandboxAtBaseline" ? false : "foreign"]) {
      f.save({ ...f.receipt, [key]: value });
      assert.throws(() => loadHRecording(f.directory, f.close), /cleanup close binding/, key);
    }
  }
  f.save({ ...f.receipt, sandboxAtBaseline: "true" });
  assert.throws(() => loadHRecording(f.directory, f.close), /cleanup close binding/);
  for (const value of [null, [], "cleanup-verified"]) {
    f.save(value);
    assert.throws(() => loadHRecording(f.directory, f.close), /cleanup close binding/);
  }
  writeFileSync(f.close, "not JSON");
  assert.throws(() => loadHRecording(f.directory, f.close), /JSON/);
  assert.throws(() => loadHRecording(f.directory, join(f.directory, "missing.json")), /ENOENT/);
});

test("cleanup closure preserves unbracketed absence even with complete capture", (t) => {
  const f = cleanupRecording(t, {
    publishes: [
      { ...observation, case: "no-time", body: { events: [{ id: "missing", source: "unit" }] } },
    ],
    capture: { ...capture, frames: [] },
  });
  const h = loadHRecording(f.directory, f.close);
  assert.equal(h.production.closed, true);
  assert.equal(h.capture.complete, true);
  assert.equal(
    compareDelivery(h.observations[0], h.capture, { ...capture, frames: [] }).verdict,
    "NOT_COMPARABLE",
  );
});

test("both replay CLI modes and the owned session validate the same cleanup receipt", async (t) => {
  const f = cleanupRecording(t);
  f.save({ ...f.receipt, runId: "foreign" });
  for (const args of [
    ["--binary", join(f.directory, "unused-binary")],
    ["--base", "http://127.0.0.1:9999", "--local", join(f.directory, "unused-capture.json")],
  ])
    await assert.rejects(
      main(["--recording", f.directory, ...args, "--out", "unused", "--cleanup-close", f.close]),
      /cleanup close binding/,
    );
  const session = join(f.directory, "session.json");
  writeFileSync(session, JSON.stringify({ recording: f.directory, cleanupClose: f.close }));
  await assert.rejects(main(["--session", session]), /cleanup close binding/);
});

test("actual local capture persists exact frames and evidence state through writeEvidence", async (t) => {
  const f = cleanupRecording(t, { capture });
  const h = loadHRecording(f.directory, f.close);
  const outputRoot = new URL("../../../target/codex-out/", import.meta.url);
  mkdirSync(outputRoot, { recursive: true });
  const directory = mkdtempSync(new URL("h-capture-test-", outputRoot));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  for (const [complete, finalRead] of [
    [true, true],
    [false, true],
    [true, false],
    [false, false],
  ]) {
    const actual = {
      complete,
      finalRead,
      frames: structuredClone(frames).map((entry) =>
        Object.assign(entry, {
          logTimestamp: "2026-10-07T16:00:00.001Z",
        }),
      ),
      observations: [{ case: "object", clock: "virtual", windowMs: 0, complete }],
    };
    const before = structuredClone(actual);
    const report = await replayH(h, {
      base: "http://127.0.0.1:9999",
      fetchImpl: async () => new Response("{}", { status: 200 }),
      localCapture: actual,
    });
    assert.deepEqual(report.localCapture, before);
    assert.deepEqual(actual, before);
    assert.equal(report.rows[0].verdict, complete && finalRead ? "MATCH" : "NOT_COMPARABLE");
    const path = join(directory, "capture.json");
    writeEvidence(path, report);
    assert.deepEqual(JSON.parse(readFileSync(path)).localCapture, before);
  }
});

test("final local capture retains late frames collected after publications", async (t) => {
  const f = cleanupRecording(t, { capture });
  const h = loadHRecording(f.directory, f.close);
  const actual = { ...capture, frames: [], observations: [] };
  let published = false;
  const report = await replayH(h, {
    base: "http://127.0.0.1:9999",
    fetchImpl: async () => new Response("{}", { status: 200 }),
    afterPublish: async () => {
      published = true;
    },
    localCapture: async () => {
      assert.equal(published, true);
      actual.frames.push(
        ...structuredClone(frames).map((entry) =>
          Object.assign(entry, {
            logTimestamp: "2026-10-07T16:00:00.999Z",
          }),
        ),
      );
      actual.observations.push({ case: "object", complete: true, clock: "virtual", windowMs: 0 });
      return actual;
    },
  });
  assert.deepEqual(report.localCapture, actual);
  assert.equal(report.localCapture.frames.length, frames.length);
  assert.equal(report.rows[0].verdict, "MATCH");
});

test("retained actual frames do not make an unknown original observation comparable", async (t) => {
  const f = cleanupRecording(t, { capture, publishes: [{ ...observation, known: false }] });
  const h = loadHRecording(f.directory, f.close);
  const report = await replayH(h, {
    base: "http://127.0.0.1:9999",
    fetchImpl: async () => new Response("{}", { status: 200 }),
    localCapture: capture,
  });
  assert.deepEqual(report.localCapture, capture);
  assert.equal(report.rows[0].verdict, "NOT_COMPARABLE");
});

test("H replay refuses a remote HTTP origin before invoking transport", async () => {
  await assert.rejects(
    replayH(
      {},
      {
        base: "http://example.org:9999",
        fetchImpl: () => {
          throw Error("must not send");
        },
      },
    ),
    /loopback/,
  );
});

test("H1 native frames compare generated tracing and member order by their declared classes", () => {
  const local = structuredClone(frames);
  for (const { frame } of local) {
    frame.event.traceparent = "00-" + "1".repeat(32) + "-" + "2".repeat(16) + "-01";
    frame.event = Object.fromEntries(Object.entries(frame.event).reverse());
    frame.eventKeys = Object.keys(frame.event);
  }
  const result = compareDelivery(observation, capture, { ...capture, frames: local });
  assert.equal(result.verdict, "MATCH");
  assert.ok(result.declaredDifferences.includes("generated-traceparent"));
  assert.ok(result.declaredDifferences.includes("cloudevent-member-order"));
  for (const mutation of ["trace", "keys", "data", "correlation", "handler"]) {
    const bad = structuredClone(local);
    const f = bad[0].frame;
    if (mutation === "trace") delete f.event.traceparent;
    if (mutation === "keys") f.eventKeys.pop();
    if (mutation === "data") f.event.data = { a: 2 };
    if (mutation === "correlation") f.correlation.id = "other";
    if (mutation === "handler") f.handler = "other";
    assert.equal(
      compareDelivery(observation, capture, { ...capture, frames: bad }).verdict,
      "DIVERGES",
      mutation,
    );
  }
});

test("unbracketed absence and incomplete captures cannot establish delivery equality", () => {
  assert.equal(
    compareDelivery(observation, { ...capture, frames: [] }, capture).verdict,
    "NOT_COMPARABLE",
  );
  assert.equal(
    compareDelivery(observation, capture, { ...capture, finalRead: false }).verdict,
    "NOT_COMPARABLE",
  );
  const refused = {
    ...observation,
    refused: true,
    before: true,
    after: true,
    windowMs: 120000,
    sentAt: 0,
    endedAt: 120000,
  };
  assert.equal(
    compareDelivery(refused, { ...capture, frames: [] }, { ...capture, frames: [] }).verdict,
    "NOT_COMPARABLE",
    "controls must be observed",
  );
});

test("declared channel order retains membership, cardinality and envelope", () => {
  const row = {
    op: "listChannels",
    request: { path: "/v1/projects/demo-h/locations/us-central1/channels" },
    response: { status: 200, body: { channels: [{ name: "a" }, { name: "b" }] } },
  };
  assert.equal(
    compareDeclaredAnswer(row, { status: 200, body: { channels: [{ name: "b" }, { name: "a" }] } })
      .verdict,
    "MATCH",
  );
  for (const channels of [
    [{ name: "a" }],
    [{ name: "a" }, { name: "a" }],
    [{ name: "a" }, { name: "c" }],
  ])
    assert.equal(
      compareDeclaredAnswer(row, { status: 200, body: { channels } }).verdict,
      "DIVERGES",
    );
  assert.equal(
    compareDeclaredAnswer(row, {
      status: 200,
      body: { channels: row.response.body.channels, extra: true },
    }).verdict,
    "DIVERGES",
  );
  const auth = { ...row, tokenMode: "expired", response: { status: 401, body: {} } };
  assert.equal(compareDeclaredAnswer(auth, { status: 200, body: {} }).verdict, "NOT_COMPARABLE");
  assert.equal(
    compareDeclaredAnswer({ ...auth, tokenMode: "none" }, { status: 200, body: {} }).verdict,
    "DIVERGES",
  );
});

const recordings = process.env.EVENTARC_RECORDINGS_ROOT;
test(
  "closed H1 v5 journals replay all actual SDK bodies and preserve the two delivery gaps",
  { skip: !recordings },
  async () => {
    const h = loadHRecording(join(recordings, "eventarc-packet-h-20261006-h1v5"));
    assert.equal(h.production.closed, true);
    assert.equal(h.observations.length, 48);
    assert.equal(h.capture.frames.length, 69);
    const sent = [];
    const result = await replayH(h, {
      base: "http://127.0.0.1:9999",
      fetchImpl: async (url, init) => {
        sent.push(JSON.parse(init.body));
        const row = h.publications[sent.length - 1];
        return new Response(JSON.stringify(row.response.body), { status: row.response.status });
      },
      localCapture: h.capture,
    });
    assert.equal(sent.length, 48);
    assert.deepEqual(
      sent,
      h.publications.map((r) => r.request.body),
    );
    assert.deepEqual(result.counts, { MATCH: 46, DIVERGES: 0, NOT_COMPARABLE: 2 });
    assert.deepEqual(
      result.rows.filter((r) => r.verdict === "NOT_COMPARABLE").map((r) => r.case),
      ["scalar", "null"],
    );
    await assert.rejects(
      replayH(h, {
        base: "https://eventarcpublishing.googleapis.com",
        fetchImpl: () => {
          throw Error("must not send");
        },
      }),
      /loopback/,
    );
  },
);


function empiricalRecording(t) {
  const sentAt = 1_000_000;
  const event = { id: "unit-event", source: "unit-source", type: "unit-type",
    specversion: "1.0", subject: "unit-case", tenant: "unit-tenant", data: { probe: true },
    traceparent: "00-11111111111111111111111111111111-2222222222222222-01" };
  const frames = ["UnitObserve", "UnitFanout"].map((handler, i) => ({
    insertId: `entry-${i}`, logTimestamp: new Date(sentAt + 10).toISOString(),
    readAt: new Date(sentAt + 20).toISOString(), executionId: `execution-${i}`,
    frame: { handler, generation: 2, run: "a1b2c3d4e5f6", recording: "h2-a",
      case: "unit-case", correlation: { id: event.id, source: event.source },
      invocationId: `invocation-${i}`, attempt: "succeeded", eventKeys: Object.keys(event), event },
  }));
  const o = { case: "unit-case", known: true, status: 200, segment: "core",
    sentAt, endedAt: sentAt + 120_000, windowMs: 120_000, expectedRecipients: [],
    body: { events: [{ id: event.id, source: event.source, type: event.type, specVersion: "1.0",
      attributes: { subject: { ceString: event.subject }, tenant: { ceString: event.tenant } },
      textData: JSON.stringify(event.data) }] } };
  const evidence = { complete: false, observations: [{ case: o.case, complete: false,
    outcome: "incomplete", delivered: frames.map(({ frame }) => ({ handler: frame.handler,
      id: event.id, source: event.source, attempt: "succeeded" })) }] };
  const f = cleanupRecording(t, { publishes: [o], capture: { complete: true, finalRead: true, frames }, evidence });
  const fixture = join(f.directory, "source-core"); mkdirSync(fixture);
  const fixtureFiles = { "index.js": "// Owned fixture reporter.\n", "package.json": "{}\n", "firebase.json": "{}\n" };
  for (const [name, bytes] of Object.entries(fixtureFiles)) writeFileSync(join(fixture, name), bytes);
  writeFileSync(join(f.directory, "SHA256SUMS-coordinator"), Object.entries(fixtureFiles)
    .map(([name, bytes]) => `${createHash("sha256").update(bytes).digest("hex")}  ./source-core/${name}`).join("\n") + "\n");
  const functions = frames.map(({ frame }) => ({ name: `projects/demo-h/locations/us-central1/functions/${frame.handler}`,
    state: "ACTIVE", environment: "GEN_2", labels: { "firebase-functions-hash": "fixture-deployment-hash" },
    buildConfig: { sourceProvenance: { resolvedStorageSource: { bucket: "unit-bucket", object: "unit-source.zip", generation: "1" } } },
    serviceConfig: { service: `projects/demo-h/locations/us-central1/services/${frame.handler.toLowerCase()}`,
      revision: `${frame.handler.toLowerCase()}-00001-unit`, environmentVariables: {
        EVENTARC_H_RUN_ID: "a1b2c3d4e5f6", EVENTARC_H_RECORDING: "h2-a", EVENTARC_H_SEGMENT: "core" } },
    eventTrigger: { channel: "unit-channel", eventType: event.type } }));
  o.channel = "unit-channel";
  const deployment = { name: functions[0].name, labels: functions[0].labels,
    buildConfig: { source: { storageSource: { bucket: "unit-upload", object: "unit-source.zip" } } },
    serviceConfig: functions[0].serviceConfig };
  writeFileSync(join(fixture, "firebase-debug.log"), `Command: deploy --config ${join(fixture, "firebase.json")}\n[body] ${JSON.stringify(deployment)}\n`);
  const logRows = frames.map((wrapper, i) => ({ op: "h.logs", at: new Date(sentAt + 20).toISOString(),
    response: { status: 200, body: { entries: [{ insertId: wrapper.insertId, timestamp: wrapper.logTimestamp,
      labels: { execution_id: wrapper.executionId }, textPayload: `FE_EVENTS_FRAME ${JSON.stringify(wrapper.frame)}`,
      logName: "projects/demo-h/logs/run.googleapis.com%2Fstdout", resource: { type: "cloud_run_revision",
        labels: { project_id: "demo-h", service_name: frames[i].frame.handler.toLowerCase(), location: "us-central1",
          revision_name: functions[i].serviceConfig.revision } } }] } } }));
  const save = () => {
    const state = { manifest: { runId: "a1b2c3d4e5f6", project: "demo-h", recording: "h2-a", location: "us-central1" },
      publishes: [o], capture: { complete: true, finalRead: true, frames }, evidence };
    writeFileSync(join(f.directory, "issued-a1b2c3d4e5f6.jsonl"), [
      { at: sentAt - 1, kind: "h-readiness-lists", value: { functions } },
      { kind: "h-run-end", value: state },
    ].map(JSON.stringify).join("\n") + "\n");
    const publication = JSON.parse(f.files["capture-a1b2c3d4e5f6.jsonl"]);
    publication.request.body = o.body;
    writeFileSync(join(f.directory, "capture-a1b2c3d4e5f6.jsonl"), [publication, ...logRows].map(JSON.stringify).join("\n") + "\n");
  };
  save();
  return { ...f, frames, o, evidence, functions, logRows, fixture, save };
}

test("empirical recipient conflict requires bound original successful envelopes", (t) => {
  const f = empiricalRecording(t);
  const h = loadHRecording(f.directory, f.close);
  assert.deepEqual(h.originalEvidence, f.evidence);
  const actual = { complete: true, finalRead: true, frames: f.frames };
  const compared = compareDelivery(h.observations[0], h.capture, actual, h.observations, h.empiricalBindings[0]);
  assert.equal(compared.verdict, "MATCH");
  assert.equal(compared.adjudication.reason, "production-witness-overrides-recorder-negative-hypothesis");
  assert.deepEqual(compared.adjudication.originalEvidence, f.evidence.observations[0]);
  assert.equal(compareDelivery(f.o, h.capture, actual).verdict, "NOT_COMPARABLE");
});

test("empirical recipient conflicts reject missing and conflicting provenance", async (t) => {
  const cases = {
    "missing raw entry": (f) => { f.logRows[0].response.body.entries.length = 0; },
    "wrong log location": (f) => { f.logRows[0].response.body.entries[0].resource.labels.location = "foreign"; },
    "wrong log project": (f) => { f.logRows[0].response.body.entries[0].resource.labels.project_id = "foreign"; },
    "wrong attempt": (f) => { f.frames[0].frame.attempt = "failed"; },
    "wrong event keys": (f) => { f.frames[0].frame.eventKeys = []; },
    "wrong trace": (f) => { f.frames[0].frame.event.traceparent = "invalid"; },
    "duplicate insert": (f) => { f.frames[1].insertId = f.frames[0].insertId; },
    "wrong fixture directory receipt": (f) => { writeFileSync(join(f.fixture, "firebase-debug.log"), "Command: foreign\n"); },
    "wrong log service": (f) => { f.logRows[0].response.body.entries[0].resource.labels.service_name = "foreign"; },
    "wrong revision": (f) => { f.functions[0].serviceConfig.revision = "foreign"; },
    "missing readiness": (f) => { f.functions.length = 0; },
    "late log": (f) => { f.logRows[0].response.body.entries[0].timestamp = new Date(f.o.endedAt + 1).toISOString(); },
    "early log": (f) => { f.frames[0].logTimestamp = new Date(f.o.sentAt - 1).toISOString(); f.logRows[0].response.body.entries[0].timestamp = f.frames[0].logTimestamp; },
    "late read": (f) => { f.frames[0].readAt = new Date(f.o.endedAt + 1).toISOString(); },
    "wrong reporter envelope": (f) => { f.logRows[0].response.body.entries[0].textPayload = "FE_EVENTS_FRAME {}"; },
    "duplicate invocation": (f) => { f.frames[1].frame.invocationId = f.frames[0].frame.invocationId; },
    "wrong fixture bytes": (f) => { writeFileSync(join(f.fixture, "index.js"), "changed"); },
    "missing fixture receipt": (f) => { rmSync(join(f.fixture, "firebase-debug.log")); },
    "wrong input data": (f) => { f.o.body.events[0].textData = '{"probe":false}'; },
    "wrong run": (f) => { f.functions[0].serviceConfig.environmentVariables.EVENTARC_H_RUN_ID = "foreign"; },
    "wrong deployment hash": (f) => { f.functions[0].labels["firebase-functions-hash"] = "foreign"; },
  };
  for (const [name, change] of Object.entries(cases)) await t.test(name, (t) => {
    const f = empiricalRecording(t); change(f); f.save();
    const h = loadHRecording(f.directory, f.close);
    assert.equal(compareDelivery(h.observations[0], h.capture,
      { complete: true, finalRead: true, frames: f.frames }, h.observations, h.empiricalBindings[0]).verdict, "NOT_COMPARABLE");
    assert.deepEqual(h.originalEvidence, f.evidence);
  });
});


test("empirical adjudication preserves raw evidence and local comparison boundaries", async (t) => {
  const f = empiricalRecording(t), h = loadHRecording(f.directory, f.close);
  const compare = (local, observation = h.observations[0]) => compareDelivery(observation, h.capture,
    local, h.observations, h.empiricalBindings[0]);
  assert.equal(compare({ complete: false, finalRead: true, frames: f.frames }).verdict, "NOT_COMPARABLE");
  assert.equal(compare({ complete: true, finalRead: false, frames: f.frames }).verdict, "NOT_COMPARABLE");
  assert.equal(compare({ complete: true, finalRead: true, frames: [] }).verdict, "DIVERGES");
  const altered = structuredClone(f.frames); altered[0].frame.event.data = { probe: false };
  assert.equal(compare({ complete: true, finalRead: true, frames: altered }).verdict, "DIVERGES");
  assert.equal(compare({ complete: true, finalRead: true, frames: f.frames },
    { ...h.observations[0], windowMs: 1 }).verdict, "NOT_COMPARABLE");
  const allowed = { ...f.o, expectedRecipients: f.frames.map(({ frame }) => ({
    handler: frame.handler, id: frame.event.id, source: frame.event.source })) };
  assert.equal(compareDelivery(allowed, h.capture, h.capture).verdict, "MATCH");
  const report = await replayH(h, { base: "http://127.0.0.1:9999", localCapture: h.capture,
    fetchImpl: async () => new Response("{}", { status: 200 }) });
  assert.deepEqual(report.originalEvidence, f.evidence);
  assert.equal(report.originalEvidence.complete, false);
  assert.equal(report.rows[0].verdict, "MATCH");
  assert.equal(report.rows[0].adjudication.originalEvidence.complete, false);
});

test("empirical timestamp boundaries are inclusive and rereads do not add deliveries", (t) => {
  const f = empiricalRecording(t);
  for (const wrapper of f.frames) {
    wrapper.logTimestamp = new Date(f.o.sentAt).toISOString();
    wrapper.readAt = new Date(f.o.endedAt).toISOString();
  }
  for (const row of f.logRows) {
    row.at = new Date(f.o.endedAt).toISOString();
    row.response.body.entries[0].timestamp = new Date(f.o.sentAt).toISOString();
  }
  f.logRows.push(structuredClone(f.logRows[0])); f.save();
  const h = loadHRecording(f.directory, f.close);
  assert.equal(compareDelivery(h.observations[0], h.capture, h.capture,
    h.observations, h.empiricalBindings[0]).verdict, "MATCH");
  assert.equal(h.empiricalBindings[0].origins.length, 2);
});


test("empirical revision binding requires nonempty strings on both sides", async (t) => {
  const values = { missing: undefined, null: null, empty: "", number: 0,
    boolean: false, object: {}, array: [] };
  for (const side of ["readiness", "log", "both"]) for (const [name, value] of Object.entries(values))
    await t.test(`${side}/${name}`, (t) => {
      const f = empiricalRecording(t);
      if (side !== "log") f.functions[0].serviceConfig.revision = value;
      if (side !== "readiness") f.logRows[0].response.body.entries[0].resource.labels.revision_name = value;
      f.save();
      const h = loadHRecording(f.directory, f.close);
      assert.equal(compareDelivery(h.observations[0], h.capture, h.capture,
        h.observations, h.empiricalBindings[0]).verdict, "NOT_COMPARABLE");
      assert.deepEqual(h.originalEvidence, f.evidence);
    });
});
