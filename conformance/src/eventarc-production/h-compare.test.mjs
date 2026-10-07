import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
        request: { body: state.publishes[0].body },
        response: { status: state.publishes[0].status },
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
