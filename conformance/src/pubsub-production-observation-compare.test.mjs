import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { protos } from "@google-cloud/pubsub";
import { readPinnedBundle, main } from "./pubsub-observation/compare.mjs";
import { makePlan, SUITE } from "./pubsub-observation/plan.mjs";
import { prepareObservation, compareObservation } from "./pubsub-observation/compare-core.mjs";

const head = "a".repeat(40),
  packetSha = "b".repeat(64),
  descriptorSha = "c".repeat(64);
const runId = "012345abcdef";
export function fixture(
  method = "GetTopic",
  reply = { ok: true, status: 200, code: "OK", body: {}, bodyBytes: 2 },
) {
  const packet = {
    suite: SUITE,
    sourceHead: head,
    runIds: [runId, "abcdef012345"],
    descriptorSha256: descriptorSha,
    plan: makePlan(),
  };
  const descriptor = { head };
  const rows = [
    {
      event: "run-start",
      runId,
      suite: SUITE,
      sourceHead: head,
      packetSha256: packetSha,
      descriptorSha256: descriptorSha,
      envelopeId: "fixture",
    },
    {
      event: "request-dispatch",
      cellId: "R3",
      requestId: 1,
      method,
      transport: "rest",
      category: "target",
      request: { name: "projects/p/topics/path", labels: { name: "body-value" } },
      routeName: "projects/p/topics/route",
    },
    {
      event: "response",
      cellId: "R3",
      requestId: 1,
      method,
      transport: "rest",
      durationMs: 0.25,
      reply,
    },
    {
      event: "case-result",
      cellId: "R3",
      complete: true,
      cleanupClosed: true,
      budgetOverrun: false,
    },
  ].map((r, i) => ({ n: i + 1, at: new Date(1000 + i * 1000).toISOString(), ...r }));
  const summary = {
    suite: SUITE,
    sourceHead: head,
    packetSha256: packetSha,
    envelopeId: "fixture",
    runId,
    a2: false,
    resourcesClosed: true,
    recordingComplete: false,
    results: [{ cellId: "R3", complete: true, cleanupClosed: true, budgetOverrun: false }],
  };
  return {
    rows,
    packet,
    descriptor,
    summary,
    packetSha256: packetSha,
    descriptorSha256: descriptorSha,
    evidenceKind: "fixture",
    verifiedFrames: new Set(),
  };
}
const prepared = (x = fixture()) => prepareObservation(x);
const result = (x = fixture(), y = fixture()) => compareObservation(prepared(x), prepared(y));

test("A preparation retains 32 baseline cells and five unused reservations", () => {
  const p = prepared();
  assert.equal(p.cells.length, 32);
  assert.equal(p.reservations.length, 5);
  assert.equal(
    p.cells.find((c) => c.id === "R3").exchanges[0].request.routeName,
    "projects/p/topics/route",
  );
  assert.equal(
    p.cells.find((c) => c.id === "R3").exchanges[0].request.body.name,
    "projects/p/topics/path",
  );
});
test("explicit dispatch time accepts fractional monotonic durations", () => {
  assert.equal(prepared().cells.find((c) => c.id === "R3").exchanges[0].durationMs, 0.25);
});
for (const field of [
  "runId",
  "sourceHead",
  "packetSha256",
  "descriptorSha256",
  "suite",
  "envelopeId",
])
  test(`binding near miss ${field} is refused`, () => {
    const f = fixture();
    f.rows[0][field] = "wrong";
    assert.throws(() => prepared(f), /binding/);
  });
test("dispatch joins reject duplicates, orphan responses and chronology regression", () => {
  for (const mutate of [
    (f) => f.rows.splice(2, 0, { ...f.rows[1] }),
    (f) => (f.rows[2].requestId = 2),
    (f) => (f.rows[2].at = f.rows[0].at),
    (f) => (f.rows[2].method = "DeleteTopic"),
    (f) => (f.rows[2].durationMs = -1),
  ]) {
    const f = fixture();
    mutate(f);
    assert.throws(() => prepared(f), /sequence|pair|chronology|duration/);
  }
});
test("equal physical bodyBytes uses the existing judge; absent cells cannot match", () => {
  const r = result();
  assert.equal(r.cells.find((c) => c.id === "R3").verdict, "MATCH");
  assert.equal(r.cells.find((c) => c.id === "R1").verdict, "NOT_COMPARABLE");
  assert.equal(r.parentClosureReady, false);
});
test("wire length gaps and missing physical lengths are never compact-body matches", () => {
  const gap = fixture();
  gap.rows[2].reply.bodyBytes = 3;
  assert.equal(result(fixture(), gap).cells.find((c) => c.id === "R3").verdict, "DIVERGES");
  delete gap.rows[2].reply.bodyBytes;
  assert.equal(result(fixture(), gap).cells.find((c) => c.id === "R3").verdict, "NOT_COMPARABLE");
});
test("unknown 418 and unknown flags never become MATCH", () => {
  for (const update of [{ status: 418, ok: false, code: "UNKNOWN" }, { unknown: true }]) {
    const f = fixture();
    Object.assign(f.rows[2].reply, update);
    assert.equal(result(f, f).cells.find((c) => c.id === "R3").verdict, "NOT_COMPARABLE");
  }
});
test("successful UpdateSubscription missing or foreign identity remains unknown", () => {
  const name = "projects/p/subscriptions/own";
  for (const body of [{}, { name: "projects/p/subscriptions/foreign" }, { name }]) {
    const f = fixture("UpdateSubscription");
    f.rows[1].request = { subscription: { name, labels: { env: "probe" } }, updateMask: "labels" };
    f.rows[2].reply.body = body;
    const p = prepared(f),
      row = p.cells.find((c) => c.id === "R3").exchanges[0];
    assert.equal(row.response.unknown, body.name !== name);
    assert.equal(
      result(f, f).cells.find((c) => c.id === "R3").verdict,
      body.name === name ? "MATCH" : "NOT_COMPARABLE",
    );
  }
});
test("different requests and routeName cannot be paired by position", () => {
  for (const update of [
    (f) => (f.rows[1].routeName = "projects/p/topics/other"),
    (f) => (f.rows[1].request.labels.name = "changed"),
    (f) => (f.rows[1].category = "get"),
  ]) {
    const f = fixture();
    update(f);
    assert.equal(result(fixture(), f).cells.find((c) => c.id === "R3").verdict, "NOT_COMPARABLE");
  }
});
test("missing response, incomplete summary and known divergence keep separate debts", () => {
  const f = fixture();
  f.rows[2].reply.body = { x: 1 };
  f.rows[3].complete = false;
  f.summary.results[0].complete = false;
  assert.equal(result(fixture(), f).cells.find((c) => c.id === "R3").verdict, "DIVERGES");
  const missing = fixture();
  missing.rows.splice(2, 1);
  missing.rows.forEach((r, i) => (r.n = i + 1));
  assert.equal(result(missing, missing).cells.find((c) => c.id === "R3").verdict, "NOT_COMPARABLE");
});
test("summary result cannot silently disagree with the captured case result", () => {
  const f = fixture();
  f.summary.results[0].complete = false;
  assert.throws(() => prepared(f), /result/);
});
test("post-persistence case budget overrun preserves incomplete evidence and known gaps", () => {
  for (const gap of [false, true]) {
    const f = fixture();
    const final = {
      ...f.summary.results[0],
      complete: false,
      budgetOverrun: true,
      reason: "cell or source budget exceeded during persistence",
    };
    f.summary.results[0] = final;
    f.rows.push({ ...final, n: 5, at: new Date(5000).toISOString(), event: "case-budget-overrun" });
    const local = fixture();
    if (gap) local.rows[2].reply.body = { x: 1 };
    assert.doesNotThrow(() => result(f, local));
    const r = result(f, local).cells.find((c) => c.id === "R3");
    assert.equal(r.verdict, gap ? "DIVERGES" : "NOT_COMPARABLE");
    assert.ok(r.debts.some((d) => d.includes("incomplete")));
  }
});
test("ACK selector remains NOT_COMPARABLE even for identical successful Pull", () => {
  const f = fixture("Pull");
  f.rows[2].reply.body = {
    receivedMessages: [{ ackId: "same", message: { messageId: "123", data: "YQ==" } }],
  };
  assert.equal(result(f, f).cells.find((c) => c.id === "R3").verdict, "NOT_COMPARABLE");
});
test("omitted publication data is explicit replay debt", () => {
  const f = fixture("Publish");
  f.rows[1].request = {
    topic: "t",
    messages: [{ data: { omitted: { length: 5000, sha256: "d".repeat(64) } } }],
  };
  assert.equal(result(f, f).cells.find((c) => c.id === "R3").verdict, "NOT_COMPARABLE");
});
test("native OK publication binds causally before opaque values are judged", () => {
  const a = fixture("Publish"),
    b = fixture("Publish");
  for (const f of [a, b]) {
    f.rows[1].transport = f.rows[2].transport = "grpc";
    f.rows[1].request = { topic: "t", messages: [{ data: "YQ==" }] };
    delete f.rows[2].reply.status;
  }
  a.rows[2].reply.body = { messageIds: ["123"] };
  b.rows[2].reply.body = { messageIds: ["456"] };
  assert.equal(result(a, b).cells.find((c) => c.id === "R3").verdict, "MATCH");
  b.rows[2].reply.body = { messageIds: ["456", "789"] };
  assert.equal(result(a, b).cells.find((c) => c.id === "R3").verdict, "NOT_COMPARABLE");
});
test("generated dispatch state traces agree with the outstanding-request reference", () => {
  for (let count = 1; count <= 64; count++) {
    const f = fixture();
    const body = [];
    const outstanding = new Set();
    for (let i = 0; i < count; i++) {
      body.push({ ...f.rows[1], requestId: i + 1 });
      outstanding.add(i + 1);
      body.push({ ...f.rows[2], requestId: i + 1 });
      outstanding.delete(i + 1);
    }
    f.rows = [f.rows[0], ...body, f.rows[3]].map((r, i) => ({
      ...r,
      n: i + 1,
      at: new Date(1000 + i * 1000).toISOString(),
    }));
    const p = prepared(f);
    assert.equal(p.cells.find((c) => c.id === "R3").exchanges.length, count);
    assert.equal(outstanding.size, 0);
    assert.equal(result(f, f).cells.find((c) => c.id === "R3").verdict, "MATCH");
  }
});
const sha = (data) => createHash("sha256").update(data).digest("hex");
function diskFixture(t) {
  const dir = mkdtempSync(join(tmpdir(), "pubsub-a-compare-"));
  t.after(() => rmSync(dir, { recursive: true }));
  const f = fixture();
  const pin = (name, value, lines = false) => {
    const data = lines
      ? value.map((r) => JSON.stringify(r)).join("\n") + "\n"
      : JSON.stringify(value);
    writeFileSync(join(dir, name), data);
    return { path: join(dir, name), sha256: sha(data) };
  };
  const descriptor = pin("descriptor.json", f.descriptor);
  f.packet.descriptorSha256 = descriptor.sha256;
  const packet = pin("packet.json", f.packet);
  f.rows[0].packetSha256 = f.summary.packetSha256 = packet.sha256;
  f.rows[0].descriptorSha256 = descriptor.sha256;
  const capture = pin("capture.jsonl", f.rows, true),
    issued = pin("issued.jsonl", [], true);
  const summary = pin("summary.json", {
    ...f.summary,
    captureSha256: capture.sha256,
    issuedSha256: issued.sha256,
  });
  const bundle = {
    schema: 1,
    evidenceKind: "fixture",
    packet,
    descriptor,
    capture,
    issued,
    summary,
  };
  return { dir, f, pin, bundle, index: pin("input.json", { source: bundle }) };
}
test("CLI preparation pins all inputs, outputs exclusively and performs no replay", (t) => {
  const d = diskFixture(t),
    out = join(d.dir, "plan.json");
  main(["--input", d.index.path, "--input-sha256", d.index.sha256, "--out", out]);
  const p = JSON.parse(readFileSync(out));
  assert.equal(p.cells.length, 32);
  assert.equal(p.replayExecuted, false);
  assert.throws(
    () => main(["--input", d.index.path, "--input-sha256", d.index.sha256, "--out", out]),
    /exist/,
  );
});
test("hash and summary capture near misses refuse before parsing or output", (t) => {
  const d = diskFixture(t);
  writeFileSync(d.bundle.capture.path, "not-json");
  assert.throws(() => readPinnedBundle(d.bundle), /hash/);
  assert.throws(
    () =>
      main([
        "--input",
        d.index.path,
        "--input-sha256",
        "0".repeat(64),
        "--out",
        join(d.dir, "no.json"),
      ]),
    /hash/,
  );
});
test("production loader requires exact coordinator pins and summary journal digests", (t) => {
  const d = diskFixture(t);
  d.bundle.evidenceKind = "production";
  const manifest =
    ["capture", "issued", "summary"]
      .map((k) => `${d.bundle[k].sha256}  ${d.bundle[k].path.split("/").at(-1)}`)
      .join("\n") + "\n";
  d.bundle.coordinatorManifest = { path: join(d.dir, "manifest.txt"), sha256: sha(manifest) };
  writeFileSync(d.bundle.coordinatorManifest.path, manifest);
  assert.equal(readPinnedBundle(d.bundle).rows.length, 4);
  writeFileSync(
    d.bundle.coordinatorManifest.path,
    manifest.replace(d.bundle.capture.sha256, "0".repeat(64)),
  );
  d.bundle.coordinatorManifest.sha256 = sha(readFileSync(d.bundle.coordinatorManifest.path));
  assert.throws(() => readPinnedBundle(d.bundle), /manifest/);
  d.bundle.evidenceKind = "fixture";
  d.bundle.summary = d.pin("mismatch.json", {
    ...d.f.summary,
    captureSha256: "0".repeat(64),
    issuedSha256: d.bundle.issued.sha256,
  });
  assert.throws(() => readPinnedBundle(d.bundle), /summary journal hash/);
});
test("native frame verification requires matching raw bytes and decoded body", (t) => {
  const d = diskFixture(t),
    body = { subscription: "projects/p/subscriptions/s", streamAckDeadlineSeconds: 10 };
  const Type = protos.google.pubsub.v1.StreamingPullRequest;
  const raw = Buffer.from(Type.encode(Type.fromObject(body)).finish());
  const path = `frame-${runId}-0001.pb`;
  writeFileSync(join(d.dir, path), raw);
  const rows = [
    d.f.rows[0],
    {
      event: "stream-frame",
      cellId: "S01",
      direction: "out",
      elapsedMs: 0,
      body,
      blob: { path, bytes: raw.length, sha256: sha(raw) },
    },
  ].map((r, i) => ({ ...r, n: i + 1, at: new Date(1000 + i * 1000).toISOString() }));
  d.bundle.capture = d.pin("frames.jsonl", rows, true);
  d.bundle.summary = d.pin("frames-summary.json", {
    ...d.f.summary,
    results: [],
    captureSha256: d.bundle.capture.sha256,
    issuedSha256: d.bundle.issued.sha256,
  });
  assert.equal(readPinnedBundle(d.bundle).verifiedFrames.has(2), true);
  rows[1].body.streamAckDeadlineSeconds = 11;
  d.bundle.capture = d.pin("bad-frames.jsonl", rows, true);
  d.bundle.summary = d.pin("bad-summary.json", {
    ...d.f.summary,
    results: [],
    captureSha256: d.bundle.capture.sha256,
    issuedSha256: d.bundle.issued.sha256,
  });
  assert.equal(readPinnedBundle(d.bundle).verifiedFrames.has(2), false);
  rows[1].blob.path = "../escape.pb";
  d.bundle.capture = d.pin("escape.jsonl", rows, true);
  d.bundle.summary = d.pin("escape-summary.json", {
    ...d.f.summary,
    results: [],
    captureSha256: d.bundle.capture.sha256,
    issuedSha256: d.bundle.issued.sha256,
  });
  assert.equal(readPinnedBundle(d.bundle).verifiedFrames.has(2), false);
});

function nativeProofFixture(t, frames) {
  const d = diskFixture(t);
  const rows = [
    d.f.rows[0],
    ...frames.map((frame, i) => {
      const path = `frame-${runId}-${String(i + 1).padStart(4, "0")}.pb`;
      writeFileSync(join(d.dir, path), frame.raw);
      return {
        event: "stream-frame",
        cellId: "S14",
        direction: frame.direction ?? "out",
        elapsedMs: 0,
        body: frame.body,
        blob: { path, bytes: frame.raw.length, sha256: frame.sha256 ?? sha(frame.raw) },
      };
    }),
  ].map((row, i) => ({ ...row, n: i + 1, at: new Date(1000 + i * 1000).toISOString() }));
  d.bundle.capture = d.pin("proof-frames.jsonl", rows, true);
  d.bundle.summary = d.pin("proof-summary.json", {
    ...d.f.summary,
    results: [],
    captureSha256: d.bundle.capture.sha256,
    issuedSha256: d.bundle.issued.sha256,
  });
  return readPinnedBundle(d.bundle).verifiedFrames;
}

test("outbound proof retains an explicit empty deadline list with exact producer encoding", (t) => {
  const Type = protos.google.pubsub.v1.StreamingPullRequest;
  const frames = [];
  for (const subscription of [undefined, "projects/p/subscriptions/s"]) {
    for (const count of [0, 1, 2]) {
      const body = { modifyDeadlineSeconds: [] };
      if (subscription) body.subscription = subscription;
      if (count) body.modifyDeadlineAckIds = Array.from({ length: count }, (_, i) => `ack-${i}`);
      frames.push({ body, raw: Buffer.from(Type.encode(Type.fromObject(body)).finish()) });
    }
  }
  assert.deepEqual([...nativeProofFixture(t, frames)], [2, 3, 4, 5, 6, 7]);
});

test("outbound empty deadline proof refuses other missing fields and altered raw bytes", (t) => {
  const Type = protos.google.pubsub.v1.StreamingPullRequest;
  const body = { modifyDeadlineAckIds: ["ack"], modifyDeadlineSeconds: [] };
  const raw = Buffer.from(Type.encode(Type.fromObject(body)).finish());
  const frames = [
    { body: { ...body, unknownField: [] }, raw },
    { body: { ...body, ackIds: [] }, raw },
    { body: { ...body, modifyDeadlineSeconds: [10] }, raw },
    { body, raw: Buffer.concat([raw, Buffer.from([0x98, 0x06, 0x01])]) },
    {
      body,
      raw: Buffer.from(raw.map((byte, i) => (i === raw.length - 1 ? byte ^ 1 : byte))),
      sha256: sha(raw),
    },
    { body, raw: Buffer.concat([raw, Buffer.from([0x18, 0x00])]) },
  ];
  assert.equal(nativeProofFixture(t, frames).size, 0);
});

test("inbound native proof keeps strict object equality for empty fields", (t) => {
  const Type = protos.google.pubsub.v1.StreamingPullResponse;
  const raw = Buffer.from(Type.encode(Type.fromObject({})).finish());
  assert.deepEqual(
    [
      ...nativeProofFixture(t, [
        { body: {}, raw, direction: "in" },
        { body: { modifyDeadlineSeconds: [] }, raw, direction: "in" },
        { body: { receivedMessages: [] }, raw, direction: "in" },
      ]),
    ],
    [2],
  );
});

test("executed native verdict requires exact raw/action coverage and measured invalid-ACK window", async () => {
  const { compareExecutedObservation } = await import("./pubsub-observation/compare-core.mjs");
  const source = prepared(),
    local = prepared(),
    cell = source.cells.find((c) => c.id === "S16"),
    peer = local.cells.find((c) => c.id === "S16");
  cell.debts = peer.debts = [
    "native stream timing and causal witness requires dedicated replay; frame equality alone is insufficient",
  ];
  cell.frames = [{ n: 7, direction: "out", verified: true, blob: { bytes: 10 } }];
  peer.frames = [{ direction: "out", verified: true, blob: { bytes: 10 } }];
  cell.events = [
    {
      event: "stream-case-observation",
      n: 8,
      invalidAckObservedMs: 30001,
      state: { incomplete: false },
    },
  ];
  const witness = {
    completed: true,
    sourceFrames: [7],
    actions: [{ sourceN: 8, event: "stream-case-observation", elapsedMs: 30001 }],
    silenceMs: 30001,
  };
  const verdict = (proof) =>
    compareExecutedObservation(source, local, { S16: proof }).cells.find((c) => c.id === "S16")
      .verdict;
  assert.equal(verdict(witness), "MATCH");
  for (const update of [
    { sourceFrames: [] },
    { completed: false },
    { actions: [] },
    { actions: [{ sourceN: 8, event: "stream-case-observation", elapsedMs: NaN }] },
    { actions: [{ sourceN: 8, event: "stream-cancel", elapsedMs: 30001 }] },
    { silenceMs: 29999 },
  ])
    assert.equal(verdict({ ...witness, ...update }), "NOT_COMPARABLE");
  peer.frames[0].verified = false;
  assert.equal(verdict(witness), "NOT_COMPARABLE");
  peer.frames[0].verified = true;
  cell.frames[0].verified = false;
  assert.equal(verdict(witness), "NOT_COMPARABLE");
  cell.frames[0].verified = true;
  peer.frames[0].blob.bytes = 11;
  assert.equal(verdict(witness), "DIVERGES");
  assert.equal(
    compareExecutedObservation(source, local, { S16: witness }).localRuntimeVerified,
    false,
  );
});

// Synthetic controls model the two recorded incomplete zero-deadline shapes.
export function zeroOutcomeFixture(details) {
  const input = fixture();
  input.packet.plan = makePlan("s10-diagnostic");
  const subscription = `projects/fireemu-oracle-idp/subscriptions/fe${runId}-s10-sub`;
  const body = {
    subscription,
    streamAckDeadlineSeconds: 0,
    maxOutstandingMessages: "1",
    maxOutstandingBytes: "1024",
  };
  const result = {
    cellId: "S10",
    complete: false,
    cleanupClosed: true,
    budgetOverrun: false,
    outstanding: [],
    names: [subscription],
  };
  input.rows = [
    input.rows[0],
    { event: "stream-dispatch", cellId: "S10" },
    {
      event: "stream-frame",
      cellId: "S10",
      direction: "out",
      elapsedMs: 1,
      body,
      blob: { bytes: 73, sha256: "d".repeat(64) },
    },
    { event: "stream-open-local", cellId: "S10", elapsedMs: 2, windowMs: 90000 },
    {
      event: "stream-error",
      cellId: "S10",
      elapsedMs: 117,
      code: 13,
      ...(details === undefined ? {} : { details }),
    },
    {
      event: "stream-status",
      cellId: "S10",
      elapsedMs: 118,
      code: 13,
      ...(details === undefined ? {} : { details }),
    },
    { event: "stream-inbound-end", cellId: "S10", elapsedMs: 119 },
    {
      event: "stream-case-observation",
      cellId: "S10",
      state: {
        terminal: { code: 13 },
        inboundEnded: true,
        incomplete: true,
        windowExpired: false,
        windowMs: 90000,
        received: 0,
      },
    },
    { event: "case-result", ...result },
  ].map((r, i) => ({ ...r, n: i + 1, at: new Date(1000 + i * 1000).toISOString() }));
  input.summary.results = [result];
  input.verifiedFrames = new Set([3]);
  return input;
}

test("fixed selected plan admits only its exact declared cells", () => {
  const input = zeroOutcomeFixture();
  assert.deepEqual(
    prepareObservation(input).cells.map((c) => c.id),
    ["S10"],
  );
  input.packet.plan.cells[0].variant += "-foreign";
  assert.throws(() => prepareObservation(input), /binding/);
});

test("exact S10 natural outcome preserves incomplete debt and message availability", async () => {
  const { compareExecutedObservation } = await import("./pubsub-observation/compare-core.mjs");
  for (const details of [
    undefined,
    "A service error has occurred. Please retry your request. If the error persists, please report it. [code=e8c0]",
  ]) {
    const source = prepareObservation(zeroOutcomeFixture(details));
    source.evidenceKind = "production";
    for (const suffix of ["Subscription", "Topic"]) {
      const name = `projects/fireemu-oracle-idp/${suffix === "Topic" ? "topics" : "subscriptions"}/fe${runId}-s10-${suffix === "Topic" ? "topic" : "sub"}`;
      for (const method of [`Delete${suffix}`, `Get${suffix}`])
        source.cells[0].exchanges.push({
          method,
          transport: "rest",
          category: method.startsWith("Delete") ? "cleanupDelete" : "cleanupGet",
          request: { body: { name } },
          response: {
            ok: method.startsWith("Delete"),
            status: method.startsWith("Delete") ? 200 : 404,
            code: method.startsWith("Delete") ? "OK" : "NOT_FOUND",
            body: {},
            unknown: false,
          },
          n: 10 + 2 * source.cells[0].exchanges.length,
          dispatchN: 9 + 2 * source.cells[0].exchanges.length,
        });
    }
    const local = structuredClone(source);
    local.evidenceKind = "local";
    const cell = local.cells[0];
    cell.events = cell.events.map((e) =>
      e.event === "stream-error" || e.event === "stream-status"
        ? {
            ...e,
            details:
              "A service error has occurred. Please retry your request. If the error persists, please report it.",
          }
        : e,
    );
    for (const event of cell.events) event.n += 1000;
    for (const frame of cell.frames) frame.n += 1000;
    for (const exchange of cell.exchanges) {
      exchange.n += 1000;
      exchange.dispatchN += 1000;
    }
    cell.events.find((e) => e.event === "stream-case-observation").elapsedMs = 120;
    const proof = {
      completed: false,
      sourceFrames: [3],
      actions: [{ sourceN: 8, event: "stream-case-observation", elapsedMs: 120 }],
      zeroOutcome: {
        state: structuredClone(
          cell.events.find((e) => e.event === "stream-case-observation").state,
        ),
        observedElapsedMs: 120,
        observationN: 1008,
      },
    };
    const result = compareExecutedObservation(source, local, { S10: proof });
    const outcome = result.cells[0].nativeOutcome;
    assert.equal(outcome.verdict, "MATCH");
    assert.equal(outcome.details.source.available, details !== undefined);
    assert.equal(outcome.details.verdict, details === undefined ? "NOT_COMPARABLE" : "DIVERGES");
    assert.equal(result.cells[0].verdict, "NOT_COMPARABLE");
    assert.equal(result.parentClosureReady, false);
    assert.ok(result.cells[0].debts.some((d) => d.includes("completion/cleanup")));
    assert.ok(result.cells[0].debts.some((d) => d.includes("details")));
    for (const side of ["source", "local"])
      for (const phase of ["before-opening", "before-terminal", "before-observation"]) {
        const s = structuredClone(source),
          l = structuredClone(local),
          p = structuredClone(proof);
        const target = (side === "source" ? s : l).cells[0];
        const threshold =
          (side === "source" ? 0 : 1000) +
          (phase === "before-opening" ? 2 : phase === "before-terminal" ? 5 : 8);
        for (const event of target.events) if (event.n >= threshold) event.n += 30;
        for (const frame of target.frames) if (frame.n >= threshold) frame.n += 30;
        if (side === "source") {
          p.sourceFrames = target.frames.map((f) => f.n);
          p.actions[0].sourceN = target.events.find((e) => e.event === "stream-case-observation").n;
        } else
          p.zeroOutcome.observationN = target.events.find(
            (e) => e.event === "stream-case-observation",
          ).n;
        assert.equal(
          compareExecutedObservation(s, l, { S10: p }).cells[0].nativeOutcome.verdict,
          "NOT_COMPARABLE",
          `${side}/${phase}`,
        );
      }
    for (let seed = 1; seed <= 64; seed++) {
      for (const [field, value] of [
        ["streamAckDeadlineSeconds", seed % 2 ? seed : -seed],
        ["maxOutstandingMessages", String(seed + 1)],
        ["maxOutstandingBytes", String(1024 + seed)],
      ]) {
        const adjacent = structuredClone(source);
        adjacent.cells[0].frames[0].body[field] = value;
        assert.equal(
          compareExecutedObservation(adjacent, local, { S10: proof }).cells[0].nativeOutcome
            .verdict,
          "NOT_COMPARABLE",
          `${field}/${seed}`,
        );
      }
    }
    for (const mutate of [
      (s, _l, _p) => (s.cells[0].coordinate = "/conditions/13/cases/8"),
      (s, _l, _p) => (s.cells[0].variant = "half-close"),
      (s, _l, _p) => (s.cells[0].frames[0].body.streamAckDeadlineSeconds = 10),
      (s, _l, _p) => (s.cells[0].frames[0].body.maxOutstandingMessages = "2"),
      (s, _l, _p) => (s.cells[0].frames[0].body.maxOutstandingBytes = "1025"),
      (s, _l, _p) => (s.cells[0].frames[0].body.subscription += "-foreign"),
      (s, _l, _p) => (s.cells[0].frames[0].verified = false),
      (s, _l, _p) =>
        (s.cells[0].events = s.cells[0].events.filter((e) => e.event !== "stream-status")),
      (s, _l, _p) =>
        (s.cells[0].events = s.cells[0].events.filter((e) => e.event !== "stream-inbound-end")),
      (s, _l, _p) => (s.cells[0].events.find((e) => e.event === "stream-error").code = 3),
      (s, _l, _p) => s.cells[0].events.push({ event: "stream-cancel" }),
      (s, _l, _p) => s.cells[0].events.push({ event: "stream-observation-window-end" }),
      (s, _l, _p) => (s.cells[0].result.cleanupClosed = false),
      (s, _l, _p) => (s.cells[0].result.budgetOverrun = true),
      (s, _l, _p) => s.cells[0].result.outstanding.push("unresolved"),
      (s, l, _p) => l.cells[0].exchanges.pop(),
      (_s, l, _p) => (l.cells[0].exchanges[0].response.ok = false),
      (_s, l, _p) => (l.cells[0].frames[0].blob.sha256 = "0".repeat(64)),
      (_s, _l, p) => (p.zeroOutcome.observedElapsedMs = 118),
      (_s, _l, p) => delete p.zeroOutcome.observationN,
      (_s, _l, p) => (p.zeroOutcome.observationN = 8),
      (_s, l, p) => {
        l.cells[0].events.find((e) => e.event === "stream-case-observation").n = 1006;
        p.zeroOutcome.observationN = 1006;
      },
      (_s, l, _p) =>
        (l.cells[0].events.find((e) => e.event === "stream-case-observation").elapsedMs = 121),
      (_s, l, _p) =>
        (l.cells[0].events.find((e) => e.event === "stream-case-observation").state.received = 1),
      (_s, l, _p) =>
        (l.cells[0].events = l.cells[0].events.filter(
          (e) => e.event !== "stream-case-observation",
        )),
      (_s, l, _p) => (l.cells[0].events.find((e) => e.event === "stream-dispatch").n = 9999),
      (_s, _l, p) => (p.sourceFrames = []),
      (_s, _l, p) => (p.actions = []),
      (_s, _l, p) => delete p.zeroOutcome,
      (s, l, _p) => l.cells[0].events.push({ event: "stream-cancel" }),
      (s, l, _p) =>
        l.cells[0].frames.push({
          direction: "in",
          verified: true,
          body: { receivedMessages: [{}] },
        }),
      (_s, _l, p) => (p.zeroOutcome.state.received = 1),
    ]) {
      const s = structuredClone(source),
        l = structuredClone(local),
        p = structuredClone(proof);
      mutate(s, l, p);
      assert.equal(
        compareExecutedObservation(s, l, { S10: p }).cells[0].nativeOutcome.verdict,
        "NOT_COMPARABLE",
      );
    }
  }
});

export function approvedNativeFixture() {
  const source = prepared(),
    local = prepared();
  const bytes = (body) =>
    Buffer.from(protos.google.pubsub.v1.StreamingPullResponse.encode(body).finish());
  const decode = (raw) =>
    protos.google.pubsub.v1.StreamingPullResponse.toObject(
      protos.google.pubsub.v1.StreamingPullResponse.decode(raw),
      { longs: String, enums: String, bytes: String, defaults: false },
    );
  const received = (ack, id) => ({
    receivedMessages: [
      {
        ackId: ack,
        message: {
          data: "bWFya2Vy",
          messageId: id,
          publishTime: { seconds: "100", nanos: 1 },
        },
      },
    ],
    subscriptionProperties: {},
  });
  const sourceBytes = bytes(received("source-ack", "source-1"));
  const localBytes = bytes(received("longer-local-ack", "actual-1"));
  for (const [observation, raw, n] of [
    [source, sourceBytes, 7],
    [local, localBytes, 17],
  ]) {
    const cell = observation.cells.find((c) => c.id === "S16");
    cell.exchanges = [];
    cell.debts = [
      "native stream timing and causal witness requires dedicated replay; frame equality alone is insufficient",
    ];
    cell.result = { complete: true, cleanupClosed: true, budgetOverrun: false };
    cell.frames = [
      {
        n,
        direction: "in",
        verified: true,
        body: decode(raw),
        blob: { bytes: raw.length, sha256: createHash("sha256").update(raw).digest("hex") },
      },
    ];
    cell.events = [
      { n: n + 1, event: "stream-status", code: 0, details: "", elapsedMs: 1 },
      {
        n: n + 2,
        event: "stream-case-observation",
        elapsedMs: 2,
        state: { incomplete: false },
        invalidAckObservedMs: 30001,
      },
    ];
  }
  const authorityBytes = Buffer.from(
    JSON.stringify({ proposalSha256: "d".repeat(64), line: "Explicit offline ACK disposition" }),
  );
  return {
    source,
    local,
    witness: {
      S16: {
        completed: true,
        semanticsVerified: true,
        sourceFrames: [7],
        actions: [{ sourceN: 9, event: "stream-case-observation", elapsedMs: 30001 }],
        silenceMs: 30001,
      },
    },
    disposition: {
      authority: {
        bytes: authorityBytes,
        sha256: createHash("sha256").update(authorityBytes).digest("hex"),
      },
      source: {
        runId: source.runId,
        packetSha256: source.packetSha256,
        descriptorSha256: source.descriptorSha256,
      },
      rawFrames: [{ sourceN: 7, localN: 17, sourceBytes, localBytes }],
      remainingDebts: {},
    },
  };
}

test("explicit pinned ACK disposition retains the literal physical gap", async () => {
  const { compareExecutedObservation } = await import("./pubsub-observation/compare-core.mjs");
  const { source, local, witness, disposition } = approvedNativeFixture();
  const ordinary = compareExecutedObservation(source, local, witness).cells.find(
    (c) => c.id === "S16",
  );
  assert.equal(ordinary.verdict, "DIVERGES");
  const report = compareExecutedObservation(source, local, witness, disposition);
  const cell = report.cells.find((c) => c.id === "S16");
  assert.equal(cell.approvedComparison.verdict, "MATCH");
  assert.equal(cell.nativeLayout.verdict, "DIVERGES");
  assert.equal(cell.verdict, "MATCH");
  assert.equal(report.parentClosureReady, false);
});

test("approved wire comparison refuses absent authority, raw coverage and semantic guards", async () => {
  const { compareExecutedObservation } = await import("./pubsub-observation/compare-core.mjs");
  for (const alter of [
    (f) => delete f.disposition.authority,
    (f) => (f.disposition.authority.sha256 = "0".repeat(64)),
    (f) => (f.disposition.source.runId = "foreign"),
    (f) => (f.disposition.rawFrames = []),
    (f) => f.disposition.rawFrames.push(f.disposition.rawFrames[0]),
    (f) => f.disposition.rawFrames[0].localN++,
    (f) => (f.disposition.rawFrames[0].localBytes[3] ^= 1),
    (f) => {
      const raw = f.disposition.rawFrames[0].localBytes;
      raw[4] ^= 1;
      f.local.cells.find((c) => c.id === "S16").frames[0].body.receivedMessages[0].ackId =
        protos.google.pubsub.v1.StreamingPullResponse.decode(raw).receivedMessages[0].ackId;
    },
    (f) => (f.witness.S16.semanticsVerified = false),
    (f) => (f.witness.S16.completed = false),
    (f) => (f.witness.S16.sourceFrames = []),
    (f) => (f.witness.S16.actions = []),
    (f) => (f.witness.S16.silenceMs = 29999),
    (f) => (f.local.cells.find((c) => c.id === "S16").frames[0].direction = "out"),
    (f) =>
      f.local.cells
        .find((c) => c.id === "S16")
        .frames.push({ ...f.local.cells.find((c) => c.id === "S16").frames[0], n: 18 }),
    (f) => (f.source.cells.find((c) => c.id === "S16").result.complete = false),
    (f) => (f.disposition.remainingDebts.S16 = ["Required terminal status remains unrecorded"]),
  ]) {
    const f = approvedNativeFixture();
    alter(f);
    assert.notEqual(
      compareExecutedObservation(f.source, f.local, f.witness, f.disposition).cells.find(
        (c) => c.id === "S16",
      ).verdict,
      "MATCH",
    );
  }
});

test("ACK projection preserves every remaining field, width, tag and terminal detail", async () => {
  const { compareExecutedObservation } = await import("./pubsub-observation/compare-core.mjs");
  const Type = protos.google.pubsub.v1.StreamingPullResponse;
  for (const alter of [
    (body) => delete body.receivedMessages[0].ackId,
    (body) => (body.receivedMessages[0].ackId = ""),
    (body) => (body.receivedMessages[0].message.data = "Zm9yZWln"),
    (body) => delete body.receivedMessages[0].message.publishTime,
    (body) => (body.receivedMessages[0].message.publishTime.seconds = "200"),
    (body) => (body.receivedMessages[0].message.publishTime.seconds = "101"),
    (body) => (body.receivedMessages[0].message.publishTime.nanos = 2),
    (body) => delete body.subscriptionProperties,
    (body) => body.receivedMessages.push(body.receivedMessages[0]),
  ]) {
    const f = approvedNativeFixture(),
      cell = f.local.cells.find((c) => c.id === "S16");
    alter(cell.frames[0].body);
    const raw = Buffer.from(Type.encode(cell.frames[0].body).finish());
    cell.frames[0].body = Type.toObject(Type.decode(raw), {
      longs: String,
      enums: String,
      bytes: String,
      defaults: false,
    });
    cell.frames[0].blob = {
      bytes: raw.length,
      sha256: createHash("sha256").update(raw).digest("hex"),
    };
    f.disposition.rawFrames[0].localBytes = raw;
    assert.notEqual(
      compareExecutedObservation(f.source, f.local, f.witness, f.disposition).cells.find(
        (c) => c.id === "S16",
      ).approvedComparison.verdict,
      "MATCH",
    );
  }
  for (const alterRaw of [
    (raw) => Buffer.concat([raw, Buffer.from([0xa8, 0x06, 0x01])]),
    (raw) => {
      const b = Buffer.from(raw);
      b[2] = 0x08;
      return b;
    },
    (raw) => {
      const b = Buffer.from(raw);
      b[2] = 0x1a;
      return b;
    },
    (raw) =>
      Buffer.concat([
        Buffer.from([0x0a, raw[1] + 3]),
        raw.subarray(2, 2 + raw[1]),
        Buffer.from([0x0a, 1, 0x78]),
        raw.subarray(2 + raw[1]),
      ]),
    (raw) => raw.subarray(0, raw.length - 1),
  ]) {
    const f = approvedNativeFixture(),
      frame = f.local.cells.find((c) => c.id === "S16").frames[0];
    const raw = alterRaw(f.disposition.rawFrames[0].localBytes);
    try {
      frame.body = Type.toObject(Type.decode(raw), {
        longs: String,
        enums: String,
        bytes: String,
        defaults: false,
      });
    } catch {
      frame.body = {};
    }
    frame.blob = { bytes: raw.length, sha256: createHash("sha256").update(raw).digest("hex") };
    f.disposition.rawFrames[0].localBytes = raw;
    assert.notEqual(
      compareExecutedObservation(f.source, f.local, f.witness, f.disposition).cells.find(
        (c) => c.id === "S16",
      ).approvedComparison.verdict,
      "MATCH",
    );
  }
  for (const alter of [
    (cell) => delete cell.events[0].details,
    (cell) => (cell.events[0].details = "different"),
    (cell) => (cell.events[0].code = 5),
    (cell) => (cell.events[0].code = "UNKNOWN"),
    (cell) => cell.events.splice(0, 1),
    (cell) => cell.events.push(cell.events[0]),
  ]) {
    const f = approvedNativeFixture();
    alter(f.local.cells.find((c) => c.id === "S16"));
    assert.notEqual(
      compareExecutedObservation(f.source, f.local, f.witness, f.disposition).cells.find(
        (c) => c.id === "S16",
      ).approvedComparison.verdict,
      "MATCH",
    );
  }
  const missingBoth = approvedNativeFixture();
  for (const observation of [missingBoth.source, missingBoth.local])
    delete observation.cells.find((c) => c.id === "S16").events[0].details;
  assert.equal(
    compareExecutedObservation(
      missingBoth.source,
      missingBoth.local,
      missingBoth.witness,
      missingBoth.disposition,
    ).cells.find((c) => c.id === "S16").approvedComparison.verdict,
    "NOT_COMPARABLE",
  );
});

test("native receive preserves publishTime values with actual publication bindings", async () => {
  const { matchNativeReceive } = await import("./pubsub-observation/replay-native.mjs");
  const { createBindings } = await import("./pubsub-production/stream-dlq-compare-core.mjs");
  const { compareExecutedObservation } = await import("./pubsub-observation/compare-core.mjs");
  for (const [field, value] of [
    ["seconds", "101"],
    ["nanos", 2],
  ]) {
    const f = approvedNativeFixture();
    const source = f.source.cells.find((c) => c.id === "S16").frames[0].body;
    const local = f.local.cells.find((c) => c.id === "S16").frames[0].body;
    const bindings = createBindings();
    bindings.linkPublish(
      { messages: [{ data: "bWFya2Vy" }] },
      { messageIds: ["source-1"] },
      { messageIds: ["actual-1"] },
    );
    assert.doesNotThrow(() => matchNativeReceive(source, local, bindings));
    local.receivedMessages[0].message.publishTime[field] = value;
    const raw = Buffer.from(protos.google.pubsub.v1.StreamingPullResponse.encode(local).finish());
    const frame = f.local.cells.find((c) => c.id === "S16").frames[0];
    assert.equal(raw.length, frame.blob.bytes);
    frame.blob = { bytes: raw.length, sha256: createHash("sha256").update(raw).digest("hex") };
    f.disposition.rawFrames[0].localBytes = raw;
    assert.equal(
      compareExecutedObservation(f.source, f.local, f.witness, f.disposition).cells.find(
        (c) => c.id === "S16",
      ).approvedComparison.verdict,
      "DIVERGES",
    );
    assert.throws(
      () => matchNativeReceive(source, local, bindings),
      /native receive semantic mismatch/,
    );
  }
});

test("S03 disposal terminal comparison retains cause and never fills the prior null observation", async () => {
  const { compareExecutedObservation } = await import("./pubsub-observation/compare-core.mjs");
  const input = fixture();
  while (input.rows.length < 21)
    input.rows.push({
      n: input.rows.length + 1,
      at: new Date((input.rows.length + 1) * 1000).toISOString(),
      event: "fixture-padding",
    });
  input.rows.push(
    {
      n: 22,
      at: new Date(22000).toISOString(),
      cellId: "S03",
      event: "stream-case-observation",
      state: { terminal: null, incomplete: false },
    },
    {
      n: 23,
      at: new Date(23000).toISOString(),
      cellId: "S03",
      event: "stream-cancel",
      reason: "dispose",
    },
    {
      n: 24,
      at: new Date(24000).toISOString(),
      cellId: "S03",
      event: "stream-error",
      code: 1,
      details: "Cancelled on client",
      phase: "disposal",
      cancelReason: "dispose",
    },
    { n: 25, at: new Date(25000).toISOString(), cellId: "S03", event: "stream-metadata" },
    {
      n: 26,
      at: new Date(26000).toISOString(),
      cellId: "S03",
      event: "stream-status",
      code: 1,
      details: "Cancelled on client",
      phase: "disposal",
      cancelReason: "dispose",
    },
  );
  const exported = prepareObservation(input).cells.find((c) => c.id === "S03");
  assert.equal(exported.events.find((e) => e.n === 22).state.terminal, null);
  for (const mutation of [
    "none",
    "natural",
    "phase",
    "missing",
    "both-missing",
    "unknown",
    "details",
    "cause",
    "code",
  ]) {
    const f = approvedNativeFixture();
    const original = f.source.cells.find((c) => c.id === "S16");
    const actual = f.local.cells.find((c) => c.id === "S16");
    original.id = actual.id = "S03";
    f.source.cells = [original];
    f.local.cells = [actual];
    original.events = structuredClone(exported.events);
    actual.events = structuredClone(exported.events);
    f.witness.S03 = {
      ...f.witness.S16,
      actions: [
        { sourceN: 22, event: "stream-case-observation", elapsedMs: 1 },
        { sourceN: 23, event: "stream-cancel", elapsedMs: 2 },
      ],
    };
    original.events[0].invalidAckObservedMs = null;
    if (mutation === "natural")
      for (const event of actual.events.filter((e) => e.code === 1)) {
        delete event.phase;
        delete event.cancelReason;
      }
    if (mutation === "phase") delete actual.events.find((e) => e.event === "stream-status").phase;
    if (mutation === "missing")
      actual.events = actual.events.filter((e) => e.event !== "stream-status");
    if (mutation === "both-missing")
      for (const cell of [original, actual])
        cell.events = cell.events.filter((e) => e.event !== "stream-status");
    if (mutation === "code") actual.events.find((e) => e.event === "stream-status").code = 13;
    if (mutation === "unknown")
      actual.events.find((e) => e.event === "stream-status").code = "UNKNOWN";
    if (mutation === "details")
      actual.events.find((e) => e.event === "stream-status").details = "different";
    if (mutation === "cause")
      actual.events.find((e) => e.event === "stream-status").cancelReason = "window-end";
    const cell = compareExecutedObservation(f.source, f.local, f.witness, f.disposition).cells.find(
      (c) => c.id === "S03",
    );
    const expected =
      mutation === "none"
        ? "MATCH"
        : ["missing", "both-missing", "unknown"].includes(mutation)
          ? "NOT_COMPARABLE"
          : "DIVERGES";
    assert.equal(cell.approvedComparison.verdict, expected, mutation);
    assert.equal(cell.nativeSemantics.verdict, expected, mutation);
    assert.equal(actual.events.find((e) => e.n === 22).state.terminal, null);
  }
});

export function generatedTimeProof() {
  const bytes = Buffer.from(
    JSON.stringify({
      ownerRow: 1135,
      proposalSha256: "8238575c8202949f721b59bb9c97ee36b3f0ae701efd552f4169c70fcf0c1c53",
    }),
  );
  const request = { topic: "owned-topic", messages: [{ data: "bWFya2Vy" }] };
  const clockBody = { clock: "2026-10-09T01:17:41.899000000Z", backwardsSets: 0 };
  const clockBytes = Buffer.from(JSON.stringify(clockBody));
  return {
    authority: { bytes, sha256: createHash("sha256").update(bytes).digest("hex") },
    runtime: { binarySha256: "a".repeat(64), inputsSha256: "b".repeat(64) },
    compiledInputs: { binarySha256: "a".repeat(64), inputsSha256: "b".repeat(64) },
    publications: [
      {
        sourceDispatchN: 10,
        sourceRequest: request,
        localRequest: structuredClone(request),
        sourceReply: { ok: true, unknown: false, body: { messageIds: ["source"] } },
        localReply: { ok: true, unknown: false, body: { messageIds: ["local"] } },
        clock: {
          sourceDispatchN: 10,
          session: "default",
          instant: "2026-10-09T01:17:41.899Z",
          status: 200,
          body: clockBody,
          responseBytes: clockBytes.toString("base64"),
          responseSha256: createHash("sha256").update(clockBytes).digest("hex"),
        },
      },
    ],
    subscription: {
      opener: "owned-subscription",
      sourceRequest: { name: "owned-subscription" },
      localRequest: { name: "owned-subscription" },
      sourceReply: {
        ok: true,
        unknown: false,
        body: { name: "owned-subscription", topic: "owned-topic" },
      },
      localReply: {
        ok: true,
        unknown: false,
        body: { name: "owned-subscription", topic: "owned-topic" },
      },
    },
    deliveries: [],
  };
}

export function generatedTimeFixture() {
  const f = approvedNativeFixture(),
    proof = generatedTimeProof();
  for (const observation of [f.source, f.local]) {
    observation.cells = observation.cells.filter((c) => c.id !== "S03");
    observation.cells.find((c) => c.id === "S16").id = "S03";
  }
  f.witness.S03 = f.witness.S16;
  delete f.witness.S16;
  const source = f.source.cells.find((c) => c.id === "S03"),
    local = f.local.cells.find((c) => c.id === "S03");
  proof.publications[0].sourceReply.body.messageIds = ["source-1"];
  proof.publications[0].localReply.body.messageIds = ["actual-1"];
  proof.source = f.disposition.source;
  proof.cellId = "S03";
  f.disposition.publishTime = proof;
  f.witness.S03.publishTime = proof;
  const Type = protos.google.pubsub.v1.StreamingPullResponse;
  for (const [cell, timestamp, side] of [
    [source, { seconds: "1791508662", nanos: 21000000 }, "sourceBytes"],
    [local, { seconds: "1791508661", nanos: 899000000 }, "localBytes"],
  ]) {
    cell.frames[0].body.receivedMessages[0].message.publishTime = timestamp;
    const raw = Buffer.from(Type.encode(Type.fromObject(cell.frames[0].body)).finish());
    cell.frames[0].blob = {
      bytes: raw.length,
      sha256: createHash("sha256").update(raw).digest("hex"),
    };
    f.disposition.rawFrames[0][side] = raw;
  }
  return f;
}
test("generated publishTime raw projection admits only its induced scalar and ancestor lengths", async () => {
  const { compareExecutedObservation } = await import("./pubsub-observation/compare-core.mjs");
  const verdict = (f) =>
    compareExecutedObservation(f.source, f.local, f.witness, f.disposition).cells.find(
      (c) => c.id === "S03",
    ).approvedComparison.verdict;
  assert.equal(verdict(generatedTimeFixture()), "MATCH");
  for (const [alter, expected] of [
    [(f) => f.disposition.publishTime.publications.splice(0), "NOT_COMPARABLE"],
    [
      (f) => {
        const clock = f.disposition.publishTime.publications[0].clock;
        clock.body.clock = "2026-10-09T01:17:41.898Z";
        const bytes = Buffer.from(JSON.stringify(clock.body));
        clock.responseBytes = bytes.toString("base64");
        clock.responseSha256 = createHash("sha256").update(bytes).digest("hex");
      },
      "DIVERGES",
    ],
    [(f) => delete f.disposition.publishTime, "DIVERGES"],
  ]) {
    const f = generatedTimeFixture();
    alter(f);
    assert.equal(verdict(f), expected);
  }
  const Type = protos.google.pubsub.v1.StreamingPullResponse;
  for (const alter of [
    (body) => (body.receivedMessages[0].message.orderingKey = "other"),
    (body) => body.receivedMessages[0].message.publishTime.nanos++,
    (body) => delete body.receivedMessages[0].message.publishTime.seconds,
    (body) => (body.receivedMessages[0].deliveryAttempt = 1),
  ]) {
    const f = generatedTimeFixture(),
      frame = f.local.cells.find((c) => c.id === "S03").frames[0];
    alter(frame.body);
    const raw = Buffer.from(Type.encode(Type.fromObject(frame.body)).finish());
    frame.blob = { bytes: raw.length, sha256: createHash("sha256").update(raw).digest("hex") };
    f.disposition.rawFrames[0].localBytes = raw;
    assert.notEqual(verdict(f), "MATCH");
  }
});

test("generated timestamp projection preserves shortest widths, field layout and sibling bytes", async () => {
  const { compareExecutedObservation } = await import("./pubsub-observation/compare-core.mjs");
  const Response = protos.google.pubsub.v1.StreamingPullResponse,
    Timestamp = protos.google.protobuf.Timestamp;
  const encode = (Type, body) => Buffer.from(Type.encode(Type.fromObject(body)).finish());
  const frameOf = (f, side) => f[side].cells.find((c) => c.id === "S03").frames[0];
  const pin = (f, side, raw) => {
    const frame = frameOf(f, side);
    frame.body = Response.toObject(Response.decode(raw), {
      longs: String,
      enums: String,
      bytes: String,
      defaults: false,
    });
    frame.blob = { bytes: raw.length, sha256: createHash("sha256").update(raw).digest("hex") };
    f.disposition.rawFrames[0][`${side}Bytes`] = raw;
  };
  const projectedCell = (f) =>
    compareExecutedObservation(f.source, f.local, f.witness, f.disposition).cells.find(
      (c) => c.id === "S03",
    );
  for (const bytes of [105, 113, 120]) {
    const f = generatedTimeFixture(),
      data = Buffer.alloc(bytes, 0x61).toString("base64");
    for (const side of ["source", "local"]) {
      frameOf(f, side).body.receivedMessages[0].message.data = data;
      f.disposition.publishTime.publications[0][`${side}Request`].messages[0].data = data;
      pin(f, side, encode(Response, frameOf(f, side).body));
    }
    const cell = projectedCell(f);
    assert.equal(cell.approvedComparison.verdict, "MATCH");
    assert.equal(cell.approvedComparison.physicalVerdict, "DIVERGES");
    assert.equal(frameOf(f, "source").body.receivedMessages[0].message.publishTime.nanos, 21000000);
  }
  const length = (value) => {
    const bytes = [];
    do {
      bytes.push((value & 127) | (value > 127 ? 128 : 0));
      value = Math.floor(value / 128);
    } while (value);
    return Buffer.from(bytes);
  };
  const field = (tag, raw) => Buffer.concat([Buffer.from([tag]), length(raw.length), raw]);
  for (const alter of [
    (raw) => Buffer.concat([raw, Buffer.from([0x08, 1])]),
    (raw) => Buffer.concat([raw, Buffer.from([0x18, 1])]),
    (raw) => Buffer.concat([Buffer.from([0x0a, 1, 1]), raw.subarray(6)]),
    (raw) => Buffer.concat([Buffer.from([0x08, raw[1] | 128, 0]), raw.subarray(2)]),
    (raw) => Buffer.concat([raw.subarray(6), raw.subarray(0, 6)]),
  ]) {
    const f = generatedTimeFixture(),
      body = frameOf(f, "local").body;
    const item = body.receivedMessages[0],
      { publishTime, ...message } = item.message,
      { message: _message, ...received } = item;
    const timestamp = alter(encode(Timestamp, publishTime));
    const rawMessage = Buffer.concat([
      encode(protos.google.pubsub.v1.PubsubMessage, message),
      field(0x22, timestamp),
    ]);
    const rawReceived = Buffer.concat([
      encode(protos.google.pubsub.v1.ReceivedMessage, received),
      field(0x12, rawMessage),
    ]);
    const raw = Buffer.concat([
      field(0x0a, rawReceived),
      encode(Response, { subscriptionProperties: body.subscriptionProperties }),
    ]);
    try {
      pin(f, "local", raw);
    } catch {
      frameOf(f, "local").body = {};
      frameOf(f, "local").blob = {
        bytes: raw.length,
        sha256: createHash("sha256").update(raw).digest("hex"),
      };
      f.disposition.rawFrames[0].localBytes = raw;
    }
    assert.notEqual(projectedCell(f).approvedComparison.verdict, "MATCH");
  }
});

test("generated Timestamp raw scalars reject int32 aliases and retain signed int64 seconds", async () => {
  const { compareExecutedObservation } = await import("./pubsub-observation/compare-core.mjs");
  const Response = protos.google.pubsub.v1.StreamingPullResponse;
  const encode = (Type, body) => Buffer.from(Type.encode(Type.fromObject(body)).finish());
  const unsigned = (value) => {
    const bytes = [];
    do {
      bytes.push(Number(value & 127n) | (value > 127n ? 128 : 0));
      value >>= 7n;
    } while (value);
    return Buffer.from(bytes);
  };
  const field = (tag, body) =>
    Buffer.concat([Buffer.from([tag]), unsigned(BigInt(body.length)), body]);
  const frameOf = (f, side) => f[side].cells.find((c) => c.id === "S03").frames[0];
  const replaceRaw = (f, side, rawNanos) => {
    const frame = frameOf(f, side),
      item = frame.body.receivedMessages[0];
    const { publishTime, ...message } = item.message,
      { message: _message, ...received } = item;
    const timestamp = Buffer.concat([
      Buffer.from([8]),
      unsigned(BigInt.asUintN(64, BigInt(publishTime.seconds))),
      Buffer.from([16]),
      unsigned(rawNanos),
    ]);
    const rawMessage = Buffer.concat([
      encode(protos.google.pubsub.v1.PubsubMessage, message),
      field(0x22, timestamp),
    ]);
    const rawReceived = Buffer.concat([
      encode(protos.google.pubsub.v1.ReceivedMessage, received),
      field(0x12, rawMessage),
    ]);
    const raw = Buffer.concat([
      field(0x0a, rawReceived),
      encode(Response, { subscriptionProperties: frame.body.subscriptionProperties }),
    ]);
    const decoded = Response.toObject(Response.decode(raw), {
      longs: String,
      enums: String,
      bytes: String,
      defaults: false,
    });
    assert.deepEqual(decoded, frame.body);
    frame.blob = { bytes: raw.length, sha256: createHash("sha256").update(raw).digest("hex") };
    f.disposition.rawFrames[0][`${side}Bytes`] = raw;
  };
  const verdict = (f) =>
    compareExecutedObservation(f.source, f.local, f.witness, f.disposition).cells.find(
      (c) => c.id === "S03",
    ).approvedComparison.verdict;
  for (const side of ["source", "local"]) {
    for (const excess of [1n << 32n, 2n << 32n, 3n << 32n]) {
      const f = generatedTimeFixture(),
        nanos = frameOf(f, side).body.receivedMessages[0].message.publishTime.nanos;
      replaceRaw(f, side, BigInt(nanos) + excess);
      assert.notEqual(verdict(f), "MATCH", `${side} raw nanos alias`);
    }
  }
  for (const side of ["source", "local"])
    for (const seconds of ["-62135596800", "-1", "253402300799"]) {
      const f = generatedTimeFixture(),
        frame = frameOf(f, side);
      frame.body.receivedMessages[0].message.publishTime.seconds = seconds;
      if (side === "local") {
        const clock = f.disposition.publishTime.publications[0].clock;
        clock.instant = new Date(Number(seconds) * 1000).toISOString().replace(".000Z", ".899Z");
        clock.body.clock = clock.instant;
        const bytes = Buffer.from(JSON.stringify(clock.body));
        clock.responseBytes = bytes.toString("base64");
        clock.responseSha256 = createHash("sha256").update(bytes).digest("hex");
      }
      replaceRaw(f, side, BigInt(frame.body.receivedMessages[0].message.publishTime.nanos));
      assert.equal(verdict(f), "MATCH", `${side} signed seconds ${seconds}`);
    }
});

test("generated publishTime proof is bound to its cell and global source and runtime", async () => {
  const { compareExecutedObservation } = await import("./pubsub-observation/compare-core.mjs");
  for (const alter of [
    (f) => delete f.witness.S03.publishTime,
    (f) => delete f.witness.S03.publishTime.cellId,
    (f) => (f.witness.S03.publishTime.cellId = "S01"),
    ...["runId", "packetSha256", "descriptorSha256"].map(
      (field) => (f) => (f.witness.S03.publishTime.source[field] = "foreign"),
    ),
    ...["binarySha256", "inputsSha256"].map((field) => (f) => {
      f.witness.S03.publishTime.runtime[field] = "f".repeat(64);
      f.witness.S03.publishTime.compiledInputs[field] = "f".repeat(64);
    }),
  ]) {
    const f = generatedTimeFixture();
    f.witness.S03.publishTime = structuredClone(f.witness.S03.publishTime);
    f.witness.S03.publishTime.authority.bytes = Buffer.from(
      f.disposition.publishTime.authority.bytes,
    );
    assert.equal(
      compareExecutedObservation(f.source, f.local, f.witness, f.disposition).cells.find(
        (c) => c.id === "S03",
      ).approvedComparison.verdict,
      "MATCH",
    );
    alter(f);
    const cell = compareExecutedObservation(f.source, f.local, f.witness, f.disposition).cells.find(
      (c) => c.id === "S03",
    );
    assert.notEqual(cell.approvedComparison.verdict, "MATCH");
    assert.equal(cell.nativeLayout.verdict, "DIVERGES");
  }
});

test("two cells cannot exchange otherwise valid generated publishTime proofs", async () => {
  const { compareExecutedObservation } = await import("./pubsub-observation/compare-core.mjs");
  const f = generatedTimeFixture();
  for (const observation of [f.source, f.local]) {
    observation.cells = observation.cells.filter((c) => c.id === "S03");
    const second = structuredClone(observation.cells[0]);
    second.id = "S01";
    second.frames[0].n += 100;
    observation.cells.push(second);
  }
  const raw = f.disposition.rawFrames[0];
  f.disposition.rawFrames.push({ ...raw, sourceN: raw.sourceN + 100, localN: raw.localN + 100 });
  f.witness.S01 = structuredClone(f.witness.S03);
  f.witness.S01.publishTime.authority.bytes = Buffer.from(
    f.disposition.publishTime.authority.bytes,
  );
  f.witness.S01.publishTime.cellId = "S01";
  f.witness.S01.sourceFrames = f.source.cells
    .find((c) => c.id === "S01")
    .frames.map((frame) => frame.n);
  const verdicts = () =>
    compareExecutedObservation(f.source, f.local, f.witness, f.disposition)
      .cells.filter((c) => ["S03", "S01"].includes(c.id))
      .map((c) => c.approvedComparison.verdict);
  assert.deepEqual(verdicts(), ["MATCH", "MATCH"]);
  [f.witness.S03.publishTime, f.witness.S01.publishTime] = [
    f.witness.S01.publishTime,
    f.witness.S03.publishTime,
  ];
  assert.ok(verdicts().every((verdict) => verdict !== "MATCH"));
});

test("mixed generated-time runs retain strict timestamp-free negative cells", async () => {
  const { compareExecutedObservation } = await import("./pubsub-observation/compare-core.mjs");
  for (const [direction, body] of [
    ["out", { subscription: "owned-subscription", streamAckDeadlineSeconds: 10 }],
    ["in", { receivedMessages: [] }],
  ]) {
    const f = generatedTimeFixture(),
      negative = approvedNativeFixture();
    const Type =
      protos.google.pubsub.v1[
        direction === "out" ? "StreamingPullRequest" : "StreamingPullResponse"
      ];
    const bytes = Buffer.from(Type.encode(Type.fromObject(body)).finish());
    for (const observation of [f.source, f.local]) {
      const cell = structuredClone(negative.source.cells.find((c) => c.id === "S16"));
      cell.frames = [
        {
          n: 107,
          direction,
          verified: true,
          body: Type.toObject(Type.decode(bytes), {
            longs: String,
            enums: String,
            bytes: String,
            defaults: false,
          }),
          blob: { bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") },
        },
      ];
      cell.events[0].code = 3;
      cell.events[0].details = "invalid argument";
      observation.cells.push(cell);
    }
    f.witness.S16 = negative.witness.S16;
    f.witness.S16.sourceFrames = [107];
    f.disposition.rawFrames.push({
      sourceN: 107,
      localN: 107,
      sourceBytes: bytes,
      localBytes: bytes,
    });
    const compare = (disposition = f.disposition) =>
      compareExecutedObservation(f.source, f.local, f.witness, disposition);
    const strict = { ...f.disposition };
    delete strict.publishTime;
    assert.equal(
      compare(strict).cells.find((c) => c.id === "S16").approvedComparison.verdict,
      "MATCH",
    );
    assert.equal(compare().cells.find((c) => c.id === "S03").approvedComparison.verdict, "MATCH");
    assert.equal(compare().cells.find((c) => c.id === "S16").approvedComparison.verdict, "MATCH");
    const peer = f.local.cells.find((c) => c.id === "S16").frames[0];
    const changed = Buffer.from(
      Type.encode(
        Type.fromObject(
          direction === "out"
            ? { ...body, streamAckDeadlineSeconds: 11 }
            : { subscriptionProperties: { exactlyOnceDeliveryEnabled: true } },
        ),
      ).finish(),
    );
    const originalFrame = structuredClone(peer);
    peer.body = Type.toObject(Type.decode(changed), {
      longs: String,
      enums: String,
      bytes: String,
      defaults: false,
    });
    peer.blob = {
      bytes: changed.length,
      sha256: createHash("sha256").update(changed).digest("hex"),
    };
    f.disposition.rawFrames.at(-1).localBytes = changed;
    assert.equal(
      compare().cells.find((c) => c.id === "S16").approvedComparison.verdict,
      "DIVERGES",
    );
    Object.assign(peer, originalFrame);
    f.disposition.rawFrames.at(-1).localBytes = bytes;
    assert.equal(compare().cells.find((c) => c.id === "S16").approvedComparison.verdict, "MATCH");
    f.local.cells.find((c) => c.id === "S16").events[0].details = "different error details";
    assert.equal(
      compare().cells.find((c) => c.id === "S16").approvedComparison.verdict,
      "DIVERGES",
    );
    delete f.witness.S03.publishTime;
    assert.notEqual(
      compare().cells.find((c) => c.id === "S03").approvedComparison.verdict,
      "MATCH",
    );
  }
});
