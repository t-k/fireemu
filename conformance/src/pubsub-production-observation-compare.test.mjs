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
    const proof = {
      completed: false,
      sourceFrames: [3],
      actions: [{ sourceN: 8, event: "stream-case-observation", elapsedMs: 120 }],
      zeroOutcome: {
        state: structuredClone(
          cell.events.find((e) => e.event === "stream-case-observation").state,
        ),
        observedElapsedMs: 120,
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
      (_s, l, _p) => (l.cells[0].events.find((e) => e.event === "stream-dispatch").n = 99),
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
