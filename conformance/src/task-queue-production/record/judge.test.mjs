// What the judge reports: deliveries joined to the case that asked for them, times from the send, and the findings that a
// reader of the recording must not miss.
import "./isolation.mjs";
import assert from "node:assert/strict";
import test from "node:test";
import { runMarker } from "../plan.mjs";
import { deliveriesOf, judge, maskNumber } from "./judge.mjs";

const RUN = "0123456789abcdef";
const marker = runMarker(RUN);
const T0 = Date.parse("2026-11-12T00:00:00.000Z");
const at = (ms) => new Date(T0 + ms).toISOString();
const start = (key, ms, retryCount = 0, extra = {}) => ({
  insertId: `s-${key}-${retryCount}-${ms}`,
  timestamp: at(ms),
  frame: {
    kind: "start",
    function: "tqdef012345",
    run: marker,
    case: key,
    at: at(ms),
    context: { retryCount },
    ...extra,
  },
});
const end = (key, startMs, endMs, retryCount = 0) => ({
  insertId: `e-${key}-${retryCount}`,
  timestamp: at(endMs),
  frame: {
    kind: "end",
    function: "tqdef012345",
    run: marker,
    case: key,
    at: at(endMs),
    startedAt: at(startMs),
    retryCount,
  },
});
const created = (ms, status = 200, extra = {}) => ({
  kind: "create",
  sent: true,
  class: status >= 200 && status < 300 ? "2xx" : "4xx",
  status,
  dispatchedAt: T0 + ms,
  ...extra,
});

test("deliveries are joined to their case with the times from the send, and an end frame is paired by start time and retry", () => {
  const program = { "env-default": created(1000), "retry-ladder": created(2000) };
  const frames = [
    start("env-default", 1500),
    end("env-default", 1500, 1600),
    start("retry-ladder", 2600, 1),
    end("retry-ladder", 2600, 2700, 1),
    start("retry-ladder", 2500, 0),
    end("retry-ladder", 2500, 2550, 0),
  ];
  const out = judge({ runId: RUN, program, frames });
  assert.deepEqual(out.findings, []);
  assert.equal(out.observationComplete, true);
  const ladder = out.cases["retry-ladder"].deliveries;
  assert.deepEqual(
    ladder.map((d) => [d.retryCount, d.startMs, d.endMs]),
    [
      [0, 500, 550],
      [1, 600, 700],
    ],
  );
  assert.deepEqual(out.totals, { cases: 2, sent: 2, deliveries: 3, errorEntries: 0 });
});

test("a retry's end frame is not taken for another attempt's, and a missing end is a null", () => {
  const frames = [start("a", 100, 0), start("a", 200, 1), end("a", 200, 260, 1)];
  const [first, second] = deliveriesOf(frames);
  assert.equal(first.endedAt, null);
  assert.equal(second.endedAt, at(260));
  assert.deepEqual(deliveriesOf([]), []);
});

test("an accepted task that never arrived is a finding, unless its case is one that is not delivered", () => {
  const program = { "env-default": created(0), "sch-31d": created(0), "sch-30d-less": created(0) };
  const out = judge({ runId: RUN, program, frames: [] });
  assert.deepEqual(out.findings, [{ kind: "not-delivered", case: "env-default" }].concat([]));
  assert.equal(out.observationComplete, false);
});

test("a delivery of a task whose create was refused or unknown is a finding of its own kind", () => {
  const program = {
    refused: created(0, 400),
    unknown: { kind: "create", sent: true, class: "unknown-status", status: 503, dispatchedAt: T0 },
  };
  const out = judge({
    runId: RUN,
    program,
    frames: [start("refused", 100), start("unknown", 100)],
  });
  assert.deepEqual(
    out.findings.map((f) => [f.kind, f.case]),
    [
      ["delivered-without-accepted-create", "refused"],
      ["delivered-without-accepted-create", "unknown"],
      ["create-not-answered", "unknown"],
    ],
  );
});

test("a frame of another run, or for a case the program does not have, is reported and never joined", () => {
  const program = { a: created(0) };
  const foreign = start("a", 100);
  foreign.frame.run = "tqrun-fedcba9876543210";
  const stray = start("zzz", 100);
  const out = judge({ runId: RUN, program, frames: [foreign, stray, start("a", 100)] });
  assert.deepEqual(
    out.findings.map((f) => f.kind),
    ["foreign-frame", "frame-for-unknown-case"],
  );
  assert.equal(out.cases.a.deliveries.length, 1);
});

test("a case that was not sent has no deliveries and no finding, and an answer keeps its masked project number", () => {
  const program = {
    skipped: { kind: "create", sent: false, why: "x" },
    "get-queue": {
      kind: "get-queue",
      sent: true,
      class: "2xx",
      status: 200,
      answer: { json: { email: "123456789012-compute@x" } },
    },
    "env-named": created(0, 200, { answer: { json: { sa: "555666777888-compute@developer" } } }),
  };
  const out = judge({
    runId: RUN,
    program,
    frames: [start("env-named", 10)],
    projectNumber: "555666777888",
  });
  assert.deepEqual(out.findings, []);
  assert.equal(out.cases.skipped.sent, false);
  assert.equal(out.cases["env-named"].answer.json.sa, "123456789012-compute@developer");
  assert.equal(
    maskNumber("a 555666777888 b 555666777888", "555666777888"),
    "a 123456789012 b 123456789012",
  );
  assert.equal(maskNumber("none", null), "none");
});

// ---- properties -------------------------------------------------------------------------------------------------

function* random(seed) {
  let x = seed >>> 0 || 1;
  while (true) {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    yield x;
  }
}

test("property: the deliveries of a case are its start frames sorted by time, whatever order the log returns them in", () => {
  const gen = random(11);
  for (let round = 0; round < 60; round++) {
    const cases = ["a", "b", "c"];
    const program = Object.fromEntries(cases.map((k, i) => [k, created(i * 100)]));
    const frames = [];
    const expected = Object.fromEntries(cases.map((k) => [k, []]));
    for (let n = 0; n < 12; n++) {
      const key = cases[gen.next().value % 3];
      const ms = 1000 + (gen.next().value % 5000) + n * 7000;
      frames.push(start(key, ms, expected[key].length));
      expected[key].push(ms);
      if (gen.next().value % 2) frames.push(end(key, ms, ms + 50, expected[key].length - 1));
    }
    const shuffled = frames.toSorted(() => (gen.next().value % 3) - 1);
    const out = judge({ runId: RUN, program, frames: shuffled });
    for (const key of cases) {
      const times = out.cases[key].deliveries.map((d) => d.startedAt);
      assert.deepEqual(times, times.toSorted(), "sorted");
      assert.deepEqual(
        out.cases[key].deliveries.map((d) => Date.parse(d.startedAt)).toSorted((x, y) => x - y),
        expected[key].map((ms) => T0 + ms).toSorted((x, y) => x - y),
      );
      for (const d of out.cases[key].deliveries)
        assert.equal(d.startMs, Date.parse(d.startedAt) - program[key].dispatchedAt);
    }
    // A frame of another run, added anywhere, changes no case.
    const foreign = start("a", 123);
    foreign.frame.run = "tqrun-fedcba9876543210";
    const again = judge({ runId: RUN, program, frames: [foreign, ...shuffled] });
    assert.deepEqual(again.cases, out.cases);
    assert.equal(again.findings.length, out.findings.length + 1);
  }
});

test("two attempts that start in the same millisecond keep their own ends", () => {
  const frames = [
    start("a", 100, 0),
    start("a", 100, 1),
    end("a", 100, 150, 1),
    end("a", 100, 120, 0),
  ];
  const [first, second] = deliveriesOf(frames);
  const byRetry = Object.fromEntries([first, second].map((d) => [d.retryCount, d.endedAt]));
  assert.deepEqual(byRetry, { 0: at(120), 1: at(150) });
});

test("the server's createTime is a second origin for the times, and is null when the answer has none", () => {
  const program = {
    a: created(1000, 200, { answer: { json: { createTime: at(900) } } }),
    b: created(1000),
    c: created(1000, 200, { answer: { json: { createTime: "not a time" } } }),
  };
  const out = judge({
    runId: RUN,
    program,
    frames: [start("a", 1500), start("b", 1500), start("c", 1500)],
  });
  assert.equal(out.cases.a.serverCreateMs, T0 + 900);
  assert.equal(out.cases.a.deliveries[0].startFromCreateMs, 600);
  assert.equal(out.cases.a.deliveries[0].startMs, 500);
  assert.equal(out.cases.b.serverCreateMs, null);
  assert.equal(out.cases.b.deliveries[0].startFromCreateMs, null);
  assert.equal(out.cases.c.deliveries[0].startFromCreateMs, null);
});

test("an end frame is paired with the start that has its start time, not with any start of the same retry count", () => {
  const frames = [
    start("a", 100, 0),
    start("a", 200, 0),
    end("a", 200, 260, 0),
    end("a", 100, 130, 0),
  ];
  const [first, second] = deliveriesOf(frames);
  assert.equal(first.endedAt, at(130));
  assert.equal(second.endedAt, at(260));
});

test("a case that was not sent has no deliveries at all, not an empty list", () => {
  const out = judge({
    runId: RUN,
    program: { skipped: { kind: "create", sent: false, why: "x" } },
    frames: [],
  });
  assert.equal("deliveries" in out.cases.skipped, false);
  assert.deepEqual(out.findings, []);
});
