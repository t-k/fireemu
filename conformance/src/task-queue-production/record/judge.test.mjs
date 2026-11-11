// What the judge reports: deliveries joined to the case that asked for them, times from the send, and the findings that a
// reader of the recording must not miss.
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
