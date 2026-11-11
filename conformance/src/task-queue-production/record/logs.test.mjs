// The log reads: the filters name only the run's services and a closed window, and the parsers keep only frames that came
// from the origin of the function they name, once each, and count everything else.
import "./isolation.mjs";
import assert from "node:assert/strict";
import test from "node:test";
import { FRAME_MARK, PROJECT, REGION, functionsOf } from "../plan.mjs";
import {
  errorFilter,
  frameFilter,
  frameOrigin,
  listRequest,
  parseErrors,
  parseFrames,
  parseFramesFromText,
} from "./logs.mjs";

const RUN = "0123456789abcdef";
const FNS = functionsOf(RUN);
const window = { start: "2026-11-12T00:00:00.000Z", end: "2026-11-12T00:05:00.000Z" };
const entry = (fn, frame, extra = {}) => {
  const o = frameOrigin(fn);
  return {
    insertId: extra.insertId ?? "i-" + Math.random(),
    timestamp: window.start,
    logName: o.logNames[0],
    resource: { type: o.resourceType, labels: o.labels },
    textPayload: FRAME_MARK + " " + JSON.stringify({ function: fn, kind: "start", ...frame }),
    ...extra,
  };
};

test("the filters name the run's eight services, the marker and the window", () => {
  const f = frameFilter(window, FNS);
  for (const fn of FNS) assert.ok(f.includes(`resource.labels.service_name="${fn}"`));
  assert.ok(f.includes(`resource.labels.location="${REGION}"`));
  assert.ok(f.includes(`timestamp>="${window.start}"`) && f.includes(`timestamp<="${window.end}"`));
  assert.ok(f.includes(FRAME_MARK));
  assert.ok(errorFilter(window, FNS).includes("severity>=ERROR"));
  assert.throws(() => frameFilter({ start: "yesterday", end: window.end }, FNS), /RFC 3339/);
  assert.throws(
    () => errorFilter({ start: window.start, end: "2026-11-12 00:05:00" }, FNS),
    /RFC 3339/,
  );
});

test("a list request is the recorder's POST to the project, oldest first, with an optional page token", () => {
  const r = listRequest({ id: "x", filter: "f", pageToken: "t" });
  assert.equal(r.method, "POST");
  assert.deepEqual(r.json.resourceNames, ["projects/" + PROJECT]);
  assert.equal(r.json.orderBy, "timestamp asc");
  assert.equal(r.json.pageToken, "t");
  assert.equal("pageToken" in listRequest({ id: "x", filter: "f" }).json, false);
});

test("a frame is kept once, from its own origin, and everything else is counted", () => {
  const fn = FNS[0];
  const seen = new Set();
  const good = entry(fn, { case: "a" }, { insertId: "1" });
  const entries = [
    good,
    { ...good }, // the same insertId again
    entry(fn, { case: "b" }, { insertId: "2", logName: "projects/p/logs/other" }),
    entry(
      fn,
      { case: "c" },
      {
        insertId: "3",
        resource: {
          type: "cloud_run_revision",
          labels: { service_name: FNS[1], location: REGION },
        },
      },
    ),
    entry(FNS[1], { function: "unknown000000" }, { insertId: "4" }),
    { insertId: "5", textPayload: "hello" },
    { insertId: "6", textPayload: FRAME_MARK + " {not json" },
    entry(fn, { kind: "other" }, { insertId: "7" }),
    null,
    "text",
  ];
  const { frames, ignored } = parseFrames(entries, FNS, seen);
  assert.deepEqual(
    frames.map((f) => f.frame.case),
    ["a"],
  );
  assert.deepEqual(ignored, { notFrame: 3, unparsed: 3, foreignOrigin: 2 });
  assert.equal(parseFrames([good], FNS, seen).frames.length, 0, "a later page repeats nothing");
  assert.deepEqual(parseFrames("nope", FNS).frames, []);
});

test("a frame from a jsonPayload message and one in the middle of a text are read; the end frame is a frame", () => {
  const fn = FNS[2];
  const o = frameOrigin(fn);
  const json = {
    insertId: "j",
    timestamp: window.start,
    logName: o.logNames[1],
    resource: { type: o.resourceType, labels: o.labels },
    jsonPayload: {
      message: "prefix " + FRAME_MARK + ' {"function":"' + fn + '","kind":"end","case":"x"}',
    },
  };
  const { frames } = parseFrames([json], FNS);
  assert.equal(frames[0].frame.kind, "end");
});

test("errors are reduced to the service, the time and 600 characters, once, for the run's services only", () => {
  const fn = FNS[0];
  const e = (id, service, text) => ({
    insertId: id,
    timestamp: window.start,
    resource: { labels: { service_name: service } },
    textPayload: text,
  });
  const out = parseErrors(
    [
      e("1", fn, "x".repeat(900)),
      e("1", fn, "again"),
      e("2", "other", "no"),
      null,
      e("3", fn, "y"),
    ],
    FNS,
  );
  assert.equal(out.length, 2);
  assert.equal(out[0].text.length, 600);
  assert.deepEqual(Object.keys(out[0]).toSorted(), ["function", "text", "timestamp"]);
});

test("the frames of fireemu's own output are the marked lines that parse", () => {
  const fn = FNS[0];
  const text = [
    "noise",
    FRAME_MARK +
      " " +
      JSON.stringify({ function: fn, kind: "start", at: "2026-11-12T00:00:01.000Z" }),
    FRAME_MARK + " {bad",
    FRAME_MARK + " " + JSON.stringify({ function: "other", kind: "start" }),
  ].join("\n");
  const { frames, ignored } = parseFramesFromText(text, FNS);
  assert.equal(frames.length, 1);
  assert.equal(frames[0].timestamp, "2026-11-12T00:00:01.000Z");
  assert.equal(ignored, 2);
});
