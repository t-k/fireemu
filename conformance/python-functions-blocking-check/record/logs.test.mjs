// The log filters and parsers: the filters name exactly the function and the window, a frame counts only from the origin of the
// function it names, duplicates and junk are counted and never thrown on.
import assert from "node:assert/strict";
import test from "node:test";
import {
  IGNORED,
  errorFilter,
  frameFilter,
  frameOrigin,
  listRequest,
  parseErrors,
  parseFrames,
  parseFramesFromText,
} from "./logs.mjs";
import { FRAME_MARK, PROJECT } from "./plan.mjs";

const window = { start: "2026-11-05T00:00:00Z", end: "2026-11-05T00:05:00.250Z" };
const entry = (frame, extra = {}) => ({
  insertId: "i-" + Math.random().toString(16).slice(2),
  timestamp: "2026-11-05T00:01:00Z",
  logName: frameOrigin("pcblock").logNames[0],
  resource: { type: "cloud_run_revision", labels: frameOrigin("pcblock").labels },
  textPayload:
    FRAME_MARK + " " + JSON.stringify({ function: "pcblock", kind: "blocking-raw", ...frame }),
  ...extra,
});

test("the frame filter names the one service, the region, the marker and the window", () => {
  const filter = frameFilter(window);
  assert.equal(filter.match(/service_name=/g).length, 1);
  assert.ok(
    filter.includes('resource.labels.service_name="pcblock"') &&
      filter.includes('resource.labels.location="us-central1"'),
  );
  assert.ok(
    filter.includes(`timestamp>="${window.start}"`) &&
      filter.includes(`timestamp<="${window.end}"`),
  );
  assert.ok(filter.includes(FRAME_MARK));
  const errors = errorFilter(window);
  assert.ok(
    errors.includes("severity>=ERROR") &&
      errors.includes(`timestamp>="${window.start}"`) &&
      errors.includes(`timestamp<="${window.end}"`),
  );
});

test("a window time may carry one to nine fraction digits and must be RFC 3339 UTC", () => {
  const at = (start) => () => frameFilter({ start, end: window.end });
  assert.doesNotThrow(at("2026-11-05T00:00:00.1Z"));
  assert.doesNotThrow(at("2026-11-05T00:00:00.123456789Z"));
  for (const bad of [
    "yesterday",
    "2026-11-05 00:00:00",
    '2026-11-05T00:00:00Z" OR 1=1',
    "",
    undefined,
    "2026-11-05T00:00:00+09:00",
    "2026-11-05T00:00:00.1234567890Z",
    "2026-11-05T00:00:00.Z",
  ])
    assert.throws(at(bad), /RFC 3339/);
  assert.throws(() => errorFilter({ start: window.start, end: "x" }), /RFC 3339/);
});

test("the list request reads only this project, oldest first, at most 200 entries", () => {
  assert.deepEqual(listRequest({ id: "x", filter: "f", pageToken: "p" }).json, {
    resourceNames: [`projects/${PROJECT}`],
    filter: "f",
    orderBy: "timestamp asc",
    pageSize: 200,
    pageToken: "p",
  });
  assert.equal("pageToken" in listRequest({ id: "x", filter: "f" }).json, false);
});

test("a frame is kept from the origin of the function it names, deduplicated by insertId", () => {
  const seen = new Set();
  const good = entry({ uid: "u" });
  assert.equal(parseFrames([good, good], seen).frames.length, 1);
  assert.equal(parseFrames([good], seen).frames.length, 0);
});

test("what is not a usable frame is counted by reason and never thrown on", () => {
  const spoof = entry(
    {},
    {
      resource: {
        type: "cloud_run_revision",
        labels: { service_name: "other", location: "us-central1" },
      },
    },
  );
  const wrongLog = entry({}, { logName: `projects/${PROJECT}/logs/run.googleapis.com%2Frequests` });
  const notFrame = { insertId: "n", textPayload: "hello" };
  const unparsed = { insertId: "u", textPayload: FRAME_MARK + " {not json" };
  const unknownFn = entry({}, { textPayload: FRAME_MARK + ' {"function":"other","kind":"x"}' });
  const noKind = entry({}, { textPayload: FRAME_MARK + ' {"function":"pcblock"}' });
  const jsonPayload = entry(
    {},
    {
      textPayload: undefined,
      jsonPayload: { message: FRAME_MARK + ' {"function":"pcblock","kind":"blocking-sdk"}' },
    },
  );
  const { frames, ignored } = parseFrames(
    [spoof, wrongLog, notFrame, unparsed, unknownFn, noKind, jsonPayload, null, 5, "x", {}],
    new Set(),
  );
  assert.equal(frames.length, 1);
  assert.deepEqual(Object.keys(ignored), IGNORED);
  assert.equal(ignored.foreignOrigin, 2);
  assert.equal(ignored.unparsed, 3);
  assert.equal(ignored.notFrame, 5);
  assert.equal(parseFrames("nope", new Set()).frames.length, 0);
});

test("errors are reduced to the service, the time and 600 characters, and only this function's count", () => {
  const errors = parseErrors(
    [
      {
        insertId: "a",
        timestamp: "t",
        resource: { labels: { service_name: "pcblock" } },
        textPayload: "x".repeat(2000),
      },
      { insertId: "b", resource: { labels: { service_name: "other" } }, textPayload: "no" },
      { insertId: "c", resource: { labels: { service_name: "pcblock" } }, jsonPayload: { a: 1 } },
      { insertId: "a", resource: { labels: { service_name: "pcblock" } }, textPayload: "dup" },
      null,
    ],
    new Set(),
  );
  assert.equal(errors.length, 2);
  assert.equal(errors[0].text.length, 600);
  assert.equal(errors[1].text, '{"a":1}');
});

test("frames in fireemu's own output are read line by line, with the junk counted", () => {
  const text = [
    "[functions:pcblock] " + FRAME_MARK + ' {"function":"pcblock","kind":"blocking-sdk","at":"t1"}',
    "some other line",
    FRAME_MARK + " {broken",
    FRAME_MARK + ' {"function":"nope","kind":"x"}',
  ].join("\n");
  const { frames, ignored } = parseFramesFromText(text);
  assert.equal(frames.length, 1);
  assert.equal(frames[0].timestamp, "t1");
  assert.equal(ignored, 2);
});

test("random junk never throws", () => {
  let seed = 3;
  const next = () => (seed = (seed * 1664525 + 1013904223) % 4294967296) / 4294967296;
  const pieces = [
    FRAME_MARK,
    " ",
    "{",
    "}",
    '"function"',
    ":",
    '"pcblock"',
    ",",
    '"kind"',
    '"x"',
    "null",
    "[",
    "\u0000",
    "\n",
  ];
  for (let i = 0; i < 300; i++) {
    let text = "";
    for (let j = 0; j < 12; j++) text += pieces[Math.floor(next() * pieces.length)];
    parseFramesFromText(text);
    parseFrames(
      [
        { insertId: String(i), textPayload: text },
        { textPayload: text, resource: 3 },
      ],
      new Set(),
    );
    parseErrors([{ textPayload: text }, { resource: { labels: null } }], new Set());
  }
});
