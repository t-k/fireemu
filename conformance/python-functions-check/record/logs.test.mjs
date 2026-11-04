// The log filters and parsers: the filters name exactly the run's services and window, a frame counts only from the
// origin of the function it names, duplicates and junk are counted and never thrown on.
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
import { ALL_FUNCTIONS, FRAME_MARK, PROJECT } from "./plan.mjs";

const window = { start: "2026-11-05T00:00:00Z", end: "2026-11-05T00:05:00.250Z" };
const entry = (fn, frame, extra = {}) => ({
  insertId: "i-" + Math.random().toString(16).slice(2),
  timestamp: "2026-11-05T00:01:00Z",
  logName: frameOrigin(fn).logNames[0],
  resource: { type: "cloud_run_revision", labels: frameOrigin(fn).labels },
  textPayload: FRAME_MARK + " " + JSON.stringify({ function: fn, kind: "sdk-event", ...frame }),
  ...extra,
});

test("the frame filter names every service of the run, the region, the marker and the window, and nothing else", () => {
  const filter = frameFilter(window);
  for (const fn of ALL_FUNCTIONS)
    assert.ok(filter.includes(`resource.labels.service_name="${fn}"`));
  assert.equal(filter.match(/service_name=/g).length, ALL_FUNCTIONS.length);
  assert.ok(filter.includes(`resource.labels.location="us-central1"`));
  assert.ok(
    filter.includes(`timestamp>="${window.start}"`) &&
      filter.includes(`timestamp<="${window.end}"`),
  );
  assert.ok(filter.includes(FRAME_MARK));
  assert.ok(errorFilter(window).includes("severity>=ERROR"));
});

test("a window must be an RFC 3339 UTC time", () => {
  for (const bad of [
    "yesterday",
    "2026-11-05 00:00:00",
    '2026-11-05T00:00:00Z" OR 1=1',
    "",
    undefined,
    "2026-11-05T00:00:00+09:00",
  ])
    assert.throws(() => frameFilter({ start: bad, end: window.end }), /RFC 3339/);
  assert.throws(() => errorFilter({ start: window.start, end: "x" }), /RFC 3339/);
});

test("the list request reads only this project, oldest first, at most 200 entries, with the page token when given", () => {
  const request = listRequest({ id: "x", filter: "f", pageToken: "p" });
  assert.deepEqual(request.json, {
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
  const good = entry("pcps", { run: "pcrun-1" });
  const first = parseFrames([good, good], seen);
  assert.equal(first.frames.length, 1);
  assert.equal(parseFrames([good], seen).frames.length, 0, "seen again in a later page");
  assert.equal(first.frames[0].frame.function, "pcps");
});

test("what is not a usable frame is counted by reason and never thrown on", () => {
  const spoof = entry(
    "pcps",
    {},
    {
      resource: {
        type: "cloud_run_revision",
        labels: { service_name: "other", location: "us-central1" },
      },
    },
  );
  const wrongLog = entry(
    "pcps",
    {},
    { logName: `projects/${PROJECT}/logs/run.googleapis.com%2Frequests` },
  );
  const wrongType = entry(
    "pcps",
    {},
    { resource: { type: "cloud_function", labels: frameOrigin("pcps").labels } },
  );
  const notFrame = { insertId: "n", textPayload: "hello" };
  const unparsed = { insertId: "u", textPayload: FRAME_MARK + " {not json" };
  const unknownFn = entry(
    "pcps",
    {},
    { textPayload: FRAME_MARK + ' {"function":"other","kind":"x"}' },
  );
  const noKind = entry("pcps", {}, { textPayload: FRAME_MARK + ' {"function":"pcps"}' });
  const jsonPayload = entry(
    "pcps",
    {},
    {
      textPayload: undefined,
      jsonPayload: { message: FRAME_MARK + ' {"function":"pcps","kind":"sdk-event"}' },
    },
  );
  const { frames, ignored } = parseFrames(
    [
      spoof,
      wrongLog,
      wrongType,
      notFrame,
      unparsed,
      unknownFn,
      noKind,
      jsonPayload,
      null,
      5,
      "x",
      {},
    ],
    new Set(),
  );
  assert.equal(frames.length, 1, "only the jsonPayload one is good");
  assert.deepEqual(Object.keys(ignored), IGNORED);
  assert.equal(ignored.foreignOrigin, 3);
  assert.equal(ignored.unparsed, 3);
  assert.equal(ignored.notFrame, 5, "the plain line and the four non-objects");
  assert.equal(parseFrames("nope", new Set()).frames.length, 0);
});

test("errors are reduced to the service, the time and 600 characters, and only the run's services count", () => {
  const long = "x".repeat(2000);
  const errors = parseErrors(
    [
      {
        insertId: "a",
        timestamp: "t",
        resource: { labels: { service_name: "pcps" } },
        textPayload: long,
      },
      { insertId: "b", resource: { labels: { service_name: "other" } }, textPayload: "no" },
      { insertId: "c", resource: { labels: { service_name: "pcst" } }, jsonPayload: { a: 1 } },
      { insertId: "a", resource: { labels: { service_name: "pcps" } }, textPayload: "dup" },
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
    "[functions:pycheck] " + FRAME_MARK + ' {"function":"pcps","kind":"sdk-event","at":"t1"}',
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
    '"pcps"',
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
