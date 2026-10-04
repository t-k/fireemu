import assert from "node:assert/strict";
import test from "node:test";

import {
  HANDLERS,
  FRAME_MARKER,
  listRequest,
  logFilter,
  origin,
  parseEntries,
} from "./functions-events/record/logs.mjs";
import { destination } from "./functions-events/record/guard.mjs";

const entryFor = (name, over = {}, frame = {}) => {
  const handler = HANDLERS.find((h) => h.name === name);
  const o = origin(handler);
  return {
    logName: o.logName,
    resource: { type: o.resourceType, labels: o.labels },
    insertId: `ins-${name}`,
    timestamp: "2026-10-04T01:00:00.123456789Z",
    textPayload: `${FRAME_MARKER}${JSON.stringify({ handler: name, generation: handler.generation, source: handler.source, event: {}, ...frame })}`,
    ...over,
  };
};

test("the 22 handlers are the fixture's exports, one origin each", () => {
  assert.equal(HANDLERS.length, 22);
  assert.equal(new Set(HANDLERS.map((h) => h.name)).size, 22);
  assert.equal(HANDLERS.filter((h) => h.generation === 1).length, 11);
  assert.equal(origin(HANDLERS[1]).labels.service_name, "fscreatedv2");
  assert.equal(origin(HANDLERS[0]).labels.function_name, "fsCreatedV1");
});

test("the filter names every origin, the window and the marker; the request passes the guard", () => {
  const filter = logFilter({
    start: "2026-10-04T00:00:00.000000Z",
    end: "2026-10-04T01:00:00.000000Z",
  });
  for (const h of HANDLERS)
    assert.ok(
      filter.includes(
        h.generation === 1 ? `function_name="${h.name}"` : `service_name="${h.name.toLowerCase()}"`,
      ),
      h.name,
    );
  assert.ok(
    filter.includes('timestamp>="2026-10-04T00:00:00.000000Z"') &&
      filter.includes("FE_EVENTS_FRAME"),
  );
  const request = listRequest({ start: "a", end: "b" });
  assert.equal(
    destination({ method: request.method, url: request.url, mutation: request.mutation }).rule,
    "logging-list",
  );
  assert.deepEqual(request.body.resourceNames, ["projects/fireemu-oracle-events"]);
});

test("a frame line becomes a frame record; the same entry is not counted twice", () => {
  const seen = new Set();
  const body = { entries: [entryFor("fsCreatedV2"), entryFor("fsCreatedV2")] };
  const first = parseEntries(body, { readAt: "t1", seen });
  assert.equal(first.frames.length, 1);
  assert.equal(first.frames[0].handler, "fsCreatedV2");
  assert.equal(first.frames[0].source, "firestore");
  assert.equal(first.frames[0].readAt, "t1");
  assert.equal(parseEntries(body, { readAt: "t2", seen }).frames.length, 0);
});

test("a JSON payload message is read as a frame line", () => {
  const e = entryFor("authCreatedV1");
  const { textPayload, ...rest } = e;
  const parsed = parseEntries(
    { entries: [{ ...rest, jsonPayload: { message: textPayload } }] },
    { readAt: "t" },
  );
  assert.equal(parsed.frames.length, 1);
});

test("what cannot be used is counted and never thrown", () => {
  const parsed = parseEntries(
    {
      entries: [
        null,
        { textPayload: "hello" },
        entryFor("fsCreatedV1", { textPayload: `${FRAME_MARKER}{not json` }),
        entryFor("fsCreatedV1", {}, { handler: "nobody" }),
        entryFor("fsCreatedV1", {}, { generation: 2 }),
        entryFor("fsCreatedV1", { logName: "projects/other/logs/x" }),
        entryFor("fsCreatedV1", {
          resource: {
            type: "cloud_function",
            labels: { function_name: "other", region: "us-central1" },
          },
        }),
      ],
      nextPageToken: "next",
    },
    { readAt: "t" },
  );
  assert.equal(parsed.frames.length, 0);
  assert.deepEqual(parsed.ignored, {
    notTyped: 1,
    notFrame: 1,
    unparsed: 1,
    unknownHandler: 2,
    foreignOrigin: 2,
  });
  assert.equal(parsed.nextPageToken, "next");
  for (const bad of [undefined, null, 7, {}, { entries: "x" }])
    assert.equal(parseEntries(bad, { readAt: "t" }).frames.length, 0);
});

test("the frame is kept exactly as printed, including members the local runs do not have", () => {
  const extra = {
    event: { context: { eventId: "1" }, data: {} },
    contextKeys: ["eventId"],
    contextExtras: {},
  };
  const parsed = parseEntries({ entries: [entryFor("fsUpdatedV1", {}, extra)] }, { readAt: "t" });
  assert.deepEqual(parsed.frames[0].frame.contextKeys, ["eventId"]);
});
