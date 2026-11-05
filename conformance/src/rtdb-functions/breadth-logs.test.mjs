import { test } from "node:test";
import assert from "node:assert/strict";
import { origin, parseEntries, logFilter } from "./breadth-logs.mjs";
test("logs accept only T1 origins and deduplicate entries", () => {
  const handler = { name: "g9WrittenV2Retry", generation: 2 };
  const o = origin(handler);
  const entry = {
    insertId: "one",
    logName: o.logName,
    resource: { type: o.resourceType, labels: o.labels },
    textPayload: "G9_FRAME " + JSON.stringify({ handler: handler.name, generation: 2 }),
  };
  const result = parseEntries(
    { entries: [entry, entry, { ...entry, logName: "other" }] },
    { readAt: "now" },
  );
  assert.equal(result.frames.length, 1);
  assert.equal(result.ignored.foreignOrigin, 1);
  assert.match(logFilter({ start: "a", end: "b" }), /G9_FRAME/);
});
