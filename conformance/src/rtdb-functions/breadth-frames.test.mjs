import { test } from "node:test";
import assert from "node:assert/strict";
import { FIXTURE_HANDLERS, FRAME_MARKER, PREFIX, RECORDED_MEMBERS } from "./breadth-frames.mjs";
test("T1 frame metadata keeps only recorded write members", () => {
  assert.equal(FRAME_MARKER, "G9_FRAME ");
  assert.equal(PREFIX, "g9-rtdb");
  assert.equal(FIXTURE_HANDLERS.length, 3);
  assert.equal(RECORDED_MEMBERS.length, 4);
  assert.ok(RECORDED_MEMBERS.every((entry) => entry.event === "write"));
});
