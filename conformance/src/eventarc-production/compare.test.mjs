import assert from "node:assert/strict";
import test from "node:test";
import { compareCloudEventKeys } from "./compare.mjs";

test("CloudEvent keys compare as a set while their wire order remains unmodelled", () => {
  assert.deepEqual(
    compareCloudEventKeys(["id", "data", "traceparent"], ["data", "id", "traceparent"]),
    {
      verdict: "MATCH",
      order: "UNMODELLED",
      missing: [],
      extra: [],
    },
  );
  assert.deepEqual(compareCloudEventKeys(["id", "traceparent"], ["id"]), {
    verdict: "DIVERGES",
    order: "UNMODELLED",
    missing: ["traceparent"],
    extra: [],
  });
});
