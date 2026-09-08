import assert from "node:assert/strict";
import { test } from "node:test";
import { probe } from "./oracle-probe.mjs";

test("successful probes compare document values and order", async () => {
  for (const actual of [[], ["a", "b"], ["b", "a", "c"]]) {
    const result = await probe("ordered", { outcome: "ok", value: ["b", "a"] }, async () => actual);
    assert.equal(result.outcomeMatches, true);
    assert.equal(result.valueMatches, false);
    assert.equal(result.matches, false);
  }
  assert.equal(
    (await probe("ordered", { outcome: "ok", value: ["b", "a"] }, async () => ["b", "a"])).matches,
    true,
  );
});

test("observation probes are explicitly separate from regression gates", async () => {
  const result = await probe("observed", null, async () => {
    throw Object.assign(new Error("unavailable"), { code: 13 });
  });
  assert.equal(result.mode, "observation");
  assert.equal(result.matches, null);
  assert.equal(result.outcome, "13");
});

test("error expectations cannot pass on successful responses", async () => {
  assert.equal((await probe("error", { outcome: "9" }, async () => [])).matches, false);
  assert.equal(
    (
      await probe("error", { outcome: "9" }, async () => {
        throw Object.assign(new Error("index"), { code: 9 });
      })
    ).matches,
    true,
  );
});
