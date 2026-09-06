import assert from "node:assert/strict";
import test from "node:test";

import { programExpectation } from "./rules-probe/program-expectations.mjs";

const oracle = { steps: { read: { status: 200, code: "OK", shape: "document" } } };
const row = (overrides = {}) => ({ id: "budget-get-10", area: "budget", oracle, ...overrides });

test("a recorded program without a divergence gates on its oracle", () => {
  const expectation = programExpectation(row());
  assert.equal(expectation.isOk(), true);
  assert.deepEqual(expectation.value, { expected: oracle, diverged: false });
});

test("a recorded program divergence without a canonical authority is refused", () => {
  const injected = row({
    divergence: {
      fireemu: { steps: { read: { status: 403, code: "PERMISSION_DENIED" } } },
      reason: "injected by editing rules-programs.json",
    },
  });
  const expectation = programExpectation(injected);
  assert.equal(expectation.isErr(), true);
  assert.match(expectation.error, /budget-get-10/);
  assert.match(expectation.error, /no canonical divergence authority/);
});

test("a divergence that is not an object is refused rather than ignored", () => {
  for (const divergence of [true, "pinned", 1, []]) {
    const expectation = programExpectation(row({ divergence }));
    assert.equal(expectation.isErr(), true, `expected ${JSON.stringify(divergence)} refused`);
  }
});
