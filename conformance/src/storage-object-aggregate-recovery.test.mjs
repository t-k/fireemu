// When a recipe throws, the aggregate ends only that recipe if nothing it owns is pending and the
// wire saw no transport failure and no throttled answer; otherwise the run stops as before. These
// tests drive `recoverFailedRecipe` with a stub sender and wire, one condition at a time.

import assert from "node:assert/strict";
import test from "node:test";
import { recoverFailedRecipe, wireTroubleSince } from "./storage-object/aggregate-replay.mjs";

const RECIPE = "storage-object/gcs/copy-rewrite";

function stubs(overrides = {}) {
  const calls = [];
  let mode = overrides.mode ?? "subject";
  const state = { halted: false, transportFailures: 0, throttled: 0, ...overrides.wire };
  const sender = {
    snapshot: () => ({ mode, total: overrides.total ?? 42 }),
    beginCleanup: () => {
      calls.push("beginCleanup");
      mode = "cleanup";
    },
    cleanupConfirmedOwned: async (options) => {
      calls.push("cleanupConfirmedOwned");
      assert.equal(typeof options.canSend, "function");
      if (overrides.cleanupThrows) throw new Error("cleanup exploded");
      return { cleanedNames: [], cleanupFailures: [], unresolved: [], ...overrides.cleanup };
    },
    verifyRunEmpty: async () => {
      calls.push("verifyRunEmpty");
      if (overrides.verifyThrows) throw new Error("prefix not empty");
      if (overrides.troubleAfterVerify) state.throttled++;
    },
    close: () => {
      calls.push("close");
      mode = "closed";
    },
    unresolved: () => overrides.unresolved ?? [],
  };
  const wire = { snapshot: () => ({ ...state }) };
  return { sender, wire, calls, state };
}

const recover = (s, extra = {}) =>
  recoverFailedRecipe({
    sender: s.sender,
    recipeId: RECIPE,
    error: new Error("rewrite answer differs\nsecond line"),
    wire: s.wire,
    wireReady: () => true,
    before: { transportFailures: 0, throttled: 0 },
    ...extra,
  });

test("a failed recipe with nothing pending is cleaned, proven empty, closed, and reported as blocked", async () => {
  const s = stubs();
  const result = await recover(s);
  assert.deepEqual(s.calls, ["beginCleanup", "cleanupConfirmedOwned", "verifyRunEmpty", "close"]);
  assert.deepEqual(result, {
    recipeId: RECIPE,
    status: "LOCAL_BLOCKED",
    requests: 42,
    failure: { reason: "rewrite answer differs" },
    cleanupFailures: [],
    unresolved: [],
  });
});

test("a sender already in its cleanup phase is not begun again", async () => {
  const s = stubs({ mode: "cleanup" });
  assert.ok(await recover(s));
  assert.deepEqual(s.calls, ["cleanupConfirmedOwned", "verifyRunEmpty", "close"]);
});

test("a sender that has already closed is left as it is, and the result stands", async () => {
  const s = stubs({ mode: "closed" });
  const result = await recover(s);
  assert.deepEqual(s.calls, []);
  assert.equal(result.status, "LOCAL_BLOCKED");
});

test("the reason is the first line of the error, at most 200 characters", async () => {
  const s = stubs();
  const result = await recover(s, { error: new Error(`${"y".repeat(300)}\nnext`) });
  assert.equal(result.failure.reason, "y".repeat(200));
  const t = stubs();
  assert.equal((await recover(t, { error: "a plain string\nx" })).failure.reason, "a plain string");
});

test("nothing is decided without a sender, or when the wire is not ready", async () => {
  const s = stubs();
  assert.equal(await recover(s, { sender: undefined }), null);
  assert.equal(await recover(s, { wireReady: () => false }), null);
  assert.deepEqual(s.calls, [], "no request is made");
});

test("a halted wire, a failed transport or a throttled answer during the recipe ends the run", async () => {
  for (const wire of [{ halted: true }, { transportFailures: 1 }, { throttled: 1 }]) {
    const s = stubs({ wire });
    assert.equal(await recover(s), null, JSON.stringify(wire));
    assert.deepEqual(s.calls, [], "and no cleanup request is made");
  }
});

test("trouble that predates the recipe does not count against it", async () => {
  const s = stubs({ wire: { transportFailures: 2, throttled: 3 } });
  const result = await recover(s, { before: { transportFailures: 2, throttled: 3 } });
  assert.equal(result.status, "LOCAL_BLOCKED");
});

test("a cleanup that fails, or leaves anything unresolved, ends the run", async () => {
  for (const cleanup of [
    { cleanupFailures: [{ name: "x" }] },
    { unresolved: ["x"] },
    { cleanupFailures: [{ name: "x" }], unresolved: ["x"] },
  ]) {
    const s = stubs({ cleanup });
    assert.equal(await recover(s), null, JSON.stringify(cleanup));
    assert.equal(s.calls.includes("verifyRunEmpty"), false);
  }
});

test("an exception in cleanup, or a prefix that does not read back empty, ends the run", async () => {
  assert.equal(await recover(stubs({ cleanupThrows: true })), null);
  const s = stubs({ verifyThrows: true });
  assert.equal(await recover(s), null);
  assert.equal(s.calls.includes("close"), false);
});

test("anything the sender still holds after cleanup ends the run", async () => {
  assert.equal(await recover(stubs({ unresolved: ["owned"] })), null);
});

test("trouble that shows up during the recovery itself ends the run", async () => {
  assert.equal(await recover(stubs({ troubleAfterVerify: true })), null);
});

test("the wire trouble check reads each count against its own start, and a missing count is zero", () => {
  const wire = (state) => ({ snapshot: () => state });
  assert.equal(wireTroubleSince(wire({}), {}), false);
  assert.equal(wireTroubleSince(wire({ halted: true }), {}), true);
  assert.equal(wireTroubleSince(wire({ transportFailures: 1 }), {}), true);
  assert.equal(wireTroubleSince(wire({ throttled: 1 }), {}), true);
  assert.equal(wireTroubleSince(wire({ transportFailures: 1 }), { transportFailures: 1 }), false);
  assert.equal(wireTroubleSince(wire({ throttled: 2 }), { throttled: 2 }), false);
  assert.equal(
    wireTroubleSince(wire({ transportFailures: 0, throttled: 0 }), { throttled: 1 }),
    false,
  );
});
