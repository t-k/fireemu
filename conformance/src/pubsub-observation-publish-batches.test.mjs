import test from "node:test";
import assert from "node:assert/strict";
import { makePlan } from "./pubsub-observation/plan.mjs";
import { createMeter } from "./pubsub-observation/meter.mjs";
import { createLedger } from "./pubsub-production/ledger.mjs";
import { runCell } from "./pubsub-observation/scenarios.mjs";
async function world(id, failure) {
  const plan = makePlan("closure-mandatory-gap"),
    cell = plan.cells.find((c) => c.id === id),
    meter = createMeter({ now: () => 0, plan });
  meter.enter(cell);
  const calls = [],
    rows = [],
    resources = new Map(),
    published = [];
  let batch = 0;
  const wire = {
    async call(c) {
      meter.start(c.category, c.transport);
      calls.push(structuredClone(c));
      const q = c.request;
      let body = {};
      if (c.method.startsWith("Create")) {
        resources.set(q.name, q);
        body = q;
      } else if (c.method.startsWith("Get")) {
        if (!resources.has(q.name))
          return {
            ok: false,
            unknown: false,
            status: 404,
            code: "NOT_FOUND",
            body: { error: { status: "NOT_FOUND" } },
          };
        body = resources.get(q.name);
      } else if (c.method.startsWith("Delete")) resources.delete(q.name);
      else if (c.method === "Publish") {
        const current = batch++;
        const ids = q.messages.map((m, i) => `id-${current}-${i}`);
        q.messages.forEach((message, i) => published.push({ message, messageId: ids[i] }));
        if (failure === "error")
          return { ok: false, unknown: false, status: 400, code: "INVALID_ARGUMENT", body: {} };
        body = {
          messageIds:
            failure === "missing"
              ? undefined
              : failure === "short"
                ? ids.slice(1)
                : failure === "numeric"
                  ? ids.map((_, i) => current * 10 + i + 1)
                  : failure === "empty"
                    ? ids.map(() => "")
                    : failure === "duplicate"
                      ? ids.map(() => "same")
                      : failure === "cross" && current === 1
                        ? [published[0].messageId]
                        : ids,
        };
      } else if (c.method === "Pull")
        body = {
          receivedMessages: published.map(({ message, messageId }) => ({
            ackId: `ack-${messageId}`,
            message: { ...message, messageId, ...(failure === "badData" ? { data: "eA==" } : {}) },
          })),
        };
      else if (c.method === "Acknowledge") {
        if (failure === "ack")
          return { ok: false, unknown: false, status: 400, code: "INVALID_ARGUMENT", body: {} };
      } else throw Error(c.method);
      return { ok: true, unknown: false, status: 200, code: "OK", body };
    },
  };
  const result = await runCell({
    cell,
    meter,
    wire,
    ledger: createLedger(),
    runId: "123456abcdef",
    journal: { write: (r) => rows.push(r) },
    sleep: async () => {},
  });
  return { result, calls, rows };
}
for (const id of ["R11", "N13"]) {
  test(`${id} splits exact eight variants into homogeneous batches and correlates own delivery/ACK`, async () => {
    const w = await world(id),
      pub = w.calls.filter((c) => c.method === "Publish");
    assert.equal(w.result.complete, true);
    assert.equal(w.result.cleanupClosed, true);
    assert.deepEqual(
      pub.map((c) => c.request.messages.length),
      [7, 1],
    );
    assert.ok(pub[0].request.messages.every((m) => !m.orderingKey));
    assert.equal(pub[1].request.messages[0].orderingKey, "k1");
    const bindings = w.rows.filter((r) => r.event === "publication-binding");
    assert.equal(bindings.length, 8);
    assert.deepEqual(
      bindings.map((r) => r.batchIndex).sort((a, b) => a - b),
      [0, 1, 2, 3, 4, 5, 6, 7],
    );
    assert.equal(
      bindings.find((r) => r.batchIndex === 4).data,
      Buffer.from("keyed").toString("base64"),
    );
    assert.equal(bindings.find((r) => r.batchIndex === 5).data, "AP+A");
    assert.equal(
      bindings.find((r) => r.batchIndex === 6).data,
      Buffer.from("ünïcödé ✓").toString("base64"),
    );
    assert.deepEqual(bindings.find((r) => r.batchIndex === 1).attributes, { color: "red", n: "1" });
    assert.equal(w.rows.filter((r) => r.event === "publication-delivery-binding").length, 8);
    assert.equal(w.calls.find((c) => c.method === "Acknowledge").request.ackIds.length, 8);
  });
  for (const failure of [
    "missing",
    "short",
    "numeric",
    "empty",
    "duplicate",
    "error",
    "cross",
    "badData",
    "ack",
  ])
    test(`${id} rejects ${failure} without qualifying or skipping cleanup`, async () => {
      const w = await world(id, failure);
      assert.equal(w.result.complete, false);
      if (!["badData", "ack"].includes(failure)) {
        if (failure !== "error")
          assert.equal(w.result.reason, "publication batch is not bijective");
        assert.equal(
          w.calls.some((call) => call.method === "Pull"),
          false,
        );
      }
      assert.equal(w.result.cleanupClosed, true);
    });
}
