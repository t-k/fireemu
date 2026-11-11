import assert from "node:assert/strict";
import test from "node:test";

import { createLedger, MAX_DELETES } from "./ledger.mjs";
import { prng } from "./support.mjs";

const N = "projects/p/subscriptions/x";
const create = (ledger, result) => {
  const id = ledger.intent({ name: N, action: "create", kind: "subscription" });
  if (result) ledger.answer(id, result);
  return id;
};
const del = (ledger, result) => {
  const id = ledger.intent({ name: N, action: "delete", kind: "subscription" });
  if (result) ledger.answer(id, result);
  return id;
};

test("a resource the run never touched is never-created and closes", () => {
  const ledger = createLedger();
  assert.equal(ledger.status(N), "never-created");
  assert.ok(ledger.closureReady());
});

test("unknown create, then only 404: stays open, in the run and at A2", () => {
  const ledger = createLedger();
  create(ledger, "unknown");
  assert.equal(ledger.status(N), "unconfirmed-create");
  ledger.read(N, "absent");
  assert.equal(ledger.status(N), "unconfirmed-create");
  assert.ok(!ledger.closureReady());
  ledger.a2Absent(N);
  assert.equal(ledger.status(N), "unconfirmed-create");
  assert.ok(!ledger.closureReady());
});

test("unknown create, then an own positive read: confirmed", () => {
  const ledger = createLedger();
  create(ledger, "unknown");
  ledger.read(N, "present");
  assert.equal(ledger.status(N), "live");
  assert.deepEqual(ledger.deletable(), [N]);
});

test("a 409 after an unknown create settles nothing", () => {
  const ledger = createLedger();
  create(ledger, "unknown");
  create(ledger, "conflict");
  assert.equal(ledger.status(N), "unconfirmed-create");
  assert.ok(!ledger.closureReady());
});

test("a 409 alone is not a confirmation either", () => {
  const ledger = createLedger();
  create(ledger, "conflict");
  assert.equal(ledger.status(N), "unconfirmed-create");
  assert.deepEqual(ledger.deletable(), []);
});

test("a create answered with a known error is never-created", () => {
  const ledger = createLedger();
  create(ledger, "notfound");
  assert.equal(ledger.status(N), "never-created");
  assert.ok(ledger.closureReady());
});

test("confirmed create, then 404 in the run: not settled until the A2 read-back", () => {
  const ledger = createLedger();
  create(ledger, "ok");
  ledger.read(N, "absent");
  assert.equal(ledger.status(N), "live-suspect");
  assert.ok(!ledger.closureReady());
  assert.deepEqual(ledger.deletable(), [N]);
  ledger.a2Absent(N);
  assert.equal(ledger.status(N), "gone-a2");
  assert.ok(ledger.closureReady());
});

test("own DELETE 2xx then an absence read settles; before the read it is unread", () => {
  const ledger = createLedger();
  create(ledger, "ok");
  del(ledger, "ok");
  assert.equal(ledger.status(N), "delete-unread");
  assert.ok(!ledger.closureReady());
  ledger.read(N, "absent");
  assert.equal(ledger.status(N), "deleted");
  assert.ok(ledger.closureReady());
});

test("DELETE 2xx but a later LIST still shows the resource: delete again", () => {
  const ledger = createLedger();
  create(ledger, "ok");
  del(ledger, "ok");
  ledger.read(N, "present");
  assert.equal(ledger.status(N), "delete-present");
  assert.deepEqual(ledger.deletable(), [N]);
});

test("DELETE answered 404 for a confirmed resource settles nothing and is retried until the third DELETE", () => {
  const ledger = createLedger();
  create(ledger, "ok");
  for (let i = 1; i <= MAX_DELETES; i += 1) {
    assert.deepEqual(ledger.deletable(), [N], `delete ${i}`);
    del(ledger, "notfound");
    assert.equal(ledger.status(N), "delete-404-present");
    ledger.read(N, "absent"); // a LIST that misses it is not enough, in the run
    assert.equal(ledger.status(N), "delete-404-present");
  }
  assert.deepEqual(ledger.deletable(), []);
  assert.ok(!ledger.closureReady());
});

test("an unknown DELETE is sticky: no retry, absence reads do not close it, only A2 does", () => {
  const ledger = createLedger();
  create(ledger, "ok");
  const id = del(ledger, "unknown");
  assert.ok(ledger.deleting(N));
  assert.deepEqual(ledger.deletable(), []);
  ledger.read(N, "absent");
  assert.equal(ledger.status(N), "delete-unknown");
  assert.ok(!ledger.closureReady());
  ledger.a2Absent(N);
  assert.equal(ledger.status(N), "gone-a2");
  assert.ok(ledger.closureReady());
  assert.ok(id > 0);
});

test("a delete whose answer never arrived blocks a re-send and closure", () => {
  const ledger = createLedger();
  create(ledger, "ok");
  del(ledger, null);
  assert.ok(ledger.deleting(N));
  assert.equal(ledger.status(N), "delete-unknown");
  ledger.a2Absent(N);
  assert.equal(ledger.status(N), "delete-unknown");
});

test("a request cannot be answered twice or unknown ids answered", () => {
  const ledger = createLedger();
  const id = create(ledger, "ok");
  assert.throws(() => ledger.answer(id, "ok"), /twice/);
  assert.throws(() => ledger.answer(999, "ok"), /unknown request id/);
});

test("a DELETE of a name the run never created is a plain absent answer", () => {
  const ledger = createLedger();
  del(ledger, "notfound");
  assert.equal(ledger.status(N), "never-created");
  assert.ok(ledger.closureReady());
});

test("property: closureReady implies every resource is deleted, gone at A2 or never created", () => {
  const random = prng(11);
  for (let round = 0; round < 400; round += 1) {
    const ledger = createLedger();
    const names = ["a", "b", "c"].map((n) => `projects/p/subscriptions/${n}`);
    for (let i = 0; i < 12; i += 1) {
      const name = names[Math.floor(random() * 3)];
      const r = random();
      const results = ["ok", "notfound", "conflict", "error", "unknown"];
      if (r < 0.3)
        ledger.answer(
          ledger.intent({ name, action: "create", kind: "subscription" }),
          results[Math.floor(random() * 5)],
        );
      else if (r < 0.5 && !ledger.deleting(name))
        ledger.answer(
          ledger.intent({ name, action: "delete", kind: "subscription" }),
          results[Math.floor(random() * 5)],
        );
      else if (r < 0.8) ledger.read(name, random() < 0.5 ? "present" : "absent");
      else if (r < 0.85) ledger.a2Absent(name);
    }
    if (ledger.closureReady())
      for (const n of ledger.all())
        assert.ok(["never-created", "deleted", "gone-a2"].includes(ledger.status(n)));
    // An unknown delete keeps the ledger open until A2 says absent.
    for (const s of ledger.snapshot())
      if (s.deletes.some((d) => d.answer === "unknown") && !s.a2Absent)
        assert.ok(!ledger.closureReady());
    // Nothing unconfirmed or already deleted twice-unknown is offered for deletion.
    for (const n of ledger.deletable()) assert.ok(!ledger.deleting(n));
  }
});
