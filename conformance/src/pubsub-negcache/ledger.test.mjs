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

test("DELETE answered 404 for a confirmed resource settles nothing and is retried only after a complete LIST shows it present, up to the third DELETE", () => {
  const ledger = createLedger();
  create(ledger, "ok");
  assert.deepEqual(ledger.deletable(), [N], "the first DELETE needs no LIST");
  for (let i = 1; i <= MAX_DELETES; i += 1) {
    del(ledger, "notfound");
    assert.equal(ledger.status(N), "delete-404-present");
    assert.deepEqual(ledger.deletable(), [], `delete ${i}: nothing admits a retry yet`);
    ledger.read(N, "absent", "list");
    assert.deepEqual(ledger.deletable(), [], "a LIST that misses it admits nothing");
    ledger.read(N, "present", "get");
    assert.deepEqual(ledger.deletable(), [], "an own GET 200 is not a LIST");
    ledger.read(N, "present", "list");
    assert.deepEqual(ledger.deletable(), i < MAX_DELETES ? [N] : [], `after delete ${i}`);
  }
  assert.ok(!ledger.closureReady());
  assert.equal(ledger.status(N), "delete-404-present");
});

test("a LIST read before the latest DELETE does not admit a retry after it", () => {
  const ledger = createLedger();
  create(ledger, "ok");
  del(ledger, "notfound");
  ledger.read(N, "present", "list");
  assert.deepEqual(ledger.deletable(), [N]);
  del(ledger, "error");
  assert.deepEqual(ledger.deletable(), [], "the admission belonged to the earlier DELETE");
});

test("a DELETE answered before the resource existed is not a DELETE of the resource", () => {
  const ledger = createLedger();
  del(ledger, "notfound");
  create(ledger, "ok");
  assert.equal(ledger.status(N), "live");
  assert.deepEqual(ledger.deletable(), [N]);
});

test("a repeated create of a live name (a failed create of an existing name) keeps the resource confirmed", () => {
  const ledger = createLedger();
  create(ledger, "ok");
  create(ledger, "notfound");
  create(ledger, "conflict");
  assert.equal(ledger.status(N), "live");
  assert.deepEqual(ledger.deletable(), [N]);
});

test("a snapshot created again after its own DELETE is a new incarnation: a lost answer keeps it open and in the cleanup", () => {
  const ledger = createLedger();
  create(ledger, "ok");
  del(ledger, "ok");
  ledger.read(N, "absent", "get");
  assert.equal(ledger.status(N), "deleted");
  assert.ok(ledger.closureReady());
  create(ledger, "unknown");
  assert.equal(ledger.status(N), "unconfirmed-create");
  assert.ok(!ledger.closureReady());
  assert.deepEqual(ledger.open(), [{ name: N, status: "unconfirmed-create" }]);
  assert.deepEqual(ledger.deletable(), [], "an unconfirmed name is read before it is deleted");
  ledger.read(N, "absent", "get");
  assert.equal(ledger.status(N), "unconfirmed-create", "a 404 never settles it");
  ledger.a2Absent(N);
  assert.equal(ledger.status(N), "unconfirmed-create", "nor does A2");
  ledger.read(N, "present", "get");
  assert.equal(ledger.status(N), "live");
  assert.deepEqual(ledger.deletable(), [N]);
  del(ledger, "ok");
  assert.equal(ledger.status(N), "delete-unread");
  ledger.read(N, "absent", "list");
  assert.equal(ledger.status(N), "deleted");
  assert.ok(ledger.closureReady());
});

test("a new incarnation answered 2xx or a known error is judged on its own, a 409 keeps the earlier one", () => {
  for (const [result, status] of [
    ["ok", "live"],
    ["conflict", "delete-present"],
    ["notfound", "deleted"],
  ]) {
    const ledger = createLedger();
    create(ledger, "ok");
    del(ledger, "ok");
    ledger.read(N, "absent", "get");
    create(ledger, result);
    assert.equal(ledger.status(N), status, result);
  }
});

test("an unknown DELETE of an earlier incarnation stays sticky across a new create", () => {
  const ledger = createLedger();
  create(ledger, "ok");
  del(ledger, "ok");
  del(ledger, "unknown");
  create(ledger, "ok");
  assert.equal(ledger.status(N), "delete-unknown");
  assert.ok(ledger.deleting(N));
  assert.deepEqual(ledger.deletable(), []);
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

test("an unknown create followed by an own positive read is live, and the A2 absence then settles it like any confirmed resource", () => {
  const ledger = createLedger();
  create(ledger, "unknown");
  ledger.read(N, "present");
  ledger.read(N, "absent");
  assert.equal(ledger.status(N), "live-suspect");
  ledger.a2Absent(N);
  assert.equal(ledger.status(N), "gone-a2");
});

test("a create attempt of a name that is already confirmed does not drop the DELETEs that followed the create", () => {
  const ledger = createLedger();
  create(ledger, "ok");
  del(ledger, "notfound");
  create(ledger, "conflict");
  assert.equal(ledger.status(N), "delete-404-present");
});

test("an unknown or unanswered DELETE made before the first create is kept, a 404 one is not", () => {
  for (const answer of ["unknown", null]) {
    const ledger = createLedger();
    del(ledger, answer);
    create(ledger, "ok");
    assert.equal(ledger.status(N), "delete-unknown", String(answer));
    assert.ok(ledger.deleting(N));
  }
  const ledger = createLedger();
  del(ledger, "notfound");
  create(ledger, "ok");
  assert.equal(ledger.status(N), "live");
});

test("an unanswered DELETE of an earlier incarnation stays sticky across a new create", () => {
  const ledger = createLedger();
  create(ledger, "ok");
  del(ledger, "ok");
  del(ledger, null);
  create(ledger, "ok");
  assert.equal(ledger.status(N), "delete-unknown");
});

test("S1: a 409 on re-creating our own name after our own 2xx DELETE keeps the earlier incarnation, which an absence read or A2 can close", () => {
  const unread = createLedger();
  create(unread, "ok");
  del(unread, "ok");
  create(unread, "conflict");
  // The 409 is positive evidence that something of that name exists: it is deletable and not yet closed.
  assert.equal(unread.status(N), "delete-present");
  assert.deepEqual(unread.deletable(), [N]);
  assert.ok(!unread.closureReady());
  unread.read(N, "absent", "list");
  assert.equal(unread.status(N), "deleted");
  const present = createLedger();
  create(present, "ok");
  del(present, "ok");
  present.read(N, "present", "list");
  create(present, "conflict");
  assert.equal(present.status(N), "delete-present");
  assert.deepEqual(present.deletable(), [N]);
  // A2 settles it like any delete whose absence was not read.
  const a2 = createLedger();
  create(a2, "ok");
  del(a2, "ok");
  create(a2, "conflict");
  a2.a2Absent(N);
  assert.equal(a2.status(N), "gone-a2");
  // A 409 on a fresh name (no earlier incarnation) stays an unconfirmed create: the packet says how it closes.
  const fresh = createLedger();
  create(fresh, "conflict");
  assert.equal(fresh.status(N), "unconfirmed-create");
  // A 409 after an unknown re-create does not undo it.
  const lost = createLedger();
  create(lost, "ok");
  del(lost, "ok");
  create(lost, "unknown");
  create(lost, "conflict");
  assert.equal(lost.status(N), "unconfirmed-create");
});

test("M1 of the v4 delta review: a 409 after an absence read never reads deleted", () => {
  const ledger = createLedger();
  create(ledger, "ok");
  del(ledger, "ok");
  ledger.read(N, "absent", "get"); // the earlier incarnation was read absent
  create(ledger, "conflict"); // but a snapshot of the name exists now
  assert.equal(ledger.status(N), "delete-present");
  assert.deepEqual(ledger.deletable(), [N]);
  assert.ok(!ledger.closureReady());
  // only a later absence (a complete LIST) closes it again
  ledger.read(N, "absent", "list");
  assert.equal(ledger.status(N), "deleted");
});

test("S1 of the m1 delta review: a known refusal of a re-create restores the earlier incarnation, and only a 409 proves presence", () => {
  for (const result of ["notfound", "error"]) {
    // never read: the cleanup LIST settles it
    const unread = createLedger();
    create(unread, "ok");
    del(unread, "ok");
    create(unread, result);
    assert.equal(unread.status(N), "delete-unread", result);
    assert.ok(!unread.closureReady(), result);
    unread.read(N, "absent", "list");
    assert.equal(unread.status(N), "deleted", result);
    // read absent before the refusal: the refusal created nothing, the absence still stands
    const absent = createLedger();
    create(absent, "ok");
    del(absent, "ok");
    absent.read(N, "absent", "get");
    create(absent, result);
    assert.equal(absent.status(N), "deleted", result);
    // read present before the refusal stays present
    const present = createLedger();
    create(present, "ok");
    del(present, "ok");
    present.read(N, "present", "list");
    create(present, result);
    assert.equal(present.status(N), "delete-present", result);
    assert.deepEqual(present.deletable(), [N], result);
  }
  // a refusal of a fresh name (no earlier incarnation) is still a rejected create
  const fresh = createLedger();
  create(fresh, "error");
  assert.equal(fresh.status(N), "never-created");
  // a refusal after an unknown re-create does not undo it
  const lost = createLedger();
  create(lost, "ok");
  del(lost, "ok");
  create(lost, "unknown");
  create(lost, "error");
  assert.equal(lost.status(N), "unconfirmed-create");
});
