import assert from "node:assert/strict";
import { test } from "node:test";

import { bandOf, inBand, makeDeps, queryConstraints } from "./fs-listen/sdk-deps.mjs";

test("bandOf is stable, above 1000, a multiple of 100 away from it, and separates runs", () => {
  assert.equal(bandOf("na1"), bandOf("na1"));
  assert.ok(bandOf("na1") >= 1000);
  assert.equal((bandOf("na1") - 1000) % 100, 0);
  assert.notEqual(bandOf("na1"), bandOf("na2"));
});

test("queryConstraints bounds the catalog query to the run's band, in the listener's order", () => {
  const spec = { where: ["rank", "<", 10], orderBy: ["rank", "asc"], limit: 10 };
  assert.deepEqual(queryConstraints(spec, 5000), [
    ["where", "rank", ">=", 5000],
    ["where", "rank", "<", 5010],
    ["orderBy", "rank", "asc"],
    ["limit", 10],
  ]);
  assert.deepEqual(queryConstraints({ ...spec, limit: 2, limitToLast: true }, 5000).at(-1), [
    "limitToLast",
    2,
  ]);
  assert.throws(() => queryConstraints({ where: ["value", "==", 1] }, 5000), /unsupported/);
});

test("inBand moves rank only for public documents that have one", () => {
  assert.deepEqual(inBand("conf_listen/r-a", { rank: 3, value: "x" }, 5000), {
    rank: 5003,
    value: "x",
  });
  assert.deepEqual(inBand("conf_rules_owner/uid", { rank: 3 }, 5000), { rank: 3 });
  assert.deepEqual(inBand("conf_listen/r-a", { value: "x" }, 5000), { value: "x" });
});

function fakeSdk(log) {
  const record =
    (name) =>
    (...args) => {
      log.push([name, ...args.map((a) => (a && a.path ? a.path : a))]);
      return { path: typeof args[1] === "string" ? args[1] : undefined, name, args };
    };
  return {
    doc: (db, path) => ({ path }),
    collection: (db, path) => ({ path }),
    query: (c, ...constraints) => ({ collection: c, constraints }),
    where: (...a) => ({ where: a }),
    orderBy: (...a) => ({ orderBy: a }),
    limit: (n) => ({ limit: n }),
    limitToLast: (n) => ({ limitToLast: n }),
    setDoc: async (ref, data) => log.push(["setDoc", ref.path, data]),
    onSnapshot: (target, options, observer) => {
      log.push(["onSnapshot", target, options]);
      observer.next({
        docs: [{ ref: { path: "conf_listen/r-a" } }],
        docChanges: () => [
          { type: "added", doc: { ref: { path: "conf_listen/r-a" } }, oldIndex: -1, newIndex: 0 },
        ],
        metadata: { fromCache: false, hasPendingWrites: false },
      });
      return () => log.push(["unsubscribe"]);
    },
    runTransaction: async (db, update) => {
      const sets = [];
      await update({ set: (ref, data) => sets.push([ref.path, data]) });
      log.push(["runTransaction", sets]);
    },
    record,
  };
}

test("makeDeps: a query listener is built in the band and its snapshot is normalized", () => {
  const log = [];
  const clients = { primary: { db: {} }, witness: { db: {} } };
  const deps = makeDeps({ sdk: fakeSdk(log), clients, base: 5000 });
  const seen = [];
  deps.firestore.onQuerySnapshot(
    "primary",
    { where: ["rank", "<", 10], orderBy: ["rank", "asc"], limit: 10 },
    { includeMetadataChanges: true },
    (row) => seen.push(row),
    () => {},
  );
  const [, target] = log.find(([name]) => name === "onSnapshot");
  assert.equal(target.collection.path, "conf_listen");
  assert.deepEqual(
    target.constraints.map((c) => Object.keys(c)[0]),
    ["where", "where", "orderBy", "limit"],
  );
  assert.deepEqual(seen, [
    {
      docs: ["conf_listen/r-a"],
      changes: [{ type: "added", path: "conf_listen/r-a", oldIndex: -1, newIndex: 0 }],
      fromCache: false,
      hasPendingWrites: false,
    },
  ]);
});

test("makeDeps: a plain write is shifted into the band; a grouped write waits for its group", async () => {
  const log = [];
  const clients = { primary: { db: {} }, witness: { db: {} } };
  const deps = makeDeps({ sdk: fakeSdk(log), clients, base: 5000 });
  await deps.firestore.setDoc("primary", "conf_listen/r-a", { rank: 1, value: "x" });
  assert.deepEqual(log.at(-1), ["setDoc", "conf_listen/r-a", { rank: 5001, value: "x" }]);
  const before = log.length;
  await deps.firestore.setDoc("witness", "conf_listen/r-b", {
    rank: 2,
    __txn: { id: "t", size: 2 },
  });
  assert.equal(log.length, before, "the first member of a group is held");
  await deps.firestore.setDoc("witness", "conf_listen/r-c", {
    rank: 3,
    __txn: { id: "t", size: 2 },
  });
  assert.deepEqual(log.at(-1), [
    "runTransaction",
    [
      ["conf_listen/r-b", { rank: 5002 }],
      ["conf_listen/r-c", { rank: 5003 }],
    ],
  ]);
  // The group is spent: a new group of the same id starts again.
  await deps.firestore.setDoc("witness", "conf_listen/r-d", {
    rank: 4,
    __txn: { id: "t", size: 2 },
  });
  assert.equal(log.at(-1)[0], "runTransaction");
  assert.equal(log.filter(([name]) => name === "runTransaction").length, 1);
});
