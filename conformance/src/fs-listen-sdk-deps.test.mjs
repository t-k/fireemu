import assert from "node:assert/strict";
import { createHash } from "node:crypto";
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

test("bandOf: stable, in range, a multiple of 100 above 1000, and different for different runs", () => {
  assert.equal(bandOf("na1"), bandOf("na1"));
  const ids = Array.from(
    { length: 200 },
    (_, i) => `n${(1_700_000_000_000 + i * 60_000).toString(36)}`,
  );
  const bands = ids.map(bandOf);
  for (const band of bands)
    assert.ok(band % 100 === 0 && band >= 1000 && band < 1000 + 100_000_000, band);
  assert.ok(new Set(bands).size >= 199, "different runs rarely share a band");
  // The first band is the hash of the run id itself, not of its length or its last character.
  assert.notEqual(bandOf("na1"), bandOf("na2"));
  assert.notEqual(bandOf("ab"), bandOf("ba"));
  assert.equal(bandOf(5), bandOf("5"));
});

test("queryConstraints: defaults, the bound moves with the base, and limit or limitToLast ends the list", () => {
  const spec = { where: ["rank", "<", 3] };
  assert.deepEqual(queryConstraints(spec, 100), [
    ["where", "rank", ">=", 100],
    ["where", "rank", "<", 103],
    ["orderBy", "rank", "asc"],
    ["limit", 10],
  ]);
  assert.deepEqual(queryConstraints({ ...spec, orderBy: ["rank", "desc"], limit: 4 }, 0).slice(2), [
    ["orderBy", "rank", "desc"],
    ["limit", 4],
  ]);
  assert.deepEqual(queryConstraints({ ...spec, limitToLast: true, limit: 2 }, 0).at(-1), [
    "limitToLast",
    2,
  ]);
  assert.deepEqual(queryConstraints({ ...spec, limitToLast: false }, 0).at(-1), ["limit", 10]);
  assert.throws(
    () => queryConstraints({ where: ["rank", ">", 1] }, 0),
    /unsupported listener filter/,
  );
  assert.throws(() => queryConstraints({ where: ["x", "<", 1] }, 0), /unsupported listener filter/);
});

test("inBand: a public document with a numeric rank moves; everything else is the same object", () => {
  const fields = { rank: 0, value: "x" };
  assert.deepEqual(inBand("conf_listen/a", fields, 7), { rank: 7, value: "x" });
  assert.deepEqual(fields, { rank: 0, value: "x" }, "the input is not changed");
  const text = { rank: "1" };
  assert.equal(inBand("conf_listen/a", text, 7), text);
  const outside = { rank: 1 };
  assert.equal(inBand("conf_listenx/a", outside, 7), outside);
  assert.equal(inBand("conf_listen", outside, 7), outside);
  const none = { value: 1 };
  assert.equal(inBand("conf_listen/a", none, 7), none);
});

test("makeDeps: the listener gets its options and error callback; the query is on the named client's db", () => {
  const log = [];
  const sdk = fakeSdk(log);
  const clients = { primary: { db: { id: "primary" } }, witness: { db: { id: "witness" } } };
  const deps = makeDeps({ sdk, clients, base: 1 });
  let failed;
  const stop = deps.firestore.onQuerySnapshot(
    "witness",
    { where: ["rank", "<", 10], limit: 10 },
    { includeMetadataChanges: false },
    () => {},
    (error) => {
      failed = error;
    },
  );
  const [, , options] = log.find(([name]) => name === "onSnapshot");
  assert.deepEqual(options, { includeMetadataChanges: false });
  stop();
  assert.deepEqual(log.at(-1), ["unsubscribe"]);
  assert.equal(failed, undefined);
});

test("makeDeps: a plain write to another collection is not shifted, and groups are kept apart by id", async () => {
  const log = [];
  const clients = { primary: { db: {} }, witness: { db: {} } };
  const deps = makeDeps({ sdk: fakeSdk(log), clients, base: 5000 });
  await deps.firestore.setDoc("primary", "conf_rules_owner/u", { rank: 1, value: "x" });
  assert.deepEqual(log.at(-1), ["setDoc", "conf_rules_owner/u", { rank: 1, value: "x" }]);
  await deps.firestore.setDoc("witness", "conf_listen/a", {
    rank: 1,
    __txn: { id: "g1", size: 2 },
  });
  await deps.firestore.setDoc("witness", "conf_listen/b", {
    rank: 2,
    __txn: { id: "g2", size: 2 },
  });
  assert.equal(log.filter(([name]) => name === "runTransaction").length, 0);
  await deps.firestore.setDoc("witness", "conf_listen/c", {
    rank: 3,
    __txn: { id: "g1", size: 2 },
  });
  const [name, sets] = log.at(-1);
  assert.equal(name, "runTransaction");
  assert.deepEqual(
    sets.map(([path]) => path),
    ["conf_listen/a", "conf_listen/c"],
  );
  // The group member's marker is not written.
  assert.deepEqual(sets[0][1], { rank: 5001 });
});

test("bandOf has fixed values, so a change of the hash or its range shows", () => {
  assert.equal(
    bandOf("na1"),
    1000 + 100 * (createHash("sha256").update("na1").digest().readUInt32BE(0) % 1_000_000),
  );
  assert.equal(bandOf("na1"), 92252600);
  assert.equal(
    bandOf("n1"),
    1000 + 100 * (createHash("sha256").update("n1").digest().readUInt32BE(0) % 1_000_000),
  );
});

test("makeDeps hands the revoke function to the adapter's auth dependencies", async () => {
  const calls = [];
  const clients = { primary: { db: {}, auth: { currentUser: { uid: "u9" } } } };
  const deps = makeDeps({
    sdk: fakeSdk([]),
    clients,
    base: 1,
    revoke: async (uid) => calls.push(uid),
  });
  await deps.auth.revoke("primary");
  assert.deepEqual(calls, ["u9"]);
  const without = makeDeps({ sdk: fakeSdk([]), clients, base: 1 });
  await assert.rejects(without.auth.revoke("primary"), /revocation is unavailable/);
});
