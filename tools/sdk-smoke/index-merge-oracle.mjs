// Production oracle probe for index merging and primary-key filters.
//
// Requires the indexes in `conformance/firestore.indexes.json` to be deployed:
//   mrg: (category ASC, star_rating ASC) and (city ASC, star_rating ASC)
//   pk:  wildcard field override `*` with no single-field indexes
//
// Every case records the outcome (`ok` or the gRPC error code) so the fireemu index
// validator can be compared against production line by line. Expected outcomes for the
// documented cases and primary-key cases are asserted, including successful result order.
//
// Env: PRODUCTION_ORACLE_PROJECT_ID=fireemu-35fe6
//      PRODUCTION_ORACLE_EXPECTED_PROJECT_NUMBER=592603257417
//      (or FIRESTORE_EMULATOR_HOST for a local run)
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { initializeApp, deleteApp, applicationDefault } from "firebase-admin/app";
import { getFirestore, FieldPath } from "firebase-admin/firestore";
import { probe as evaluateProbe } from "./oracle-probe.mjs";

const production = process.env.PRODUCTION_ORACLE_PROJECT_ID;
if (!process.env.FIRESTORE_EMULATOR_HOST) {
  assert.equal(
    production,
    "fireemu-35fe6",
    "An explicitly selected oracle or emulator is required",
  );
  assert.equal(process.env.PRODUCTION_ORACLE_EXPECTED_PROJECT_NUMBER, "592603257417");
}
const app = initializeApp({
  projectId: production || "demo-app",
  ...(production ? { credential: applicationDefault() } : {}),
});
const db = getFirestore(app);
const run = randomUUID().slice(0, 8);
const mrg = db.collection("mrg");
const pk = db.collection("pk");
const fixtures = [
  [mrg.doc(`${run}-a`), { category: run, city: "SF", editors_pick: true, star_rating: 4 }],
  [mrg.doc(`${run}-b`), { category: run, city: "SF", editors_pick: false, star_rating: 2 }],
  [mrg.doc(`${run}-c`), { category: run, city: "LA", editors_pick: true, star_rating: 5 }],
  [pk.doc(`${run}-a`), { n: 1 }],
  [pk.doc(`${run}-b`), { n: 2 }],
  [db.collection("ord").doc(`${run}-a`), { n: 1 }],
  [db.collection("ord").doc(`${run}-b`), { n: 2 }],
];

const results = [];
async function probe(name, expected, fn, expectedValue) {
  if (expected === "ok")
    assert.notEqual(expectedValue, undefined, "Success gates require expected results");
  results.push(
    await evaluateProbe(
      name,
      expected === null
        ? null
        : {
            outcome: expected,
            ...(expected === "ok" ? { value: expectedValue } : {}),
          },
      fn,
    ),
  );
}
const ids = (snap) => snap.docs.map((d) => d.id.replace(`${run}-`, ""));

try {
  await Promise.all(fixtures.map(([ref, data]) => ref.set(data)));

  await probe(
    "mrg: category == AND city == orderBy star_rating (merge two composites)",
    "ok",
    async () =>
      ids(
        await mrg
          .where("category", "==", run)
          .where("city", "==", "SF")
          .orderBy("star_rating")
          .get(),
      ),
    ["b", "a"],
  );
  await probe(
    "mrg: category == AND city == (merge automatic indexes)",
    "ok",
    async () => ids(await mrg.where("category", "==", run).where("city", "==", "SF").get()),
    ["a", "b"],
  );
  await probe(
    "mrg: + editors_pick == orderBy star_rating (no editors_pick composite)",
    "9",
    async () =>
      ids(
        await mrg
          .where("category", "==", run)
          .where("city", "==", "SF")
          .where("editors_pick", "==", true)
          .orderBy("star_rating")
          .get(),
      ),
  );
  await probe(
    "mrg: category == AND city == orderBy star_rating DESC (direction mismatch)",
    "9",
    async () =>
      ids(
        await mrg
          .where("category", "==", run)
          .where("city", "==", "SF")
          .orderBy("star_rating", "desc")
          .get(),
      ),
  );
  await probe(
    "mrg: category == orderBy star_rating (single composite)",
    "ok",
    async () => ids(await mrg.where("category", "==", run).orderBy("star_rating").get()),
    ["b", "a", "c"],
  );
  await probe("mrg: __name__ == ref AND star_rating > 0", "3", async () =>
    ids(
      await mrg
        .where(FieldPath.documentId(), "==", mrg.doc(`${run}-a`))
        .where("star_rating", ">", 0)
        .get(),
    ),
  );
  await probe("mrg: __name__ in refs AND star_rating > 0", "3", async () =>
    ids(
      await mrg
        .where(FieldPath.documentId(), "in", [mrg.doc(`${run}-a`)])
        .where("star_rating", ">", 0)
        .get(),
    ),
  );
  await probe(
    "mrg: category == AND star_rating > 0 (range control)",
    "ok",
    async () => ids(await mrg.where("category", "==", run).where("star_rating", ">", 0).get()),
    ["b", "a", "c"],
  );

  await probe("pk: n == 1 (exempt field, control)", "9", async () =>
    ids(await pk.where("n", "==", 1).get()),
  );
  await probe(
    "pk: __name__ == ref",
    "ok",
    async () => ids(await pk.where(FieldPath.documentId(), "==", pk.doc(`${run}-a`)).get()),
    ["a"],
  );
  await probe(
    "pk: __name__ in [refs]",
    "ok",
    async () =>
      ids(
        await pk
          .where(FieldPath.documentId(), "in", [pk.doc(`${run}-a`), pk.doc(`${run}-b`)])
          .get(),
      ),
    ["a", "b"],
  );
  await probe(
    "pk: __name__ > ref",
    "ok",
    async () =>
      ids(
        await pk
          .where(FieldPath.documentId(), ">", pk.doc(`${run}-a`))
          .where(FieldPath.documentId(), "<", pk.doc(`${run}-c`))
          .get(),
      ),
    ["b"],
  );
  await probe("pk: orderBy __name__ desc (no __name__ DESC index)", "9", async () =>
    ids(await pk.orderBy(FieldPath.documentId(), "desc").limit(2).get()),
  );
  await probe("pk: __name__ > ref orderBy __name__ desc", "9", async () =>
    ids(
      await pk
        .where(FieldPath.documentId(), ">", pk.doc(`${run}-a`))
        .orderBy(FieldPath.documentId(), "desc")
        .get(),
    ),
  );
  await probe("pk: collectionGroup orderBy __name__ desc", "9", async () =>
    ids(await db.collectionGroup("pk").orderBy(FieldPath.documentId(), "desc").limit(2).get()),
  );
  await probe(
    "mrg: category == orderBy __name__ desc (automatic descending index)",
    "ok",
    async () =>
      ids(await mrg.where("category", "==", run).orderBy(FieldPath.documentId(), "desc").get()),
    ["c", "b", "a"],
  );
  await probe(
    "mrg: orderBy __name__ desc without filter (default single-field config)",
    "9",
    async () => ids(await mrg.orderBy(FieldPath.documentId(), "desc").limit(1).get()),
  );
  await probe(
    "mrg: collectionGroup orderBy __name__ desc (default single-field config)",
    "9",
    async () =>
      ids(await db.collectionGroup("mrg").orderBy(FieldPath.documentId(), "desc").limit(1).get()),
  );
  await probe(
    "ord: orderBy __name__ desc (explicit __name__ DESC composite)",
    "ok",
    async () =>
      ids(
        await db
          .collection("ord")
          .where(FieldPath.documentId(), ">=", `${run}-a`)
          .where(FieldPath.documentId(), "<=", `${run}-z`)
          .orderBy(FieldPath.documentId(), "desc")
          .limit(2)
          .get(),
      ),
    ["b", "a"],
  );
  await probe("pk: __name__ == ref AND n == 1 (exempt field stays required)", "9", async () =>
    ids(
      await pk
        .where(FieldPath.documentId(), "==", pk.doc(`${run}-a`))
        .where("n", "==", 1)
        .get(),
    ),
  );
} finally {
  await Promise.all(fixtures.map(([ref]) => ref.delete()));
  await deleteApp(app);
}
console.log(JSON.stringify(results, null, 1));
console.error(
  JSON.stringify({
    regressionCases: results.filter((r) => r.mode === "regression").length,
    observationCases: results.filter((r) => r.mode === "observation").length,
  }),
);
const failed = results.filter((r) => r.matches === false);
process.exit(failed.length ? 1 : 0);
