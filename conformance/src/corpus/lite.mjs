// firebase/firestore/lite rows: the same operations as the gRPC client, but over the REST
// transport only, so the two transports' error codes and payload shapes can be compared.

import {
  collection,
  deleteDoc,
  doc,
  getCount,
  getDoc,
  getDocs,
  increment,
  limit,
  orderBy,
  query,
  runTransaction,
  serverTimestamp,
  setDoc,
  updateDoc,
  where,
  writeBatch,
} from "firebase/firestore/lite";

import { VARIANTS } from "../config.mjs";

const liteRest = {
  id: "firestore/lite-rest-transport",
  product: "firestore",
  variant: VARIANTS.baseline,
  sdks: ["firebase/firestore/lite"],
  title: "Firestore Lite (REST only): writes, queries, aggregations, transactions and denials",
  async run(ctx) {
    const db = ctx.shared.liteFirestore();

    await ctx.step("set-and-get", async () => {
      await setDoc(doc(db, "conf_values/lite"), {
        n: 1,
        s: "x",
        nested: { k: [1, "two", null] },
        at: serverTimestamp(),
      });
      const snap = await getDoc(doc(db, "conf_values/lite"));
      return { exists: snap.exists(), data: snap.data() };
    });

    await ctx.step("update-with-a-transform-and-a-nested-path", async () => {
      await updateDoc(doc(db, "conf_values/lite"), { n: increment(4), "nested.k": [9] });
      return (await getDoc(doc(db, "conf_values/lite"))).data();
    });

    await ctx.step("query-with-filter-order-and-limit", async () => {
      await setDoc(doc(db, "conf_values/lite-b"), { n: 7 });
      await setDoc(doc(db, "conf_values/lite-c"), { n: 3 });
      const snap = await getDocs(
        query(collection(db, "conf_values"), where("n", ">", 2), orderBy("n", "desc"), limit(2)),
      );
      return snap.docs.map((d) => d.id);
    });

    await ctx.step("count-aggregation", async () => {
      const snap = await getCount(collection(db, "conf_values"));
      return snap.data().count;
    });

    await ctx.step("batch-write", async () => {
      const batch = writeBatch(db);
      batch.set(doc(db, "conf_values/lite-d"), { n: 10 });
      batch.delete(doc(db, "conf_values/lite-c"));
      await batch.commit();
      return { deletedStillExists: (await getDoc(doc(db, "conf_values/lite-c"))).exists() };
    });

    await ctx.step("transaction", async () => {
      await setDoc(doc(db, "conf_txn/lite"), { value: 1 });
      const before = await runTransaction(db, async (tx) => {
        const snap = await tx.get(doc(db, "conf_txn/lite"));
        tx.update(doc(db, "conf_txn/lite"), { value: snap.data().value + 1 });
        return snap.data().value;
      });
      return { before, after: (await getDoc(doc(db, "conf_txn/lite"))).data().value };
    });

    await ctx.step("delete", async () => {
      await deleteDoc(doc(db, "conf_values/lite"));
      return { exists: (await getDoc(doc(db, "conf_values/lite"))).exists() };
    });

    await ctx.step("write-into-a-rules-closed-collection-is-denied", async () => {
      await setDoc(doc(db, "conf_rules_closed/lite"), { v: 1 });
      return "written";
    });

    await ctx.step("query-needing-a-composite-index", async () => {
      const snap = await getDocs(
        query(collection(db, "conf_index"), where("name", "==", "x"), where("age", "==", 1)),
      );
      return { size: snap.size, ids: snap.docs.map((d) => d.id) };
    });
  },
};

export const scenarios = [liteRest];
