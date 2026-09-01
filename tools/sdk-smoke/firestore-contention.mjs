import { initializeApp } from "firebase-admin/app";
import { FieldValue, getFirestore } from "firebase-admin/firestore";

const app = initializeApp({ projectId: "demo-app" });
const db = getFirestore(app);
const clients = 20;
const counter = db.doc("contention/counter");
await counter.set({ value: 0 });

let firstReads = 0;
let releaseFirstReads;
const allFirstReads = new Promise((resolve) => {
  releaseFirstReads = resolve;
});

await Promise.all(
  Array.from({ length: clients }, (_, clientId) => {
    let attempt = 0;
    return db.runTransaction(async (transaction) => {
      const current = await transaction.get(counter);
      if (attempt++ === 0) {
        firstReads += 1;
        if (firstReads === clients) releaseFirstReads();
        await allFirstReads;
      }
      transaction.create(db.doc(`contention-items/client-${clientId}`), { clientId });
      transaction.update(counter, { value: current.data().value + 1, writes: FieldValue.increment(1) });
    });
  }),
);

const [counterSnapshot, items] = await Promise.all([
  counter.get(),
  db.collection("contention-items").get(),
]);
const result = {
  clients,
  counter: counterSnapshot.data().value,
  items: items.size,
};
console.log(JSON.stringify(result, null, 1));
process.exit(result.counter === clients && result.items === clients ? 0 : 1);
