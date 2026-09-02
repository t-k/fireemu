import { initializeApp } from "firebase/app";
import {
  collection,
  connectFirestoreEmulator,
  doc,
  getFirestore,
  onSnapshot,
  query,
  setDoc,
  waitForPendingWrites,
  where,
} from "firebase/firestore";

const [host, port] = process.env.FIRESTORE_EMULATOR_HOST.split(":");
const app = initializeApp({ projectId: process.env.GOOGLE_CLOUD_PROJECT ?? "demo-app" });
const db = getFirestore(app);
connectFirestoreEmulator(db, host, Number(port));
const item = doc(db, "listener-replacement/item");
await setDoc(item, { group: "one", revision: 0 });
await waitForPendingWrites(db);
const replacementQuery = query(
  collection(db, "listener-replacement"),
  where("group", "==", "one"),
);

const firstValues = [];
const firstInitial = Promise.withResolvers();
const unsubscribeFirst = onSnapshot(
  replacementQuery,
  (snapshot) => {
    const values = snapshot.docs.map((candidate) => candidate.get("revision"));
    firstValues.push(values);
    firstInitial.resolve();
  },
  firstInitial.reject,
);
await firstInitial.promise;
unsubscribeFirst();

const replacementValues = [];
const replacementInitial = Promise.withResolvers();
const replacementUpdate = Promise.withResolvers();
const unsubscribeReplacement = onSnapshot(
  replacementQuery,
  (snapshot) => {
    const values = snapshot.docs.map((candidate) => candidate.get("revision"));
    replacementValues.push(values);
    if (values.includes(0)) replacementInitial.resolve();
    if (values.includes(1)) replacementUpdate.resolve();
  },
  (error) => {
    replacementInitial.reject(error);
    replacementUpdate.reject(error);
  },
);
await replacementInitial.promise;
await setDoc(item, { group: "one", revision: 1 });
await waitForPendingWrites(db);
await replacementUpdate.promise;
await new Promise((resolve) => setTimeout(resolve, 50));
unsubscribeReplacement();

const passed =
  JSON.stringify(firstValues) === JSON.stringify([[0]]) &&
  JSON.stringify(replacementValues) === JSON.stringify([[0], [1]]);
console.log(JSON.stringify({ passed, firstValues, replacementValues }, null, 2));
process.exit(passed ? 0 : 1);
