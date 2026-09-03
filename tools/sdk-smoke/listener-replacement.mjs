import { initializeApp } from "firebase/app";
import {
  collection,
  connectFirestoreEmulator,
  doc,
  initializeFirestore,
  onSnapshot,
  query,
  setDoc,
  waitForPendingWrites,
  where,
} from "firebase/firestore";
import { deferred, requireNode20 } from "./listener-runtime-compat.mjs";

requireNode20();

const [host, port] = process.env.FIRESTORE_EMULATOR_HOST.split(":");
const app = initializeApp({ projectId: process.env.GOOGLE_CLOUD_PROJECT ?? "demo-app" });
const db = initializeFirestore(app, { experimentalForceLongPolling: true });
connectFirestoreEmulator(db, host, Number(port));
const bounded = async (promise, label) => {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out`)), 10_000);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
};
const item = doc(db, "listener-replacement/item");
await setDoc(item, { group: "one", revision: 0 });
await waitForPendingWrites(db);
const replacementQuery = query(collection(db, "listener-replacement"), where("group", "==", "one"));

const firstValues = [];
const firstInitial = deferred();
let unsubscribeFirst = () => {};
const replacementValues = [];
const replacementInitial = deferred();
const replacementUpdate = deferred();
let unsubscribeReplacement = () => {};
try {
  unsubscribeFirst = onSnapshot(
    replacementQuery,
    (snapshot) => {
      const values = snapshot.docs.map((candidate) => candidate.get("revision"));
      firstValues.push(values);
      if (values.includes(0)) {
        unsubscribeFirst();
        firstInitial.resolve();
      }
    },
    firstInitial.reject,
  );
  await bounded(firstInitial.promise, "initial listener");

  unsubscribeReplacement = onSnapshot(
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
  await bounded(replacementInitial.promise, "replacement initial snapshot");
  await setDoc(item, { group: "one", revision: 1 });
  await waitForPendingWrites(db);
  await bounded(replacementUpdate.promise, "replacement update snapshot");
  await new Promise((resolve) => setTimeout(resolve, 250));
} finally {
  unsubscribeFirst();
  unsubscribeReplacement();
}

const passed =
  JSON.stringify(firstValues) === JSON.stringify([[0]]) &&
  JSON.stringify(replacementValues) === JSON.stringify([[0], [1]]);
console.log(
  JSON.stringify(
    { passed, transport: "force-long-polling", firstValues, replacementValues },
    null,
    2,
  ),
);
process.exit(passed ? 0 : 1);
