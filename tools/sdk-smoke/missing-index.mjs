// Missing-index smoke: the real `firebase` client SDK against a conservative
// firebase-testd that declares exactly one composite index
// (`tasks`: ownerId ASCENDING, createdAt DESCENDING).
//
// A query the index does not cover must reach the application as
// `failed-precondition` with the actionable diagnostic, and it must not take the
// Listen stream (or the WebChannel session) with it: the same client keeps working.
//
// Env: FIRESTORE_EMULATOR_HOST, GOOGLE_CLOUD_PROJECT (demo-app)
import { initializeApp } from "firebase/app";
import {
  getFirestore,
  connectFirestoreEmulator,
  collection,
  doc,
  setDoc,
  query,
  where,
  orderBy,
  getDocsFromServer,
  onSnapshot,
} from "firebase/firestore";

const project = process.env.GOOGLE_CLOUD_PROJECT ?? "demo-app";
const fsHost = process.env.FIRESTORE_EMULATOR_HOST ?? "127.0.0.1:8080";
const [fsAddr, fsPort] = fsHost.split(":");

const results = [];
async function check(name, fn) {
  try {
    results.push({ name, ok: true, extra: await fn() });
  } catch (e) {
    results.push({ name, ok: false, extra: (e && (e.code || e.message)) || String(e) });
  }
}

const app = initializeApp({ projectId: project, apiKey: "fake-api-key" });
const db = getFirestore(app);
connectFirestoreEmulator(db, fsAddr, Number(fsPort));

const uid = "u1";
await check("seed one task", async () => {
  await setDoc(doc(db, "tasks/t1"), {
    ownerId: uid,
    createdAt: "2026-08-29T12:00:00Z",
    updatedAt: "2026-08-29T12:30:00Z",
  });
  return "ok";
});

// The undeclared query: production answers FAILED_PRECONDITION and so must the daemon.
// Before the fix the SDK saw the Listen stream fail and reported `unavailable` instead.
await check("undeclared composite query rejects with failed-precondition", async () => {
  try {
    await getDocsFromServer(
      query(collection(db, "tasks"), where("ownerId", "==", uid), orderBy("updatedAt", "desc")),
    );
  } catch (e) {
    if (e.code !== "failed-precondition") {
      throw new Error(`expected failed-precondition, got ${e.code}: ${e.message}`);
    }
    if (!e.message.includes("The query requires an index.")) {
      throw new Error(`the actionable diagnostic is missing: ${e.message}`);
    }
    if (!e.message.includes("firestore.indexes.json")) {
      throw new Error(`the firestore.indexes.json fragment is missing: ${e.message}`);
    }
    return "failed-precondition";
  }
  throw new Error("expected the undeclared query to be rejected");
});

// The rejection was target-scoped: the same client still serves the covered query.
await check("the declared query still succeeds on the same client", async () => {
  const snap = await getDocsFromServer(
    query(collection(db, "tasks"), where("ownerId", "==", uid), orderBy("createdAt", "desc")),
  );
  if (snap.size !== 1) throw new Error(`expected 1 document, got ${snap.size}`);
  return snap.docs.map((d) => d.id);
});

await check("a live listener on the same client reaches a snapshot", async () => {
  const seen = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("no snapshot within 5 s")), 5000);
    const unsub = onSnapshot(
      query(collection(db, "tasks"), where("ownerId", "==", uid), orderBy("createdAt", "desc")),
      (snap) => {
        clearTimeout(timer);
        unsub();
        resolve(snap.docs.map((d) => d.id));
      },
      (e) => {
        clearTimeout(timer);
        unsub();
        reject(e);
      },
    );
  });
  return seen;
});

// The browser transport, which the Node build of the SDK never takes: the failing
// AddTarget rides along with the WebChannel handshake, so the session has to stay open
// until the first back channel can carry the cause. A closed session answers the back
// channel with `Unknown SID`, which the browser SDK reports as `unavailable`.
await check("the WebChannel handshake target is refused without closing the session", async () => {
  const database = `projects/${project}/databases/(default)`;
  const addTarget = JSON.stringify({
    database,
    addTarget: {
      targetId: 41,
      query: {
        parent: `${database}/documents`,
        structuredQuery: {
          from: [{ collectionId: "tasks" }],
          where: {
            fieldFilter: {
              field: { fieldPath: "ownerId" },
              op: "EQUAL",
              value: { stringValue: uid },
            },
          },
          orderBy: [{ field: { fieldPath: "updatedAt" }, direction: "DESCENDING" }],
        },
      },
    },
  });
  const base = `http://${fsHost}/google.firestore.v1.Firestore/Listen/channel`;
  const open = await fetch(
    `${base}?database=${encodeURIComponent(database)}&VER=8&RID=1&CVER=22`,
    {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        count: "1",
        ofs: "0",
        req0___data__: addTarget,
      }).toString(),
    },
  );
  if (!open.ok) throw new Error(`handshake failed: ${open.status} ${await open.text()}`);
  const sid = open.headers.get("x-http-session-id");
  await open.text();
  if (!sid) throw new Error("the handshake carried no session id");
  const back = await fetch(
    `${base}?SID=${encodeURIComponent(sid)}&RID=rpc&AID=0&CI=1&TYPE=xmlhttp`,
    { method: "GET" },
  );
  const body = await back.text();
  if (!back.ok || body.includes("Unknown SID")) {
    throw new Error(`the session was closed before the back channel: ${back.status} ${body}`);
  }
  if (!body.includes('"REMOVE"') || !body.includes("The query requires an index.")) {
    throw new Error(`the back channel did not carry the target removal: ${body}`);
  }
  return "REMOVE with the index diagnostic";
});

console.log(JSON.stringify(results, null, 1));
process.exit(results.every((r) => r.ok) ? 0 : 1);
