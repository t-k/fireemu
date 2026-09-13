// G3 local real client SDK smoke: Auth switching, rules refusal state, and listener teardown.
// The Node Firebase client uses Firestore's gRPC transport here; this is not a WebChannel test.

import { initializeApp } from "firebase/app";
import {
  connectAuthEmulator,
  createUserWithEmailAndPassword,
  getAuth,
  onAuthStateChanged,
  signInWithEmailAndPassword,
  signOut,
} from "firebase/auth";
import {
  connectFirestoreEmulator,
  deleteDoc,
  doc,
  getDoc,
  getFirestore,
  onSnapshot,
  setDoc,
  waitForPendingWrites,
} from "firebase/firestore";

const project = process.env.GOOGLE_CLOUD_PROJECT ?? "demo-app";
const firestoreHost = process.env.FIRESTORE_EMULATOR_HOST;
const authHost = process.env.FIREBASE_AUTH_EMULATOR_HOST;
const controlUrl = process.env.FIREEMU_CONTROL_URL;
const controlToken = process.env.FIREEMU_CONTROL_TOKEN;
const suffix = `${Date.now()}-${process.pid}`;
const emailA = `g3-a-${suffix}@example.test`;
const emailB = `g3-b-${suffix}@example.test`;
const password = "password123";
const results = {};
const overallDeadline = Date.now() + 45_000;
const authEvents = [];
let currentUser = null;
let stopAuth = () => {};
let stopListener = () => {};
let uidA;
let uidB;
const rules = `
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /g3-profiles/{uid} {
      allow read, write: if request.auth != null && request.auth.uid == uid;
    }
    match /g3-denied/{id} {
      allow create: if request.auth != null && request.auth.uid == request.resource.data.owner;
      allow read, update, delete: if request.auth != null && request.auth.uid == resource.data.owner;
    }
  }
}`;

const loopbackOrigin = (value, name) => {
  if (!value) throw new Error(`${name} is required from owned runner`);
  const url = new URL(value.includes("://") ? value : `http://${value}`);
  if (url.protocol !== "http:" || url.hostname !== "127.0.0.1" || !url.port || url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
    throw new Error(`${name} must be a bare loopback origin`);
  }
  return url;
};
const firestoreUrl = loopbackOrigin(firestoreHost, "FIRESTORE_EMULATOR_HOST");
const authUrl = loopbackOrigin(authHost, "FIREBASE_AUTH_EMULATOR_HOST");
const control = new URL(controlUrl || "");
if (control.protocol !== "http:" || control.hostname !== "127.0.0.1" || !control.port || control.pathname !== "/v1/" || !controlToken) {
  throw new Error("owned control URL and token are required");
}
const identityResponse = await fetch(new URL("sessions/default/resources", control), {
  headers: { authorization: `Bearer ${controlToken}` },
  signal: AbortSignal.timeout(5_000),
});
if (!identityResponse.ok || (await identityResponse.json()).project !== project) {
  throw new Error("owned runner project identity mismatch");
}

const bounded = async (promise, label, milliseconds = 10_000) => {
  const remaining = overallDeadline - Date.now();
  if (remaining <= 0) throw new Error("G3 overall deadline exceeded");
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out`)), Math.min(milliseconds, remaining));
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
};

const expectDenied = async (operation) => {
  try {
    await bounded(operation(), "denied operation", 10_000);
  } catch (error) {
    if (error?.code === "permission-denied") return error.code;
    throw error;
  }
  throw new Error("expected permission-denied");
};
const sdk = (promise, label) => bounded(promise, label, 10_000);

const app = initializeApp({ projectId: project, apiKey: "fake-api-key" });
const auth = getAuth(app);
connectAuthEmulator(auth, authUrl.origin, { disableWarnings: true });
const db = getFirestore(app);
connectFirestoreEmulator(db, firestoreUrl.hostname, Number(firestoreUrl.port));
const rulesResponse = await fetch(new URL("v1/rules", authUrl), {
  method: "PUT",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ source: rules }),
  signal: AbortSignal.timeout(5_000),
});
if (!rulesResponse.ok) throw new Error(`PUT /v1/rules failed: ${rulesResponse.status}`);

const authReady = new Promise((resolve, reject) => {
  stopAuth = onAuthStateChanged(
    auth,
    (user) => {
      currentUser = user;
      authEvents.push(user ? { state: "signed-in", uid: user.uid } : { state: "signed-out" });
  if (authEvents.length >= 1) resolve();
    },
    reject,
  );
});

try {
  await bounded(authReady, "initial Auth state");
  await sdk(signOut(auth), "initial sign-out");
  const credentialA = await sdk(createUserWithEmailAndPassword(auth, emailA, password), "create user A");
  uidA = credentialA.user.uid;
  await sdk(setDoc(doc(db, "g3-profiles", uidA), { owner: uidA, revision: 0 }), "create A profile");
  await sdk(setDoc(doc(db, "g3-denied", "state"), { owner: uidA, revision: 0 }), "create protected state");
  await sdk(waitForPendingWrites(db), "flush A writes");
  await sdk(signOut(auth), "switch sign-out A");
  const credentialB = await sdk(createUserWithEmailAndPassword(auth, emailB, password), "create user B");
  uidB = credentialB.user.uid;
  await sdk(setDoc(doc(db, "g3-profiles", uidB), { owner: uidB, revision: 0 }), "create B profile");
  await sdk(waitForPendingWrites(db), "flush B writes");
  await expectDenied(() => setDoc(doc(db, "g3-denied", "state"), { owner: uidB, revision: 1 }));
  await sdk(signOut(auth), "switch sign-out B");
  await sdk(signInWithEmailAndPassword(auth, emailA, password), "sign in A");
  const afterDenied = await sdk(getDoc(doc(db, "g3-denied", "state")), "read protected state");
  results.deniedWritePostState = {
    error: "permission-denied",
    exists: afterDenied.exists(),
    data: afterDenied.data(),
  };
  await sdk(deleteDoc(doc(db, "g3-denied", "state")), "delete protected state");
  await sdk(waitForPendingWrites(db), "flush protected delete");
  await sdk(signOut(auth), "switch sign-out A");
  await sdk(signInWithEmailAndPassword(auth, emailB, password), "sign in B");
  const watched = doc(db, "g3-profiles", uidB);
  await sdk(setDoc(watched, { owner: uidB, revision: 0 }), "reset watched document");
  await sdk(waitForPendingWrites(db), "flush watched reset");
  const revisions = [];
  const replacementRevisions = [];
  let initial;
  const initialReady = new Promise((resolve, reject) => {
    initial = { resolve, reject };
  });
  stopListener = onSnapshot(
    watched,
    (snapshot) => {
      revisions.push(snapshot.data()?.revision ?? null);
      if (revisions.length === 1) {
        stopListener();
        initial.resolve();
      }
    },
    initial.reject,
  );
  await bounded(initialReady, "listener initial callback");
  let replacementResolve;
  let replacementReject;
  const replacementReady = new Promise((resolve, reject) => {
    replacementResolve = resolve;
    replacementReject = reject;
  });
  let replacementUpdateResolve;
  let replacementUpdateReject;
  const replacementUpdate = new Promise((resolve, reject) => {
    replacementUpdateResolve = resolve;
    replacementUpdateReject = reject;
  });
  stopListener = onSnapshot(
    watched,
    (snapshot) => {
      const revision = snapshot.data()?.revision ?? null;
      replacementRevisions.push(revision);
      if (replacementRevisions.length === 1) replacementResolve();
      if (revision === 1) replacementUpdateResolve();
    },
    (error) => {
      replacementReject(error);
      replacementUpdateReject(error);
    },
  );
  await bounded(replacementReady, "replacement listener initial callback");
  await sdk(setDoc(watched, { owner: uidB, revision: 1 }), "update watched document");
  await sdk(waitForPendingWrites(db), "flush watched update");
  await bounded(replacementUpdate, "replacement listener update");
  await new Promise((resolve) => setTimeout(resolve, 300));
  stopListener();
  results.unsubscribe = {
    revisions,
    replacementRevisions,
    callbacksAfterUnsubscribe: Math.max(0, revisions.length - 1),
  };
  results.authSwitch = { events: authEvents, finalState: currentUser ? "signed-in" : "signed-out" };
  if (revisions.length !== 1 || revisions[0] !== 0 || JSON.stringify(replacementRevisions) !== JSON.stringify([0, 1])) throw new Error("listener lifecycle mismatch");
  if (JSON.stringify(results.deniedWritePostState.data) !== JSON.stringify({ owner: uidA, revision: 0 })) throw new Error("denied write changed post-state");
  const expectedAuthPrefix = ["signed-out", `signed-in:${uidA}`, "signed-out", `signed-in:${uidB}`, "signed-out"];
  const actualAuthStates = authEvents.map((event) => event.uid ? `signed-in:${event.uid}` : "signed-out");
  let matched = 0;
  for (const state of actualAuthStates) {
    if (state === expectedAuthPrefix[matched]) matched += 1;
    if (matched === expectedAuthPrefix.length) break;
  }
  if (matched !== expectedAuthPrefix.length) throw new Error(`Auth A/B switch ordering mismatch: ${JSON.stringify(actualAuthStates)}`);
} finally {
  stopListener();
  if (currentUser?.uid === uidA) {
    await bounded(deleteDoc(doc(db, "g3-profiles", uidA)), "cleanup A profile", 5_000).catch(() => {});
  }
  if (currentUser?.uid === uidB) {
    await bounded(deleteDoc(doc(db, "g3-profiles", uidB)), "cleanup B profile", 5_000).catch(() => {});
  }
  await bounded(signOut(auth), "cleanup sign-out", 5_000).catch(() => {});
  stopAuth();
  if (results.authSwitch) results.authSwitch.finalState = currentUser ? "signed-in" : "signed-out";
}

if (results.authSwitch?.finalState !== "signed-out") throw new Error("Auth did not finish signed-out");

console.log(JSON.stringify({ passed: true, transport: "firebase-client-node-grpc", ...results }, null, 2));
