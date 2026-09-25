// G3 local real client SDK smoke: Auth switching, rules refusal state, and listener teardown.
// The Node Firebase client uses Firestore's gRPC transport here; this is not a WebChannel test.

import assert from "node:assert/strict";

import { deleteApp, initializeApp } from "firebase/app";
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
  disableNetwork,
  doc,
  enableNetwork,
  getDoc,
  getDocFromServer,
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

const readServerDocument = async (path, idToken) => {
  const response = await fetch(`http://${firestoreUrl.host}/v1/projects/${project}/databases/(default)/documents/${path}`, {
    headers: { authorization: `Bearer ${idToken}` },
    signal: AbortSignal.timeout(5_000),
  });
  const body = await response.json();
  if (!response.ok) throw new Error(`server read failed: ${response.status} ${JSON.stringify(body)}`);
  return body;
};
const deleteServerDocument = async (path, idToken) => {
  const response = await fetch(`http://${firestoreUrl.host}/v1/projects/${project}/databases/(default)/documents/${path}`, { method: "DELETE", headers: { authorization: `Bearer ${idToken}` }, signal: AbortSignal.timeout(5_000) });
  if (!response.ok && response.status !== 404) throw new Error(`server delete failed: ${response.status}`);
};

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
  await sdk(setDoc(doc(db, "g3-denied", "reconnect"), { owner: uidA, revision: 0 }), "create reconnect protected state");
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

  const reconnectApp = initializeApp({ projectId: project, apiKey: "fake-api-key" }, `g3-reconnect-${suffix}`);
  const reconnectAuth = getAuth(reconnectApp);
  const reconnectDb = getFirestore(reconnectApp);
  connectAuthEmulator(reconnectAuth, authUrl.origin, { disableWarnings: true });
  connectFirestoreEmulator(reconnectDb, firestoreUrl.hostname, Number(firestoreUrl.port));
  let reconnectStop = () => {};
  results.reconnectAfterRejectedWrite = { originalClient: {}, cleanupComplete: false };
  const reconnectResult = results.reconnectAfterRejectedWrite.originalClient;
  try {
    await sdk(signInWithEmailAndPassword(reconnectAuth, emailB, password), "sign in reconnect client");
    const reconnectDoc = doc(reconnectDb, "g3-profiles", uidB);
    const reconnectSnapshots = [];
    reconnectResult.listenerSnapshots = reconnectSnapshots;
    const reconnectInitial = new Promise((resolve, reject) => {
      reconnectStop = onSnapshot(
        reconnectDoc,
        { includeMetadataChanges: true },
        (snapshot) => {
          reconnectSnapshots.push({ revision: snapshot.data()?.revision ?? null, fromCache: snapshot.metadata.fromCache, hasPendingWrites: snapshot.metadata.hasPendingWrites });
          if (!snapshot.metadata.fromCache && !snapshot.metadata.hasPendingWrites) resolve();
        },
        reject,
      );
    });
    await bounded(reconnectInitial, "reconnect listener initial callback");
    assert.deepEqual(reconnectSnapshots.at(-1), { revision: 1, fromCache: false, hasPendingWrites: false });
    const ownerToken = await sdk(credentialA.user.getIdToken(), "get owner ID token");
    const serverBefore = await sdk(readServerDocument("g3-denied/reconnect", ownerToken), "server state before reconnect refusal");
    reconnectResult.serverBefore = serverBefore;
    assert.equal(serverBefore.name, `projects/${project}/databases/(default)/documents/g3-denied/reconnect`);
    assert.deepEqual(serverBefore.fields, { owner: { stringValue: uidA }, revision: { integerValue: "0" } });
    let rejected;
    try {
      await sdk(setDoc(doc(reconnectDb, "g3-denied", "reconnect"), { owner: uidB, revision: 1 }), "rejected reconnect write");
    } catch (error) {
      rejected = { code: error?.code, message: error?.message };
    }
    reconnectResult.rejected = rejected ?? { unexpectedSuccess: true };
    if (rejected?.code !== "permission-denied") throw new Error(`expected permission-denied reconnect write, got ${JSON.stringify(rejected)}`);
    const serverAfterRejected = await sdk(readServerDocument("g3-denied/reconnect", ownerToken), "server state after reconnect refusal");
    reconnectResult.serverAfterRejected = serverAfterRejected;
    assert.deepEqual(serverAfterRejected, serverBefore, "rejected write changed full server document");
    await sdk(disableNetwork(reconnectDb), "disable network after rejected write");
    await sdk(enableNetwork(reconnectDb), "enable network after rejected write");
    const accepted = await sdk(setDoc(reconnectDoc, { owner: uidB, revision: 2 }), "accepted write after reconnect").then(() => true).catch((error) => ({ code: error?.code, message: error?.message }));
    reconnectResult.accepted = accepted;
    const pending = await sdk(waitForPendingWrites(reconnectDb), "pending writes after reconnect").then(() => true).catch((error) => ({ code: error?.code, message: error?.message }));
    reconnectResult.pending = pending;
    const profileAfterAccepted = await sdk(readServerDocument(`g3-profiles/${uidB}`, await sdk(reconnectAuth.currentUser.getIdToken(), "profile readback token")), "accepted profile server readback");
    reconnectResult.profileAfterAccepted = profileAfterAccepted;
    assert.equal(profileAfterAccepted.name, `projects/${project}/databases/(default)/documents/g3-profiles/${uidB}`);
    assert.deepEqual(profileAfterAccepted.fields, { owner: { stringValue: uidB }, revision: { integerValue: "2" } });
    const serverAfterAccepted = await sdk(readServerDocument("g3-denied/reconnect", ownerToken), "server state after reconnect write");
    Object.assign(reconnectResult, { serverAfterAccepted, accepted, pending });
    if (accepted !== true || pending !== true) throw new Error(`accepted/pending outcome mismatch: ${JSON.stringify({ accepted, pending })}`);
    assert.deepEqual(serverAfterAccepted, serverBefore, "profile write changed protected document");
    let listenerAcknowledged = false;
    try {
      await bounded(new Promise((resolve, reject) => {
        const deadline = Date.now() + 5_000;
        const check = () => {
          if (reconnectSnapshots.some((snapshot) => snapshot.revision === 2 && snapshot.fromCache === false && snapshot.hasPendingWrites === false)) return resolve();
          if (Date.now() >= deadline) return reject(new Error("listener acknowledgement timed out"));
          setTimeout(check, 25);
        };
        check();
      }), "listener acknowledgement after reconnect", 6_000);
      listenerAcknowledged = true;
    } catch (error) {
      listenerAcknowledged = { code: error?.code, message: error?.message };
    }
    reconnectResult.listenerAcknowledged = listenerAcknowledged;
    reconnectStop();

    const freshApp = initializeApp({ projectId: project, apiKey: "fake-api-key" }, `g3-reconnect-positive-${suffix}`);
    const freshAuth = getAuth(freshApp);
    const freshDb = getFirestore(freshApp);
    connectAuthEmulator(freshAuth, authUrl.origin, { disableWarnings: true });
    connectFirestoreEmulator(freshDb, firestoreUrl.hostname, Number(firestoreUrl.port));
    try {
      await sdk(signInWithEmailAndPassword(freshAuth, emailB, password), "sign in fresh reconnect client");
      const freshDoc = doc(freshDb, "g3-profiles", uidB);
      const freshRead = await sdk(getDocFromServer(freshDoc), "fresh client server read");
      await sdk(setDoc(freshDoc, { owner: uidB, revision: 3 }), "fresh client accepted write");
      await sdk(waitForPendingWrites(freshDb), "fresh client pending writes");
      assert.equal(freshRead.ref.path, `g3-profiles/${uidB}`);
      assert.deepEqual(freshRead.data(), { owner: uidB, revision: 2 });
      const freshInitialRevision = freshRead.data()?.revision ?? null;
      const freshAfter = await sdk(getDocFromServer(freshDoc), "fresh client server read after write");
      assert.equal(freshAfter.ref.path, `g3-profiles/${uidB}`);
      assert.deepEqual(freshAfter.data(), { owner: uidB, revision: 3 });
      const freshAfterRevision = freshAfter.data()?.revision ?? null;
      if (freshInitialRevision !== 2 || freshAfterRevision !== 3) throw new Error(`fresh client state mismatch: initial=${freshInitialRevision} after=${freshAfterRevision}`);
      results.reconnectAfterRejectedWrite.freshClientPositiveControl = { initialRevision: freshInitialRevision, acceptedRevision: freshAfterRevision, pendingWritesResolved: true };
    } finally {
      await signOut(freshAuth).catch(() => {});
      await deleteApp(freshApp).catch(() => {});
    }
    results.reconnectAfterRejectedWrite.originalClient.listenerAcknowledged = listenerAcknowledged;
    results.reconnectAfterRejectedWrite.originalClient.listenerSnapshots = reconnectSnapshots;
  } catch (error) {
    results.reconnectAfterRejectedWrite.error = { code: error?.code, message: error?.message };
  } finally {
    reconnectStop();
    try {
      await sdk(deleteServerDocument("g3-denied/reconnect", await sdk(credentialA.user.getIdToken(), "cleanup owner token")), "cleanup reconnect document");
      results.reconnectAfterRejectedWrite.cleanupComplete = true;
    } catch (error) {
      results.reconnectAfterRejectedWrite.cleanupError = { code: error?.code, message: error?.message };
    }
    await signOut(reconnectAuth).catch(() => {});
    await deleteApp(reconnectApp).catch(() => {});
  }
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

const reconnectPassed = results.reconnectAfterRejectedWrite?.cleanupComplete === true
  && !results.reconnectAfterRejectedWrite?.error
  && results.reconnectAfterRejectedWrite?.originalClient?.rejected?.code === "permission-denied"
  && results.reconnectAfterRejectedWrite?.originalClient?.accepted === true
  && results.reconnectAfterRejectedWrite?.originalClient?.pending === true
  && results.reconnectAfterRejectedWrite?.originalClient?.listenerAcknowledged === true
  && results.reconnectAfterRejectedWrite?.freshClientPositiveControl?.initialRevision === 2
  && results.reconnectAfterRejectedWrite?.freshClientPositiveControl?.acceptedRevision === 3;
console.log(JSON.stringify({ passed: reconnectPassed, transport: "firebase-client-node-grpc", ...results }, null, 2));
if (!reconnectPassed) process.exitCode = 1;
