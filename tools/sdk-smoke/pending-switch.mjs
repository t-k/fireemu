import assert from "node:assert/strict";
import { deleteApp, getApps, initializeApp } from "firebase/app";
import { connectAuthEmulator, createUserWithEmailAndPassword, getAuth, signOut } from "firebase/auth";
import { connectFirestoreEmulator, disableNetwork, doc, enableNetwork, getDocFromCache, getDocFromServer, getFirestore, onSnapshot, setDoc, terminate } from "firebase/firestore";

const project = process.env.GOOGLE_CLOUD_PROJECT ?? "demo-app";
const fsUrl = new URL(`http://${process.env.FIRESTORE_EMULATOR_HOST}`);
const authUrl = new URL(`http://${process.env.FIREBASE_AUTH_EMULATOR_HOST}`);
// This probe installs rules and must only target a disposable local emulator.
for (const url of [fsUrl, authUrl]) assert.ok(["127.0.0.1", "localhost", "[::1]"].includes(url.hostname), "local emulator required");
const suffix = `${Date.now()}-${process.pid}`;
const password = "password123";
let deadline = Date.now() + 30_000;
const errorValue = (error) => ({ code: error?.code ?? null, message: error?.message ?? String(error) });
const bounded = async (operation, label, ms = 5_000) => {
  const remaining = Math.min(ms, deadline - Date.now());
  if (remaining <= 0) throw new Error(`${label}: overall deadline exceeded`);
  let timer;
  try {
    return await Promise.race([Promise.resolve().then(operation), new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${label} timed out`)), remaining);
    })]);
  } finally { clearTimeout(timer); }
};
const request = async (url, options = {}) => {
  const ms = Math.min(5_000, deadline - Date.now());
  if (ms <= 0) throw new Error("HTTP deadline exceeded");
  const timeout = AbortSignal.timeout(ms);
  const response = await fetch(url, { ...options, signal: options.signal ? AbortSignal.any([options.signal, timeout]) : timeout });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null };
};
const server = (uid, token, method = "GET", value, signal) => request(
  new URL(`/v1/projects/${project}/databases/(default)/documents/pending-switch/${uid}`, fsUrl),
  { method, signal, headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, ...(value ? { body: JSON.stringify(value) } : {}) },
);
const view = (snap) => ({ exists: snap.exists(), owner: snap.data()?.owner ?? null, revision: snap.data()?.revision ?? null, fromCache: snap.metadata.fromCache, hasPendingWrites: snap.metadata.hasPendingWrites });
const expected = (owner, revision, hasPendingWrites, fromCache = true) => ({ exists: true, owner, revision, fromCache, hasPendingWrites });
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const app = initializeApp({ projectId: project, apiKey: "fake-api-key" }, `g3-pending-${suffix}`);
const auth = getAuth(app);
connectAuthEmulator(auth, authUrl.origin, { disableWarnings: true });
const db = getFirestore(app);
connectFirestoreEmulator(db, fsUrl.hostname, Number(fsUrl.port));
const result = {
  operationSequence: ["seed A", "disable network", "listen to A", "queue one A write", "sign out A", "create/sign in B", "enable network", "await A listener terminal error", "observe original promise", "verify A/B authorization and A state", "normal B offline/reconnect control", "cleanup"],
  writePromise: {}, cache: {}, listener: { snapshots: [], errors: [] }, server: {}, cleanup: { errors: [] },
};
// This unref'ed guard only fires if an operation/resource prevents natural exit.
setTimeout(() => {
  result.cleanup.errors.push({ operation: "process exit", message: "55-second process deadline exceeded" });
  console.log(JSON.stringify({ passed: false, evidence: "partial", ...result }, null, 2));
  process.exit(1);
}, 55_000).unref();
let unsubscribe = () => {};
let uidA;
let uidB;
let tokenA;
let tokenB;
let writeState = { status: "not-dispatched" };
let phase = "setup";
let callbacks = 0;
let terminal = false;
let resolveSnapshot;
let resolveTerminal;
const terminalEvent = new Promise((resolve) => { resolveTerminal = resolve; });
const waitSnapshotCount = async (count) => {
  if (result.listener.snapshots.length >= count) return;
  await bounded(() => new Promise((resolve) => { resolveSnapshot = resolve; }), `listener snapshot ${count}`);
  assert.equal(result.listener.snapshots.length, count);
};
const assertAUnchanged = (response) => {
  assert.equal(response.status, 200);
  assert.deepEqual(response.body.fields, { owner: { stringValue: uidA }, revision: { integerValue: "0" } });
};
try {
  const rules = "rules_version = '2'; service cloud.firestore { match /databases/{database}/documents { match /pending-switch/{uid} { allow read, write: if request.auth != null && request.auth.uid == uid; } } }";
  const rulesResponse = await request(new URL("v1/rules", authUrl), { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ source: rules }) });
  assert.equal(rulesResponse.status, 200);
  await bounded(() => signOut(auth), "initial sign-out");
  const a = await bounded(() => createUserWithEmailAndPassword(auth, `g3-pending-a-${suffix}@example.test`, password), "create A");
  uidA = a.user.uid;
  tokenA = await bounded(() => a.user.getIdToken(), "get A token");
  const refA = doc(db, "pending-switch", uidA);
  await bounded(() => setDoc(refA, { owner: uidA, revision: 0 }), "seed A");
  await bounded(() => disableNetwork(db), "disable network");
  phase = "offline-A";
  unsubscribe = onSnapshot(refA, { includeMetadataChanges: true }, (snap) => {
    callbacks++;
    result.listener.snapshots.push({ phase, ...view(snap) });
    resolveSnapshot?.();
    resolveSnapshot = undefined;
  }, (error) => {
    callbacks++;
    terminal = true;
    const event = { phase, ...errorValue(error) };
    result.listener.errors.push(event);
    resolveTerminal(event);
  });
  await waitSnapshotCount(1);
  result.cache.initial = view(await bounded(() => getDocFromCache(refA), "initial cache"));
  assert.deepEqual(result.cache.initial, expected(uidA, 0, false));
  writeState = { status: "pending" };
  // Exactly one write is dispatched in the fixed A-to-B switch interval.
  const originalWrite = setDoc(refA, { owner: uidA, revision: 1 }).then(
    () => { writeState = { status: "resolved" }; return writeState; },
    (error) => { writeState = { status: "rejected", ...errorValue(error) }; return writeState; },
  );
  await waitSnapshotCount(2);
  result.cache.pendingA = view(await bounded(() => getDocFromCache(refA), "pending A cache"));
  assert.deepEqual(result.cache.pendingA, expected(uidA, 1, true));
  result.writePromise.beforeSwitch = { ...writeState };
  assert.equal(writeState.status, "pending");
  phase = "sign-out-A";
  const callbacksAtSignOut = callbacks;
  await bounded(() => signOut(auth), "sign out A");
  await bounded(() => delay(100), "listener quiet after sign out");
  assert.equal(callbacks, callbacksAtSignOut, "listener emitted during the sign-out transition");
  result.listener.signOutQuietWindow = { windowMs: 100, callbacks: 0 };
  phase = "sign-in-B";
  const b = await bounded(() => createUserWithEmailAndPassword(auth, `g3-pending-b-${suffix}@example.test`, password), "create B");
  uidB = b.user.uid;
  tokenB = await bounded(() => b.user.getIdToken(), "get B token");
  result.switch = { uidA, uidB, finalAuth: auth.currentUser?.uid };
  assert.notEqual(uidA, uidB);
  assert.equal(result.switch.finalAuth, uidB);
  result.writePromise.afterSwitch = { ...writeState };
  assert.equal(writeState.status, "pending");
  phase = "reconnect-B";
  await bounded(() => enableNetwork(db), "enable network");
  const listenerOutcome = await bounded(() => terminalEvent, "A listener terminal error after reconnect");
  assert.equal(listenerOutcome.code, "permission-denied");
  assert.equal(listenerOutcome.phase, "reconnect-B");
  result.listener.lifecycle = "terminal-permission-denied";
  result.server.afterReconnectA = await server(uidA, tokenA);
  assertAUnchanged(result.server.afterReconnectA);
  const observationMs = 1_000;
  const observationStarted = Date.now();
  let observationTimer;
  let observation;
  try {
    observation = await bounded(() => Promise.race([originalWrite, new Promise((resolve) => {
      observationTimer = setTimeout(() => resolve({ status: "pendingAfterReconnectWindow" }), observationMs);
    })]), "post-reconnect promise observation", observationMs + 1_000);
  } finally { clearTimeout(observationTimer); }
  result.writePromise.observation = { afterReconnect: true, windowMs: observationMs, elapsedMs: Date.now() - observationStarted, ...observation };
  assert.equal(result.writePromise.observation.afterReconnect, true, "pending promise must be observed after reconnect");
  assert.equal(observation.status, "pendingAfterReconnectWindow", "this bounded local scenario expects an unresolved former-user promise");
  assert.equal(writeState.status, "pending");
  result.cache.afterReconnectB = view(await bounded(() => getDocFromCache(refA), "B cache after reconnect"));
  assert.deepEqual(result.cache.afterReconnectB, expected(uidA, 0, false));
  result.server.bReadA = await server(uidA, tokenB);
  assert.equal(result.server.bReadA.status, 403);
  result.server.bWriteA = await server(uidA, tokenB, "PATCH", { fields: { owner: { stringValue: uidB }, revision: { integerValue: "2" } } });
  assert.equal(result.server.bWriteA.status, 403);
  result.server.afterObservationA = await server(uidA, tokenA);
  assertAUnchanged(result.server.afterObservationA);
  const refB = doc(db, "pending-switch", uidB);
  phase = "normal-B-control";
  await bounded(() => disableNetwork(db), "disable B control network");
  let controlState = "pending";
  const controlWrite = setDoc(refB, { owner: uidB, revision: 0 }).then(() => { controlState = "resolved"; }, (error) => { controlState = "rejected"; return errorValue(error); });
  const offlineB = view(await bounded(() => getDocFromCache(refB), "B control offline cache"));
  assert.deepEqual(offlineB, expected(uidB, 0, true));
  assert.equal(controlState, "pending");
  await bounded(() => enableNetwork(db), "reconnect B control");
  await bounded(() => controlWrite, "normal B control write");
  assert.equal(controlState, "resolved");
  const onlineB = view(await bounded(() => getDocFromServer(refB), "normal B control server read"));
  assert.deepEqual(onlineB, expected(uidB, 0, false, false));
  result.normalControl = { offline: offlineB, online: onlineB, writePromise: controlState };
  result.server.afterControlA = await server(uidA, tokenA);
  assertAUnchanged(result.server.afterControlA);
  assert.equal(auth.currentUser?.uid, uidB);
  result.switch.finalAuth = auth.currentUser.uid;
  assert.equal(writeState.status, "pending");
  assert.equal(result.listener.errors.length, 1);
  assert.deepEqual(result.listener.snapshots, [
    { phase: "offline-A", ...expected(uidA, 0, false) },
    { phase: "offline-A", ...expected(uidA, 1, true) },
  ]);
  const terminalCallbacks = callbacks;
  await bounded(() => delay(100), "terminal listener quiet window");
  assert.equal(callbacks, terminalCallbacks, "terminal listener emitted another callback");
  result.listener.quietAfterTerminal = { windowMs: 100, callbacks: 0 };
} catch (error) {
  result.error = errorValue(error);
} finally {
  // Cleanup gets its own finite budget even if the scenario deadline expired.
  deadline = Date.now() + 25_000;
  phase = "cleanup";
  const clean = async (label, operation) => {
    const controller = new AbortController();
    try { return await bounded(() => operation(controller.signal), label, 3_000); }
    catch (error) { result.cleanup.errors.push({ operation: label, ...errorValue(error) }); return null; }
    finally { controller.abort(); }
  };
  const callbacksAtUnsubscribe = callbacks;
  await clean("unsubscribe listener", () => { unsubscribe(); result.cleanup.listenerUnsubscribed = true; });
  await clean("disable network", () => disableNetwork(db));
  await clean("sign out", async () => { await signOut(auth); assert.equal(auth.currentUser, null); result.cleanup.signedOut = true; });
  for (const [identity, uid, token] of [["A", uidA, tokenA], ["B", uidB, tokenB]]) {
    if (!uid) continue;
    await clean(`delete and verify ${identity} document`, async (signal) => {
      assert.ok(token, `missing ${identity} cleanup token`);
      const deleted = await server(uid, token, "DELETE", undefined, signal);
      assert.ok([200, 204, 404].includes(deleted.status), `delete ${identity}: HTTP ${deleted.status}`);
      const absent = await server(uid, token, "GET", undefined, signal);
      result.cleanup[identity] = { deletedStatus: deleted.status, absenceStatus: absent.status };
      assert.equal(absent.status, 404, `${identity} document remains`);
    });
  }
  result.writePromise.beforeTermination = { ...writeState };
  await clean("terminate Firestore", async () => { await terminate(db); result.cleanup.firestoreTerminated = true; });
  await clean("delete app", async () => { await deleteApp(app); assert.ok(!getApps().includes(app)); result.cleanup.appDeleted = true; });
  await clean("listener quiet after unsubscribe", async () => {
    await delay(100);
    assert.equal(callbacks, callbacksAtUnsubscribe);
    result.cleanup.listenerQuiet = { windowMs: 100, callbacks: 0, terminalBeforeUnsubscribe: terminal };
  });
  result.writePromise.afterTermination = { ...writeState };
}
const passed = !result.error && result.cleanup.errors.length === 0;
console.log(JSON.stringify({ passed, evidence: passed ? "bounded-local-observation" : "partial", transport: "firebase-client-node-grpc", ...result }, null, 2));
if (!passed) process.exitCode = 1;
