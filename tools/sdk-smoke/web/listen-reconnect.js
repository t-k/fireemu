import {
  initializeApp,
  deleteApp,
} from "https://www.gstatic.com/firebasejs/12.18.0/firebase-app.js";
import {
  connectAuthEmulator,
  createUserWithEmailAndPassword,
  getAuth,
  inMemoryPersistence,
  setPersistence,
  signOut,
} from "https://www.gstatic.com/firebasejs/12.18.0/firebase-auth.js";
import {
  connectFirestoreEmulator,
  disableNetwork,
  doc,
  enableNetwork,
  getDocFromCache,
  getDocFromServer,
  initializeFirestore,
  onSnapshot,
  setDoc,
  terminate,
  waitForPendingWrites,
} from "https://www.gstatic.com/firebasejs/12.18.0/firebase-firestore.js";

const params = new URLSearchParams(location.search);
const project = params.get("project") || "demo-app";
const firestorePort = Number(params.get("fs"));
const authPort = Number(params.get("auth"));
const resultNode = document.getElementById("result");
const suffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
const email = `webchannel-listen-${suffix}@example.test`;
const password = "password123";
const events = [];

const bounded = async (operation, label, milliseconds = 10_000) => {
  let timer;
  try {
    return await Promise.race([
      Promise.resolve().then(operation),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out`)), milliseconds);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
};

const view = (snapshot) => ({
  exists: snapshot.exists(),
  revision: snapshot.data()?.revision ?? null,
  fromCache: snapshot.metadata.fromCache,
  hasPendingWrites: snapshot.metadata.hasPendingWrites,
});

const waitFor = (predicate, label) =>
  bounded(
    () =>
      new Promise((resolve, reject) => {
        const deadline = Date.now() + 10_000;
        const poll = () => {
          const value = predicate();
          if (value) return resolve(value);
          if (Date.now() >= deadline) return reject(new Error(`${label} timed out`));
          setTimeout(poll, 25);
        };
        poll();
      }),
    label,
  );

// Under the automated runner the control token never reaches this page: the
// runner exposes `__fireemuInstallRules(source)` and performs the PUT itself.
// Opened by hand, the page falls back to the `token` query parameter.
const installRules = async (source) => {
  if (typeof window.__fireemuInstallRules === "function") {
    const outcome = await window.__fireemuInstallRules(source);
    if (!outcome || outcome.ok !== true) {
      throw new Error(`rules load failed: ${outcome?.error ?? outcome?.status ?? "unknown"}`);
    }
    return;
  }
  const token = params.get("token") || "";
  const rulesResponse = await fetch(`http://127.0.0.1:${authPort}/v1/rules`, {
    method: "PUT",
    headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
    body: JSON.stringify({ source }),
  });
  if (!rulesResponse.ok) throw new Error(`rules load failed: ${rulesResponse.status}`);
};

const run = async () => {
  if (!Number.isInteger(firestorePort) || !Number.isInteger(authPort)) {
    throw new Error("fs and auth query parameters must be integer emulator ports");
  }
  const app = initializeApp({ projectId: project, apiKey: "fake-api-key" }, `webchannel-${suffix}`);
  const auth = getAuth(app);
  const firestore = initializeFirestore(app, { experimentalForceLongPolling: true });
  connectAuthEmulator(auth, `http://127.0.0.1:${authPort}`, { disableWarnings: true });
  connectFirestoreEmulator(firestore, "127.0.0.1", firestorePort);
  await setPersistence(auth, inMemoryPersistence);

  const rules =
    "rules_version = '2'; service cloud.firestore { match /databases/{database}/documents { match /webchannel-listen/{uid} { allow read, write: if request.auth != null && request.auth.uid == uid; } } }";
  await installRules(rules);

  const credential = await createUserWithEmailAndPassword(auth, email, password);
  const reference = doc(firestore, "webchannel-listen", credential.user.uid);
  const snapshots = [];
  let listenerError = null;
  let unsubscribe = () => {};
  try {
    await setDoc(reference, { revision: 0 });
    await waitForPendingWrites(firestore);
    const initial = new Promise((resolve, reject) => {
      unsubscribe = onSnapshot(
        reference,
        { includeMetadataChanges: true },
        (snapshot) => {
          const value = view(snapshot);
          snapshots.push(value);
          events.push({ event: "snapshot", value });
          if (value.revision === 0 && !value.fromCache && !value.hasPendingWrites) resolve();
        },
        (error) => {
          listenerError = { code: error?.code ?? null, message: error?.message ?? String(error) };
          events.push({ event: "listener-error", error: listenerError });
          reject(error);
        },
      );
    });
    await bounded(() => initial, "initial WebChannel snapshot");

    await disableNetwork(firestore);
    const pendingWrite = setDoc(reference, { revision: 1 });
    await waitFor(() => snapshots.some((snapshot) => snapshot.revision === 1), "pending snapshot");
    const pending = view(await getDocFromCache(reference));
    events.push({ event: "pending-cache", value: pending });
    await enableNetwork(firestore);
    await pendingWrite;
    await waitForPendingWrites(firestore);
    await waitFor(
      () =>
        snapshots.some(
          (snapshot) =>
            snapshot.revision === 1 && !snapshot.fromCache && !snapshot.hasPendingWrites,
        ),
      "reconnect acknowledgement",
    );
    const acknowledged = view(await getDocFromServer(reference));
    events.push({ event: "reconnect-ack", value: acknowledged });

    unsubscribe();
    const callbacksAtUnsubscribe = snapshots.length;
    await setDoc(reference, { revision: 2 });
    await waitForPendingWrites(firestore);
    await new Promise((resolve) => setTimeout(resolve, 100));
    const callbacksAfterUnsubscribe = snapshots.length - callbacksAtUnsubscribe;
    events.push({ event: "unsubscribe-check", callbacksAfterUnsubscribe });

    await signOut(auth);
    events.push({ event: "auth-switch", state: "signed-out" });
    const denied = await getDocFromServer(reference).then(
      () => false,
      (error) => error?.code === "permission-denied",
    );
    events.push({ event: "unauthenticated-read", denied });
    return {
      passed:
        listenerError === null &&
        pending.revision === 1 &&
        pending.fromCache === true &&
        pending.hasPendingWrites === true &&
        acknowledged.revision === 1 &&
        acknowledged.fromCache === false &&
        acknowledged.hasPendingWrites === false &&
        callbacksAfterUnsubscribe === 0 &&
        denied,
      transport: "browser-webchannel",
      sdkVersion: "12.18.0",
      snapshots,
      events,
    };
  } finally {
    unsubscribe();
    await signOut(auth).catch(() => {});
    await terminate(firestore).catch(() => {});
    await deleteApp(app).catch(() => {});
  }
};

run()
  .then((result) => {
    resultNode.textContent = JSON.stringify(result, null, 2);
    document.body.dataset.status = result.passed ? "passed" : "failed";
  })
  .catch((error) => {
    const result = {
      passed: false,
      transport: "browser-webchannel",
      error: error?.stack || String(error),
      events,
    };
    resultNode.textContent = JSON.stringify(result, null, 2);
    document.body.dataset.status = "failed";
  });
