import { initializeApp } from "https://www.gstatic.com/firebasejs/12.4.0/firebase-app.js";
import {
  connectAuthEmulator,
  createUserWithEmailAndPassword,
  getAuth,
  inMemoryPersistence,
  onAuthStateChanged,
  setPersistence,
  signOut,
} from "https://www.gstatic.com/firebasejs/12.4.0/firebase-auth.js";
import {
  collection,
  connectFirestoreEmulator,
  doc,
  getDoc,
  getFirestore,
  onSnapshot,
  query,
  setDoc,
  waitForPendingWrites,
  where,
} from "https://www.gstatic.com/firebasejs/12.4.0/firebase-firestore.js";

const params = new URLSearchParams(location.search);
const firestorePort = Number(params.get("fs"));
const authPort = Number(params.get("auth"));
const projectId = params.get("project") || "demo-app";
const resultNode = document.getElementById("result");
const appNode = document.getElementById("app");
const diagnostics = window.__listenerLifecycle;
const events = diagnostics.ledger;
const activeSubscriptions = new Map();
const callbackAfterUnsubscribe = [];
let subscriptionOrdinal = 0;

const record = (event, fields = {}) => events.push({ event, ...fields });
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
const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
};
const renderRouteTree = (treeId, label) => {
  const form = document.createElement("form");
  form.dataset.settingForm = treeId;
  const heading = document.createElement("h1");
  heading.textContent = "Listener lifecycle settings";
  const output = document.createElement("output");
  output.textContent = label;
  form.append(heading, output);
  appNode.dataset.routeTree = treeId;
  appNode.replaceChildren(form);
  diagnostics.sample(`mount-${treeId}`);
};
const subscribe = (label, reference, values, valueOf, ready) => {
  const ordinal = ++subscriptionOrdinal;
  activeSubscriptions.set(ordinal, true);
  record("subscribe", { label, ordinal });
  const unsubscribe = onSnapshot(
    reference,
    (snapshot) => {
      if (!activeSubscriptions.get(ordinal)) callbackAfterUnsubscribe.push({ label, ordinal });
      const value = valueOf(snapshot);
      values.push(value);
      record("callback", { label, ordinal, callbackOrdinal: values.length, value });
      ready.resolve();
    },
    ready.reject,
  );
  return () => {
    if (!activeSubscriptions.get(ordinal)) return;
    activeSubscriptions.set(ordinal, false);
    record("unsubscribe", { label, ordinal });
    unsubscribe();
  };
};

const run = async () => {
  if (!Number.isInteger(firestorePort) || !Number.isInteger(authPort)) {
    throw new Error("The fs and auth query parameters must contain emulator ports");
  }
  const firebaseApp = initializeApp({ projectId, apiKey: "fake-api-key" });
  const auth = getAuth(firebaseApp);
  connectAuthEmulator(auth, `http://127.0.0.1:${authPort}`, { disableWarnings: true });
  await setPersistence(auth, inMemoryPersistence);
  await signOut(auth);
  const db = getFirestore(firebaseApp);
  connectFirestoreEmulator(db, "127.0.0.1", firestorePort);

  const authReady = deferred();
  let authOrdinal = 0;
  const stopAuth = onAuthStateChanged(auth, (user) => {
    authOrdinal += 1;
    record("auth", { ordinal: authOrdinal, state: user ? "signed-in" : "signed-out" });
    if (user) authReady.resolve(user);
  }, authReady.reject);
  const credential = await createUserWithEmailAndPassword(
    auth,
    `listener-${Date.now()}-${Math.random().toString(16).slice(2)}@example.test`,
    "password123",
  );
  const user = await bounded(authReady.promise, "auth readiness");
  if (user.uid !== credential.user.uid) throw new Error("Auth readiness changed identity");

  const userRef = doc(db, "lifecycle-users", user.uid);
  const projectRef = doc(db, "lifecycle-projects", user.uid);
  const mailRef = doc(db, "lifecycle-mail", user.uid);
  const destinations = query(
    collection(db, "lifecycle-destinations", user.uid, "items"),
    where("enabled", "==", true),
  );
  await Promise.all([
    setDoc(userRef, { revision: 0 }),
    setDoc(projectRef, { revision: 0 }),
    setDoc(mailRef, { revision: 0 }),
    setDoc(doc(db, "lifecycle-destinations", user.uid, "items", "primary"), {
      enabled: true,
      revision: 0,
    }),
  ]);
  await waitForPendingWrites(db);

  renderRouteTree("client-1", "Authenticated client state");
  const shellUserValues = [];
  const pageUserValues = [];
  const firstProjectValues = [];
  const firstDestinationSizes = [];
  const shellReady = deferred();
  const pageReady = deferred();
  const projectReady = deferred();
  const destinationReady = deferred();
  const stopShellUser = subscribe(
    "shell-user",
    userRef,
    shellUserValues,
    (snapshot) => snapshot.data()?.revision ?? null,
    shellReady,
  );
  let stopPageUser = subscribe(
    "page-user-1",
    userRef,
    pageUserValues,
    (snapshot) => snapshot.data()?.revision ?? null,
    pageReady,
  );
  let stopProject = subscribe(
    "project-1",
    projectRef,
    firstProjectValues,
    (snapshot) => snapshot.data()?.revision ?? null,
    projectReady,
  );
  let stopDestinations = subscribe(
    "destinations-1",
    destinations,
    firstDestinationSizes,
    (snapshot) => snapshot.size,
    destinationReady,
  );
  await bounded(
    Promise.all([
      shellReady.promise,
      pageReady.promise,
      projectReady.promise,
      destinationReady.promise,
    ]),
    "initial subscriptions",
  );
  record("one-shot", { label: "mail", revision: (await getDoc(mailRef)).data()?.revision ?? null });

  stopPageUser();
  stopProject();
  stopDestinations();
  diagnostics.sample("unmount-client-1");
  renderRouteTree("client-2", "Replacement client state");

  const replacementUserValues = [];
  const replacementProjectValues = [];
  const replacementDestinationSizes = [];
  const replacementUserReady = deferred();
  const replacementProjectReady = deferred();
  const replacementProjectUpdated = deferred();
  const replacementDestinationReady = deferred();
  stopPageUser = subscribe(
    "page-user-2",
    userRef,
    replacementUserValues,
    (snapshot) => snapshot.data()?.revision ?? null,
    replacementUserReady,
  );
  stopProject = subscribe(
    "project-2",
    projectRef,
    replacementProjectValues,
    (snapshot) => {
      const revision = snapshot.data()?.revision ?? null;
      if (revision === 1) replacementProjectUpdated.resolve();
      return revision;
    },
    replacementProjectReady,
  );
  stopDestinations = subscribe(
    "destinations-2",
    destinations,
    replacementDestinationSizes,
    (snapshot) => snapshot.size,
    replacementDestinationReady,
  );
  await bounded(
    Promise.all([
      replacementUserReady.promise,
      replacementProjectReady.promise,
      replacementDestinationReady.promise,
    ]),
    "replacement subscriptions",
  );
  await setDoc(projectRef, { revision: 1 });
  await waitForPendingWrites(db);
  await bounded(replacementProjectUpdated.promise, "replacement update");
  await new Promise((resolve) => setTimeout(resolve, 250));

  stopPageUser();
  stopProject();
  stopDestinations();
  stopShellUser();
  stopAuth();
  await signOut(auth);
  diagnostics.sample("settled");
  diagnostics.observer.disconnect();

  const summary = {
    passed:
      diagnostics.maximumConnectedForms() === 1 &&
      callbackAfterUnsubscribe.length === 0 &&
      JSON.stringify(firstProjectValues) === JSON.stringify([0]) &&
      JSON.stringify(replacementProjectValues) === JSON.stringify([0, 1]),
    maximumConnectedForms: diagnostics.maximumConnectedForms(),
    callbackAfterUnsubscribe,
    values: {
      shellUser: shellUserValues,
      pageUser: pageUserValues,
      firstProject: firstProjectValues,
      firstDestinationSizes,
      replacementUser: replacementUserValues,
      replacementProject: replacementProjectValues,
      replacementDestinationSizes,
    },
    eventCount: events.length,
    events,
  };
  window.__listenerLifecycleResult = summary;
  document.body.dataset.status = summary.passed ? "passed" : "failed";
  resultNode.textContent = JSON.stringify(summary, null, 2);
};

run().catch((error) => {
  diagnostics.observer.disconnect();
  const summary = { passed: false, error: error?.stack || String(error), events };
  window.__listenerLifecycleResult = summary;
  document.body.dataset.status = "failed";
  resultNode.textContent = JSON.stringify(summary, null, 2);
});
