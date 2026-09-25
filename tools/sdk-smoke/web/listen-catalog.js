// Browser side of the FS-LISTEN-SDK catalog: the same collector the Node lane
// runs (`tools/compat-broad/fs-listen-resume/listen_collector.mjs`, served
// byte-identical under `/collector/`) driven through the browser build of the
// pinned firebase JS SDK, whose Firestore transport is WebChannel.
//
// This file mirrors `createDeps` and `executeLocalLifecycle` from
// `listen_sdk_adapter.mjs`. Everything the page cannot do from a browser origin
// (account lookup and deletion through the emulator's management route, the
// responsibility journal, the receipt) stays in the Node runner, which calls
// `window.__o6RunCatalog(config)` and reads the returned plain object.
//
// The throwaway account password arrives inside `config`, in memory, and is
// never placed in the URL, the DOM or the returned result.

import {
  deleteApp,
  initializeApp,
  SDK_VERSION,
} from "https://www.gstatic.com/firebasejs/12.18.0/firebase-app.js";
import {
  connectAuthEmulator,
  createUserWithEmailAndPassword,
  getAuth,
  inMemoryPersistence,
  setPersistence,
  signInWithEmailAndPassword,
  signOut,
} from "https://www.gstatic.com/firebasejs/12.18.0/firebase-auth.js";
import {
  collection,
  connectFirestoreEmulator,
  deleteDoc,
  disableNetwork,
  doc,
  enableNetwork,
  getDocFromServer,
  initializeFirestore,
  limit,
  onSnapshot,
  orderBy,
  query,
  runTransaction,
  setDoc,
  terminate,
  where,
} from "https://www.gstatic.com/firebasejs/12.18.0/firebase-firestore.js";
import {
  classifyCleanup,
  createBudget,
  createRecoveryBudget,
  ownedPaths,
  runCatalog,
  runCleanup,
  secondaryPaths,
} from "/collector/listen_collector.mjs";

const resultNode = document.getElementById("result");

// Transport selection is the only thing the browser lane varies. Both modes
// are real WebChannel: forced long polling closes every backchannel response
// immediately (`CI=1`), streaming keeps one chunked backchannel open (`CI=0`).
const FIRESTORE_SETTINGS = Object.freeze({
  "long-polling": Object.freeze({ experimentalForceLongPolling: true }),
  streaming: Object.freeze({
    experimentalForceLongPolling: false,
    experimentalAutoDetectLongPolling: false,
  }),
});

// Mirrors CLIENT_ACCOUNTS / CLEANUP_CLIENT_FOR in listen_sdk_adapter.mjs.
const CLIENT_ACCOUNTS = Object.freeze({ primary: "account", witness: "account", secondary: "secondaryAccount" });
const CLEANUP_CLIENT_FOR = Object.freeze({ privateB: "secondary" });

const nameOfFactory = (paths) => {
  const names = new Map(Object.entries(paths).map(([name, value]) => [value, name]));
  return (value) => names.get(value) ?? String(value).split("/").at(-1);
};

const lifecycleFailure = (error) =>
  typeof error?.code === "string" && /^[a-zA-Z0-9_/-]{1,80}$/.test(error.code)
    ? error.code
    : "local-lifecycle-operation-failed";

const createDeps = (clients) => ({
  now: () => Math.trunc(performance.now()),
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  firestore: {
    async setDoc(client, docPath, fields) {
      await setDoc(doc(clients[client].db, docPath), fields);
    },
    async deleteDoc(client, docPath, precondition = null) {
      if (precondition !== null) {
        throw new Error("client SDK cannot apply an updateTime delete precondition");
      }
      await deleteDoc(doc(clients[client].db, docPath));
    },
    async deleteOwnedDoc(client, docPath, condition) {
      if (
        !condition ||
        typeof condition.owner !== "string" ||
        !condition.owner ||
        Object.keys(condition).length !== 1
      ) {
        throw new Error("owned cleanup marker required");
      }
      const db = clients[client].db;
      const ref = doc(db, docPath);
      return runTransaction(
        db,
        async (transaction) => {
          const snapshot = await transaction.get(ref);
          const exists = snapshot.exists();
          if (typeof exists !== "boolean") throw new Error("typed transaction presence required");
          if (!exists) return;
          if (snapshot.data()?.owner !== condition.owner) {
            throw Object.assign(new Error("owned marker changed"), { code: "failed-precondition" });
          }
          transaction.delete(ref);
        },
        { maxAttempts: 1 },
      );
    },
    async getDoc(client, docPath) {
      const snapshot = await getDocFromServer(doc(clients[client].db, docPath));
      if (snapshot.metadata?.fromCache !== false || snapshot.metadata?.hasPendingWrites !== false) {
        throw new Error("server-confirmed cleanup snapshot required");
      }
      const exists = snapshot.exists();
      if (typeof exists !== "boolean") throw new Error("typed document presence required");
      return { exists, fields: exists ? snapshot.data() : null, updateTime: null };
    },
    onDocSnapshot(client, docPath, options, onNext, onError) {
      return onSnapshot(doc(clients[client].db, docPath), options, {
        next: (snapshot) =>
          onNext({
            path: docPath,
            exists: snapshot.exists(),
            fromCache: snapshot.metadata.fromCache,
            hasPendingWrites: snapshot.metadata.hasPendingWrites,
          }),
        error: onError,
      });
    },
    onQuerySnapshot(client, spec, options, onNext, onError) {
      const target = collection(clients[client].db, `${spec.parent}/${spec.target}`);
      const constraints = [
        where(spec.where[0], spec.where[1], spec.where[2]),
        orderBy(spec.orderBy?.[0] ?? spec.where[0], spec.orderBy?.[1] ?? "asc"),
        limit(spec.limit ?? 10),
      ];
      return onSnapshot(query(target, ...constraints), options, {
        next: (snapshot) =>
          onNext({
            docs: snapshot.docs.map((entry) => entry.ref.path),
            changes: snapshot.docChanges().map((change) => ({
              type: change.type,
              path: change.doc.ref.path,
              oldIndex: change.oldIndex,
              newIndex: change.newIndex,
            })),
            fromCache: snapshot.metadata.fromCache,
            hasPendingWrites: snapshot.metadata.hasPendingWrites,
          }),
        error: onError,
      });
    },
    async disableNetwork(client) {
      await disableNetwork(clients[client].db);
    },
    async enableNetwork(client) {
      await enableNetwork(clients[client].db);
    },
  },
  auth: {
    async signIn(client, account) {
      const target = clients[client];
      if (account && account !== target.account.name) {
        throw new Error(`unknown sign-in account: ${account}`);
      }
      await signInWithEmailAndPassword(target.auth, target.account.email, target.account.password);
    },
    async signOut(client) {
      await signOut(clients[client].auth);
    },
    // Revocation is a management operation; the Node runner exposes it to the
    // page as window.__o6Revoke(uid) for the duration of the run.
    async revoke(client) {
      const user = clients[client].auth.currentUser;
      if (typeof user?.uid !== "string" || !user.uid) throw new Error("revoke needs a signed-in client");
      if (typeof window.__o6Revoke !== "function") throw new Error("session revocation is unavailable");
      await window.__o6Revoke(user.uid, user.email);
    },
  },
});

const buildClients = async ({ projectId, firestorePort, authPort, account, secondaryAccount, nonce,
  mode, clients }) => {
  const settings = FIRESTORE_SETTINGS[mode];
  if (!settings) throw new Error(`unknown browser transport mode: ${mode}`);
  const accounts = { account, secondaryAccount };
  for (const [name, accountKey] of Object.entries(CLIENT_ACCOUNTS)) {
    const account = accounts[accountKey];
    const app = initializeApp({ projectId, apiKey: "fake-api-key" }, `o6-${nonce}-${mode}-${name}`);
    clients[name] = { app, account };
    const db = initializeFirestore(app, { ...settings });
    clients[name].db = db;
    connectFirestoreEmulator(db, "127.0.0.1", firestorePort);
    const auth = getAuth(app);
    clients[name].auth = auth;
    connectAuthEmulator(auth, `http://127.0.0.1:${authPort}`, { disableWarnings: true });
    await setPersistence(auth, inMemoryPersistence);
    clients[name] = { app, db, auth, account };
  }
  return clients;
};

const teardownClients = async (clients) => {
  const rows = [];
  for (const [name, client] of Object.entries(clients)) {
    const row = { client: name, databaseTerminated: !client.db, appDeleted: false, failures: [] };
    rows.push(row);
    if (client.db) {
      try {
        await terminate(client.db);
        row.databaseTerminated = true;
      } catch (error) {
        row.failures.push(lifecycleFailure(error));
      }
    }
    try {
      await deleteApp(client.app);
      row.appDeleted = true;
    } catch (error) {
      row.failures.push(lifecycleFailure(error));
    }
  }
  return { complete: rows.every((row) => row.databaseTerminated && row.appDeleted), rows };
};

const checkpoint = async (phase, value) => {
  if (typeof window.__o6Checkpoint === "function") await window.__o6Checkpoint(phase, value);
};

/**
 * Run the catalog once. The Node runner has already confirmed the account
 * namespace is free; the page creates the account, drives every case, runs the
 * document cleanup passes and reports what it observed. Account deletion is the
 * runner's job because the management route is not open to a browser origin.
 */
const runLifecycle = async (config) => {
  const { projectId, firestorePort, authPort, account, secondaryAccount, nonce, catalog, budgetSpec,
    mode, stepTimeoutMs, deadlineMs } = config;
  if (!/^[0-9a-f]{32}$/.test(nonce) || !/^[a-zA-Z0-9_-]{1,128}$/.test(projectId)) {
    throw new Error("local namespace required");
  }
  if (!secondaryAccount || secondaryAccount.email === account.email) {
    throw new Error("two distinct throwaway accounts required");
  }
  if (!Number.isInteger(firestorePort) || !Number.isInteger(authPort)) {
    throw new Error("integer emulator ports required");
  }
  const budget = createBudget({
    now: () => performance.now(),
    deadlineMs: Math.min(deadlineMs, budgetSpec.maxDurationSeconds * 1000),
    limits: {
      reads: budgetSpec.maxReads,
      writes: budgetSpec.maxWrites,
      deletes: budgetSpec.maxDeletes,
      snapshots: budgetSpec.maxSnapshots,
      listeners: budgetSpec.maxListenerRegistrations,
    },
  });
  const cleanupBudget = createRecoveryBudget({
    now: () => performance.now(),
    deadlineMs: budgetSpec.cleanupReserveSeconds * 1000,
    limits: {
      reads: budgetSpec.cleanupReserveReads,
      writes: 0,
      deletes: budgetSpec.cleanupReserveDeletes,
      snapshots: 0,
      listeners: 0,
    },
  });
  const clients = {};
  // Both principals share one lifecycle: A is the case client, B owns privateB.
  const principals = {
    primary: { account, uid: null, signupAttempted: false },
    secondary: { account: secondaryAccount, uid: null, signupAttempted: false },
  };
  let paths = null;
  let catalogStarted = false;
  let catalogReturned = false;
  let outcome = { caseRecords: [], cleanup: classifyCleanup([]), cleanupPasses: [],
    totalDeleted: 0, thrown: null };
  const lifecycle = { failure: null, clients: null };
  try {
    const admitObservation = () => {
      if (budget.remainingMs() <= 0) throw new Error("observation phase expired");
    };
    admitObservation();
    await buildClients({ projectId, firestorePort, authPort, account, secondaryAccount, nonce, mode, clients });
    admitObservation();
    await checkpoint("account-create-intent");
    const signUp = async (name, principal) => {
      principal.signupAttempted = true;
      const { email, password } = principal.account;
      const credential = await createUserWithEmailAndPassword(clients[name].auth, email, password);
      const user = credential?.user;
      if (!user || typeof user.uid !== "string" || !user.uid || user.email !== email ||
          clients[name].auth.currentUser?.uid !== user.uid) {
        throw new Error("signup identity unconfirmed");
      }
      principal.uid = user.uid;
    };
    await signUp("primary", principals.primary);
    await signUp("secondary", principals.secondary);
    const uid = principals.primary.uid;
    const secondaryUid = principals.secondary.uid;
    if (secondaryUid === uid) throw new Error("second principal is not distinct");
    paths = { ...ownedPaths(nonce, uid), ...secondaryPaths(nonce, secondaryUid) };
    await checkpoint("account-created", { uid, paths: ownedPaths(nonce, uid), secondaryUid,
      secondaryPaths: secondaryPaths(nonce, secondaryUid) });
    admitObservation();
    const witness = await signInWithEmailAndPassword(
      clients.witness.auth, account.email, account.password);
    if (witness?.user?.uid !== uid) throw new Error("witness identity mismatch");
    admitObservation();
    const deps = createDeps(clients);
    // Both clients of the first principal are re-signed between cases: the
    // revocation case invalidates every session that principal held.
    const restore = async () => {
      for (const name of ["primary", "witness"]) {
        const signed = await signInWithEmailAndPassword(clients[name].auth, account.email, account.password);
        if (signed?.user?.uid !== uid) throw new Error("cleanup principal changed");
      }
      if (clients.secondary.auth.currentUser?.uid !== secondaryUid) {
        const signed = await signInWithEmailAndPassword(
          clients.secondary.auth, secondaryAccount.email, secondaryAccount.password);
        if (signed?.user?.uid !== secondaryUid) throw new Error("second principal changed");
      }
    };
    await checkpoint("documents-at-risk");
    catalogStarted = true;
    outcome = await runCatalog(deps, {
      catalog, budget, cleanupBudget, paths, nonce, client: "primary", clientFor: CLEANUP_CLIENT_FOR,
      contextFor: () => ({
        client: "primary",
        clients: { primary: "primary", witness: "witness", secondary: "secondary" },
        nonce, paths, nameOf: nameOfFactory(paths), stepTimeoutMs, pollMs: 25, budget,
      }),
      betweenCases: restore,
      beforeFinalCleanup: restore,
    });
    catalogReturned = true;
  } catch (error) {
    lifecycle.failure = lifecycleFailure(error);
    outcome.thrown = lifecycle.failure;
  } finally {
    if (catalogStarted && !catalogReturned) {
      try {
        outcome.cleanup = await cleanupBudget.withPhase(async () => {
          const signed = await signInWithEmailAndPassword(
            clients.primary.auth, account.email, account.password);
          if (signed?.user?.uid !== principals.primary.uid) throw new Error("cleanup principal changed");
          const second = await signInWithEmailAndPassword(
            clients.secondary.auth, secondaryAccount.email, secondaryAccount.password);
          if (second?.user?.uid !== principals.secondary.uid) throw new Error("second principal changed");
          return runCleanup(createDeps(clients), {
            client: "primary", paths, nonce, budget: cleanupBudget, clientFor: CLEANUP_CLIENT_FOR,
          });
        });
      } catch (error) {
        outcome.cleanup = classifyCleanup([{ name: "outer-recovery", pathDigest: null,
          outcome: "cleanup-threw", detail: lifecycleFailure(error) }]);
      }
    }
    lifecycle.clients = await teardownClients(clients);
  }
  return {
    sdkVersion: SDK_VERSION,
    mode,
    principals: {
      primary: { uid: principals.primary.uid, signupAttempted: principals.primary.signupAttempted },
      secondary: { uid: principals.secondary.uid, signupAttempted: principals.secondary.signupAttempted },
    },
    caseRecords: outcome.caseRecords,
    cleanup: outcome.cleanup,
    cleanupPasses: outcome.cleanupPasses,
    totalDeleted: outcome.totalDeleted,
    thrown: outcome.thrown,
    lifecycle,
    budget: budget.snapshot(),
    cleanupBudget: cleanupBudget.snapshot(),
  };
};

window.__o6RunCatalog = async (config) => {
  resultNode.textContent = `running ${config?.mode ?? "?"}`;
  try {
    const result = await runLifecycle(config);
    resultNode.textContent = `finished ${result.mode}: ${result.caseRecords.length} cases`;
    return result;
  } catch (error) {
    resultNode.textContent = "failed";
    return { pageError: lifecycleFailure(error), sdkVersion: SDK_VERSION };
  }
};
document.body.dataset.catalogReady = "true";
