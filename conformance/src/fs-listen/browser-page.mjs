// The page of the browser recording (FS-LISTEN-SDK packet L2): the Web SDK 12.18.0 browser bundles
// (the gstatic URLs below are answered by the driver from the pinned npm package, never fetched)
// running the same catalog run as the Node driver (`runSdkCatalog`), through the collector served
// byte-identical. The page does one mode per load: `window.listenRun(config)` builds the three
// clients with the mode's Firestore settings, runs the cases and returns the receipt. The
// accounts exist already (the parent made them); the page only signs in. Passwords arrive in
// memory through `page.evaluate`, never in the URL or the DOM.

import {
  deleteApp,
  initializeApp,
} from "https://www.gstatic.com/firebasejs/12.18.0/firebase-app.js";
import * as auth from "https://www.gstatic.com/firebasejs/12.18.0/firebase-auth.js";
import * as firestore from "https://www.gstatic.com/firebasejs/12.18.0/firebase-firestore.js";

import {
  createBudget,
  createRecoveryBudget,
  runCatalog,
} from "/lib/collector/listen_collector.mjs";
import { createPageDeps } from "/lib/sdk-deps-browser.mjs";
import { wrapDeps } from "/lib/sdk-deps-core.mjs";
import { runSdkCatalog } from "/lib/sdk-run.mjs";
import { MODE_SETTINGS } from "/lib/browser-modes.mjs";

const sdk = { initializeApp, deleteApp, ...auth, ...firestore };

async function buildClient(config, name, account) {
  const settings = MODE_SETTINGS[config.mode];
  if (!settings) throw new Error(`unknown browser transport mode: ${config.mode}`);
  const app = initializeApp(config.web, `listen-${config.run}-${name}`);
  const db = firestore.initializeFirestore(app, { ...settings });
  const clientAuth = auth.getAuth(app);
  // No IndexedDB: a session lives and dies with the page.
  await auth.setPersistence(clientAuth, auth.inMemoryPersistence);
  if (config.local) {
    auth.connectAuthEmulator(clientAuth, config.authEmulator, { disableWarnings: true });
    firestore.connectFirestoreEmulator(
      db,
      config.firestoreEmulator.host,
      config.firestoreEmulator.port,
    );
  }
  return { app, db, auth: clientAuth, account };
}

window.listenRun = async (config) => {
  const { accounts } = config;
  const clients = {
    primary: await buildClient(config, "primary", { name: "throwaway", ...accounts.a }),
    witness: await buildClient(config, "witness", { name: "throwaway", ...accounts.a }),
    secondary: await buildClient(config, "secondary", { name: "second", ...accounts.b }),
  };
  const deps = wrapDeps(createPageDeps(sdk, clients), { sdk, clients, base: config.base });
  return runSdkCatalog({
    sdk,
    collector: { createBudget, createRecoveryBudget, runCatalog },
    clients,
    deps,
    run: config.run,
    accounts,
    cases: config.cases,
    now: () => performance.now(),
  });
};
document.body.dataset.ready = "true";

// L3 state is copied to the parent before destroying any page or browser.
let l3;
window.listenL3Init = async (config) => {
  const app = initializeApp(config.web, `listen-${config.run}-l3`);
  const db = firestore.initializeFirestore(app, { ...MODE_SETTINGS[config.mode] });
  if (config.local)
    firestore.connectFirestoreEmulator(
      db,
      config.firestoreEmulator.host,
      config.firestoreEmulator.port,
    );
  l3 = {
    app,
    db,
    config,
    snapshots: [],
    errors: [],
    failures: [],
    enableCalls: 0,
    networkDisabled: false,
  };
  if (config.persistent) await firestore.enableIndexedDbPersistence(db);
  if (config.offline) {
    await firestore.disableNetwork(db);
    l3.networkDisabled = true;
  }
  l3.query = firestore.query(
    firestore.collection(db, "conf_listen"),
    firestore.where("rank", ">=", config.base),
    firestore.where("rank", "<", config.base + 10),
    firestore.orderBy("rank", "asc"),
    firestore.limit(10),
  );
};
const l3Snapshot = (snapshot) => ({
  docs: snapshot.docs.map((d) =>
    d.id === `${l3.config.run}-alpha`
      ? "alpha"
      : d.id === `${l3.config.run}-beta`
        ? "beta"
        : "other",
  ),
  fromCache: snapshot.metadata.fromCache,
  hasPendingWrites: snapshot.metadata.hasPendingWrites,
  changes: snapshot.docChanges({ includeMetadataChanges: true }).map((c) => ({
    type: c.type,
    doc: c.doc.id.endsWith("-alpha") ? "alpha" : c.doc.id.endsWith("-beta") ? "beta" : "other",
    oldIndex: c.oldIndex,
    newIndex: c.newIndex,
  })),
  elapsedMs: Math.trunc(performance.now()),
});
window.listenL3Seed = async (name) => {
  const [rank, value] = name === "alpha" ? [1, "a0"] : [2, "b0"];
  await firestore.setDoc(firestore.doc(l3.db, `conf_listen/${l3.config.run}-${name}`), {
    rank: l3.config.base + rank,
    owner: l3.config.run,
    value,
  });
  return { name, acknowledged: true };
};
window.listenL3Subscribe = () => {
  l3.unsubscribe = firestore.onSnapshot(
    l3.query,
    { includeMetadataChanges: true },
    (snapshot) => l3.snapshots.push(l3Snapshot(snapshot)),
    (error) => l3.errors.push(String(error.code ?? "unknown")),
  );
};
window.listenL3Read = async () => {
  try {
    const snapshot = await firestore.getDocsFromCache(l3.query);
    l3.cacheRead = { outcome: "success", ...l3Snapshot(snapshot) };
  } catch (error) {
    l3.cacheRead = { outcome: "error", code: String(error.code ?? "unknown") };
  }
};
window.listenL3Online = async () => {
  l3.enableCalls += 1;
  await firestore.enableNetwork(l3.db);
};
window.listenL3Checkpoint = () => ({
  snapshots: l3.snapshots,
  errors: l3.errors,
  failures: l3.failures,
  cacheRead: l3.cacheRead ?? null,
  networkDisabled: l3.networkDisabled,
  enableCalls: l3.enableCalls,
});
window.listenL3Stop = async (clear = false) => {
  l3.unsubscribe?.();
  await firestore.terminate(l3.db);
  if (clear) await firestore.clearIndexedDbPersistence(l3.db);
  await deleteApp(l3.app);
  return { closed: true, cacheCleared: clear };
};
