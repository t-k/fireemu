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
