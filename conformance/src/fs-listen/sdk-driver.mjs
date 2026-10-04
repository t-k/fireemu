// One Node Web SDK 12.18.0 process that runs the SDK cases of packet L1 and prints a receipt
// (FS-LISTEN-SDK). It runs the catalog's own step machine (listen_collector.runCatalog) over the
// real SDK, behind the wire guard of the AUTH-FS-CROSS driver: only the Google hosts the SDK needs
// are reachable, every request counts against a cap and none carries a token the receipt keeps.
//
//   env AFC_SDK_CONFIG  { mode: "production"|"local", wireCap, connectionCap, web: { apiKey,
//                         projectId, authDomain }, authEmulator?, firestoreEmulator?: { host, port } }
//   stdin, one line     { run, accounts: { a: { email, password, uid }, b: { ... } } }
//   stdout              JSON lines; the last is { event: "receipt", receipt }

// Must stay the first import: it installs the wire guard before Firebase loads.
import { config, emit, local } from "../auth-fs-cross/sdk-driver-wire.mjs";

import { createInterface } from "node:readline";

import { deleteApp, initializeApp } from "firebase/app";
import * as auth from "firebase/auth";
import * as firestore from "firebase/firestore";

import {
  createBudget,
  createRecoveryBudget,
  runCatalog,
} from "../../../tools/compat-broad/fs-listen-resume/listen_collector.mjs";
import { OWNER_COLLECTION, PUBLIC_COLLECTION, sdkCases } from "./sdk-cases.mjs";
import { bandOf, makeDeps } from "./sdk-deps.mjs";

const sdk = { initializeApp, deleteApp, ...auth, ...firestore };

/** The bounds of one recording: the catalog's, widened for the three extra cases. */
export const LIMITS = {
  reads: 900,
  writes: 120,
  deletes: 120,
  snapshots: 300,
  listeners: 60,
};
const DEADLINE_MS = 15 * 60_000;
const CLEANUP_LIMITS = { reads: 300, writes: 0, deletes: 150, snapshots: 0, listeners: 0 };
const CLEANUP_MS = 3 * 60_000;

const readLine = () =>
  new Promise((resolve) =>
    createInterface({ input: process.stdin }).once("line", (line) => resolve(JSON.parse(line))),
  );

function buildClient(name, account) {
  const app = initializeApp(config.web, `listen-${name}-${process.pid}`);
  const db = firestore.getFirestore(app);
  const clientAuth = auth.getAuth(app);
  if (local) {
    auth.connectAuthEmulator(clientAuth, config.authEmulator, { disableWarnings: true });
    firestore.connectFirestoreEmulator(
      db,
      config.firestoreEmulator.host,
      config.firestoreEmulator.port,
    );
  }
  return { app, db, auth: clientAuth, account };
}

async function main() {
  const { run, accounts } = await readLine();
  const base = bandOf(run);
  const clients = {
    primary: buildClient("primary", { name: "throwaway", ...accounts.a }),
    witness: buildClient("witness", { name: "throwaway", ...accounts.a }),
    secondary: buildClient("secondary", { name: "second", ...accounts.b }),
  };
  const paths = {
    run: PUBLIC_COLLECTION,
    alpha: `${PUBLIC_COLLECTION}/${run}-alpha`,
    beta: `${PUBLIC_COLLECTION}/${run}-beta`,
    gamma: `${PUBLIC_COLLECTION}/${run}-gamma`,
    delta: `${PUBLIC_COLLECTION}/${run}-delta`,
    absent: `${PUBLIC_COLLECTION}/${run}-absent`,
    private: `${OWNER_COLLECTION}/${accounts.a.uid}`,
    privateB: `${OWNER_COLLECTION}/${accounts.b.uid}`,
  };
  // `private` is only ever read (106N, while signed out): there is nothing of ours to clean up.
  const { private: _read, ...cleanupPaths } = paths;
  const byPath = new Map(Object.entries(paths).map(([name, path]) => [path, name]));
  const nameOf = (path) => byPath.get(path) ?? "<other>";
  const now = () => performance.now();
  const budget = createBudget({ now, deadlineMs: DEADLINE_MS, limits: LIMITS });
  const cleanupBudget = createRecoveryBudget({
    now,
    deadlineMs: CLEANUP_MS,
    limits: CLEANUP_LIMITS,
  });
  const deps = makeDeps({ sdk, clients, base });
  const nonce = run;
  let thrown = null;
  let outcome;
  try {
    // The second principal is signed in for the whole run: it writes and owns `privateB`.
    await sdk.signInWithEmailAndPassword(
      clients.secondary.auth,
      accounts.b.email,
      accounts.b.password,
    );
    outcome = await runCatalog(deps, {
      catalog: { cases: sdkCases() },
      contextFor: () => ({
        budget,
        nonce,
        paths,
        nameOf,
        // The collector addresses a client by its name; the dependencies look it up.
        clients: Object.fromEntries(Object.keys(clients).map((name) => [name, name])),
        client: "primary",
        stepTimeoutMs: 20_000,
        pollMs: 100,
      }),
      budget,
      cleanupBudget,
      paths: cleanupPaths,
      nonce,
      client: "primary",
      clientFor: { privateB: "secondary" },
    });
  } catch (error) {
    thrown = String(error?.code ?? error?.message ?? error);
  }
  const teardown = [];
  for (const [name, client] of Object.entries(clients)) {
    try {
      await sdk.terminate(client.db);
      await sdk.deleteApp(client.app);
      teardown.push({ client: name, closed: true });
    } catch {
      teardown.push({ client: name, closed: false });
    }
  }
  const receipt = {
    thrown: thrown ?? outcome?.thrown ?? null,
    cleanup: outcome?.cleanup ?? { complete: false },
    cleanupPasses: outcome?.cleanupPasses ?? [],
    budget: budget.snapshot(),
    cases: (outcome?.caseRecords ?? []).map((record) => ({
      caseId: record.caseId,
      role: record.role,
      comparison: record.comparison,
      complete: record.complete,
      failures: record.failures,
      observed: record.observed,
      comparedFields: record.comparedFields,
      invariantViolations: record.invariantViolations,
      listenersClosed: record.listenersClosed,
      rawEventCount: record.rawEventCount,
    })),
    teardown,
  };
  emit({ event: "receipt", receipt });
  setTimeout(() => process.exit(0), 50);
}

main().catch((error) => {
  emit({ event: "driver-error", message: String(error?.message ?? error) });
  setTimeout(() => process.exit(1), 50);
});
