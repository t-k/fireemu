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
import { selectedSdkCases } from "./sdk-cases.mjs";
import { bandOf, makeDeps } from "./sdk-deps.mjs";
import { runSdkCatalog } from "./sdk-run.mjs";

const sdk = { initializeApp, deleteApp, ...auth, ...firestore };

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
  const { run, accounts, caseSelection, caseIds } = await readLine();
  if (caseSelection !== undefined && caseIds === undefined)
    throw new Error("selected SDK case IDs do not match");
  const cases = selectedSdkCases(caseSelection, caseIds);
  const clients = {
    primary: buildClient("primary", { name: "throwaway", ...accounts.a }),
    witness: buildClient("witness", { name: "throwaway", ...accounts.a }),
    secondary: buildClient("secondary", { name: "second", ...accounts.b }),
  };
  const receipt = await runSdkCatalog({
    sdk,
    collector: { createBudget, createRecoveryBudget, runCatalog },
    clients,
    deps: makeDeps({ sdk, clients, base: bandOf(run) }),
    run,
    accounts,
    cases,
    now: () => performance.now(),
  });
  emit({ event: "receipt", receipt });
  setTimeout(() => process.exit(0), 50);
}

main().catch((error) => {
  emit({ event: "driver-error", message: String(error?.message ?? error) });
  setTimeout(() => process.exit(1), 50);
});
