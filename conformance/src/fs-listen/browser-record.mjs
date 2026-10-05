// Records the SDK cases in a real browser (FS-LISTEN-SDK packet L2), once for each WebChannel
// transport in one run: forced long polling, then streaming, each with a run id of its own. Plain
// like sdk-record.mjs: the owner's access token is used only here, in the parent, to make and
// remove the two accounts and to sweep documents by each mode's prefix with a read-back; the page
// never sees it. Whether a row is right is decided offline (compare.mjs).

import { createAccountClient, createAccountSession } from "./accounts.mjs";
import { originOf } from "./browser-driver.mjs";
import { EXPECTED_CI, MODES, modeRun } from "./browser-modes.mjs";
import { NULL_JOURNAL } from "./journal.mjs";
import { createNativeClient } from "./native-client.mjs";
import {
  issuedSdkNames,
  preflightKey,
  rowsFromReceipt,
  runDriver,
  sweepDocuments,
  unknownWrites,
} from "./sdk-record.mjs";
import { PUBLIC_COLLECTION } from "./sdk-deps-core.mjs";

const BROWSER_DRIVER = new URL("./browser-driver.mjs", import.meta.url).pathname;
/** Wire requests per mode and connections: provisional bounds, set from the local counts. */
export const WIRE_CAP = 3000;
export const CONNECTION_CAP = 300;
/** Two modes of up to 20 minutes of cases and 3 of cleanup each, and the browser's start. */
export const DRIVER_TIMEOUT_MS = 50 * 60_000;

/** Runs the browser driver; resolves like `runDriver` does for the Node one. */
export const runBrowserDriver = (options) =>
  runDriver({ timeoutMs: DRIVER_TIMEOUT_MS, ...options, script: BROWSER_DRIVER });

/** The rows of every mode, each key prefixed with its transport: `browser-streaming/sdk/101`. */
export function browserRows(modeResults) {
  const rows = {};
  for (const [mode, result] of Object.entries(modeResults)) {
    if (!result?.receipt) continue;
    for (const [id, row] of Object.entries(rowsFromReceipt(result.receipt)))
      rows[`browser-${mode}/${id}`] = row;
  }
  return rows;
}

/**
 * Why the transport evidence of a mode does not show the mode. The backchannel request of a Listen
 * channel carries `CI`: 1 in forced long polling, 0 in streaming. The forward channel carries none,
 * which is ignored. The mode is shown when requests with its `CI` came and none with the other.
 */
export function transportProblems(mode, transport) {
  const ci = transport?.ci ?? {};
  const expected = EXPECTED_CI[mode];
  const problems = [];
  if (!(ci[expected] > 0)) problems.push(`${mode}: no Listen channel request with CI=${expected}`);
  for (const value of Object.keys(ci))
    if (value !== expected && value !== "none")
      problems.push(`${mode}: a Listen channel request carried CI=${value}`);
  return problems;
}

/**
 * One browser recording. `target` is { kind: "production", project, token, web, originPort } or
 * { kind: "local", project, originPort, firestore: { host, port }, auth: "http://host:port" }.
 */
export async function recordBrowser({
  target,
  run,
  modes = MODES,
  log = () => {},
  runDriverImpl = runBrowserDriver,
  makeNative = createNativeClient,
  preflightImpl = preflightKey,
  journal = NULL_JOURNAL,
}) {
  const startedAt = new Date().toISOString();
  const production = target.kind === "production";
  let preflightRequests = 0;
  let wire = 0;
  let accountClient;
  let native;
  const productionRequests = () =>
    production
      ? preflightRequests + accountClient.requestCount() + (native?.requestCount?.() ?? 0) + wire
      : null;
  // The key must belong to this project, and the origin the page is served from must be an
  // authorized domain of it, before an account is made or a request is signed in.
  if (production)
    await preflightImpl({
      apiKey: target.web.apiKey,
      project: target.project,
      token: target.token,
      origin: originOf(target.originPort),
      onRequest: () => {
        preflightRequests += 1;
      },
    });
  accountClient = createAccountClient({
    base: production
      ? "https://identitytoolkit.googleapis.com"
      : `${target.auth}/identitytoolkit.googleapis.com`,
    project: target.project,
    headers: production
      ? { authorization: `Bearer ${target.token}`, "x-goog-user-project": target.project }
      : { authorization: "Bearer owner" },
  });
  const session = createAccountSession({ client: accountClient, run, journal });
  native = makeNative({
    project: target.project,
    target: production ? { kind: "production" } : { kind: "local", ...target.firestore },
    token: target.token,
  });
  const errors = {};
  let accounts = {};
  let outcome;
  let diagnostics = [];
  const root = `projects/${target.project}/databases/(default)/documents`;
  try {
    // Ledger 330: conf_listen reads as empty before the run; if it is not, stop without deleting.
    if (production) {
      const before = await native.listIds({
        parent: root,
        collectionId: PUBLIC_COLLECTION,
        prefix: "",
      });
      if (before.length > 0)
        throw new Error(`${PUBLIC_COLLECTION} is not empty before the run: nothing was made`);
    }
    accounts = await session.create(["a", "b"]);
    log("accounts created");
    journal.append({
      type: "names",
      phase: "before",
      names: namesOf({ project: target.project, run, modes, accounts }).map((name) => ({
        name,
        op: "create",
      })),
    });
    const config = {
      mode: production ? "production" : "local",
      wireCap: WIRE_CAP,
      connectionCap: CONNECTION_CAP,
      originPort: target.originPort,
      web: production
        ? target.web
        : { apiKey: "fake-api-key", projectId: target.project, authDomain: "localhost" },
      ...(production ? {} : { authEmulator: target.auth, firestoreEmulator: target.firestore }),
    };
    outcome = await runDriverImpl({ config, input: { run, modes, accounts } });
    wire = outcome.wire ?? 0;
    diagnostics = outcome.diagnostics ?? [];
  } catch (error) {
    errors["browser/run"] = String(error?.message ?? error);
    wire = error?.wire ?? 0;
    diagnostics = error?.diagnostics ?? [];
  }
  const modeResults = outcome?.receipt?.modes ?? {};
  const documents = { complete: true, modes: {} };
  try {
    for (const mode of modes) {
      const swept = await sweepDocuments({
        client: native,
        project: target.project,
        run: modeRun(run, mode),
        accounts,
      });
      documents.modes[mode] = swept;
      if (!swept.complete) documents.complete = false;
    }
    // Ledger 330 again at the end: conf_listen must be empty; anything left is reported, not deleted.
    if (production) {
      const left = await native.listIds({
        parent: root,
        collectionId: PUBLIC_COLLECTION,
        prefix: "",
      });
      if (left.length > 0) {
        documents.confListenLeft = left;
        documents.complete = false;
      }
    }
  } catch (error) {
    documents.complete = false;
    documents.error = String(error?.message ?? error);
  } finally {
    native.close();
  }
  let accountReport;
  try {
    accountReport = await session.cleanup();
  } catch (error) {
    accountReport = { complete: false, error: String(error?.message ?? error) };
  }
  const perMode = {};
  let clientsClosed = Object.keys(modeResults).length === modes.length;
  let writesKnown = clientsClosed;
  let sdkCleanupComplete = clientsClosed;
  for (const mode of modes) {
    const result = modeResults[mode];
    if (!result || result.error || !result.receipt) {
      errors[`browser/${mode}`] = result?.error ?? "no result for this mode";
      clientsClosed = false;
      writesKnown = false;
      sdkCleanupComplete = false;
      continue;
    }
    const { receipt } = result;
    if (receipt.thrown) errors[`browser/${mode}/driver`] = String(receipt.thrown);
    const transportIssues = transportProblems(mode, result.transport);
    if (transportIssues.length > 0)
      errors[`browser/${mode}/transport`] = transportIssues.join("; ");
    if (!receipt.teardown.every((t) => t.closed)) clientsClosed = false;
    if (unknownWrites(receipt)) writesKnown = false;
    if (!receipt.cleanup?.complete) sdkCleanupComplete = false;
    perMode[mode] = { run: result.run, transport: result.transport };
  }
  const total = productionRequests();
  journal.append({ type: "end", productionRequests: total });
  return {
    version: 1,
    kind: "browser",
    run,
    startedAt,
    endedAt: new Date().toISOString(),
    node: process.version,
    sdk: `firebase ${outcome?.receipt?.sdkVersion ?? "12.18.0"}`,
    modes,
    requests: wire,
    productionRequests: total,
    issued: namesOf({ project: target.project, run, modes, accounts }),
    connections: outcome?.connections ?? 0,
    errors,
    cleanup: {
      complete:
        sdkCleanupComplete &&
        documents.complete &&
        accountReport.complete &&
        clientsClosed &&
        writesKnown,
      writesKnown,
      sdk: { complete: sdkCleanupComplete },
      documents,
      accounts: accountReport,
      clientsClosed,
    },
    transport: perMode,
    diagnostics,
    rows: browserRows(modeResults),
  };
}

/** Every name the cases may write in any mode: each mode's public documents and the owner documents. */
export function namesOf({ project, run, modes, accounts }) {
  const names = new Set();
  for (const mode of modes)
    for (const name of issuedSdkNames({ project, run: modeRun(run, mode), accounts }))
      names.add(name);
  return [...names];
}
