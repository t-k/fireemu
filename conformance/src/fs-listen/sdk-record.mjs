// Records the Node SDK cases (packet L1) against the query sandbox or against fireemu. Plain on
// purpose: the owner's access token (print-access-token) is used only here, in the parent, to make
// and remove the two accounts and to sweep documents by the run's prefix with a read-back; the SDK
// process never sees it. Whether a row is right is decided offline (compare.mjs).

import { spawn } from "node:child_process";
import { readFile, stat } from "node:fs/promises";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

import { createAccountClient, createAccountSession } from "./accounts.mjs";
import { NULL_JOURNAL } from "./journal.mjs";
import { createNativeClient } from "./native-client.mjs";
import { createLedger, settleNames } from "./native-ledger.mjs";
import { OWNER_COLLECTION, PUBLIC_COLLECTION } from "./sdk-cases.mjs";

const DRIVER = fileURLToPath(new URL("./sdk-driver.mjs", import.meta.url));
const WIRE_CAP = 1500;
const CONNECTION_CAP = 200;
const DRIVER_TIMEOUT_MS = 20 * 60_000;

/** The closure conditions each SDK case serves. */
export function conditionsOf(caseId) {
  const n = caseId.replace("FS-LISTEN-SDK-", "");
  const table = [
    [/^101/, "document-event-order"],
    [/^102/, "pending-writes"],
    [/^103/, "query-change-order"],
    [/^104/, "reconnect-resume"],
    [/^105/, "unsubscribe"],
    [/^106N/, "initial-unauthenticated-refusal"],
    [/^107/, "default-subscription"],
    [/^108/, "cross-principal-rules"],
    [/^111/, "existence-filter-reconnect"],
  ];
  const hit = table.find(([pattern]) => pattern.test(n));
  if (!hit) throw new Error(`no condition for case ${caseId}`);
  return [`FS-LISTEN-SDK/${hit[1]}`];
}

/**
 * The API key of the web app, from a file only the owner may read. The file holds the key alone;
 * the other web config fields (project id, auth domain) are derived from the project, not read
 * from a secret.
 */
export async function loadApiKey(
  path,
  { stat: statImpl = stat, readFile: readImpl = readFile } = {},
) {
  const info = await statImpl(path);
  if (!info.isFile()) throw new Error("the API key path is not a file");
  if ((info.mode & 0o077) !== 0)
    throw new Error("the API key file is readable by others (use mode 0600)");
  const key = (await readImpl(path, "utf8")).trim();
  if (!/^[A-Za-z0-9_-]{20,}$/.test(key))
    throw new Error("the API key file does not hold one API key");
  return key;
}

/**
 * Binds the key to the project before anything is created. The Identity Toolkit project read with
 * the key answers the project NUMBER in its `projectId` field; the project's own number comes
 * from Resource Manager under the owner's token. They must be the same, and either missing stops
 * the run. Messages never carry the key or a number.
 */
export async function preflightKey({
  apiKey,
  project,
  token,
  fetchImpl = globalThis.fetch,
  onRequest = () => {},
}) {
  const read = async (url, headers, what) => {
    onRequest();
    let response;
    try {
      response = await fetchImpl(url, {
        method: "GET",
        headers,
        redirect: "manual",
        signal: AbortSignal.timeout(30_000),
      });
    } catch {
      throw new Error(`${what} failed (transport)`);
    }
    if (response.status !== 200) throw new Error(`${what} failed (status ${response.status})`);
    try {
      return await response.json();
    } catch {
      throw new Error(`${what} answer was unreadable`);
    }
  };
  const isNumber = (value) => typeof value === "string" && /^[0-9]+$/.test(value);
  const keyed = await read(
    `https://identitytoolkit.googleapis.com/v1/projects?key=${encodeURIComponent(apiKey)}`,
    {},
    "key read",
  );
  const owned = await read(
    `https://cloudresourcemanager.googleapis.com/v1/projects/${encodeURIComponent(project)}`,
    { authorization: `Bearer ${token}`, "x-goog-user-project": project },
    "project read",
  );
  if (!isNumber(keyed.projectId)) throw new Error("the key read gave no project number");
  if (!isNumber(owned.projectNumber)) throw new Error("the project read gave no project number");
  if (owned.projectId !== project) throw new Error("the project read is not the project asked for");
  if (owned.lifecycleState !== "ACTIVE") throw new Error("the project is not ACTIVE");
  if (keyed.projectId !== owned.projectNumber)
    throw new Error("the API key belongs to a different project");
  return { projectNumber: owned.projectNumber };
}

/** A wait that ran out says nothing about absence: such a case is INDETERMINATE offline. */
export const ranOut = (failures) =>
  failures.some((failure) => /timeout|deadline|budget|expired/.test(failure));

/**
 * An event with only the fields its case compares (the catalog's `comparedFields`), plus the cache
 * transitions an aggregate carries. A field the case does not compare is timing, not behavior.
 */
export function projectEvent(event, comparedFields) {
  const keep = new Set([...(comparedFields ?? Object.keys(event)), "fromCacheTransitions"]);
  return Object.fromEntries(Object.entries(event).filter(([key]) => keep.has(key)));
}

/** The rows of a recording, from the driver's receipt. */
export function rowsFromReceipt(receipt) {
  const rows = {};
  for (const record of receipt.cases) {
    rows[`sdk/${record.caseId.replace("FS-LISTEN-SDK-", "")}`] = {
      conditions: conditionsOf(record.caseId),
      observed: record.observed.map((event) => projectEvent(event, record.comparedFields)),
      failures: record.failures,
      invariantViolations: record.invariantViolations,
      end: null,
      timedOut: ranOut(record.failures),
    };
  }
  return rows;
}

/** Runs the driver; resolves with its receipt and the counts of its wire records. */
export function runDriver({ config, input, timeoutMs = DRIVER_TIMEOUT_MS, spawnImpl = spawn }) {
  return new Promise((resolve, reject) => {
    const child = spawnImpl(process.execPath, [DRIVER], {
      env: { ...process.env, AFC_SDK_CONFIG: JSON.stringify(config) },
      stdio: ["pipe", "pipe", "inherit"],
    });
    let receipt;
    let driverError;
    let wire = 0;
    let connections = 0;
    let refused;
    createInterface({ input: child.stdout }).on("line", (line) => {
      let event;
      try {
        event = JSON.parse(line);
      } catch {
        return;
      }
      if (event.event === "receipt") receipt = event.receipt;
      else if (event.event === "driver-error") driverError = event.message;
      else if (event.event === "wire") wire += 1;
      else if (event.event === "connection") connections += 1;
      else if (event.event === "wire-refused") refused = event;
    });
    const timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
    child.once("close", (code) => {
      clearTimeout(timer);
      if (receipt) resolve({ receipt, wire, connections, refused });
      else
        reject(
          Object.assign(
            new Error(
              `sdk driver ended (${code}) without a receipt: ${driverError ?? refused?.reason ?? "no reason"}`,
            ),
            { wire, connections },
          ),
        );
    });
    child.stdin.write(`${JSON.stringify(input)}\n`);
  });
}

/** The document names the SDK cases may write: the run's public ones and the accounts' owner documents. */
export function issuedSdkNames({ project, run, accounts }) {
  const root = `projects/${project}/databases/(default)/documents`;
  const names = ["alpha", "beta", "gamma", "delta", "absent"].map(
    (doc) => `${root}/${PUBLIC_COLLECTION}/${run}-${doc}`,
  );
  for (const uid of Object.values(accounts)
    .map((a) => a.uid)
    .filter(Boolean))
    names.push(`${root}/${OWNER_COLLECTION}/${uid}`);
  return names;
}

/**
 * Settles the names the SDK cases may have written. Each is read directly: one that is there is
 * ours (the run issued the name, and an account's owner document carries the uid of an account the
 * run created) and is deleted and read back; a prefix listing only looks for strays. Whether a
 * case's write threw is the receipt's to say (see `unknownWrites`): absence cannot settle those.
 */
export async function sweepDocuments({ client, project, run, accounts }) {
  const root = `projects/${project}/databases/(default)/documents`;
  // Every name is treated as one the SDK may have created: a read that finds it makes it ours.
  const ledger = createLedger();
  ledger.answered(
    issuedSdkNames({ project, run, accounts }).map((name) => ({ update: { name } })),
    "ok",
  );
  return settleNames({ issued: ledger.entries(), client, root, run });
}

/** Whether any case recorded a step that threw: a write or delete whose outcome is then unknown. */
export const unknownWrites = (receipt) =>
  receipt.cases.some((record) =>
    record.failures.some((failure) => failure.startsWith("step-threw")),
  );

/**
 * One SDK recording. `target` is { kind: "production", project, token, web } or
 * { kind: "local", project, firestore: { host, port }, auth: "http://host:port" }.
 */
export async function recordSdk({
  target,
  run,
  log = () => {},
  runDriverImpl = runDriver,
  makeNative = createNativeClient,
  preflightImpl = preflightKey,
  journal = NULL_JOURNAL,
}) {
  const startedAt = new Date().toISOString();
  const production = target.kind === "production";
  // Every production request but the token commands: the preflight reads, the accounts' calls, the
  // native client's calls and the SDK's own wire records.
  let preflightRequests = 0;
  let wire = 0;
  let accountClient;
  let native;
  const productionRequests = () =>
    production
      ? preflightRequests +
        (accountClient?.requestCount?.() ?? 0) +
        (native?.requestCount?.() ?? 0) +
        wire
      : null;
  // The key must belong to this project before an account is made or a request is signed in.
  if (production)
    await preflightImpl({
      apiKey: target.web.apiKey,
      project: target.project,
      token: target.token,
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
  let confListenBefore;
  const root = `projects/${target.project}/databases/(default)/documents`;
  try {
    // Ledger 330: the query cases read conf_listen as empty before the run; if it is not, stop
    // without deleting anything (nothing has been made yet).
    if (production) {
      confListenBefore = await native.listIds({
        parent: root,
        collectionId: PUBLIC_COLLECTION,
        prefix: "",
      });
      if (confListenBefore.length > 0)
        throw new Error(`${PUBLIC_COLLECTION} is not empty before the run: nothing was made`);
    }
    accounts = await session.create(["a", "b"]);
    log("accounts created");
    journal.append({
      type: "names",
      phase: "before",
      names: issuedSdkNames({ project: target.project, run, accounts }).map((name) => ({
        name,
        op: "create",
      })),
    });
    const config = {
      mode: production ? "production" : "local",
      wireCap: WIRE_CAP,
      connectionCap: CONNECTION_CAP,
      web: production
        ? target.web
        : { apiKey: "fake-api-key", projectId: target.project, authDomain: "localhost" },
      ...(production ? {} : { authEmulator: target.auth, firestoreEmulator: target.firestore }),
    };
    outcome = await runDriverImpl({ config, input: { run, accounts } });
    wire = outcome.wire ?? 0;
  } catch (error) {
    errors["sdk/run"] = String(error?.message ?? error);
    wire = error?.wire ?? 0;
  }
  let documents;
  try {
    documents = await sweepDocuments({ client: native, project: target.project, run, accounts });
    // Ledger 330 again at the end: conf_listen must be empty; anything left is reported, not deleted.
    if (production) {
      const left = await native.listIds({
        parent: root,
        collectionId: PUBLIC_COLLECTION,
        prefix: "",
      });
      if (left.length > 0) documents = { ...documents, complete: false, confListenLeft: left };
    }
  } catch (error) {
    documents = { complete: false, error: String(error?.message ?? error) };
  } finally {
    native.close();
  }
  let accountReport;
  try {
    accountReport = await session.cleanup();
  } catch (error) {
    accountReport = { complete: false, error: String(error?.message ?? error) };
  }
  const receipt = outcome?.receipt;
  if (receipt?.thrown) errors["sdk/driver"] = String(receipt.thrown);
  const clientsClosed = receipt ? receipt.teardown.every((t) => t.closed) : false;
  // A write that threw has an unknown outcome, which a read that finds nothing cannot settle.
  const writesKnown = receipt ? !unknownWrites(receipt) : false;
  const total = productionRequests();
  journal.append({ type: "end", productionRequests: total });
  return {
    version: 1,
    kind: "sdk",
    run,
    startedAt,
    endedAt: new Date().toISOString(),
    node: process.version,
    sdk: "firebase 12.18.0",
    requests: outcome ? outcome.wire : 0,
    productionRequests: total,
    issued: issuedSdkNames({ project: target.project, run, accounts }),
    connections: outcome ? outcome.connections : 0,
    errors,
    cleanup: {
      complete:
        Boolean(receipt?.cleanup?.complete) &&
        documents.complete &&
        accountReport.complete &&
        clientsClosed &&
        writesKnown,
      writesKnown,
      sdk: receipt ? { complete: receipt.cleanup.complete } : null,
      documents,
      accounts: accountReport,
      clientsClosed,
    },
    rows: receipt ? rowsFromReceipt(receipt) : {},
  };
}
