// Records the Node SDK cases (packet L1) against the query sandbox or against fireemu. Plain on
// purpose: the owner's access token (print-access-token) is used only here, in the parent, to make
// and remove the two accounts and to sweep documents by the run's prefix with a read-back; the SDK
// process never sees it. Whether a row is right is decided offline (compare.mjs).

import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

import { createAccountClient, createAccountSession } from "./accounts.mjs";
import { createNativeClient } from "./native-client.mjs";
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
          new Error(
            `sdk driver ended (${code}) without a receipt: ${driverError ?? refused?.reason ?? "no reason"}`,
          ),
        );
    });
    child.stdin.write(`${JSON.stringify(input)}\n`);
  });
}

/** Deletes what the run left in the shared collections and reads every name back. */
export async function sweepDocuments({ client, project, run, accounts }) {
  const root = `projects/${project}/databases/(default)/documents`;
  const listed = await client.listIds({
    parent: root,
    collectionId: PUBLIC_COLLECTION,
    prefix: run,
  });
  const names = new Set(listed);
  for (const uid of Object.values(accounts)
    .map((a) => a.uid)
    .filter(Boolean))
    names.add(`${root}/${OWNER_COLLECTION}/${uid}`);
  const all = [...names];
  const before = await client.missing(all);
  const present = before.filter((entry) => entry.exists).map((entry) => entry.name);
  if (present.length) await client.commit({ writes: present.map((name) => ({ delete: name })) });
  const after = await client.missing(all);
  const stillPresent = after.filter((entry) => entry.exists).map((entry) => entry.name);
  return {
    complete: stillPresent.length === 0,
    deleted: present.length,
    stillPresent: stillPresent.length,
    checked: all.length,
  };
}

/**
 * One SDK recording. `target` is { kind: "production", project, token, web } or
 * { kind: "local", project, firestore: { host, port }, auth: "http://host:port" }.
 */
export async function recordSdk({ target, run, log = () => {}, runDriverImpl = runDriver }) {
  const startedAt = new Date().toISOString();
  const production = target.kind === "production";
  const accountClient = createAccountClient({
    base: production
      ? "https://identitytoolkit.googleapis.com"
      : `${target.auth}/identitytoolkit.googleapis.com`,
    project: target.project,
    headers: production
      ? { authorization: `Bearer ${target.token}`, "x-goog-user-project": target.project }
      : { authorization: "Bearer owner" },
  });
  const session = createAccountSession({ client: accountClient, run });
  const native = createNativeClient({
    project: target.project,
    target: production ? { kind: "production" } : { kind: "local", ...target.firestore },
    token: target.token,
  });
  const errors = {};
  let accounts = {};
  let outcome;
  try {
    accounts = await session.create(["a", "b"]);
    log("accounts created");
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
  } catch (error) {
    errors["sdk/run"] = String(error?.message ?? error);
  }
  let documents = { complete: false, error: "sweep did not run" };
  try {
    documents = await sweepDocuments({ client: native, project: target.project, run, accounts });
  } catch (error) {
    documents = { complete: false, error: String(error?.message ?? error) };
  } finally {
    native.close();
  }
  let accountReport = { complete: false, error: "cleanup did not run" };
  try {
    accountReport = await session.cleanup();
  } catch (error) {
    accountReport = { complete: false, error: String(error?.message ?? error) };
  }
  const receipt = outcome?.receipt;
  if (receipt?.thrown) errors["sdk/driver"] = String(receipt.thrown);
  const clientsClosed = receipt ? receipt.teardown.every((t) => t.closed) : false;
  return {
    version: 1,
    kind: "sdk",
    startedAt,
    node: process.version,
    sdk: "firebase 12.18.0",
    requests: outcome ? outcome.wire : 0,
    connections: outcome ? outcome.connections : 0,
    errors,
    cleanup: {
      complete:
        Boolean(receipt?.cleanup?.complete) &&
        documents.complete &&
        accountReport.complete &&
        clientsClosed,
      sdk: receipt ? { complete: receipt.cleanup.complete } : null,
      documents,
      accounts: accountReport,
      clientsClosed,
    },
    rows: receipt ? rowsFromReceipt(receipt) : {},
  };
}
