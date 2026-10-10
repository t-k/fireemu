// Records the Node SDK cases (packet L1) against the query sandbox or against fireemu. Plain on
// purpose: the owner's access token (print-access-token) is used only here, in the parent, to make
// and remove the two accounts and to sweep documents by the run's prefix with a read-back; the SDK
// process never sees it. Whether a row is right is decided offline (compare.mjs).

import { execFile, spawn } from "node:child_process";
import { readFile, stat } from "node:fs/promises";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

import { createAccountClient, createAccountSession } from "./accounts.mjs";
import { NULL_JOURNAL } from "./journal.mjs";
import { createNativeClient } from "./native-client.mjs";
import { createLedger, settleNames } from "./native-ledger.mjs";
import { OWNER_COLLECTION, PUBLIC_COLLECTION, sdkCases, selectedSdkCases } from "./sdk-cases.mjs";

const DRIVER = fileURLToPath(new URL("./sdk-driver.mjs", import.meta.url));
const WIRE_CAP = 1500;
const CONNECTION_CAP = 200;
const DRIVER_TIMEOUT_MS = 20 * 60_000;

/** The selected recorder's shared admission budget; it never claims a hard process bound. */
export function createSdk111ParentBound({
  now = () => performance.now(),
  journal = NULL_JOURNAL,
} = {}) {
  let phase = "work";
  const startedAtMs = now();
  let phaseStartedAtMs = startedAtMs;
  let deadline = phaseStartedAtMs + 22 * 60_000;
  let controller = new AbortController();
  const workSignal = controller.signal;
  let workSent = 0;
  let cleanupSent = 0;
  let refused = 0;
  let timer;
  const snapshot = () => {
    const observedAtMs = now();
    return {
      phase,
      workSent,
      cleanupSent,
      sent: workSent + cleanupSent,
      refused,
      startedAtMs,
      phaseStartedAtMs,
      phaseDeadlineAtMs: deadline,
      observedAtMs,
      phaseElapsedMs: observedAtMs - phaseStartedAtMs,
      elapsedMs: observedAtMs - startedAtMs,
      hardWholeParentBound: false,
    };
  };
  const note = (reason) =>
    journal.append({ type: "sdk111-parent-bound", ...snapshot(), ...(reason ? { reason } : {}) });
  const expire = () => {
    if (!controller.signal.aborted) controller.abort(new Error(`parent ${phase} deadline`));
    note("deadline");
  };
  const arm = () => {
    timer = setTimeout(expire, Math.max(1, deadline - now()));
    timer.unref?.();
  };
  arm();
  return {
    workSignal,
    snapshot,
    checkWork() {
      if (now() >= deadline && !controller.signal.aborted) expire();
      if (phase !== "work" || controller.signal.aborted) {
        note("work launch refused");
        throw controller.signal.reason ?? new Error("parent work phase closed");
      }
    },
    admit() {
      if (now() >= deadline && !controller.signal.aborted) expire();
      const count = phase === "work" ? workSent : cleanupSent;
      if (
        controller.signal.aborted ||
        count >= (phase === "work" ? 40 : 20) ||
        workSent + cleanupSent >= 60
      ) {
        refused += 1;
        const error = controller.signal.aborted
          ? controller.signal.reason
          : new Error(`parent ${phase} request cap`);
        note(error.message);
        throw error;
      }
      if (phase === "work") workSent += 1;
      else cleanupSent += 1;
      note();
      return {
        signal: controller.signal,
        timeoutMs: Math.max(1, Math.min(30_000, deadline - now())),
      };
    },
    beginCleanup() {
      if (phase === "cleanup") return;
      clearTimeout(timer);
      note("work phase drained");
      controller.abort(new Error("parent work phase closed"));
      phase = "cleanup";
      controller = new AbortController();
      phaseStartedAtMs = now();
      deadline = phaseStartedAtMs + 7 * 60_000;
      note();
      arm();
    },
    close() {
      clearTimeout(timer);
      controller.abort(new Error("parent recorder closed"));
    },
  };
}

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
  origin,
}) {
  const read = async (url, headers, what) => {
    const control = onRequest() ?? {};
    const wait = async (promise) => {
      if (!control.signal) return promise;
      control.signal.throwIfAborted();
      let abort;
      try {
        return await Promise.race([
          promise,
          new Promise((_, reject) => {
            abort = () => reject(control.signal.reason);
            control.signal.addEventListener("abort", abort, { once: true });
          }),
        ]);
      } finally {
        control.signal.removeEventListener("abort", abort);
      }
    };
    let response;
    try {
      response = await wait(
        fetchImpl(url, {
          method: "GET",
          headers,
          redirect: "manual",
          signal: control.signal
            ? AbortSignal.any([control.signal, AbortSignal.timeout(control.timeoutMs ?? 30_000)])
            : AbortSignal.timeout(30_000),
        }),
      );
    } catch {
      throw new Error(`${what} failed (transport)`);
    }
    if (response.status !== 200) throw new Error(`${what} failed (status ${response.status})`);
    try {
      return await wait(response.json());
    } catch {
      throw new Error(`${what} answer was unreadable`);
    }
  };
  const isNumber = (value) => typeof value === "string" && /^[0-9]+$/.test(value);
  // A browser at `origin` reads the key with that origin as its referer (the key may be
  // restricted to it), and needs the origin's domain among the project's authorized domains.
  const keyed = await read(
    `https://identitytoolkit.googleapis.com/v1/projects?key=${encodeURIComponent(apiKey)}`,
    origin === undefined ? {} : { referer: `${origin}/` },
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
  if (origin !== undefined) {
    const domains = keyed.authorizedDomains;
    if (!Array.isArray(domains) || !domains.includes(new URL(origin).hostname))
      throw new Error("the origin's domain is not among the project's authorized domains");
  }
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
  const cases = Array.isArray(receipt?.cases) ? receipt.cases : [];
  for (const record of cases) {
    // A record that is not shaped like one says nothing: no row (the writes are then not known).
    if (typeof record?.caseId !== "string") continue;
    const failures = Array.isArray(record.failures) ? record.failures : [];
    rows[`sdk/${record.caseId.replace("FS-LISTEN-SDK-", "")}`] = {
      conditions: conditionsOf(record.caseId),
      observed: (Array.isArray(record.observed) ? record.observed : []).map((event) =>
        projectEvent(event, record.comparedFields),
      ),
      // The collector already redacts callback records; keep their boundaries and metadata.
      ...(Array.isArray(record.rawEvents) ? { rawEvents: record.rawEvents } : {}),
      ...(Number.isSafeInteger(record.rawEventCount) && record.rawEventCount >= 0
        ? { rawEventCount: record.rawEventCount }
        : {}),
      ...(Number.isSafeInteger(record.baselineAt) && record.baselineAt >= 0
        ? { baselineAt: record.baselineAt }
        : {}),
      failures,
      invariantViolations: Array.isArray(record.invariantViolations)
        ? record.invariantViolations
        : [],
      end: null,
      timedOut: ranOut(failures),
    };
  }
  return rows;
}

/** Reads only the direct child's PID, birth, executable and arguments for owned termination. */
const childIdentity = (pid) =>
  new Promise((resolve) => {
    if (!Number.isSafeInteger(pid) || pid <= 0) return resolve(null);
    execFile(
      "ps",
      ["-ww", "-p", String(pid), "-o", "pid=,lstart=,comm=,args="],
      { timeout: 1000 },
      (error, stdout) => resolve(error ? null : stdout.trim() || null),
    );
  });

/** Runs the driver; resolves with its receipt and the counts of its wire records. */
export function runDriver({
  config,
  input,
  timeoutMs = DRIVER_TIMEOUT_MS,
  spawnImpl = spawn,
  script = DRIVER,
  signal,
  ownedLifecycle = false,
  identityOfImpl = childIdentity,
}) {
  if (ownedLifecycle && signal?.aborted) {
    const reason = String(signal.reason?.message ?? signal.reason ?? "parent work canceled");
    return Promise.reject(
      Object.assign(new Error(reason), {
        wire: 0,
        connections: 0,
        sdkRefusedAttempts: 0,
        childExit: {
          closed: true,
          stopped: true,
          ownershipVerified: true,
          reason,
          notSpawned: true,
        },
      }),
    );
  }
  return new Promise((resolve, reject) => {
    const child = spawnImpl(process.execPath, [script], {
      env: { ...process.env, AFC_SDK_CONFIG: JSON.stringify(config) },
      stdio: ["pipe", "pipe", "inherit"],
    });
    let receipt;
    let closed = false;
    let exited = false;
    if (ownedLifecycle)
      child.once("exit", () => {
        exited = true;
      });
    let stopped = false;
    let stopReason;
    let hardTimer;
    let ownershipVerified = true;
    const identity = ownedLifecycle
      ? Promise.resolve(identityOfImpl(child.pid)).catch(() => null)
      : null;
    const childExit = () => ({
      closed,
      stopped,
      ownershipVerified,
      ...(stopReason ? { reason: stopReason } : {}),
    });
    const terminate = async (reason) => {
      if (closed || exited || stopped) return;
      stopped = true;
      stopReason = reason;
      const verify = async () => {
        const original = await identity;
        const current = await Promise.resolve(identityOfImpl(child.pid)).catch(() => null);
        return (
          typeof original === "string" &&
          original.length > 0 &&
          original === current &&
          original.includes(script)
        );
      };
      const refuse = () => {
        ownershipVerified = false;
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        reject(
          Object.assign(new Error("sdk child ownership could not be verified"), {
            wire,
            connections,
            diagnostics,
            receipt,
            refused,
            sdkRefusedAttempts: refused ? 1 : 0,
            childExit: childExit(),
          }),
        );
      };
      if (!(await verify())) {
        if (!closed) refuse();
        return;
      }
      if (closed || exited) return;
      child.kill("SIGTERM");
      hardTimer = setTimeout(async () => {
        if (closed || exited) return;
        if (!(await verify())) {
          if (!closed) refuse();
          return;
        }
        if (!closed && !exited) child.kill("SIGKILL");
      }, 2000);
    };
    const onAbort = () => {
      void terminate("parent work deadline");
    };
    let driverError;
    if (ownedLifecycle) {
      child.once("error", (error) => {
        driverError = String(error.code ?? "spawn-error");
      });
      child.stdin.on("error", () => {
        driverError = "driver-input-error";
      });
    }
    let wire = 0;
    let connections = 0;
    let refused;
    // What the page reported besides the counts: a failed request or a page error (at most 50).
    const diagnostics = [];
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
      else if (
        (event.event === "request-failed" || event.event === "page-error") &&
        diagnostics.length < 50
      )
        diagnostics.push(event);
    });
    const timer = setTimeout(
      () => (ownedLifecycle ? void terminate("driver deadline") : child.kill("SIGKILL")),
      timeoutMs,
    );
    if (ownedLifecycle) signal?.addEventListener("abort", onAbort, { once: true });
    child.once("close", (code) => {
      closed = true;
      clearTimeout(timer);
      clearTimeout(hardTimer);
      signal?.removeEventListener("abort", onAbort);
      if (receipt)
        resolve({
          receipt,
          wire,
          connections,
          refused,
          diagnostics,
          ...(ownedLifecycle ? { childExit: childExit() } : {}),
        });
      else
        reject(
          Object.assign(
            new Error(
              `sdk driver ended (${code}) without a receipt: ${driverError ?? refused?.reason ?? "no reason"}`,
            ),
            {
              wire,
              connections,
              diagnostics,
              ...(ownedLifecycle
                ? { childExit: childExit(), sdkRefusedAttempts: refused ? 1 : 0 }
                : {}),
            },
          ),
        );
    });
    if (ownedLifecycle && signal?.aborted) onAbort();
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
    "maybe",
  );
  return settleNames({ issued: ledger.entries(), client, root, run });
}

/**
 * Whether no write of the run has an unknown outcome: the driver left a receipt, nothing was thrown
 * (a case that throws after its steps loses its whole record, and the step-threw with it; the
 * empty string is a thrown value too), the receipt carries exactly the catalog's cases, each once,
 * every record says what its steps did, and no case recorded a step that threw. A receipt that is
 * not shaped like that is not a receipt of known writes, and is not an error either.
 */
export const writesAreKnown = (receipt, expectedIds = sdkCases().map((c) => c.caseId)) =>
  Boolean(receipt) &&
  receipt.thrown == null &&
  Array.isArray(receipt.cases) &&
  receipt.cases.every((record) => Array.isArray(record?.failures)) &&
  receipt.cases.length === expectedIds.length &&
  receipt.cases
    .map((record) => record.caseId)
    .toSorted()
    .join("\n") === expectedIds.toSorted().join("\n") &&
  !unknownWrites(receipt);

/** Whether any case recorded a step that threw: a write or delete whose outcome is then unknown. */
export const unknownWrites = (receipt) =>
  receipt.cases.some((record) =>
    record.failures.some((failure) => failure.startsWith("step-threw")),
  );

/**
 * One SDK recording. `target` is { kind: "production", project, token, web } or
 * { kind: "local", project, firestore: { host, port }, auth: "http://host:port" }.
 */
export async function recordSdk(options) {
  const selectedCaseIds = selectedSdkCases(options.caseSelection).map((c) => c.caseId);
  const parentBound =
    options.caseSelection === "sdk111"
      ? createSdk111ParentBound({ now: options.parentNow, journal: options.journal })
      : null;
  try {
    return await recordSdkWithParentBound(options, parentBound, selectedCaseIds);
  } finally {
    parentBound?.close();
  }
}

async function recordSdkWithParentBound(
  {
    target,
    caseSelection,
    run,
    log = () => {},
    runDriverImpl = runDriver,
    makeNative = createNativeClient,
    preflightImpl = preflightKey,
    journal = NULL_JOURNAL,
  },
  parentBound,
  selectedCaseIds,
) {
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
      ? preflightRequests + accountClient.requestCount() + (native?.requestCount?.() ?? 0) + wire
      : null;
  const preflight = async () => {
    // The key must belong to this project before an account is made or a request is signed in.
    if (production)
      await preflightImpl({
        apiKey: target.web.apiKey,
        project: target.project,
        token: target.token,
        onRequest: () => {
          const control = parentBound?.admit();
          preflightRequests += 1;
          return control;
        },
      });
  };
  if (!parentBound) await preflight();
  accountClient = createAccountClient({
    base: production
      ? "https://identitytoolkit.googleapis.com"
      : `${target.auth}/identitytoolkit.googleapis.com`,
    project: target.project,
    ...(parentBound ? { beforeSend: () => parentBound.admit() } : {}),
    headers: production
      ? { authorization: `Bearer ${target.token}`, "x-goog-user-project": target.project }
      : { authorization: "Bearer owner" },
  });
  const session = createAccountSession({ client: accountClient, run, journal });
  native = makeNative({
    project: target.project,
    target: production ? { kind: "production" } : { kind: "local", ...target.firestore },
    token: target.token,
    ...(parentBound ? { beforeSend: () => parentBound.admit(), maxPages: 1 } : {}),
  });
  const errors = {};
  let accounts = {};
  let outcome;
  let childExit;
  let sdkRefusedAttempts = 0;
  let retainedReceipt;
  let sdkRefusal;
  let sdkConnections = 0;
  let confListenBefore;
  let journaledNames;
  const root = `projects/${target.project}/databases/(default)/documents`;
  try {
    if (parentBound) await preflight();
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
    // Names the cases may write: marked `maybe` so that the A2 read-back does not read the missing
    // answer line as an unknown create. A run whose writes turn out not to be known gets its answer
    // line (unknown) below.
    journaledNames = issuedSdkNames({ project: target.project, run, accounts }).map((name) => ({
      name,
      op: "create",
    }));
    journal.append({ type: "names", phase: "before", maybe: true, names: journaledNames });
    const config = {
      mode: production ? "production" : "local",
      wireCap: caseSelection === "sdk111" ? 200 : WIRE_CAP,
      connectionCap: caseSelection === "sdk111" ? 20 : CONNECTION_CAP,
      web: production
        ? target.web
        : { apiKey: "fake-api-key", projectId: target.project, authDomain: "localhost" },
      ...(production ? {} : { authEmulator: target.auth, firestoreEmulator: target.firestore }),
    };
    parentBound?.checkWork();
    outcome = await runDriverImpl({
      ...(parentBound ? { signal: parentBound.workSignal, ownedLifecycle: true } : {}),
      config,
      input: {
        run,
        accounts,
        ...(caseSelection === undefined ? {} : { caseSelection, caseIds: selectedCaseIds }),
      },
    });
    wire = outcome.wire ?? 0;
    childExit = outcome.childExit;
    sdkRefusedAttempts = outcome.refused ? 1 : 0;
    sdkRefusal = outcome.refused;
    sdkConnections = outcome.connections ?? 0;
    if (childExit?.stopped) errors["sdk/run"] = childExit.reason;
  } catch (error) {
    errors["sdk/run"] = String(error?.message ?? error);
    wire = error?.wire ?? 0;
    childExit = error?.childExit;
    sdkRefusedAttempts = error?.sdkRefusedAttempts ?? 0;
    if (parentBound) {
      retainedReceipt = error?.receipt;
      sdkRefusal = error?.refused;
      sdkConnections = error?.connections ?? 0;
    }
  }
  // A write that threw has an unknown outcome, which a read that finds nothing cannot settle; so
  // has any write of a driver that left no receipt, threw, or lost a case record. The names the
  // cases may have written are closed with `known` when no write is of unknown outcome and with
  // `unknown` otherwise; a journal that ends without either leaves them unconfirmed at A2.
  if (childExit?.closed !== false) parentBound?.beginCleanup();
  const receipt = outcome?.receipt ?? retainedReceipt;
  const writesKnown = writesAreKnown(receipt, selectedCaseIds) && !childExit?.stopped;
  if (journaledNames)
    journal.append({
      type: "names",
      phase: "after",
      outcome: writesKnown ? "known" : "unknown",
      names: journaledNames,
    });
  let documents;
  try {
    if (parentBound && childExit?.closed === false)
      throw new Error("owned SDK child has not exited; cleanup withheld");
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
    if (parentBound && childExit?.closed === false)
      throw new Error("owned SDK child has not exited; cleanup withheld");
    accountReport = await session.cleanup();
  } catch (error) {
    accountReport = {
      complete: false,
      error: String(error?.message ?? error),
      ...(parentBound
        ? { rows: session.entries().map((entry) => Object.assign({}, entry, { settled: false })) }
        : {}),
    };
  }
  if (receipt?.thrown != null) errors["sdk/driver"] = String(receipt.thrown);
  const clientsClosed = Array.isArray(receipt?.teardown) && receipt.teardown.every((t) => t.closed);
  const total = productionRequests();
  journal.append({
    type: "end",
    productionRequests: total,
    ...(parentBound
      ? {
          parentBound: parentBound.snapshot(),
          childExit: childExit ?? null,
          sdkRefusedAttempts,
          sdkRefusal: sdkRefusal ?? null,
        }
      : {}),
  });
  return {
    version: 1,
    kind: "sdk",
    run,
    startedAt,
    endedAt: new Date().toISOString(),
    node: process.version,
    sdk: "firebase 12.18.0",
    ...(caseSelection === undefined ? {} : { caseSelection, selectedCaseIds }),
    requests: parentBound ? wire : outcome ? outcome.wire : 0,
    productionRequests: total,
    ...(parentBound
      ? {
          parentBound: parentBound.snapshot(),
          childExit: childExit ?? null,
          sdkRefusedAttempts,
          sdkRefusal: sdkRefusal ?? null,
        }
      : {}),
    issued: issuedSdkNames({ project: target.project, run, accounts }),
    connections: parentBound ? sdkConnections : outcome ? outcome.connections : 0,
    errors,
    cleanup: {
      complete:
        Boolean(receipt?.cleanup?.complete) &&
        documents.complete &&
        accountReport.complete &&
        clientsClosed &&
        writesKnown,
      writesKnown,
      sdk: receipt ? { complete: Boolean(receipt.cleanup?.complete) } : null,
      documents,
      accounts: accountReport,
      clientsClosed,
    },
    rows: receipt ? rowsFromReceipt(receipt) : {},
  };
}
