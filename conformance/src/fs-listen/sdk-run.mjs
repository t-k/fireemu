// One run of the SDK cases over a set of clients (FS-LISTEN-SDK packets L1 and L2), the same code
// in the Node driver and in a browser page: the paths of the run, the budgets, the catalog run
// with its cleanup, the teardown of the clients, and the receipt. It imports nothing; the SDK
// calls it needs (`signInWithEmailAndPassword`, `terminate`, `deleteApp`) and the collector come
// in as arguments.

import { OWNER_COLLECTION, PUBLIC_COLLECTION } from "./sdk-deps-core.mjs";

/** The bounds of one recording: the catalog's, widened for the three extra cases. */
export const LIMITS = {
  reads: 900,
  writes: 120,
  deletes: 120,
  snapshots: 300,
  listeners: 60,
};
export const DEADLINE_MS = 15 * 60_000;
export const CLEANUP_LIMITS = { reads: 300, writes: 0, deletes: 150, snapshots: 0, listeners: 0 };
export const CLEANUP_MS = 3 * 60_000;
export const STEP_TIMEOUT_MS = 20_000;
export const POLL_MS = 100;

/**
 * The documents of a run: the public ones named with the run id as their prefix, and the two
 * accounts' owner documents. `private` is only ever read (106N, while signed out).
 */
export function runPaths(run, accounts) {
  return {
    run: PUBLIC_COLLECTION,
    alpha: `${PUBLIC_COLLECTION}/${run}-alpha`,
    beta: `${PUBLIC_COLLECTION}/${run}-beta`,
    gamma: `${PUBLIC_COLLECTION}/${run}-gamma`,
    delta: `${PUBLIC_COLLECTION}/${run}-delta`,
    absent: `${PUBLIC_COLLECTION}/${run}-absent`,
    private: `${OWNER_COLLECTION}/${accounts.a.uid}`,
    privateB: `${OWNER_COLLECTION}/${accounts.b.uid}`,
  };
}

/** The receipt of a run, from what the collector returned. */
export function buildReceipt({ thrown, outcome, budget, teardown }) {
  return {
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
      ...(Array.isArray(record.rawEvents) ? { rawEvents: record.rawEvents } : {}),
      ...(Number.isSafeInteger(record.baselineAt) && record.baselineAt >= 0
        ? { baselineAt: record.baselineAt }
        : {}),
    })),
    teardown,
  };
}

/** Terminates every client's database and deletes its app; reports which closed. */
export async function teardownClients(sdk, clients) {
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
  return teardown;
}

/**
 * Runs the catalog `cases` over `clients` (primary, witness and secondary) and returns the
 * receipt. `collector` is { createBudget, createRecoveryBudget, runCatalog }; `deps` the
 * dependencies over the real SDK; `now` a monotonic millisecond clock.
 */
export async function runSdkCatalog({ sdk, collector, clients, deps, run, accounts, cases, now }) {
  const paths = runPaths(run, accounts);
  const { private: _read, ...cleanupPaths } = paths;
  const byPath = new Map(Object.entries(paths).map(([name, path]) => [path, name]));
  const nameOf = (path) => byPath.get(path) ?? "<other>";
  const budget = collector.createBudget({ now, deadlineMs: DEADLINE_MS, limits: LIMITS });
  const cleanupBudget = collector.createRecoveryBudget({
    now,
    deadlineMs: CLEANUP_MS,
    limits: CLEANUP_LIMITS,
  });
  let thrown = null;
  let outcome;
  try {
    // The second principal is signed in for the whole run: it writes and owns `privateB`.
    await sdk.signInWithEmailAndPassword(
      clients.secondary.auth,
      accounts.b.email,
      accounts.b.password,
    );
    outcome = await collector.runCatalog(deps, {
      catalog: { cases },
      contextFor: () => ({
        budget,
        nonce: run,
        paths,
        nameOf,
        // The collector addresses a client by its name; the dependencies look it up.
        clients: Object.fromEntries(Object.keys(clients).map((name) => [name, name])),
        client: "primary",
        stepTimeoutMs: STEP_TIMEOUT_MS,
        pollMs: POLL_MS,
      }),
      budget,
      cleanupBudget,
      paths: cleanupPaths,
      nonce: run,
      client: "primary",
      clientFor: { privateB: "secondary" },
    });
  } catch (error) {
    thrown = String(error?.code ?? error?.message ?? error);
  }
  const teardown = await teardownClients(sdk, clients);
  return buildReceipt({ thrown, outcome, budget, teardown });
}
