// One request budget for a whole production campaign of the AUTH-TENANT-BLOCKING runner (issue
// auth-tenant-campaign-total-request-cap, C1-C3). The owner approves a campaign by its total
// number of external requests; the per-pass ceilings of the session never added up to that.
//
// Once installed, every `fetch` of the process is charged before it is sent, and each `gcloud`
// token call is charged by `chargeExternal` with a declared weight. A charge is either work or
// cleanup: work may use the budget up to the cleanup reserve, cleanup up to the total, so a
// program whose work runs out still deletes its tenants and restores the project. A refused
// charge is fatal and sends nothing. The kind of a charge is the current phase (a cleanup
// section of the runner runs inside `withPhase("cleanup")`); `withKind` overrides it for one
// synchronous call. The runner is sequential, so a process-wide phase is exact.

/** The largest campaign the owner has approved (2026-09-26: at most 2000 requests). */
export const MAX_CAMPAIGN_REQUESTS = 2000;
/**
 * A `gcloud auth application-default print-access-token` call is one operation whose internal
 * HTTP requests (a token refresh, its retries) cannot be counted from outside: it is charged as
 * this many requests, an assumption the packet states (C4).
 */
export const OAUTH_ATTEMPT_WEIGHT = 3;
/** Forced owner-token refreshes (after a 401 in a cleanup) a campaign may make. */
export const FORCED_REFRESH_CAP = 2;
/**
 * signJwt preflight attempts while a new binding propagates (1 to 6.4 minutes on this project,
 * sometimes over 7 by Google's account): 30 s apart, about 9.5 minutes, only while signJwt
 * answers 403 (review MF-1, review-2 Should-1).
 */
export const SIGNER_READY_ATTEMPTS = 20;

const fatal = (message) => Object.assign(new Error(message), { fatal: true });

let phase = "work";
let override;
let installed;

/** The kind the next charge takes. */
export const currentKind = () => override ?? phase;

export function createRequestBudget({ total, cleanupReserve }) {
  if (!Number.isInteger(total) || total < 1 || total > MAX_CAMPAIGN_REQUESTS)
    throw new Error(`request budget: total ${total} is not a whole number in 1..2000`);
  if (!Number.isInteger(cleanupReserve) || cleanupReserve < 0 || cleanupReserve >= total)
    throw new Error(`request budget: cleanup reserve ${cleanupReserve} does not fit ${total}`);
  let used = 0;
  let refused = 0;
  return {
    total,
    cleanupReserve,
    /** Charges `weight` requests of `kind` before they are sent; refuses past the limit. */
    take(kind, weight = 1) {
      const limit = kind === "cleanup" ? total : total - cleanupReserve;
      if (used + weight > limit) {
        refused += 1;
        throw fatal(`request budget: ${kind} request ${used + weight} would pass ${limit}`);
      }
      used += weight;
    },
    used: () => used,
    snapshot: () => ({ total, cleanupReserve, used, refused }),
  };
}

/** Charges every `fetch` of `target` to `budget` until the returned function restores it. */
export function installBudget(budget, target = globalThis) {
  if (installed) throw new Error("a request budget is already installed");
  const original = target.fetch;
  target.fetch = (...args) => {
    budget.take(currentKind());
    return original(...args);
  };
  installed = budget;
  return () => {
    target.fetch = original;
    installed = undefined;
  };
}

/** Charges an operation outside `fetch` (a `gcloud` token call) to the installed budget. */
export function chargeExternal(weight) {
  installed?.take(currentKind(), weight);
}

/** Runs `fn` (synchronously starting its request) with `kind` as the charge's kind. */
export function withKind(kind, fn) {
  const previous = override;
  override = kind;
  try {
    return fn();
  } finally {
    override = previous;
  }
}

/** Runs the async `fn` as a phase whose charges are of `kind`. */
export async function withPhase(kind, fn) {
  const previous = phase;
  phase = kind;
  try {
    return await fn();
  } finally {
    phase = previous;
  }
}

/**
 * The most requests a program's cleanup can send (session.mjs `runProgram` after its steps):
 * a wipe (up to 20 rounds of a list and a delete), multi-tenancy switched on when a program that
 * ran with it off created a tenant anyway (a PATCH and up to 30 read-backs), up to three rounds
 * of deleting every owned tenant and listing up to 20 pages, the program config restored and
 * multi-tenancy switched off (a PATCH and up to 30 read-backs each).
 */
export function programCleanupBound(program) {
  const creates = program.steps.filter(
    (step) => step.method === "POST" && step.path.endsWith("/tenants"),
  ).length;
  const owned = Object.keys(program.tenants ?? {}).length + creates;
  const multiTenant = program.multiTenant !== false;
  const writeAndReadBack = 31;
  let bound = 40;
  if (multiTenant || creates > 0) {
    if (!multiTenant) bound += writeAndReadBack;
    bound += 3 * (owned + 20);
  }
  if (program.config && Object.keys(program.config).length) bound += writeAndReadBack;
  return bound + writeAndReadBack;
}

/**
 * The reserve a campaign keeps for cleanup: the largest program's cleanup, the final wipe (40)
 * and the four read-backs after a pass, the read of the switches after a stop, one periodic and
 * the capped forced owner-token refreshes with the request each forced refresh repeats.
 */
export function cleanupReserveFor(programs) {
  const largest = Math.max(0, ...programs.map(programCleanupBound));
  const refreshes = OAUTH_ATTEMPT_WEIGHT + FORCED_REFRESH_CAP * (OAUTH_ATTEMPT_WEIGHT + 1);
  return largest + 40 + 4 + 1 + refreshes;
}

/**
 * The fewest work requests two passes of `programs` can take: before each pass the account and
 * config read-backs (5), every step, the signJwt preflight's attempts when a program mints a
 * token, and the first owner token. A budget whose work share is smaller cannot complete a campaign and is
 * refused before anything is sent (it is a floor, not an estimate: the charges above enforce the
 * ceiling).
 */
export function minimumWork(programs) {
  const steps = programs.reduce((total, program) => total + program.steps.length, 0);
  const signer = programs.some((program) => program.tokens) ? SIGNER_READY_ATTEMPTS : 0;
  return 2 * (5 + steps) + signer + OAUTH_ATTEMPT_WEIGHT;
}

/**
 * The budget a campaign runs under, from the value the reviewed command pins
 * (`FIREEMU_AUTH_TENANT_REQUEST_BUDGET`): a whole number of requests no larger than the approved
 * maximum, whose work share carries two passes after the cleanup reserve.
 */
export function planCampaignBudget(programs, value) {
  if (value === undefined || value === "")
    throw new Error("FIREEMU_AUTH_TENANT_REQUEST_BUDGET is required for a production campaign");
  if (!/^\d+$/.test(String(value)))
    throw new Error(`request budget: ${value} is not a whole number`);
  const total = Number(value);
  if (total < 1 || total > MAX_CAMPAIGN_REQUESTS)
    throw new Error(`request budget: total ${total} is not a whole number in 1..2000`);
  const reserve = cleanupReserveFor(programs);
  const work = minimumWork(programs);
  if (total - reserve < work)
    throw new Error(
      `request budget: ${total} cannot carry ${work} work requests and a ${reserve} cleanup reserve`,
    );
  return { total, cleanupReserve: reserve, minimumWork: work };
}
