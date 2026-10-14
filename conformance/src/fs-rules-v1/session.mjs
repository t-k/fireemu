// Executes the FS-3 programs against one target (the Identity Platform sandbox in production, or
// fireemu or the official Firestore emulator on loopback) and returns what it answered.
//
// The session owns one anonymous account (production and fireemu only), the Rules release of the
// sandbox's `(default)` database and the rulesets it creates. Requests made as a principal are
// recorded as rows; harness calls (sign-in, publication, marker polls, seed, wipe, cleanup) are
// counted but not recorded. Every call is guarded: production requests may only reach the sandbox
// project, and a stop signal ends the run at the next step after cleanup.
//
// An unknown answer to a call that creates or deletes something (a timeout, a status below 200, a
// 3xx or a 5xx) is kept in `unknowns`. It is never retried and never settled by a 404, and it
// keeps `closureReady` false: such a run needs the coordinator's read-back or a recovery packet.

import {
  buildFirestoreGrpc,
  buildFirestoreRest,
  databaseName,
  DEFAULT_DATABASE,
  documentsName,
  guardFirestoreRequest,
  guardGrpcRequest,
  isTransient,
  normalizeGrpc,
  normalizeRest,
  normalizeString,
  PRODUCTION,
  SANDBOX_PROJECT,
} from "../fs-rules/harness.mjs";
import { markerOf, rulesetSource } from "./corpus.mjs";

/** An error that must stop the whole run: the sandbox may no longer be in a known state. */
export const fatal = (message) => Object.assign(new Error(message), { fatal: true });
const realSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const COMMIT_BATCH = 400;
/** Consecutive marker answers that must agree before a publication counts as propagated. */
export const SETTLE_STREAK = 30;
const SETTLE_LIMIT_MS = 8 * 60_000;
const RELEASE = "cloud.firestore";
/** A Listen is read until it ends, goes quiet for this long, or reaches the cap. */
export const LISTEN_IDLE_MS = 2000;
export const LISTEN_CAP_MS = 20_000;

/** Whether an answer to a mutating call says nothing about whether it took effect. */
export const isUnknownStatus = (status) =>
  status < 200 || (status >= 300 && status < 400) || status >= 500;

const escapeRegex = (text) => text.replaceAll(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`);

/**
 * Refuses any harness request that would leave the target: production calls may only reach the
 * Firestore, Rules and Identity Toolkit hosts and only the sandbox project's resources (the one
 * project-less path is the end-user sign-up, which the API key binds to the sandbox).
 */
export function guardHarnessRequest(url, ctx) {
  const parsed = new URL(url);
  if (ctx.target.kind !== "production") {
    const allowed = [ctx.target.firestoreOrigin, ctx.target.authOrigin].map(
      (o) => new URL(o).origin,
    );
    if (!allowed.includes(parsed.origin))
      throw new Error(`local request left loopback: ${parsed.origin}`);
    return;
  }
  const project = escapeRegex(ctx.project);
  const allowed = {
    [PRODUCTION.firestore]: [
      new RegExp(`^/v1/projects/${project}/databases$`),
      new RegExp(`^/v1/projects/${project}/databases/\\(default\\)/documents(:[A-Za-z]+)?$`),
    ],
    [PRODUCTION.rules]: [
      new RegExp(`^/v1/projects/${project}/rulesets(/[A-Za-z0-9_-]+)?$`),
      new RegExp(`^/v1/projects/${project}/releases(/cloud\\.firestore)?$`),
    ],
    [PRODUCTION.itk]: [
      new RegExp(`^/v1/projects/${project}/accounts:(query|delete)$`),
      new RegExp(`^/admin/v2/projects/${project}/config$`),
      /^\/v1\/accounts:signUp$/,
    ],
  };
  const patterns = allowed[parsed.origin];
  const path = decodeURIComponent(parsed.pathname);
  if (!patterns?.some((pattern) => pattern.test(path)))
    throw new Error(`harness request is outside the sandbox project: ${parsed.origin}${path}`);
}

/** The listen frames as the rows record them: no times or tokens, documents merged and sorted. */
export function summarizeListen(frames, end, ctx, principals) {
  const out = [];
  for (const frame of frames) {
    if (frame.kind === "documentChange") {
      const name = normalizeString(frame.documentChange?.document?.name ?? "", ctx, principals);
      const last = out.at(-1);
      if (last?.kind === "documentChange") last.names = [...last.names, name].toSorted();
      else out.push({ kind: "documentChange", names: [name] });
    } else if (frame.kind === "targetChange") {
      const change = frame.targetChange ?? {};
      out.push({
        kind: "targetChange",
        type: change.targetChangeType,
        targetIds: change.targetIds ?? [],
        ...(change.cause
          ? {
              cause: {
                code: change.cause.code,
                message: normalizeString(change.cause.message ?? "", ctx, principals),
              },
            }
          : {}),
      });
    } else {
      out.push({ kind: String(frame.kind ?? "unknown") });
    }
  }
  const ended = end && end.reason !== "closed-by-harness";
  return {
    listen: true,
    frames: out,
    end: ended
      ? {
          reason: end.reason,
          code: end.code,
          details: normalizeString(end.details ?? "", ctx, principals),
        }
      : "open",
    ...(out.length === 0 && !ended ? { silent: true } : {}),
  };
}

export function createSession(
  ctx,
  deps,
  {
    timeoutMs = 60_000,
    maxRequests = Infinity,
    maxHarnessRequests = Infinity,
    settleStreak = SETTLE_STREAK,
    settlePollMs = 1000,
    log = () => {},
    shouldStop = () => false,
  } = {},
) {
  const { fetchImpl = fetch, grpc, sleep = realSleep, now = Date.now } = deps;
  let requests = 0;
  let harnessRequests = 0;
  /** A sleep that ends early once a stop is requested, so a signal never waits out a long wait. */
  async function pause(ms) {
    const until = now() + ms;
    const keepWaiting = () => cleaningUp || !shouldStop();
    while (now() < until && keepWaiting()) await sleep(Math.min(1000, Math.max(1, until - now())));
    if (shouldStop() && !cleaningUp) throw fatal("stopped by a signal");
  }
  const principals = new Map();
  /** Rulesets this session created in production, deleted at the end. */
  const createdRulesets = new Set();
  /** The marker label in force (`null`: none), as the harness set it. */
  let active = null;
  let previousLabel = null;
  let released = false;
  const publications = [];
  /** Production refusals of a ruleset, for the evidence (never compared). */
  const diagnostics = {};
  /** Unknown answers to calls that create or delete: a run with any is not closure-ready. */
  const unknowns = [];
  let cleaningUp = false;

  const charge = (harness) => {
    if (harness) {
      if (harnessRequests >= maxHarnessRequests && !cleaningUp)
        throw fatal(`harness request ceiling ${maxHarnessRequests} reached`);
      harnessRequests += 1;
    } else {
      if (requests >= maxRequests) throw fatal(`request ceiling ${maxRequests} reached`);
      requests += 1;
    }
  };

  async function refreshOwner() {
    try {
      await ctx.target.refresh?.();
    } catch (error) {
      throw fatal(`owner credential refresh failed: ${error?.message ?? error}`);
    }
  }

  const ownerHeaders = () =>
    ctx.target.kind === "production"
      ? {
          authorization: `Bearer ${ctx.target.adminToken}`,
          "x-goog-user-project": ctx.target.quotaProject,
        }
      : { authorization: "Bearer owner" };

  function apiUrl(api, path) {
    if (ctx.target.kind === "production") return `${PRODUCTION[api]}/${path}`;
    if (api === "itk") return `${ctx.target.authOrigin}/identitytoolkit.googleapis.com/${path}`;
    if (api === "firestore") return `${ctx.target.firestoreOrigin}/${path}`;
    throw new Error(`${api} has no local form`);
  }

  /**
   * One harness HTTP call. `mutates` names a call that creates or deletes: an unknown answer to
   * it is recorded in `unknowns`. Any answer outside `expect` is fatal.
   */
  async function call(url, init, { expect = [200], timeout = timeoutMs, mutates } = {}) {
    guardHarnessRequest(url, ctx);
    charge(true);
    const path = new URL(url).pathname;
    let response;
    let text;
    try {
      response = await fetchImpl(url, { ...init, signal: AbortSignal.timeout(timeout) });
      text = await response.text();
    } catch (error) {
      if (mutates)
        unknowns.push({ call: mutates, answer: `transport ${error?.cause?.code ?? error?.name}` });
      throw fatal(`harness ${init.method} ${path}: ${error?.cause?.code ?? error?.name}`);
    }
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      /* not JSON */
    }
    if (!expect.includes(response.status)) {
      if (mutates && isUnknownStatus(response.status))
        unknowns.push({ call: mutates, answer: `HTTP ${response.status}` });
      throw fatal(
        `harness ${init.method} ${path}: HTTP ${response.status} ${normalizeString(text.slice(0, 300), ctx, principals)}`,
      );
    }
    return { status: response.status, json };
  }

  async function admin(method, api, path, body, options) {
    await refreshOwner();
    return call(
      apiUrl(api, path),
      {
        method,
        headers: {
          ...ownerHeaders(),
          ...(body === undefined ? {} : { "content-type": "application/json" }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      },
      options,
    );
  }

  // ---- principals ----------------------------------------------------------------------------

  /** One anonymous account: a real sign-up, or a mock token on the official emulator. */
  async function createPrincipal(name, spec) {
    if (spec?.provider !== "anonymous")
      throw fatal(`principal ${name}: only anonymous sign-up is supported, not ${spec?.provider}`);
    if (ctx.target.mockToken) {
      const uid = `fsr-${ctx.run}-${name}`;
      principals.set(name, { uid, idToken: ctx.target.mockToken(uid) });
      return;
    }
    const key = ctx.target.kind === "production" ? ctx.target.apiKey : "fake-api-key";
    const { json } = await call(
      apiUrl("itk", `v1/accounts:signUp?key=${key}`),
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ returnSecureToken: true }),
      },
      { mutates: "sign-up" },
    );
    if (!json?.idToken || !json?.localId) throw fatal(`sign-in of ${name} returned no token`);
    principals.set(name, { uid: json.localId, idToken: json.idToken });
  }

  async function deletePrincipals() {
    if (ctx.target.kind !== "production") return;
    const errors = [];
    for (const [, principal] of principals) {
      if (principal.deleted) continue;
      try {
        await admin(
          "POST",
          "itk",
          `v1/projects/${ctx.project}/accounts:delete`,
          { localId: principal.uid },
          { mutates: "delete account" },
        );
        principal.deleted = true;
      } catch (error) {
        errors.push(String(error.message ?? error));
      }
    }
    if (errors.length) throw fatal(errors.join("; "));
  }

  /** Production: the sign-in baseline allows anonymous accounts (read, never changed). */
  async function prepareSignIn() {
    if (ctx.target.kind !== "production") return;
    const { json } = await admin("GET", "itk", `admin/v2/projects/${ctx.project}/config`);
    if (json?.signIn?.anonymous?.enabled !== true)
      throw fatal("the sandbox does not allow anonymous sign-in");
  }

  // ---- documents -----------------------------------------------------------------------------

  async function commit(writes) {
    for (let i = 0; i < writes.length; i += COMMIT_BATCH) {
      await admin("POST", "firestore", `v1/${databaseName(ctx)}/documents:commit`, {
        writes: writes.slice(i, i + COMMIT_BATCH),
      });
    }
  }

  /** Deletes every document of `(default)` with owner credentials. */
  async function wipe() {
    if (ctx.target.kind !== "production") {
      await call(
        `${ctx.target.firestoreOrigin}/emulator/v1/projects/${ctx.project}/databases/${DEFAULT_DATABASE}/documents`,
        { method: "DELETE", headers: ownerHeaders() },
      );
      return;
    }
    for (let round = 0; round < 40; round += 1) {
      const { json } = await admin("POST", "firestore", `v1/${documentsName(ctx)}:runQuery`, {
        structuredQuery: {
          from: [{ allDescendants: true }],
          select: { fields: [{ fieldPath: "__name__" }] },
          limit: COMMIT_BATCH,
        },
      });
      const names = (json ?? []).filter((e) => e.document).map((e) => e.document.name);
      if (names.length === 0) return;
      await commit(names.map((name) => ({ delete: name })));
    }
    throw fatal("wipe: documents remain after 40 rounds");
  }

  async function seed(documents) {
    await commit(
      (documents ?? []).map(({ doc, fields }) => ({
        update: { name: `${documentsName(ctx)}/${doc}`, fields },
      })),
    );
  }

  // ---- requests made as a principal ----------------------------------------------------------

  /** The Authorization header value of a step's `as` (undefined: none). */
  function bearerFor(as) {
    if (as === "none" || as === undefined) return undefined;
    const principal = principals.get(as);
    if (!principal) throw fatal(`unknown principal ${as}`);
    return `Bearer ${principal.idToken}`;
  }

  /** A request the guards refuse is a bug in the corpus or the harness: it stops the run. */
  function guarded(check) {
    try {
      return check();
    } catch (error) {
      throw error.fatal ? error : fatal(String(error.message ?? error));
    }
  }

  async function sendRest(step, { harness = false } = {}) {
    const request = guarded(() => {
      const built = buildFirestoreRest(step, ctx, new Map(), principals, bearerFor(step.as));
      guardFirestoreRequest(built, ctx);
      return built;
    });
    charge(harness);
    let response;
    try {
      response = await fetchImpl(request.url, {
        ...request.init,
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (error) {
      return {
        status: 0,
        recorded: { status: 0, transport: error?.cause?.code ?? error?.name ?? "error" },
      };
    }
    const text = await response.text();
    return {
      status: response.status,
      recorded: normalizeRest(response.status, text, ctx, principals),
    };
  }

  async function sendGrpc(step, { harness = false } = {}) {
    const built = guarded(() => {
      const request = buildFirestoreGrpc(step, ctx, new Map(), principals);
      guardGrpcRequest(request, ctx);
      return request;
    });
    charge(harness);
    const answer = await grpc.call(built, bearerFor(step.as));
    return { code: answer.code, recorded: normalizeGrpc(answer, ctx, principals) };
  }

  async function sendListen(step) {
    const database = databaseName(ctx);
    const parent = step.parent ? `${documentsName(ctx)}/${step.parent}` : documentsName(ctx);
    guarded(() => guardGrpcRequest({ request: { database, parent } }, ctx));
    charge(false);
    const handle = grpc.listen({
      database,
      parent,
      structuredQuery: step.query,
      bearer: bearerFor(step.as),
    });
    const start = now();
    let lastCount = 0;
    let lastChange = start;
    while (!handle.ended()) {
      if (handle.frames.length !== lastCount) {
        lastCount = handle.frames.length;
        lastChange = now();
      }
      if (now() - start >= LISTEN_CAP_MS) break;
      if (handle.frames.length > 0 && now() - lastChange >= LISTEN_IDLE_MS) break;
      await sleep(100);
    }
    const end = handle.ended();
    await handle.close();
    return summarizeListen(handle.frames, end, ctx, principals);
  }

  async function runRow(step) {
    if (step.rpc === "listen") return sendListen(step);
    return (step.transport === "grpc" ? await sendGrpc(step) : await sendRest(step)).recorded;
  }

  // ---- rules publication ---------------------------------------------------------------------

  const releaseResource = () => `projects/${ctx.project}/releases/${RELEASE}`;

  /** An unauthenticated write of the marker document, as the status REST and gRPC answer. */
  async function markerStatus(label) {
    const step = {
      id: "marker",
      as: "none",
      rpc: "patch",
      doc: `fsr-marker/${label}`,
      body: { fields: {} },
    };
    const rest = (await sendRest(step, { harness: true })).status;
    const { code } = await sendGrpc({ ...step, transport: "grpc" }, { harness: true }).catch(
      (error) => {
        if (error.fatal) throw error;
        return { code: -1 };
      },
    );
    const grpcStatus = { 0: 200, 7: 403 }[code] ?? -code - 1;
    return rest === grpcStatus ? rest : `rest ${rest} grpc ${code}`;
  }

  /** The markers a ruleset in force must answer 200 for and every other one 403 for. */
  const expectedMarkers = (label, previous) => [
    ...(label ? [[label, 200]] : []),
    ...(previous && previous !== label ? [[previous, 403]] : []),
  ];

  /**
   * Waits until `settleStreak` consecutive polls, each over REST and gRPC, see `label` in force
   * and the superseded marker refused. Production serves a switch from several frontends that
   * change over at different times, so one good answer proves nothing. fireemu and the official
   * emulator switch synchronously: a disagreement there is a difference the rows record.
   */
  async function settle(label, previous) {
    const expect = expectedMarkers(label, previous);
    if (expect.length === 0 || ctx.target.kind !== "production") return { settleMs: 0, polls: 0 };
    const start = now();
    let streak = 0;
    let polls = 0;
    while (now() - start < SETTLE_LIMIT_MS) {
      let ok = true;
      for (const [marker, status] of expect) ok = ok && (await markerStatus(marker)) === status;
      polls += 1;
      streak = ok ? streak + 1 : 0;
      if (streak >= settleStreak) return { settleMs: now() - start, polls };
      await pause(settlePollMs);
    }
    throw fatal(`release of ${label ?? "nothing"} did not settle`);
  }

  /** Whether the ruleset the rows ran under is still in force (10 polls, production only). */
  async function stillInForce() {
    if (ctx.target.kind !== "production") return true;
    for (let i = 0; i < 10; i += 1) {
      for (const [marker, status] of expectedMarkers(active, previousLabel)) {
        if ((await markerStatus(marker)) !== status) return false;
      }
    }
    return true;
  }

  async function loadLocal(source) {
    return call(
      `${ctx.target.firestoreOrigin}/emulator/v1/projects/${ctx.project}:securityRules`,
      {
        method: "PUT",
        headers: { ...ownerHeaders(), "content-type": "application/json" },
        body: JSON.stringify({ rules: { files: [{ name: "firestore.rules", content: source }] } }),
      },
      { expect: [200, 400, 413, 429, 500, 502, 503, 504], timeout: 600_000 },
    );
  }

  /**
   * Puts a ruleset in force. Returns `{ compiled }`: false when production (rulesets.create) or
   * the emulator refuses to compile it, in which case nothing is in force that was not before.
   * Any other answer is fatal in production and recorded as transient locally.
   */
  async function publish(rulesetId) {
    const label = markerOf(rulesetId);
    const source = rulesetSource(rulesetId);
    if (ctx.target.kind !== "production") {
      const { status } = await loadLocal(source);
      if (status === 400) return { recorded: { compiled: false } };
      if (status !== 200) return { recorded: { status, transport: "compile-status" } };
    } else {
      const created = await admin(
        "POST",
        "rules",
        `v1/projects/${ctx.project}/rulesets`,
        { source: { files: [{ name: "firestore.rules", content: source }] } },
        { expect: [200, 400], mutates: "create ruleset" },
      );
      if (created.status === 400) {
        diagnostics[rulesetId] = {
          stage: "ruleset",
          status: 400,
          message: normalizeString(
            String(created.json?.error?.message ?? "").slice(0, 600),
            ctx,
            principals,
          ),
        };
        return { recorded: { compiled: false } };
      }
      createdRulesets.add(created.json.name);
      // Known before anything is sent, so cleanup deletes the release whatever fails after this.
      released = true;
      const rulesetName = created.json.name;
      // A 400 is a definite refusal (the ruleset stays created, to be deleted at the end); anything
      // unknown is fatal and recorded as unknown by `call`.
      let refusal;
      const patched = await admin(
        "PATCH",
        "rules",
        `v1/${releaseResource()}`,
        { release: { name: releaseResource(), rulesetName } },
        { expect: [200, 400, 404], mutates: "update release" },
      );
      if (patched.status === 400) refusal = patched;
      if (patched.status === 404) {
        const posted = await admin(
          "POST",
          "rules",
          `v1/projects/${ctx.project}/releases`,
          { name: releaseResource(), rulesetName },
          { expect: [200, 400], mutates: "create release" },
        );
        if (posted.status === 400) refusal = posted;
      }
      if (refusal) {
        diagnostics[rulesetId] = {
          stage: "release",
          status: 400,
          message: normalizeString(
            String(refusal.json?.error?.message ?? "").slice(0, 600),
            ctx,
            principals,
          ),
        };
        return { recorded: { compiled: false } };
      }
      const { json } = await admin("GET", "rules", `v1/${releaseResource()}`);
      if (json?.rulesetName !== rulesetName) throw fatal("the release did not read back");
    }
    const settled = await settle(label, active);
    previousLabel = active;
    active = label;
    publications.push({ label, previous: previousLabel, ...settled });
    log(`release: ${label} (${settled.polls} polls, ${settled.settleMs} ms)`);
    return { recorded: { compiled: true } };
  }

  /** Deletes the release (never re-sent on an unknown answer) and waits for the lingering rules. */
  async function unpublish() {
    if (ctx.target.kind !== "production") return;
    if (!released) return;
    await admin("DELETE", "rules", `v1/${releaseResource()}`, undefined, {
      expect: [200, 404],
      mutates: "delete release",
    });
    await settle(null, active);
    active = null;
    released = false;
  }

  async function deleteCreatedRulesets() {
    const errors = [];
    for (const name of createdRulesets) {
      try {
        await admin("DELETE", "rules", `v1/${name}`, undefined, {
          expect: [200, 404],
          mutates: "delete ruleset",
        });
        createdRulesets.delete(name);
      } catch (error) {
        errors.push(String(error.message ?? error));
      }
    }
    if (errors.length) throw fatal(errors.join("; "));
  }

  /**
   * Reads back that the run left the sandbox as it found it (the preflight refuses a sandbox
   * with a release, a ruleset, a named database, an account or a document): no release, no
   * ruleset, no database but `(default)`, no document, no project-level account. Production only.
   */
  async function audit() {
    if (ctx.target.kind !== "production") return [];
    const problems = [];
    const { json: releases } = await admin("GET", "rules", `v1/projects/${ctx.project}/releases`);
    if ((releases?.releases ?? []).length) problems.push("a release remains");
    const { json: rulesets } = await admin("GET", "rules", `v1/projects/${ctx.project}/rulesets`);
    if ((rulesets?.rulesets ?? []).length)
      problems.push(`${rulesets.rulesets.length} ruleset(s) remain`);
    const { json: databases } = await admin(
      "GET",
      "firestore",
      `v1/projects/${ctx.project}/databases`,
    );
    const extra = (databases?.databases ?? []).filter(({ name }) => !name.endsWith("/(default)"));
    if (extra.length) problems.push(`${extra.length} named database(s) remain`);
    const { json: documents } = await admin(
      "POST",
      "firestore",
      `v1/${documentsName(ctx)}:runQuery`,
      {
        structuredQuery: {
          from: [{ allDescendants: true }],
          select: { fields: [{ fieldPath: "__name__" }] },
          limit: 1,
        },
      },
    );
    if ((documents ?? []).some((e) => e.document)) problems.push("a document remains in (default)");
    const { json: accounts } = await admin(
      "POST",
      "itk",
      `v1/projects/${ctx.project}/accounts:query`,
      {
        returnUserInfo: false,
      },
    );
    if (Number(accounts?.recordsCount ?? -1) !== 0)
      problems.push("a project-level account remains");
    return problems;
  }

  // ---- programs ------------------------------------------------------------------------------

  async function runProgram(program) {
    const steps = {};
    await wipe();
    let failure;
    try {
      const [publication, ...rows] = program.steps;
      const outcome = await publish(program.ruleset);
      steps[publication.id] = outcome.recorded;
      const compiled = outcome.recorded.compiled === true;
      if (compiled) {
        // The marker documents the publication wrote must not show in a kindless query.
        await wipe();
        await seed(program.seed);
      }
      for (const step of rows) {
        if (shouldStop()) throw fatal("stopped by a signal");
        steps[step.id] = compiled
          ? await runRow(step)
          : { status: -1, unresolved: `ruleset ${program.ruleset} did not compile` };
        log(`${program.id}#${step.id} ${steps[step.id].status ?? steps[step.id].grpc ?? "listen"}`);
      }
      // A row counts only if the ruleset it ran under was still in force after it.
      if (compiled && !(await stillInForce())) {
        for (const recorded of Object.values(steps)) recorded.publication = "unsettled";
      }
    } catch (error) {
      failure = error;
    }
    let cleanup;
    try {
      await wipe();
    } catch (error) {
      cleanup = error;
    }
    if (cleanup) throw cleanup;
    if (failure) throw failure;
    return { steps };
  }

  return {
    runProgram,
    prepareSignIn,
    createPrincipal,
    deletePrincipals,
    unpublish,
    deleteCreatedRulesets,
    wipe,
    audit,
    principals,
    beginCleanup: () => {
      cleaningUp = true;
    },
    evidence: () => ({ publications, diagnostics, unknowns: [...unknowns] }),
    close: async () => grpc.close(),
    counts: () => ({ requests, harnessRequests }),
  };
}

/**
 * Runs a whole corpus: sign-in first, then every program, then cleanup in reverse order, which
 * always runs. A program that throws is recorded as a failure; a fatal error stops the run after
 * cleanup. `closureReady` is false after any cleanup error or unknown answer to a mutating call.
 */
export async function runCorpus({ programs, principals: specs }, ctx, deps, options = {}) {
  if (ctx.project !== SANDBOX_PROJECT && ctx.target.kind === "production")
    throw new Error("production runs address the sandbox project only");
  const session = createSession(ctx, deps, options);
  const results = {};
  const failures = [];
  let fatalError;
  try {
    await session.prepareSignIn();
    for (const [name, spec] of Object.entries(specs)) await session.createPrincipal(name, spec);
    for (const program of programs) {
      try {
        results[program.id] = await session.runProgram(program);
      } catch (error) {
        if (error.fatal) throw error;
        failures.push({ program: program.id, error: String(error.message ?? error) });
      }
    }
  } catch (error) {
    fatalError = error;
  }
  const cleanupErrors = [];
  session.beginCleanup();
  for (const step of [
    () => session.unpublish(),
    () => session.wipe(),
    () => session.deletePrincipals(),
    () => session.deleteCreatedRulesets(),
    async () => {
      const problems = await session.audit();
      if (problems.length) throw new Error(`audit: ${problems.join("; ")}`);
    },
  ]) {
    try {
      await step();
    } catch (error) {
      cleanupErrors.push(String(error.message ?? error));
    }
  }
  await session.close();
  const evidence = session.evidence();
  const out = {
    context: { run: ctx.run, startedMs: ctx.startedMs },
    results,
    failures,
    cleanupErrors,
    ...evidence,
    closureReady: cleanupErrors.length === 0 && evidence.unknowns.length === 0,
    ...session.counts(),
  };
  if (fatalError) throw Object.assign(fatalError, { partial: out });
  if (cleanupErrors.length)
    throw Object.assign(fatal(`cleanup failed: ${cleanupErrors.join("; ")}`), { partial: out });
  return out;
}

export { isTransient };
