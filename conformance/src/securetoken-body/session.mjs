// One recording of the Secure Token body corpus against one target (the sandbox, or fireemu).
//
// Order: switch multi-tenancy on when it is off, require that no tenant exists, create the run's
// tenant and its three accounts through the Admin API (names carry the run id, so every name is
// the run's own and can be searched for), sign each in for a refresh token, send the rows, then
// clean up: delete the accounts and the tenant with a read-back each, audit that nothing of the
// run remains, and restore multi-tenancy with a read-back. Cleanup always runs; it only deletes
// names the ownership ledger says this run created (shared/ownership.mjs), and it never re-sends
// a delete that answered unknown.
//
// Tokens live in memory. A row is stored as its status and normalized body, the request's field
// names and byte length, and the presence and length of each token in the answer; the journal
// keeps one metadata line per request. No token, password or key is written anywhere.

import { normalizeCredentialResponse } from "../auth-credential/tokens.mjs";
import {
  beginCreate,
  beginDelete,
  closureReport,
  isOwned,
  mayDelete,
  recordAnswer,
  recordRead,
} from "../shared/ownership.mjs";
import { ACCOUNTS, ROWS, accountsNeeded, encodeBody, fieldNames } from "./corpus.mjs";
import {
  buildRequest,
  guardRequest,
  localIdOf,
  requests as R,
  tenantNameOf,
  withProject,
} from "./harness.mjs";

/** An error that must stop the whole recording: the sandbox may no longer be in a known state. */
const fatal = (message) => Object.assign(new Error(message), { fatal: true });
const defaultSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const TOKEN_FIELDS = ["access_token", "id_token", "refresh_token"];

/** Whether the multi-tenancy switch reads as the wanted value (production omits a false). */
export const tenancyIs = (config, wanted) =>
  wanted ? config?.multiTenant?.allowTenants === true : config?.multiTenant?.allowTenants !== true;

export function createSession(ctx, options = {}) {
  const {
    transport = fetch,
    timeoutMs = 60_000,
    maxRequests = Infinity,
    maxHarnessRequests = Infinity,
    ownership,
    journal = () => {},
    sleep = defaultSleep,
    pollMs = 2000,
    pollLimit = 30,
    // Production applies an accepted configuration change before the read-back shows it
    // (AUTH-TENANT-BLOCKING exploration, 2026-09-24): wait this long after it does.
    settleMs = ctx.target.kind === "production" ? 5000 : 0,
    log = () => {},
    shouldStop = () => false,
    rows = ROWS,
  } = options;
  if (!ownership) throw new Error("a session needs an ownership ledger");
  let requestCount = 0;
  let harnessCount = 0;
  let seq = 0;
  const secrets = [];
  const remember = (value) => {
    if (typeof value === "string" && value.length > 0 && !secrets.includes(value))
      secrets.push(value);
  };

  /** Sends one request through the guard; a transport failure is returned, not thrown. */
  async function send(spec, { harness = false } = {}) {
    const request = buildRequest(ctx, withProject(spec, ctx.project));
    guardRequest(request, ctx);
    if (harness) {
      if (harnessCount >= maxHarnessRequests)
        throw fatal(`harness request ceiling ${maxHarnessRequests} reached`);
      harnessCount += 1;
    } else {
      if (requestCount >= maxRequests) throw fatal(`request ceiling ${maxRequests} reached`);
      requestCount += 1;
    }
    // Only a call that carries the owner credential renews it; a sign-in carries the key alone.
    if (spec.auth === "admin" && ctx.target.kind === "production") {
      try {
        await ctx.target.refresh?.();
      } catch (error) {
        throw fatal(`owner credential refresh failed: ${error?.message ?? error}`);
      }
      request.init.headers.authorization = `Bearer ${ctx.target.adminToken}`;
    }
    seq += 1;
    const entry = {
      seq,
      at: new Date().toISOString(),
      harness,
      id: spec.id,
      method: request.init.method,
      path: new URL(request.url).pathname,
    };
    let response;
    let text;
    try {
      response = await transport(request.url, {
        ...request.init,
        signal: AbortSignal.timeout(timeoutMs),
      });
      text = await response.text();
    } catch (error) {
      const code = error?.cause?.code ?? error?.name ?? "error";
      journal({ ...entry, status: 0, transport: code });
      return { status: 0, transport: code, text: undefined, json: null };
    }
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      /* recorded as non-JSON */
    }
    journal({ ...entry, status: response.status, bodyBytes: Buffer.byteLength(text) });
    return { status: response.status, text, json };
  }

  /** A harness call whose only good answer is 200; anything else stops the recording. */
  async function admin(spec) {
    const res = await send(spec, { harness: true });
    if (res.status !== 200)
      throw fatal(
        `harness ${spec.method ?? "POST"} ${spec.path}: ${res.status === 0 ? res.transport : `HTTP ${res.status}`}`,
      );
    // A 200 whose body cannot be read says nothing: reading it as "off" or "empty" would be a guess.
    if (res.json === null)
      throw fatal(`harness ${spec.method ?? "POST"} ${spec.path}: unreadable body`);
    return res.json;
  }

  const answerOf = (res) =>
    res.status === 0
      ? { transportError: res.transport }
      : { status: res.status, bodyReadable: res.text !== undefined };

  // ---- multi-tenancy ----------------------------------------------------------------------

  const tenancy = { before: undefined, switchedOn: false, restored: undefined };

  async function readTenancy() {
    return tenancyIs(await admin(R.readConfig()), true);
  }

  async function setTenancy(allow) {
    await admin(R.writeTenancy(allow));
    for (let attempt = 0; attempt < pollLimit; attempt += 1) {
      const config = await admin(R.readConfig());
      if (tenancyIs(config, allow)) {
        if (settleMs) await sleep(settleMs);
        return;
      }
      await sleep(pollMs);
    }
    throw fatal(`multi-tenancy did not read back as ${allow}`);
  }

  async function listTenants() {
    const found = [];
    let pageToken;
    for (let page = 0; page < 20; page += 1) {
      const json = await admin(R.listTenants(pageToken));
      found.push(...(json?.tenants ?? []));
      pageToken = json?.nextPageToken;
      if (!pageToken) return found;
    }
    throw fatal("the tenant list has more than 20 pages");
  }

  // ---- the run's resources -----------------------------------------------------------------

  const state = { tenantId: undefined, tokens: {}, created: [] };
  const accountName = (key) => `account:${localIdOf(ctx.run, key)}`;
  const tenantName = () => `tenant:${tenantNameOf(ctx.run)}`;

  const tenantIdOfName = (name) =>
    /^projects\/[^/]+\/tenants\/([A-Za-z0-9_-]+)$/.exec(name ?? "")?.[1];

  async function createTenant() {
    const name = tenantName();
    const ticket = beginCreate(ownership, { name, transport: "rest" });
    const res = await send(R.createTenant(ctx.run), { harness: true });
    const id = res.status === 200 ? tenantIdOfName(res.json?.name) : undefined;
    // A 200 whose body names no tenant is not a confirmed create.
    recordAnswer(
      ownership,
      ticket,
      res.status === 200 && id === undefined ? { status: 200, bodyReadable: false } : answerOf(res),
    );
    if (id !== undefined && res.json?.displayName === tenantNameOf(ctx.run)) {
      state.tenantId = id;
      ctx.tenantId = id;
      return;
    }
    // A refusal made no tenant: nothing to look for, and nothing to delete.
    if (res.status >= 400 && res.status < 500 && res.status !== 408)
      throw fatal(`the tenant create was refused (HTTP ${res.status})`);
    // Unknown (or malformed) answer: look for the tenant by its display name, then read it.
    const settled = await settleTenant(name);
    if (!settled) throw fatal(`the answer to the tenant create is unknown and no read shows it`);
  }

  async function settleTenant(name) {
    const candidates = (await listTenants()).filter((t) => t.displayName === tenantNameOf(ctx.run));
    for (const candidate of candidates) {
      const id = tenantIdOfName(candidate.name);
      if (id === undefined) continue;
      ctx.tenantId = id;
      const res = await send(R.getTenant(id), { harness: true });
      const present = res.status === 200 && res.json?.displayName === tenantNameOf(ctx.run);
      recordRead(ownership, {
        name,
        transport: "rest",
        answer: present ? { status: 200, bodyReadable: true, bodyName: name } : answerOf(res),
      });
      if (present) {
        state.tenantId = id;
        return true;
      }
      ctx.tenantId = undefined;
    }
    return false;
  }

  /** What a lookup of an account answered, in the terms of the ownership library. */
  function lookupAnswer(res, key, name) {
    if (res.status === 0) return { transportError: res.transport };
    if (res.status !== 200 || res.json === null) return answerOf(res);
    const users = res.json.users;
    // A missing account reads as 200 without `users` (AUTH-TENANT-BLOCKING selection, recorded).
    if (users === undefined || (Array.isArray(users) && users.length === 0))
      return { status: 404, bodyReadable: true };
    const own = Array.isArray(users) && users.some((u) => u.localId === localIdOf(ctx.run, key));
    return { status: 200, bodyReadable: true, bodyName: own ? name : "other" };
  }

  async function createAccount(key) {
    const name = accountName(key);
    const tenantId = ACCOUNTS[key].tenant ? state.tenantId : undefined;
    const ticket = beginCreate(ownership, { name, transport: "rest" });
    const res = await send(R.createAccount(ctx.run, key, tenantId), { harness: true });
    const classified = recordAnswer(ownership, ticket, answerOf(res));
    if (classified.class !== "ok") {
      if (classified.class !== "unknown")
        throw fatal(`account ${key} was not created (HTTP ${res.status})`);
      const lookup = await send(R.lookupAccount(ctx.run, key, tenantId), { harness: true });
      recordRead(ownership, {
        name,
        transport: "rest",
        answer: lookupAnswer(lookup, key, name),
      });
      if (!isOwned(ownership, name)) throw fatal(`account ${key}: the create answer is unknown`);
    }
    state.created.push(key);
    const signIn = await send(R.signIn(ctx.run, key, tenantId), { harness: true });
    const token = signIn.json?.refreshToken;
    remember(token);
    remember(signIn.json?.idToken);
    if (signIn.status !== 200 || typeof token !== "string" || token === "")
      throw fatal(
        `sign-in of account ${key} answered ${signIn.status === 0 ? signIn.transport : signIn.status}`,
      );
    state.tokens[key] = token;
  }

  // ---- rows --------------------------------------------------------------------------------

  /** The normalized, token-free record of one refresh answer. */
  function recordRefresh(spec, encoded, res) {
    const request = {
      contentType: spec.contentType,
      bodyBytes: Buffer.byteLength(encoded.body),
      fields: fieldNames(spec),
    };
    if (res.status === 0) return { status: 0, transport: res.transport, request };
    for (const field of TOKEN_FIELDS) remember(res.json?.[field]);
    const normalized = normalizeCredentialResponse(res.status, res.text, ctx);
    const masked = maskTenant(normalized);
    const facts = {};
    if (res.json !== null && typeof res.json === "object") {
      facts.tokens = Object.fromEntries(
        TOKEN_FIELDS.filter((f) => typeof res.json[f] === "string").map((f) => [
          f,
          { length: res.json[f].length },
        ]),
      );
      const returned = res.json.refresh_token;
      if (typeof returned === "string")
        facts.refreshTokenReturned =
          Object.entries(state.tokens).find(([, token]) => token === returned)?.[0] ?? "new";
    }
    return { ...masked, request, facts };
  }

  function maskTenant(normalized) {
    if (state.tenantId === undefined) return normalized;
    // The run id inside the tenant id was already replaced by the normalization.
    const runless = state.tenantId.replaceAll(ctx.run, "<run>");
    return JSON.parse(
      JSON.stringify(normalized)
        .replaceAll(state.tenantId, "<tenant>")
        .replaceAll(runless, "<tenant>"),
    );
  }

  async function runRow(spec) {
    const encoded = encodeBody(spec, state.tokens);
    const res = await send(R.refresh(encoded));
    return recordRefresh(spec, encoded, res);
  }

  // ---- cleanup -----------------------------------------------------------------------------

  const cleanupErrors = [];
  const attempt = async (label, action) => {
    try {
      await action();
    } catch (error) {
      cleanupErrors.push(`${label}: ${error?.message ?? error}`);
      return false;
    }
    return true;
  };

  async function deleteAndReadBack(name, deleteSpec, readSpec, toAnswer) {
    if (!mayDelete(ownership, name).allowed) {
      if (isOwned(ownership, name)) cleanupErrors.push(`${name}: may not be deleted`);
      return;
    }
    const ticket = beginDelete(ownership, { name, transport: "rest" });
    const res = await send(deleteSpec, { harness: true });
    recordAnswer(ownership, ticket, answerOf(res));
    const read = await send(readSpec, { harness: true });
    recordRead(ownership, { name, transport: "rest", answer: toAnswer(read) });
  }

  async function cleanup() {
    for (const key of ["t", "b", "a"]) {
      if (!state.created.includes(key)) continue;
      const tenantId = ACCOUNTS[key].tenant ? state.tenantId : undefined;
      await attempt(`account ${key}`, () =>
        deleteAndReadBack(
          accountName(key),
          R.deleteAccount(ctx.run, key, tenantId),
          R.lookupAccount(ctx.run, key, tenantId),
          (read) => lookupAnswer(read, key, accountName(key)),
        ),
      );
    }
    // An account unknown at create and never found is searched for by its local id before the
    // tenant goes (a tenant's accounts go with it, but a project account does not).
    if (state.tenantId !== undefined && isOwned(ownership, tenantName())) {
      await attempt("tenant", () =>
        deleteAndReadBack(
          tenantName(),
          R.deleteTenant(state.tenantId),
          R.getTenant(state.tenantId),
          (read) =>
            read.status === 200 && read.json?.displayName === tenantNameOf(ctx.run)
              ? { status: 200, bodyReadable: true, bodyName: tenantName() }
              : answerOf(read),
        ),
      );
    }
    // Nothing of the run may remain, whether or not this run switched tenancy on.
    await attempt("tenant audit", async () => {
      // Only the run's own tenant is its business; a foreign one is the preflight's to refuse.
      const left = (await listTenants()).filter((t) => t.displayName === tenantNameOf(ctx.run));
      if (left.length) throw new Error(`${left.length} tenant(s) remain`);
    });
    if (tenancy.switchedOn) {
      const clear = closureReport(ownership).closureReady;
      if (clear) {
        tenancy.restored = await attempt("restore multi-tenancy", () => setTenancy(false));
      } else {
        tenancy.restored = false;
        cleanupErrors.push("multi-tenancy left on: a name of this run is not closed");
      }
    }
    await attempt("account audit", async () => {
      const json = await admin(R.countAccounts());
      if (Number(json?.recordsCount ?? -1) !== 0)
        throw new Error(`${json?.recordsCount} project-level account(s) remain`);
    });
  }

  // ---- the recording -----------------------------------------------------------------------

  async function runRecording() {
    const recorded = {};
    let failure;
    try {
      tenancy.before = await readTenancy();
      if (!tenancy.before) {
        tenancy.switchedOn = true; // before the write: a lost answer must still be restored
        await setTenancy(true);
      }
      const existing = await listTenants();
      if (existing.length) throw fatal(`${existing.length} tenant(s) exist; nothing is created`);
      await createTenant();
      for (const key of Object.keys(ACCOUNTS)) {
        if (accountsNeeded(rows).has(key)) await createAccount(key);
      }
      for (const spec of rows) {
        if (shouldStop()) throw fatal("stopped by a signal");
        recorded[spec.id] = await runRow(spec);
        log(`${spec.id} ${recorded[spec.id].status}`);
      }
    } catch (error) {
      failure = error;
    }
    await cleanup();
    const closure = closureReport(ownership);
    // The project id is a sandbox identifier: messages keep the path, not the name.
    const clean = (text) => String(text).replaceAll(ctx.project, "<project>");
    const closureReady =
      closure.closureReady &&
      cleanupErrors.length === 0 &&
      (!tenancy.switchedOn || tenancy.restored === true);
    return {
      run: ctx.run,
      rows: recorded,
      requests: requestCount,
      harnessRequests: harnessCount,
      tenancy: { ...tenancy },
      cleanupErrors: cleanupErrors.map(clean),
      unknowns: closure.unknownAnswers.map((u) => ({
        call: clean(`${u.action} ${u.name}`),
        answer: u.reason,
        state: u.state,
      })),
      ownership: closure,
      closureReady,
      ...(failure
        ? { failure: clean(failure.message ?? failure), fatal: failure.fatal === true }
        : {}),
      secrets,
    };
  }

  return {
    runRecording,
    counts: () => ({ requests: requestCount, harnessRequests: harnessCount }),
  };
}
