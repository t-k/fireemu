// Executes AUTH-TENANT-BLOCKING programs against one target and returns what it answered.
//
// This is the AUTH-MFA session with tenants: a program switches the project's multi-tenancy on
// for its own duration (owner decision TB2), creates the tenants its corpus names, and at its
// end deletes every tenant it created or saw created, reads the tenant list back, switches
// multi-tenancy off again and reads that back. Project settings a program changes (T7) are
// restored and read back the same way. Requests name a tenant as `TENANT(label)` (a tenant the
// harness created) or `{$tenantOf: step}` (the tenant a recorded step created). TOTP codes are
// computed from the secret an enrollment start returned at the target's own clock, and custom
// tokens are minted as the AUTH-CREDENTIAL session mints them. Codes, secrets, session infos and
// pending credentials are never recorded.
//
// Every program starts and ends with a project-wide account wipe; a tenant's accounts go with
// the tenant. Harness calls are not recorded as rows but are counted.

import { buildRequest, isTransient, normalizeConfig } from "../auth-account/harness.mjs";
import { configMatches } from "../auth-account/session.mjs";
import { isDeepStrictEqual } from "node:util";

import { harnessRequest, substituteText } from "../auth-credential/harness.mjs";
import { materialize } from "../auth-credential/session.mjs";
import {
  customTokenClaims,
  decodeJwt,
  relate,
  signLocally,
  tokenPath,
} from "../auth-credential/tokens.mjs";
import { createEnrollmentRegistry } from "../auth-mfa/harness.mjs";
import { resolveCodes } from "../auth-mfa/session.mjs";
import { DISPLAY_NAME_PREFIX, guardTenantRequest } from "./guard.mjs";
import { createTenantRegistry, normalizeTenantResponse } from "./harness.mjs";

/** An error that must stop the whole run: the sandbox may no longer be in a known state. */
const fatal = (message) => Object.assign(new Error(message), { fatal: true });

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Answer members whose values are secrets the fixture scan looks for by value. */
const SECRET_MEMBERS = new Set([
  "sharedSecretKey",
  "sessionInfo",
  "mfaPendingCredential",
  "oobCode",
  "oobLink",
  "refreshToken",
  "refresh_token",
  "idToken",
  "id_token",
  "access_token",
  "sessionCookie",
]);

function collectSecrets(value, into, key = "") {
  if (typeof value === "string") {
    if (SECRET_MEMBERS.has(key) && value.length >= 16) into.add(value);
  } else if (Array.isArray(value)) for (const v of value) collectSecrets(v, into, key);
  else if (value && typeof value === "object")
    for (const [k, v] of Object.entries(value)) collectSecrets(v, into, k);
}

/** Production applies an accepted config change before this settles (exploration 2026-09-24). */
const CONFIG_SETTLE_MS = 5000;

function pick(object, path) {
  return path.split(".").reduce((value, key) => (value == null ? undefined : value[key]), object);
}

function assign(object, path, value) {
  const keys = path.split(".");
  let current = object;
  for (const key of keys.slice(0, -1)) current = current[key] ??= {};
  if (value !== undefined) current[keys.at(-1)] = value;
  return object;
}

/** The tenant id at the end of a tenant resource name. */
export function tenantIdOf(name) {
  const match = /\/tenants\/([^/]+)$/.exec(String(name ?? ""));
  return match?.[1];
}

/**
 * Resolves the tenant forms of a request value: `TENANT(label)` inside a string (a tenant the
 * harness created), `{$tenantOf: step}` (the tenant a recorded step created, from its `name`)
 * and `{$phoneKeys: {"PHONE(n)": value}}` (an object keyed by test phones). The AUTH-ACCOUNT
 * request builder substitutes the rest (EMAIL(...), UID(...), PHONE(n), {project}).
 */
export function resolveTenants(value, labels, raw) {
  if (typeof value === "string") {
    return value
      .replaceAll(/TENANT\(([a-z])\)/g, (_, label) => {
        const id = labels.get(label);
        if (id === undefined) throw fatal(`tenant ${label} was not created`);
        return id;
      })
      .replaceAll(/TENANTOF\(([a-z0-9-]+)\)/g, (_, stepId) => {
        const id = tenantIdOf(raw.get(stepId)?.name);
        if (id === undefined) throw new Error(`step ${stepId} recorded nothing at name`);
        return id;
      });
  }
  if (Array.isArray(value)) return value.map((v) => resolveTenants(v, labels, raw));
  if (value && typeof value === "object") {
    if (typeof value.$tenantOf === "string") {
      const id = tenantIdOf(raw.get(value.$tenantOf)?.name);
      if (id === undefined) throw new Error(`step ${value.$tenantOf} recorded nothing at name`);
      return id;
    }
    if (value.$phoneKeys && typeof value.$phoneKeys === "object") {
      return Object.fromEntries(
        Object.entries(value.$phoneKeys).map(([key, v]) => [
          key.replaceAll(/PHONE\((\d)\)/g, (_, i) => {
            const phone = [
              "+16505550101",
              "+16505550102",
              "+16505550103",
              "+16505550104",
              "+16505550105",
              "+16505550106",
            ][Number(i)];
            if (!phone) throw new Error(`no test phone ${i}`);
            return phone;
          }),
          resolveTenants(v, labels, raw),
        ]),
      );
    }
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, resolveTenants(v, labels, raw)]),
    );
  }
  return value;
}

/** `step:path` → the value at `path` in the raw answer of `step`, descending into tokens. */
function fromRaw(raw, reference) {
  const [stepId, ...rest] = reference.split(":");
  return tokenPath(raw.get(stepId), rest.join(":"));
}

const usesCodes = (value) => /"\$(totp|totpWrong|sameCode)"/.test(JSON.stringify(value ?? null));

export function createSession(
  ctx,
  {
    timeoutMs = 60_000,
    maxRequests = Infinity,
    maxHarnessRequests = Infinity,
    maxCleanupRequests = Infinity,
    signers,
    signal,
    configSettleMs = CONFIG_SETTLE_MS,
    log = () => {},
  } = {},
) {
  const seenSecrets = new Set();
  let requests = 0;
  let harnessRequests = 0;
  // Wipes, tenant deletion and config restores draw on their own reserve, so a run that used up
  // its harness budget can still clean up.
  let cleanupRequests = 0;

  async function refreshCredential() {
    try {
      await ctx.target.refresh?.();
    } catch (error) {
      throw fatal(`owner credential refresh failed: ${error?.message ?? error}`);
    }
  }

  const charge = (harness, cleanup = false) => {
    if (cleanup) {
      if (cleanupRequests >= maxCleanupRequests)
        throw fatal(`cleanup request ceiling ${maxCleanupRequests} reached`);
      cleanupRequests += 1;
    } else if (harness) {
      if (harnessRequests >= maxHarnessRequests)
        throw fatal(`harness request ceiling ${maxHarnessRequests} reached`);
      harnessRequests += 1;
    } else {
      if (requests >= maxRequests) throw fatal(`request ceiling ${maxRequests} reached`);
      requests += 1;
    }
  };

  /** The target's clock in Unix seconds: this machine's in production, fireemu's own locally. */
  async function nowSeconds() {
    if (ctx.target.kind === "production") return Date.now() / 1000;
    charge(true);
    const control = new URL(ctx.target.control.url);
    if (!["127.0.0.1", "localhost", "[::1]"].includes(control.hostname))
      throw fatal("control API must be loopback");
    const response = await fetch(`${control.origin}/v1/sessions/default`, {
      headers: ctx.target.control.token
        ? { authorization: `Bearer ${ctx.target.control.token}` }
        : {},
    });
    if (response.status !== 200) throw fatal(`clock read: HTTP ${response.status}`);
    const clock = (await response.json())?.clock?.clock;
    const millis = Date.parse(String(clock).replace(/(\.\d{3})\d+/, "$1"));
    if (!Number.isFinite(millis)) throw fatal(`clock read: ${clock}`);
    return millis / 1000;
  }

  /**
   * One request. `tenants` is the set of tenant ids the guard lets it name; a recorded answer is
   * normalized with the program's registries.
   */
  async function send(step, raw, registries, { harness = false, cleanup = false } = {}) {
    if (ctx.target.kind === "production" && step.auth === "admin") await refreshCredential();
    const request = buildRequest(step, ctx, raw);
    guardTenantRequest(request, ctx, {
      harness: harness || cleanup,
      tenants: new Set(registries.tenants.ids()),
    });
    charge(harness, cleanup);
    let response;
    try {
      // A redirect would lead to a URL the guard never saw.
      response = await fetch(request.url, {
        ...request.init,
        redirect: "error",
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (error) {
      return {
        recorded: { status: 0, transport: error?.cause?.code ?? error?.name ?? "error" },
        json: null,
      };
    }
    const text = await response.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      /* recorded as non-JSON */
    }
    return {
      recorded: normalizeTenantResponse(response.status, text, ctx, registries, {
        project: step.project,
      }),
      json,
    };
  }

  const harnessRegistries = () => ({
    enrollments: createEnrollmentRegistry(),
    tenants: createTenantRegistry(),
  });

  /** A harness call; any answer but `accept` is fatal. The registries decide which tenants it may name. */
  async function admin(
    method,
    path,
    { body, query, cleanup = false, registries, accept = [200] } = {},
  ) {
    const request = () =>
      send(
        { id: "harness", method, path, auth: "admin", body, query },
        new Map(),
        registries ?? harnessRegistries(),
        { harness: true, cleanup },
      );
    let { recorded, json } = await request();
    if (recorded.status === 401 && cleanup && ctx.target.kind === "production") {
      try {
        await ctx.target.refresh?.({ force: true });
      } catch (error) {
        throw fatal(`owner credential refresh failed: ${error?.message ?? error}`);
      }
      ({ recorded, json } = await request());
    }
    if (!accept.includes(recorded.status)) {
      // A failed config answer may carry key material: only its error member is shown.
      throw fatal(
        `harness ${method} ${path}: HTTP ${recorded.status} ${JSON.stringify(recorded.body?.error ?? null)}`,
      );
    }
    return { status: recorded.status, json };
  }

  /** One custom token: production signs through IAM `signJwt`, fireemu's run through a local key. */
  async function mint(spec, labels) {
    const signer = signers?.[spec.signer ?? "project"];
    if (!signer) throw fatal(`no signer ${spec.signer ?? "project"}`);
    const resolved = resolveTenants(spec, labels, new Map());
    const claims = customTokenClaims(
      resolved,
      signer.serviceAccount,
      Math.floor(Date.now() / 1000),
      (t) => substituteText(t, ctx),
    );
    if (signer.privateKeyPem) return signLocally(claims, signer.privateKeyPem, signer.kid);
    charge(true);
    await refreshCredential();
    const request = harnessRequest.signJwt(ctx, signer.serviceAccount, claims);
    let response;
    try {
      response = await fetch(request.url, {
        ...request.init,
        redirect: "error",
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (error) {
      throw fatal(`signJwt: ${error?.cause?.code ?? error?.name ?? "error"}`);
    }
    const body = await response.json().catch(() => null);
    if (response.status !== 200 || typeof body?.signedJwt !== "string")
      throw fatal(`signJwt: HTTP ${response.status}`);
    if (!isDeepStrictEqual(decodeJwt(body.signedJwt)?.claims, claims))
      throw fatal("signJwt signed claims other than the requested ones");
    return body.signedJwt;
  }

  /** Deletes every project-level account; any failure leaves the sandbox unknown, so it is fatal. */
  async function wipe() {
    try {
      for (let round = 0; round < 20; round += 1) {
        const { json: page } = await admin("GET", "v1/projects/{project}/accounts:batchGet", {
          query: { maxResults: 1000 },
          cleanup: true,
        });
        const ids = (page?.users ?? []).map((u) => u.localId);
        if (ids.length === 0) return;
        await admin("POST", "v1/projects/{project}/accounts:batchDelete", {
          body: { localIds: ids, force: true },
          cleanup: true,
        });
      }
    } catch (error) {
      throw error.fatal ? error : fatal(`wipe failed: ${error?.message ?? error}`);
    }
    throw fatal("wipe: accounts remain after 20 rounds");
  }

  async function readConfig(mask, { cleanup = false } = {}) {
    const { json: config } = await admin("GET", "admin/v2/projects/{project}/config", { cleanup });
    return Object.fromEntries(mask.map((path) => [path, pick(config, path)]));
  }

  /** Patches the masked paths and waits until a read-back shows them; a timeout is fatal. */
  async function writeConfig(mask, values, { cleanup = false } = {}) {
    const body = {};
    for (const path of mask) assign(body, path, values[path]);
    await admin("PATCH", "admin/v2/projects/{project}/config", {
      body,
      query: { updateMask: mask.join(",") },
      cleanup,
    });
    for (let attempt = 0; attempt < 30; attempt += 1) {
      const now = await readConfig(mask, { cleanup });
      if (mask.every((path) => configMatches(now[path], values[path]))) {
        if (ctx.target.kind === "production") await sleep(configSettleMs);
        return now;
      }
      if (ctx.target.kind === "production") await sleep(2000);
    }
    throw fatal(`config ${mask.join(",")} did not read back`);
  }

  /** The tenants the project lists (every page); an unreadable list is fatal. */
  async function listTenants({ cleanup = false, registries } = {}) {
    const ids = [];
    let pageToken;
    for (let page = 0; page < 20; page += 1) {
      const { json } = await admin("GET", "v2/projects/{project}/tenants", {
        query: { pageSize: 100, ...(pageToken ? { pageToken } : {}) },
        cleanup,
        registries,
      });
      for (const tenant of json?.tenants ?? [])
        ids.push({ id: tenantIdOf(tenant.name), displayName: tenant.displayName });
      pageToken = json?.nextPageToken;
      if (!pageToken) return ids;
    }
    throw fatal("tenant list: more than 20 pages");
  }

  /** Creates the tenants a program names, labelled in its registry. */
  async function createTenants(program, registries, labels) {
    for (const [label, spec] of Object.entries(program.tenants ?? {})) {
      const body = resolveTenants(spec, labels, new Map());
      // Its own registries: the program's would name the new tenant by order before its label.
      const { status, json } = await admin("POST", "v2/projects/{project}/tenants", {
        body,
        accept: [200, 400],
      });
      const id = tenantIdOf(json?.name);
      // A refused creation left nothing behind: the program fails, the run goes on.
      if (status !== 200)
        throw new Error(`tenant ${label}: HTTP ${status} ${JSON.stringify(json?.error ?? null)}`);
      if (!id) throw fatal(`tenant ${label}: the answer names no tenant`);
      registries.tenants.label(id, label);
      labels.set(label, id);
      log(`${program.id}: tenant ${label} created`);
    }
  }

  /**
   * Deletes every tenant the program created or saw created, then reads the list back: none of
   * them, and no tenant of the harness's display names, may remain.
   */
  async function deleteTenants(program, registries) {
    for (const id of registries.tenants.ids()) {
      await admin("DELETE", `v2/projects/{project}/tenants/${id}`, {
        cleanup: true,
        registries,
        accept: [200, 404],
      });
    }
    const left = await listTenants({ cleanup: true, registries });
    const ours = left.filter(
      ({ id, displayName }) =>
        registries.tenants.ids().includes(id) ||
        String(displayName ?? "").startsWith(DISPLAY_NAME_PREFIX),
    );
    if (ours.length) throw fatal(`${program.id}: tenants remain after cleanup: ${ours.length}`);
  }

  /**
   * Deletes one tenant a crashed run of this harness left behind (restore-sandbox names it by its
   * display-name prefix); 404 counts as deleted.
   */
  async function deleteHarnessTenant(id) {
    const registries = harnessRegistries();
    registries.tenants.label(id, "r");
    await admin("DELETE", `v2/projects/{project}/tenants/${id}`, {
      cleanup: true,
      registries,
      accept: [200, 404],
    });
  }

  async function runSteps(program, raw, steps, registries, tokens, labels) {
    const codes = new Map();
    for (const step of program.steps) {
      if (signal?.aborted) throw fatal(`stopped by a signal before ${program.id}#${step.id}`);
      let outcome;
      try {
        const now = usesCodes(step.body) ? await nowSeconds() : undefined;
        const sent = [];
        const concrete = {
          ...step,
          path: resolveTenants(step.path, labels, raw),
          body: materialize(
            resolveTenants(resolveCodes(step.body, raw, codes, now, sent), labels, raw),
            raw,
            tokens,
          ),
          form: materialize(resolveTenants(step.form, labels, raw), raw, tokens),
          query: materialize(resolveTenants(step.query, labels, raw), raw, tokens),
        };
        if (sent.length) codes.set(step.id, sent[0]);
        outcome = await send(concrete, raw, registries);
        collectSecrets(outcome.json, seenSecrets);
      } catch (error) {
        if (error.fatal || !/recorded nothing at/.test(String(error.message))) throw error;
        const dependency = /^step (\S+) recorded nothing/.exec(String(error.message))?.[1];
        outcome = {
          recorded: {
            status: -1,
            unresolved: String(error.message),
            dependencyTransient: isTransient(steps[dependency]),
          },
          json: null,
        };
      }
      const { recorded, json } = outcome;
      raw.set(step.id, json);
      const relations = {};
      for (const [name, { kind, left, right }] of Object.entries(step.relations ?? {})) {
        const value = (reference) => {
          try {
            return reference.includes(":") ? fromRaw(raw, reference) : tokenPath(json, reference);
          } catch {
            return undefined;
          }
        };
        relations[name] = relate(kind, value(left), value(right));
      }
      if (Object.keys(relations).length) recorded.relations = relations;
      steps[step.id] = recorded;
      log(`${program.id}#${step.id} ${recorded.status}`);
    }
  }

  async function runProgram(program) {
    if (signal?.aborted) throw fatal(`stopped by a signal before ${program.id}`);
    const raw = new Map();
    const steps = {};
    const registries = harnessRegistries();
    const labels = new Map();
    const tokens = new Map();
    const multiTenant = program.multiTenant !== false;
    const mask = Object.keys(program.config ?? {});
    let projection;
    await wipe();
    const baseline = mask.length ? await readConfig(mask) : undefined;
    let failure;
    try {
      if (multiTenant)
        await writeConfig(["multiTenant.allowTenants"], { "multiTenant.allowTenants": true });
      await createTenants(program, registries, labels);
      if (mask.length) {
        const applied = await writeConfig(mask, program.config);
        projection = {
          baseline: normalizeConfig(baseline, ctx),
          applied: normalizeConfig(applied, ctx),
        };
      }
      for (const [name, spec] of Object.entries(program.tokens ?? {}))
        tokens.set(name, await mint(spec, labels));
      await runSteps(program, raw, steps, registries, tokens, labels);
    } catch (error) {
      failure = error;
    }
    // Cleanup always runs: accounts, then tenants (their accounts go with them), then the
    // project settings, then multi-tenancy off, each read back.
    const problems = [];
    try {
      await wipe();
    } catch (error) {
      problems.push(error);
    }
    if (registries.tenants.ids().length || multiTenant) {
      try {
        // Tenants can only be listed and deleted while multi-tenancy is on; a program that ran
        // with it off switches it on for the cleanup when a step created a tenant anyway.
        if (!multiTenant && registries.tenants.ids().length)
          await writeConfig(
            ["multiTenant.allowTenants"],
            { "multiTenant.allowTenants": true },
            { cleanup: true },
          );
        await deleteTenants(program, registries);
      } catch (error) {
        problems.push(error);
      }
    }
    if (mask.length) {
      try {
        const restored = await writeConfig(mask, baseline, { cleanup: true });
        projection = { ...projection, restored: normalizeConfig(restored, ctx) };
      } catch (error) {
        problems.push(error);
      }
    }
    try {
      await writeConfig(
        ["multiTenant.allowTenants"],
        { "multiTenant.allowTenants": false },
        { cleanup: true },
      );
    } catch (error) {
      problems.push(error);
    }
    if (problems.length) {
      log(
        `SANDBOX STATE UNKNOWN after ${program.id}: ${problems.map((e) => e.message).join("; ")}`,
      );
      throw fatal(problems.map((e) => String(e.message ?? e)).join("; "));
    }
    if (failure) throw failure;
    return { steps, ...(projection ? { config: projection } : {}) };
  }

  return {
    runProgram,
    wipe,
    readConfig,
    writeConfig,
    listTenants,
    deleteHarnessTenant,
    admin,
    counts: () => ({ requests, harnessRequests: harnessRequests + cleanupRequests }),
    secrets: () => [...seenSecrets],
  };
}

/** Runs every program; a program that throws is recorded as a harness failure, not a row. */
export async function runCorpus(programs, ctx, options = {}) {
  const session = createSession(ctx, options);
  const results = {};
  const failures = [];
  for (const program of programs) {
    try {
      results[program.id] = await session.runProgram(program);
    } catch (error) {
      if (error.fatal)
        throw Object.assign(error, {
          partial: { results, failures, ...session.counts() },
          secrets: session.secrets(),
        });
      failures.push({ program: program.id, error: String(error.message ?? error) });
    }
  }
  await session.wipe();
  return { results, failures, secrets: session.secrets(), ...session.counts() };
}
