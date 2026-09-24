// Executes AUTH-MFA programs against one target and returns what it answered.
//
// This is the AUTH-ACTION session (`../auth-action/session.mjs`) with what second factors need:
// the project `mfa` config, read before a program, applied and read back, and always restored
// and read back afterwards; TOTP codes computed from the secret an enrollment start returned at
// the target's own clock (production: this machine's clock; fireemu: its virtual clock, read
// through the control API); a step can first move to the middle of a 30-second step, so that a
// code's position in the window does not depend on latency; second factors named per program
// (harness.mjs); and custom tokens minted per program as the AUTH-CREDENTIAL session mints them
// (IAM `signJwt` in production, a run-local key against fireemu). Codes, secrets, session infos and pending credentials are never
// recorded. It is a separate module because the other fixtures are bound to the digests of
// their own sessions.
//
// Every program starts and ends with a project-wide account wipe. Harness calls (wipe, config,
// clock) are not recorded as rows but are counted.

import {
  buildRequest,
  isTransient,
  normalizeConfig,
  sameRecording,
} from "../auth-account/harness.mjs";
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
import { guardMfaRequest } from "./guard.mjs";
import {
  TOTP_PERIOD_SECONDS,
  createEnrollmentRegistry,
  deadlineAfter,
  normalizeMfaResponse,
  timeStep,
  totpCode,
  wrongCode,
} from "./harness.mjs";

/** An error that must stop the whole run: the sandbox may no longer be in a known state. */
const fatal = (message) => Object.assign(new Error(message), { fatal: true });

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Where in a 30-second step a code-sensitive step may start, in seconds. */
export const ALIGN_WINDOW = { from: 4, to: 14 };
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

/** `step:path` → the value at `path` in the raw answer of `step`, descending into tokens. */
function fromRaw(raw, reference) {
  const [stepId, ...rest] = reference.split(":");
  return tokenPath(raw.get(stepId), rest.join(":"));
}

/** The shared secret an enrollment start answered, or the dependency error a row records. */
function secretOf(raw, stepId) {
  const secret = raw.get(stepId)?.totpSessionInfo?.sharedSecretKey;
  if (typeof secret !== "string")
    throw new Error(`step ${stepId} recorded nothing at totpSessionInfo.sharedSecretKey`);
  return secret;
}

/**
 * Resolves the code forms of a request value against the target's clock: `{$totp: step,
 * offset}` (the code `offset` steps from now, from the secret `step` answered), `{$totpWrong:
 * step}` (a code no nearby step produces) and `{$sameCode: step}` (exactly the code an earlier
 * step sent). `sent` collects the codes this step sends.
 */
export function resolveCodes(value, raw, codes, nowSeconds, sent) {
  if (Array.isArray(value)) return value.map((v) => resolveCodes(v, raw, codes, nowSeconds, sent));
  if (value && typeof value === "object") {
    if (typeof value.$totp === "string") {
      const code = totpCode(secretOf(raw, value.$totp), timeStep(nowSeconds) + (value.offset ?? 0));
      sent.push(code);
      return code;
    }
    if (typeof value.$totpWrong === "string") {
      const code = wrongCode(secretOf(raw, value.$totpWrong), timeStep(nowSeconds));
      sent.push(code);
      return code;
    }
    if (typeof value.$sameCode === "string") {
      const code = codes.get(value.$sameCode);
      if (code === undefined) throw new Error(`step ${value.$sameCode} recorded nothing at code`);
      sent.push(code);
      return code;
    }
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, resolveCodes(v, raw, codes, nowSeconds, sent)]),
    );
  }
  return value;
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
    log = () => {},
  } = {},
) {
  let requests = 0;
  let harnessRequests = 0;
  // Wipes and the config restore draw on their own reserve, so a run that used up its harness
  // budget can still delete its accounts and switch MFA back off.
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
      if (cleanupRequests >= maxCleanupRequests) {
        throw fatal(`cleanup request ceiling ${maxCleanupRequests} reached`);
      }
      cleanupRequests += 1;
    } else if (harness) {
      if (harnessRequests >= maxHarnessRequests) {
        throw fatal(`harness request ceiling ${maxHarnessRequests} reached`);
      }
      harnessRequests += 1;
    } else {
      if (requests >= maxRequests) throw fatal(`request ceiling ${maxRequests} reached`);
      requests += 1;
    }
  };

  function localControl() {
    const control = new URL(ctx.target.control.url);
    if (!["127.0.0.1", "localhost", "[::1]"].includes(control.hostname))
      throw fatal("control API must be loopback");
    return {
      origin: control.origin,
      headers: {
        "content-type": "application/json",
        ...(ctx.target.control.token
          ? { authorization: `Bearer ${ctx.target.control.token}` }
          : {}),
      },
    };
  }

  /** The target's clock in Unix seconds: this machine's in production, fireemu's own locally. */
  async function nowSeconds() {
    if (ctx.target.kind === "production") return Date.now() / 1000;
    charge(true);
    const { origin, headers } = localControl();
    const response = await fetch(`${origin}/v1/sessions/default`, { headers });
    if (response.status !== 200) throw fatal(`clock read: HTTP ${response.status}`);
    // `{clock: {clock: "<rfc3339>", backwardsSets}}` (control.rs `clock_json`).
    const clock = (await response.json())?.clock?.clock;
    // Date.parse keeps milliseconds; a longer fraction is cut to them.
    const millis = Date.parse(String(clock).replace(/(\.\d{3})\d+/, "$1"));
    if (!Number.isFinite(millis)) throw fatal(`clock read: ${clock}`);
    return millis / 1000;
  }

  /** Production waits in real time; fireemu moves its virtual clock. */
  async function wait(seconds) {
    if (ctx.target.kind === "production") {
      await sleep(seconds * 1000);
      return;
    }
    charge(true);
    const { origin, headers } = localControl();
    const response = await fetch(`${origin}/v1/sessions/default/clock:advance`, {
      method: "POST",
      headers,
      body: JSON.stringify({ millis: Math.round(seconds * 1000) }),
    });
    if (response.status !== 200) throw fatal(`clock:advance ${seconds}: HTTP ${response.status}`);
  }

  /** Moves to the reviewed part of a TOTP step, so a few requests stay inside that step. */
  async function align() {
    const now = await nowSeconds();
    const into = now % TOTP_PERIOD_SECONDS;
    if (into >= ALIGN_WINDOW.from && into <= ALIGN_WINDOW.to) return;
    const target =
      into < ALIGN_WINDOW.from
        ? ALIGN_WINDOW.from + 0.5 - into
        : TOTP_PERIOD_SECONDS - into + ALIGN_WINDOW.from + 0.5;
    await wait(target);
  }

  async function send(step, raw, registry, { harness = false, cleanup = false } = {}) {
    if (ctx.target.kind === "production" && step.auth === "admin") await refreshCredential();
    const request = buildRequest(step, ctx, raw);
    guardMfaRequest(request, ctx, { harness: harness || cleanup });
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
      recorded: normalizeMfaResponse(response.status, text, ctx, registry, {
        project: step.project,
      }),
      json,
    };
  }

  async function admin(method, path, { body, query, cleanup = false } = {}) {
    const { recorded, json } = await send(
      { id: "harness", method, path, auth: "admin", body, query },
      new Map(),
      createEnrollmentRegistry(),
      { harness: true, cleanup },
    );
    if (recorded.status !== 200) {
      // A failed config answer may carry key material: only its error member is shown.
      throw fatal(
        `harness ${method} ${path}: HTTP ${recorded.status} ${JSON.stringify(recorded.body?.error ?? null)}`,
      );
    }
    return json;
  }

  /** One custom token: production signs through IAM `signJwt`, fireemu's run through a local key. */
  async function mint(spec) {
    const signer = signers?.[spec.signer ?? "project"];
    if (!signer) throw fatal(`no signer ${spec.signer ?? "project"}`);
    const claims = customTokenClaims(
      spec,
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
    // The locally signed stand-in must carry exactly what production signed.
    if (!isDeepStrictEqual(decodeJwt(body.signedJwt)?.claims, claims))
      throw fatal("signJwt signed claims other than the requested ones");
    return body.signedJwt;
  }

  /** Deletes every account in the project; any failure leaves the sandbox unknown, so it is fatal. */
  async function wipe() {
    try {
      for (let round = 0; round < 20; round += 1) {
        const page = await admin("GET", "v1/projects/{project}/accounts:batchGet", {
          query: { maxResults: 1000 },
          cleanup: true,
        });
        const ids = (page.users ?? []).map((u) => u.localId);
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
    const config = await admin("GET", "admin/v2/projects/{project}/config", { cleanup });
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
      // `mfa` exactly: a provider left behind by a partial match would change later programs.
      const matches = (path) =>
        path === "mfa"
          ? sameRecording(now[path], values[path])
          : configMatches(now[path], values[path]);
      if (mask.every(matches)) {
        if (ctx.target.kind === "production") await sleep(CONFIG_SETTLE_MS);
        return now;
      }
      if (ctx.target.kind === "production") await sleep(2000);
    }
    throw fatal(`config ${mask.join(",")} did not read back`);
  }

  /** Fails before a long wait, not after it, when an earlier answer says nothing. */
  function assertNothingSilent(steps, step) {
    const silent = Object.entries(steps).find(([, recorded]) => isTransient(recorded));
    if (silent) throw new Error(`${silent[0]} was indeterminate; not waiting for ${step.id}`);
  }

  async function runSteps(program, raw, steps, registry, tokens) {
    const codes = new Map();
    // When each resource an aged row names was acquired, on the target's clock.
    const agedFrom = new Set(program.steps.map((step) => step.age?.from).filter(Boolean));
    const acquired = new Map();
    for (const step of program.steps) {
      // fireemu's clock follows the wall clock only forward: once an alignment or an age moved
      // it ahead, a real sleep would not move it, so it moves the clock instead.
      if (step.delayMs) await wait(step.delayMs / 1000);
      if (step.waitSeconds >= 600) assertNothingSilent(steps, step);
      if (step.waitSeconds) await wait(step.waitSeconds);
      if (step.age) {
        const since = acquired.get(step.age.from);
        if (since === undefined) throw fatal(`${step.id}: ${step.age.from} was never sent`);
        const remaining = since + step.age.seconds - (await nowSeconds());
        if (remaining >= 600) assertNothingSilent(steps, step);
        // Half a second past the age, so a refusal is attributed to an age at least this old.
        if (remaining > -0.5) await wait(remaining + 0.5);
      }
      if (step.align) await align();
      let outcome;
      let sentAt;
      try {
        const needsClock = usesCodes(step.body) || step.deadline || agedFrom.has(step.id);
        const now = needsClock ? await nowSeconds() : undefined;
        const sent = [];
        const concrete = {
          ...step,
          body: materialize(resolveCodes(step.body, raw, codes, now, sent), raw, tokens),
          form: materialize(step.form, raw, tokens),
          query: materialize(step.query, raw, tokens),
        };
        if (sent.length) codes.set(step.id, sent[0]);
        sentAt = now;
        if (agedFrom.has(step.id)) acquired.set(step.id, now);
        if (step.age) {
          const age = now - acquired.get(step.age.from);
          log(`${program.id}#${step.id} aged ${age.toFixed(1)} s (target ${step.age.seconds})`);
        }
        outcome = await send(concrete, raw, registry);
      } catch (error) {
        if (error.fatal || !/recorded nothing at/.test(String(error.message))) throw error;
        // An earlier step did not return what this one needs: record that, keep going.
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
      if (step.deadline) {
        const instant = json?.totpSessionInfo?.finalizeEnrollmentTime;
        relations.finalizeDeadline =
          typeof instant === "string" ? deadlineAfter(instant, sentAt) : "missing";
      }
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
    const raw = new Map();
    const steps = {};
    const registry = createEnrollmentRegistry();
    const tokens = new Map();
    let projection;
    await wipe();
    const mask = program.config ? Object.keys(program.config) : [];
    const baseline = mask.length ? await readConfig(mask) : undefined;
    let failure;
    try {
      if (mask.length) {
        const applied = await writeConfig(mask, program.config);
        projection = {
          baseline: normalizeConfig(baseline, ctx),
          applied: normalizeConfig(applied, ctx),
        };
      }
      for (const [name, spec] of Object.entries(program.tokens ?? {}))
        tokens.set(name, await mint(spec));
      await runSteps(program, raw, steps, registry, tokens);
    } catch (error) {
      failure = error;
    }
    // Cleanup always runs: accounts first, then the config back to what it was (a program with
    // a recorded config step always declares a config, guard.mjs).
    let wipeFailure;
    try {
      await wipe();
    } catch (error) {
      wipeFailure = error;
    }
    if (mask.length) {
      try {
        const restored = await writeConfig(mask, baseline, { cleanup: true });
        projection = { ...projection, restored: normalizeConfig(restored, ctx) };
      } catch (error) {
        const now = await readConfig(mask, { cleanup: true }).catch(() => "unreadable");
        log(`SANDBOX CONFIG CHANGED by ${program.id}: ${JSON.stringify(now)}`);
        throw error.fatal ? error : fatal(String(error.message ?? error));
      }
    }
    if (wipeFailure) throw wipeFailure;
    if (failure) throw failure;
    return { steps, ...(projection ? { config: projection } : {}) };
  }

  return {
    runProgram,
    wipe,
    readConfig,
    counts: () => ({ requests, harnessRequests: harnessRequests + cleanupRequests }),
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
        throw Object.assign(error, { partial: { results, failures, ...session.counts() } });
      failures.push({ program: program.id, error: String(error.message ?? error) });
    }
  }
  await session.wipe();
  return { results, failures, ...session.counts() };
}
