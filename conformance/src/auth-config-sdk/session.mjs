// Executes AUTH-CONFIG-SDK programs against one target and returns what it answered.
//
// A program is `{id, projection, touches?, steps}`. A step is either an HTTP request (the
// AUTH-ACCOUNT step form: path, auth, method, body, query) or an SDK call (`sdk`, `args`; see
// sdk.mjs). Configuration writes are ordinary recorded steps. What makes them safe on a shared
// sandbox is `touches`: before the first step the session reads the current value of every
// touched path, and afterwards, whatever happened, it wipes the accounts, writes those values
// back and reads them back. A step with `settle` waits (unrecorded reads) until the config shows
// what it wrote, because production applies a change eventually.
//
// Every program starts and ends with a project-wide account wipe. Harness calls (wipe, config
// snapshot, settle and restore) are not recorded as rows but are counted.

import {
  buildRequest,
  isTransient,
  resolveValue,
  sameRecording,
} from "../auth-account/harness.mjs";
import { materialize } from "../auth-credential/session.mjs";
import { guardHttp, leafPaths } from "./guard.mjs";
import { normalizeHttp, normalizeSdk, withoutOtherLanes } from "./harness.mjs";
import { harnessFetch, openSdk, runSdkStep } from "./sdk.mjs";

/** An error that must stop the whole run: the sandbox may no longer be in a known state. */
const fatal = (message) => Object.assign(new Error(message), { fatal: true });

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export function pick(object, path) {
  return path.split(".").reduce((value, key) => (value == null ? undefined : value[key]), object);
}

function assign(object, path, value) {
  const keys = path.split(".");
  let current = object;
  for (const key of keys.slice(0, -1)) current = current[key] ??= {};
  if (value !== undefined) current[keys.at(-1)] = value;
  return object;
}

/** Output-only members production adds to what was written. */
/**
 * Output-only members production adds to what was written. reCAPTCHA keys are provisioned by
 * production when a provider is audited and may outlive the setting that created them.
 */
const OUTPUT_ONLY = new Set(["lastUpdateTime", "schemaVersion", "recaptchaKeys"]);

/**
 * The comparable form of a config value: output-only members dropped, and a false or null
 * member read as absent, because production leaves a false switch out of its answer. An empty
 * object is kept: production answers `{}` for members such as `quota`, and an empty oneof
 * member (`allowByDefault: {}` against `allowlistOnly: {}`) is the whole setting.
 */
export function settledForm(value) {
  if (value === undefined || value === null || value === false) return undefined;
  if (Array.isArray(value)) return value.map(settledForm);
  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([key]) => !OUTPUT_ONLY.has(key))
        .map(([key, v]) => [key, settledForm(v)])
        .filter(([, v]) => v !== undefined),
    );
  }
  return value;
}

/** `{$isoFromNow: seconds}` → the instant that many seconds from now, to whole seconds. */
export function withTimes(value, now = Date.now()) {
  if (Array.isArray(value)) return value.map((v) => withTimes(v, now));
  if (value && typeof value === "object") {
    if (typeof value.$isoFromNow === "number")
      return new Date(now + value.$isoFromNow * 1000).toISOString().replace(/\.\d+Z$/, "Z");
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, withTimes(v, now)]));
  }
  return value;
}

/** Members whose empty-object value is the setting itself (a oneof choice). */
const ONEOF_PARENTS = new Set(["smsRegionConfig"]);

/**
 * The form in which two whole configurations are compared: settled, and an empty object read
 * as absent (a cleared member may be left as `{}`), except the oneof choices of
 * `ONEOF_PARENTS`, where `{}` is the setting.
 */
export function driftForm(value, key = "", parent = "") {
  if (Array.isArray(value)) return value.map((v) => driftForm(v));
  if (value && typeof value === "object") {
    const entries = Object.entries(value)
      .map(([k, v]) => [k, driftForm(v, k, key)])
      .filter(([, v]) => v !== undefined);
    if (entries.length === 0 && !ONEOF_PARENTS.has(parent)) return undefined;
    return Object.fromEntries(entries);
  }
  return value;
}

/** The dotted paths at which two settled configurations differ. */
export function configDrift(a, b, path = "") {
  if (sameRecording(a, b)) return [];
  const object = (v) => v && typeof v === "object" && !Array.isArray(v);
  if (object(a) && object(b)) {
    return [...new Set([...Object.keys(a), ...Object.keys(b)])].flatMap((key) =>
      configDrift(a[key], b[key], path ? `${path}.${key}` : key),
    );
  }
  return [path || "<root>"];
}

/**
 * Whether a config value read back shows everything written: each written member has the
 * written value, and members the server adds (a default minimum length, output-only members)
 * are allowed. An unset value must read back unset. The whole configuration is compared exactly
 * after each program anyway.
 */
export function configCovers(actual, wanted) {
  const want = settledForm(wanted);
  const have = settledForm(actual);
  const empty = (v) =>
    v === undefined || (v && typeof v === "object" && !Array.isArray(v) && !Object.keys(v).length);
  if (empty(want)) return empty(have);
  if (Array.isArray(want)) {
    return (
      Array.isArray(have) &&
      have.length === want.length &&
      want.every((item, i) => configCovers(have[i], item))
    );
  }
  if (typeof want === "object") {
    return (
      have !== null &&
      typeof have === "object" &&
      !Array.isArray(have) &&
      Object.entries(want).every(([key, value]) =>
        // A written empty object (a oneof choice such as `allowByDefault: {}`) must be there.
        value && typeof value === "object" && !Object.keys(value).length
          ? key in have
          : configCovers(have[key], value),
      )
    );
  }
  return sameRecording(have, want);
}

/**
 * Whether a config value read back is the value wanted. At the compared path itself an empty
 * object also counts as unset (a cleared member may read back as `{}`).
 */
export function configEquals(actual, wanted) {
  const top = (value) => {
    const settled = settledForm(value);
    return settled &&
      typeof settled === "object" &&
      !Array.isArray(settled) &&
      !Object.keys(settled).length
      ? null
      : (settled ?? null);
  };
  return sameRecording(top(actual), top(wanted));
}

export function createSession(
  ctx,
  {
    timeoutMs = 60_000,
    maxRequests = Infinity,
    maxHarnessRequests = Infinity,
    maxCleanupRequests = Infinity,
    maxSdkRequests = Infinity,
    settleAttempts = 30,
    settleDelayMs = 2000,
    log = () => {},
    signal,
    fetchImpl = harnessFetch,
  } = {},
) {
  let requests = 0;
  let harnessRequests = 0;
  let cleanupRequests = 0;
  let sdkRequests = 0;

  const charge = (kind) => {
    const limits = {
      step: [requests, maxRequests],
      harness: [harnessRequests, maxHarnessRequests],
      cleanup: [cleanupRequests, maxCleanupRequests],
      sdk: [sdkRequests, maxSdkRequests],
    };
    const [used, limit] = limits[kind];
    if (used >= limit) throw fatal(`${kind} request ceiling ${limit} reached`);
    if (kind === "step") requests += 1;
    else if (kind === "harness") harnessRequests += 1;
    else if (kind === "cleanup") cleanupRequests += 1;
    else sdkRequests += 1;
  };

  async function refreshCredential() {
    try {
      await ctx.target.refresh?.();
    } catch (error) {
      throw fatal(`owner credential refresh failed: ${error?.message ?? error}`);
    }
  }

  const isConfigPath = (path) => /^(admin\/)?v2\/projects\/\{project\}\/config$/.test(path);

  async function send(step, raw, { kind = "step" } = {}) {
    if (ctx.target.kind === "production" && step.auth === "admin") await refreshCredential();
    const request = buildRequest(step, ctx, raw);
    try {
      guardHttp(
        {
          url: request.url,
          method: request.init.method,
          headers: request.init.headers,
          body: request.init.body,
        },
        ctx,
        { role: kind === "step" ? "step" : "harness" },
      );
    } catch (error) {
      throw fatal(`guard refused ${step.id}: ${error.message}`);
    }
    charge(kind);
    let response;
    try {
      // A redirect would lead to a URL the guard never saw.
      response = await fetchImpl(request.url, {
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
      recorded: normalizeHttp(response.status, text, ctx, { config: isConfigPath(step.path) }),
      json,
    };
  }

  async function admin(method, path, { body, query, cleanup = false } = {}) {
    const { recorded, json } = await send(
      { id: "harness", method, path, auth: "admin", body, query },
      new Map(),
      { kind: cleanup ? "cleanup" : "harness" },
    );
    if (recorded.status !== 200) {
      throw fatal(
        `harness ${method} ${path}: HTTP ${recorded.status} ${JSON.stringify(recorded.body ?? recorded)}`,
      );
    }
    return json;
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

  /** Whether any project-level account exists (0 or 1: one page of one). */
  async function accountCount() {
    const page = await admin("GET", "v1/projects/{project}/accounts:batchGet", {
      query: { maxResults: 1 },
      cleanup: true,
    });
    return (page.users ?? []).length;
  }

  async function readConfig(paths, { cleanup = false } = {}) {
    const config = await admin("GET", "admin/v2/projects/{project}/config", { cleanup });
    return Object.fromEntries(paths.map((path) => [path, pick(config, path)]));
  }

  /** Waits until a config read shows `wanted` at every path; a timeout is fatal. */
  async function awaitConfig(wanted, { cleanup = false } = {}) {
    const paths = Object.keys(wanted);
    for (let attempt = 0; attempt < settleAttempts; attempt += 1) {
      const now = await readConfig(paths, { cleanup });
      if (paths.every((path) => configCovers(now[path], wanted[path]))) return now;
      if (ctx.target.kind === "production") await sleep(settleDelayMs);
    }
    const now = await readConfig(paths, { cleanup }).catch(() => "unreadable");
    throw fatal(`config ${paths.join(",")} did not read back: ${JSON.stringify(now)}`);
  }

  /** One restoring PATCH, retried on a failure that may pass (transport, 429, 5xx). */
  async function writeBack(paths, snapshot) {
    const body = {};
    for (const path of paths) assign(body, path, snapshot[path]);
    for (let attempt = 0; ; attempt += 1) {
      try {
        await admin("PATCH", "admin/v2/projects/{project}/config", {
          body,
          query: { updateMask: paths.join(",") },
          cleanup: true,
        });
        return;
      } catch (error) {
        const status = Number(/HTTP (\d+)/.exec(String(error.message))?.[1] ?? 0);
        const passing = status === 0 || status === 429 || status >= 500;
        if (!passing || attempt >= 2) throw error;
        if (ctx.target.kind === "production") await sleep(2000 * (attempt + 1));
      }
    }
  }

  /**
   * Writes the snapshot back and reads it back. A combined write production refuses is retried
   * one path at a time, so one member it will not take back leaves no other member changed.
   */
  async function restore(snapshot) {
    // Only what changed is written back: a member production refuses to write (the email
    // templates, EMAIL_TEMPLATE_UPDATE_NOT_ALLOWED) never changed in the first place.
    const now = await readConfig(Object.keys(snapshot), { cleanup: true });
    const paths = Object.keys(snapshot).filter((path) => !configEquals(now[path], snapshot[path]));
    if (paths.length === 0) return now;
    try {
      await writeBack(paths, snapshot);
    } catch (error) {
      if (paths.length === 1) throw error;
      // Every path is tried, and the refused ones once more, before the run stops.
      let refused = [];
      for (const round of [0, 1]) {
        const pending = round === 0 ? paths : refused;
        refused = [];
        for (const path of pending) {
          try {
            await writeBack([path], snapshot);
          } catch (pathError) {
            if (round === 1) log(`restore of ${path} refused: ${pathError.message}`);
            refused.push(path);
          }
        }
        if (refused.length === 0) break;
      }
      // A refused path another path's restore already brought back (a localized template
      // follows `notification.defaultLocale`) is restored.
      if (refused.length) {
        const after = await readConfig(refused, { cleanup: true });
        refused = refused.filter((path) => !configEquals(after[path], snapshot[path]));
      }
      if (refused.length) throw fatal(`restore refused for ${refused.join(", ")}`);
    }
    return awaitConfig(Object.fromEntries(paths.map((path) => [path, snapshot[path]])), {
      cleanup: true,
    });
  }

  /**
   * The whole configuration as this harness may compare it: other lanes' members left out,
   * output-only members and false switches settled.
   */
  async function fullConfig({ cleanup = false } = {}) {
    const config = await admin("GET", "admin/v2/projects/{project}/config", { cleanup });
    return driftForm(settledForm(withoutOtherLanes(config))) ?? {};
  }

  /** What a settling step waits for: its masked paths as its body sets them. */
  function settleTarget(step, body) {
    const mask = String(step.query?.updateMask ?? "")
      .split(",")
      .filter(Boolean);
    const paths = mask.length ? mask : leafPaths(body);
    return Object.fromEntries(paths.map((path) => [path, pick(body, path)]));
  }

  async function runHttpStep(step, raw) {
    let concrete;
    try {
      concrete = {
        ...step,
        body: materialize(withTimes(step.body), raw, new Map()),
        query: materialize(step.query, raw, new Map()),
      };
      return { ...(await send(concrete, raw)), sentBody: concrete.body };
    } catch (error) {
      if (error.fatal || !/recorded nothing at/.test(String(error.message))) throw error;
      // An earlier step did not return what this one needs: record that, keep going.
      const dependency = /^step (\S+) recorded nothing/.exec(String(error.message))?.[1];
      return {
        recorded: {
          status: -1,
          unresolved: String(error.message),
          dependencyTransient: dependency ? isTransient(raw.get(`recorded:${dependency}`)) : false,
        },
        json: null,
      };
    }
  }

  async function runSteps(program, raw, steps) {
    let opened;
    const kept = new Map();
    let violation;
    try {
      for (const step of program.steps) {
        if (signal?.aborted) throw fatal("stopped by signal");
        if (step.delayMs) await sleep(step.delayMs);
        if (step.sdk) {
          if (!opened) {
            opened = await openSdk(ctx, {
              check(request, role, { bodyPending = false } = {}) {
                try {
                  guardHttp(request, ctx, { role, bodyPending });
                  if (!bodyPending) charge("sdk");
                } catch (error) {
                  violation ??= error;
                  throw error;
                }
              },
              refuse(error) {
                violation ??= error;
              },
            });
          }
          const { outcome } = await runSdkStep(opened, step, ctx, raw, kept);
          if (violation)
            throw fatal(`guard refused an SDK request in ${step.id}: ${violation.message}`);
          steps[step.id] = normalizeSdk(outcome, ctx);
          log(`${program.id}#${step.id} ${steps[step.id].sdk} ${steps[step.id].code ?? ""}`);
          if (step.settleTo && outcome.value !== undefined) await awaitConfig(step.settleTo);
          continue;
        }
        const { recorded, json, sentBody } = await runHttpStep(step, raw);
        raw.set(step.id, json);
        raw.set(`recorded:${step.id}`, recorded);
        steps[step.id] = recorded;
        log(`${program.id}#${step.id} ${recorded.status}`);
        if (step.settle && recorded.status === 200)
          await awaitConfig(settleTarget(step, resolveValue(sentBody ?? {}, ctx, raw)));
      }
    } finally {
      await opened?.close();
    }
    // A request the SDKs make while closing is refused too; it must still stop the run.
    if (violation)
      throw fatal(`guard refused an SDK request in ${program.id}: ${violation.message}`);
  }

  /**
   * Runs one program. `expected` is the whole configuration the program must leave behind (the
   * run's baseline); after the restore, any difference from it stops the run.
   */
  async function runProgram(program, { expected } = {}) {
    const raw = new Map();
    const steps = {};
    await wipe();
    const touches = program.touches ?? [];
    const snapshot = touches.length ? await readConfig(touches) : undefined;
    let failure;
    // The guard lets a program write only the paths it restores.
    ctx.touches = touches;
    try {
      await runSteps(program, raw, steps);
    } catch (error) {
      failure = error;
    } finally {
      ctx.touches = undefined;
    }
    // Cleanup always runs: accounts first (a setting such as duplicate emails may not switch
    // back while duplicates exist), then every touched path back to what it was.
    let wipeFailure;
    try {
      await wipe();
    } catch (error) {
      wipeFailure = error;
    }
    if (snapshot) {
      try {
        await restore(snapshot);
      } catch (error) {
        const now = await readConfig(touches, { cleanup: true }).catch(() => "unreadable");
        log(`SANDBOX CONFIG CHANGED by ${program.id}: ${JSON.stringify(now)}`);
        throw error.fatal ? error : fatal(String(error.message ?? error));
      }
    }
    if (expected !== undefined) {
      const now = await fullConfig({ cleanup: true });
      if (!sameRecording(now, expected)) {
        log(`SANDBOX CONFIG CHANGED by ${program.id} outside its restored paths`);
        throw fatal(
          `${program.id} left the configuration changed: ${JSON.stringify(configDrift(expected, now))}`,
        );
      }
    }
    if (wipeFailure) throw wipeFailure;
    if (failure) throw failure;
    return { steps };
  }

  return {
    runProgram,
    wipe,
    readConfig,
    restore,
    fullConfig,
    accountCount,
    counts: () => ({
      requests,
      sdkRequests,
      harnessRequests: harnessRequests + cleanupRequests,
    }),
  };
}

/** Runs every program; a program that throws is recorded as a harness failure, not a row. */
export async function runCorpus(programs, ctx, options = {}) {
  const session = createSession(ctx, options);
  const results = {};
  const failures = [];
  const expected = await session.fullConfig();
  for (const program of programs) {
    try {
      results[program.id] = await session.runProgram(program, { expected });
    } catch (error) {
      if (error.fatal)
        throw Object.assign(error, { partial: { results, failures, ...session.counts() } });
      failures.push({ program: program.id, error: String(error.message ?? error) });
    }
  }
  await session.wipe();
  return { results, failures, ...session.counts() };
}
