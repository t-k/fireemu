// Executes AUTH-ACTION programs against one target and returns what it answered.
//
// This is the AUTH-CREDENTIAL session (`../auth-credential/session.mjs`) with what action codes
// need: the email-link switch of the project config, read before a program, applied and read
// back, and always restored and read back afterwards, as the AUTH-ACCOUNT session does; and
// action links described by `normalizeActionResponse`. Custom tokens are not minted here. It is
// a separate module because the AUTH-CREDENTIAL fixture is bound to the digest of its session.
//
// Every program starts and ends with a project-wide account wipe. Harness calls (wipe, config,
// clock) are not recorded as rows but are counted.

import { buildRequest, isTransient, normalizeConfig } from "../auth-account/harness.mjs";
import { configMatches } from "../auth-account/session.mjs";
import { materialize } from "../auth-credential/session.mjs";
import { relate, tokenPath } from "../auth-credential/tokens.mjs";
import { guardActionRequest, normalizeActionResponse } from "./harness.mjs";

/** An error that must stop the whole run: the sandbox may no longer be in a known state. */
const fatal = (message) => Object.assign(new Error(message), { fatal: true });

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

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

export function createSession(
  ctx,
  {
    timeoutMs = 60_000,
    maxRequests = Infinity,
    maxHarnessRequests = Infinity,
    log = () => {},
  } = {},
) {
  let requests = 0;
  let harnessRequests = 0;

  async function refreshCredential() {
    try {
      await ctx.target.refresh?.();
    } catch (error) {
      throw fatal(`owner credential refresh failed: ${error?.message ?? error}`);
    }
  }

  const charge = (harness) => {
    if (harness) {
      if (harnessRequests >= maxHarnessRequests) {
        throw fatal(`harness request ceiling ${maxHarnessRequests} reached`);
      }
      harnessRequests += 1;
    } else {
      if (requests >= maxRequests) throw fatal(`request ceiling ${maxRequests} reached`);
      requests += 1;
    }
  };

  async function send(step, raw, { harness = false } = {}) {
    if (ctx.target.kind === "production" && step.auth === "admin") await refreshCredential();
    const request = buildRequest(step, ctx, raw);
    guardActionRequest(request, ctx, { harness });
    charge(harness);
    let response;
    try {
      response = await fetch(request.url, {
        ...request.init,
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
    return { recorded: normalizeActionResponse(response.status, text, ctx), json };
  }

  async function admin(method, path, { body, query } = {}) {
    const { recorded, json } = await send(
      { id: "harness", method, path, auth: "admin", body, query },
      new Map(),
      { harness: true },
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
        });
        const ids = (page.users ?? []).map((u) => u.localId);
        if (ids.length === 0) return;
        await admin("POST", "v1/projects/{project}/accounts:batchDelete", {
          body: { localIds: ids, force: true },
        });
      }
    } catch (error) {
      throw error.fatal ? error : fatal(`wipe failed: ${error?.message ?? error}`);
    }
    throw fatal("wipe: accounts remain after 20 rounds");
  }

  async function readConfig(mask) {
    const config = await admin("GET", "admin/v2/projects/{project}/config");
    return Object.fromEntries(mask.map((path) => [path, pick(config, path)]));
  }

  /** Patches the masked paths and waits until a read-back shows them; a timeout is fatal. */
  async function writeConfig(mask, values) {
    const body = {};
    for (const path of mask) assign(body, path, values[path]);
    await admin("PATCH", "admin/v2/projects/{project}/config", {
      body,
      query: { updateMask: mask.join(",") },
    });
    for (let attempt = 0; attempt < 30; attempt += 1) {
      const now = await readConfig(mask);
      if (mask.every((path) => configMatches(now[path], values[path]))) return now;
      if (ctx.target.kind === "production") await sleep(2000);
    }
    throw fatal(`config ${mask.join(",")} did not read back`);
  }

  /** Production waits in real time; fireemu moves its virtual clock. */
  async function wait(seconds) {
    if (ctx.target.kind === "production") {
      await sleep(seconds * 1000);
      return;
    }
    charge(true);
    const control = new URL(ctx.target.control.url);
    if (!["127.0.0.1", "localhost", "[::1]"].includes(control.hostname))
      throw fatal("control API must be loopback");
    const response = await fetch(`${control.origin}/v1/sessions/default/clock:advance`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(ctx.target.control.token
          ? { authorization: `Bearer ${ctx.target.control.token}` }
          : {}),
      },
      body: JSON.stringify({ seconds }),
    });
    if (response.status !== 200) throw fatal(`clock:advance ${seconds}: HTTP ${response.status}`);
  }

  async function runSteps(program, raw, steps) {
    for (const step of program.steps) {
      if (step.delayMs) await sleep(step.delayMs);
      if (step.waitSeconds >= 600) {
        // Fail before a long wait, not after it, when an earlier answer says nothing.
        const silent = Object.entries(steps).find(([, recorded]) => isTransient(recorded));
        if (silent) throw new Error(`${silent[0]} was indeterminate; not waiting for ${step.id}`);
      }
      if (step.waitSeconds) await wait(step.waitSeconds);
      let outcome;
      try {
        const concrete = {
          ...step,
          body: materialize(step.body, raw, new Map()),
          form: materialize(step.form, raw, new Map()),
          query: materialize(step.query, raw, new Map()),
        };
        outcome = await send(concrete, raw);
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
      if (step.relations) {
        recorded.relations = Object.fromEntries(
          Object.entries(step.relations).map(([name, { kind, left, right }]) => {
            const value = (reference) => {
              try {
                return reference.includes(":")
                  ? fromRaw(raw, reference)
                  : tokenPath(json, reference);
              } catch {
                return undefined;
              }
            };
            return [name, relate(kind, value(left), value(right))];
          }),
        );
      }
      steps[step.id] = recorded;
      log(`${program.id}#${step.id} ${recorded.status}`);
    }
  }

  async function runProgram(program) {
    const raw = new Map();
    const steps = {};
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
      await runSteps(program, raw, steps);
    } catch (error) {
      failure = error;
    }
    // Cleanup always runs: accounts first, then the config switch back to what it was.
    let wipeFailure;
    try {
      await wipe();
    } catch (error) {
      wipeFailure = error;
    }
    if (mask.length) {
      try {
        const restored = await writeConfig(mask, baseline);
        projection = { ...projection, restored: normalizeConfig(restored, ctx) };
      } catch (error) {
        const now = await readConfig(mask).catch(() => "unreadable");
        log(`SANDBOX CONFIG CHANGED by ${program.id}: ${JSON.stringify(now)}`);
        throw error.fatal ? error : fatal(String(error.message ?? error));
      }
    }
    if (wipeFailure) throw wipeFailure;
    if (failure) throw failure;
    return { steps, ...(projection ? { config: projection } : {}) };
  }

  return { runProgram, wipe, readConfig, counts: () => ({ requests, harnessRequests }) };
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
