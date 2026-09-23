// Executes AUTH-ACCOUNT programs against one target and returns what it answered.
//
// Every program starts and ends with a project-wide account wipe (the sandbox and the local
// emulator are wholly owned). A program with `config` reads the current values of its masked
// fields, patches them, waits until a read-back shows them, runs, and always restores and
// re-reads the original values, even when a step fails. Harness calls (wipe, config) are not
// recorded as rows but are counted.

import { buildRequest, normalizeResponse, resolveValue, sameRecording } from "./harness.mjs";

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

export function createSession(ctx, { timeoutMs = 60_000, settleMs = 0, log = () => {} } = {}) {
  let requests = 0;
  let harnessRequests = 0;

  async function send(step, raw, { harness = false } = {}) {
    const { url, init } = buildRequest(step, ctx, raw);
    if (harness) harnessRequests += 1;
    else requests += 1;
    let response;
    try {
      response = await fetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
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
    return { recorded: normalizeResponse(response.status, text, ctx), json };
  }

  async function admin(method, path, { body, query } = {}) {
    const { recorded, json } = await send(
      { id: "harness", method, path, auth: "admin", body, query },
      new Map(),
      { harness: true },
    );
    if (recorded.status !== 200) {
      throw new Error(
        `harness ${method} ${path}: HTTP ${recorded.status} ${JSON.stringify(recorded.body ?? recorded)}`,
      );
    }
    return json;
  }

  /** Deletes every account in the project. */
  async function wipe() {
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
    throw new Error("wipe: accounts remain after 20 rounds");
  }

  async function readConfig(mask) {
    const config = await admin("GET", "admin/v2/projects/{project}/config");
    return Object.fromEntries(mask.map((path) => [path, pick(config, path)]));
  }

  async function writeConfig(mask, values) {
    const body = {};
    for (const path of mask) assign(body, path, values[path]);
    await admin("PATCH", "admin/v2/projects/{project}/config", {
      body,
      query: { updateMask: mask.join(",") },
    });
    for (let attempt = 0; attempt < 30; attempt += 1) {
      const now = await readConfig(mask);
      if (mask.every((path) => sameRecording(now[path] ?? null, values[path] ?? null))) {
        if (settleMs) await sleep(settleMs);
        return now;
      }
      await sleep(2000);
    }
    throw new Error(`config ${mask.join(",")} did not read back`);
  }

  async function runProgram(program) {
    const raw = new Map();
    const steps = {};
    let projection;
    await wipe();
    const mask = program.config ? Object.keys(program.config) : [];
    const baseline = mask.length ? await readConfig(mask) : undefined;
    try {
      if (mask.length) {
        const applied = await writeConfig(mask, resolveValue(program.config, ctx, raw));
        projection = { baseline, applied };
      }
      for (const step of program.steps) {
        if (step.delayMs) await sleep(step.delayMs);
        const { recorded, json } = await send(step, raw);
        raw.set(step.id, json);
        steps[step.id] = recorded;
        log(`${program.id}#${step.id} ${recorded.status}`);
      }
    } finally {
      if (mask.length) {
        const restored = await writeConfig(mask, baseline);
        projection = { ...projection, restored };
      }
      await wipe();
    }
    return { steps, ...(projection ? { config: projection } : {}) };
  }

  return {
    runProgram,
    wipe,
    readConfig,
    writeConfig,
    counts: () => ({ requests, harnessRequests }),
  };
}

/** Runs every program; a program that throws is recorded as a harness failure, not a row. */
export async function runCorpus(programs, ctx, options = {}) {
  const session = createSession(ctx, options);
  const results = {};
  const failures = [];
  if (options.baselineConfig) {
    await session.writeConfig(Object.keys(options.baselineConfig), options.baselineConfig);
  }
  for (const program of programs) {
    try {
      results[program.id] = await session.runProgram(program);
    } catch (error) {
      failures.push({ program: program.id, error: String(error.message ?? error) });
    }
  }
  await session.wipe();
  return { results, failures, ...session.counts() };
}
