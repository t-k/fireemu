// Executes AUTH-CREDENTIAL programs against one target and returns what it answered.
//
// This is the AUTH-ACCOUNT session (`../auth-account/session.mjs`) with what credentials need:
// custom tokens minted per program (IAM `signJwt` in production, a run-local key against
// fireemu), values read from inside issued tokens, relations between tokens of one program,
// and waits that fireemu takes on its virtual clock instead of in real time. It is a separate
// module because the AUTH-ACCOUNT fixture is bound to the digest of its own session source.
//
// Every program starts and ends with a project-wide account wipe. No program changes project
// configuration. Harness calls (wipe, signing, clock) are not recorded as rows but are counted.

import { isDeepStrictEqual } from "node:util";

import { buildRequest, isTransient } from "../auth-account/harness.mjs";
import { guardCredentialRequest, harnessRequest, substituteText } from "./harness.mjs";
import {
  customTokenClaims,
  decodeJwt,
  normalizeCredentialResponse,
  relate,
  signLocally,
  tamper,
  tokenPath,
} from "./tokens.mjs";

/** An error that must stop the whole run: the sandbox may no longer be in a known state. */
const fatal = (message) => Object.assign(new Error(message), { fatal: true });

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** `step:path` → the value at `path` in the raw answer of `step`, descending into tokens. */
function fromRaw(raw, reference) {
  const [stepId, ...rest] = reference.split(":");
  const found = tokenPath(raw.get(stepId), rest.join(":"));
  if (found === undefined) throw new Error(`step ${stepId} recorded nothing at ${rest.join(":")}`);
  return found;
}

/**
 * Resolves the credential forms of a request value: `{$from: "step:path"}` (JWT-aware),
 * `{$token: name, tamper?}`, `{$tamperFrom: "step:path", how}`, `{$chop: "step:path", drop}`,
 * `{$sum: [a, b]}` and `{$string: v}`. What remains is handed to
 * the AUTH-ACCOUNT request builder, which substitutes EMAIL(...), UID(...) and {project}.
 */
export function materialize(value, raw, tokens) {
  if (Array.isArray(value)) return value.map((v) => materialize(v, raw, tokens));
  if (value && typeof value === "object") {
    if (typeof value.$from === "string") return fromRaw(raw, value.$from);
    if (typeof value.$token === "string") {
      const token = tokens.get(value.$token);
      if (token === undefined) throw fatal(`custom token ${value.$token} was not minted`);
      return value.tamper ? tamper(token, value.tamper) : token;
    }
    if (typeof value.$tamperFrom === "string")
      return tamper(fromRaw(raw, value.$tamperFrom), value.how);
    if (typeof value.$chop === "string")
      return String(fromRaw(raw, value.$chop)).slice(0, -value.drop);
    if (Array.isArray(value.$sum)) {
      return value.$sum.map((v) => Number(materialize(v, raw, tokens))).reduce((a, b) => a + b, 0);
    }
    if (value.$string !== undefined) return String(materialize(value.$string, raw, tokens));
    if (value.$json !== undefined) return JSON.stringify(materialize(value.$json, raw, tokens));
    if (typeof value.$repeat === "string") return value.$repeat.repeat(value.count);
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, materialize(v, raw, tokens)]),
    );
  }
  return value;
}

export function createSession(
  ctx,
  {
    timeoutMs = 60_000,
    maxRequests = Infinity,
    maxHarnessRequests = Infinity,
    signers,
    log = () => {},
  } = {},
) {
  let requests = 0;
  let harnessRequests = 0;

  /** A credential that cannot be renewed stops the run: nothing after it could clean up. */
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
    // An owner access token lives about an hour; the expiry program waits longer than that.
    if (ctx.target.kind === "production" && step.auth === "admin") await refreshCredential();
    const request = buildRequest(step, ctx, raw);
    guardCredentialRequest(request, ctx, { harness });
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
    return { recorded: normalizeCredentialResponse(response.status, text, ctx), json };
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
      await wipeRounds();
    } catch (error) {
      throw error.fatal ? error : fatal(`wipe failed: ${error?.message ?? error}`);
    }
  }

  async function wipeRounds() {
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
    throw fatal("wipe: accounts remain after 20 rounds");
  }

  /** One custom token: production signs through IAM `signJwt`, fireemu's run through a local key. */
  async function mint(spec) {
    const signer = signers?.[spec.signer ?? "project"];
    if (!signer) throw fatal(`no signer ${spec.signer}`);
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
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (error) {
      throw fatal(`signJwt for ${spec.signer}: ${error?.cause?.code ?? error?.name ?? "error"}`);
    }
    const body = await response.json().catch(() => null);
    if (response.status !== 200 || typeof body?.signedJwt !== "string") {
      throw fatal(`signJwt for ${spec.signer}: HTTP ${response.status}`);
    }
    // The locally signed stand-in must carry exactly what production signed; a signer that
    // adds or changes a claim would make the two sides compare different tokens.
    if (!isDeepStrictEqual(decodeJwt(body.signedJwt)?.claims, claims)) {
      throw fatal(`signJwt for ${spec.signer} signed claims other than the requested ones`);
    }
    return body.signedJwt;
  }

  /**
   * Waits until `seconds` (Unix time) plus a 300 ms margin, so a request lands inside the
   * intended whole second whatever the transport latency: production sleeps, fireemu moves its
   * virtual clock to the same instant.
   */
  async function waitUntil(seconds) {
    const target = seconds * 1000 + 300;
    if (ctx.target.kind === "production") {
      await sleep(Math.max(0, target - Date.now()));
      // A timer that fired late (a sleeping machine, a slow answer before it) would record the
      // wrong side of the edge: the caller records that step as indeterminate instead.
      return Date.now() - target <= 200;
    }
    charge(true);
    const request = harnessRequest.advanceClockTo(ctx, target);
    const response = await fetch(request.url, request.init);
    if (response.status !== 200) throw fatal(`clock:advanceTo ${target}: HTTP ${response.status}`);
    return true;
  }

  /** Production waits in real time; fireemu moves its virtual clock (see run.mjs ordering). */
  async function wait(seconds) {
    if (ctx.target.kind === "production") {
      await sleep(seconds * 1000);
      return;
    }
    charge(true);
    const request = harnessRequest.advanceClock(ctx, seconds);
    const response = await fetch(request.url, request.init);
    if (response.status !== 200) throw fatal(`clock:advance ${seconds}: HTTP ${response.status}`);
  }

  async function runProgram(program) {
    const raw = new Map();
    const steps = {};
    const tokens = new Map();
    await wipe();
    let failure;
    try {
      for (const [name, spec] of Object.entries(program.tokens ?? {})) {
        tokens.set(name, await mint(spec));
      }
      for (const step of program.steps) {
        if (step.delayMs) await sleep(step.delayMs);
        if (step.waitSeconds >= 600) {
          // Fail before a long wait, not after it, when an earlier answer says nothing.
          const silent = Object.entries(steps).find(([, recorded]) => isTransient(recorded));
          if (silent) throw new Error(`${silent[0]} was indeterminate; not waiting for ${step.id}`);
        }
        if (step.waitSeconds) await wait(step.waitSeconds);
        if (step.waitUntil) {
          // `{of: "step:path" | "token:name:claim", plus}`: a time claim of an earlier answer
          // or of a minted custom token, plus whole seconds.
          const [kind, name, claim] = step.waitUntil.of.split(":");
          let base;
          try {
            base =
              kind === "token"
                ? decodeJwt(tokens.get(name) ?? "")?.claims?.[claim]
                : fromRaw(raw, step.waitUntil.of);
          } catch {
            base = undefined;
          }
          // An answer that carried no time leaves the step to record its missing dependency.
          if (typeof base === "number" && !(await waitUntil(base + step.waitUntil.plus))) {
            const recorded = { status: 0, transport: "late-timer" };
            raw.set(step.id, null);
            steps[step.id] = recorded;
            log(`${program.id}#${step.id} late`);
            continue;
          }
        }
        let outcome;
        try {
          const concrete = {
            ...step,
            body: materialize(step.body, raw, tokens),
            form: materialize(step.form, raw, tokens),
            query: materialize(step.query, raw, tokens),
          };
          outcome = await send(concrete, raw);
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
    } catch (error) {
      failure = error;
    }
    let wipeFailure;
    try {
      await wipe();
    } catch (error) {
      wipeFailure = error;
    }
    if (wipeFailure) throw wipeFailure;
    if (failure) throw failure;
    return { steps };
  }

  return { runProgram, wipe, counts: () => ({ requests, harnessRequests }) };
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
