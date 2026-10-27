// The RTDB side of the CV14 run: the sandbox instance and its Rules, the nine writes (seven with the
// ADC token, two with none), and the cleanup back to the starting state. The administration is the
// residual recorder's own code (tools/sdk-smoke-database/rtdb-admin.mjs and the CV11 admin client): the
// same state machine, the same sticky unknown answers, the same read-backs. This module wires it to the
// CV14 prefix and Rules and adds the write of one sequence step.

import { adminClient } from "../../../tools/sdk-smoke-database/cv11-genuine-auth.mjs";
import { Stop, createRtdbAdmin } from "../../../tools/sdk-smoke-database/rtdb-admin.mjs";
import { INSTANCE, LOCATION, PREFIX } from "./frames.mjs";

export { Stop };

// observe/cleanup: admin requests per phase; mutations: admin writes overall (the residual recorder's table).
export const CAPS = { observe: 80, cleanup: 30, mutations: 40, pollsPerOperation: 12 };
// The two writes without a token: nothing else is ever sent without one.
export const ANON_CAPS = { observe: 2, cleanup: 0, mutations: 2 };
const PROPAGATION_MS = 120_000;

/** Nothing is readable or writable, except the one item the unauthenticated writes go to. */
export function rulesFor(prefix) {
  return {
    rules: { ".read": false, ".write": false, [prefix]: { items: { c: { ".write": true } } } },
  };
}

/**
 * `headers` carries the ADC token and the quota project (never in a URL); `packet` holds the project
 * identity and the Rules baseline sha; `now` stamps the answer of each write.
 */
export function createRtdb({
  fetchImpl = fetch,
  headers,
  packet,
  log,
  stop = {},
  secrets = [],
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  now = Date.now,
}) {
  const admin = adminClient({ fetchImpl, headers, log, stop, secrets, caps: CAPS });
  const anonymous = adminClient({ fetchImpl, headers: {}, log, stop, secrets, caps: ANON_CAPS });
  const fns = createRtdbAdmin({
    instance: INSTANCE,
    location: LOCATION,
    caps: CAPS,
    propagationMs: PROPAGATION_MS,
    fireGraceMs: 0,
    rulesFor,
  });
  const options = { mode: "production", packet, prefix: PREFIX };
  const run = {
    admin,
    call: admin.call,
    u: fns.urls(options),
    propagation: false,
    propagationWaited: 0,
    state: { api: "baseline", instance: "baseline", rules: "baseline", data: "baseline" },
    unresolved: [],
    errors: [],
    fireWait: false,
    sleep,
  };

  return {
    run,
    /** API enable, undelete, reenable and the Rules install; throws when a step cannot be trusted. */
    async setup() {
      await fns.setupProduction(run, sleep);
      await fns.installRules(run, options);
      run.propagation = false;
    },
    /** One step of the write sequence; the answer is `ok`, `refused` or `unknown`, and an unknown one is never re-sent. */
    async write(step) {
      const client = step.context === "anonymous" ? anonymous : admin;
      const reply = await client.call(step.id, step.method, run.u.data(step.path), step.body);
      return { outcome: reply.outcome, status: reply.status, answeredAtMs: now() };
    },
    /** Prefix delete, Rules restore, instance retire, API disable, each read back; `closed` only for an exact baseline. */
    async cleanup() {
      run.propagation = false;
      await fns.cleanup(run, options, sleep);
      const restored = Object.values(run.state).every((state) => state === "baseline");
      const accounted =
        admin.counts.logFailures === 0 &&
        anonymous.counts.logFailures === 0 &&
        !run.errors.some((error) => error.startsWith("unexpected"));
      return {
        closed: run.unresolved.length === 0 && restored && accounted,
        errors: [...run.errors],
        unresolved: [...run.unresolved],
        state: { ...run.state },
        counts: { admin: { ...admin.counts }, anonymous: { ...anonymous.counts } },
      };
    },
  };
}
