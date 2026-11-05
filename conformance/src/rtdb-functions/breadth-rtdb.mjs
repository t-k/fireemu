import { adminClient } from "../../../tools/sdk-smoke-database/cv11-genuine-auth.mjs";
import { Stop, createRtdbAdmin } from "../../../tools/sdk-smoke-database/rtdb-admin.mjs";
import { INSTANCE, LOCATION, PREFIX } from "./breadth-frames.mjs";

export { Stop };
export const CAPS = { observe: 80, cleanup: 40, mutations: 40, pollsPerOperation: 12 };
export const USER_CAPS = { observe: 6, cleanup: 0, mutations: 6 };

export function rulesFor(prefix, nonce) {
  if (!/^[A-Za-z0-9_-]+$/.test(nonce)) throw new Error("invalid nonce");
  const validate = `newData.child('run').val() === '${nonce}'`;
  return {
    rules: {
      ".read": false,
      ".write": false,
      [prefix]: {
        gv: { items: { $id: { ".write": "auth != null", ".validate": validate } } },
        gu: {
          ".write": "auth != null",
          items: { $id: { ".validate": validate } },
          $other: { ".validate": false },
        },
      },
    },
  };
}

export function createRtdb({
  fetchImpl = fetch,
  adminFetch = fetchImpl,
  headers = {},
  packet,
  log,
  stop = {},
  secrets = [],
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  now = Date.now,
  nonce,
  userToken,
}) {
  const written = new Set();
  const admin = adminClient({ fetchImpl: adminFetch, headers, log, stop, secrets, caps: CAPS });
  const userSecrets = [...secrets];
  const user = adminClient({
    fetchImpl,
    headers: {},
    log: (row) =>
      log({
        ...row,
        url: row.url.replace(/([?&]auth=)[^&]*/g, "$1***"),
        body: row.body === undefined ? undefined : "***",
      }),
    stop,
    secrets: userSecrets,
    caps: USER_CAPS,
  });
  const fns = createRtdbAdmin({
    instance: INSTANCE,
    location: LOCATION,
    caps: CAPS,
    propagationMs: 120000,
    fireGraceMs: 0,
    rulesFor: (prefix) => rulesFor(prefix, nonce),
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
    async setup() {
      await fns.setupProduction(run, sleep);
      await fns.installRules(run, options);
      run.propagation = false;
    },
    async write(step) {
      if (!["admin", "user-rest"].includes(step.context)) throw new Stop("invalid write context");
      if (written.has(step.id)) throw new Stop("write already sent");
      let url = run.u.data(step.path);
      if (step.context === "user-rest") {
        const token = userToken();
        if (!token) throw new Stop("missing user token");
        userSecrets.push(token);
        url += `${url.includes("?") ? "&" : "?"}auth=${encodeURIComponent(token)}`;
      }
      written.add(step.id);
      const reply = await (step.context === "user-rest" ? user : admin).call(
        step.id,
        step.method,
        url,
        step.body,
      );
      return { outcome: reply.outcome, status: reply.status, answeredAtMs: now() };
    },
    async cleanup() {
      run.propagation = true;
      run.propagationWaited = 0;
      await fns.cleanup(run, options, sleep);
      run.propagation = false;
      const restored = Object.values(run.state).every((state) => state === "baseline");
      const accounted =
        admin.counts.logFailures === 0 &&
        user.counts.logFailures === 0 &&
        !run.errors.some((error) => error.startsWith("unexpected"));
      return {
        closed: run.unresolved.length === 0 && restored && accounted,
        errors: [...run.errors],
        unresolved: [...run.unresolved],
        state: { ...run.state },
        counts: { admin: { ...admin.counts }, user: { ...user.counts } },
      };
    },
  };
}
