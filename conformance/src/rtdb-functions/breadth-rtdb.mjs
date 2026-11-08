import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
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
  runDir,
}) {
  let baselineVerified = false;
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
      await fns.read(
        run,
        "api-before",
        "GET",
        run.u.service,
        (value) => value?.name === run.u.serviceName && value.state === "ENABLED",
      );
      await fns.read(run, "instance-before", "GET", run.u.instance, fns.isInstance(run, "ACTIVE"));
      await fns.read(
        run,
        "active-before",
        "GET",
        run.u.list,
        (value) =>
          value?.instances?.length === 1 &&
          fns.isInstance(run, "ACTIVE")(value.instances[0]) &&
          !value.nextPageToken,
      );
      run.baseline = await fns.read(
        run,
        "rules-before",
        "GET",
        run.u.data(".settings/rules"),
        (_, text) => createHash("sha256").update(text).digest("hex") === packet.baselineRulesSha256,
      );
      if (runDir)
        await writeFile(join(runDir, "baseline.rules.json"), run.baseline, { mode: 0o600 });
      await fns.read(run, "prefix-before", "GET", run.u.data(PREFIX), (value) => value === null);
      baselineVerified = true;
      run.state.data = "ours";
      await fns.putRules(run, "rules-install", rulesFor(PREFIX, nonce));
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
      admin.cleanup();
      try {
        if (run.state.data !== "baseline") {
          await fns.mutate(
            run,
            "prefix-delete",
            "data",
            "DELETE",
            run.u.data(PREFIX),
            undefined,
            (value) => value === null,
          );
          await fns.read(run, "prefix-null", "GET", run.u.data(PREFIX), (value) => value === null);
          run.state.data = "baseline";
        }
      } catch (error) {
        run.errors.push(error instanceof Stop ? error.message : `unexpected: ${error?.message}`);
      }
      try {
        if (run.state.rules !== "baseline") {
          await fns.mutate(
            run,
            "rules-restore",
            null,
            "PUT",
            run.u.data(".settings/rules"),
            run.baseline,
            (value) => value?.status === "ok",
            false,
          );
          await fns.read(
            run,
            "rules-restored",
            "GET",
            run.u.data(".settings/rules"),
            (_, text) =>
              createHash("sha256").update(text).digest("hex") === packet.baselineRulesSha256,
          );
          run.state.rules = "baseline";
        }
      } catch (error) {
        run.errors.push(error instanceof Stop ? error.message : `unexpected: ${error?.message}`);
      }
      run.propagation = false;
      const restored = Object.values(run.state).every((state) => state === "baseline");
      const accounted =
        admin.counts.logFailures === 0 &&
        user.counts.logFailures === 0 &&
        !run.errors.some((error) => error.startsWith("unexpected"));
      return {
        closed: baselineVerified && run.unresolved.length === 0 && restored && accounted,
        errors: [...run.errors],
        unresolved: [...run.unresolved],
        state: { ...run.state },
        counts: { admin: { ...admin.counts }, user: { ...user.counts } },
      };
    },
  };
}
