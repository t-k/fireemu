// An in-memory model of what the v4 recovery touches, started from the bodies the v4 run recorded
// (record/recorded/v4-run, sanitized): the storageArchivedV2 function left in state UNKNOWN with its Run service, trigger,
// Eventarc topic and subscription in us-central1, and a pubsubPublishedV2 in us-east1 (a copy of the recorded storage
// item with the Pub/Sub names; the run's us-east1 bodies were not recorded) with its trigger and a subscription on
// `_deleted-topic_`. It is a test double, not a claim about the services.

import { readFileSync } from "node:fs";

const recorded = (name) =>
  JSON.parse(
    readFileSync(
      new URL(`./functions-events/record/recorded/v4-run/${name}.json`, import.meta.url),
      "utf8",
    ),
  ).body;
const clone = (value) => JSON.parse(JSON.stringify(value));
const PROJECT = "fireemu-oracle-events";

export function createRecoverWorld({
  eventarcCleans = true,
  operationPolls = 2,
  failOperationFor = [],
  failures = [],
  neverDone = [],
  errorButRemoved = [],
} = {}) {
  const fnCentral = recorded("0140-lists.functions-v2").functions[0];
  const fnEast = clone(fnCentral);
  fnEast.name = `projects/${PROJECT}/locations/us-east1/functions/pubsubPublishedV2`;
  fnEast.state = "ACTIVE";
  const svcCentral = recorded("0141-lists.run-services").services[0];
  const svcEast = clone(svcCentral);
  svcEast.name = `projects/${PROJECT}/locations/us-east1/services/pubsubpublishedv2`;
  const trgCentral = recorded("0142-lists.eventarc-triggers").triggers[0];
  const trgEast = clone(trgCentral);
  trgEast.name = `projects/${PROJECT}/locations/us-east1/triggers/pubsubpublishedv2-974238`;
  const subs = recorded("0147-cleanup.subscriptions").subscriptions;
  const state = {
    functions: new Map([
      ["us-central1/storageArchivedV2", fnCentral],
      ["us-east1/pubsubPublishedV2", fnEast],
    ]),
    services: new Map([
      ["us-central1/storagearchivedv2", svcCentral],
      ["us-east1/pubsubpublishedv2", svcEast],
    ]),
    triggers: new Map([
      ["us-central1/storagearchivedv2-494903", trgCentral],
      ["us-east1/pubsubpublishedv2-974238", trgEast],
    ]),
    subscriptions: new Map(subs.map((s) => [s.name.split("/").at(-1), s])),
    topics: new Map(
      recorded("0146-cleanup.topics").topics.map((t) => [t.name.split("/").at(-1), t]),
    ),
    operations: new Map(),
    requests: [],
    deleted: [],
  };
  let operationCounter = 0;
  const json = (status, body) => ({
    status,
    arrayBuffer: async () => Buffer.from(typeof body === "string" ? body : JSON.stringify(body)),
  });
  const notFound = () => json(404, { error: { code: 404, status: "NOT_FOUND" } });

  async function fetch(url, init) {
    const { hostname, pathname, searchParams } = new URL(url);
    const method = init.method;
    state.requests.push({ method, host: hostname, path: pathname, query: searchParams.toString() });
    const failure = failures.find((f) => f.match(method, `${hostname}${pathname}`));
    if (failure) {
      if (failure.timeout) throw Object.assign(new Error("timeout"), { name: "TimeoutError" });
      return json(failure.status, failure.body ?? "<html>error</html>");
    }
    let m;
    if (hostname === "cloudfunctions.googleapis.com") {
      if (
        (m = /^\/v2\/projects\/[^/]+\/locations\/([a-z0-9-]+)\/functions\/([A-Za-z0-9]+)$/.exec(
          pathname,
        ))
      ) {
        const key = `${m[1]}/${m[2]}`;
        if (method === "GET")
          return state.functions.has(key) ? json(200, state.functions.get(key)) : notFound();
        if (method === "DELETE") {
          if (!state.functions.has(key)) return notFound();
          const id = `operation-${(operationCounter += 1)}`;
          const name = `projects/${PROJECT}/locations/${m[1]}/operations/${id}`;
          state.operations.set(id, { name, key, polls: 0, fn: m[2] });
          return json(200, { name, metadata: { verb: "delete" }, done: false });
        }
      }
      if (
        (m = /^\/v2\/projects\/[^/]+\/locations\/([a-z0-9-]+)\/operations\/([A-Za-z0-9_-]+)$/.exec(
          pathname,
        )) &&
        method === "GET"
      ) {
        const op = state.operations.get(m[2]);
        if (!op) return notFound();
        op.polls += 1;
        if (neverDone.includes(op.fn) || op.polls <= operationPolls)
          return json(200, { name: op.name, done: false });
        if (failOperationFor.includes(op.fn)) {
          const fn = state.functions.get(op.key);
          if (fn) fn.state = "UNKNOWN";
          return json(200, {
            name: op.name,
            done: true,
            error: {
              code: 13,
              message: "Deleting trigger failed: Failed to update storage bucket metadata",
            },
          });
        }
        state.functions.delete(op.key);
        state.deleted.push(op.key);
        const [region] = op.key.split("/");
        const low = op.fn.toLowerCase();
        for (const [k] of state.services) if (k === `${region}/${low}`) state.services.delete(k);
        for (const [k] of state.triggers)
          if (k.startsWith(`${region}/${low}-`)) state.triggers.delete(k);
        if (eventarcCleans) {
          for (const k of state.subscriptions.keys())
            if (k.includes(low)) state.subscriptions.delete(k);
          for (const k of state.topics.keys()) if (k.includes(low)) state.topics.delete(k);
        }
        if (errorButRemoved.includes(op.fn))
          return json(200, {
            name: op.name,
            done: true,
            error: { code: 13, message: "finished with an error after the function was gone" },
          });
        return json(200, { name: op.name, done: true, response: {} });
      }
      if (
        (m = /^\/v([12])\/projects\/[^/]+\/locations\/([a-z0-9-]+)\/functions$/.exec(pathname)) &&
        method === "GET"
      ) {
        const items = [...state.functions]
          .filter(([k]) => k.startsWith(`${m[2]}/`))
          .map(([, v]) => v);
        return json(200, items.length ? { functions: items } : {});
      }
    }
    if (
      hostname === "run.googleapis.com" &&
      (m = /\/locations\/([a-z0-9-]+)\/services$/.exec(pathname))
    ) {
      const items = [...state.services].filter(([k]) => k.startsWith(`${m[1]}/`)).map(([, v]) => v);
      return json(200, items.length ? { services: items } : {});
    }
    if (
      hostname === "eventarc.googleapis.com" &&
      (m = /\/locations\/([a-z0-9-]+)\/triggers$/.exec(pathname))
    ) {
      const items = [...state.triggers].filter(([k]) => k.startsWith(`${m[1]}/`)).map(([, v]) => v);
      return json(200, items.length ? { triggers: items } : {});
    }
    if (hostname === "pubsub.googleapis.com") {
      for (const [kind, map] of [
        ["subscriptions", state.subscriptions],
        ["topics", state.topics],
      ]) {
        if ((m = new RegExp(`^/v1/projects/[^/]+/${kind}/([A-Za-z0-9_.-]+)$`).exec(pathname))) {
          if (method === "GET") return map.has(m[1]) ? json(200, map.get(m[1])) : notFound();
          if (method === "DELETE") {
            if (!map.has(m[1])) return notFound();
            map.delete(m[1]);
            state.deleted.push(`${kind}/${m[1]}`);
            return json(200, {});
          }
        }
        if (pathname === `/v1/projects/${PROJECT}/${kind}` && method === "GET") {
          const items = [...map.values()];
          return json(200, items.length ? { [kind]: items } : {});
        }
      }
    }
    if (
      hostname === "artifactregistry.googleapis.com" &&
      /\/repositories\/gcf-artifacts$/.test(pathname)
    )
      return json(200, {
        name: pathname.slice(4),
        cleanupPolicies: { "firebase-functions-cleanup": { id: "firebase-functions-cleanup" } },
      });
    if (hostname === "storage.googleapis.com" && /\/storage\/v1\/b\/[^/]+$/.test(pathname))
      return json(200, { name: pathname.split("/").at(-1), versioning: { enabled: false } });
    return json(404, {
      error: { code: 404, message: `the world has no ${method} ${hostname}${pathname}` },
    });
  }
  return { fetch, state };
}
