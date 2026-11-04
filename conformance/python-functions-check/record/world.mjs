// Test support for the Python Functions check: an in-memory Cloud Functions, Cloud Run, Cloud Scheduler, Cloud Tasks,
// Pub/Sub, Eventarc, Artifact Registry, Firestore, Storage, Cloud Logging and Service Usage that answer in the
// recorded shapes and enforce the documented required fields of each request the check sends, plus a fake Firebase
// CLI that creates and deletes what a real deploy creates. A virtual clock advances only when the recorder sleeps.
// A source operation produces the frames of the local dry run (golden-frames.txt) for the functions it reaches, at the
// virtual time it arrives. Not part of the packet; it sends nothing.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { frameOrigin, parseFramesFromText } from "./logs.mjs";
import {
  ALL_FUNCTIONS,
  FRAME_MARK,
  JOB_IDS,
  PROJECT,
  QUEUE_IDS,
  REGION,
  SCHEDULER_FUNCTIONS,
  TOPIC,
  functionName,
  jobName,
  packageIds,
  queueName,
  runMarker,
  topicName,
} from "./plan.mjs";
import { operations } from "./script.mjs";

const here = dirname(fileURLToPath(import.meta.url));
export const NUMBER = "123456789012";
export const START = Date.parse("2026-11-05T00:00:30Z");
export const BUCKET = PROJECT + ".firebasestorage.app";
export const SERVICE_ACCOUNT = NUMBER + "-compute@developer.gserviceaccount.com";
export const uriOf = (fn) => "https://" + fn + "-abc-uc.a.run.app";
export const pretty = (json) => JSON.stringify(json, null, 2) + "\n";
export const reply = (status, json) =>
  new Response(pretty(json), { status, headers: { "content-type": "application/json" } });
const notFound = (what) =>
  reply(404, { error: { code: 404, message: what + " not found", status: "NOT_FOUND" } });
const gcsNotFound = (what) =>
  reply(404, {
    error: {
      code: 404,
      message: "No such object: " + what,
      errors: [{ message: "No such object: " + what, domain: "global", reason: "notFound" }],
    },
  });
const badRequest = (message) =>
  reply(400, { error: { code: 400, message, status: "INVALID_ARGUMENT" } });
const iso = (ms) => new Date(ms).toISOString();
const GOLDEN = parseFramesFromText(
  readFileSync(join(here, "../local/golden-frames.txt"), "utf8"),
).frames.map((f) => f.frame);

/** The dry run's frames reshaped to what the check expects of production, so a clean run judges all-as-expected. */
function productionShaped(frame) {
  const f = structuredClone(frame);
  if (f.kind === "raw-event" && f.request === null)
    f.request = {
      method: "POST",
      path: "/",
      header_names: ["content-type", "host"],
      headers: { "content-type": f.attributes?.datacontenttype ?? "application/json" },
      authorization: null,
      body_length: 0,
    };
  if (f.function === "pcschraw") {
    f.request.headers["content-length"] = "0";
    f.request.headers.host = "us-central1-" + PROJECT + ".cloudfunctions.net";
  }
  if (f.function === "pctaskraw") {
    f.request.headers["x-cloudtasks-queuename"] = "pctaskraw";
    f.request.authorization = { scheme: "Bearer", segments: 3 };
  }
  return f;
}
export const PRODUCTION_FRAMES = GOLDEN.map(productionShaped);

const REQUIRED = [
  "artifactregistry.googleapis.com",
  "cloudbuild.googleapis.com",
  "cloudfunctions.googleapis.com",
  "cloudscheduler.googleapis.com",
  "cloudtasks.googleapis.com",
  "eventarc.googleapis.com",
  "eventarcpublishing.googleapis.com",
  "firestore.googleapis.com",
  "pubsub.googleapis.com",
  "run.googleapis.com",
  "storage.googleapis.com",
  "serviceusage.googleapis.com",
];

/**
 * `hooks` maps "METHOD host/path" (or "METHOD /path") to a function returning a Response, "throw", or nothing.
 * `leaveOnDelete` names functions the fake CLI's delete leaves behind. `failDeploy` makes the deploy exit 1 without
 * creating anything. `failSources` names source operation keys the world answers with 500 after applying them.
 */
export function createWorld({
  runId = "0123456789abcdef",
  hooks = {},
  leaveOnDelete = [],
  failDeploy = false,
  listPageSize = 0,
  logPageSize = 0,
  appEngine = true,
  seedChannels = ["firebase"],
  silent = [],
} = {}) {
  const w = {
    runId,
    now: START,
    calls: [],
    functions: new Map(),
    runServices: new Set(),
    jobs: new Map(),
    queues: new Map(),
    topics: new Set(),
    triggers: new Set(),
    packages: new Set(),
    documents: new Map(),
    objects: new Map(),
    channels: new Set(seedChannels),
    entries: [],
    cliRuns: [],
    deliveries: [],
    insert: 0,
    services: new Set([
      ...REQUIRED,
      "compute.googleapis.com",
      "firebase.googleapis.com",
      "firebaserules.googleapis.com",
    ]),
    cursor: Object.fromEntries(ALL_FUNCTIONS.map((fn) => [fn, 0])),
  };
  const log = (entry) => w.entries.push({ insertId: "w" + ++w.insert, ...entry });
  const goldenFor = (fn) => PRODUCTION_FRAMES.filter((frame) => frame.function === fn);

  /** The frame the next delivery to `fn` produces: the dry run's, with this run's marker. */
  const deliver = (fn, key) => {
    const frames = goldenFor(fn);
    const frame = frames[w.cursor[fn]++];
    w.deliveries.push({ fn, key, at: w.now, frame: Boolean(frame) });
    if (!frame || silent.includes(fn)) return;
    const o = frameOrigin(fn);
    log({
      timestamp: iso(w.now + 3000),
      logName: o.logNames[0],
      resource: { type: o.resourceType, labels: o.labels },
      textPayload:
        FRAME_MARK + " " + JSON.stringify(frame).replaceAll("pcrun-RUNID", runMarker(w.runId)),
    });
  };

  w.advance = (ms) => {
    w.now += ms;
  };

  const createDeployed = () => {
    for (const fn of ALL_FUNCTIONS) {
      const name = functionName(fn);
      w.functions.set(name, {
        name,
        state: "ACTIVE",
        environment: "GEN_2",
        serviceConfig: { uri: uriOf(fn), serviceAccountEmail: SERVICE_ACCOUNT },
        ...(SCHEDULER_FUNCTIONS.includes(fn) || QUEUE_IDS.includes(fn)
          ? {}
          : {
              eventTrigger: {
                eventType: "x",
                trigger:
                  "projects/" + PROJECT + "/locations/" + REGION + "/triggers/" + fn + "-123",
              },
            }),
      });
      w.runServices.add(fn);
      for (const id of packageIds(fn)) w.packages.add(id);
      if (!SCHEDULER_FUNCTIONS.includes(fn) && !QUEUE_IDS.includes(fn)) w.triggers.add(fn + "-123");
    }
    for (const id of JOB_IDS)
      w.jobs.set(id, {
        name: jobName(id),
        state: "ENABLED",
        schedule: "0 0 1 1 *",
        timeZone: "UTC",
        httpTarget: { uri: uriOf(SCHEDULER_FUNCTIONS[JOB_IDS.indexOf(id)]) },
        runs: 0,
      });
    for (const id of QUEUE_IDS)
      w.queues.set(id, { name: queueName(id), state: "RUNNING", retryConfig: { maxAttempts: 1 } });
    w.topics.add(TOPIC);
    w.channels.add("firebase");
  };
  const deleteDeployed = () => {
    for (const fn of ALL_FUNCTIONS) {
      if (leaveOnDelete.includes(fn)) continue;
      w.functions.delete(functionName(fn));
      w.runServices.delete(fn);
      w.triggers.delete(fn + "-123");
    }
    for (const id of JOB_IDS) if (!leaveOnDelete.includes("job:" + id)) w.jobs.delete(id);
    for (const id of QUEUE_IDS) if (!leaveOnDelete.includes("queue:" + id)) w.queues.delete(id);
  };

  /** The fake CLI: returns what `runCli` returns. */
  w.runCli = async ({ action }) => {
    w.cliRuns.push(action);
    if (action === "deploy") {
      if (failDeploy)
        return { action, exitCode: 1, timedOut: false, error: null, errored: 5, durationMs: 1 };
      createDeployed();
      w.advance(110_000);
    } else if (action === "delete") {
      deleteDeployed();
      w.advance(30_000);
    }
    return {
      action,
      exitCode: 0,
      signal: null,
      timedOut: false,
      error: null,
      errored: 0,
      unknownWrites: [],
      durationMs: 1,
    };
  };

  const page = (items, key, url) => {
    if (!listPageSize || !url) return reply(200, items.length ? { [key]: items } : {});
    const start = Number(url.searchParams.get("pageToken") ?? 0);
    const slice = items.slice(start, start + listPageSize);
    return reply(200, {
      ...(slice.length ? { [key]: slice } : {}),
      ...(start + listPageSize < items.length
        ? { nextPageToken: String(start + listPageSize) }
        : {}),
    });
  };
  const sameJson = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  /** Which declared source operation a request is, if any. */
  const sourceOp = (method, url, body) => {
    const targets = Object.fromEntries(
      ALL_FUNCTIONS.map((fn) => [fn, { uri: uriOf(fn), serviceAccountEmail: SERVICE_ACCOUNT }]),
    );
    return operations({ runId: w.runId, bucket: BUCKET, targets }).find(
      (op) =>
        op.request.method === method &&
        op.request.url === url &&
        sameJson(op.request.json, body ?? undefined),
    );
  };

  w.send = async (request) => {
    const url = new URL(request.url);
    const method = request.method;
    const path = url.pathname;
    const key = method + " " + url.hostname + path;
    w.calls.push(key);
    const body = request.body ? JSON.parse(request.body) : undefined;
    const hook = hooks[key] ?? hooks[method + " " + path];
    if (hook) {
      const out = await hook({ w, body, url, method });
      if (out === "throw") throw new Error("transport");
      if (out) return out;
    }
    const host = url.hostname;
    if (host === "firebaserules.googleapis.com")
      return reply(200, {
        name: "projects/" + PROJECT + "/releases/cloud.firestore",
        rulesetName: "projects/" + PROJECT + "/rulesets/abc",
      });
    if (host === "serviceusage.googleapis.com")
      return reply(200, {
        services: [...w.services].toSorted().map((id) => ({
          name: "projects/" + NUMBER + "/services/" + id,
          config: { name: id },
          state: "ENABLED",
          parent: "projects/" + NUMBER,
        })),
      });
    if (path.endsWith(":getIamPolicy")) return reply(200, { version: 1, etag: "e", bindings: [] });
    if (path.endsWith("/adminSdkConfig"))
      return reply(200, { projectId: PROJECT, storageBucket: BUCKET });
    if (host === "appengine.googleapis.com")
      return appEngine
        ? reply(200, { name: "apps/" + PROJECT, locationId: "us-central" })
        : notFound("app");
    if (host === "cloudfunctions.googleapis.com") {
      if (path.includes("/operations/"))
        return reply(200, { name: path.split("/").slice(-1)[0], done: true });
      if (path.endsWith("/functions")) return page([...w.functions.values()], "functions", url);
      const name = path.slice(path.indexOf("/projects/") + 1);
      if (method === "GET")
        return w.functions.has(name) ? reply(200, w.functions.get(name)) : notFound(name);
      if (method === "DELETE") {
        if (!w.functions.has(name)) return notFound(name);
        w.functions.delete(name);
        const fn = name.split("/").at(-1);
        w.runServices.delete(fn);
        w.triggers.delete(fn + "-123");
        return reply(200, {
          name: "projects/" + PROJECT + "/locations/" + REGION + "/operations/del-" + ++w.insert,
          done: false,
        });
      }
    }
    if (host === "cloudbuild.googleapis.com") return notFound("build");
    if (host === "run.googleapis.com")
      return page(
        [...w.runServices].map((id) => ({
          name: "projects/" + PROJECT + "/locations/" + REGION + "/services/" + id,
        })),
        "services",
        url,
      );
    if (host === "eventarc.googleapis.com") {
      if (path.endsWith("/triggers"))
        return page(
          [...w.triggers].map((id) => ({
            name: "projects/" + PROJECT + "/locations/" + REGION + "/triggers/" + id,
          })),
          "triggers",
          url,
        );
      if (path.endsWith("/channels"))
        return page(
          [...w.channels].map((id) => ({
            name: "projects/" + PROJECT + "/locations/" + REGION + "/channels/" + id,
          })),
          "channels",
          url,
        );
    }
    if (host === "artifactregistry.googleapis.com") {
      if (path.includes("/operations/")) return reply(200, { name: path, done: true });
      const base =
        "projects/" + PROJECT + "/locations/" + REGION + "/repositories/gcf-artifacts/packages";
      if (path.endsWith("/packages"))
        return page(
          [...w.packages].map((id) => ({ name: base + "/" + id })),
          "packages",
          url,
        );
      const id = path.slice(path.indexOf("/packages/") + "/packages/".length);
      if (method === "GET")
        return w.packages.has(id) ? reply(200, { name: base + "/" + id }) : notFound("package");
      if (method === "DELETE") {
        if (!w.packages.delete(id)) return notFound("package");
        return reply(200, {
          name: "projects/" + PROJECT + "/locations/" + REGION + "/operations/pk-" + ++w.insert,
          done: true,
        });
      }
    }
    if (host === "cloudscheduler.googleapis.com") {
      if (path.endsWith("/jobs") && method === "GET")
        return page([...w.jobs.values()], "jobs", url);
      const m = /\/jobs\/([^/:]+)(?::(run))?$/.exec(path);
      const job = m && w.jobs.get(m[1]);
      if (!job) return notFound("Job");
      if (m[2] === "run") {
        if (method !== "POST") return badRequest("run needs POST");
        job.runs++;
        deliver(SCHEDULER_FUNCTIONS[JOB_IDS.indexOf(m[1])], "sched");
        return reply(200, {});
      }
      if (method === "GET") return reply(200, job);
      if (method === "DELETE") {
        w.jobs.delete(m[1]);
        return reply(200, {});
      }
    }
    if (host === "cloudtasks.googleapis.com") {
      if (path.endsWith("/queues") && method === "GET")
        return page([...w.queues.values()], "queues", url);
      const create = /\/queues\/([^/:]+)\/tasks$/.exec(path);
      if (create && method === "POST") {
        if (!w.queues.has(create[1])) return notFound("Queue");
        const target = body?.task?.httpRequest;
        if (!target?.url || target.url !== uriOf(create[1]))
          return badRequest("task.httpRequest.url is required and must be the function's");
        if (!target.oidcToken?.serviceAccountEmail)
          return badRequest("oidcToken.serviceAccountEmail is required");
        if (target.httpMethod !== "POST") return badRequest("httpMethod");
        deliver(create[1], "task");
        return reply(200, { name: queueName(create[1]) + "/tasks/" + ++w.insert });
      }
      const m = /\/queues\/([^/:]+)$/.exec(path);
      if (m && method === "GET")
        return w.queues.has(m[1]) ? reply(200, w.queues.get(m[1])) : notFound("Queue");
      if (m && method === "DELETE")
        return w.queues.delete(m[1]) ? reply(200, {}) : notFound("Queue");
    }
    if (host === "pubsub.googleapis.com") {
      if (path.endsWith("/topics"))
        return page(
          [...w.topics].map((id) => ({ name: topicName(id) })),
          "topics",
          url,
        );
      if (path.endsWith("/subscriptions")) return page([], "subscriptions", url);
      const publish = /\/topics\/([^/:]+):publish$/.exec(path);
      if (publish) {
        if (!w.topics.has(publish[1])) return notFound("topic");
        if (
          !Array.isArray(body?.messages) ||
          !body.messages.every((message) => typeof message.data === "string")
        )
          return badRequest("messages[].data is required");
        const op = sourceOp(method, request.url, body);
        for (const fn of op?.reaches ?? []) deliver(fn, op.key);
        return reply(200, { messageIds: ["1"] });
      }
      const topic = /\/topics\/([^/:]+)$/.exec(path);
      if (topic) {
        if (method === "PUT") {
          w.topics.add(topic[1]);
          return reply(200, { name: topicName(topic[1]) });
        }
        if (method === "GET")
          return w.topics.has(topic[1])
            ? reply(200, { name: topicName(topic[1]) })
            : notFound("topic");
        if (method === "DELETE")
          return w.topics.delete(topic[1]) ? reply(200, {}) : notFound("topic");
      }
    }
    if (host === "eventarcpublishing.googleapis.com") {
      if (
        !Array.isArray(body?.events) ||
        !body.events.every(
          (event) =>
            event["@type"] === "type.googleapis.com/io.cloudevents.v1.CloudEvent" &&
            event.id &&
            event.source &&
            event.type,
        )
      )
        return badRequest("events[] must be CloudEvent protos with id, source and type");
      const op = sourceOp(method, request.url, body);
      for (const fn of op?.reaches ?? []) deliver(fn, op.key);
      return reply(200, {});
    }
    if (host === "firestore.googleapis.com") {
      const docs = /\/documents\/([^/]+)(?:\/([^/]+))?$/.exec(path);
      if (!docs) return notFound("path");
      if (!docs[2] && method === "GET")
        return reply(200, w.documents.size ? { documents: [...w.documents.values()] } : {});
      if (!docs[2] && method === "POST") {
        if (!body?.fields) return badRequest("fields");
        const id = url.searchParams.get("documentId");
        if (!id || w.documents.has(id))
          return reply(409, { error: { code: 409, status: "ALREADY_EXISTS", message: "exists" } });
        const doc = {
          name: "projects/" + PROJECT + "/databases/(default)/documents/" + docs[1] + "/" + id,
          fields: body.fields,
        };
        w.documents.set(id, doc);
        const op = sourceOp(method, request.url, body);
        for (const fn of op?.reaches ?? []) deliver(fn, op.key);
        return reply(200, doc);
      }
      const id = docs[2];
      if (method === "PATCH") {
        if (!w.documents.has(id)) return notFound("document");
        if (
          url.searchParams.get("currentDocument.exists") !== "true" ||
          !url.searchParams.get("updateMask.fieldPaths")
        )
          return badRequest("mask and precondition");
        w.documents.set(id, {
          ...w.documents.get(id),
          fields: { ...w.documents.get(id).fields, ...body.fields },
        });
        const op = sourceOp(method, request.url, body);
        for (const fn of op?.reaches ?? []) deliver(fn, op.key);
        return reply(200, w.documents.get(id));
      }
      if (method === "GET")
        return w.documents.has(id) ? reply(200, w.documents.get(id)) : notFound("document");
      if (method === "DELETE")
        return w.documents.delete(id) ? reply(200, {}) : notFound("document");
    }
    if (host === "storage.googleapis.com") {
      if (path.startsWith("/upload/")) {
        const name = url.searchParams.get("name");
        if (url.searchParams.get("uploadType") !== "media" || !name)
          return badRequest("uploadType and name");
        w.objects.set(name, { name });
        const op = sourceOp(method, request.url, body);
        for (const fn of op?.reaches ?? []) deliver(fn, op.key);
        return reply(200, { name, bucket: BUCKET });
      }
      if (/^\/storage\/v1\/b\/[^/]+$/.test(path)) return reply(200, { name: BUCKET });
      if (path.endsWith("/o"))
        return reply(200, w.objects.size ? { items: [...w.objects.values()] } : {});
      const name = decodeURIComponent(path.split("/o/")[1] ?? "");
      if (method === "GET")
        return w.objects.has(name) ? reply(200, w.objects.get(name)) : gcsNotFound(name);
      if (method === "DELETE")
        return w.objects.delete(name) ? new Response(null, { status: 204 }) : gcsNotFound(name);
    }
    if (host === "logging.googleapis.com") {
      const filter = body.filter;
      const from = /timestamp>="([^"]+)"/.exec(filter)?.[1];
      const to = /timestamp<="([^"]+)"/.exec(filter)?.[1];
      const wantErrors = filter.includes("severity>=ERROR");
      const hits = w.entries.filter((e) => {
        const at = Date.parse(e.timestamp);
        if (at < Date.parse(from) || at > Date.parse(to)) return false;
        return wantErrors
          ? e.severity === "ERROR"
          : typeof e.textPayload === "string" && e.textPayload.includes(FRAME_MARK);
      });
      const start = body.pageToken ? Number(body.pageToken) : 0;
      const size = logPageSize || body.pageSize;
      const slice = hits.slice(start, start + size);
      return reply(200, {
        ...(slice.length ? { entries: slice } : {}),
        ...(start + size < hits.length ? { nextPageToken: String(start + size) } : {}),
      });
    }
    throw new Error("world: unexpected " + key);
  };
  return w;
}
