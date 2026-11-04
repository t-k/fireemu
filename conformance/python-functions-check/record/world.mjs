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
  sourceBuckets,
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

const CHANNEL_TOPIC = "eventarc-channel-us-central1-firebase-450";
const REQUIRED = [
  "artifactregistry.googleapis.com",
  "cloudbilling.googleapis.com",
  "cloudbuild.googleapis.com",
  "cloudfunctions.googleapis.com",
  "cloudscheduler.googleapis.com",
  "cloudtasks.googleapis.com",
  "compute.googleapis.com",
  "eventarc.googleapis.com",
  "eventarcpublishing.googleapis.com",
  "firebaseextensions.googleapis.com",
  "firestore.googleapis.com",
  "pubsub.googleapis.com",
  "run.googleapis.com",
  "storage.googleapis.com",
  "serviceusage.googleapis.com",
];

/**
 * `hooks` maps "METHOD host/path" (or "METHOD /path") to a function returning a Response, "throw", or nothing.
 * `leaveOnDelete` names functions the fake CLI's delete leaves behind. `failDeploy` makes the deploy exit 1 without
 * creating anything. `publicInvokers` names functions whose Cloud Run service the CLI makes public (`allUsers`).
 * `uploadLines` is "normal", "none" (no receipt in the CLI log), "refused" (the upload PUT answered 403) or "extra" (a second
 * receipt for an object nobody made). `failSources` names source operation keys the world answers with 500 after applying them.
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
  deployState = "ACTIVE",
  foreignSubscriptions = 0,
  withSourceBuckets = true,
  sourcePageSize = 0,
  publicInvokers = [],
  uploadLines = "normal",
  withoutServices = [],
  cliWrites = undefined,
  projectNumberReported = NUMBER,
  leaveSubscriptions = false,
  servicePageSize = 0,
  projectIam = [],
  notifications = [],
  propagationReads = 0,
  invokerBindings = undefined,
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
    app: appEngine
      ? { name: "apps/" + PROJECT, id: PROJECT, locationId: "us-central", servingStatus: "SERVING" }
      : null,
    appOperationReads: 0,
    cliRuns: [],
    sourceBuckets: withSourceBuckets
      ? new Map(
          sourceBuckets(NUMBER).map((name) => [
            name,
            ["old-upload.zip"].slice(name.startsWith("gcf-v2-uploads") ? 0 : 1),
          ]),
        )
      : new Map(),
    deliveries: [],
    policies: new Map(),
    subscriptions: new Set(),
    enableRequests: [],
    enableReads: 0,
    generations: new Map(),
    upload: null,
    insert: 0,
    projectIam: structuredClone(projectIam),
    notifications: new Set(notifications),
    refused: new Map(),
    services: new Set([
      ...REQUIRED.filter((id) => !withoutServices.includes(id)),
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

  /** The inventory a recorder would read from this world now, in the shape the closure compares (names, sorted). */
  w.inventory = () => {
    const base = "projects/" + PROJECT;
    const names = (ids, prefix) => [...ids].map((id) => prefix + id).toSorted();
    const buckets = sourceBuckets(NUMBER);
    return {
      channels: [...w.channels].toSorted(),
      triggers: names(w.triggers, base + "/locations/" + REGION + "/triggers/"),
      subscriptions: [
        ...Array.from(
          { length: foreignSubscriptions },
          (_, n) => `${base}/subscriptions/foreign-${n}`,
        ),
        ...names(w.subscriptions, base + "/subscriptions/"),
      ].toSorted(),
      topics: names(w.topics, base + "/topics/"),
      packages: names(
        w.packages,
        base + "/locations/" + REGION + "/repositories/gcf-artifacts/packages/",
      ),
      services: [...w.services].toSorted(),
      iam: { bindings: structuredClone(w.projectIam) },
      notifications: [...w.notifications].toSorted(),
      sourceObjects: {
        uploads: [...(w.sourceBuckets.get(buckets[0]) ?? [])].toSorted(),
        sources: [...(w.sourceBuckets.get(buckets[1]) ?? [])].toSorted(),
      },
    };
  };
  w.advance = (ms) => {
    w.now += ms;
  };

  const createDeployed = () => {
    for (const fn of ALL_FUNCTIONS) {
      const name = functionName(fn);
      w.functions.set(name, {
        name,
        state: deployState,
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
    if (!w.topics.has(CHANNEL_TOPIC) && !seedChannels.includes("firebase"))
      w.topics.add(CHANNEL_TOPIC);
    for (const fn of ALL_FUNCTIONS)
      if (!SCHEDULER_FUNCTIONS.includes(fn) && !QUEUE_IDS.includes(fn))
        w.subscriptions.add(`eventarc-${REGION}-${fn}-123-sub-000`);
    for (const [name, items] of w.sourceBuckets) {
      if (name.startsWith("gcf-v2-uploads")) {
        w.upload =
          "514cacbe-3258-46fd-9a02-54b7485b" + String(++w.insert).padStart(4, "0") + ".zip";
        if (uploadLines !== "refused") {
          items.push(w.upload);
          w.generations.set(name + "/" + w.upload, String(1760000000000000 + w.insert));
        }
      } else for (const fn of ALL_FUNCTIONS) items.push(fn + "/function-source.zip");
    }
    for (const fn of ALL_FUNCTIONS)
      w.policies.set(fn, {
        version: 1,
        etag: "etag-" + fn + "-1",
        bindings: invokerBindings
          ? structuredClone(invokerBindings)
          : publicInvokers.includes(fn)
            ? [{ role: "roles/run.invoker", members: ["allUsers"] }]
            : SCHEDULER_FUNCTIONS.includes(fn)
              ? [{ role: "roles/run.invoker", members: ["serviceAccount:" + SERVICE_ACCOUNT] }]
              : [],
      });
  };
  const deleteDeployed = () => {
    for (const fn of ALL_FUNCTIONS) {
      if (leaveOnDelete.includes(fn)) continue;
      w.functions.delete(functionName(fn));
      w.runServices.delete(fn);
      w.policies.delete(fn);
      w.triggers.delete(fn + "-123");
      if (!leaveSubscriptions) w.subscriptions.delete(`eventarc-${REGION}-${fn}-123-sub-000`);
    }
    for (const id of JOB_IDS) if (!leaveOnDelete.includes("job:" + id)) w.jobs.delete(id);
    for (const id of QUEUE_IDS) if (!leaveOnDelete.includes("queue:" + id)) w.queues.delete(id);
  };

  /** The fake CLI: returns what `runCli` returns. */
  w.runCli = async ({ action }) => {
    w.cliRuns.push(action);
    if (action === "deploy") {
      if (failDeploy)
        return {
          action,
          exitCode: 1,
          timedOut: false,
          error: null,
          errored: 5,
          uploadEvents: [],
          cliWrites: [],
          durationMs: 1,
        };
      createDeployed();
      w.advance(110_000);
    } else if (action === "delete") {
      deleteDeployed();
      w.advance(30_000);
    }
    const bucket = sourceBuckets(NUMBER)[0];
    const uploadEvents =
      action === "deploy" && uploadLines !== "none" && w.upload
        ? [
            { type: "receipt", bucket, object: w.upload },
            {
              type: "put-status",
              bucket,
              object: w.upload,
              status: uploadLines === "refused" ? 403 : 200,
            },
            ...(uploadLines === "extra"
              ? [{ type: "receipt", bucket, object: "99999999-0000-0000-0000-000000000000.zip" }]
              : []),
          ]
        : action === "deploy"
          ? []
          : undefined;
    return {
      action,
      exitCode: 0,
      signal: null,
      timedOut: false,
      error: null,
      errored: 0,
      unknownWrites: [],
      ...(uploadEvents ? { uploadEvents } : {}),
      cliWrites: cliWrites ?? [],
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
    // A request that carries the quota project for an API that is not on (or not yet propagated after the enable) is refused
    // with 403 SERVICE_DISABLED in the layout production uses (recorded: FS-RULES 2026-09-27, the EVENTARC A1 fixture).
    if (withoutServices.includes(host)) {
      const left = w.refused.get(host) ?? 0;
      if (!w.services.has(host) || left > 0) {
        if (left > 0) w.refused.set(host, left - 1);
        return reply(403, {
          error: {
            code: 403,
            message:
              `${host} has not been used in project ${PROJECT} before or it is disabled. Enable it by visiting ` +
              `https://console.developers.google.com/apis/api/${host}/overview?project=${PROJECT} then retry. ` +
              "If you enabled this API recently, wait a few minutes for the action to propagate to our systems and retry.",
            status: "PERMISSION_DENIED",
            details: [
              {
                "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                reason: "SERVICE_DISABLED",
                domain: "googleapis.com",
                metadata: { consumer: "projects/" + PROJECT, service: host },
              },
            ],
          },
        });
      }
    }
    if (
      host === "cloudresourcemanager.googleapis.com" &&
      method === "GET" &&
      path === "/v1/projects/" + PROJECT
    )
      return reply(200, {
        projectNumber: projectNumberReported,
        projectId: PROJECT,
        lifecycleState: "ACTIVE",
        name: PROJECT,
      });
    if (host === "serviceusage.googleapis.com") {
      if (method === "POST" && path.endsWith("/services:batchEnable")) {
        if (!Array.isArray(body?.serviceIds) || Object.keys(body).length !== 1)
          return badRequest("serviceIds is required");
        w.enableRequests.push([...body.serviceIds]);
        for (const id of body.serviceIds) {
          if (!w.services.has(id)) w.refused.set(id, propagationReads);
          w.services.add(id);
        }
        return reply(200, { name: "operations/enable-" + w.enableRequests.length, done: false });
      }
      if (method === "GET" && path.startsWith("/v1/operations/"))
        return reply(200, { name: path.slice(4), done: ++w.enableReads >= 2 });
      const all = [...w.services].toSorted().map((id) => ({
        name: "projects/" + NUMBER + "/services/" + id,
        config: { name: id },
        state: "ENABLED",
        parent: "projects/" + NUMBER,
      }));
      const start = Number(url.searchParams.get("pageToken") ?? 0);
      const slice = servicePageSize ? all.slice(start, start + servicePageSize) : all;
      return reply(200, {
        services: slice,
        ...(servicePageSize && start + servicePageSize < all.length
          ? { nextPageToken: String(start + servicePageSize) }
          : {}),
      });
    }
    const policyCall =
      /^\/v2\/projects\/[^/]+\/locations\/[^/]+\/services\/([^/:]+):(get|set)IamPolicy$/.exec(path);
    if (host === "run.googleapis.com" && policyCall) {
      const [, fn, verb] = policyCall;
      if (!w.policies.has(fn))
        return reply(404, {
          error: { code: 404, message: "Resource " + fn + " not found", status: "NOT_FOUND" },
        });
      if (verb === "get") return reply(200, w.policies.get(fn));
      const given = body?.policy;
      if (method !== "POST" || !given || Object.keys(body).length !== 1)
        return badRequest("policy is required");
      if (given.etag !== w.policies.get(fn).etag)
        return reply(409, { error: { code: 409, status: "ABORTED", message: "etag mismatch" } });
      w.policies.set(fn, { version: 1, etag: given.etag + "+", bindings: given.bindings ?? [] });
      return reply(200, w.policies.get(fn));
    }
    if (path.endsWith(":getIamPolicy"))
      return reply(200, { version: 1, etag: "e", bindings: w.projectIam });
    if (path.endsWith("/adminSdkConfig"))
      return reply(200, { projectId: PROJECT, storageBucket: BUCKET });
    if (host === "appengine.googleapis.com") {
      if (method !== "GET") throw new Error("world: unexpected " + key);
      return w.app ? reply(200, w.app) : notFound("app");
    }
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
        w.policies.delete(fn);
        w.triggers.delete(fn + "-123");
        w.subscriptions.delete(`eventarc-${REGION}-${fn}-123-sub-000`);
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
      const channel = /\/channels\/([^/]+)$/.exec(path);
      if (channel) {
        if (method === "GET")
          return w.channels.has(channel[1])
            ? reply(200, {
                name: "projects/" + PROJECT + "/locations/" + REGION + "/channels/" + channel[1],
                pubsubTopic: "projects/" + PROJECT + "/topics/" + CHANNEL_TOPIC,
              })
            : notFound("channel");
        if (method === "DELETE") {
          if (!w.channels.has(channel[1])) return notFound("channel");
          w.channels.delete(channel[1]);
          w.topics.delete(CHANNEL_TOPIC);
          return reply(200, {
            name: "projects/" + PROJECT + "/locations/" + REGION + "/operations/ch-1",
            done: false,
          });
        }
      }
      if (path.includes("/operations/")) return reply(200, { name: path.slice(4), done: true });
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
      if (path.endsWith("/subscriptions"))
        return page(
          [
            ...Array.from({ length: foreignSubscriptions }, (_, n) => ({
              name: `projects/${PROJECT}/subscriptions/foreign-${n}`,
            })),
            ...[...w.subscriptions].toSorted().map((id) => ({
              name: `projects/${PROJECT}/subscriptions/${id}`,
            })),
          ],
          "subscriptions",
          url,
        );
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
      if (path.endsWith("/notificationConfigs") && method === "GET")
        return reply(200, {
          kind: "storage#notifications",
          ...(w.notifications.size
            ? {
                items: [...w.notifications].toSorted().map((id) => ({
                  kind: "storage#notification",
                  id,
                  topic: "//pubsub.googleapis.com/projects/p/topics/t",
                })),
              }
            : {}),
        });
      if (path.startsWith("/upload/")) {
        const name = url.searchParams.get("name");
        if (url.searchParams.get("uploadType") !== "media" || !name)
          return badRequest("uploadType and name");
        w.objects.set(name, { name });
        const op = sourceOp(method, request.url, body);
        for (const fn of op?.reaches ?? []) deliver(fn, op.key);
        return reply(200, { name, bucket: BUCKET });
      }
      const sourceBucket = /^\/storage\/v1\/b\/([^/]+)\/o$/.exec(path)?.[1];
      if (sourceBucket && sourceBucket !== BUCKET) {
        const items = w.sourceBuckets.get(sourceBucket);
        if (!items) return gcsNotFound(sourceBucket);
        const start = Number(url.searchParams.get("pageToken") ?? 0);
        const slice = sourcePageSize ? items.slice(start, start + sourcePageSize) : items;
        return reply(200, {
          ...(slice.length ? { items: slice.map((name) => ({ name })) } : {}),
          ...(sourcePageSize && start + sourcePageSize < items.length
            ? { nextPageToken: String(start + sourcePageSize) }
            : {}),
        });
      }
      const sourceObject = /^\/storage\/v1\/b\/([^/]+)\/o\/([^/]+)$/.exec(path);
      if (sourceObject && sourceObject[1] !== BUCKET) {
        const items = w.sourceBuckets.get(sourceObject[1]);
        const objectName_ = decodeURIComponent(sourceObject[2]);
        if (!items || !items.includes(objectName_)) return gcsNotFound(objectName_);
        const generation = w.generations.get(sourceObject[1] + "/" + objectName_) ?? "1";
        if (method === "GET")
          return reply(200, { name: objectName_, bucket: sourceObject[1], generation });
        if (method === "DELETE") {
          const wanted = url.searchParams.get("ifGenerationMatch");
          if (wanted !== null && wanted !== generation)
            return reply(412, {
              error: {
                code: 412,
                message: "Precondition Failed",
                errors: [{ domain: "global", reason: "conditionNotMet" }],
              },
            });
          items.splice(items.indexOf(objectName_), 1);
          return new Response(null, { status: 204 });
        }
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
  w.baseline = w.inventory();
  return w;
}
