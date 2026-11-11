// Test support for the TASK-QUEUE-FUNCTIONS recording: an in-memory Cloud Functions, Cloud Run, Cloud Tasks, Artifact
// Registry, Storage (the two Gen2 buckets), Cloud Logging, Service Usage, Pub/Sub and Eventarc (lists only) that answer
// with the shapes the recording reads, plus a fake Firebase CLI that creates and deletes what a real deploy creates. A
// virtual clock advances only when the recorder sleeps. Cloud Tasks here is a MODEL of the documented rules (task id
// characters and length, the 30 day limit, the dispatch deadline range, the 1 MiB task size, 409 for a name in use, the
// retry and rate settings of the queue), written to exercise the recorder; it is not an observation of production and
// the shapes it answers are not recorded shapes. Adapted from the Python Functions check's world.mjs
// (work/python-functions-check 650824f6c). Not part of the packet; it sends nothing.
import { frameOrigin } from "./logs.mjs";
import {
  FRAME_MARK,
  PROJECT,
  REGION,
  ROLES,
  functionName,
  functionsOf,
  packageIds,
  queueName,
  roleOf,
  runMarker,
  sourceBuckets,
} from "../plan.mjs";

export const NUMBER = "123456789012";
export const START = Date.parse("2026-11-12T00:00:30Z");
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

const REQUIRED = [
  "artifactregistry.googleapis.com",
  "cloudbilling.googleapis.com",
  "cloudbuild.googleapis.com",
  "cloudfunctions.googleapis.com",
  "cloudtasks.googleapis.com",
  "compute.googleapis.com",
  "eventarc.googleapis.com",
  "eventarcpublishing.googleapis.com",
  "firebaseextensions.googleapis.com",
  "run.googleapis.com",
  "storage.googleapis.com",
  "serviceusage.googleapis.com",
];

/** The queue settings firebase-tools writes for a role: its defaults, overridden by the role's options (cloudtasks.js 15.28.2). */
export function queueSettings(role) {
  const options = ROLES[role] ?? {};
  const seconds = (n) => `${n}s`;
  return {
    rateLimits: {
      maxConcurrentDispatches: 1000,
      maxDispatchesPerSecond: 500,
      ...options.rateLimits,
    },
    state: "RUNNING",
    retryConfig: {
      maxDoublings: options.retryConfig?.maxDoublings ?? 16,
      maxAttempts: options.retryConfig?.maxAttempts ?? 3,
      maxBackoff: seconds(options.retryConfig?.maxBackoffSeconds ?? 3600),
      minBackoff:
        options.retryConfig?.minBackoffSeconds === undefined
          ? "0.100s"
          : seconds(options.retryConfig.minBackoffSeconds),
      ...(options.retryConfig?.maxRetrySeconds === undefined
        ? {}
        : { maxRetryDuration: seconds(options.retryConfig.maxRetrySeconds) }),
    },
  };
}

const TASK_ID = /^[A-Za-z0-9_-]{1,500}$/;
const decode = (text) => Buffer.from(text, "base64").toString("utf8");

/**
 * `hooks` maps "METHOD host/path" (or "METHOD /path") to a function returning a Response, "throw", or nothing.
 * `leaveOnDelete` names functions the fake CLI's delete leaves behind. `failDeploy` makes the deploy exit 1 without
 * creating anything. `queueTombstones` is a set of queue ids Cloud Tasks will not create again. `uploadLines` is "normal",
 * "none" (no receipt in the CLI log), "refused" (the upload PUT answered 403) or "extra" (a second receipt for an object
 * nobody made). `silent` names functions whose deliveries print no frame.
 */
export function createWorld({
  runId = "0123456789abcdef",
  hooks = {},
  leaveOnDelete = [],
  failDeploy = false,
  listPageSize = 0,
  logPageSize = 0,
  silent = [],
  deployState = "ACTIVE",
  withSourceBuckets = true,
  sourcePageSize = 0,
  uploadLines = "normal",
  withoutServices = [],
  cliWrites = undefined,
  projectNumberReported = NUMBER,
  servicePageSize = 0,
  projectIam = [],
  queueTombstones = new Set(),
  seedQueues = [],
  seedChannels = [],
} = {}) {
  const FNS = functionsOf(runId);
  const w = {
    runId,
    now: START,
    calls: [],
    functions: new Map(),
    runServices: new Set(),
    queues: new Map(),
    tasks: new Map(),
    names: new Map(),
    packages: new Set(),
    entries: [],
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
    generations: new Map(),
    upload: null,
    insert: 0,
    projectIam: structuredClone(projectIam),
    channels: new Set(seedChannels),
    services: new Set([
      ...REQUIRED.filter((id) => !withoutServices.includes(id)),
      "firebase.googleapis.com",
    ]),
  };
  for (const id of seedQueues) w.queues.set(id, { name: queueName(id), state: "RUNNING" });
  const log = (entry) => w.entries.push({ insertId: "w" + ++w.insert, ...entry });
  const marker = runMarker(runId);

  /** One printed frame, at a virtual time that may be later than now (the log is read by timestamp). */
  const print = (fn, at, frame, taskKey = null) => {
    if (silent.includes(fn)) return;
    const o = frameOrigin(fn);
    log({
      taskKey,
      timestamp: iso(at),
      logName: o.logNames[0],
      resource: { type: o.resourceType, labels: o.labels },
      textPayload:
        FRAME_MARK +
        " " +
        JSON.stringify({ function: fn, role: roleOf(fn), run: marker, ...frame }),
    });
  };

  /** The deliveries of one accepted task under the queue's settings (the model's rules, not production's). */
  const dispatch = (fn, taskId, data, sentAt, scheduleMs, deadlineSeconds) => {
    const taskKey = queueName(fn) + "/tasks/" + taskId;
    const role = roleOf(fn);
    const settings = queueSettings(role);
    const seconds = (text) => Number.parseFloat(text);
    const script = Array.isArray(data?.script) ? data.script : [];
    const maxAttempts = settings.retryConfig.maxAttempts;
    const min = seconds(settings.retryConfig.minBackoff) * 1000;
    const max = seconds(settings.retryConfig.maxBackoff) * 1000;
    const window =
      settings.retryConfig.maxRetryDuration === undefined
        ? Infinity
        : seconds(settings.retryConfig.maxRetryDuration) * 1000;
    let at = Math.max(sentAt + 400, scheduleMs ?? 0);
    const first = at;
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const step = script.length
        ? (script[Math.min(attempt, script.length - 1)] ?? { status: "ok" })
        : { status: "ok" };
      const hold = step.sleepMs ?? 0;
      // A delivery that outlasts the dispatch deadline fails with a timeout and is retried like any other failure.
      const status = hold > deadlineSeconds * 1000 ? "timeout" : (step.status ?? "ok");
      print(
        fn,
        at,
        {
          kind: "start",
          at: iso(at),
          case: data?.case ?? null,
          request: {
            method: "POST",
            path: "/",
            headers: { "content-type": "application/json", "user-agent": "Google-Cloud-Tasks" },
            bodyLength: 100,
          },
          context: { id: taskId, retryCount: attempt, executionCount: attempt },
          step: { status, sleepMs: hold },
        },
        taskKey,
      );
      print(
        fn,
        at + hold,
        {
          kind: "end",
          at: iso(at + hold),
          startedAt: iso(at),
          case: data?.case ?? null,
          id: taskId,
          retryCount: attempt,
          status,
        },
        taskKey,
      );
      w.deliveries.push({ fn, taskId, attempt, at });
      if (status === "ok") return;
      const doublings = Math.min(attempt, settings.retryConfig.maxDoublings);
      const backoff = Math.min(min * 2 ** doublings, max);
      if (at + backoff - first > window) return;
      at += backoff;
    }
  };

  w.inventory = () => {
    const base = "projects/" + PROJECT;
    const names = (ids, prefix) => [...ids].map((id) => prefix + id).toSorted();
    const buckets = sourceBuckets(NUMBER);
    return {
      channels: [...w.channels].toSorted(),
      triggers: [],
      subscriptions: [],
      topics: [],
      packages: names(
        w.packages,
        base + "/locations/" + REGION + "/repositories/gcf-artifacts/packages/",
      ),
      queues: names(w.queues.keys(), base + "/locations/" + REGION + "/queues/"),
      services: [...w.services].toSorted(),
      iam: { bindings: structuredClone(w.projectIam) },
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
    for (const fn of FNS) {
      const name = functionName(fn);
      w.functions.set(name, {
        name,
        state: deployState,
        environment: "GEN_2",
        serviceConfig: { uri: uriOf(fn), serviceAccountEmail: SERVICE_ACCOUNT },
      });
      w.runServices.add(fn);
      for (const id of packageIds(fn)) w.packages.add(id);
      if (!queueTombstones.has(fn))
        w.queues.set(fn, { name: queueName(fn), ...queueSettings(roleOf(fn)) });
      w.policies.set(fn, { version: 1, etag: "etag-" + fn + "-1", bindings: [] });
    }
    for (const [name, items] of w.sourceBuckets) {
      if (name.startsWith("gcf-v2-uploads")) {
        w.upload =
          "514cacbe-3258-46fd-9a02-54b7485b" + String(++w.insert).padStart(4, "0") + ".zip";
        if (uploadLines !== "refused") {
          items.push(w.upload);
          w.generations.set(name + "/" + w.upload, String(1760000000000000 + w.insert));
        }
      } else for (const fn of FNS) items.push(fn + "/function-source.zip");
    }
  };
  const deleteDeployed = () => {
    for (const fn of FNS) {
      if (leaveOnDelete.includes(fn)) continue;
      w.functions.delete(functionName(fn));
      w.runServices.delete(fn);
      w.policies.delete(fn);
      if (!leaveOnDelete.includes("queue:" + fn)) {
        w.queues.delete(fn);
        queueTombstones.add(fn);
      }
    }
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

  /** createTask against the model of the documented rules. Returns a Response. */
  const createTask = (queue, body) => {
    if (!w.queues.has(queue)) return notFound("Queue does not exist: " + queue);
    const keys = Object.keys(body ?? {});
    if (keys.some((k) => !["task", "responseView"].includes(k)) || !body?.task)
      return badRequest("task is required");
    const task = body.task;
    if (
      Object.keys(task).some(
        (k) => !["name", "httpRequest", "scheduleTime", "dispatchDeadline"].includes(k),
      )
    )
      return badRequest('Invalid JSON payload received. Unknown name in "task"');
    const http = task.httpRequest;
    if (!http?.url) return badRequest("task.http_request.url is required");
    if (http.httpMethod !== "POST") return badRequest("httpMethod");
    if (!http.oidcToken?.serviceAccountEmail)
      return badRequest("oidcToken.serviceAccountEmail is required");
    const taskBytes = Buffer.byteLength(JSON.stringify(task));
    if (taskBytes > 1_048_576 * 1.4) return badRequest("Task size too large");
    const raw = decode(http.body ?? "");
    if (raw.length > 1_048_576) return badRequest("Task size too large");
    let id = null;
    if (task.name !== undefined) {
      const prefix = queueName(queue) + "/tasks/";
      if (!task.name.startsWith(prefix)) return badRequest("Task name does not match the queue");
      id = task.name.slice(prefix.length);
      if (!TASK_ID.test(id)) return badRequest("Task id is invalid");
    }
    let scheduleMs = null;
    if (task.scheduleTime !== undefined) {
      scheduleMs = Date.parse(task.scheduleTime);
      if (!Number.isFinite(scheduleMs)) return badRequest("Invalid scheduleTime");
      if (scheduleMs - w.now > 30 * 86_400_000) return badRequest("scheduleTime is too far");
    }
    if (task.dispatchDeadline !== undefined) {
      const m = /^(\d+(?:\.\d+)?)s$/.exec(task.dispatchDeadline);
      if (!m || Number(m[1]) < 15 || Number(m[1]) > 1800)
        return badRequest("dispatchDeadline must be between 15s and 30m");
    }
    const taskId = id ?? String(++w.insert);
    const full = queueName(queue) + "/tasks/" + taskId;
    if (w.names.has(full))
      return reply(409, {
        error: { code: 409, message: "Task already exists", status: "ALREADY_EXISTS" },
      });
    w.names.set(full, "live");
    w.tasks.set(full, { queue, task });
    let data = null;
    try {
      data = JSON.parse(raw).data;
    } catch {
      return badRequest("body is not JSON");
    }
    const deadline =
      task.dispatchDeadline === undefined ? 600 : Number.parseFloat(task.dispatchDeadline);
    dispatch(queue, taskId, data, w.now, scheduleMs, deadline);
    return reply(200, { name: full, httpRequest: { url: http.url, httpMethod: "POST" } });
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
      /^\/v2\/projects\/[^/]+\/locations\/[^/]+\/services\/([^/:]+):getIamPolicy$/.exec(path);
    if (host === "run.googleapis.com" && policyCall)
      return w.policies.has(policyCall[1])
        ? reply(200, w.policies.get(policyCall[1]))
        : reply(404, {
            error: { code: 404, message: "Resource not found", status: "NOT_FOUND" },
          });
    if (path.endsWith(":getIamPolicy"))
      return reply(200, { version: 1, etag: "e", bindings: w.projectIam });
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
      if (path.endsWith("/triggers")) return page([], "triggers", url);
      if (path.endsWith("/channels"))
        return page(
          [...w.channels].map((id) => ({
            name: "projects/" + PROJECT + "/locations/" + REGION + "/channels/" + id,
          })),
          "channels",
          url,
        );
    }
    if (host === "pubsub.googleapis.com") {
      if (path.endsWith("/topics")) return page([], "topics", url);
      if (path.endsWith("/subscriptions")) return page([], "subscriptions", url);
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
    if (host === "cloudtasks.googleapis.com") {
      if (path.endsWith("/queues") && method === "GET")
        return page([...w.queues.values()], "queues", url);
      const taskRoute = /\/queues\/([^/:]+)\/tasks(?:\/([^/]+))?$/.exec(path);
      if (taskRoute) {
        const [, queue, id] = taskRoute;
        if (!id && method === "POST") return createTask(queue, body);
        const full = queueName(queue) + "/tasks/" + id;
        if (method === "GET")
          return w.tasks.has(full) ? reply(200, { name: full }) : notFound("Task");
        if (method === "DELETE") {
          if (!w.tasks.delete(full)) return notFound("Task");
          // A task that is deleted delivers nothing from now on.
          w.entries = w.entries.filter(
            (e) => e.taskKey !== full || Date.parse(e.timestamp) <= w.now,
          );
          return reply(200, {});
        }
      }
      const m = /\/queues\/([^/:]+)$/.exec(path);
      if (m && method === "GET")
        return w.queues.has(m[1]) ? reply(200, w.queues.get(m[1])) : notFound("Queue");
      if (m && method === "DELETE") {
        if (!w.queues.delete(m[1])) return notFound("Queue");
        queueTombstones.add(m[1]);
        return reply(200, {});
      }
    }
    if (host === "storage.googleapis.com") {
      const sourceBucket = /^\/storage\/v1\/b\/([^/]+)\/o$/.exec(path)?.[1];
      if (sourceBucket) {
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
      if (sourceObject) {
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
