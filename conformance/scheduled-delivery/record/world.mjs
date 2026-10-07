// Test support for the delivery recorder: an in-memory Cloud Functions, Cloud Run, Cloud Scheduler, Pub/Sub,
// Cloud Logging and Service Usage that answer in the recorded shapes, and a fake Firebase CLI that creates and
// deletes what a real deploy creates. A virtual clock advances only when the recorder sleeps; scheduled jobs
// fire on it. Not part of the packet; it sends nothing.
import {
  ALL_FUNCTIONS,
  FRAME_MARK,
  FUNCTIONS,
  PROJECT,
  REGION,
  functionName,
  jobName,
  runServiceId,
  scheduleId,
  topicName,
} from "./plan.mjs";
import { frameOrigin } from "./logs.mjs";

export const NUMBER = "123456789012";
export const START = Date.parse("2026-10-06T00:00:30Z");
export const pretty = (json) => JSON.stringify(json, null, 2) + "\n";
export const reply = (status, json) =>
  new Response(pretty(json), { status, headers: { "content-type": "application/json" } });
const notFound = (what) =>
  reply(404, { error: { code: 404, message: what + " not found", status: "NOT_FOUND" } });
const iso = (ms) => new Date(ms).toISOString();

const SCHEDULES = {
  schedOkV2: 60_000,
  schedRetryV2: 300_000,
  schedSlowV2: 60_000,
  schedOkV1: 60_000,
  schedFailV1: 300_000,
  schedRetryV1: 300_000,
};

export function createWorld({
  hooks = {},
  leaveOnDelete = [],
  failDeploy = false,
  listPageSize = 0,
  logPageSize = 0,
  v1Operations = false,
} = {}) {
  const w = {
    now: START,
    calls: [],
    functionsV1: new Map(),
    functionsV2: new Map(),
    runServices: new Set(),
    builds: new Map(),
    buildLogs: new Map(),
    jobs: new Map(),
    topics: new Set(),
    subs: new Map(),
    entries: [],
    creates: [],
    cliRuns: [],
    insert: 0,
    services: new Set([
      "cloudfunctions.googleapis.com",
      "run.googleapis.com",
      "cloudbuild.googleapis.com",
      "artifactregistry.googleapis.com",
      "compute.googleapis.com",
      "eventarc.googleapis.com",
      "storage.googleapis.com",
      "firebaseextensions.googleapis.com",
      "cloudscheduler.googleapis.com",
      "pubsub.googleapis.com",
      "serviceusage.googleapis.com",
      "iamcredentials.googleapis.com",
      "firebase.googleapis.com",
      "firebaserules.googleapis.com",
      "appengine.googleapis.com",
    ]),
  };

  const log = (entry) => w.entries.push({ insertId: "w" + ++w.insert, ...entry });
  const fire = (id, at, forced) => {
    const job = w.jobs.get(id);
    const fn = ALL_FUNCTIONS.find((f) => scheduleId(f) === id);
    log({
      timestamp: iso(at),
      logName: "projects/" + PROJECT + "/logs/cloudscheduler.googleapis.com%2Fexecutions",
      resource: { type: "cloud_scheduler_job", labels: { job_id: id, location: REGION } },
      jsonPayload: {
        "@type": "type.googleapis.com/google.cloud.scheduler.logging.AttemptStarted",
        jobName: jobName(id),
      },
    });
    if (fn) {
      const o = frameOrigin(fn);
      log({
        timestamp: iso(at + 500),
        logName: o.logName,
        resource: { type: o.resourceType, labels: o.labels },
        textPayload:
          FRAME_MARK +
          " " +
          JSON.stringify({ handler: fn, generation: FUNCTIONS.v1.includes(fn) ? 1 : 2, forced }),
      });
      if (FUNCTIONS.v1.includes(fn)) {
        for (const sub of w.subs.values())
          if (sub.topic.endsWith("/" + id))
            sub.queue.push({
              ackId: "ack-" + ++w.insert,
              message: {
                data: "eA==",
                messageId: "m" + w.insert,
                publishTime: iso(at),
                attributes: { scheduled: "true" },
              },
            });
      }
    }
    job.lastAttemptTime = iso(at);
  };

  /** Advances the virtual clock, firing every ENABLED deployed job whose instant passes. */
  w.advance = (ms) => {
    const end = w.now + ms;
    for (const [id, job] of w.jobs) {
      if (job.state !== "ENABLED" || job.manualOnly) continue;
      const fn = ALL_FUNCTIONS.find((f) => scheduleId(f) === id);
      const period = SCHEDULES[fn];
      if (!period) continue;
      for (let t = Math.floor(w.now / period) * period + period; t <= end; t += period)
        fire(id, t, false);
    }
    w.now = end;
  };

  const createDeployed = () => {
    for (const fn of ALL_FUNCTIONS) {
      const id = scheduleId(fn);
      if (FUNCTIONS.v1.includes(fn)) {
        w.functionsV1.set(functionName(fn), {
          name: functionName(fn),
          status: "ACTIVE",
          eventTrigger: { resource: topicName(id) },
        });
        w.topics.add(id);
      } else {
        w.functionsV2.set(functionName(fn), {
          name: functionName(fn),
          state: "ACTIVE",
          environment: "GEN_2",
          serviceConfig: { uri: "https://" + runServiceId(fn) + "-abc-uc.a.run.app" },
        });
        w.runServices.add(runServiceId(fn));
      }
      w.jobs.set(id, {
        name: jobName(id),
        state: "ENABLED",
        schedule: "every 1 minutes",
        ...(FUNCTIONS.v2.includes(fn)
          ? {
              httpTarget: {
                uri: "https://" + runServiceId(fn) + "-abc-uc.a.run.app",
                httpMethod: "POST",
                oidcToken: {
                  serviceAccountEmail: NUMBER + "-compute@developer.gserviceaccount.com",
                },
              },
            }
          : { pubsubTarget: { topicName: topicName(id), attributes: { scheduled: "true" } } }),
      });
    }
  };
  const deleteDeployed = () => {
    for (const fn of ALL_FUNCTIONS) {
      if (leaveOnDelete.includes(fn)) continue;
      const id = scheduleId(fn);
      w.functionsV1.delete(functionName(fn));
      w.functionsV2.delete(functionName(fn));
      w.runServices.delete(runServiceId(fn));
      w.jobs.delete(id);
      w.topics.delete(id);
    }
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
    if (url.hostname === "firebaserules.googleapis.com")
      return reply(200, {
        name: "projects/" + PROJECT + "/releases/cloud.firestore",
        rulesetName: "projects/" + PROJECT + "/rulesets/abc",
      });
    if (url.hostname === "serviceusage.googleapis.com")
      return reply(200, {
        services: [...w.services].toSorted().map((id) => ({
          name: "projects/" + NUMBER + "/services/" + id,
          config: { name: id },
          state: "ENABLED",
          parent: "projects/" + NUMBER,
        })),
      });
    if (path.endsWith(":getIamPolicy")) return reply(200, { version: 1, etag: "e", bindings: [] });
    if (path.endsWith("/adminSdkConfig")) return reply(200, { projectId: PROJECT });
    if (url.hostname === "appengine.googleapis.com") return notFound("app");
    if (url.hostname === "cloudfunctions.googleapis.com") {
      const v = path.startsWith("/v1/") ? w.functionsV1 : w.functionsV2;
      if (path.includes("/operations/"))
        return reply(200, { name: path.split("/").slice(-1)[0], done: true });
      if (path.endsWith("/functions")) {
        // The v2 list also carries the first-generation functions (environment GEN_1), as production's does.
        const gen1 =
          v === w.functionsV2
            ? [...w.functionsV1.values()].map((f) => ({
                name: f.name,
                state: f.status,
                environment: "GEN_1",
                buildConfig: {
                  build:
                    f.buildName ?? `projects/${NUMBER}/locations/${REGION}/builds/${f.buildId}`,
                },
              }))
            : [];
        return page([...v.values(), ...gen1], "functions", url);
      }
      const name = path.slice(path.indexOf("/projects/") + 1);
      if (method === "GET") return v.has(name) ? reply(200, v.get(name)) : notFound(name);
      if (method === "DELETE") {
        if (!v.has(name)) return notFound(name);
        v.delete(name);
        const fn = name.split("/").at(-1);
        w.runServices.delete(runServiceId(fn));
        return reply(200, {
          name:
            v1Operations && path.startsWith("/v1/")
              ? "operations/del-" + ++w.insert
              : "projects/" + PROJECT + "/locations/" + REGION + "/operations/del-" + ++w.insert,
          done: false,
        });
      }
    }
    if (url.hostname === "cloudbuild.googleapis.com") {
      const id = path.split("/").at(-1);
      return w.builds.has(id) ? reply(200, w.builds.get(id)) : notFound("build");
    }
    if (url.hostname === "run.googleapis.com")
      return page(
        [...w.runServices].map((id) => ({
          name: "projects/" + PROJECT + "/locations/" + REGION + "/services/" + id,
        })),
        "services",
        url,
      );
    if (url.hostname === "artifactregistry.googleapis.com") return reply(200, {});
    if (url.hostname === "cloudscheduler.googleapis.com") {
      if (path.endsWith("/jobs") && method === "GET")
        return page([...w.jobs.values()], "jobs", url);
      if (path.endsWith("/jobs") && method === "POST") {
        const id = body.name.split("/").at(-1);
        // What production answered (runs e0ec2f41 and 156715222b86ea44): a count of 6 or more, and a fractional
        // second in the retry window, are refused with HTTP 400.
        const retry = body.retryConfig ?? {};
        if (Number(retry.retryCount) >= 6)
          return reply(400, {
            error: {
              code: 400,
              message:
                "invalid retry count. The retry_count must be a positive integer less than 5: invalid argument",
              status: "INVALID_ARGUMENT",
            },
          });
        if (/\./.test(String(retry.maxRetryDuration ?? "")))
          return reply(400, {
            error: {
              code: 400,
              message: "retryConfig.max_retry_duration.nanos cannot be set: invalid argument",
              status: "INVALID_ARGUMENT",
            },
          });
        w.creates.push(id);
        w.jobs.set(id, { ...body, state: "ENABLED", manualOnly: true });
        return reply(200, w.jobs.get(id));
      }
      const m = /\/jobs\/([^/:]+)(?::(run|pause))?$/.exec(path);
      const job = m && w.jobs.get(m[1]);
      if (!job) return notFound("Job");
      if (m[2] === "run") {
        fire(m[1], w.now, true);
        return reply(200, {});
      }
      if (m[2] === "pause") {
        job.state = "PAUSED";
        return reply(200, job);
      }
      if (method === "GET") return reply(200, job);
      if (method === "DELETE") {
        w.jobs.delete(m[1]);
        return reply(200, {});
      }
    }
    if (url.hostname === "pubsub.googleapis.com") {
      if (path.endsWith("/topics"))
        return page(
          [...w.topics].map((id) => ({ name: topicName(id) })),
          "topics",
          url,
        );
      if (path.endsWith("/subscriptions"))
        return page(
          [...w.subs].map(([n, s]) => ({ name: n, topic: s.topic })),
          "subscriptions",
          url,
        );
      const topic = /\/topics\/([^/:]+)$/.exec(path);
      if (topic) {
        if (method === "GET")
          return w.topics.has(topic[1])
            ? reply(200, { name: topicName(topic[1]) })
            : notFound("topic");
        if (method === "DELETE")
          return w.topics.delete(topic[1]) ? reply(200, {}) : notFound("topic");
      }
      const sub = /\/subscriptions\/([^/:]+)(?::(pull|acknowledge))?$/.exec(path);
      if (sub) {
        const full = "projects/" + PROJECT + "/subscriptions/" + sub[1];
        if (method === "PUT") {
          w.subs.set(full, { topic: body.topic, queue: [] });
          return reply(200, { name: full, topic: body.topic });
        }
        const s = w.subs.get(full);
        if (!s) return notFound("subscription");
        if (sub[2] === "pull") {
          const received = s.queue.splice(0, body.maxMessages);
          return reply(200, received.length ? { receivedMessages: received } : {});
        }
        if (sub[2] === "acknowledge") return reply(200, {});
        if (method === "GET") return reply(200, { name: full, topic: s.topic });
        if (method === "DELETE") {
          w.subs.delete(full);
          return reply(200, {});
        }
      }
    }
    if (url.hostname === "logging.googleapis.com") {
      const filter = body.filter;
      const from = /timestamp>="([^"]+)"/.exec(filter)?.[1];
      const to = /timestamp<="([^"]+)"/.exec(filter)?.[1];
      const build = /^resource\.type="build" AND resource\.labels\.build_id="([^"]+)"$/.exec(
        filter,
      );
      if (build) {
        const entries = w.buildLogs.get(build[1]) ?? [];
        return reply(200, entries.length ? { entries } : {});
      }
      const wantScheduler = filter.startsWith('resource.type="cloud_scheduler_job"');
      const hits = w.entries.filter((e) => {
        const at = Date.parse(e.timestamp);
        if (at < Date.parse(from) || at > Date.parse(to)) return false;
        return wantScheduler
          ? e.resource.type === "cloud_scheduler_job"
          : e.resource.type !== "cloud_scheduler_job";
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
