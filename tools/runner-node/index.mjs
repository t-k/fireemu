#!/usr/bin/env node
// fireemu Node runner: loads a Firebase Functions codebase (firebase-functions v2,
// plus v1 HTTP functions), discovers its functions, and serves invocations sent by the
// daemon over stdin/stdout (length-prefixed JSON frames). HTTP and callable functions are
// hosted on a local express server whose port is announced in the hello frame.
//
//   node tools/runner-node/index.mjs --source <functions dir>
//
// stdout is the protocol channel: everything the functions print goes to stderr.

import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { existsSync, readFileSync } from "node:fs";
import { resolve, join, dirname } from "node:path";
import { timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { instrumentCallables } from "./callable-app-check.mjs";

const frameWrite = process.stdout.write.bind(process.stdout);
process.stdout.write = (chunk, encoding, cb) => process.stderr.write(chunk, encoding, cb);

function send(msg) {
  const payload = Buffer.from(JSON.stringify(msg), "utf8");
  frameWrite(`${payload.length}\n`);
  frameWrite(payload);
}

function log(level, message, invocationId) {
  send({ type: "log", level, message: String(message), invocationId });
}

function parseArgs(argv) {
  const out = { source: process.cwd() };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--source" && argv[i + 1]) out.source = argv[++i];
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));
const sourceDir = resolve(args.source);
process.env.FUNCTIONS_EMULATOR = process.env.FUNCTIONS_EMULATOR || "true";
process.env.FUNCTION_TARGET = process.env.FUNCTION_TARGET || "";
process.env.FUNCTION_SIGNATURE_TYPE = process.env.FUNCTION_SIGNATURE_TYPE || "";

async function loadCodebase() {
  const pkgPath = join(sourceDir, "package.json");
  let main = "index.js";
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
      if (pkg.main) main = pkg.main;
    } catch (e) {
      throw new Error(`cannot read ${pkgPath}: ${e.message}`);
    }
  }
  const entry = resolve(sourceDir, main);
  if (!existsSync(entry)) throw new Error(`functions entry point ${entry} does not exist`);
  const mod = await import(pathToFileURL(entry).href);
  const ns = { ...mod };
  if (mod.default && typeof mod.default === "object") Object.assign(ns, mod.default);
  // Node exposes CommonJS exports as `default` and (22+) as "module.exports".
  delete ns.default;
  delete ns["module.exports"];
  return ns;
}

// Flattens nested export groups: exports.api = { users: fn } -> "api-users".
function collectFunctions(ns, prefix, out) {
  for (const [key, value] of Object.entries(ns)) {
    if (!value) continue;
    const name = prefix ? `${prefix}-${key}` : key;
    if (typeof value === "function" && (value.__endpoint || value.__trigger)) {
      out.set(name, value);
    } else if (typeof value === "object" && !Array.isArray(value)) {
      collectFunctions(value, name, out);
    }
  }
  return out;
}

function firstRegion(ep) {
  const r = ep.region;
  if (Array.isArray(r)) return r[0];
  return r || undefined;
}

// firebase-functions v1 triggers: legacy event types and a resource pattern.
function describeV1Event(base, type, resource, schedule, retry) {
  const v1 = { v1: true };
  const fsMatch = type.match(/^providers\/cloud\.firestore\/eventTypes\/document\.(create|update|delete|write)$/);
  if (fsMatch) {
    const docIndex = resource.indexOf("/documents/");
    const dbMatch = resource.match(/\/databases\/([^/]+)\//);
    return {
      ...base,
      ...v1,
      retry,
      trigger: {
        type: "firestore",
        eventType: `google.cloud.firestore.document.v1.${{ create: "created", update: "updated", delete: "deleted", write: "written" }[fsMatch[1]]}`,
        database: dbMatch ? dbMatch[1] : "(default)",
        document: docIndex >= 0 ? resource.slice(docIndex + "/documents/".length) : undefined,
      },
    };
  }
  const stMatch = type.match(/^google\.storage\.object\.(finalize|delete|metadataUpdate|archive)$/);
  if (stMatch) {
    const bucketMatch = resource.match(/\/buckets\/([^/]+)/);
    return {
      ...base,
      ...v1,
      retry,
      trigger: {
        type: "storage",
        eventType: `google.cloud.storage.object.v1.${{ finalize: "finalized", delete: "deleted", metadataUpdate: "metadataUpdated", archive: "archived" }[stMatch[1]]}`,
        bucket: bucketMatch ? bucketMatch[1] : undefined,
      },
    };
  }
  if (schedule) {
    return {
      ...base,
      ...v1,
      retry: Number(schedule.retryConfig?.retryCount || 0) > 0,
      trigger: { type: "schedule", schedule: schedule.schedule, timeZone: schedule.timeZone || undefined },
    };
  }
  const authMatch = type.match(/^providers\/firebase\.auth\/eventTypes\/user\.(create|delete)$/);
  if (authMatch) {
    return {
      ...base,
      ...v1,
      retry,
      trigger: { type: "auth", eventType: `google.firebase.auth.user.v1.${{ create: "created", delete: "deleted" }[authMatch[1]]}` },
    };
  }
  if (type === "providers/cloud.pubsub/eventTypes/topic.publish" || type === "google.pubsub.topic.publish") {
    const topicMatch = resource.match(/\/topics\/([^/]+)$/);
    return {
      ...base,
      ...v1,
      retry,
      trigger: { type: "pubsub", topic: topicMatch ? topicMatch[1] : resource },
    };
  }
  return { ...base, unsupported: `v1 event type ${type}` };
}

function isV1(fn) {
  return fn.__endpoint?.platform === "gcfv1" || (!(fn.__endpoint && Object.keys(fn.__endpoint).length > 0) && !!fn.__trigger);
}

// The callable App Check options of one function, as the loader instrumentation observed
// them. An unobserved callable is `undetermined`, never a guessed `false` (spec 13.4).
function callableAppCheck(instrumentation, fn) {
  const observed = instrumentation.optionsOf(fn);
  return {
    enforceAppCheck: observed?.enforceAppCheck === true,
    consumeAppCheckToken: observed ? observed.consumeAppCheckToken : "undetermined",
  };
}

function describe(name, fn, instrumentation) {
  const callable = () => ({ type: "http", callable: true, ...callableAppCheck(instrumentation, fn) });
  const ep = fn.__endpoint;
  const base = { name, entryPoint: name };
  if (ep && ep.platform === "gcfv1") {
    if (ep.timeoutSeconds) base.timeoutSeconds = ep.timeoutSeconds;
    const region = firstRegion(ep);
    if (region) base.region = region;
    if (ep.httpsTrigger) return { ...base, trigger: { type: "http", callable: false } };
    if (ep.callableTrigger) return { ...base, trigger: callable() };
    const et = ep.eventTrigger || {};
    return describeV1Event(base, String(et.eventType || ""), String(et.eventFilters?.resource || ""), ep.scheduleTrigger, !!et.retry);
  }
  if (ep && Object.keys(ep).length > 0) {
    const region = firstRegion(ep);
    if (region) base.region = region;
    if (ep.timeoutSeconds) base.timeoutSeconds = ep.timeoutSeconds;
    if (ep.concurrency) base.concurrency = ep.concurrency;
    if (ep.httpsTrigger) return { ...base, trigger: { type: "http", callable: false } };
    if (ep.callableTrigger) return { ...base, trigger: callable() };
    if (ep.scheduleTrigger) {
      const retryCount = Number(ep.scheduleTrigger.retryConfig?.retryCount || 0);
      return {
        ...base,
        retry: retryCount > 0,
        trigger: {
          type: "schedule",
          schedule: ep.scheduleTrigger.schedule,
          timeZone: ep.scheduleTrigger.timeZone || undefined,
        },
      };
    }
    if (ep.eventTrigger) {
      const et = ep.eventTrigger;
      const type = et.eventType || "";
      base.retry = !!et.retry;
      if (type.startsWith("google.cloud.firestore.")) {
        const filters = et.eventFilters || {};
        const patterns = et.eventFilterPathPatterns || {};
        return {
          ...base,
          trigger: {
            type: "firestore",
            eventType: type,
            database: filters.database || "(default)",
            document: patterns.document || filters.document,
          },
        };
      }
      if (type.startsWith("google.cloud.storage.")) {
        return {
          ...base,
          trigger: { type: "storage", eventType: type, bucket: (et.eventFilters || {}).bucket || undefined },
        };
      }
      if (type === "google.cloud.pubsub.topic.v1.messagePublished") {
        const topic = String((et.eventFilters || {}).topic || "");
        return { ...base, trigger: { type: "pubsub", topic: topic.replace(/^.*\/topics\//, "") } };
      }
      return { ...base, unsupported: `event type ${type}` };
    }
    if (ep.blockingTrigger) {
      return { ...base, unsupported: "blocking identity functions (beforeUserCreated / beforeUserSignedIn) are not modelled" };
    }
    return { ...base, unsupported: "unknown endpoint shape" };
  }
  const t = fn.__trigger;
  if (t) {
    if (t.timeout) base.timeoutSeconds = Number(String(t.timeout).replace(/s$/, "")) || undefined;
    if (t.regions?.length) base.region = t.regions[0];
    if (t.httpsTrigger) {
      return {
        ...base,
        trigger: t.labels?.["deployment-callable"] ? callable() : { type: "http", callable: false },
      };
    }
    const et = t.eventTrigger;
    if (et) return describeV1Event(base, String(et.eventType || ""), String(et.resource || ""), t.schedule, !!et.failurePolicy || !!t.failurePolicy);
    return { ...base, unsupported: "unknown v1 trigger shape" };
  }
  return { ...base, unsupported: "not a Firebase function" };
}

// v1 functions are called as (data, context) with the legacy event shapes.

function v1Context(msg) {
  const event = msg.event;
  switch (msg.trigger) {
    case "firestore": {
      const legacy = {
        "google.cloud.firestore.document.v1.created": "providers/cloud.firestore/eventTypes/document.create",
        "google.cloud.firestore.document.v1.updated": "providers/cloud.firestore/eventTypes/document.update",
        "google.cloud.firestore.document.v1.deleted": "providers/cloud.firestore/eventTypes/document.delete",
        "google.cloud.firestore.document.v1.written": "providers/cloud.firestore/eventTypes/document.write",
      }[event.type];
      return {
        eventId: event.id,
        timestamp: event.time,
        eventType: legacy,
        // A string: firebase-functions rewrites a legacy event type's resource into
        // { service, name } itself (makeCloudFunction); an object here would be nested.
        resource: event.source,
        params: event.params || {},
      };
    }
    case "storage": {
      const o = event.data;
      return {
        eventId: event.id,
        timestamp: event.time,
        eventType: {
          "google.cloud.storage.object.v1.finalized": "google.storage.object.finalize",
          "google.cloud.storage.object.v1.deleted": "google.storage.object.delete",
          "google.cloud.storage.object.v1.metadataUpdated": "google.storage.object.metadataUpdate",
          "google.cloud.storage.object.v1.archived": "google.storage.object.archive",
        }[event.type],
        resource: { service: "storage.googleapis.com", name: `projects/_/buckets/${o.bucket}/objects/${o.name}#${o.generation}` },
        params: {},
      };
    }
    case "schedule":
      return {
        eventId: event.id,
        timestamp: event.time,
        eventType: "google.pubsub.topic.publish",
        resource: { service: "pubsub.googleapis.com", name: event.data.jobName },
        params: {},
      };
    case "pubsub": {
      const topic = String(event.source || "").replace(/^\/\/pubsub\.googleapis\.com\//, "");
      return {
        eventId: event.id,
        timestamp: event.time,
        eventType: "google.pubsub.topic.publish",
        resource: { service: "pubsub.googleapis.com", name: topic },
        params: {},
      };
    }
    case "auth": {
      // A string resource: the SDK rewrites a legacy event type's resource into
      // { service, name } itself.
      const project = String(event.source || "").replace(/^\/\/firebaseauth\.googleapis\.com\//, "");
      return {
        eventId: event.id,
        timestamp: event.time,
        eventType: event.type === "google.firebase.auth.user.v1.deleted" ? "providers/firebase.auth/eventTypes/user.delete" : "providers/firebase.auth/eventTypes/user.create",
        resource: project,
        params: {},
      };
    }
    default:
      return { eventId: event.id, timestamp: event.time, eventType: event.type, resource: event.source, params: {} };
  }
}

// Constant-time comparison of the per-runner secret.
function secretMatches(presented, expected) {
  if (typeof presented !== "string") return false;
  const a = Buffer.from(presented, "utf8");
  const b = Buffer.from(expected, "utf8");
  // `timingSafeEqual` throws on a length mismatch, which would itself be a length oracle.
  return a.length === b.length && timingSafeEqual(a, b);
}

function makeHttpServer(functions, manifest) {
  const require = createRequire(join(sourceDir, "package.json"));
  let express;
  try {
    express = require("express");
  } catch {
    return null;
  }
  const app = express();
  app.use(express.json({ limit: "32mb", verify: (req, _res, buf) => { req.rawBody = buf; } }));
  app.use(express.text({ limit: "32mb", verify: (req, _res, buf) => { req.rawBody = buf; } }));
  app.use(express.urlencoded({ extended: true, limit: "32mb", verify: (req, _res, buf) => { req.rawBody = buf; } }));
  app.use(express.raw({ type: () => true, limit: "32mb", verify: (req, _res, buf) => { req.rawBody = buf; } }));
  const major = Number.parseInt(String(require("express/package.json").version).split(".")[0], 10);
  // Express 5 (path-to-regexp 8) and Express 4 spell the optional rest differently.
  const route = major >= 5 ? "/:project/:region/:name{/*rest}" : "/:project/:region/:name*";
  const secret = process.env.FIREEMU_RUNNER_SECRET || "";
  const project = process.env.GCLOUD_PROJECT || "";
  app.all(route, (req, res, next) => {
    // Only the daemon's proxy may reach this server (it carries the per-runner secret and has
    // already applied timeouts, concurrency and idle accounting). A missing secret refuses
    // every request instead of waving them through: this server is the one place that decodes
    // the credentials the daemon prevalidated, and under the trusted callable protocol it also
    // honours the auth-override headers, so an unguarded runner would be an open
    // impersonation endpoint for anything else on the loopback interface.
    if (!secret) {
      res.status(500).send("FIREEMU_RUNNER_SECRET is required");
      return;
    }
    if (!secretMatches(req.get("x-fireemu-runner-secret"), secret)) {
      res.status(403).send("not the fireemu proxy");
      return;
    }
    // The secret is not part of the request the function sees.
    delete req.headers["x-fireemu-runner-secret"];
    const spec = manifest.functions.find((f) => f.name === req.params.name && f.trigger?.type === "http");
    const fn = spec && functions.get(spec.entryPoint);
    const region = spec?.region || "us-central1";
    if (!fn || (project && req.params.project !== project) || req.params.region !== region) {
      res.status(404).send(`no HTTP function ${req.params.project}/${req.params.region}/${req.params.name}`);
      return;
    }
    // The function sees the path relative to its mount point: drop the three route segments.
    const original = req.url;
    const queryAt = original.indexOf("?");
    const pathPart = queryAt >= 0 ? original.slice(0, queryAt) : original;
    const query = queryAt >= 0 ? original.slice(queryAt) : "";
    const rest = pathPart.split("/").slice(4).join("/");
    req.url = `/${rest}${query}`;
    Promise.resolve()
      .then(() => fn(req, res))
      .catch((e) => {
        log("error", `${spec.name}: ${e?.stack || e}`);
        if (!res.headersSent) res.status(500).send("internal error");
        next();
      });
  });
  const server = createServer(app);
  return new Promise((resolveServer, reject) => {
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => resolveServer(server));
  });
}

async function invoke(functions, msg) {
  const fn = functions.get(msg.entryPoint) || functions.get(msg.function);
  if (!fn) throw new Error(`unknown function ${msg.function}`);
  if (isV1(fn)) {
    const context = v1Context(msg);
    let data = msg.event.data;
    if (msg.trigger === "schedule") data = {};
    // v1 `topic().onPublish(message, context)`: the message itself is the data.
    if (msg.trigger === "pubsub") data = msg.event.data.message;
    await fn(data, context);
    return;
  }
  switch (msg.trigger) {
    case "schedule": {
      const run = fn.run || fn;
      await run(msg.event.data);
      return;
    }
    case "firestore":
    case "storage":
    case "pubsub":
      await fn(msg.event);
      return;
    case "auth":
      throw new Error("Auth user events are delivered to v1 auth.user() handlers only");
    default:
      throw new Error(`unsupported trigger ${msg.trigger}`);
  }
}

function readFrames(onFrame, onEnd) {
  let buffer = Buffer.alloc(0);
  process.stdin.on("data", (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    for (;;) {
      const nl = buffer.indexOf(10);
      if (nl < 0) return;
      const len = Number.parseInt(buffer.subarray(0, nl).toString("utf8"), 10);
      if (!Number.isFinite(len)) {
        log("error", "malformed frame length");
        process.exit(2);
      }
      if (buffer.length < nl + 1 + len) return;
      const payload = buffer.subarray(nl + 1, nl + 1 + len).toString("utf8");
      buffer = buffer.subarray(nl + 1 + len);
      try {
        onFrame(JSON.parse(payload));
      } catch (e) {
        log("error", `malformed frame: ${e.message}`);
      }
    }
  });
  process.stdin.on("end", onEnd);
}

async function main() {
  // Before any user code loads: the callable options are only observable as a callable is
  // declared (spec 13.4).
  const instrumentation = instrumentCallables(sourceDir);
  let ns;
  try {
    ns = await loadCodebase();
  } catch (e) {
    log("error", `cannot load functions from ${sourceDir}: ${e?.stack || e}`);
    process.exit(1);
  }
  const functions = collectFunctions(ns, "", new Map());
  const described = [...functions.entries()].map(([name, fn]) => describe(name, fn, instrumentation));
  for (const d of described.filter((d) => d.unsupported)) {
    log("warn", `function ${d.name} skipped: ${d.unsupported}`);
  }
  const manifest = { functions: described.filter((d) => !d.unsupported) };
  let httpPort;
  if (manifest.functions.some((f) => f.trigger.type === "http")) {
    try {
      const server = await makeHttpServer(functions, manifest);
      if (server) httpPort = server.address().port;
      else log("warn", "express is not installed in the functions codebase; HTTP functions are unavailable");
    } catch (e) {
      log("error", `cannot start the HTTP server: ${e?.stack || e}`);
    }
  }
  send({
    type: "hello",
    runner: "node",
    version: process.version,
    httpPort,
    manifest,
    appCheck: {
      firebaseFunctionsVersion: instrumentation.version,
      instrumentation: instrumentation.supported ? "ok" : instrumentation.reason,
      debugFeatures: instrumentation.debugFeatures,
      debugMode: process.env.FIREBASE_DEBUG_MODE === "true",
      authHeaders: instrumentation.authHeaders,
    },
  });
  readFrames(
    (msg) => {
      if (msg.type === "shutdown") process.exit(0);
      if (msg.type !== "invoke") return;
      invoke(functions, msg)
        .then(() => send({ type: "result", invocationId: msg.invocationId, ok: true }))
        .catch((e) => {
          log("error", `${msg.function}: ${e?.stack || e}`, msg.invocationId);
          send({ type: "result", invocationId: msg.invocationId, ok: false, error: String(e?.message || e) });
        });
    },
    () => process.exit(0),
  );
}

main();
