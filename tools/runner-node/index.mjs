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

const localSecrets = (() => {
  const encoded = process.env.FIREEMU_LOCAL_SECRETS_JSON;
  delete process.env.FIREEMU_LOCAL_SECRETS_JSON;
  if (!encoded) return new Map();
  const parsed = JSON.parse(encoded);
  return new Map(Object.entries(parsed).filter(([, value]) => typeof value === "string"));
})();
let functionEnvironmentQueue = Promise.resolve();
let discoveredGlobalOptions = {};

function esmExportTarget(value) {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) {
    for (const candidate of value) {
      const selected = esmExportTarget(candidate);
      if (selected) return selected;
    }
    return undefined;
  }
  if (!value || typeof value !== "object") return undefined;
  for (const [condition, candidate] of Object.entries(value)) {
    if (condition === "node" || condition === "import" || condition === "default") {
      const selected = esmExportTarget(candidate);
      if (selected) return selected;
    }
  }
  return undefined;
}

function send(msg) {
  const payload = Buffer.from(JSON.stringify(msg), "utf8");
  frameWrite(`${payload.length}\n`);
  frameWrite(payload);
}

function log(level, message, invocationId) {
  send({ type: "log", level, message: String(message), invocationId });
}

function parseArgs(argv) {
  const out = { source: process.cwd(), codebase: "default" };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--source" && argv[i + 1]) out.source = argv[++i];
    else if (argv[i] === "--codebase" && argv[i + 1]) out.codebase = argv[++i];
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));
const sourceDir = resolve(args.source);
process.env.FUNCTIONS_EMULATOR = process.env.FUNCTIONS_EMULATOR || "true";
process.env.FUNCTION_TARGET = process.env.FUNCTION_TARGET || "";
process.env.FUNCTION_SIGNATURE_TYPE = process.env.FUNCTION_SIGNATURE_TYPE || "";
process.env.K_SERVICE = process.env.K_SERVICE || "";

// `getSignatureType` (functionsEmulatorShared.js:292): what the runtime is being asked to
// speak for one function.
function signatureType(spec) {
  if (spec.trigger?.type === "http") return "http";
  if (spec.trigger?.type === "schedule") return spec.v1 ? "event" : "http";
  return spec.v1 ? "event" : "cloudevent";
}

// The official emulator starts one runtime process per trigger, so it can set these three at
// spawn and they stay true for the life of the process (functionsEmulator.js:983-988). One
// fireemu runner serves a whole codebase, so they are set synchronously just before a handler
// is entered and name the invocation that started most recently. Under concurrency that is
// not the same guarantee, and it is the honest one a shared process can make; it is written
// down in the Functions section of README.md.
function setFunctionIdentity(spec) {
  process.env.FUNCTION_TARGET = spec?.entryPoint ?? "";
  process.env.FUNCTION_SIGNATURE_TYPE = spec ? signatureType(spec) : "";
  process.env.K_SERVICE = spec?.name ?? "";
}

function withFunctionEnvironment(spec, task) {
  const run = async () => {
    setFunctionIdentity(spec);
    const saved = new Map();
    for (const [name] of localSecrets) {
      saved.set(
        name,
        Object.prototype.hasOwnProperty.call(process.env, name) ? process.env[name] : undefined,
      );
      delete process.env[name];
    }
    for (const name of spec?.platformOptions?.secrets || []) {
      if (localSecrets.has(name)) process.env[name] = localSecrets.get(name);
    }
    try {
      return await task();
    } finally {
      for (const [name, value] of saved) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
    }
  };
  if (localSecrets.size === 0) return run();
  const result = functionEnvironmentQueue.then(run);
  functionEnvironmentQueue = result.catch(() => {});
  return result;
}

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
  // Export order matters: it is the order the emulator lists functions in, and the official
  // emulator reads a CommonJS codebase's `module.exports` object, which keeps it. An ES
  // module namespace object sorts its keys, so `module.exports` -- which Node hands over as
  // `default` -- goes in first and the namespace only fills in what it did not carry.
  const ns = {};
  if (mod.default && typeof mod.default === "object") Object.assign(ns, mod.default);
  for (const [key, value] of Object.entries(mod)) {
    if (!(key in ns)) ns[key] = value;
  }
  // Node exposes CommonJS exports as `default` and (22+) as "module.exports".
  delete ns.default;
  delete ns["module.exports"];
  return ns;
}

// Flattens nested export groups: exports.api = { users: fn } -> "api-users".
//
// `__endpoint` and `__trigger` are getters on the v1 SDK's cloud functions and can throw
// while they describe themselves (`database.ref(...)` throws when FIREBASE_CONFIG carries no
// databaseURL). A throwing export is recorded as malformed and named, never allowed to take
// the whole runner down: the daemon's inventory must be able to say what happened to it.
function collectFunctions(ns, prefix, out, broken) {
  for (const [key, value] of Object.entries(ns)) {
    if (!value) continue;
    const name = prefix ? `${prefix}-${key}` : key;
    if (typeof value === "function") {
      let marked = false;
      try {
        marked = Boolean(value.__endpoint || value.__trigger);
      } catch (e) {
        broken.set(name, e?.message ? String(e.message).split("\n")[0] : String(e));
        continue;
      }
      if (marked) out.set(name, value);
    } else if (typeof value === "object" && !Array.isArray(value)) {
      collectFunctions(value, name, out, broken);
    }
  }
  return out;
}

function firstRegion(ep) {
  const r = ep.region;
  if (Array.isArray(r)) return r[0];
  return r || undefined;
}

// Options that control the managed deployment platform have no local scheduling or IAM
// effect, but discovery must retain them so diagnostics never imply that they disappeared.
function platformOptions(ep) {
  if (!ep || ep.platform !== "gcfv2") return undefined;
  const options = {};
  const preserveExternalChanges =
    ep.preserveExternalChanges ?? discoveredGlobalOptions.preserveExternalChanges;
  if (preserveExternalChanges != null)
    options.preserveExternalChanges = Boolean(preserveExternalChanges);
  if (ep.availableMemoryMb != null) options.availableMemoryMb = ep.availableMemoryMb;
  if (ep.minInstances != null) options.minInstances = ep.minInstances;
  if (ep.maxInstances != null) options.maxInstances = ep.maxInstances;
  if (ep.cpu != null) options.cpu = String(ep.cpu);
  if (ep.ingressSettings != null) options.ingressSettings = ep.ingressSettings;
  if (ep.httpsTrigger?.invoker?.length) options.invoker = ep.httpsTrigger.invoker;
  if (ep.serviceAccountEmail != null) options.serviceAccountEmail = ep.serviceAccountEmail;
  if (ep.vpc?.connector != null) options.vpcConnector = ep.vpc.connector;
  if (ep.vpc?.egressSettings != null) options.vpcEgressSettings = ep.vpc.egressSettings;
  if (Array.isArray(ep.vpc?.networkInterfaces))
    options.networkInterfaces = ep.vpc.networkInterfaces;
  if (ep.labels && Object.keys(ep.labels).length > 0) options.labels = ep.labels;
  if (Array.isArray(ep.secretEnvironmentVariables)) {
    options.secrets = ep.secretEnvironmentVariables.map((secret) => secret.key).filter(Boolean);
  }
  return Object.keys(options).length > 0 ? options : undefined;
}

// Every export the runner cannot serve is reported, never dropped. `scope` says why, in the
// daemon's product-scope vocabulary: a product decision (`deferred`, `planned`, `notPlanned`)
// is fatal to discovery, while `unsupported` -- a shape neither the official emulator nor
// this runner recognises -- is reported and skipped, which is what the official emulator does
// (`functionsEmulator.js:488` logs `Unsupported trigger`, `:497` logs `Unsupported function
// type on <name>`, and both leave the definition in the inventory with `ignored: true`).
function ignored(base, triggerType, scope, reason) {
  return { ...base, ignored: { triggerType, scope, reason } };
}

// Products the official emulator has a trigger service for and fireemu does not serve.
// The event-type substring is matched the way `getServiceFromEventType` matches it.
const DEFERRED_TRIGGER_PRODUCTS = [
  {
    match: (type) =>
      type.includes("firebase.database") || type.includes("google.firebase.database"),
    triggerType: "database",
    scope: "deferred",
    reason: "deferred: the Realtime Database emulator is not in the active supported surface",
  },
  {
    match: (type) => type.includes("remoteconfig"),
    triggerType: "remoteConfig",
    scope: "deferred",
    reason: "deferred: Remote Config has no emulator in the active supported surface",
  },
  {
    match: (type) => type.includes("analytics"),
    triggerType: "analytics",
    scope: "notPlanned",
    reason: "not planned: Google Analytics triggers have no local emulator",
  },
  {
    match: (type) => type.includes("testing"),
    triggerType: "testLab",
    scope: "notPlanned",
    reason: "not planned: Test Lab triggers have no local emulator",
  },
];

// The product scope of an event type fireemu does not serve, or null when the type is simply
// unrecognised.
function deferredProduct(type) {
  return DEFERRED_TRIGGER_PRODUCTS.find((p) => p.match(type)) || null;
}

// firebase-functions v1 triggers: legacy event types and a resource pattern.
function describeV1Event(base, type, resource, schedule, retry) {
  const v1 = { v1: true };
  const fsMatch = type.match(
    /^providers\/cloud\.firestore\/eventTypes\/document\.(create|update|delete|write)$/,
  );
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
      trigger: {
        type: "schedule",
        schedule: schedule.schedule,
        timeZone: schedule.timeZone || undefined,
        retryConfig: schedule.retryConfig || {},
      },
    };
  }
  const authMatch = type.match(/^providers\/firebase\.auth\/eventTypes\/user\.(create|delete)$/);
  if (authMatch) {
    return {
      ...base,
      ...v1,
      retry,
      trigger: {
        type: "auth",
        eventType: `google.firebase.auth.user.v1.${{ create: "created", delete: "deleted" }[authMatch[1]]}`,
      },
    };
  }
  if (
    type === "providers/cloud.pubsub/eventTypes/topic.publish" ||
    type === "google.pubsub.topic.publish"
  ) {
    const topicMatch = resource.match(/\/topics\/([^/]+)$/);
    return {
      ...base,
      ...v1,
      retry,
      trigger: { type: "pubsub", topic: topicMatch ? topicMatch[1] : resource },
    };
  }
  const product = deferredProduct(type);
  if (product) {
    return ignored(base, product.triggerType, product.scope, product.reason);
  }
  return ignored(base, "unknown", "unsupported", `v1 event type ${type} is not recognised`);
}

function isV1(fn) {
  return (
    fn.__endpoint?.platform === "gcfv1" ||
    (!(fn.__endpoint && Object.keys(fn.__endpoint).length > 0) && !!fn.__trigger)
  );
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

function blockingResult(value) {
  if (!value || typeof value !== "object") return {};
  if (value.userRecord) return value;
  const userRecord = {};
  const updateMask = [];
  for (const [publicName, wireName] of [
    ["displayName", "displayName"],
    ["photoURL", "photoUrl"],
    ["disabled", "disabled"],
    ["emailVerified", "emailVerified"],
    ["customClaims", "customClaims"],
    ["sessionClaims", "sessionClaims"],
  ]) {
    if (Object.prototype.hasOwnProperty.call(value, publicName)) {
      userRecord[wireName] = value[publicName];
      updateMask.push(wireName);
    }
  }
  return updateMask.length > 0
    ? { userRecord: { ...userRecord, updateMask: updateMask.join(",") } }
    : {};
}

function describe(name, fn, instrumentation) {
  const callable = () => ({
    type: "http",
    callable: true,
    ...callableAppCheck(instrumentation, fn),
  });
  const ep = fn.__endpoint;
  const base = { name, entryPoint: name };
  if (ep?.omit === true) return { ...base, omitted: true };
  if (ep && ep.platform === "gcfv1") {
    if (ep.timeoutSeconds) base.timeoutSeconds = ep.timeoutSeconds;
    const region = firstRegion(ep);
    if (region) base.region = region;
    if (ep.httpsTrigger) return { ...base, trigger: { type: "http", callable: false } };
    if (ep.callableTrigger) return { ...base, trigger: callable() };
    const et = ep.eventTrigger || {};
    return describeV1Event(
      base,
      String(et.eventType || ""),
      String(et.eventFilters?.resource || ""),
      ep.scheduleTrigger,
      !!et.retry,
    );
  }
  if (ep && Object.keys(ep).length > 0) {
    const deployment = platformOptions(ep);
    if (deployment) base.platformOptions = deployment;
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
          retryConfig: ep.scheduleTrigger.retryConfig || {},
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
          trigger: {
            type: "storage",
            eventType: type,
            bucket: (et.eventFilters || {}).bucket || undefined,
          },
        };
      }
      if (type === "google.cloud.pubsub.topic.v1.messagePublished") {
        const topic = String((et.eventFilters || {}).topic || "");
        return { ...base, trigger: { type: "pubsub", topic: topic.replace(/^.*\/topics\//, "") } };
      }
      if (et.channel) {
        // `onCustomEventPublished`: the channel is `locations/<l>/channels/<c>` and every
        // eventFilter beyond the type is matched against the published event's attributes.
        return {
          ...base,
          trigger: {
            type: "eventarc",
            eventType: type,
            channel: et.channel,
            filters: et.eventFilters || {},
          },
        };
      }
      if (type.includes("firebasealerts")) {
        // Every `onAlertPublished` family member registers an ordinary event trigger with no
        // channel and `eventFilters: {alerttype, appid?}`. The official emulator hands it to
        // its Eventarc emulator, which indexes it under `<eventType>-google` and delivers to
        // it verbatim from `POST /google/publishEvents`. It is an Eventarc trigger on the
        // sentinel channel, and modelling it as anything else would need a second mechanism
        // for the same wire path.
        return {
          ...base,
          trigger: {
            type: "eventarc",
            eventType: type,
            channel: "google",
            filters: et.eventFilters || {},
          },
        };
      }
      const product = deferredProduct(type);
      if (product) return ignored(base, product.triggerType, product.scope, product.reason);
      return ignored(base, "unknown", "unsupported", `event type ${type} is not recognised`);
    }
    if (ep.blockingTrigger) {
      const eventType = String(ep.blockingTrigger.eventType || "");
      if (eventType.endsWith("beforeCreate") || eventType.endsWith("beforeSignIn")) {
        return { ...base, trigger: { type: "blockingAuth", eventType } };
      }
      return ignored(
        base,
        "blocking",
        "unsupported",
        `blocking identity event ${eventType} is not served`,
      );
    }
    if (ep.taskQueueTrigger) {
      // An `onTaskDispatched` function is an HTTP function that only its queue calls: the
      // official emulator sets both `httpsTrigger` and `taskQueueTrigger` on the definition
      // and gives it the ordinary /{project}/{region}/{name} URL, which becomes the queue's
      // defaultUri. The nulls the manifest carries mean "the default", as the emulator's `??`
      // reads them.
      return {
        ...base,
        trigger: {
          type: "tasks",
          retryConfig: ep.taskQueueTrigger.retryConfig || {},
          rateLimits: ep.taskQueueTrigger.rateLimits || {},
        },
      };
    }
    return ignored(
      base,
      "unknown",
      "unsupported",
      "the endpoint declares no trigger this runner recognises",
    );
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
    if (et)
      return describeV1Event(
        base,
        String(et.eventType || ""),
        String(et.resource || ""),
        t.schedule,
        !!et.failurePolicy || !!t.failurePolicy,
      );
    if (t.blockingTrigger) {
      const eventType = String(t.blockingTrigger.eventType || "");
      if (eventType.endsWith("beforeCreate") || eventType.endsWith("beforeSignIn")) {
        return { ...base, trigger: { type: "blockingAuth", eventType } };
      }
      return ignored(
        base,
        "blocking",
        "unsupported",
        `blocking identity event ${eventType} is not served`,
      );
    }
    return ignored(
      base,
      "unknown",
      "unsupported",
      "the v1 trigger declares no shape this runner recognises",
    );
  }
  // The official emulator's `Unsupported function type on <name>. Expected either an
  // httpsTrigger, eventTrigger, or blockingTrigger.` (functionsEmulator.js:497).
  return ignored(
    base,
    "unknown",
    "unsupported",
    "unsupported function type: expected either an httpsTrigger, eventTrigger, or blockingTrigger",
  );
}

// v1 functions are called as (data, context) with the legacy event shapes.

function v1Context(msg) {
  const event = msg.event;
  switch (msg.trigger) {
    case "firestore": {
      const legacy = {
        "google.cloud.firestore.document.v1.created":
          "providers/cloud.firestore/eventTypes/document.create",
        "google.cloud.firestore.document.v1.updated":
          "providers/cloud.firestore/eventTypes/document.update",
        "google.cloud.firestore.document.v1.deleted":
          "providers/cloud.firestore/eventTypes/document.delete",
        "google.cloud.firestore.document.v1.written":
          "providers/cloud.firestore/eventTypes/document.write",
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
        // The official emulator's legacy storage event resource: no generation suffix, and
        // a `type` member (its createLegacyEventRequestBody).
        resource: {
          service: "storage.googleapis.com",
          name: `projects/_/buckets/${o.bucket}/objects/${o.name}`,
          type: "storage#object",
        },
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
      const project = String(event.source || "").replace(
        /^\/\/firebaseauth\.googleapis\.com\//,
        "",
      );
      return {
        eventId: event.id,
        timestamp: event.time,
        eventType:
          event.type === "google.firebase.auth.user.v1.deleted"
            ? "providers/firebase.auth/eventTypes/user.delete"
            : "providers/firebase.auth/eventTypes/user.create",
        resource: project,
        params: {},
      };
    }
    default:
      return {
        eventId: event.id,
        timestamp: event.time,
        eventType: event.type,
        resource: event.source,
        params: {},
      };
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
  app.use(
    express.json({
      limit: "32mb",
      verify: (req, _res, buf) => {
        req.rawBody = buf;
      },
    }),
  );
  app.use(
    express.text({
      limit: "32mb",
      verify: (req, _res, buf) => {
        req.rawBody = buf;
      },
    }),
  );
  app.use(
    express.urlencoded({
      extended: true,
      limit: "32mb",
      verify: (req, _res, buf) => {
        req.rawBody = buf;
      },
    }),
  );
  app.use(
    express.raw({
      type: () => true,
      limit: "32mb",
      verify: (req, _res, buf) => {
        req.rawBody = buf;
      },
    }),
  );
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
    const spec = manifest.functions.find(
      (f) =>
        f.name === req.params.name &&
        (f.trigger?.type === "http" ||
          f.trigger?.type === "tasks" ||
          f.trigger?.type === "blockingAuth"),
    );
    const fn = spec && functions.get(spec.entryPoint);
    const region = spec?.region || "us-central1";
    if (!fn || (project && req.params.project !== project) || req.params.region !== region) {
      res
        .status(404)
        .send(`no HTTP function ${req.params.project}/${req.params.region}/${req.params.name}`);
      return;
    }
    // The function sees the path relative to its mount point: drop the three route segments.
    const original = req.url;
    const queryAt = original.indexOf("?");
    const pathPart = queryAt >= 0 ? original.slice(0, queryAt) : original;
    const query = queryAt >= 0 ? original.slice(queryAt) : "";
    const rest = pathPart.split("/").slice(4).join("/");
    req.url = `/${rest}${query}`;
    if (spec.trigger?.type === "blockingAuth") {
      withFunctionEnvironment(spec, () => {
        const user = req.body?.data?.user;
        const context = req.body?.data?.context || {};
        return isV1(fn) ? fn.run(user, context) : fn.run({ ...context, data: user });
      })
        .then((value) => res.status(200).json(blockingResult(value)))
        .catch((e) => {
          log("error", `${spec.name}: ${e?.stack || e}`);
          const code = e?.code || "internal";
          res.status(400).json({ error: { status: code, message: String(e?.message || e) } });
        });
      return;
    }
    withFunctionEnvironment(spec, async () => {
      await fn(req, res);
      if (!res.writableEnded) {
        await new Promise((resolve) => {
          res.once("finish", resolve);
          res.once("close", resolve);
        });
      }
    }).catch((e) => {
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

async function invoke(functions, manifest, msg) {
  const fn = functions.get(msg.entryPoint) || functions.get(msg.function);
  if (!fn) throw new Error(`unknown function ${msg.function}`);
  const spec = manifest.functions.find((f) => f.name === msg.function);
  await withFunctionEnvironment(spec, async () => {
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
      // A custom event reaches the handler as the CloudEvent itself, exactly as the official
      // Eventarc emulator POSTs it to the functions emulator.
      case "eventarc":
        await fn(msg.event);
        return;
      case "auth":
        throw new Error("Auth user events are delivered to v1 auth.user() handlers only");
      default:
        throw new Error(`unsupported trigger ${msg.trigger}`);
    }
  });
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
  try {
    const require = createRequire(join(sourceDir, "package.json"));
    const cjsOptions = require("firebase-functions/v2/options").getGlobalOptions();
    let sdkRoot = dirname(require.resolve("firebase-functions"));
    let sdkPackage;
    for (;;) {
      const candidate = join(sdkRoot, "package.json");
      if (existsSync(candidate)) {
        const parsed = JSON.parse(readFileSync(candidate, "utf8"));
        if (parsed.name === "firebase-functions") {
          sdkPackage = parsed;
          break;
        }
      }
      const parent = dirname(sdkRoot);
      if (parent === sdkRoot) throw new Error("cannot locate the firebase-functions package root");
      sdkRoot = parent;
    }
    const optionsExport = sdkPackage.exports?.["./v2/options"];
    const esmTarget = esmExportTarget(optionsExport);
    if (typeof esmTarget !== "string" || !esmTarget.startsWith("./")) {
      throw new Error("firebase-functions does not export ESM v2/options");
    }
    const esmOptions = await import(pathToFileURL(resolve(sdkRoot, esmTarget)).href);
    discoveredGlobalOptions = {
      ...cjsOptions,
      ...esmOptions.getGlobalOptions(),
    };
  } catch (e) {
    log("warn", `cannot inspect firebase-functions global options: ${e?.message || e}`);
  }
  const broken = new Map();
  const functions = collectFunctions(ns, "", new Map(), broken);
  const described = [...functions.entries()].map(([name, fn]) => {
    try {
      return describe(name, fn, instrumentation);
    } catch (e) {
      return ignored(
        { name, entryPoint: name },
        "unknown",
        "unsupported",
        `the export could not be described: ${e?.message || e}`,
      );
    }
  });
  for (const [name, reason] of broken) {
    described.push(
      ignored(
        { name, entryPoint: name },
        "unknown",
        "unsupported",
        `the export could not be described: ${reason}`,
      ),
    );
  }
  // Nothing is dropped: an export this runner cannot serve travels in the manifest's
  // `ignored` array with its region, its trigger type and its product scope, and the daemon
  // decides what to do with it.
  const manifest = {
    functions: described.filter((d) => !d.ignored && !d.omitted),
    ignored: described
      .filter((d) => d.ignored)
      .map((d) => ({
        name: d.name,
        region: d.region || "us-central1",
        triggerType: d.ignored.triggerType,
        scope: d.ignored.scope,
        reason: d.ignored.reason,
      })),
  };
  let httpPort;
  if (
    manifest.functions.some(
      (f) =>
        f.trigger.type === "http" ||
        f.trigger.type === "tasks" ||
        f.trigger.type === "blockingAuth",
    )
  ) {
    try {
      const server = await makeHttpServer(functions, manifest);
      if (server) httpPort = server.address().port;
      else
        log(
          "warn",
          "express is not installed in the functions codebase; HTTP functions are unavailable",
        );
    } catch (e) {
      log("error", `cannot start the HTTP server: ${e?.stack || e}`);
    }
  }
  send({
    type: "hello",
    runner: "node",
    codebase: args.codebase,
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
      invoke(functions, manifest, msg)
        .then(() => send({ type: "result", invocationId: msg.invocationId, ok: true }))
        .catch((e) => {
          log("error", `${msg.function}: ${e?.stack || e}`, msg.invocationId);
          send({
            type: "result",
            invocationId: msg.invocationId,
            ok: false,
            error: String(e?.message || e),
          });
        });
    },
    () => process.exit(0),
  );
}

main();
