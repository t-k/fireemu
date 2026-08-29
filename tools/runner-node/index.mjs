#!/usr/bin/env node
// firebase-testd Node runner: loads a Firebase Functions codebase (firebase-functions v2,
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
import { createServer } from "node:http";

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

function describe(name, fn) {
  const ep = fn.__endpoint;
  const base = { name, entryPoint: name };
  if (ep && Object.keys(ep).length > 0) {
    const region = firstRegion(ep);
    if (region) base.region = region;
    if (ep.timeoutSeconds) base.timeoutSeconds = ep.timeoutSeconds;
    if (ep.concurrency) base.concurrency = ep.concurrency;
    if (ep.httpsTrigger) return { ...base, trigger: { type: "http", callable: false } };
    if (ep.callableTrigger) return { ...base, trigger: { type: "http", callable: true } };
    if (ep.scheduleTrigger) {
      return {
        ...base,
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
      return { ...base, unsupported: `event type ${type}` };
    }
    return { ...base, unsupported: "unknown endpoint shape" };
  }
  const t = fn.__trigger;
  if (t) {
    if (t.httpsTrigger) return { ...base, trigger: { type: "http", callable: !!t.labels?.["deployment-callable"] } };
    return { ...base, unsupported: "v1 event / schedule functions (use the v2 API)" };
  }
  return { ...base, unsupported: "not a Firebase function" };
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
  app.all(route, (req, res, next) => {
    const spec = manifest.functions.find((f) => f.name === req.params.name && f.trigger?.type === "http");
    const fn = spec && functions.get(spec.entryPoint);
    if (!fn) {
      res.status(404).send(`no HTTP function ${req.params.name}`);
      return;
    }
    // The function sees the path relative to its mount point.
    req.url = req.url.slice(req.url.indexOf(`/${req.params.name}`) + req.params.name.length + 1) || "/";
    if (!req.url.startsWith("/")) req.url = `/${req.url}`;
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
  const origLog = console.log;
  switch (msg.trigger) {
    case "schedule": {
      const run = fn.run || fn;
      await run(msg.event.data);
      return;
    }
    case "firestore":
    case "storage":
      await fn(msg.event);
      return;
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
  let ns;
  try {
    ns = await loadCodebase();
  } catch (e) {
    log("error", `cannot load functions from ${sourceDir}: ${e?.stack || e}`);
    process.exit(1);
  }
  const functions = collectFunctions(ns, "", new Map());
  const described = [...functions.entries()].map(([name, fn]) => describe(name, fn));
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
  send({ type: "hello", runner: "node", version: process.version, httpPort, manifest });
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
