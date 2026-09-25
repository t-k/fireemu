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
import { existsSync, readFileSync, readlinkSync } from "node:fs";
import { resolve, join, dirname } from "node:path";
import { createServer } from "node:http";
import { execFileSync, spawn } from "node:child_process";
import { url as inspectorUrl } from "node:inspector";
import { instrumentCallables } from "./callable-app-check.mjs";
import { blockingFailure } from "./blocking-error.mjs";
import { blockingResult } from "./blocking-response.mjs";
import { boundLogMessage, createInvocationLogger } from "./log-context.mjs";
import { invocationFailure } from "./invocation-error.mjs";
import { InvocationBudget, readFrames } from "./protocol.mjs";
import { collectFunctions, exportNamespace } from "./discovery.mjs";
import { FrameWriter } from "./output.mjs";
import { installDiagnosticOutput } from "./diagnostic-output.mjs";
import { trackHttpResponse } from "./http-lifecycle.mjs";
import { createHttpAdmission } from "./http-admission.mjs";

// Keep one best-effort terminal diagnostic available after ordinary output
// admission closes. It is only used when stderr has no pending data, never to
// bypass a failed/stalled diagnostic channel or grow its queue.
const terminalDiagnosticWrite = process.stderr.write.bind(process.stderr);
let outputFailed = false;
const diagnosticOutput = installDiagnosticOutput(process.stderr, {
  onError() {
    // fd2 may be stalled or broken. Do not recursively log to it or pretend that
    // already-executed callback side effects were rolled back.
    outputFailed = true;
    process.exit(2);
  },
});
const frameOutput = new FrameWriter(process.stdout, {
  onError(error) {
    outputFailed = true;
    // Retire rather than drop frames or let an unbounded stream queue grow.
    // Callback side effects are not rolled back; native waiters see RunnerGone.
    try {
      const state = diagnosticOutput.state;
      const message = `${error.message}\n`;
      if (!state.failed && state.pendingWrites === 0 && Buffer.byteLength(message) <= 256) {
        terminalDiagnosticWrite(message);
      }
    } finally { process.exit(2); }
  },
});
let finishingOutput = false;
let groupCleanupPromise = Promise.resolve(true);
function finishOutput() {
  if (finishingOutput || outputFailed) return;
  finishingOutput = true;
  void Promise.all([frameOutput.finish(), diagnosticOutput.finish(), groupCleanupPromise])
    .then(results => process.exit(results.every(Boolean) && !outputFailed ? 0 : 2));
}

function processGroup(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 1) return null;
  if (process.platform === 'linux' && existsSync('/proc/self/stat')) {
    try {
      const stat = readFileSync(pid === process.pid ? '/proc/self/stat' : `/proc/${pid}/stat`, 'utf8');
      // The comm field may contain spaces and parentheses; fields resume after its last ") ".
      if (!stat.startsWith(`${pid} (`)) return null;
      const end = stat.lastIndexOf(') ');
      if (end < String(pid).length + 2) return null;
      const fields = stat.slice(end + 2).trim().split(/\s+/);
      const group = Number(fields[2]); // state, ppid, then pgrp (field 5).
      return /^[A-Za-z]$/.test(fields[0]) && /^\d+$/.test(fields[2]) &&
        Number.isSafeInteger(group) && group > 1 ? group : null;
    } catch {
      return null;
    }
  }
  try {
    const value = execFileSync('/bin/ps', ['-o', 'pgid=', '-p', String(pid)], {
      encoding: 'utf8', timeout: 1000, maxBuffer: 2048,
    }).trim();
    const group = Number(value);
    return /^\d+$/.test(value) && Number.isSafeInteger(group) && group > 1 ? group : null;
  } catch {
    return null;
  }
}

function processExecutable(pid) {
  try {
    if (process.platform === 'linux') return readlinkSync(`/proc/${pid}/exe`);
    if (process.platform === 'darwin') {
      const files = execFileSync('/usr/sbin/lsof', ['-a', '-p', String(pid), '-d', 'txt', '-Fn'], {
        encoding: 'utf8', timeout: 1000, maxBuffer: 16384,
      });
      return files.split('\n').find(line => line.startsWith('n'))?.slice(1) ?? null;
    }
  } catch {
    // Unknown executable identity cannot authorize signaling a parent-led group.
  }
  return null;
}

function runnerProcessGroupCandidate() {
  if (process.platform === 'win32') return null;
  const group = processGroup(process.pid);
  if (!group) return null;
  if (group === process.pid) return {group, needsShim: false};
  if (group !== process.ppid || processGroup(group) !== group) return null;
  return {group, needsShim: true};
}

// Capture the group before user code can spawn children. A parent-led group is
// authorized only when cleanup needs it, so lsof cannot delay normal startup.
const daemonManagedRunner = process.env.FIREEMU_RUNNER === '1';
const groupCandidate = daemonManagedRunner ? runnerProcessGroupCandidate() : null;
let ownedProcessGroup = groupCandidate && !groupCandidate.needsShim ? groupCandidate.group : null;
let shimChecked = !groupCandidate?.needsShim;
let ownershipWarningSent = false;
function verifiedOwnedProcessGroup() {
  if (shimChecked) return ownedProcessGroup;
  shimChecked = true;
  const group = groupCandidate.group;
  if (processGroup(process.pid) === group && processGroup(group) === group &&
      processExecutable(group)?.endsWith('/volta-shim')) ownedProcessGroup = group;
  return ownedProcessGroup;
}
function warnUnverifiedGroup() {
  if (!daemonManagedRunner || ownershipWarningSent) return;
  ownershipWarningSent = true;
  process.stderr.write('[functions] runner process group ownership is unverified; cleanup disabled\n');
}
let inputCleanupStarted = false;
let explicitShutdown = false;
let deferredExitCleanup = false;
const groupCleanupHelper = `
const {execFileSync} = require('node:child_process');
const {existsSync, readFileSync} = require('node:fs');
const group = Number(process.argv[1]);
function ownGroup() {
  try {
    if (process.platform === 'linux' && existsSync('/proc/self/stat')) {
      const stat = readFileSync('/proc/self/stat', 'utf8');
      if (!stat.startsWith(process.pid + ' (')) return null;
      const end = stat.lastIndexOf(') ');
      if (end < String(process.pid).length + 2) return null;
      const fields = stat.slice(end + 2).trim().split(/\\s+/);
      const id = Number(fields[2]);
      return /^[A-Za-z]$/.test(fields[0]) && /^\\d+$/.test(fields[2]) &&
        Number.isSafeInteger(id) && id > 1 ? id : null;
    }
    const value = execFileSync('/bin/ps', ['-o', 'pgid=', '-p', String(process.pid)], {
      encoding: 'utf8', timeout: 1000, maxBuffer: 2048,
    }).trim();
    const id = Number(value);
    return /^\\d+$/.test(value) && Number.isSafeInteger(id) && id > 1 ? id : null;
  } catch { return null; }
}
function killOwnedGroup() {
  try {
    if (group > 1 && ownGroup() === group) process.kill(-group, 'SIGKILL');
  } catch { /* The group is already gone or signaling is unavailable. */ }
}
const watchdog = setTimeout(killOwnedGroup, 4000);
process.stdin.on('end', () => {
  clearTimeout(watchdog);
  setTimeout(killOwnedGroup, 1500);
});
process.stdin.on('error', () => {});
process.stdin.resume();
`;
function deferCleanShutdownGroupCleanup() {
  const group = verifiedOwnedProcessGroup();
  if (!group || processGroup(process.pid) !== group) {
    warnUnverifiedGroup();
    return;
  }
  // Keep a known member in the group after Node exits. Rust normally kills it
  // first; if the daemon dies in that gap, the helper performs bounded cleanup.
  try {
    const helper = spawn(process.execPath, ['-e', groupCleanupHelper, String(group)], {
      stdio: ['pipe', 'ignore', 'ignore'], env: {},
    });
    if (!helper.pid) return;
    helper.on('error', () => { deferredExitCleanup = false; });
    helper.stdin.on('error', () => {});
    helper.unref();
    helper.stdin.unref?.();
    deferredExitCleanup = true;
  } catch {
    // The exit handler still cleans the group when a helper cannot start.
  }
}
function moveOwnedGroupCleanupToLastExitHandler() {
  if (!ownedProcessGroup) return;
  process.removeListener('exit', killOwnedGroupOnExit);
  process.on('exit', killOwnedGroupOnExit);
}
function cleanupProcessGroupOnInputClose() {
  if (inputCleanupStarted || process.platform === 'win32') return;
  inputCleanupStarted = true;
  const group = verifiedOwnedProcessGroup();
  if (!group || processGroup(process.pid) !== group) {
    warnUnverifiedGroup();
    return;
  }
  // The group signal reaches this Node process too. Keep it alive until escalation;
  // a shim may forward another TERM after receiving the group signal itself.
  process.on('SIGTERM', () => {});
  // The 500 ms SIGKILL skips user exit handlers; this listener only covers early exit.
  moveOwnedGroupCleanupToLastExitHandler();
  groupCleanupPromise = new Promise(resolve => {
    setTimeout(() => {
      // An undrained output pipe must not postpone descendant cleanup.
      if (processGroup(process.pid) === ownedProcessGroup) {
        try { process.kill(-ownedProcessGroup, 'SIGKILL'); }
        catch { /* The exit handler makes one final ownership-checked attempt. */ }
      }
      resolve(true);
    }, 500);
  });
  try {
    process.kill(-ownedProcessGroup, 'SIGTERM');
  } catch (error) {
    process.stderr.write(`[functions] runner process group cleanup failed: ${error.code ?? 'unknown'}\n`);
  }
}
function killOwnedGroupOnExit() {
  // A fatal frame or output error can exit before stdin close or the grace timer.
  // The runner is still a member, so its original group ID cannot be reused yet.
  if (deferredExitCleanup) return;
  const group = verifiedOwnedProcessGroup();
  if (!group || processGroup(process.pid) !== group) {
    warnUnverifiedGroup();
    return;
  }
  // Fatal exits can precede user exit listeners. Keep a verified group member
  // alive until those listeners finish, then let it reap the group.
  if (!inputCleanupStarted) {
    deferCleanShutdownGroupCleanup();
    if (deferredExitCleanup) return;
  }
  try { process.kill(-ownedProcessGroup, 'SIGKILL'); }
  catch { /* The group has already ended or signaling was denied. */ }
}
process.on('exit', killOwnedGroupOnExit);
process.stdin.on('close', () => {
  if (!explicitShutdown) cleanupProcessGroupOnInputClose();
  finishOutput();
});
process.stdout.write = (chunk, encoding, cb) => process.stderr.write(chunk, encoding, cb);

const localSecrets = (() => {
  const encoded = process.env.FIREEMU_LOCAL_SECRETS_JSON;
  delete process.env.FIREEMU_LOCAL_SECRETS_JSON;
  if (!encoded) return new Map();
  const parsed = JSON.parse(encoded);
  return new Map(Object.entries(parsed).filter(([, value]) => typeof value === "string"));
})();
let functionEnvironmentQueue = Promise.resolve();
const sharedFunctionInvocations = new Set();
let queuedSharedKey = null;
let activeSharedEnvironments = 0;
let activeSharedKey = null;
let sharedSavedSecrets;
let discoveredGlobalOptions = {};

function inspectorPort() {
  const activeUrl = inspectorUrl();
  if (!activeUrl) return undefined;
  try {
    const endpoint = new URL(activeUrl);
    if (endpoint.hostname !== "127.0.0.1") return undefined;
    const port = Number(endpoint.port);
    return Number.isInteger(port) && port >= 1 && port <= 65535 ? port : undefined;
  } catch {
    return undefined;
  }
}

let activeInspectorPort;

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

function firebaseFunctionsPackage(require) {
  let root = dirname(require.resolve("firebase-functions"));
  for (;;) {
    const candidate = join(root, "package.json");
    if (existsSync(candidate)) {
      const manifest = JSON.parse(readFileSync(candidate, "utf8"));
      if (manifest.name === "firebase-functions") return { root, manifest };
    }
    const parent = dirname(root);
    if (parent === root) throw new Error("cannot locate the firebase-functions package root");
    root = parent;
  }
}

async function firebaseHttpsErrorConstructors(require) {
  const constructors = [];
  try {
    constructors.push(require("firebase-functions/https").HttpsError);
  } catch {
    // The ESM export below may still be available. An empty set fails closed.
  }
  try {
    const { root, manifest } = firebaseFunctionsPackage(require);
    const esmTarget = esmExportTarget(manifest.exports?.["./https"]);
    if (typeof esmTarget !== "string" || !esmTarget.startsWith("./")) {
      throw new Error("firebase-functions does not export ESM https");
    }
    const esmHttps = await import(pathToFileURL(resolve(root, esmTarget)).href);
    constructors.push(esmHttps.HttpsError);
  } catch {
    // A missing constructor never widens trust; genuine errors from that module fail closed.
  }
  return constructors.filter(
    (constructor, index) =>
      typeof constructor === "function" && constructors.indexOf(constructor) === index,
  );
}

function send(msg) {
  return frameOutput.send(msg);
}

function log(level, message, invocationId, functionName, user = false, fields) {
  const entry = {
    type: "log",
    level,
    message: boundLogMessage(message),
    invocationId,
    functionName,
    user,
  };
  if (fields && Object.keys(fields).length > 0) entry.fields = fields;
  send(entry);
}

const invocationLogger = createInvocationLogger((entry) =>
  log(entry.level, entry.message, entry.invocationId, entry.functionName, entry.user, entry.fields),
);
invocationLogger.install();

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
  // Tasks and Blocking Auth also enter through the HTTP wrapper, regardless
  // of generation. Generation is the value announced to the daemon, not a
  // second read of user-owned function metadata at invocation time.
  if (["http", "tasks", "blockingAuth"].includes(spec.trigger?.type)) return "http";
  if (spec.trigger?.type === "schedule") return spec.generation === 1 ? "event" : "http";
  return spec.generation === 1 ? "event" : "cloudevent";
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

function withFunctionEnvironment(spec, task, invocationId) {
  const shared = localSecrets.size > 0 && activeInspectorPort === undefined;
  const sharedKey = shared ? JSON.stringify([...new Set(
    (spec?.platformOptions?.secrets || []).filter(name => localSecrets.has(name)),
  )].sort()) : null;
  const run = async () => {
    if (finishingOutput || outputFailed) throw new Error("runner is shutting down");
    setFunctionIdentity(spec);
    let saved;
    if (shared) {
      if (activeSharedEnvironments === 0) {
        sharedSavedSecrets = hideLocalSecrets();
        activeSharedKey = sharedKey;
      } else if (activeSharedKey !== sharedKey) {
        throw new Error("secret environment groups overlapped");
      }
      activeSharedEnvironments++;
    } else {
      saved = hideLocalSecrets();
    }
    try {
      for (const name of spec?.platformOptions?.secrets || []) {
        if (localSecrets.has(name)) process.env[name] = localSecrets.get(name);
      }
      return await invocationLogger.run({ functionName: spec?.name, invocationId }, task);
    } finally {
      if (shared) {
        activeSharedEnvironments--;
        if (activeSharedEnvironments === 0) {
          restoreLocalSecrets(sharedSavedSecrets);
          sharedSavedSecrets = undefined;
          activeSharedKey = null;
        }
      } else {
        restoreLocalSecrets(saved);
      }
    }
  };
  if (localSecrets.size === 0 && activeInspectorPort === undefined) return run();
  const previous = functionEnvironmentQueue;
  if (shared) {
    // Only identical local-secret sets share an environment. A different set
    // closes this group before its first invocation can enter.
    if (queuedSharedKey !== sharedKey) {
      const pendingShared = [...sharedFunctionInvocations];
      sharedFunctionInvocations.clear();
      functionEnvironmentQueue = Promise.allSettled([previous, ...pendingShared]).then(() => {});
      queuedSharedKey = sharedKey;
    }
    const result = functionEnvironmentQueue.then(run);
    sharedFunctionInvocations.add(result);
    void result.then(
      () => sharedFunctionInvocations.delete(result),
      () => sharedFunctionInvocations.delete(result),
    );
    return result;
  }
  const pendingShared = [...sharedFunctionInvocations];
  sharedFunctionInvocations.clear();
  queuedSharedKey = null;
  const result = Promise.allSettled([previous, ...pendingShared]).then(run);
  functionEnvironmentQueue = result.catch(() => {});
  return result;
}

function hideLocalSecrets() {
  const saved = new Map();
  for (const [name] of localSecrets) {
    saved.set(
      name,
      Object.prototype.hasOwnProperty.call(process.env, name) ? process.env[name] : undefined,
    );
    delete process.env[name];
  }
  return saved;
}

function restoreLocalSecrets(saved) {
  for (const [name, value] of saved) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
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
  return exportNamespace(mod);
}

// Unsupported async options may already be rejected. Observe that rejection
// before isolating the export so it cannot terminate discovery of siblings.
function observeAsyncValue(value) {
  try {
    if (value instanceof Promise) {
      void Promise.prototype.then.call(value, undefined, () => {});
      return true;
    }
    if ((typeof value === "object" && value !== null) || typeof value === "function") {
      // Obtain a thenable's accessor once; Promise.resolve(value) would read it
      // again. The fixed wrapper preserves asynchronous assimilation and the
      // original receiver without consulting the user object's getter twice.
      const then = value.then;
      if (typeof then === "function") {
        void Promise.resolve({
          then(resolve, reject) { Reflect.apply(then, value, [resolve, reject]); },
        }).catch(() => {});
        return true;
      }
    }
  } catch {
    // Even instanceof/getPrototypeOf or a then getter may throw (e.g. a
    // revoked Proxy). Error reporting must not throw a second time and kill
    // healthy sibling discovery. This is not an arbitrary-code sandbox.
  }
  return false;
}

function rejectAsyncOption(value, field) {
  if (observeAsyncValue(value))
    throw new Error(`${field} expression returned an asynchronous value`);
  return value;
}

// SDK endpoint options keep Expression objects until the local runtime resolves
// them. JSON/toString encode a deployment expression, not its runtime value.
// Match the existing numeric-option `.value()` protocol, but never read its
// accessor twice or coerce an unresolved value into false/true/default.
function resolvedOption(value, field) {
  if (value == null) return undefined;
  if (value?.[Symbol.for("firebase-functions:ResetValue:Tag")] === true) return undefined;
  if (typeof value === "object") {
    const evaluate = value.value;
    if (typeof evaluate === "function") {
      const resolved = evaluate.call(value);
      if (resolved == null) throw new Error(`${field} expression did not resolve to a value`);
      return rejectAsyncOption(resolved, field);
    }
  }
  return rejectAsyncOption(value, field);
}

function resolvedBoolean(value, field) {
  const resolved = resolvedOption(value, field);
  if (resolved === undefined) return undefined;
  if (typeof resolved !== "boolean") throw new Error(`${field} did not resolve to a boolean`);
  return resolved;
}

function firstRegion(ep) {
  const resolved = resolvedOption(ep.region, "region");
  if (resolved === undefined) return undefined;
  // Preserve this runner's existing first-region policy. This is not a new
  // multi-region deployment implementation. Validate the list rather than
  // allowing malformed later entries to be silently hidden by selection.
  const values = Array.isArray(resolved)
    ? resolved.map(region => resolvedOption(region, "region"))
    : [resolved];
  for (const value of values) {
    if (typeof value !== "string" || value.length === 0) {
      throw new Error("region did not resolve to a non-empty string");
    }
  }
  return values[0];
}

function resolvedNonNegativeInteger(value, field) {
  const resolved = resolvedOption(value, field);
  if (resolved === undefined) return undefined;
  if (!Number.isSafeInteger(resolved) || resolved < 0) {
    throw new Error(`${field} did not resolve to a non-negative integer`);
  }
  return resolved;
}

// Routing and dispatch options must be concrete before publishing the hello.
// Do not stringify an Expression (that emits its deployment representation),
// coerce malformed values, or retain a caller-owned map with a later toJSON.
function triggerRecord(value, field) {
  if (value == null || value?.[Symbol.for("firebase-functions:ResetValue:Tag")] === true) {
    return Object.create(null);
  }
  rejectAsyncOption(value, field);
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${field} must be an object`);
  }
  return value;
}

function triggerString(value, field, { optional = false, allowEmpty = false } = {}) {
  const resolved = resolvedOption(value, field);
  if (resolved === undefined && optional) return undefined;
  if (typeof resolved !== "string" || (!allowEmpty && resolved.length === 0)) {
    throw new Error(`${field} did not resolve to ${allowEmpty ? "a string" : "a non-empty string"}`);
  }
  return resolved;
}

function triggerFilters(value) {
  const input = triggerRecord(value, "eventFilters");
  const output = Object.create(null);
  for (const key of Object.keys(input)) {
    // Preserve empty exact-match values and literal __proto__/toJSON keys as
    // strings, not object hooks. Null is not an instruction to drop a filter.
    output[key] = triggerString(input[key], `eventFilters.${key}`, { allowEmpty: true });
  }
  return Object.freeze(output);
}

const SCHEDULE_RETRY_FIELDS = new Set([
  "retryCount", "maxRetrySeconds", "minBackoffSeconds", "maxBackoffSeconds", "maxDoublings",
]);
const TASK_RETRY_FIELDS = new Set([
  "maxAttempts", "maxRetrySeconds", "minBackoffSeconds", "maxBackoffSeconds", "maxDoublings",
]);
const TASK_RATE_FIELDS = new Set(["maxConcurrentDispatches", "maxDispatchesPerSecond"]);

const V1_SCHEDULE_DURATIONS = Object.freeze({
  maxRetryDuration: "maxRetrySeconds",
  minBackoffDuration: "minBackoffSeconds",
  maxBackoffDuration: "maxBackoffSeconds",
});

function triggerNumbers(value, field, allowed, durationAliases = undefined) {
  const input = triggerRecord(value, field);
  const output = Object.create(null);
  const populated = new Set();
  for (const key of Object.keys(input)) {
    const durationKey = durationAliases && Object.hasOwn(durationAliases, key)
      ? durationAliases[key] : undefined;
    if (!allowed.has(key) && !durationKey) {
      observeAsyncValue(input[key]);
      throw new Error(`${field}.${key} is not supported`);
    }
    const outputKey = durationKey ?? key;
    const original = input[key];
    if (original !== undefined) {
      if (populated.has(outputKey)) throw new Error(`${field}.${outputKey} is specified twice`);
      populated.add(outputKey);
    }
    let resolved = resolvedOption(original, `${field}.${key}`);
    if (resolved === undefined) {
      // Pinned SDKs put null/ResetValue in numeric records for defaults. Keep
      // that wire meaning; an expression returning null has already failed.
      if (original !== undefined) output[outputKey] = null;
      continue;
    }
    if (durationKey) {
      // Gen1's public ScheduleRetryConfig uses protobuf Duration strings,
      // while this runner's existing native protocol uses numeric seconds.
      // Accept the non-negative seconds form; never parseFloat a suffix or CEL.
      if (typeof resolved !== "string" || !/^(?:0|[1-9][0-9]*)(?:\.[0-9]{1,9})?s$/.test(resolved)) {
        throw new Error(`${field}.${key} did not resolve to a seconds duration`);
      }
      resolved = Number(resolved.slice(0, -1));
    }
    if (typeof resolved !== "number" || !Number.isFinite(resolved)) {
      throw new Error(`${field}.${key} did not resolve to a finite number`);
    }
    // Preserve fractional seconds and rates. Native range/count conversion is
    // unchanged: this is not a second implementation of cloud quota policy.
    output[outputKey] = resolved;
  }
  return Object.freeze(output);
}

function describeSchedule(base, value) {
  const input = triggerRecord(value, "scheduleTrigger");
  const schedule = triggerString(input.schedule, "scheduleTrigger.schedule");
  const timeZone = triggerString(input.timeZone, "scheduleTrigger.timeZone", { optional: true });
  // Some Gen1 SDK entrypoints already turn an Expression into braced CEL.
  // This local resolver does not implement CEL: do not announce it as a cron.
  if (schedule.includes("{{") || timeZone?.includes("{{")) {
    throw new Error("scheduleTrigger contains an unresolved deployment expression");
  }
  const retryConfig = triggerNumbers(input.retryConfig, "scheduleTrigger.retryConfig",
    SCHEDULE_RETRY_FIELDS, base.generation === 1 ? V1_SCHEDULE_DURATIONS : undefined);
  return {
    ...base,
    retry: (retryConfig.retryCount ?? 0) > 0,
    trigger: { type: "schedule", schedule, timeZone, retryConfig },
  };
}

// Preserve shared Gen1/Gen2 endpoint options. Memory and instance limits shape local
// admission; the other deployment and IAM values remain visible for faithful diagnostics.
function platformOptions(ep) {
  if (!ep) return undefined;
  const options = {};
  const preserveExternalChanges =
    ep.preserveExternalChanges ??
    (ep.platform === "gcfv2" ? discoveredGlobalOptions.preserveExternalChanges : undefined);
  if (preserveExternalChanges != null)
    options.preserveExternalChanges = Boolean(preserveExternalChanges);
  const availableMemoryMb = resolvedNonNegativeInteger(ep.availableMemoryMb, "availableMemoryMb");
  if (availableMemoryMb !== undefined) options.availableMemoryMb = availableMemoryMb;
  const minInstances = resolvedNonNegativeInteger(ep.minInstances, "minInstances");
  if (minInstances !== undefined) options.minInstances = minInstances;
  const maxInstances = resolvedNonNegativeInteger(ep.maxInstances, "maxInstances");
  if (maxInstances !== undefined) options.maxInstances = maxInstances;
  if (ep.ingressSettings != null) options.ingressSettings = ep.ingressSettings;
  if (ep.httpsTrigger?.invoker?.length) options.invoker = ep.httpsTrigger.invoker;
  if (ep.serviceAccountEmail != null) options.serviceAccountEmail = ep.serviceAccountEmail;
  if (ep.vpc?.connector != null) options.vpcConnector = ep.vpc.connector;
  if (ep.vpc?.egressSettings != null) options.vpcEgressSettings = ep.vpc.egressSettings;
  if (ep.labels && Object.keys(ep.labels).length > 0) options.labels = ep.labels;
  if (ep.platform === "gcfv2") {
    if (ep.cpu != null) options.cpu = String(ep.cpu);
    if (Array.isArray(ep.vpc?.networkInterfaces))
      options.networkInterfaces = ep.vpc.networkInterfaces;
  }
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

// A blocking trigger the runner does not serve: a product decision when the event belongs to
// a deferred or not-planned product (Firebase AI Logic), otherwise the official emulator's
// "not served" report for an identity event it has no hook for (email and SMS).
function ignoredBlocking(base, eventType) {
  const product = deferredProduct(eventType);
  if (product) return ignored(base, product.triggerType, product.scope, product.reason);
  return ignored(base, "blocking", "unsupported", `blocking identity event ${eventType} is not served`);
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
    match: (type) => type.includes("dataconnect"),
    triggerType: "dataconnect",
    scope: "deferred",
    reason: "deferred: the Data Connect emulator is not in the active supported surface",
  },
  {
    match: (type) => type.includes("ailogic"),
    triggerType: "ai",
    scope: "notPlanned",
    reason: "not planned: Firebase AI Logic blocking triggers have no local emulator",
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
    // Resource labels have fixed positions. A project/database can itself be
    // named "documents" or "databases"; substring searches pick the wrong slash.
    // Preserve the document pattern verbatim for the native pattern validator.
    resource = triggerString(resource, "eventTrigger.resource", { optional: true, allowEmpty: true }) ?? "";
    const match = resource.match(/^projects\/[^/]+\/databases\/([^/]+)\/documents\/(.+)$/s);
    if (!match) {
      return ignored(
        base, "firestore", "unsupported", "v1 Firestore resource has an unsupported shape",
      );
    }
    return {
      ...base,
      ...v1,
      retry,
      trigger: {
        type: "firestore",
        eventType: `google.cloud.firestore.document.v1.${{ create: "created", update: "updated", delete: "deleted", write: "written" }[fsMatch[1]]}`,
        database: match[1],
        document: match[2],
      },
    };
  }
  const stMatch = type.match(/^google\.storage\.object\.(finalize|delete|metadataUpdate|archive)$/);
  if (stMatch) {
    resource = triggerString(resource, "eventTrigger.resource", { optional: true, allowEmpty: true }) ?? "";
    const match = resource.match(/^projects\/[^/]+\/buckets\/([^/]+)$/);
    if (!match) {
      // Missing/unparseable bucket metadata must not become an unfiltered
      // Storage trigger. Valid SDK v1 resources use projects/_/buckets/<bucket>.
      return ignored(
        base, "storage", "unsupported", "v1 Storage resource has an unsupported shape",
      );
    }
    return {
      ...base,
      ...v1,
      retry,
      trigger: {
        type: "storage",
        eventType: `google.cloud.storage.object.v1.${{ finalize: "finalized", delete: "deleted", metadataUpdate: "metadataUpdated", archive: "archived" }[stMatch[1]]}`,
        bucket: match[1],
      },
    };
  }
  if (schedule) {
    return describeSchedule({ ...base, ...v1 }, schedule);
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
    resource = triggerString(resource, "eventTrigger.resource");
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

// Both SDK generations expose a taskQueueTrigger (legacy v1 also exposes it
// on __trigger). Always call the exported HTTP wrapper, not its testing-only
// .run callback, so decoding and task context stay in the SDK wrapper.
function describeTaskQueue(base, queue) {
  if (!queue || typeof queue !== "object" || Array.isArray(queue)) {
    throw new Error("taskQueueTrigger must be an object");
  }
  const retryConfig = triggerNumbers(queue.retryConfig, "taskQueueTrigger.retryConfig", TASK_RETRY_FIELDS);
  const rateLimits = triggerNumbers(queue.rateLimits, "taskQueueTrigger.rateLimits", TASK_RATE_FIELDS);
  return { ...base, trigger: { type: "tasks", retryConfig, rateLimits } };
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

function blockingAuthTrigger(eventType, options) {
  return {
    type: "blockingAuth",
    eventType,
    accessToken: options?.accessToken === true,
    idToken: options?.idToken === true,
    refreshToken: options?.refreshToken === true,
  };
}

function describe(name, fn, instrumentation) {
  const callable = () => ({
    type: "http",
    callable: true,
    ...callableAppCheck(instrumentation, fn),
  });
  const ep = fn.__endpoint;
  const platform = ep?.platform;
  const base = {
    name,
    entryPoint: name,
    generation: platform === "gcfv2" ? 2 : 1,
  };
  if (resolvedBoolean(ep?.omit, "omit") === true) return { ...base, omitted: true };
  if (ep && Object.keys(ep).length > 0 && platform !== "gcfv1" && platform !== "gcfv2") {
    // A nonempty endpoint without a known platform is not a legacy trigger.
    // Do not advertise generation 1 while silently invoking the v2 convention.
    return ignored(base, "unknown", "unsupported", "endpoint platform is not recognised");
  }
  if (ep && platform === "gcfv1") {
    const deployment = platformOptions(ep);
    if (deployment) base.platformOptions = deployment;
    const timeout = resolvedNonNegativeInteger(ep.timeoutSeconds, "timeoutSeconds");
    // The pinned SDK uses literal zero for unset/default timeout. Do not turn
    // an Expression resolving to zero into a zero-length native deadline.
    if (timeout !== undefined && timeout > 0) base.timeoutSeconds = timeout;
    const region = firstRegion(ep);
    if (region) base.region = region;
    if (ep.taskQueueTrigger) return describeTaskQueue(base, ep.taskQueueTrigger);
    if (ep.httpsTrigger) return { ...base, trigger: { type: "http", callable: false } };
    if (ep.callableTrigger) return { ...base, trigger: callable() };
    if (ep.blockingTrigger) {
      const eventType = String(ep.blockingTrigger.eventType || "");
      if (eventType.endsWith("beforeCreate") || eventType.endsWith("beforeSignIn")) {
        return {
          ...base,
          trigger: blockingAuthTrigger(eventType, ep.blockingTrigger.options),
        };
      }
      return ignoredBlocking(base, eventType,
      );
    }
    const et = ep.eventTrigger || {};
    return describeV1Event(
      base,
      String(et.eventType || ""),
      triggerRecord(et.eventFilters, "eventFilters").resource,
      ep.scheduleTrigger,
      resolvedBoolean(et.retry, "eventTrigger.retry") ?? false,
    );
  }
  if (ep && Object.keys(ep).length > 0) {
    const deployment = platformOptions(ep);
    if (deployment) base.platformOptions = deployment;
    const region = firstRegion(ep);
    if (region) base.region = region;
    const timeout = resolvedNonNegativeInteger(ep.timeoutSeconds, "timeoutSeconds");
    // The pinned SDK uses literal zero for unset/default timeout. Do not turn
    // an Expression resolving to zero into a zero-length native deadline.
    if (timeout !== undefined && timeout > 0) base.timeoutSeconds = timeout;
    const concurrency = resolvedNonNegativeInteger(ep.concurrency, "concurrency");
    if (concurrency !== undefined) base.concurrency = concurrency;
    if (ep.taskQueueTrigger) return describeTaskQueue(base, ep.taskQueueTrigger);
    if (ep.httpsTrigger) return { ...base, trigger: { type: "http", callable: false } };
    if (ep.callableTrigger) return { ...base, trigger: callable() };
    if (ep.scheduleTrigger) {
      return describeSchedule(base, ep.scheduleTrigger);
    }
    if (ep.blockingTrigger) {
      const eventType = String(ep.blockingTrigger.eventType || "");
      if (eventType.endsWith("beforeCreate") || eventType.endsWith("beforeSignIn")) {
        return {
          ...base,
          trigger: blockingAuthTrigger(eventType, ep.blockingTrigger.options),
        };
      }
      return ignoredBlocking(base, eventType,
      );
    }
    if (ep.eventTrigger) {
      const et = ep.eventTrigger;
      const type = et.eventType || "";
      base.retry = resolvedBoolean(et.retry, "eventTrigger.retry") ?? false;
      if (type.startsWith("google.cloud.firestore.")) {
        const filters = triggerRecord(et.eventFilters, "eventFilters");
        const patterns = triggerRecord(et.eventFilterPathPatterns, "eventFilterPathPatterns");
        const documentPattern = triggerString(patterns.document, "eventFilterPathPatterns.document", { optional: true });
        return {
          ...base,
          trigger: {
            type: "firestore",
            eventType: type,
            database: triggerString(filters.database, "eventFilters.database", { optional: true }) ?? "(default)",
            document: documentPattern ?? triggerString(filters.document, "eventFilters.document"),
          },
        };
      }
      if (type.startsWith("google.cloud.storage.")) {
        return {
          ...base,
          trigger: {
            type: "storage",
            eventType: type,
            bucket: triggerString(triggerRecord(et.eventFilters, "eventFilters").bucket, "eventFilters.bucket", { optional: true }),
          },
        };
      }
      if (type === "google.cloud.pubsub.topic.v1.messagePublished") {
        const topic = triggerString(triggerRecord(et.eventFilters, "eventFilters").topic, "eventFilters.topic");
        const projectedTopic = topic.replace(/^.*\/topics\//, "");
        if (!projectedTopic) throw new Error("eventFilters.topic resolved to an empty topic");
        return { ...base, trigger: { type: "pubsub", topic: projectedTopic } };
      }
      const channel = triggerString(et.channel, "eventTrigger.channel", { optional: true });
      if (channel !== undefined) {
        // `onCustomEventPublished`: the channel is `locations/<l>/channels/<c>` and every
        // eventFilter beyond the type is matched against the published event's attributes.
        return {
          ...base,
          trigger: {
            type: "eventarc",
            eventType: type,
            channel,
            filters: triggerFilters(et.eventFilters),
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
            filters: triggerFilters(et.eventFilters),
          },
        };
      }
      const product = deferredProduct(type);
      if (product) return ignored(base, product.triggerType, product.scope, product.reason);
      return ignored(base, "unknown", "unsupported", `event type ${type} is not recognised`);
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
    if (t.taskQueueTrigger) return describeTaskQueue(base, t.taskQueueTrigger);
    if (t.httpsTrigger) {
      return {
        ...base,
        trigger: t.labels?.["deployment-callable"] ? callable() : { type: "http", callable: false },
      };
    }
    if (t.blockingTrigger) {
      const eventType = String(t.blockingTrigger.eventType || "");
      if (eventType.endsWith("beforeCreate") || eventType.endsWith("beforeSignIn")) {
        return {
          ...base,
          trigger: blockingAuthTrigger(eventType, t.blockingTrigger.options),
        };
      }
      return ignoredBlocking(base, eventType,
      );
    }
    const et = t.eventTrigger;
    if (et)
      return describeV1Event(
        base,
        String(et.eventType || ""),
        et.resource,
        t.schedule,
        !!et.failurePolicy || !!t.failurePolicy,
      );
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

async function makeHttpServer(functions, manifest) {
  const require = createRequire(join(sourceDir, "package.json"));
  let express;
  let expressRequire = require;
  try {
    express = require("express");
  } catch {
    // A Functions codebase is required to install firebase-functions, not Express directly.
    // npm commonly hoists the SDK's dependency, while pnpm keeps it beside the SDK. Resolve
    // from firebase-functions as a fallback so both valid layouts behave the same way.
    try {
      expressRequire = createRequire(require.resolve("firebase-functions"));
      express = expressRequire("express");
    } catch {
      return null;
    }
  }
  const HttpsErrors = await firebaseHttpsErrorConstructors(require);
  const app = express();
  const admission = createHttpAdmission({
    secret: process.env.FIREEMU_RUNNER_SECRET || "",
    isStopping: () => finishingOutput || outputFailed,
  });
  app.use(
    express.json({
      limit: "32mb",
      verify: (req, _res, buf) => {
        admission.verify(req, _res, buf);
        req.rawBody = buf;
      },
    }),
  );
  app.use(
    express.text({
      limit: "32mb",
      verify: (req, _res, buf) => {
        admission.verify(req, _res, buf);
        req.rawBody = buf;
      },
    }),
  );
  app.use(
    express.urlencoded({
      extended: true,
      limit: "32mb",
      verify: (req, _res, buf) => {
        admission.verify(req, _res, buf);
        req.rawBody = buf;
      },
    }),
  );
  app.use(
    express.raw({
      type: () => true,
      limit: "32mb",
      verify: (req, _res, buf) => {
        admission.verify(req, _res, buf);
        req.rawBody = buf;
      },
    }),
  );
  const major = Number.parseInt(
    String(expressRequire("express/package.json").version).split(".")[0],
    10,
  );
  // Express 5 (path-to-regexp 8) and Express 4 spell the optional rest differently.
  const route = major >= 5 ? "/:project/:region/:name{/*rest}" : "/:project/:region/:name*";
  const project = process.env.GCLOUD_PROJECT || "";
  app.all(route, (req, res) => {
    if (finishingOutput || outputFailed) {
      res.status(503).send("runner is shutting down");
      return;
    }
    // Node-level admission authenticated the proxy before body parsing and
    // removed its capability header. Selection below retains namespace checks.
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
    // Capture close/finish while waiting for the per-function environment too.
    // A completed IncomingMessage is not a disconnected response: do not use
    // req.close or req.destroyed to cancel a valid, fully received request.
    const completeAdmission = admission.begin(req);
    if (!completeAdmission) { if (!res.destroyed && !res.writableEnded) res.destroy(); return; }
    const lifetime = trackHttpResponse(res);
    const blocking = spec.trigger?.type === "blockingAuth";
    const replyFailure = (error) => {
      const failure = blocking
        ? blockingFailure(error, HttpsErrors)
        : invocationFailure(error);
      try {
        const diagnostic = blocking ? invocationFailure(error).diagnostic : failure.diagnostic;
        log("error", `${spec.name}: ${diagnostic}`, undefined, spec.name);
      } catch {
        // Diagnostics cannot suppress the already classified response.
      }
      // Never try to append a second error body to a partial/finished response,
      // or send a reply to a peer that has already disconnected.
      if (res.destroyed || res.writableEnded) return;
      try {
        if (res.headersSent) res.destroy();
        else if (blocking) res.status(failure.status).json({
          error: { status: failure.canonicalName, message: failure.message },
        });
        else res.status(500).send("internal error");
      } catch {
        res.destroy();
      }
    };
    void withFunctionEnvironment(spec, async () => {
      // Do not run queued callbacks whose requesting peer has gone away. This
      // check never races a running callback against close: its Promise still
      // owns the environment until it settles, even after the response closes.
      if (!lifetime.canStart()) return;
      try {
        if (blocking) {
          const user = req.body?.data?.user;
          const context = req.body?.data?.context || {};
          const value = await (spec.generation === 1 ? fn.run(user, context) : fn.run({ ...context, data: user }));
          if (lifetime.canStart()) {
            // Materialization can call user getters/toJSON. Keep it inside this
            // function's secret/logger environment, not the next queue entry's.
            const payload = blockingResult(value, spec.trigger.eventType, HttpsErrors[0]);
            if (lifetime.canStart()) res.status(200).json(payload);
          }
        } else {
          await fn(req, res);
        }
      } catch (error) {
        replyFailure(error);
      }
      // Already-observed close/finish resolves immediately. A callback that
      // returned before ending its response still retains the environment.
      await lifetime.wait();
    })
      .catch(replyFailure)
      .finally(() => { lifetime.dispose(); completeAdmission(); });
  });
  const server = createServer((req, res) => admission.handle(req, res, app));
  // Do not let Node send 100 Continue before authentication/capacity checks.
  server.on("checkContinue", (req, res) => admission.handle(req, res, app, true));
  return new Promise((resolveServer, reject) => {
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => resolveServer(server));
  });
}

async function invoke(functions, manifest, msg) {
  const spec = manifest.functions.find((f) => f.name === msg.function);
  if (!spec) throw new Error("unknown function");
  if (msg.entryPoint !== undefined && msg.entryPoint !== spec.entryPoint) {
    throw new Error("entry point does not match the function manifest");
  }
  if (msg.trigger !== spec.trigger?.type ||
      !["schedule", "firestore", "storage", "pubsub", "eventarc", "auth"].includes(msg.trigger)) {
    throw new Error("trigger does not match the function manifest");
  }
  const fn = functions.get(spec.entryPoint);
  if (typeof fn !== "function") throw new Error("missing function entry point");
  await withFunctionEnvironment(
    spec,
    async () => {
      if (spec.generation === 1) {
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
    },
    msg.invocationId,
  );
}


async function main() {
  let functions;
  let manifest;
  let runnerReady = false;
  const activeInvocations = new InvocationBudget();
  // Read before loading user code, which may await indefinitely after spawning children.
  readFrames(
    process.stdin,
    (msg, payloadBytes) => {
      if (msg.type === "shutdown") {
        explicitShutdown = true;
        // Volta must observe Node exit before its shim is killed, or the daemon
        // can finish shutdown while Node still owns an inspector listener.
        deferCleanShutdownGroupCleanup();
        finishOutput();
        return false;
      }
      if (!runnerReady) {
        process.stderr.write('[functions] invocation received before runner hello\n');
        process.exit(2);
      }
      // Includes callbacks waiting for secret/debugger environment selection.
      // Retire on overflow; never report an unexecuted request as successful or
      // retry uncertain in-flight side effects inside this runner.
      const release = activeInvocations.reserve(msg.invocationId, payloadBytes);
      invoke(functions, manifest, msg)
        .then(() => send({ type: "result", invocationId: msg.invocationId, ok: true }))
        .catch((error) => {
          const failure = invocationFailure(error);
          try {
            log("error", `${msg.function}: ${failure.diagnostic}`, msg.invocationId, msg.function);
          } catch {
            // Diagnostic output cannot suppress the invocation's failure result.
          }
          send({
            type: "result",
            invocationId: msg.invocationId,
            ok: false,
            error: failure.message,
          });
        })
        .finally(release);
    },
    () => {
      cleanupProcessGroupOnInputClose();
      finishOutput();
    },
    (error) => {
      // The pipe cannot be resynchronized safely. Retire the runner so the daemon
      // resolves outstanding invocations as RunnerGone, rather than timing out.
      // Do not print JSON.parse diagnostics containing user payload fragments.
      try { process.stderr.write(`${error.message}\n`); } finally { process.exit(2); }
    },
  );
  // Before any user code loads: the callable options are only observable as a callable is
  // declared (spec 13.4).
  const instrumentation = instrumentCallables(sourceDir);
  let ns;
  try {
    ns = await loadCodebase();
  } catch (e) {
    log("error", `cannot load functions from ${sourceDir}: ${invocationFailure(e).diagnostic}`);
    process.exit(1);
  }
  try {
    const require = createRequire(join(sourceDir, "package.json"));
    const cjsOptions = require("firebase-functions/v2/options").getGlobalOptions();
    const { root: sdkRoot, manifest: sdkPackage } = firebaseFunctionsPackage(require);
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
    log("warn", `cannot inspect firebase-functions global options: ${invocationFailure(e).message}`);
  }
  const discovered = collectFunctions(ns);
  functions = discovered.functions;
  const { broken } = discovered;
  const described = [...functions.entries()].map(([name, fn]) => {
    try {
      return describe(name, fn, instrumentation);
    } catch (e) {
      const failure = observeAsyncValue(e)
        ? new Error("asynchronous endpoint metadata failure")
        : e;
      return ignored(
        { name, entryPoint: name },
        "unknown",
        "unsupported",
        `the export could not be described: ${invocationFailure(failure).message}`,
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
  manifest = {
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
      log("error", `cannot start the HTTP server: ${invocationFailure(e).diagnostic}`);
    }
  }
  activeInspectorPort = inspectorPort();
  send({
    type: "hello",
    runner: "node",
    codebase: args.codebase,
    version: process.version,
    inspectorPort: activeInspectorPort,
    httpPort,
    manifest,
    appCheck: {
      firebaseFunctionsVersion: instrumentation.version,
      instrumentation: instrumentation.supported ? "ok" : instrumentation.reason,
      debugFeatures: instrumentation.debugFeatures,
      debugMode: process.env.FIREBASE_DEBUG_MODE === "true",
      authHeaders: instrumentation.authHeaders,
      graphs: instrumentation.graphs,
    },
  });
  runnerReady = true;
}

main().catch((error) => {
  // Failed discovery must not publish a partial hello or rely on Node's
  // unhandled-rejection formatting of arbitrary thrown user objects.
  const failure = invocationFailure(error);
  try { process.stderr.write(`${failure.message}\n`); } finally { process.exit(1); }
});
