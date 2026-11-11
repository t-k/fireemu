// The nested-callable guard is wired into both module graphs of firebase-functions: the CommonJS
// build through callable-app-check.mjs and the ESM build through its loader hook. This test runs the
// real instrumentation against a minimal stand-in for the SDK's internal modules, in a child process
// (the instrumentation registers a global and a module hook that cannot be undone).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const here = (name) => fileURLToPath(new URL(name, import.meta.url));

function fakeSdk(root) {
  const pkg = join(root, "node_modules/firebase-functions");
  for (const dir of ["lib/common/providers", "lib/v2", "lib/common"]) {
    mkdirSync(join(pkg, dir), { recursive: true });
  }
  writeFileSync(
    join(pkg, "package.json"),
    JSON.stringify({ name: "firebase-functions", version: "7.3.2", main: "index.js" }),
  );
  writeFileSync(join(pkg, "index.js"), "module.exports = {};\n");
  writeFileSync(
    join(pkg, "lib/common/providers/https.js"),
    `exports.onCallHandler = (options, handler, version) => options.notAFunction ?? ((req, res) => handler(req, res));
exports.unsafeDecodeAppCheckToken = () => ({});
exports.CALLABLE_AUTH_HEADER = "X-Callable-Context-Auth";
exports.ORIGINAL_AUTH_HEADER = "X-Original-Auth";
`,
  );
  writeFileSync(join(pkg, "lib/v2/trace.js"), "exports.wrapTraceContext = (handler) => (...a) => handler(...a);\n");
  writeFileSync(join(pkg, "lib/common/onInit.js"), "exports.withInit = (func) => (...a) => func(...a);\n");
  writeFileSync(
    join(pkg, "lib/common/debug.js"),
    `const features = () => { try { return JSON.parse(process.env.FIREBASE_DEBUG_FEATURES ?? "{}"); } catch { return {}; } };
exports.isDebugFeatureEnabled = (name) => process.env.FIREBASE_DEBUG_MODE === "true" && features()[name] === true;
exports.debugFeatureValue = (name) => features()[name];
`,
  );
  return pkg;
}

const CHILD = `
import { createRequire } from "node:module";
import { join } from "node:path";
import { instrumentCallables } from ${JSON.stringify(here("./callable-app-check.mjs"))};
import { markNonCallableRequest, VERIFIED_CREDENTIAL_HEADER, UNVERIFIED_CREDENTIAL } from ${JSON.stringify(here("./nested-callable.mjs"))};
const root = process.argv[2];
const status = instrumentCallables(root);
const require = createRequire(join(root, "package.json"));
const pkg = join(root, "node_modules/firebase-functions");
const https = require(join(pkg, "lib/common/providers/https.js"));
const trace = require(join(pkg, "lib/v2/trace.js"));
const onInit = require(join(pkg, "lib/common/onInit.js"));
const seen = [];
const handler = (req) => { seen.push(req.header("authorization") ?? null); return "ok"; };
const built = https.onCallHandler({ enforceAppCheck: true, consumeAppCheckToken: true }, handler, "gcfv2");
const notAFunction = { marker: 1 };
const passedThrough = https.onCallHandler({ notAFunction }, handler, "gcfv2");
const request = (headers) => ({ headers: { ...headers }, rawHeaders: [], header(n) { return this.headers[n.toLowerCase()]; } });
const plain = { strict: true, nonCallableHttp: true };
const nested = request({ authorization: "Bearer forged" });
markNonCallableRequest(nested, plain);
const verified = request({ authorization: "Bearer good", [VERIFIED_CREDENTIAL_HEADER]: "1" });
markNonCallableRequest(verified, plain);
const real = request({ authorization: "Bearer forged" });
const wrapped = trace.wrapTraceContext(onInit.withInit(built));
const results = [await built(nested), await built(verified), await built(real), await wrapped(nested)];
console.log(JSON.stringify({
  supported: status.supported,
  seen,
  results,
  unverified: UNVERIFIED_CREDENTIAL,
  options: status.optionsOf(built) ?? null,
  carried: status.optionsOf(wrapped) ?? null,
  sameFunction: built === wrapped,
  notAFunctionKept: passedThrough === notAFunction,
}));
`;

test("the CommonJS hook hands the guarded wrapper back, keeps its observed options and carries them", () => {
  const root = mkdtempSync(join(tmpdir(), "fireemu-nested-wiring-"));
  try {
    fakeSdk(root);
    writeFileSync(join(root, "child.mjs"), CHILD);
    const run = spawnSync(process.execPath, [join(root, "child.mjs"), root], {
      encoding: "utf8",
      env: { PATH: process.env.PATH, FIREBASE_DEBUG_MODE: "true", FIREBASE_DEBUG_FEATURES: '{"skipTokenVerification":true}' },
    });
    assert.equal(run.status, 0, run.stderr);
    const out = JSON.parse(run.stdout.trim().split("\n").at(-1));
    assert.equal(out.supported, true);
    assert.deepEqual(out.seen, [out.unverified, "Bearer good", "Bearer forged", out.unverified]);
    assert.deepEqual(out.results, ["ok", "ok", "ok", "ok"]);
    const options = { enforceAppCheck: true, consumeAppCheckToken: "enabled" };
    assert.deepEqual(out.options, options);
    assert.deepEqual(out.carried, options);
    assert.equal(out.sameFunction, false);
    assert.equal(out.notAFunctionKept, true, "a value that is not a function is handed back as it is");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the ESM hook returns what the registry's observe returns, so the guarded wrapper is the one exported", async () => {
  const { initialize, load } = await import("./callable-app-check-loader.mjs");
  const url = "file:///fake/lib/esm/common/providers/https.mjs";
  initialize({ targets: { [url]: "commonHttps" } });
  const source = [
    "function onCallHandler(options, handler, version) {",
    "  return handler;",
    "}",
    "function encodeSSE(data) {",
    "  return data;",
    "}",
    "export { onCallHandler, encodeSSE };",
    "",
  ].join("\n");
  const loaded = await load(url, {}, async () => ({ format: "module", source }));
  assert.match(loaded.source, /^globalThis\[Symbol\.for\("fireemu\.callableAppCheck"\)\]\.moduleLoaded\("commonHttps"\);/);
  const registry = Symbol.for("fireemu.callableAppCheck");
  const calls = [];
  const had = Object.getOwnPropertyDescriptor(globalThis, registry);
  assert.equal(had, undefined, "this test needs the registry symbol free in its process");
  Object.defineProperty(globalThis, registry, {
    configurable: true,
    value: {
      moduleLoaded() {},
      observe(fn, options) {
        calls.push([fn, options]);
        return "the guarded wrapper";
      },
    },
  });
  try {
    const module = await import(`data:text/javascript;base64,${Buffer.from(loaded.source).toString("base64")}`);
    const handler = () => {};
    assert.equal(module.onCallHandler({ enforceAppCheck: true }, handler, "gcfv2"), "the guarded wrapper");
    assert.deepEqual(calls, [[handler, { enforceAppCheck: true }]]);
  } finally {
    delete globalThis[registry];
  }
});
