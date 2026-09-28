import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { canonicalG0Origins, compareG0, g0SessionPythonSource, readOwnedProcessArgv, resolveLockedUvCommand, validateG0Origins } from "../g0.mjs";
import { verifyG0ProgramDigest } from "../pilot.mjs";
import { digestJson } from "../core.mjs";
import { G0_CASE } from "../registry.mjs";

test("G0 compare refuses a missing retained build binding", () => {
  assert.throws(
    () =>
      compareG0({
        repo: process.cwd(),
        entry: G0_CASE,
        actual: {},
        execution: { artifact: { sha256: "a".repeat(64) } },
        build: null,
      }),
    /g0-artifact-receipt-mismatch/,
  );
});

test("G0 compare refuses a snapshot whose bytes differ from the retained receipt", () => {
  assert.throws(
    () =>
      compareG0({
        repo: process.cwd(),
        entry: G0_CASE,
        actual: {},
        execution: { artifact: { sha256: "b".repeat(64) } },
        build: { artifactSha256: "a".repeat(64) },
      }),
    /g0-artifact-receipt-mismatch/,
  );
});

test("G0 origin binding requires both real loopback services", () => {
  assert.deepEqual(
    validateG0Origins({
      FIRESTORE_EMULATOR_HOST: "127.0.0.1:18080",
      FIREBASE_AUTH_EMULATOR_HOST: "127.0.0.1:19090",
    }),
    { firestore: "127.0.0.1:18080", auth: "127.0.0.1:19090" },
  );
  for (const env of [
    { FIRESTORE_EMULATOR_HOST: "127.0.0.1:18080" },
    { FIRESTORE_EMULATOR_HOST: "example.invalid:18080", FIREBASE_AUTH_EMULATOR_HOST: "127.0.0.1:19090" },
  ]) assert.throws(() => validateG0Origins(env), /g0-owned-origin-required/);
  assert.deepEqual(
    canonicalG0Origins({ FIRESTORE_EMULATOR_HOST: "127.0.0.1:18080", FIREBASE_AUTH_EMULATOR_HOST: "127.0.0.1:19090" }),
    { firestore: "http://127.0.0.1:18080", auth: "http://127.0.0.1:19090" },
  );
});

test("G0 session bridge compiles as the exact Python source it will execute", () => {
  const source = g0SessionPythonSource();
  assert.match(source, /from g0_local_recovery import execute/);
  execFileSync(
    "uv",
    ["run", "python", "-c", "compile(__import__('sys').stdin.read(), '<g0-session>', 'exec')"],
    { input: source, encoding: "utf8", stdio: ["pipe", "ignore", "pipe"] },
  );
});

test("G0 session uses the locked Python 3.12 inventory runtime for generated code", () => {
  const sessionSource = readFileSync(new URL("../g0-session.mjs", import.meta.url), "utf8");
  for (const token of ["--project", "inventoryProject", "--locked", "--python", '"3.12"'])
    assert.match(sessionSource, new RegExp(token.replace(/[.*+?^${}()|[\\]\\]/g, "\\$&")));
  const source = g0SessionPythonSource();
  const output = execFileSync(
    "uv",
    [
      "run",
      "--project",
      resolve(process.cwd(), "tools/compat-inventory"),
      "--locked",
      "--python",
      "3.12",
      "python",
      "-c",
      "import sys; assert sys.version_info >= (3, 12); compile(sys.stdin.read(), '<g0-session>', 'exec'); print(sys.version.split()[0])",
    ],
    { cwd: process.cwd(), input: source, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] },
  );
  assert.match(output.trim(), /^3\.12(?:\.|$)/);
});

test("G0 session rejects stale or substituted launcher receipts before Python dispatch", () => {
  const source = readFileSync(new URL("../g0-session.mjs", import.meta.url), "utf8");
  for (const token of [
    "receipt.pid === process.ppid",
    "receipt.binarySha256 === binaryHash",
    "receipt.configSha256 === configHash",
    "receipt.rulesSha256 === rulesHash",
    "receipt.runDirectory?.ino === runInfo.ino",
    "!receipt.args.includes(\"--import\")",
    "receipt.import === null",
  ]) assert.ok(source.includes(token), token);
});

test("G0 process identity uses the OS-native exact argv of a real owned child", async () => {
  const child = spawn("/bin/sleep", ["1"]);
  try {
    assert.ok(Number.isInteger(child.pid) && child.pid > 0);
    assert.deepEqual(readOwnedProcessArgv(child.pid), ["/bin/sleep", "1"]);
  } finally {
    child.kill("SIGTERM");
    await new Promise((resolve) => child.once("close", resolve));
  }
});

test("G0 session startup resolves the locked uv executable through its real launcher lookup", () => {
  assert.match(resolveLockedUvCommand(), /^\//);
  const source = readFileSync(new URL("../g0-session.mjs", import.meta.url), "utf8");
  assert.match(source, /resolveLockedUvCommand\(\)/);
});

test("G0 session results retain the validated owned Firestore endpoint for closure checks", () => {
  const source = readFileSync(new URL("../g0-session.mjs", import.meta.url), "utf8");
  assert.equal((source.match(/endpoint: canonicalOrigins\.firestore/g) ?? []).length, 2);
  assert.throws(() => canonicalG0Origins({ FIRESTORE_EMULATOR_HOST: "example.invalid:8080", FIREBASE_AUTH_EMULATOR_HOST: "127.0.0.1:19090" }), /g0-owned-origin-required/);
});

test("locked uv Python startup failure is retained as bounded private diagnostics before Gate or wire startup", async () => {
  const directory = mkdtempSync(join(tmpdir(), "g0-startup-diagnostic-"));
  const child = spawn(
    resolveLockedUvCommand(),
    [
      "run",
      "--project",
      resolve(process.cwd(), "tools/compat-inventory"),
      "--locked",
      "--python",
      "3.12",
      "python",
      "-c",
      "raise RuntimeError('bounded-startup-fixture')",
    ],
    { cwd: process.cwd(), stdio: ["ignore", "ignore", "pipe"] },
  );
  let stderrBytes = 0;
  child.stderr.on("data", (chunk) => {
    stderrBytes += chunk.length;
  });
  const exitCode = await new Promise((resolveExit) => child.once("close", resolveExit));
  try {
    assert.notEqual(exitCode, 0);
    assert.ok(stderrBytes > 0);
    assert.equal(existsSync(join(directory, "gate")), false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

const nativeG0PathEnvironment = [
  "G0_RETAINED_ARTIFACT",
  "G0_BUILD_MANIFEST",
  "G0_PRIVATE_PRODUCTION_RESULT",
  "G0_NATIVE_OUTPUT_ROOT",
];
export function nativeG0ReadyFor(env) {
  return (
    nativeG0PathEnvironment.every((name) => typeof env[name] === "string" && env[name].startsWith("/")) &&
    typeof env.G0_ARTIFACT_PROFILE === "string" &&
    /^[a-z0-9][a-z0-9-]{1,80}$/.test(env.G0_ARTIFACT_PROFILE)
  );
}
const nativeG0Ready = nativeG0ReadyFor(process.env);

test("native G0 readiness separates absolute inputs from the registered profile identifier", () => {
  const valid = {
    G0_RETAINED_ARTIFACT: "/artifact",
    G0_BUILD_MANIFEST: "/manifest",
    G0_ARTIFACT_PROFILE: "current-8f129b10",
    G0_PRIVATE_PRODUCTION_RESULT: "/production.json",
    G0_NATIVE_OUTPUT_ROOT: "/runs",
  };
  assert.equal(nativeG0ReadyFor(valid), true);
  assert.equal(nativeG0ReadyFor({ ...valid, G0_ARTIFACT_PROFILE: "" }), false);
  assert.equal(nativeG0ReadyFor({ ...valid, G0_ARTIFACT_PROFILE: "/profile" }), false);
  assert.equal(nativeG0ReadyFor({ ...valid, G0_NATIVE_OUTPUT_ROOT: "relative" }), false);
});

test("G0 opt-in native handoff reaches the real worker and closes every recovery slot", { skip: !nativeG0Ready }, async () => {
  assert.equal(existsSync(process.env.G0_NATIVE_OUTPUT_ROOT), true, "native output parent must exist");
  const output = join(process.env.G0_NATIVE_OUTPUT_ROOT, `g0-native-${process.pid}-${Date.now()}`);
  assert.equal(existsSync(output), false);
  const pilot = spawn(
    process.execPath,
    [
      resolve(process.cwd(), "conformance/production-diff/pilot.mjs"),
      "replay",
      "--case",
      "fs.g0.saved-68012694.v1",
      "--binary",
      process.env.G0_RETAINED_ARTIFACT,
      "--out",
      output,
      "--timeout",
      "600",
    ],
    { cwd: process.cwd(), env: process.env, stdio: ["ignore", "ignore", "pipe"] },
  );
  let stderrBytes = 0;
  let stderrTruncated = false;
  pilot.stderr.on("data", (chunk) => {
    stderrBytes += chunk.length;
    if (stderrBytes > 64 * 1024) stderrTruncated = true;
  });
  const exitCode = await new Promise((resolveExit) => pilot.once("close", resolveExit));
  assert.equal(exitCode, 0, `native G0 replay failed; retained output: ${output}; stderrBytes=${stderrBytes}; stderrTruncated=${stderrTruncated}`);
  const batch = JSON.parse(readFileSync(join(output, "batch", "result.json"), "utf8"));
  assert.equal(batch.completed, true);
  const jobs = Object.values(batch.jobs);
  assert.equal(jobs.reduce((total, result) => total + result.rows.length, 0), 12);
  assert.equal(jobs.reduce((total, result) => total + result.cleanup.length, 0), 12);
  assert.equal(new Set(Object.values(batch.gate.jobs).flatMap((job) => job.absent)).size, 4);
});

test("G0 session binds validated origins before the real Gate and Adapter are constructed", () => {
  const directory = mkdtempSync(join(tmpdir(), "g0-binding-"));
  const script = `
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
sys.path.insert(0, str(root / "tools/compat-broad"))
from batch_adapter import Adapter, observer_digest
from batch_contract import candidate
from shared_gate import Gate, create
from shared_production_pair import frozen_g0_manifest

nonce = "68012694f81df504600f8e67301410c6"
origins = {"firestore": "http://127.0.0.1:18080", "auth": "http://127.0.0.1:19090"}
plan = frozen_g0_manifest(nonce)
plan["observerSha256"] = observer_digest()
plan["localOrigins"] = origins
create(out / "gate", plan)
adapter = Adapter(candidate(), nonce, out / "adapter", local_origins=origins)
adapter.shared_gate = Gate(out / "gate", "partial")
assert adapter.shared_gate.snapshot()["plan"]["localOrigins"] == origins

for mutation in ("origin", "nonce", "observer"):
    gate_path = out / ("gate-" + mutation)
    gate_plan = dict(plan)
    if mutation == "observer":
        gate_plan["observerSha256"] = "f" * 64
    create(gate_path, gate_plan)
    adapter = Adapter(candidate(), nonce, out / ("adapter-" + mutation), local_origins=origins)
    adapter.shared_gate = Gate(gate_path, "partial")
    adapter.shared_gate.claim()
    if mutation == "origin":
        adapter.local = {"firestore": origins["firestore"], "auth": "http://127.0.0.1:19091"}
    elif mutation == "nonce":
        adapter.nonce = "0" * 32
    called = []
    try:
        adapter.shared_gate.adapter_request(
            adapter,
            gate_plan["jobs"]["partial"]["observation"][0],
            lambda: (called.append(True), (404, {"error": {"code": 404, "status": "NOT_FOUND"}}))[1],
        )
    except ValueError as error:
        assert str(error) == "adapter origin/nonce/observer binding mismatch"
    else:
        raise AssertionError(mutation + " binding was accepted")
print("binding-ok")
`;
  try {
    const output = execFileSync(
      "uv",
      ["run", "python", "-c", script, process.cwd(), directory],
      { cwd: process.cwd(), encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    );
    assert.equal(output.trim(), "binding-ok");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("session verification binds the prepared canonical program, not its runtime-enriched clone", () => {
  const prepared = { jobs: { partial: { observation: [] } }, nonce: "a".repeat(32) };
  const canonical = digestJson(prepared);
  verifyG0ProgramDigest(canonical, prepared);
  const runtimePlan = { ...prepared, localOrigins: { firestore: "127.0.0.1:18080" } };
  assert.notEqual(digestJson(runtimePlan), canonical);
  assert.throws(() => verifyG0ProgramDigest(digestJson(runtimePlan), prepared), /local-record-binding/);
  assert.throws(() => verifyG0ProgramDigest("0".repeat(64), prepared), /local-record-binding/);
});
