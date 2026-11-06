import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import {
  endpoint,
  verifyResources,
  verifyIdentity,
  compareFixture,
  verifyDigest,
  boundedRequest,
  readyService,
  command,
  readyQuery,
  verifyBuild,
} from "./run.mjs";

test("only an explicit loopback HTTP endpoint can reach the SDK", () => {
  for (const value of [
    "https://example.com:9399",
    "http://example.com:9399",
    "http://127.0.0.1:9399/x",
    "http://user@127.0.0.1:9399",
    "http://127.0.0.1:9399?x",
    "http://127.0.0.1:9399#x",
  ]) {
    assert.throws(() => endpoint(value), /loopback/);
  }
  assert.equal(endpoint("http://127.0.0.1:9399").hostname, "127.0.0.1");
  assert.equal(endpoint("http://[::1]:9399").hostname, "[::1]");
});

test("effective cgroups must enforce the full resource contract", () => {
  const good = { memory: "4294967296", swap: "0", pids: "256" };
  verifyResources(good);
  for (const [key, value] of [
    ["memory", "max"],
    ["memory", "8589934592"],
    ["swap", "max"],
    ["swap", "1"],
    ["pids", "max"],
  ]) {
    assert.throws(() => verifyResources({ ...good, [key]: value }), /resource/);
  }
});

test("cleanup requires exact container ID and ownership label", () => {
  const id = "a".repeat(64);
  verifyIdentity(
    { Id: id, Config: { Labels: { "fireemu.dataconnect.run": "run-one" } } },
    id,
    "run-one",
  );
  for (const actual of [
    { Id: "b".repeat(64), Config: { Labels: { "fireemu.dataconnect.run": "run-one" } } },
    { Id: id, Config: { Labels: { "fireemu.dataconnect.run": "run-two" } } },
    { Id: id },
  ]) {
    assert.throws(() => verifyIdentity(actual, id, "run-one"), /ownership/);
  }
});

test("fixture comparison detects changed data and missing or duplicated cases", () => {
  const expected = [
    { id: "empty", data: [] },
    { id: "insert", data: { id: "synthetic" } },
  ];
  compareFixture(expected, structuredClone(expected));
  for (const actual of [
    expected.slice(1),
    [...expected, expected[0]],
    [{ id: "empty", data: [1] }, expected[1]],
    expected.toReversed(),
  ]) {
    assert.throws(() => compareFixture(expected, actual), /fixture/);
  }
});

test("a missing or changed artifact cannot pass checksum validation", () => {
  const bytes = Buffer.from("synthetic artifact");
  const hash = createHash("sha256").update(bytes).digest("hex");
  verifyDigest(bytes, hash);
  assert.throws(() => verifyDigest(Buffer.from("changed"), hash), /checksum/);
  assert.throws(() => verifyDigest(bytes, undefined), /checksum/);
});

test("a stalled request fails within its deadline instead of becoming an expected server error", async () => {
  const observed = await Promise.race([
    boundedRequest(new Promise(() => {}), 5).catch((error) => error.code),
    new Promise((resolve) => setTimeout(() => resolve("missing deadline"), 30)),
  ]);
  assert.equal(observed, "FIXTURE_TIMEOUT");
  assert.equal(await boundedRequest(Promise.resolve(7), 5), 7);
});

test("the executable entry can load the corpus without a module evaluation deadlock", () => {
  const result = spawnSync(
    process.execPath,
    [fileURLToPath(new URL("./run.mjs", import.meta.url)), "--check-corpus"],
    { encoding: "utf8", timeout: 5000 },
  );
  assert.equal(result.status, 0, `entry failed: ${result.error?.message ?? result.stderr}`);
  assert.match(result.stdout, /corpus module ready/);
});

test("a loaded schema is not ready until its PostgreSQL connection is configured", () => {
  assert.equal(readyService({ services: [{ serviceId: "fixture" }] }), false);
  assert.equal(
    readyService({ services: [{ serviceId: "other", connectionString: "local" }] }),
    false,
  );
  assert.equal(
    readyService({ services: [{ serviceId: "fixture", connectionString: "local" }] }),
    true,
  );
});

test("diagnostic capture retains stderr from container logs", () => {
  const text = command(
    process.execPath,
    ["-e", "console.log('out'); console.error('diagnostic');"],
    { includeStderr: true },
  );
  assert.match(text, /out/);
  assert.match(text, /diagnostic/);
});

test("readiness retries only the exact recorded missing-schema response", () => {
  assert.equal(readyQuery(200, { data: { items: [] } }), true);
  const body = {
    code: 5,
    message: 'no schema found for service "fixture". No service has a schema.',
    details: [],
  };
  assert.equal(readyQuery(404, body), false);
  for (const [status, answer] of [
    [503, body],
    [404, { ...body, code: 14 }],
    [404, { ...body, message: "different failure" }],
    [200, { data: {} }],
    [400, body],
  ]) {
    assert.throws(() => readyQuery(status, answer), /readiness/);
  }
});

test("local toolkit build errors are fatal even when the process exits zero", () => {
  verifyBuild({ status: 0, stdout: '{"metadata":{}}' });
  for (const result of [
    { status: 1, stdout: "{}" },
    { status: 0, stdout: '{"errors":[{"message":"invalid schema"}]}' },
    { status: 0, stdout: "not json" },
    { status: null, stdout: "{}", error: new Error("timeout") },
  ]) {
    assert.throws(() => verifyBuild(result), /build/);
  }
});
