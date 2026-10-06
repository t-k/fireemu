import assert from "node:assert/strict";
import test from "node:test";
import * as iam from "./pubsub-production/iam.mjs";
import { plannedRequests, selectCases } from "./pubsub-production/runner.mjs";
import { createPhaseLimit } from "./pubsub-production/limits.mjs";

const principal = "serviceAccount:service-123456789012@gcp-sa-pubsub.iam.gserviceaccount.com";
const role = "roles/pubsub.subscriber";
const resource = "projects/demo-v2/subscriptions/fe0123456789ab-da-r-source";
const complete = (body) => ({ ok: true, code: "OK", status: 200, unknown: false, body });

test("v2 actual plan has228 requests22resources and approved900/1800window", () => {
  const cases = selectCases(undefined, "stream-dlq-v2");
  assert.equal(plannedRequests(cases), 228);
  assert.equal(
    cases.reduce((sum, item) => sum + item.resources, 0),
    22,
  );
  assert.equal(cases.find((item) => item.id === "dlq-grant-window").timeoutMs, 1_800_000);
  assert.equal(iam.IAM_WAIT_MS, 900_000);
  assert.equal(iam.IAM_CONVERGENCE_CLAIM, false);
  assert.equal(cases.find((item) => item.id === "rest-layout-routes").requests, 9);
});

test("policy edits preserve unrelated conditional bindings and fresh etag across generated policies", () => {
  for (let seed = 0; seed < 128; seed += 1) {
    const before = {
      version: 3,
      etag: `etag-${seed}`,
      bindings: [
        { role, members: [`user:other-${seed}@example.com`] },
        {
          role,
          members: [principal],
          condition: { title: `condition-${seed}`, expression: "false" },
        },
        { role: "roles/viewer", members: [`group:others-${seed}@example.com`] },
      ],
    };
    const saved = structuredClone(before);
    const { policy, added } = iam.addOwnBinding(before, role, principal);
    assert.equal(added, true);
    assert.deepEqual(before, saved);
    assert.equal(policy.etag, before.etag);
    assert.deepEqual(policy.bindings[1], before.bindings[1]);
    policy.etag = `fresh-${seed}`;
    policy.bindings.push({ role: "roles/editor", members: ["user:concurrent@example.com"] });
    const restored = iam.removeOwnBinding(policy, role, principal);
    assert.equal(restored.etag, policy.etag);
    assert.deepEqual(restored.bindings, [...before.bindings, policy.bindings.at(-1)]);
    assert.equal(
      iam.addOwnBinding({ ...before, bindings: [{ role, members: [principal] }] }, role, principal)
        .added,
      false,
    );
  }
  for (const bad of [
    {},
    { etag: "" },
    { etag: "x", bindings: "bad" },
    { etag: "x", bindings: [{ role, members: [42] }] },
  ])
    assert.throws(() => iam.addOwnBinding(bad, role, principal), /policy/);
});

test("grant intent is durable before set and restore uses current etag before resources delete", async () => {
  let policy = { version: 3, etag: "before", bindings: [] };
  const journal = [];
  const sent = [];
  const manager = iam.createIamOwnership({
    journal: { write: (row) => journal.push(row) },
    assertOwned: (name) => assert.equal(name, resource),
  });
  const client = {
    async getIamPolicy() {
      sent.push("get");
      return complete(structuredClone(policy));
    },
    async setIamPolicy(name, next) {
      assert.equal(name, resource);
      assert.equal(journal.at(-1).phase, sent.length === 1 ? "grant-intent" : "restore-intent");
      assert.equal(next.etag, policy.etag);
      sent.push("set");
      policy = { ...structuredClone(next), etag: `${policy.etag}-new` };
      return complete(structuredClone(policy));
    },
  };
  await manager.grant(client, resource, role, principal);
  assert.deepEqual(sent, ["get", "set", "get"]);
  policy.bindings.push({ role: "roles/viewer", members: ["user:other@example.com"] });
  const report = await manager.restore(client);
  assert.deepEqual(report.unsettled, []);
  assert.deepEqual(sent, ["get", "set", "get", "get", "set", "get"]);
  assert.deepEqual(policy.bindings, [
    { role: "roles/viewer", members: ["user:other@example.com"] },
  ]);
});

test("ambiguous grant or restore is sticky without retries and prevents closure", async () => {
  for (const status of [199, 302, 503, 499, null]) {
    const journal = [];
    let writes = 0;
    const manager = iam.createIamOwnership({
      journal: { write: (row) => journal.push(row) },
      assertOwned() {},
    });
    const client = {
      async getIamPolicy() {
        return complete({ etag: "etag", bindings: [] });
      },
      async setIamPolicy() {
        writes += 1;
        return { status, ok: false, code: "UNKNOWN", unknown: true };
      },
    };
    await assert.rejects(manager.grant(client, resource, role, principal), /grant/);
    const report = await manager.restore(client);
    assert.equal(writes, 1);
    assert.equal(report.unsettled.length, 1);
    assert.equal(journal[0].phase, "grant-intent");
  }
});

test("IAM wait uses aged monotonic time and zero requests until900seconds after last grant", async () => {
  for (const age of [0, 3_600_000]) {
    let now = age;
    const phase = createPhaseLimit(1_800_000, () => now);
    phase.remaining();
    let requests = 0;
    await iam.waitAfterLastGrant({
      grantedAt: now,
      now: () => now,
      sleep: phase.sleep(async (ms) => {
        assert.equal(requests, 0);
        now += ms;
      }),
    });
    assert.equal(now - age, 900_000);
    requests += 1;
    assert.equal(requests, 1);
    assert.equal(phase.remaining(), 900_000);
  }
});

test("IAM replay of unanswered intent never resends a grant or restoration", async () => {
  for (const phase of ["grant-intent", "restore-intent"]) {
    const before = { etag: "before", bindings: [] };
    const requested = iam.addOwnBinding(before, role, principal).policy;
    const proof = complete({ ...requested, etag: "after" });
    const replay = [
      { phase: "grant-intent", resource, role, principal, before, requested },
      ...(phase === "restore-intent"
        ? [
            { phase: "grant-confirmed", resource, setAnswer: proof, readback: proof },
            {
              phase,
              resource,
              before: proof.body,
              requested: iam.removeOwnBinding(proof.body, role, principal),
            },
          ]
        : []),
    ];
    const manager = iam.createIamOwnership({ journal: { write() {} }, assertOwned() {}, replay });
    let calls = 0;
    const report = await manager.restore({
      async getIamPolicy() {
        calls += 1;
      },
      async setIamPolicy() {
        calls += 1;
      },
    });
    assert.equal(calls, 0);
    assert.equal(report.unsettled.length, 1);
  }
});

test("IAM restore unknown answer stays sticky after a later clean policy read", async () => {
  let policy = { etag: "start", bindings: [] };
  let restore = false;
  let sets = 0;
  const manager = iam.createIamOwnership({ journal: { write() {} }, assertOwned() {} });
  const client = {
    async getIamPolicy() {
      return complete(structuredClone(policy));
    },
    async setIamPolicy(_name, next) {
      sets += 1;
      policy = { ...next, etag: "changed" };
      return restore ? { unknown: true, ok: false, status: 503 } : complete(policy);
    },
  };
  await manager.grant(client, resource, role, principal);
  restore = true;
  assert.equal((await manager.restore(client)).unsettled.length, 1);
  assert.equal((await manager.restore(client)).unsettled.length, 1);
  assert.equal(sets, 2);
});

test("actual v2 prepare defaults to228source22resources and never constructs a credential provider", async () => {
  const record = await import("./pubsub-production/record.mjs");
  let output = "";
  let error = "";
  const code = await record.main(
    [
      "--target",
      "production",
      "--project",
      "demo-v2",
      "--out",
      "/unused",
      "--suite",
      "stream-dlq-v2",
      "--prepare",
    ],
    {},
    { stdout: { write: (text) => (output += text) }, stderr: { write: (text) => (error += text) } },
    { now: Date.now, noWire: true },
  );
  assert.equal(code, 0, error);
  const value = JSON.parse(output);
  assert.equal(value.requests, 228);
  assert.equal(value.resources, 22);
  assert.equal(value.noWire, true);
  assert.equal(value.iamWaitAfterGrantMs, 900_000);
  assert.equal(value.iamConvergenceClaim, false);
});

test("actual default v2 production path rejects absent source-bound authority before no-wire guard", async () => {
  const record = await import("./pubsub-production/record.mjs");
  let error = "";
  const code = await record.main(
    [
      "--target",
      "production",
      "--project",
      "demo-v2",
      "--out",
      "/unused",
      "--suite",
      "stream-dlq-v2",
    ],
    {},
    { stdout: { write() {} }, stderr: { write: (text) => (error += text) } },
    { now: Date.now, noWire: true },
  );
  assert.equal(code, 2);
  assert.match(error, /descriptor|authority/);
});

test("v2 default admission rejects duplicate transports and excess source budget", async () => {
  const record = await import("./pubsub-production/record.mjs");
  for (const extra of [
    ["--transports", "rest,rest,grpc"],
    ["--max-requests", "1026"],
  ]) {
    let error = "";
    const code = await record.main(
      [
        "--target",
        "production",
        "--project",
        "demo-v2",
        "--out",
        "/unused",
        "--suite",
        "stream-dlq-v2",
        "--prepare",
        ...extra,
      ],
      {},
      { stdout: { write() {} }, stderr: { write: (text) => (error += text) } },
      { now: Date.now, noWire: true },
    );
    assert.equal(code, 2);
    assert.match(error, /transport|228/);
  }
});

async function recordedWorld({ emptyLayout = false, ambiguousGrant = false, age = 0 } = {}) {
  const { readFileSync } = await import("node:fs");
  const { createRest } = await import("./pubsub-production/rest.mjs");
  const { createCapture, createBudget } = await import("./pubsub-production/capture.mjs");
  const { createClient, newPushState } = await import("./pubsub-production/client.mjs");
  const { createOwnership } = await import("./pubsub-production/names.mjs");
  const { createLedger } = await import("./pubsub-production/ledger.mjs");
  const fixtures = JSON.parse(
    readFileSync(new URL("./pubsub-production/fixtures/recorded-v2-routes.json", import.meta.url)),
  );
  const prototype = (op) => structuredClone(fixtures.find((item) => item.op === op).response.body);
  const live = new Map();
  const policies = new Map();
  const requests = [];
  const lines = [];
  const sleeps = [];
  let now = age;
  const ownership = createOwnership({ project: "demo-v2", runId: "0123456789ab" });
  const ledger = createLedger();
  const pushState = newPushState();
  const capture = createCapture({ journal: { write: (line) => lines.push(line) } });
  const rest = createRest({
    base: "http://127.0.0.1:1",
    journalDispatch: true,
    budget: createBudget(828),
    capture,
    fetchImpl: async (url, options) => {
      const parsed = new URL(url);
      const path = decodeURIComponent(parsed.pathname.slice(4));
      const body = options.body === undefined ? undefined : JSON.parse(options.body);
      requests.push({ path, method: options.method, body, at: now, query: parsed.search });
      let value = {};
      let status = 200;
      if (path.endsWith(":getIamPolicy")) {
        assert.equal(parsed.searchParams.get("options.requestedPolicyVersion"), "3");
        value = structuredClone(
          policies.get(path.split(":")[0]) ?? { etag: "empty-policy-etag", bindings: [] },
        );
      } else if (path.endsWith(":setIamPolicy")) {
        const key = path.split(":")[0];
        assert.equal(body.policy.etag, (policies.get(key) ?? { etag: "empty-policy-etag" }).etag);
        value = { ...body.policy, etag: `${body.policy.etag}-new` };
        policies.set(key, structuredClone(value));
        if (ambiguousGrant) {
          status = 503;
          value = { error: { status: "UNAVAILABLE" } };
        }
      } else if (options.method === "PUT") {
        const op = path.includes("/subscriptions/")
          ? "createSubscription"
          : path.includes("/snapshots/")
            ? "createSnapshot"
            : "createTopic";
        if (op === "createSubscription") assert.equal(typeof body.topic, "string");
        if (op === "createSnapshot") assert.equal(typeof body.subscription, "string");
        value = { ...prototype(op), name: path, ...body };
        live.set(path, value);
      } else if (options.method === "DELETE") {
        assert.equal(
          (policies.get(path)?.bindings ?? []).some((b) => b.members.includes(principal)),
          false,
          "IAM must restore before DELETE",
        );
        live.delete(path);
      } else if (path.endsWith(":publish")) {
        assert.equal(body.messages.length, 1);
        assert.equal(typeof body.messages[0].data, "string");
        value = { messageIds: ["demo-published-id"] };
      } else if (path.endsWith(":pull")) {
        assert.equal(body.maxMessages, 1);
        value = emptyLayout && path.includes("-rl-r-") ? {} : prototype("pull");
        assert.ok(Array.isArray(value.receivedMessages) || Object.keys(value).length === 0);
      } else if (path.endsWith(":acknowledge") || path.endsWith(":modifyAckDeadline")) {
        assert.ok(body.ackIds.length > 0);
        assert.ok(body.ackIds.every((id) => typeof id === "string" && id.length));
      } else if (path.endsWith(":seek")) {
        assert.equal(typeof body.snapshot, "string");
        assert.equal(body.time, undefined);
      } else if (/\/(topics|subscriptions|snapshots)$/.test(path)) {
        const kind = path.split("/").at(-1);
        const values = [...live.values()].filter((item) => item.name.includes(`/${kind}/`));
        value =
          kind === "snapshots" && values.length === 0
            ? prototype("listSnapshots")
            : { [kind]: values };
        if (parsed.searchParams.get("pageSize") === "1")
          value = { topics: values.slice(0, 1), nextPageToken: "safe-own-cursor" };
      } else {
        value = live.get(path);
        if (!value) {
          status = 404;
          value = prototype("getTopic");
        }
      }
      const text = `\n ${JSON.stringify(value, null, 2)}\n`;
      return new Response(text, {
        status,
        headers: { "content-length": String(Buffer.byteLength(text)) },
      });
    },
  });
  const grpc = {
    name: "grpc",
    async call({ label, op, service, method, request }) {
      const body = { ...request };
      if (request.name) live.set(request.name, body);
      capture.record({
        ...label,
        transport: "grpc",
        op,
        request: { rpc: `${service}/${method}`, body: request },
        response: { code: "OK", body },
      });
      return { code: "OK", body, unknown: false };
    },
    async stream({ label, frames, afterReceive }) {
      capture.record({
        ...label,
        transport: "grpc",
        op: "streamingPull",
        response: { code: "INVALID_ARGUMENT" },
      });
      return {
        code: "INVALID_ARGUMENT",
        unknown: false,
        outboundFrames: frames.length,
        followUpSent: afterReceive !== undefined,
      };
    },
  };
  const manager = iam.createIamOwnership({
    journal: { write: (row) => lines.push({ iam: row }) },
    assertOwned: (name) => ownership.assertOwned(name),
    now: () => now,
  });
  const cleanupRest = createClient({
    transport: rest,
    ownership,
    pushState,
    ledger,
    caseId: "cleanup",
  });
  return {
    requests,
    lines,
    sleeps,
    live,
    policies,
    ownership,
    ledger,
    capture,
    pushState,
    cleanupRest,
    transports: { rest, grpc },
    options: {
      suite: "stream-dlq-v2",
      production: true,
      serviceAgent: principal,
      iam: manager,
      monotonicNow: () => now,
    },
    sleep: async (ms) => {
      sleeps.push({ ms, at: now, requests: requests.length });
      now += ms;
    },
  };
}

test("actual v2 runner restores two policies before cleanup and emits physical layout on four routes", async () => {
  const { runCases } = await import("./pubsub-production/runner.mjs");
  const fixture = await recordedWorld({ age: 3_600_000 });
  const summary = await runCases({
    ...fixture,
    cases: selectCases(["rest-layout-routes", "dlq-grant-window"], "stream-dlq-v2"),
  });
  assert.deepEqual(
    summary.cases.map((entry) => entry.outcome),
    ["completed", "completed"],
  );
  assert.equal(summary.iam.restored.length, 2);
  assert.deepEqual(summary.iam.unsettled, []);
  assert.deepEqual(summary.cleanup.errors, []);
  assert.ok(fixture.sleeps.some((item) => item.ms === 900_000));
  assert.equal(fixture.sleeps.find((item) => item.ms === 900_000).requests, 18);
  const wait = fixture.sleeps.find((item) => item.ms === 900_000);
  assert.equal(fixture.requests.find((call) => call.at > wait.at).at, wait.at + 900_000);
  const rows = fixture.lines.filter(
    (line) =>
      line.case === "rest-layout-routes/rest" &&
      line.transport === "rest" &&
      line.response !== undefined,
  );
  for (const op of ["createSubscription", "pull", "acknowledge", "seek"]) {
    const row = rows.find((item) => item.op === op);
    assert.ok(row);
    assert.equal(Number(row.response.contentLength), row.response.bodyBytes);
    assert.ok(row.response.bodyBytes > Buffer.byteLength(JSON.stringify(row.response.body)));
  }
  assert.ok(
    fixture.requests
      .filter((call) => call.path.endsWith(":getIamPolicy"))
      .every((call) => call.query.includes("requestedPolicyVersion=3")),
  );
});

test("layout with no real received ACK records an aborted unmet observation without fabricated ACK or Seek", async () => {
  const { runCases } = await import("./pubsub-production/runner.mjs");
  const fixture = await recordedWorld({ emptyLayout: true });
  const summary = await runCases({
    ...fixture,
    cases: selectCases(["rest-layout-routes"], "stream-dlq-v2"),
  });
  assert.equal(summary.cases[0].outcome, "aborted");
  assert.equal(fixture.requests.filter((call) => call.path.endsWith(":pull")).length, 3);
  assert.equal(fixture.requests.filter((call) => /:(acknowledge|seek)$/.test(call.path)).length, 0);
});

test("actual ambiguous IAM write blocks its resource DELETE and run closure without resend", async () => {
  const { runCases } = await import("./pubsub-production/runner.mjs");
  const fixture = await recordedWorld({ ambiguousGrant: true });
  const summary = await runCases({
    ...fixture,
    cases: selectCases(["dlq-grant-window"], "stream-dlq-v2"),
  });
  assert.equal(summary.iam.unsettled.length, 1);
  assert.equal(fixture.requests.filter((call) => call.path.endsWith(":setIamPolicy")).length, 1);
  assert.ok(summary.cleanup.errors.some((error) => error.includes("IAM")));
  assert.ok(summary.cleanup.leftover.includes(summary.iam.unsettled[0].resource));
  assert.equal(
    fixture.requests.filter(
      (call) => call.method === "DELETE" && call.path === summary.iam.unsettled[0].resource,
    ).length,
    0,
  );
});

test("IAM replay refuses invented confirmation, reordered phases and altered ownership", () => {
  const before = { etag: "before", bindings: [] };
  const requested = iam.addOwnBinding(before, role, principal).policy;
  const intent = { phase: "grant-intent", resource, role, principal, before, requested };
  for (const replay of [
    [intent, { phase: "restore-confirmed", resource }],
    [intent, { phase: "grant-confirmed", resource }],
    [{ ...intent, role: "roles/owner" }],
    [{ ...intent, principal: "user:other@example.com" }],
    [{ ...intent, before: requested }],
    [intent, intent],
  ])
    assert.throws(
      () => iam.createIamOwnership({ journal: { write() {} }, assertOwned() {}, replay }),
      /IAM|grant|proof|transition|intent|scope/,
    );
});

test("IAM wait rejects nonfinite clock before considering the wait complete", async () => {
  for (const value of [NaN, Infinity, -Infinity])
    await assert.rejects(
      iam.waitAfterLastGrant({ grantedAt: 0, now: () => value, sleep: async () => {} }),
      /clock/,
    );
});

test("actual A2 v2 capture rejects omitted or wrong suite before a marker, credentials or transport", async () => {
  const { mkdtempSync, writeFileSync, existsSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const record = await import("./pubsub-production/record.mjs");
  const out = mkdtempSync(join(tmpdir(), "v2-recovery-"));
  const runId = "0123456789ab";
  const path = join(out, `capture-${runId}.jsonl`);
  writeFileSync(
    path,
    JSON.stringify({
      at: "2026-01-01T00:00:00Z",
      note: "run-start",
      suite: "stream-dlq-v2",
      project: "demo-v2",
      runId,
    }) + "\n",
  );
  writeFileSync(join(out, `issued-${runId}.jsonl`), "");
  writeFileSync(join(out, `iam-${runId}.jsonl`), "");
  try {
    for (const extra of [[], ["--suite", "unary"]]) {
      let error = "";
      const code = await record
        .main(
          [
            "--target",
            "production",
            "--project",
            "demo-v2",
            "--out",
            out,
            "--cleanup-only",
            "--run-id",
            runId,
            "--from-capture",
            path,
            ...extra,
          ],
          {},
          { stdout: { write() {} }, stderr: { write: (text) => (error += text) } },
          { now: Date.now, noWire: true },
        )
        .catch((error) => assert.fail(`preflight escaped: ${error.message}`));
      assert.equal(code, 2);
      assert.match(error, /suite|v2/);
      assert.equal(existsSync(join(out, `a2-started-${runId}.json`)), false);
    }
  } finally {
    rmSync(out, { recursive: true });
  }
});

test("actual runtime identity binds installed dependency trees and refuses preload execution", async () => {
  const { execFileSync, spawnSync } = await import("node:child_process");
  const { fileURLToPath } = await import("node:url");
  const path = fileURLToPath(
    new URL("./pubsub-production/fixtures/v2-runtime-probe.mjs", import.meta.url),
  );
  const env = { ...process.env, NODE_OPTIONS: "", NODE_PATH: "" };
  const identity = JSON.parse(execFileSync(process.execPath, [path], { env, timeout: 15_000 }));
  assert.ok(Array.isArray(identity.dependencies));
  assert.ok(identity.dependencies.length > 20);
  assert.ok(identity.dependencies.every((pin) => /^[a-f0-9]{64}$/.test(pin.treeSha256)));
  const bad = spawnSync(process.execPath, [path, "preload"], {
    env,
    timeout: 15_000,
    encoding: "utf8",
  });
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /preload|runtime/);
});

test("IAM durable prefixes agree with bounded reference states and reject corrupted proofs", async () => {
  for (let seed = 0; seed < 24; seed += 1) {
    let policy = {
      etag: `e-${seed}`,
      bindings: [{ role: "roles/viewer", members: [`user:s${seed}@example.com`] }],
    };
    const rows = [];
    const journal = { write: (row) => rows.push(structuredClone(row)) };
    const manager = iam.createIamOwnership({ journal, assertOwned() {} });
    const client = {
      async getIamPolicy() {
        return complete(structuredClone(policy));
      },
      async setIamPolicy(_name, next) {
        policy = { ...next, etag: `${policy.etag}-next` };
        return complete(structuredClone(policy));
      },
    };
    await manager.grant(client, resource, role, principal);
    await manager.restore(client);
    assert.deepEqual(
      rows.map((row) => row.phase),
      ["grant-intent", "grant-confirmed", "restore-intent", "restore-confirmed"],
    );
    const expected = ["grant-unknown", "granted", "restore-unknown", null];
    for (let length = 1; length <= rows.length; length += 1) {
      const loaded = iam.createIamOwnership({
        journal: { write() {} },
        assertOwned() {},
        replay: rows.slice(0, length),
      });
      assert.equal(loaded.outstanding()[0]?.state ?? null, expected[length - 1]);
    }
    for (const index of [1, 3]) {
      const corrupted = structuredClone(rows);
      delete corrupted[index].readback;
      assert.throws(
        () =>
          iam.createIamOwnership({ journal: { write() {} }, assertOwned() {}, replay: corrupted }),
        /proof|transition/,
      );
    }
    const restarted = [rows[0], { phase: "grant-unknown", resource }, rows[1]];
    assert.throws(
      () =>
        iam.createIamOwnership({ journal: { write() {} }, assertOwned() {}, replay: restarted }),
      /transition/,
    );
  }
});

test("IAM rejects a success label without a complete REST200 policy", async () => {
  for (const status of [undefined, null, "200", 201, 204, 302]) {
    let writes = 0;
    const manager = iam.createIamOwnership({ journal: { write() {} }, assertOwned() {} });
    const client = {
      async getIamPolicy() {
        return { ...complete({ etag: "e", bindings: [] }), status };
      },
      async setIamPolicy() {
        writes += 1;
      },
    };
    await assert.rejects(manager.grant(client, resource, role, principal), /read/);
    assert.equal(writes, 0);
  }
});

test("v2 full packet rejects partial case and transport selection", async () => {
  const { parseArgs } = await import("./pubsub-production/record.mjs");
  const base = [
    "--target",
    "production",
    "--project",
    "demo-v2",
    "--out",
    "/unused",
    "--suite",
    "stream-dlq-v2",
  ];
  for (const extra of [
    ["--only", "rest-layout-routes"],
    ["--transports", "rest"],
    ["--transports", ""],
  ])
    assert.throws(() => parseArgs([...base, ...extra]), /v2|packet|transports/);
});

test("v2 recovery validates IAM intent proofs before any authority or marker", async () => {
  const { mkdtempSync, writeFileSync, existsSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { main } = await import("./pubsub-production/record.mjs");
  const out = mkdtempSync(join(tmpdir(), "v2-proof-"));
  const runId = "0123456789ab";
  const capture = join(out, `capture-${runId}.jsonl`);
  writeFileSync(
    capture,
    JSON.stringify({
      at: "2026-01-01T00:00:00Z",
      note: "run-start",
      suite: "stream-dlq-v2",
      project: "demo-v2",
      runId,
    }) + "\n",
  );
  writeFileSync(join(out, `issued-${runId}.jsonl`), "");
  writeFileSync(
    join(out, `iam-${runId}.jsonl`),
    JSON.stringify({ phase: "restore-confirmed", resource }) + "\n",
  );
  try {
    let error = "";
    assert.equal(
      await main(
        [
          "--target",
          "production",
          "--project",
          "demo-v2",
          "--out",
          out,
          "--suite",
          "stream-dlq-v2",
          "--cleanup-only",
          "--run-id",
          runId,
          "--from-capture",
          capture,
        ],
        {},
        { stdout: { write() {} }, stderr: { write: (text) => (error += text) } },
        { now: Date.now, noWire: true },
      ),
      2,
    );
    assert.match(error, /IAM answer without owned intent/);
    assert.equal(existsSync(join(out, `a2-started-${runId}.json`)), false);
  } finally {
    rmSync(out, { recursive: true });
  }
});

test("authority checks actual proof hashes and full E/V scope before demanding a live canonical lock", async () => {
  const { mkdtempSync, writeFileSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { verifyAuthority, sha256 } = await import("./pubsub-production/admission.mjs");
  const out = mkdtempSync(join(tmpdir(), "v2-authority-"));
  const put = (name, value) => {
    const bytes = JSON.stringify(value);
    const path = join(out, `${name}.json`);
    writeFileSync(path, bytes);
    return { path, sha256: sha256(bytes) };
  };
  const descriptor = { head: "a".repeat(40) };
  const digest = "b".repeat(64);
  const packet = put("packet", { taskId: "PUBSUB-STREAM-DLQ", suite: "stream-dlq-v2" });
  const options = { project: "demo-v2", runId: "0123456789ab", serviceAgent: principal, out };
  const authority = {
    schema: 1,
    taskId: "PUBSUB-STREAM-DLQ",
    suite: "stream-dlq-v2",
    envelopeId: "PUBSUB-STREAM-DLQ-V2",
    sourceHead: descriptor.head,
    descriptorSha256: digest,
    packetPath: packet.path,
    packetSha256: packet.sha256,
    project: options.project,
    runIds: [options.runId, "0123456789ac"],
    runOutputs: { [options.runId]: out, "0123456789ac": join(out, "second") },
    expiresAt: "2099-01-01T00:00:00Z",
    iamWaitAfterGrantMs: 900_000,
    iamPhaseMs: 1_800_000,
    iamConvergenceClaim: false,
    maxRequestsPerAttempt: 228,
    cleanupRequests: 600,
    a2Requests: 600,
    serviceAgent: principal,
    lockPath: join(out, "copied-lock.json"),
    lockFd: 17,
  };
  const row = (kind) => ({
    kind,
    state: "APPROVED",
    taskId: authority.taskId,
    envelopeId: authority.envelopeId,
    sourceHead: authority.sourceHead,
    descriptorSha256: digest,
    packetSha256: packet.sha256,
    project: authority.project,
    runIds: authority.runIds,
    runOutputs: authority.runOutputs,
    expiresAt: authority.expiresAt,
    maxRequestsPerAttempt: 228,
    cleanupRequests: 600,
    a2Requests: 600,
  });
  authority.E = put("E", row("E"));
  authority.V = put("V", row("V"));
  authority.inheritedGrantAudit = {
    ...put("audit", {
      project: options.project,
      serviceAgent: principal,
      noEffectiveGrantB: true,
      envelopeId: authority.envelopeId,
    }),
    noEffectiveGrantB: true,
  };
  try {
    assert.throws(
      () => verifyAuthority(authority, descriptor, digest, options, 0),
      /canonical live lock FD/,
    );
    for (const changes of [
      { envelopeId: undefined },
      { expiresAt: "1970-01-01T00:00:00Z" },
      { runIds: [options.runId, options.runId] },
      { maxRequestsPerAttempt: 229 },
      { iamConvergenceClaim: true },
      { sourceHead: "c".repeat(40) },
      { descriptorSha256: "d".repeat(64) },
    ])
      assert.throws(
        () => verifyAuthority({ ...authority, ...changes }, descriptor, digest, options, 0),
        /authority/,
      );
    for (const kind of ["E", "V"]) {
      for (const changes of [
        { project: "demo-other" },
        { runIds: ["0123456789ad", "0123456789ae"] },
        { expiresAt: "2098-01-01T00:00:00Z" },
        { maxRequestsPerAttempt: 229 },
        { cleanupRequests: 601 },
        { a2Requests: 601 },
        { state: "DRAFT" },
        { envelopeId: "OTHER-ENVELOPE" },
        { sourceHead: "c".repeat(40) },
        { packetSha256: "f".repeat(64) },
      ]) {
        const proof = put(`bad-${kind}`, { ...row(kind), ...changes });
        assert.throws(
          () => verifyAuthority({ ...authority, [kind]: proof }, descriptor, digest, options, 0),
          new RegExp(`${kind} authority proof`),
        );
      }
      assert.throws(
        () =>
          verifyAuthority(
            { ...authority, [kind]: { ...authority[kind], sha256: "0".repeat(64) } },
            descriptor,
            digest,
            options,
            0,
          ),
        /proof mismatch/,
      );
    }
    assert.throws(
      () =>
        verifyAuthority(
          { ...authority, packetSha256: "f".repeat(64) },
          descriptor,
          digest,
          options,
          0,
        ),
      /packet digest/,
    );
    const badAudit = {
      ...put("bad-audit", {
        project: "demo-other",
        serviceAgent: principal,
        noEffectiveGrantB: true,
        envelopeId: authority.envelopeId,
      }),
      noEffectiveGrantB: true,
    };
    assert.throws(
      () =>
        verifyAuthority(
          { ...authority, inheritedGrantAudit: badAudit },
          descriptor,
          digest,
          options,
          0,
        ),
      /audit mismatch/,
    );
  } finally {
    rmSync(out, { recursive: true });
  }
});

test("IAM wait refuses a clock that becomes nonfinite after the initial sample", async () => {
  let calls = 0;
  await assert.rejects(
    iam.waitAfterLastGrant({
      grantedAt: 0,
      now: () => (calls++ === 0 ? 0 : NaN),
      sleep: async () => {},
    }),
    /clock/,
  );
});

test("live lock proof reads the held inode and rejects copies symlinks and wrong envelopes", async () => {
  const { mkdtempSync, writeFileSync, openSync, closeSync, rmSync, symlinkSync } =
    await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { verifyLiveLock } = await import("./pubsub-production/admission.mjs");
  const out = mkdtempSync(join(tmpdir(), "v2-held-inode-"));
  const binding = {
    project: "demo-v2",
    taskId: "PUBSUB-STREAM-DLQ",
    envelopeId: "PUBSUB-STREAM-DLQ-V2",
  };
  const path = join(out, "test-lock.json");
  const copy = join(out, "copy.json");
  const link = join(out, "link.json");
  writeFileSync(path, JSON.stringify(binding), { flag: "wx" });
  writeFileSync(copy, JSON.stringify(binding));
  symlinkSync(path, link);
  const fd = openSync(path, "r");
  const other = openSync(copy, "r");
  try {
    for (let repeat = 0; repeat < 3; repeat += 1)
      assert.deepEqual(verifyLiveLock({ path, fd, expectedPath: path }, binding), binding);
    assert.throws(() => verifyLiveLock({ path, fd: other, expectedPath: path }, binding), /inode/);
    assert.throws(
      () => verifyLiveLock({ path: copy, fd: other, expectedPath: path }, binding),
      /canonical/,
    );
    assert.throws(
      () => verifyLiveLock({ path: link, fd, expectedPath: link }, binding),
      /inode|symlink/,
    );
    assert.throws(
      () =>
        verifyLiveLock(
          { path, fd, expectedPath: path },
          { ...binding, envelopeId: "OTHER-ENVELOPE" },
        ),
      /authority/,
    );
    assert.throws(() => verifyLiveLock({ path, fd: 2, expectedPath: path }, binding), /canonical/);
  } finally {
    closeSync(fd);
    closeSync(other);
    rmSync(out, { recursive: true });
  }
});

test("phase refuses REST unary gRPC and native stream dispatch after credential latency", async () => {
  const { createRest } = await import("./pubsub-production/rest.mjs");
  const { createGrpc } = await import("./pubsub-production/grpc.mjs");
  const grpcLib = (await import("@grpc/grpc-js")).default;
  for (const mode of ["rest", "grpc", "stream"]) {
    let now = 0;
    let sent = 0;
    const phase = createPhaseLimit(1_800_000, () => now);
    phase.remaining();
    now = 1_799_990;
    const getToken = async () => {
      now += 100;
      return "synthetic-token";
    };
    const common = { budget: { consume() {} }, capture: { record() {}, frame() {} }, getToken };
    let transport;
    if (mode === "rest")
      transport = createRest({
        ...common,
        base: "http://127.0.0.1:1",
        fetchImpl: async () => {
          sent += 1;
          return new Response("{}");
        },
      });
    else {
      class Client {
        close() {}
        makeUnaryRequest(_path, _serialize, _deserialize, _body, _metadata, _options, callback) {
          sent += 1;
          callback(null, {});
        }
        makeBidiStreamRequest() {
          sent += 1;
          throw new Error("must not dispatch");
        }
      }
      transport = createGrpc({
        ...common,
        target: "127.0.0.1:1",
        secure: false,
        grpc: { ...grpcLib, Client },
      });
    }
    const guarded = phase.transport(transport);
    try {
      const call =
        mode === "rest"
          ? guarded.request({ method: "GET", path: "/v1/projects/demo-v2/topics/own" })
          : mode === "grpc"
            ? guarded.call({
                service: "Publisher",
                method: "GetTopic",
                request: { topic: "projects/demo-v2/topics/own" },
              })
            : guarded.stream({
                frames: [{ subscription: resource, streamAckDeadlineSeconds: 10 }],
                timeoutMs: 30_000,
              });
      await assert.rejects(call, /phase time budget/);
      assert.equal(sent, 0);
    } finally {
      transport.close?.();
    }
  }
});

test("v2 output binding rejects a run restart in a different directory and an atomic marker refuses reuse", async () => {
  const { tempDir } = await import("./test-tmpdir.mjs");
  const { join } = await import("node:path");
  const { verifyRunOutput, claimSourceRun } = await import("./pubsub-production/admission.mjs");
  const out = tempDir("v2-one-use-");
  const runId = "0123456789ab";
  const authority = { runOutputs: { [runId]: out } };
  assert.doesNotThrow(() => verifyRunOutput(authority, { runId, out }));
  assert.throws(() => verifyRunOutput(authority, { runId, out: join(out, "other") }), /output/);
  claimSourceRun({ out, runId });
  assert.throws(() => claimSourceRun({ out, runId }), /started|EEXIST/);
  assert.throws(
    () =>
      verifyRunOutput(
        { ...authority, cleanupRecovery: { out: join(out, "recovery") } },
        { runId, out, cleanupOnly: true },
      ),
    /output/,
  );
});

test("v2 runner enforces22distinct resources across cases and rechecks phase after final response", async () => {
  const { runCases } = await import("./pubsub-production/runner.mjs");
  const fixture = await recordedWorld();
  const cases = [
    {
      id: "resource-limit",
      short: "zz",
      requests: 0,
      transports: ["rest"],
      async run(ctx) {
        for (let n = 0; n < 23; n += 1) ctx.name("topics", `n${n}`);
      },
    },
  ];
  const limited = await runCases({ ...fixture, cases });
  assert.equal(limited.cases[0].outcome, "limit");
  const expired = await runCases({
    ...(await recordedWorld()),
    options: {
      suite: "stream-dlq-v2",
      monotonicNow: (() => {
        let n = 0;
        return () => (n++ === 0 ? 0 : 1_800_000);
      })(),
    },
    cases: [
      {
        id: "final-late",
        short: "zz",
        requests: 0,
        timeoutMs: 1_800_000,
        transports: ["rest"],
        async run() {},
      },
    ],
  });
  assert.equal(expired.cases[0].outcome, "budget");
});

test("phase bounds an unresolved credential and shortens the actual gRPC deadline after credential work", async () => {
  const { createRest } = await import("./pubsub-production/rest.mjs");
  const { createGrpc } = await import("./pubsub-production/grpc.mjs");
  const grpcLib = (await import("@grpc/grpc-js")).default;
  let sent = 0;
  const rest = createRest({
    base: "http://127.0.0.1:1",
    budget: { consume() {} },
    capture: { record() {} },
    getToken: () => new Promise(() => {}),
    fetchImpl: async () => {
      sent += 1;
      return new Response("{}");
    },
  });
  await assert.rejects(
    createPhaseLimit(25)
      .transport(rest)
      .request({ method: "GET", path: "/v1/projects/demo-v2/topics/own" }),
    /phase time budget/,
  );
  assert.equal(sent, 0);
  let now = 0;
  let deadline;
  class Client {
    close() {}
    makeUnaryRequest(_path, _serialize, _deserialize, _body, _metadata, options, callback) {
      deadline = options.deadline.getTime();
      callback(null, {});
    }
  }
  const transport = createGrpc({
    target: "127.0.0.1:1",
    secure: false,
    grpc: { ...grpcLib, Client },
    budget: { consume() {} },
    capture: { record() {} },
    now: () => now,
    getToken: async () => {
      now += 40;
      return "synthetic";
    },
  });
  try {
    await createPhaseLimit(100, () => now)
      .transport(transport)
      .call({
        service: "Publisher",
        method: "GetTopic",
        request: { topic: "projects/demo-v2/topics/own" },
      });
    assert.equal(deadline, 100);
  } finally {
    transport.close();
  }
});

test("descriptor refuses an omitted producer or altered runtime in a plain actual process", async () => {
  const { spawnSync } = await import("node:child_process");
  const { fileURLToPath } = await import("node:url");
  const path = fileURLToPath(
    new URL("./pubsub-production/fixtures/v2-runtime-probe.mjs", import.meta.url),
  );
  for (const mode of ["source-omission", "runtime-mismatch"]) {
    const result = spawnSync(process.execPath, [path, mode], {
      env: { ...process.env, NODE_OPTIONS: "", NODE_PATH: "" },
      encoding: "utf8",
      timeout: 15_000,
    });
    assert.equal(result.status, 2);
    assert.match(result.stderr, /descriptor source\/runtime mismatch/);
  }
});

test("v2 summary preserves project source and envelope for attempt2 admission", async () => {
  const { summarize } = await import("./pubsub-production/record.mjs");
  const options = {
    runId: "0123456789ab",
    project: "demo-v2",
    suite: "stream-dlq-v2",
    admitted: { sourceHead: "a".repeat(40), envelopeId: "PUBSUB-STREAM-DLQ-V2" },
  };
  const result = summarize({
    options,
    capture: { count: () => 0, unknownCount: () => 0, unknowns: () => [], perCase: () => ({}) },
    summary: { stopped: null, cleanup: { leftover: [], errors: [], unsettled: [] } },
  });
  assert.equal(result.sourceHead, options.admitted.sourceHead);
  assert.equal(result.envelopeId, options.admitted.envelopeId);
  assert.equal(result.project, options.project);
  assert.equal(result.closureReady, true);
});

test("descriptor equality covers generated source runtime head and schema near misses", async () => {
  const { descriptorMatches } = await import("./pubsub-production/admission.mjs");
  for (let seed = 0; seed < 128; seed += 1) {
    const actual = {
      schema: 1,
      suite: "stream-dlq-v2",
      head: `${seed}`.padStart(40, "0"),
      runtime: {
        node: `v${seed}`,
        dependencies: [{ name: "sdk", treeSha256: `${seed}`.padStart(64, "0") }],
      },
      sources: [{ path: "producer.mjs", sha256: `${seed}`.padStart(64, "0") }],
    };
    assert.equal(descriptorMatches(structuredClone(actual), actual), true);
    for (const changes of [
      { schema: 2 },
      { suite: "stream-dlq" },
      { head: "bad" },
      { runtime: { ...actual.runtime, node: "altered" } },
      { runtime: { ...actual.runtime, dependencies: [] } },
      { sources: [] },
      { sources: [{ ...actual.sources[0], sha256: "altered" }] },
    ])
      assert.equal(descriptorMatches({ ...actual, ...changes }, actual), false);
  }
  assert.equal(descriptorMatches(null, {}), false);
});

test("REST and native stream use newly remaining deadline after credential work", async () => {
  const { createRest } = await import("./pubsub-production/rest.mjs");
  const { createGrpc } = await import("./pubsub-production/grpc.mjs");
  const { EventEmitter } = await import("node:events");
  const grpcLib = (await import("@grpc/grpc-js")).default;
  let now = 0;
  let timeout;
  let deadline;
  const getToken = async () => {
    now += 40;
    return "synthetic";
  };
  const common = {
    budget: { consume() {} },
    capture: { record() {}, frame() {} },
    now: () => now,
    getToken,
  };
  const originalTimeout = AbortSignal.timeout;
  AbortSignal.timeout = (ms) => {
    timeout = ms;
    return originalTimeout(ms);
  };
  try {
    const rest = createRest({
      ...common,
      base: "http://127.0.0.1:1",
      fetchImpl: async () => new Response("{}"),
    });
    await createPhaseLimit(100, () => now)
      .transport(rest)
      .request({ method: "GET", path: "/v1/projects/demo-v2/topics/own" });
    assert.equal(timeout, 60);
  } finally {
    AbortSignal.timeout = originalTimeout;
  }
  now = 0;
  class Client {
    close() {}
    makeBidiStreamRequest(_path, _serialize, _deserialize, _metadata, options) {
      deadline = options.deadline.getTime();
      const rpc = new EventEmitter();
      rpc.write = () => {};
      rpc.end = () => {};
      rpc.cancel = () => {};
      process.nextTick(() => rpc.emit("status", { code: grpcLib.status.OK, details: "" }));
      return rpc;
    }
  }
  const transport = createGrpc({
    ...common,
    target: "127.0.0.1:1",
    secure: false,
    grpc: { ...grpcLib, Client },
  });
  try {
    await createPhaseLimit(100, () => now)
      .transport(transport)
      .stream({ frames: [{ subscription: resource, streamAckDeadlineSeconds: 10 }] });
    assert.equal(deadline, 100);
  } finally {
    transport.close();
  }
});

test("v2 A2 binds original input directory so copied bytes cannot reuse the one-use marker", async () => {
  const { verifyRunOutput } = await import("./pubsub-production/admission.mjs");
  const { tempDir } = await import("./test-tmpdir.mjs");
  const { join } = await import("node:path");
  const source = tempDir("v2-a2-source-");
  const recovery = tempDir("v2-a2-output-");
  const copy = tempDir("v2-a2-copy-");
  const runId = "0123456789ab";
  const authority = { runOutputs: { [runId]: source }, cleanupRecovery: { out: recovery } };
  const options = {
    cleanupOnly: true,
    runId,
    out: recovery,
    fromCapture: join(source, `capture-${runId}.jsonl`),
  };
  assert.doesNotThrow(() => verifyRunOutput(authority, options));
  assert.throws(
    () =>
      verifyRunOutput(authority, { ...options, fromCapture: join(copy, `capture-${runId}.jsonl`) }),
    /input|directory/,
  );
  assert.throws(
    () => verifyRunOutput(authority, { ...options, fromCapture: undefined }),
    /input|directory/,
  );
});

test("REST dispatch intent persists a conservative deadline before an unanswered post-wait request", async () => {
  const { createRest } = await import("./pubsub-production/rest.mjs");
  const notes = [];
  let sent = false;
  const transport = createRest({
    base: "http://127.0.0.1:1",
    budget: { consume() {} },
    journalDispatch: true,
    now: () => 900_000,
    capture: { note: (kind, data) => notes.push({ kind, ...data }), record() {} },
    fetchImpl: async () => {
      assert.equal(notes.length, 1);
      sent = true;
      throw new Error("unanswered");
    },
  });
  const reply = await transport.request({
    method: "POST",
    path: "/v1/projects/demo-v2/topics/own:publish",
    timeoutMs: 30_000,
  });
  assert.equal(sent, true);
  assert.equal(reply.unknown, true);
  assert.equal(notes[0].kind, "request-dispatch");
  assert.equal(Date.parse(notes[0].requestDeadlineAt), 930_000);
});

test("v2 A2 ages from unanswered dispatch deadline rather than a pre-wait completed line", async () => {
  const { mkdtempSync, writeFileSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { main } = await import("./pubsub-production/record.mjs");
  const out = mkdtempSync(join(tmpdir(), "v2-a2-age-"));
  const runId = "0123456789ab";
  const path = join(out, `capture-${runId}.jsonl`);
  const now = Date.parse("2026-01-01T00:15:01Z");
  const rows = [
    {
      at: "2026-01-01T00:00:00Z",
      note: "run-start",
      suite: "stream-dlq-v2",
      project: "demo-v2",
      runId,
    },
    {
      at: "2026-01-01T00:15:00Z",
      note: "request-dispatch",
      requestDeadlineAt: "2026-01-01T00:15:30Z",
    },
  ];
  writeFileSync(path, rows.map((row) => JSON.stringify(row)).join("\n") + "\n");
  writeFileSync(join(out, `issued-${runId}.jsonl`), "");
  writeFileSync(join(out, `iam-${runId}.jsonl`), "");
  try {
    for (const value of [now, Date.parse("2026-01-01T00:25:00Z")]) {
      let error = "";
      const code = await main(
        [
          "--target",
          "production",
          "--project",
          "demo-v2",
          "--out",
          out,
          "--suite",
          "stream-dlq-v2",
          "--cleanup-only",
          "--run-id",
          runId,
          "--from-capture",
          path,
        ],
        {},
        { stdout: { write() {} }, stderr: { write: (text) => (error += text) } },
        { now: () => value, noWire: true },
      );
      assert.equal(code, 2);
      assert.match(error, /at least.*minutes/);
    }
  } finally {
    rmSync(out, { recursive: true });
  }
});

test("unary and native gRPC persist request deadline before dispatch", async () => {
  const { createGrpc } = await import("./pubsub-production/grpc.mjs");
  const { EventEmitter } = await import("node:events");
  const grpcLib = (await import("@grpc/grpc-js")).default;
  const notes = [];
  let unary = false;
  let native = false;
  class Client {
    close() {}
    makeUnaryRequest(_path, _serialize, _deserialize, _body, _metadata, _options, callback) {
      assert.equal(notes.at(-1).kind, "request-dispatch");
      unary = true;
      callback(null, {});
    }
    makeBidiStreamRequest() {
      assert.equal(notes.at(-1).kind, "request-dispatch");
      native = true;
      const rpc = new EventEmitter();
      rpc.write = () => {};
      rpc.end = () => {};
      rpc.cancel = () => {};
      process.nextTick(() => rpc.emit("status", { code: grpcLib.status.OK }));
      return rpc;
    }
  }
  const transport = createGrpc({
    target: "127.0.0.1:1",
    secure: false,
    grpc: { ...grpcLib, Client },
    budget: { consume() {} },
    capture: { note: (kind, data) => notes.push({ kind, ...data }), record() {}, frame() {} },
    now: () => 900_000,
    journalDispatch: true,
  });
  try {
    await transport.call({
      service: "Publisher",
      method: "GetTopic",
      request: { topic: "projects/demo-v2/topics/own" },
    });
    await transport.stream({ frames: [{ subscription: resource, streamAckDeadlineSeconds: 10 }] });
    assert.equal(unary, true);
    assert.equal(native, true);
    assert.equal(notes.length, 2);
    assert.ok(notes.every((row) => Date.parse(row.requestDeadlineAt) === 930_000));
  } finally {
    transport.close();
  }
});
