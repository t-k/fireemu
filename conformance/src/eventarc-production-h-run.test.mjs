import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { hManifest, hPublishes } from "./eventarc-production/h-script.mjs";
import {
  hCliFailed,
  hCliPlan,
  hManifestProblems,
  hReadList,
  hReady,
} from "./eventarc-production/h-deploy.mjs";
import { recordH, createHRest } from "./eventarc-production/h-record.mjs";
import { hCapture } from "./eventarc-production/h-capture.mjs";
import { createBudget, createCapture } from "./pubsub-production/capture.mjs";

const m = hManifest({ project: "demo-eventarc-h", runId: "012345abcdef" });

test("H CLI is single-export, forced and fails on exit-zero Functions Errored", () => {
  const plan = hCliPlan({
    manifest: m,
    name: m.observe,
    fixtureDir: "/private/source",
    configPath: "/private/source/firebase.json",
    env: {},
  });
  assert.deepEqual(plan.args.slice(-4), [
    `functions:eventarc-h:${m.observe}`,
    "--non-interactive",
    "--force",
    "--debug",
  ]);
  assert.throws(() => hCliPlan({ manifest: m, name: "all" }));
  const v4 = readFileSync(
    new URL("./eventarc-production/fixtures/h-fe/cli-deploy-tail.txt", import.meta.url),
    "utf8",
  );
  const v6 = readFileSync(
    new URL("./eventarc-production/fixtures/h-fe/cli-delete-tail.txt", import.meta.url),
    "utf8",
  );
  assert.equal(hCliFailed({ exitCode: 0, stdout: v4 }), false);
  assert.equal(hCliFailed({ exitCode: 0, stdout: v6 }), true);
  for (const r of [
    { exitCode: 0, stdout: "" },
    { exitCode: 2, stdout: v4 },
    { exitCode: 0, stdout: v4, timedOut: true },
    { exitCode: 0, stdout: v4, processCleanupUnknown: true },
  ])
    assert.equal(hCliFailed(r), true);
});

test("H manifest discovery refuses implicit regions and filter or endpoint drift", () => {
  const e = (name) => ({
    platform: "gcfv2",
    region: ["us-central1"],
    minInstances: 0,
    maxInstances: 2,
    eventTrigger: {
      eventType: m.type,
      channel: "locations/us-central1/channels/firebase",
      retry: name === m.observe,
      eventFilters: name === m.observe ? {} : { source: m.source, tenant: m.tenant },
    },
  });
  const endpoints = { [m.observe]: e(m.observe), [m.filtered]: e(m.filtered) };
  assert.deepEqual(hManifestProblems(endpoints, m), []);
  for (const mutate of [
    (e) => delete e[m.observe].region,
    (e) => (e[m.filtered].region = ["us-east1"]),
    (e) => (e[m.filtered].eventTrigger.eventFilters.tenant = "other"),
    (e) => (e.other = {}),
    (e) => (e[m.observe].maxInstances = 20),
  ]) {
    const bad = structuredClone(endpoints);
    mutate(bad);
    assert.ok(hManifestProblems(bad, m).length);
  }
});

test("H readiness and list reads replay FE v4 bodies with Gen1 and UNKNOWN entries", async () => {
  const fixture = (name) =>
    JSON.parse(
      readFileSync(
        new URL(`./eventarc-production/fixtures/h-fe/${name}.json`, import.meta.url),
        "utf8",
      ),
    );
  let reads = 0;
  for (const [name, key] of [
    ["functions-v2", "functions"],
    ["run-services", "services"],
    ["eventarc-triggers", "triggers"],
  ]) {
    const f = fixture(name);
    const items = await hReadList(
      { request: async () => ({ status: f.status, body: f.body }) },
      { path: "/recorded", key, phase: "readiness" },
      () => reads++,
    );
    assert.deepEqual(items, f.body[key]);
  }
  assert.equal(reads, 3);
  const functions = fixture("functions-v2").body.functions;
  assert.ok(functions.some((f) => f.environment === "GEN_1"));
  assert.ok(fixture("functions-v2-unknown").body.functions.some((f) => f.state === "UNKNOWN"));
  const ready = hReady({
    manifest: m,
    functions,
    services: fixture("run-services").body.services,
    triggers: fixture("eventarc-triggers").body.triggers,
    channel: { name: m.channel, state: "ACTIVE" },
  });
  assert.equal(ready.ready, false);
  await assert.rejects(
    hReadList(
      { request: async () => ({ status: 200, body: { functions: "bad" } }) },
      { path: "/v2/functions", key: "functions" },
      () => {},
    ),
    /incomplete/,
  );
  await assert.rejects(
    hReadList(
      {
        request: async () => ({
          status: 200,
          body: { functions: [], nextPageToken: "still-more" },
        }),
      },
      { path: "/v2/functions", key: "functions" },
      () => {},
    ),
    /truncated/,
  );
});

test("H transport captures every 5xx as unknown including 501 and preserves native bytes", async () => {
  const rows = [];
  const raw = '{\n  "error": {"code": 501}\n}\n';
  const transport = createHRest({
    base: "http://offline.invalid",
    capture: createCapture({ journal: { write: (row) => rows.push(row) } }),
    budget: createBudget(1),
    fetchImpl: async () =>
      new Response(raw, {
        status: 501,
        headers: { "content-length": String(Buffer.byteLength(raw)) },
      }),
  });
  const reply = await transport.request({
    method: "POST",
    path: "/write",
    body: { name: "owned" },
  });
  assert.equal(reply.unknown, true);
  assert.equal(rows[0].unknown, true);
  assert.equal(rows[0].response.bodyBytes, Buffer.byteLength(raw));
  assert.equal(Buffer.from(rows[0].response.bodyBase64, "base64").toString(), raw);
});

test("H capture retains failed pages as incomplete after a complete final reread", async () => {
  let calls = 0;
  const capture = hCapture({
    manifest: m,
    origins: [],
    now: () => 2000,
    startedAt: 1000,
    saveFrame: () => {},
    transport: {
      request: async () =>
        ++calls === 1 ? { status: 503, unknown: true } : { status: 200, body: {} },
    },
  });
  await capture.poll();
  await capture.finish();
  assert.equal(capture.result().complete, false);
  assert.equal(capture.result().finalRead, true);
});

test("H recorder fails closed before cloud writes without frozen production shape evidence", async () => {
  let sent = 0;
  const result = await recordH({
    manifest: m,
    transports: {},
    cli: () => {
      sent++;
    },
    sleep: () => {},
    now: () => 0,
    note: () => {},
    saveFrame: () => {},
  });
  assert.equal(sent, 0);
  assert.equal(result.closureReady, false);
  assert.match(result.stopped, /evidence/);
  assert.equal(hPublishes(m).length, 48);
});

// This world verifies orchestration only; it is not production shape admission evidence.
function hWorld({ partial = false, unknownDelete = false } = {}) {
  let clock = Date.parse("2026-10-06T00:00:00Z");
  let channel = false;
  let marker = false;
  let insert = 0;
  const functions = new Map();
  const entries = [];
  const calls = [];
  const deleted = [];
  const makeFunction = (name) => {
    const full = `projects/${m.project}/locations/us-central1/functions/${name}`;
    return {
      name: full,
      environment: "GEN_2",
      state: "ACTIVE",
      buildConfig: {
        build: "projects/123456789012/locations/us-central1/builds/build-1",
        dockerRepository: `projects/${m.project}/locations/us-central1/repositories/gcf-artifacts`,
        source: {
          storageSource: {
            bucket: "gcf-v2-sources-123456789012-us-central1",
            object: `${name}/function-source.zip`,
          },
        },
      },
      serviceConfig: {
        service: `projects/${m.project}/locations/us-central1/services/${name.toLowerCase()}`,
      },
      eventTrigger: {
        trigger: `projects/${m.project}/locations/us-central1/triggers/${name.toLowerCase()}-actual`,
        triggerRegion: "us-central1",
        channel: m.channel,
        eventType: m.type,
        retryPolicy: name === m.observe ? "RETRY_POLICY_RETRY" : "RETRY_POLICY_DO_NOT_RETRY",
      },
    };
  };
  const trigger = (f) => ({
    name: f.eventTrigger.trigger,
    channel: m.channel,
    destination: { cloudFunction: f.name },
    eventFilters: [
      { attribute: "type", value: m.type },
      ...(f.name.endsWith(m.filtered)
        ? [
            { attribute: "source", value: m.source },
            { attribute: "tenant", value: m.tenant },
          ]
        : []),
    ],
    transport: {
      pubsub: {
        topic: `projects/${m.project}/topics/managed-${f.name.split("/").at(-1)}`,
        subscription: `projects/${m.project}/subscriptions/managed-${f.name.split("/").at(-1)}`,
      },
    },
  });
  const absent = () => ({ status: 404, body: { error: { code: 404, status: "NOT_FOUND" } } });
  const request = async (host, spec) => {
    calls.push({ host, ...spec });
    if (host === "usage")
      return {
        status: 200,
        body: { state: "ENABLED", config: { name: spec.path.split("/").at(-1) } },
      };
    if (host === "logging") return { status: 200, body: { entries } };
    if (host === "firestore") {
      if (spec.path.endsWith("databases/(default)"))
        return { status: 200, body: { type: "FIRESTORE_NATIVE", locationId: "us-central1" } };
      if (spec.method === "DELETE") {
        marker = false;
        return { status: 200, body: {} };
      }
      return marker
        ? {
            status: 200,
            body: { name: spec.path.slice(4), fields: { run: { stringValue: m.runId } } },
          }
        : absent();
    }
    if (spec.path.endsWith("/functions"))
      return { status: 200, body: { functions: [...functions.values()] } };
    if (spec.path.endsWith("/services"))
      return {
        status: 200,
        body: {
          services: [...functions.values()].map((f) => ({
            name: f.serviceConfig.service,
            terminalCondition: { state: "CONDITION_SUCCEEDED" },
          })),
        },
      };
    if (spec.path.endsWith("/triggers"))
      return { status: 200, body: { triggers: [...functions.values()].map(trigger) } };
    if (host === "functions") {
      const name = spec.path.split("/").at(-1);
      if (spec.method === "DELETE") {
        deleted.push(name);
        if (unknownDelete) return { status: 503, unknown: true, body: {} };
        functions.delete(name);
        return {
          status: 200,
          body: {
            name: `projects/${m.project}/locations/us-central1/operations/delete-${name}`,
            metadata: { target: spec.path.slice(4) },
            done: true,
          },
        };
      }
      return functions.has(name) ? { status: 200, body: functions.get(name) } : absent();
    }
    if (host === "eventarc" && spec.path.includes("/channels/firebase")) {
      if (spec.method === "DELETE") {
        deleted.push("firebase");
        channel = false;
        return {
          status: 200,
          body: {
            name: `projects/${m.project}/locations/us-central1/operations/delete-channel`,
            metadata: { target: m.channel },
            done: true,
          },
        };
      }
      return channel ? { status: 200, body: { name: m.channel, state: "ACTIVE" } } : absent();
    }
    if (host === "publishing") {
      const events = spec.body.events;
      const refused = events.length > 100 || events.some((e) => !e.type);
      if (refused) return { status: 400, body: { error: { status: "INVALID_ARGUMENT" } } };
      for (const e of events) {
        if (e.type !== m.type || !e.attributes.time || e.attributes.convbytes) continue;
        const event = {
          id: e.id,
          source: e.source,
          type: e.type,
          specversion: "1.0",
          time: e.attributes.time.ceTimestamp,
          tenant: e.attributes.tenant?.ceString,
          data: e.binaryData ? e.binaryData : JSON.parse(e.textData),
        };
        const caseId = /^fe[a-f0-9]{12}-h-(.+)-\d+$/.exec(e.id)?.[1] ?? event.data.case;
        const retry = caseId === "retry";
        if (retry) marker = true;
        for (const handler of [
          m.observe,
          ...(e.source === m.source && event.tenant === m.tenant ? [m.filtered] : []),
        ]) {
          for (const attempt of retry && handler === m.observe
            ? ["failed", "succeeded"]
            : ["succeeded"]) {
            const frame = {
              handler,
              generation: 2,
              run: m.runId,
              recording: "h1",
              case: caseId,
              correlation: { id: event.id, source: event.source },
              invocationId: `attempt-${++insert}`,
              attempt,
              eventKeys: Object.keys(JSON.parse(JSON.stringify(event))),
              event,
            };
            entries.push({
              insertId: String(insert),
              timestamp: new Date(clock).toISOString(),
              logName: `projects/${m.project}/logs/run.googleapis.com%2Fstdout`,
              resource: {
                type: "cloud_run_revision",
                labels: {
                  project_id: m.project,
                  service_name: handler.toLowerCase(),
                  location: "us-central1",
                },
              },
              textPayload: `FE_EVENTS_FRAME ${JSON.stringify(frame)}`,
            });
          }
        }
      }
      return { status: 200, body: {} };
    }
    return absent();
  };
  const options = {
    manifest: m,
    transports: Object.fromEntries(
      ["usage", "firestore", "functions", "run", "eventarc", "publishing", "logging", "pubsub"].map(
        (host) => [host, { request: (spec) => request(host, spec) }],
      ),
    ),
    now: () => clock,
    sleep: async (ms) => {
      clock += ms;
    },
    note: () => {},
    saveFrame: () => {},
    cli: async (name) => {
      functions.set(name, makeFunction(name));
      channel = true;
      return { exitCode: 0, stdout: "0 Functions Errored\n", name };
    },
    evidence: {
      preflight: () => true,
      logging: () => true,
      readiness: () => true,
      operation: () => true,
      notFound: (r) => r.status === 404,
      cliWrites: (deployed) => ({
        complete: !partial,
        function: { state: "confirmed" },
        resources:
          deployed.name === m.observe
            ? [
                {
                  name: m.channel,
                  action: "create",
                  host: "eventarc",
                  kind: "channel",
                  state: "confirmed",
                },
              ]
            : [],
      }),
      retention: async () => ({ complete: true, atBaseline: true, resources: [] }),
    },
    makeSdk: async ({ transport }) => ({
      close: async () => {},
      publish: async (p) => {
        const e = p.events[0];
        const reply = await transport.request({
          method: "POST",
          path: `/v1/${m.channel}:publishEvents`,
          body: {
            events: [
              {
                "@type": "type.googleapis.com/io.cloudevents.v1.CloudEvent",
                id: e.id ?? `generated-${++insert}`,
                source: e.source ?? "//generated/sdk",
                type: e.type,
                specVersion: "1.0",
                attributes: {
                  time: { ceTimestamp: e.time ?? new Date(clock).toISOString() },
                  tenant: { ceString: e.tenant },
                },
                textData: JSON.stringify(e.data),
              },
            ],
          },
        });
        return { threw: reply.status !== 200, requests: 1 };
      },
    }),
  };
  return { options, calls, deleted };
}

test("H orchestration runs the frozen table, captures handlers and deletes its owned channel", async () => {
  const world = hWorld();
  const result = await recordH(world.options);
  assert.equal(result.stopped, null);
  assert.equal(result.publishes.length, 48);
  assert.equal(result.counts.publish, 48);
  assert.equal(result.closureReady, true);
  assert.deepEqual(world.deleted, [m.filtered, m.observe, "firebase"]);
  assert.equal(result.evidence.observations.find((o) => o.case === "retry").complete, true);
});

test("H preserves partial CLI inventory and never repeats an unknown function DELETE", async () => {
  const partial = hWorld({ partial: true });
  const result = await recordH(partial.options);
  assert.equal(result.closureReady, false);
  assert.ok(result.writes.some((w) => w.name === m.channel));
  assert.ok(result.cleanup.unconfirmed.some((n) => n.includes("write-inventory")));
  assert.equal(partial.calls.filter((c) => c.host === "publishing").length, 0);
  const unknown = hWorld({ unknownDelete: true });
  const stopped = await recordH(unknown.options);
  assert.equal(stopped.closureReady, false);
  assert.equal(unknown.deleted.filter((n) => n === m.observe).length, 1);
  assert.equal(unknown.deleted.filter((n) => n === m.filtered).length, 1);
  assert.equal(unknown.deleted.includes("firebase"), false);
});

test("H SDK requests use the real pinned SDK locally including generated ID and time", async () => {
  const { createSdk } = await import("./eventarc-production/sdk.mjs");
  const { createOwnership } = await import("./eventarc-production/names.mjs");
  const ownership = createOwnership(m);
  ownership.allowPublish(m.channel);
  const bodies = [];
  const sdk = await createSdk({
    project: m.project,
    runId: m.runId,
    caseId: "h-sdk",
    ownership,
    publishPrefix: "/v1",
    getToken: async () => "local-emulator-token",
    transport: {
      request: async (spec) => {
        bodies.push(spec);
        return { status: 200, body: {} };
      },
    },
  });
  try {
    for (const p of hPublishes(m).filter((p) => p.sdk)) {
      const result = await sdk.publish(p);
      assert.equal(result.requests, 1, p.case);
      assert.equal(result.threw, false, p.case);
    }
    assert.equal(bodies.length, 5);
    assert.ok(bodies.every((b) => b.path === `/v1/${m.channel}:publishEvents`));
    const generated = bodies[3].body.events[0];
    assert.match(generated.id, /^[a-f0-9-]{36}$/);
    assert.ok(generated.attributes.time.ceTimestamp);
    assert.equal(generated.source, m.source);
  } finally {
    await sdk.close();
  }
});

test("H A2 cannot close opaque CLI writes or an unknown create, and enforces its clock", async () => {
  const { hA2 } = await import("./eventarc-production/h-record.mjs");
  const options = {
    now: () => 600000,
    note: () => {},
    evidence: {
      notFound: (r) => r.status === 404,
      readiness: () => true,
      retention: async () => ({ complete: true, atBaseline: true }),
    },
    transports: {
      functions: {
        request: async () => ({ status: 404, body: { error: { code: 404, status: "NOT_FOUND" } } }),
      },
    },
  };
  const recording = {
    manifest: m,
    stopped: null,
    evidence: { complete: true },
    lastRequestAt: 0,
    writes: [
      {
        name: "projects/demo-eventarc-h/locations/us-central1/functions/owned",
        host: "functions",
        action: "create",
        state: "unknown",
      },
    ],
    identities: [],
    cleanup: { retained: [], unconfirmed: [], unsettled: [] },
  };
  assert.equal((await hA2({ ...options, recording })).closureReady, false);
  assert.equal(
    (
      await hA2({
        ...options,
        recording: {
          ...recording,
          writes: [],
          cleanup: { ...recording.cleanup, unconfirmed: ["cli:owned:write-inventory"] },
        },
      })
    ).closureReady,
    false,
  );
  await assert.rejects(hA2({ ...options, now: () => 599999, recording }), /ten minutes/);
  const confirmed = {
    ...recording,
    writes: [
      { ...recording.writes[0], state: "confirmed" },
      { ...recording.writes[0], action: "delete", state: "unknown" },
    ],
  };
  assert.equal((await hA2({ ...options, recording: confirmed })).closureReady, true);
});

test("H A2 keeps restoration and handler-evidence obligations separate from resource absence", async () => {
  const { hA2 } = await import("./eventarc-production/h-record.mjs");
  const name = `projects/${m.project}/locations/us-central1/functions/${m.observe}`;
  const recording = {
    lastRequestAt: 0,
    writes: [
      { name, host: "functions", action: "create", state: "confirmed" },
      { name, host: "functions", action: "delete", state: "unknown" },
      { name, host: "functions", action: "restore", state: "unknown" },
    ],
    identities: [],
    cleanup: { retained: [], unconfirmed: [], unsettled: [name] },
    stopped: "H control missing",
    evidence: { complete: false },
    retentionVerified: false,
  };
  const options = {
    recording,
    now: () => 600000,
    note: () => {},
    evidence: {
      notFound: (r) => r.status === 404,
      readiness: () => true,
      retention: async () => ({ complete: true, atBaseline: true }),
    },
    transports: {
      functions: {
        request: async () => ({ status: 404, body: { error: { status: "NOT_FOUND" } } }),
      },
    },
  };
  const r = await hA2(options);
  assert.equal(r.closureReady, false);
  assert.equal(r.cleanupReady, false);
  const clean = await hA2({
    ...options,
    recording: { ...recording, writes: recording.writes.slice(0, 2) },
  });
  assert.equal(clean.cleanupReady, true);
  assert.equal(clean.closureReady, false);
  const incompleteEvidence = await hA2({
    ...options,
    recording: { ...recording, stopped: null, writes: recording.writes.slice(0, 2) },
  });
  assert.equal(incompleteEvidence.cleanupReady, true);
  assert.equal(incompleteEvidence.closureReady, false);
});

test("H CLI escalates its own process group after exit without spawning a real process", async (t) => {
  const { EventEmitter } = await import("node:events");
  const { runHCli } = await import("./eventarc-production/h-deploy.mjs");
  const child = new EventEmitter();
  child.pid = 999999;
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  const kills = [];
  const originalKill = process.kill;
  t.mock.timers.enable({ apis: ["setTimeout"] });
  process.kill = (pid, signal) => {
    kills.push([pid, signal]);
    return true;
  };
  try {
    const promise = runHCli({
      node: "unused",
      firebaseJs: "unused",
      plan: { args: [], cwd: ".", env: {} },
      save: () => {},
      spawnFn: () => child,
    });
    child.emit("close", 0);
    t.mock.timers.tick(60000);
    await promise;
    assert.deepEqual(kills, [
      [-999999, "SIGTERM"],
      [-999999, "SIGKILL"],
    ]);
  } finally {
    process.kill = originalKill;
    t.mock.timers.reset();
  }
});

test("H discovery snapshot is built by the installed pinned SDK, not a handcrafted manifest", () => {
  const snapshot = JSON.parse(
    readFileSync(
      new URL("./eventarc-production/fixtures/h-fe/discovered-h.json", import.meta.url),
      "utf8",
    ),
  );
  assert.deepEqual(
    hManifestProblems(
      snapshot.endpoints,
      hManifest({ project: "fireemu-oracle-events", runId: "cafe60000001" }),
    ),
    [],
  );
});

test("H CLI kills a real SIGTERM-resistant child and the test reaps it on failure", async (t) => {
  const { spawn } = await import("node:child_process");
  const { setTimeout: delay } = await import("node:timers/promises");
  const { runHCli } = await import("./eventarc-production/h-deploy.mjs");
  let child;
  let closed = false;
  let ready;
  const started = new Promise((resolve) => {
    ready = resolve;
  });
  t.mock.timers.enable({ apis: ["setTimeout"] });
  try {
    const result = runHCli({
      node: process.execPath,
      firebaseJs: "--eval",
      plan: {
        args: ["process.on('SIGTERM',()=>{}); console.log('ready'); setInterval(()=>{},1000)"],
        cwd: process.cwd(),
        env: {},
      },
      save: (_stream, chunk) => {
        if (chunk.toString().includes("ready")) ready();
      },
      spawnFn: (...args) => {
        child = spawn(...args);
        child.once("close", () => {
          closed = true;
        });
        child.once("error", ready);
        return child;
      },
    });
    await started;
    t.mock.timers.tick(20 * 60_000);
    await delay(100);
    assert.equal(closed, false, "SIGTERM was ignored during the grace period");
    t.mock.timers.tick(60_000);
    assert.equal((await result).timedOut, true);
    assert.equal(closed, true);
    assert.throws(() => process.kill(child.pid, 0), { code: "ESRCH" });
  } finally {
    t.mock.timers.reset();
    // This test owns this exact child; never leave it behind after a failed assertion.
    if (child?.pid && !closed) {
      child.kill("SIGTERM");
      await delay(100);
      if (!closed) child.kill("SIGKILL");
      if (!closed) await new Promise((resolve) => child.once("close", resolve));
    }
  }
});
