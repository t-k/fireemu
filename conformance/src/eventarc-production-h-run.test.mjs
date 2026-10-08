import test from "node:test";
import assert from "node:assert/strict";
import {
  readFileSync,
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  rmSync,
  existsSync,
  realpathSync,
  renameSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, delimiter } from "node:path";
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
      eventType: name === m.observe ? m.type : m.filteredType,
      channel: "locations/us-central1/channels/firebase",
      retry: name === m.observe,
      eventFilters: {},
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
function hWorld({
  manifest = m,
  partial = false,
  unknownDelete = false,
  pendingDelete = false,
  cascadePresent = false,
  observationUnknown = false,
  enable = false,
  functionDeleteMs = 0,
  channelDeleteMs = 0,
  enablePending = false,
  enableMismatch = false,
  badChild = false,
  badPackages = false,
  missingPolicy = false,
} = {}) {
  const m = manifest;
  let clock = Date.parse("2026-10-06T00:00:00Z");
  let channel = false;
  let publishingEnabled = !enable;
  let marker = false;
  let insert = 0;
  const functions = new Map();
  const entries = [];
  const calls = [];
  const deleted = [];
  const operations = new Map();
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
        eventType: name === m.observe ? m.type : m.filteredType,
        retryPolicy: name === m.observe ? "RETRY_POLICY_RETRY" : "RETRY_POLICY_DO_NOT_RETRY",
      },
    };
  };
  const trigger = (f) => ({
    name: f.eventTrigger.trigger,
    channel: m.channel,
    destination: { cloudFunction: f.name },
    eventFilters: [{ attribute: "type", value: f.eventTrigger.eventType }],
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
    if (spec.op === "h.observeOnly" && observationUnknown)
      return { status: 503, unknown: true, body: {} };
    if (host === "artifact")
      return {
        status: 200,
        body: spec.path.includes("/packages")
          ? badPackages
            ? { packages: [{}] }
            : {}
          : missingPolicy
            ? {}
            : { cleanupPolicies: { existing: {} } },
      };
    if (badChild && spec.label?.case === "h-cleanup" && spec.path.includes("/subscriptions"))
      throw new Error("bad child page");
    if (spec.path.includes("/operations/") && operations.has(spec.path.slice(4))) {
      const op = operations.get(spec.path.slice(4));
      return {
        status: 200,
        body: {
          name: spec.path.slice(4),
          metadata: { target: op.target },
          done: clock - op.at >= op.duration,
        },
      };
    }
    if (host === "usage") {
      if (spec.method === "POST") return { status: 200, body: { name: "operations/enable" } };
      if (spec.path.includes("operations/")) {
        publishingEnabled = true;
        return {
          status: 200,
          body: {
            name: enableMismatch ? "operations/other" : "operations/enable",
            done: !enablePending,
            response: {},
          },
        };
      }
      return {
        status: 200,
        body: {
          services: [
            "artifactregistry",
            "cloudbuild",
            "cloudfunctions",
            "cloudresourcemanager",
            "eventarc",
            "firestore",
            "logging",
            "pubsub",
            "run",
            "storage",
            ...(publishingEnabled ? ["eventarcpublishing"] : []),
          ].map((api) => ({
            name: `projects/123456789012/services/${api}.googleapis.com`,
            state: "ENABLED",
            config: { name: `${api}.googleapis.com` },
          })),
        },
      };
    }
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
    if (spec.path.includes("/topics?"))
      return {
        status: 200,
        body: {
          topics: [...functions.values()].map((f) => ({ name: trigger(f).transport.pubsub.topic })),
        },
      };
    if (spec.path.includes("/subscriptions?"))
      return {
        status: 200,
        body: {
          subscriptions: [...functions.values()].map((f) => ({
            name: trigger(f).transport.pubsub.subscription,
          })),
        },
      };
    if (spec.path.endsWith("/functions"))
      return { status: 200, body: { functions: [...functions.values()] } };
    if (spec.path.endsWith("/services"))
      return {
        status: 200,
        body: {
          services: [
            ...functions.values(),
            ...(cascadePresent && deleted.length ? [makeFunction(m.observe)] : []),
          ].map((f) => ({
            name: f.serviceConfig.service,
            terminalCondition: { state: "CONDITION_SUCCEEDED" },
          })),
        },
      };
    if (spec.path.endsWith("/triggers"))
      return { status: 200, body: { triggers: [...functions.values()].map(trigger) } };
    if (host === "functions") {
      const name = spec.path.split("/").at(-1);
      if (spec.path.includes("/operations/"))
        return {
          status: 200,
          body: {
            name: spec.path.slice(4),
            metadata: {
              target: `${m.channel.replace("/channels/firebase", "/functions/")}${name.replace(/^delete-/, "")}`,
            },
            done: false,
          },
        };
      if (spec.method === "DELETE") {
        deleted.push(name);
        if (unknownDelete) return { status: 503, unknown: true, body: {} };
        functions.delete(name);
        if (functionDeleteMs)
          operations.set(`projects/${m.project}/locations/us-central1/operations/delete-${name}`, {
            at: clock,
            target: spec.path.slice(4),
            duration: functionDeleteMs,
          });
        return {
          status: 200,
          body: {
            name: `projects/${m.project}/locations/us-central1/operations/delete-${name}`,
            metadata: { target: spec.path.slice(4) },
            done: !pendingDelete && !functionDeleteMs,
          },
        };
      }
      return functions.has(name) ? { status: 200, body: functions.get(name) } : absent();
    }
    if (host === "eventarc" && spec.path.includes("/channels/firebase")) {
      if (spec.method === "DELETE") {
        deleted.push("firebase");
        channel = false;
        if (channelDeleteMs)
          operations.set(`projects/${m.project}/locations/us-central1/operations/delete-channel`, {
            at: clock,
            target: m.channel,
            duration: channelDeleteMs,
          });
        return {
          status: 200,
          body: {
            name: `projects/${m.project}/locations/us-central1/operations/delete-channel`,
            metadata: { target: m.channel },
            done: !channelDeleteMs,
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
        if (
          ![m.type, m.filteredType].includes(e.type) ||
          !e.attributes.time ||
          e.attributes.convbytes
        )
          continue;
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
        for (const handler of [e.type === m.type ? m.observe : m.filtered]) {
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
      [
        "usage",
        "firestore",
        "functions",
        "run",
        "eventarc",
        "publishing",
        "logging",
        "pubsub",
        "artifact",
      ].map((host) => [host, { request: (spec) => request(host, spec) }]),
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
      a2ListRuling: true,
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
  return {
    options,
    calls,
    deleted,
    request,
    setClock: (value) => {
      clock = value;
    },
  };
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
      a2ListRuling: true,
      readiness: () => true,
      retention: async () => ({ complete: true, atBaseline: true }),
    },
    transports: {
      functions: {
        request: async () => ({ status: 200, body: {} }),
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
      a2ListRuling: true,
      readiness: () => true,
      retention: async () => ({ complete: true, atBaseline: true }),
    },
    transports: {
      functions: {
        request: async () => ({ status: 200, body: {} }),
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

test("H R1 requires its own completed DELETE even when a fresh list omits the function", async () => {
  const world = hWorld({ pendingDelete: true });
  const result = await recordH(world.options);
  assert.equal(result.closureReady, false);
  assert.ok(
    result.cleanup.unsettled.includes(
      `projects/${m.project}/locations/us-central1/functions/${m.filtered}`,
    ),
  );
  assert.equal(world.deleted.filter((name) => name === m.filtered).length, 1);
});

test("H R2 keeps a listed cascade open after its function settles", async () => {
  const world = hWorld({ cascadePresent: true });
  const result = await recordH(world.options);
  assert.equal(result.closureReady, false);
  assert.ok(
    result.cleanup.unsettled.includes(
      `projects/${m.project}/locations/us-central1/services/${m.observe.toLowerCase()}`,
    ),
  );
  assert.equal(world.deleted.includes("firebase"), false);
});

test("H observeOnly GET failures settle nothing and do not block closure", async () => {
  const world = hWorld({ observationUnknown: true });
  const result = await recordH(world.options);
  assert.equal(result.closureReady, true);
  const reads = world.calls.filter((call) => call.op === "h.observeOnly");
  assert.equal(reads.length, 15);
  assert.ok(reads.every((call) => call.method === "GET"));
});

test("H enables publishing once between recorded complete service lists and never disables it", async () => {
  const world = hWorld({ enable: true });
  const notes = [];
  world.options.note = (kind, value) => notes.push({ kind, value });
  const result = await recordH(world.options);
  assert.equal(result.closureReady, true);
  const writes = world.calls.filter((call) => call.host === "usage" && call.method === "POST");
  assert.equal(writes.length, 1);
  assert.match(writes[0].path, /eventarcpublishing.googleapis.com:enable$/);
  assert.deepEqual(writes[0].body, {});
  assert.equal(
    notes
      .find((n) => n.kind === "h-enabled-services-before")
      .value.some((s) => s.config.name === "eventarcpublishing.googleapis.com"),
    false,
  );
  assert.equal(
    notes
      .find((n) => n.kind === "h-enabled-services-after")
      .value.some((s) => s.config.name === "eventarcpublishing.googleapis.com"),
    true,
  );
});

test("H deploy 2 never runs after partial deploy 1 and complete lists drive cleanup", async () => {
  const world = hWorld({ partial: true });
  const result = await recordH(world.options);
  assert.equal(
    result.writes.filter((write) => write.kind === "function" && write.action === "create").length,
    1,
  );
  for (const collection of ["functions", "services", "triggers", "topics", "subscriptions"])
    assert.ok(
      world.calls.some(
        (call) =>
          call.label?.case === "h-cleanup" &&
          new URL(call.path, "https://offline.invalid").pathname.endsWith(`/${collection}`),
      ),
    );
});

test("H R4 requires a ledger ruling and complete fresh lists, and R3 rejects absent unknown creates", async () => {
  const { hA2 } = await import("./eventarc-production/h-record.mjs");
  const full = `projects/${m.project}/locations/us-central1/functions/${m.observe}`;
  const recording = {
    manifest: m,
    lastRequestAt: 0,
    writes: [
      { name: full, host: "functions", action: "create", state: "confirmed" },
      { name: full, host: "functions", action: "delete", state: "unknown" },
    ],
    identities: [],
    cleanup: {},
    evidence: { complete: true },
    stopped: null,
  };
  let requests = 0;
  const options = {
    recording,
    now: () => 600000,
    note: () => {},
    evidence: {
      a2ListRuling: true,
      readiness: () => true,
      retention: async () => ({ complete: true, atBaseline: true }),
    },
    transports: {
      functions: {
        request: async (spec) => {
          requests++;
          assert.equal(spec.path, `/v2/projects/${m.project}/locations/us-central1/functions`);
          return { status: 200, body: {} };
        },
      },
    },
  };
  assert.equal((await hA2(options)).cleanupReady, true);
  assert.equal(requests, 1);
  assert.equal(
    (await hA2({ ...options, evidence: { ...options.evidence, a2ListRuling: false } }))
      .cleanupReady,
    false,
  );
  for (const state of ["unknown", "pending"])
    assert.equal(
      (
        await hA2({
          ...options,
          recording: { ...recording, writes: [{ ...recording.writes[0], state }] },
        })
      ).cleanupReady,
      false,
    );
  for (const body of [{ functions: "bad" }, { nextPageToken: "never-exhausted" }])
    assert.equal(
      (
        await hA2({
          ...options,
          transports: { functions: { request: async () => ({ status: 200, body }) } },
        })
      ).cleanupReady,
      false,
    );
  await assert.rejects(hA2({ ...options, now: () => 599999 }), /ten minutes/);
});

test("H R2 A2 cannot close a cascade before its unknown function create settles", async () => {
  const { hA2 } = await import("./eventarc-production/h-record.mjs");
  const full = `projects/${m.project}/locations/us-central1/functions/${m.observe}`;
  const service = `projects/${m.project}/locations/us-central1/services/owned`;
  const result = await hA2({
    recording: {
      lastRequestAt: 0,
      writes: [{ name: full, host: "functions", action: "create", state: "unknown" }],
      identities: [{ function: full, service }],
      cleanup: {},
    },
    now: () => 600000,
    note: () => {},
    evidence: {
      a2ListRuling: true,
      readiness: () => true,
      retention: async () => ({ complete: true, atBaseline: true }),
    },
    transports: Object.fromEntries(
      ["functions", "run"].map((host) => [
        host,
        { request: async () => ({ status: 200, body: {} }) },
      ]),
    ),
  });
  assert.equal(result.cleanupReady, false);
  assert.equal(result.facts.find((f) => f.name === service).closed, false);
});

test("H R2 lists that omit children cannot settle them before a pending parent DELETE settles", async () => {
  const world = hWorld({ pendingDelete: true });
  const result = await recordH(world.options);
  assert.equal(result.closureReady, false);
  for (const identity of result.identities)
    for (const name of [identity.service, identity.trigger, identity.topic, identity.subscription])
      assert.ok(result.cleanup.unsettled.includes(name));
});

test("H closure remains false when the CLI never captured its own default channel CREATE", async () => {
  const world = hWorld();
  const cliWrites = world.options.evidence.cliWrites;
  world.options.evidence.cliWrites = (...args) => ({ ...cliWrites(...args), resources: [] });
  const result = await recordH(world.options);
  assert.equal(result.stopped, null);
  assert.equal(result.evidence.complete, true);
  assert.ok(result.cleanup.unconfirmed.includes(m.channel));
  assert.equal(result.closureReady, false);
});

test("H production judges receive native metadata from each concurrent REST response", async () => {
  const { hProductionEvidence } = await import("./eventarc-production/h-production.mjs");
  const records = JSON.parse(
    readFileSync(
      new URL("./eventarc-production/fixtures/h-fe/stage-c-replay.json", import.meta.url),
      "utf8",
    ),
  );
  const recorded = records.find((r) => r.sequence === 2);
  const captured = [];
  const transport = createHRest({
    base: "http://offline.invalid",
    capture: { record: (entry) => captured.push(entry) },
    budget: createBudget(2),
    fetchImpl: async (url) => {
      const body = structuredClone(recorded.body);
      if (url.endsWith("other")) body.error.message += " other";
      const raw = `${JSON.stringify(body, null, 2)}\n`;
      return new Response(raw, {
        status: 404,
        headers: { "content-length": String(Buffer.byteLength(raw)) },
      });
    },
  });
  const paths = [recorded.path, recorded.path.replace("firebase", "other")];
  const replies = await Promise.all(
    paths.map((path) => transport.request({ method: "GET", path })),
  );
  for (let i = 0; i < replies.length; i++) {
    const reply = replies[i];
    assert.equal(Buffer.from(reply.bodyBase64, "base64").length, reply.bodyBytes);
    assert.ok(reply.bodySha256);
    assert.equal(
      hProductionEvidence.notFound(reply, { host: "eventarc", method: "GET", path: paths[i] }),
      true,
    );
    assert.equal(
      hProductionEvidence.notFound(
        { ...reply, bodyBytes: 1 },
        { host: "eventarc", method: "GET", path: paths[i] },
      ),
      false,
    );
  }
  assert.notEqual(replies[0].bodyBytes, replies[1].bodyBytes);
  assert.equal(captured.length, 2);
});

test("H cleanup tolerates a 25 second Gen2 delete and 5 second channel delete within its caps", async () => {
  const world = hWorld({ functionDeleteMs: 25000, channelDeleteMs: 5000 });
  const result = await recordH(world.options);
  assert.equal(result.closureReady, true);
  assert.equal(result.counts.cleanup, 40);
});

test("H cleanup deletes both functions even when a child list is unreadable", async () => {
  const world = hWorld({ badChild: true });
  const result = await recordH(world.options);
  assert.equal(result.closureReady, false);
  assert.deepEqual(world.deleted, [m.filtered, m.observe]);
});

test("H Artifact Registry preflight refuses packages or a missing policy before CLI", async () => {
  for (const options of [{ badPackages: true }, { missingPolicy: true }]) {
    const world = hWorld(options);
    const result = await recordH(world.options);
    assert.match(result.stopped, /Artifact Registry/);
    assert.equal(
      result.writes.some((w) => w.kind === "function"),
      false,
    );
  }
});

test("H enable never posts when enabled, never resends pending, and rejects operation mismatch", async () => {
  for (const options of [
    {},
    { enable: true, enablePending: true },
    { enable: true, enableMismatch: true },
  ]) {
    const world = hWorld(options);
    const result = await recordH(world.options);
    const posts = world.calls.filter((c) => c.host === "usage" && c.method === "POST");
    assert.equal(posts.length, options.enable ? 1 : 0);
    if (options.enable) {
      assert.match(result.stopped, options.enablePending ? /enable pending/ : /operation mismatch/);
      assert.equal(
        result.writes.some((w) => w.kind === "function"),
        false,
      );
    }
  }
});

test("H failed CREATE requires absence and does not close a listed FAILED function at A2", async () => {
  const { hDisposition } = await import("./eventarc-production/h-deploy.mjs");
  const { hA2 } = await import("./eventarc-production/h-record.mjs");
  for (const mode of ["run", "a2"])
    for (const read of ["present", "unknown"])
      assert.equal(hDisposition({ create: "failed", read, mode, ageMs: 600000 }).closed, false);
  const full = `projects/${m.project}/locations/us-central1/functions/${m.observe}`;
  const result = await hA2({
    recording: {
      lastRequestAt: 0,
      writes: [{ name: full, host: "functions", action: "create", state: "failed" }],
      identities: [],
      cleanup: {},
    },
    now: () => 600000,
    note: () => {},
    evidence: {
      a2ListRuling: true,
      readiness: () => true,
      retention: async () => ({ complete: true, atBaseline: true }),
    },
    transports: {
      functions: {
        request: async () => ({
          status: 200,
          body: { functions: [{ name: full, state: "FAILED" }] },
        }),
      },
    },
  });
  assert.equal(result.cleanupReady, false);
});

test("H entry rehearses with the stage C server, fsynced journal, token refresh and separate A2", async () => {
  const {
    mkdtempSync,
    mkdirSync,
    writeFileSync,
    rmSync,
    statSync,
    existsSync,
    readdirSync,
    cpSync,
  } = await import("node:fs");
  const { join } = await import("node:path");
  const { main, H_A2_RULING, readHJournal } = await import("./eventarc-production/h-run.mjs");
  const { createWorld } = await import("./eventarc-production/testing/world.mjs");
  const { serveWorld } = await import("./eventarc-production/testing/world-server.mjs");
  const dir = mkdtempSync(join(tmpdir(), "h-entry-"));
  const manifest = hManifest({ project: "fireemu-oracle-events", runId: "cafe60000001" });
  const world = hWorld({ manifest });
  const channelWorld = createWorld({ project: manifest.project, withState: true });
  const originalRequest = channelWorld.request;
  channelWorld.request = async (spec) => {
    const reply = await originalRequest(spec);
    if (reply.body?.metadata || spec.op === "getOperation") {
      reply.body.metadata ??= {};
      reply.body.metadata.target = manifest.channel;
    }
    return reply;
  };
  const server = await serveWorld(channelWorld);
  let tokenInvocations = 0;
  let a2Mode = false;
  let stopOnPublish = false;
  const ownerLedger = join(dir, "owner.md");
  writeFileSync(ownerLedger, `${H_A2_RULING}\n`);
  const config = {
    ...manifest,
    adcFile: "coordinator-supplied-owner-adc",
    depsDir: new URL("../node_modules", import.meta.url).pathname,
    firebaseJs: "unused-fake-cli",
    sourceCommit: "d756be23fc3d177db23413e1af6ee8a259fb4eb6",
    out: join(dir, "out"),
    sandboxLedger: join(dir, "sandbox.jsonl"),
    lockDir: join(dir, "locks"),
    ownerLedger,
    frozenManifest: new URL(
      "./eventarc-production/fixtures/h-fe/discovered-h.json",
      import.meta.url,
    ).pathname,
  };
  config.depsDir = join(dir, "deps");
  cpSync(new URL("../node_modules", import.meta.url).pathname, config.depsDir, {
    recursive: true,
    verbatimSymlinks: true,
  });
  const framework = join(config.depsDir, "@google-cloud/functions-framework");
  mkdirSync(framework, { recursive: true });
  // Discovery does not execute the serving framework; its package pin is a local fake.
  writeFileSync(join(framework, "package.json"), JSON.stringify({ version: "5.0.5" }));
  const input = join(dir, "input.json");
  writeFileSync(input, JSON.stringify(config));
  const launchEnv = {
    HOME: dir,
    PATH: `${dirname(realpathSync(process.execPath))}${delimiter}${process.env.PATH}`,
    GOOGLE_CLOUD_QUOTA_PROJECT: manifest.project,
  };
  const messages = [];
  const io = {
    stdout: { write: (s) => messages.push(s) },
    stderr: { write: (s) => messages.push(s) },
  };
  const deps = {
    ...world.options,
    execToken: async () => {
      tokenInvocations++;
      return "local-emulator-token-long-enough";
    },
    prepare: () => ({ fixtureDir: dir, configPath: join(dir, "firebase.json") }),
    discover: ({ directory }) => {
      mkdirSync(directory, { recursive: true });
      const frozen = readFileSync(config.frozenManifest);
      writeFileSync(join(directory, "functions-manifest.json"), frozen);
      return JSON.parse(frozen).endpoints;
    },
    runCli: async ({ plan, save }) => {
      const name = plan.args[plan.args.indexOf("--only") + 1].split(":").at(-1);
      assert.equal(plan.env.FIREBASE_TOKEN, undefined);
      assert.equal(plan.env.HOME, launchEnv.HOME);
      assert.equal(plan.env.GOOGLE_CLOUD_QUOTA_PROJECT, manifest.project);
      assert.equal(plan.env.PATH.split(delimiter)[0], dirname(realpathSync(process.execPath)));
      const result = await world.options.cli(name);
      if (name === manifest.observe)
        await channelWorld.request({
          op: "createChannel",
          method: "POST",
          path: `/v1/projects/${manifest.project}/locations/us-central1/channels?channelId=firebase`,
          body: { name: manifest.channel },
        });
      save("stdout", Buffer.from(result.stdout));
      return result;
    },
    fetchImpl: async (url, spec) => {
      const host =
        {
          serviceusage: "usage",
          cloudfunctions: "functions",
          eventarcpublishing: "publishing",
          artifactregistry: "artifact",
        }[new URL(url).hostname.split(".")[0]] ?? new URL(url).hostname.split(".")[0];
      const path = new URL(url).pathname + new URL(url).search;
      if (
        host === "eventarc" &&
        (path.endsWith("/channels/firebase") || path.includes("/operations/"))
      )
        return fetch(`${server.host}${path}`, spec);
      const issuedName = a2Mode
        ? readdirSync(config.out)
            .filter((n) => n.startsWith(`issued-${manifest.runId}-a2-`))
            .sort()
            .at(-1)
        : `issued-${manifest.runId}.jsonl`;
      const journal = readFileSync(join(config.out, issuedName), "utf8")
        .trim()
        .split("\n")
        .map(JSON.parse);
      assert.equal(journal.at(-1).kind, "request", "intent is durable before fetch");
      const reply = await world.request(host, {
        method: spec.method,
        path,
        body: spec.body && JSON.parse(spec.body),
      });
      if (host === "publishing" && stopOnPublish) {
        stopOnPublish = false;
        process.emit("SIGTERM");
      }
      return new Response(`${JSON.stringify(reply.body, null, 2)}\n`, { status: reply.status });
    },
  };
  try {
    writeFileSync(ownerLedger, "decision=APPROVE\n");
    assert.equal(await main(["--config", input], launchEnv, io, deps), 2);
    assert.equal(existsSync(config.sandboxLedger), false);
    writeFileSync(ownerLedger, `${H_A2_RULING}\n`);
    const prepareFake = deps.prepare;
    const discoverFake = deps.discover;
    delete deps.prepare;
    delete deps.discover;
    const code = await main(["--config", input], launchEnv, io, deps);
    deps.prepare = prepareFake;
    deps.discover = discoverFake;
    assert.equal(
      code,
      0,
      messages.join("") +
        (existsSync(join(config.out, "summary.json"))
          ? readFileSync(join(config.out, "summary.json"), "utf8")
          : ""),
    );
    assert.equal(tokenInvocations, 3);
    const recording = readHJournal(join(config.out, `issued-${manifest.runId}.jsonl`));
    assert.equal(
      recording.writes.filter((w) => w.kind === "function" && w.action === "create").length,
      2,
    );
    assert.equal(recording.identities.length, 2);
    assert.ok(recording.marker);
    assert.equal(recording.baseline.status, 404);
    assert.equal(statSync(join(config.out, `${manifest.observe}-stdout.txt`)).mode & 0o777, 0o600);
    assert.equal(existsSync(join(config.lockDir, `${manifest.project}.lock`)), false);
    world.setClock(recording.lastRequestAt + 600000);
    a2Mode = true;
    const a2code = await main(["--config", input, "--a2"], launchEnv, io, deps);
    assert.equal(
      a2code,
      0,
      messages.join("") +
        readFileSync(
          join(
            config.out,
            readdirSync(config.out).find((n) => n.startsWith("summary-a2")),
          ),
          "utf8",
        ),
    );
    const rows = readFileSync(config.sandboxLedger, "utf8").trim().split("\n").map(JSON.parse);
    assert.deepEqual(
      rows.map((r) => r.event),
      ["started", "finished", "started", "finished"],
    );
    assert.ok(
      rows.every(
        (r) =>
          r.envelopeId === `EVENTARC-H-${manifest.runId}` && typeof r.estimatedUsd === "number",
      ),
    );
    assert.ok(
      rows
        .filter((r) => r.event === "finished")
        .every((r) => r.sandboxAtBaseline && r.lockRetained === false),
    );
    config.out = join(dir, "signal-out");
    writeFileSync(input, JSON.stringify(config));
    a2Mode = false;
    stopOnPublish = true;
    assert.equal(await main(["--config", input], launchEnv, io, deps), 3);
    const interrupted = readHJournal(join(config.out, `issued-${manifest.runId}.jsonl`));
    assert.equal(interrupted.stopped, "H signal");
    assert.equal(interrupted.publishes.length, 1);
    assert.equal(interrupted.identities.length, 2);
    const requests = readFileSync(join(config.out, `issued-${manifest.runId}.jsonl`), "utf8")
      .trim()
      .split("\n")
      .map(JSON.parse);
    assert.equal(
      requests.filter((r) => r.kind === "request").length,
      requests.filter((r) => r.kind === "answer").length,
    );
    assert.equal(existsSync(join(config.lockDir, `${manifest.project}.lock`)), true);
    world.setClock(interrupted.lastRequestAt + 599999);
    assert.equal(await main(["--config", input, "--a2"], launchEnv, io, deps), 1);
    world.setClock(interrupted.lastRequestAt + 600000);
    deps.checkPid = () => {
      throw Object.assign(new Error("fake reaped recorder"), { code: "ESRCH" });
    };
    a2Mode = true;
    assert.equal(await main(["--config", input, "--a2"], launchEnv, io, deps), 1);
    assert.equal(existsSync(join(config.lockDir, `${manifest.project}.lock`)), false);
    assert.equal(process.listenerCount("SIGTERM"), 0);
    config.out = join(dir, "cli-signal-out");
    writeFileSync(input, JSON.stringify(config));
    a2Mode = false;
    const { spawn } = await import("node:child_process");
    const { runHCli } = await import("./eventarc-production/h-deploy.mjs");
    let child;
    deps.evidence = {
      ...deps.evidence,
      cliWrites: (await import("./eventarc-production/h-production.mjs")).hProductionEvidence
        .cliWrites,
    };
    deps.runCli = (options) =>
      runHCli({
        ...options,
        firebaseJs: "--eval",
        plan: { ...options.plan, args: ["console.log('ready');setInterval(()=>{},1000)"] },
        save: (stream, chunk) => {
          options.save(stream, chunk);
          if (chunk.toString().includes("ready")) process.emit("SIGTERM");
        },
        spawnFn: (...args) => {
          child = spawn(...args);
          return child;
        },
      });
    try {
      assert.equal(await main(["--config", input], launchEnv, io, deps), 3);
      assert.throws(() => process.kill(child.pid, 0), { code: "ESRCH" });
      const killed = readHJournal(join(config.out, `issued-${manifest.runId}.jsonl`));
      assert.equal(killed.writes.find((w) => w.kind === "function").state, "unknown");
    } finally {
      if (child?.exitCode === null && child?.signalCode === null) child.kill("SIGKILL");
    }
    assert.equal(process.listenerCount("SIGTERM"), 0);
  } finally {
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("H slow pending DELETE closes only at A2 600 seconds and target mismatch fails closed", async () => {
  const { hA2 } = await import("./eventarc-production/h-record.mjs");
  const world = hWorld({ functionDeleteMs: 130000 });
  const recording = await recordH(world.options);
  assert.equal(recording.closureReady, false);
  assert.equal(
    recording.writes
      .filter((w) => w.action === "delete" && w.host === "functions")
      .every((w) => w.state === "pending"),
    true,
  );
  world.setClock(recording.lastRequestAt + 599999);
  await assert.rejects(hA2({ ...world.options, recording }), /ten minutes/);
  world.setClock(recording.lastRequestAt + 600000);
  const a2 = await hA2({ ...world.options, recording });
  assert.equal(a2.closureReady, true);
  assert.ok(world.deleted.includes("firebase"));
  const broken = hWorld({ functionDeleteMs: 25000 });
  const request = broken.options.transports.functions.request;
  broken.options.transports.functions.request = async (spec) => {
    const reply = await request(spec);
    if (spec.path.includes("/operations/")) reply.body.metadata.target += "-other";
    return reply;
  };
  assert.equal((await recordH(broken.options)).closureReady, false);
});

test("H A2 does not delete a channel with dependents or replay a previous marker DELETE", async () => {
  const { hA2 } = await import("./eventarc-production/h-record.mjs");
  const marker = `projects/${m.project}/databases/(default)/documents/${m.markerCollection}/owned`;
  const recording = {
    manifest: m,
    baseline: { status: 404 },
    lastRequestAt: 0,
    cleanup: {},
    identities: [],
    writes: [
      { name: marker, host: "firestore", action: "create", state: "confirmed" },
      { name: marker, host: "firestore", action: "delete", state: "unknown" },
      { name: m.channel, host: "eventarc", action: "create", state: "confirmed" },
    ],
    marker,
  };
  const calls = [];
  const result = await hA2({
    recording,
    now: () => 600000,
    note: () => {},
    evidence: {
      a2ListRuling: true,
      readiness: () => true,
      notFound: (r) => r.status === 404,
      retention: async () => ({ complete: true, atBaseline: true }),
    },
    transports: Object.fromEntries(
      ["firestore", "eventarc"].map((host) => [
        host,
        {
          request: async (spec) => {
            calls.push(spec);
            return {
              status: 200,
              body: spec.path.endsWith("/triggers")
                ? { triggers: [{ name: "dependent", channel: m.channel }] }
                : { name: spec.path.slice(4) },
            };
          },
        },
      ]),
    ),
  });
  assert.equal(result.cleanupReady, false);
  assert.equal(
    calls.some((c) => c.method === "DELETE"),
    false,
  );
  recording.writes = recording.writes.filter((w) => w.name === m.channel);
  calls.length = 0;
  await hA2({
    recording,
    now: () => 600000,
    note: () => {},
    evidence: {
      a2ListRuling: true,
      readiness: () => true,
      notFound: () => false,
      retention: async () => ({ complete: true, atBaseline: true }),
    },
    transports: {
      eventarc: {
        request: async (spec) => {
          calls.push(spec);
          return {
            status: 200,
            body: spec.path.endsWith("/triggers")
              ? { triggers: [{ name: "dependent", channel: m.channel }] }
              : { name: m.channel },
          };
        },
      },
    },
  });
  assert.equal(
    calls.some((c) => c.method === "DELETE"),
    false,
  );
});

test("H journal recovers an incomplete tail but refuses a malformed completed row", async () => {
  const { mkdtempSync, writeFileSync, rmSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { readHJournal } = await import("./eventarc-production/h-run.mjs");
  const dir = mkdtempSync(join(tmpdir(), "h-tail-"));
  const path = join(dir, `issued-${m.runId}.jsonl`);
  const prefix = `${JSON.stringify({ kind: "h-state", value: { writes: [], identities: [], marker: "owned", baseline: {}, cleanup: { unconfirmed: [] } } })}\n${JSON.stringify({ kind: "request", at: 123 })}\n`;
  try {
    writeFileSync(path, prefix + '{"kind":"answer"');
    assert.equal(readHJournal(path).lastRequestAt, 123);
    writeFileSync(path, prefix + "broken\n");
    assert.throws(() => readHJournal(path), SyntaxError);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("H owned CLI journals each write before native send and fsyncs native answers", async () => {
  const { mkdtempSync, writeFileSync, rmSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { spawn } = await import("node:child_process");
  const { runHCli } = await import("./eventarc-production/h-deploy.mjs");
  const dir = mkdtempSync(join(tmpdir(), "h-native-"));
  const journal = join(dir, "issued.jsonl");
  const preload = join(dir, "fake-https.mjs");
  writeFileSync(journal, "");
  writeFileSync(
    preload,
    `import https from 'node:https'; import { EventEmitter } from 'node:events'; import { readFileSync } from 'node:fs';
https.request = (...args) => { const req = new EventEmitter(); const callback = args.find((arg)=>typeof arg === 'function'); if(callback) req.on('response', callback); Object.assign(req, { host: 'cloudfunctions.googleapis.com', method: 'POST', path: '/v2/projects/demo/functions?secret=private' });
const check = () => { const rows = readFileSync(process.env.EVENTARC_H_ISSUED_JOURNAL,'utf8').trim().split('\\n').map(JSON.parse); if (rows.at(-1).kind !== 'cli-native-issued') throw Error('sent before durable intent'); };
req.write = check; req.flushHeaders = check; req.end = () => { check(); const response = new EventEmitter(); response.statusCode=200; req.emit('response', response); response.emit('data', Buffer.from('{}')); response.emit('end'); }; return req; };
`,
  );
  try {
    const result = await runHCli({
      node: process.execPath,
      firebaseJs: "--eval",
      issuedPath: journal,
      plan: {
        cwd: dir,
        env: {},
        args: [
          "const https=require('node:https');const r=https.request({},(res)=>res.once('end',()=>{const rows=require('node:fs').readFileSync(process.env.EVENTARC_H_ISSUED_JOURNAL,'utf8').trim().split('\\n').map(JSON.parse);if(rows.at(-1).kind!=='cli-native-answer')throw Error('callback before durable answer');}));r.flushHeaders();r.write('{}');r.end();console.log('0 Functions Errored');",
        ],
      },
      save: () => {},
      spawnFn: (node, args, opts) => spawn(node, ["--import", preload, ...args], opts),
    });
    assert.equal(result.exitCode, 0);
    const rows = readFileSync(journal, "utf8").trim().split("\n").map(JSON.parse);
    assert.deepEqual(
      rows.map((r) => r.kind),
      ["cli-native-issued", "cli-native-answer"],
    );
    assert.equal(rows[0].value.path.includes("secret"), false);
    assert.equal(rows[1].value.bodyBase64, "e30=");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("H marker gate requires two confirmed function attempts", async () => {
  const world = hWorld();
  let stops = 0;
  world.options.shouldStop = () => ++stops > 1;
  const result = await recordH(world.options);
  assert.equal(
    result.writes.filter((w) => w.kind === "function" && w.action === "create").length,
    1,
  );
  assert.equal(
    world.calls.some(
      (c) =>
        c.host === "firestore" && c.label?.case === "h-cleanup" && c.path.includes("/documents/"),
    ),
    false,
  );
});

test("H pinned CLI fetch and undici paths journal before MockAgent send and replay native bodies", async () => {
  const { mkdtempSync, mkdirSync, writeFileSync, rmSync, symlinkSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { runHCli } = await import("./eventarc-production/h-deploy.mjs");
  const dir = mkdtempSync(join(tmpdir(), "h-fetch-"));
  const journal = join(dir, "issued.jsonl");
  const script = join(dir, "cli.cjs");
  const packageDir = new URL("../node_modules/firebase-tools/", import.meta.url).pathname;
  mkdirSync(join(dir, "node_modules"));
  symlinkSync(join(packageDir, "node_modules/undici"), join(dir, "node_modules/undici"));
  writeFileSync(journal, "");
  writeFileSync(
    script,
    `const assert=require('node:assert/strict');const fs=require('node:fs');const undici=require('undici');
const {Client}=require(${JSON.stringify(join(packageDir, "lib/apiv2.js"))});
const mock=new undici.MockAgent();mock.disableNetConnect();undici.setGlobalDispatcher(mock);
const rows=()=>fs.readFileSync(process.env.EVENTARC_H_ISSUED_JOURNAL,'utf8').trim().split('\\n').map(JSON.parse);
(async()=>{for(const [path,compress] of [['/v2/fetch',true],['/v2/undici',false]]){
mock.get('https://cloudfunctions.googleapis.com').intercept({path,method:'POST'}).reply(()=>{assert.equal(rows().at(-1).kind,'cli-native-issued');return {statusCode:200,data:'{\\n  "accepted": true\\n}\\n'};});
const reply=await new Client({urlPrefix:'https://cloudfunctions.googleapis.com',apiVersion:'v2',auth:false}).request({method:'POST',path:path.slice(3),body:{},compress,responseType:'json'});
assert.deepEqual(reply.body,{accepted:true});assert.equal(rows().at(-1).kind,'cli-native-answer');}
assert.deepEqual(rows().map(r=>r.kind),['cli-native-issued','cli-native-answer','cli-native-issued','cli-native-answer']);
await mock.close();console.log('0 Functions Errored');})().catch(e=>{console.error(e);process.exitCode=1;});
`,
  );
  try {
    const result = await runHCli({
      node: process.execPath,
      firebaseJs: script,
      issuedPath: journal,
      plan: { cwd: dir, env: { HOME: dir, XDG_CONFIG_HOME: join(dir, ".config") }, args: [] },
      save: () => {},
    });
    assert.equal(result.exitCode, 0, result.stderr);
    const rows = readFileSync(journal, "utf8").trim().split("\n").map(JSON.parse);
    assert.equal(rows.length, 4);
    assert.ok(
      rows
        .filter((r) => r.kind === "cli-native-answer")
        .every(
          (r) =>
            Buffer.from(r.value.bodyBase64, "base64").toString() === '{\n  "accepted": true\n}\n',
        ),
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("H journal restores interrupted channel ownership and counts native CLI timestamps", async (t) => {
  const { readHJournal } = await import("./eventarc-production/h-run.mjs");
  const dir = mkdtempSync(join(tmpdir(), "h-replay-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, `issued-${m.runId}.jsonl`);
  const recording = {
    manifest: m,
    writes: [],
    baseline: { status: 404 },
    cleanup: { unconfirmed: [] },
  };
  const rows = [
    { kind: "h-state", value: recording },
    { kind: "cli-issued", at: 100, value: { name: m.observe } },
    {
      kind: "cli-native-issued",
      at: 200,
      value: {
        host: "eventarc.googleapis.com",
        method: "POST",
        path: `/v1/projects/${m.project}/locations/us-central1/channels`,
      },
    },
  ];
  writeFileSync(path, rows.map(JSON.stringify).join("\n") + "\n");
  let restored = readHJournal(path);
  assert.equal(restored.lastRequestAt, 200);
  assert.deepEqual(restored.writes, [
    { name: m.channel, host: "eventarc", kind: "channel", action: "create", state: "unknown" },
  ]);
  assert.deepEqual(restored.cleanup.unconfirmed, [`cli:${m.observe}:interrupted-inventory`]);
  rows.push({ kind: "cli-native-answer", at: 300, value: { status: 200 } });
  writeFileSync(path, rows.map(JSON.stringify).join("\n") + "\n");
  assert.equal(readHJournal(path).lastRequestAt, 300);
  rows.push({ kind: "h-state", value: { ...recording, writes: restored.writes } });
  writeFileSync(path, rows.map(JSON.stringify).join("\n") + "\n");
  assert.deepEqual(readHJournal(path).cleanup.unconfirmed, []);
});

test("H A2 keeps its own unknown DELETE sticky despite an immediate 404", async () => {
  const { hA2 } = await import("./eventarc-production/h-record.mjs");
  for (const host of ["firestore", "eventarc"]) {
    const name =
      host === "eventarc"
        ? m.channel
        : `projects/${m.project}/databases/(default)/documents/${m.markerCollection}/owned`;
    const recording = {
      manifest: m,
      marker: host === "firestore" ? name : undefined,
      baseline: { status: 404 },
      lastRequestAt: 0,
      cleanup: {},
      identities: [],
      writes: [{ name, host, action: "create", state: "confirmed" }],
    };
    let deleted = false;
    let deletes = 0;
    const result = await hA2({
      recording,
      now: () => 600000,
      note: () => {},
      evidence: {
        readiness: () => true,
        notFound: (r) => r.status === 404,
        retention: async () => ({ complete: true, atBaseline: true }),
      },
      transports: {
        [host]: {
          request: async (spec) => {
            if (spec.method === "DELETE") {
              deleted = true;
              deletes++;
              return { status: 503, unknown: true, body: {} };
            }
            if (spec.path.endsWith("/triggers")) return { status: 200, body: { triggers: [] } };
            return deleted ? { status: 404, body: {} } : { status: 200, body: { name } };
          },
        },
      },
    });
    assert.equal(deletes, 1);
    assert.equal(result.facts[0].read, "absent");
    assert.equal(result.facts[0].closed, false);
    assert.equal(result.cleanupReady, false);
  }
});

test("H A2 refuses marker and channel DELETE until all earlier facts close and the channel baseline is absent", async () => {
  const { hA2 } = await import("./eventarc-production/h-record.mjs");
  for (const scenario of ["function-present", "channel-preexisting", "inventory-unconfirmed"]) {
    const marker = `projects/${m.project}/databases/(default)/documents/${m.markerCollection}/owned`;
    const full = `projects/${m.project}/locations/us-central1/functions/${m.observe}`;
    const recording = {
      manifest: m,
      marker,
      baseline: { status: scenario === "channel-preexisting" ? 200 : 404 },
      lastRequestAt: 0,
      cleanup: { unconfirmed: scenario === "inventory-unconfirmed" ? ["opaque-cli-write"] : [] },
      identities: [],
      writes: [
        ...(scenario === "function-present"
          ? [{ name: full, host: "functions", action: "create", state: "confirmed" }]
          : []),
        ...(scenario === "channel-preexisting"
          ? []
          : [{ name: marker, host: "firestore", action: "create", state: "confirmed" }]),
        { name: m.channel, host: "eventarc", action: "create", state: "confirmed" },
      ],
    };
    const deletes = [];
    const result = await hA2({
      recording,
      now: () => 600000,
      note: () => {},
      evidence: { a2ListRuling: true, readiness: () => true, notFound: () => false },
      transports: Object.fromEntries(
        ["functions", "firestore", "eventarc"].map((host) => [
          host,
          {
            request: async (spec) => {
              if (spec.method === "DELETE") deletes.push(spec.path);
              return {
                status: 200,
                body: spec.path.endsWith("/functions")
                  ? { functions: [{ name: full }] }
                  : spec.path.endsWith("/triggers")
                    ? { triggers: [] }
                    : { name: spec.path.slice(4) },
              };
            },
          },
        ]),
      ),
    });
    assert.deepEqual(deletes, [], scenario);
    assert.equal(result.cleanupReady, false);
  }
});

test("H entry refuses live, foreign and changed recovery locks before adoption", async (t) => {
  const { main, H_A2_RULING } = await import("./eventarc-production/h-run.mjs");
  const dir = mkdtempSync(join(tmpdir(), "h-lock-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const manifest = hManifest({ project: "fireemu-oracle-events", runId: m.runId });
  const config = {
    ...manifest,
    sourceCommit: "d9d63ab0433f049badc3726dca932e14cc2e291c",
    out: join(dir, "out"),
    sandboxLedger: join(dir, "sandbox.jsonl"),
    lockDir: join(dir, "locks"),
    ownerLedger: join(dir, "owner.md"),
    frozenManifest: "unused",
    adcFile: "unused",
    depsDir: "unused",
    firebaseJs: "unused",
  };
  mkdirSync(config.out);
  mkdirSync(config.lockDir, { mode: 0o700 });
  writeFileSync(config.ownerLedger, H_A2_RULING + "\n");
  writeFileSync(
    join(config.out, `issued-${m.runId}.jsonl`),
    [
      {
        kind: "h-state",
        value: {
          manifest: { ...manifest, projectNumber: "123456789012" },
          writes: [],
          cleanup: {},
          identities: [],
        },
      },
      { kind: "request", at: 0 },
    ]
      .map(JSON.stringify)
      .join("\n") + "\n",
  );
  const input = join(dir, "input.json");
  writeFileSync(input, JSON.stringify(config));
  const path = join(config.lockDir, `${manifest.project}.lock`);
  const own = {
    taskId: "PUBSUB-EVENTARC",
    packetId: `EVENTARC-H-${m.runId}`,
    sourceCommit: config.sourceCommit,
    pid: process.pid,
  };
  for (const scenario of ["live", "task", "packet", "source", "pid", "body", "inode"]) {
    const lock = {
      ...own,
      ...(scenario === "task"
        ? { taskId: "OTHER" }
        : scenario === "packet"
          ? { packetId: "OTHER" }
          : scenario === "source"
            ? { sourceCommit: "0".repeat(40) }
            : scenario === "pid"
              ? { pid: -1 }
              : {}),
    };
    writeFileSync(path, JSON.stringify(lock));
    let message = "";
    const code = await main(
      ["--config", input, "--a2"],
      { HOME: dir, PATH: dirname(realpathSync(process.execPath)) },
      { stdout: { write: () => {} }, stderr: { write: (s) => (message += s) } },
      {
        now: () => 600000,
        checkPid: () => {
          if (scenario === "live") return;
          if (scenario === "body") writeFileSync(path, JSON.stringify({ ...lock, changed: true }));
          if (scenario === "inode") {
            renameSync(path, path + ".old");
            writeFileSync(path, JSON.stringify(lock));
          }
          throw Object.assign(new Error("dead test PID"), { code: "ESRCH" });
        },
        fetchImpl: () => {
          throw new Error("unexpected request");
        },
        execToken: () => {
          throw new Error("unexpected credential call");
        },
      },
    );
    assert.equal(code, 1, scenario);
    assert.match(
      message,
      scenario === "live"
        ? /recorder process is still alive/
        : ["body", "inode"].includes(scenario)
          ? /recovery lock changed/
          : /foreign recovery lock/,
      scenario,
    );
    assert.equal(existsSync(path), true);
    assert.equal(existsSync(config.sandboxLedger), false);
  }
});

test("H entry refuses discovery drift without requests or writes and releases a stopped-clean lock", async (t) => {
  const { main, H_A2_RULING } = await import("./eventarc-production/h-run.mjs");
  const dir = mkdtempSync(join(tmpdir(), "h-discovery-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const manifest = hManifest({ project: "fireemu-oracle-events", runId: m.runId });
  const config = {
    ...manifest,
    sourceCommit: "d9d63ab0433f049badc3726dca932e14cc2e291c",
    out: join(dir, "out"),
    sandboxLedger: join(dir, "sandbox.jsonl"),
    lockDir: join(dir, "locks"),
    ownerLedger: join(dir, "owner.md"),
    frozenManifest: join(dir, "frozen.json"),
    adcFile: "unused",
    depsDir: "unused",
    firebaseJs: "unused",
  };
  writeFileSync(config.ownerLedger, H_A2_RULING + "\n");
  const frozen = { endpoints: { frozen: {} }, requiredAPIs: [] };
  writeFileSync(config.frozenManifest, JSON.stringify(frozen));
  const input = join(dir, "input.json");
  writeFileSync(input, JSON.stringify(config));
  const env = { HOME: dir, PATH: dirname(realpathSync(process.execPath)) };
  let messages = "";
  const io = { stdout: { write: () => {} }, stderr: { write: (s) => (messages += s) } };
  for (const badPath of ["", join(dir, "volta/bin")]) {
    assert.equal(await main(["--config", input], { ...env, PATH: badPath }, io), 2);
    assert.match(messages, /real Node 24.14.0 bin first on PATH/);
    assert.equal(existsSync(config.sandboxLedger), false);
  }
  for (const drift of ["endpoints", "metadata", "missing-evidence"]) {
    config.out = join(dir, drift);
    writeFileSync(input, JSON.stringify(config));
    messages = "";
    const code = await main(["--config", input], env, io, {
      evidence: {},
      prepare: () => ({}),
      discover: ({ directory }) => {
        mkdirSync(directory, { recursive: true });
        const discovered =
          drift === "metadata"
            ? { ...frozen, requiredAPIs: ["unexpected"] }
            : drift === "endpoints"
              ? { ...frozen, endpoints: {} }
              : frozen;
        writeFileSync(join(directory, "functions-manifest.json"), JSON.stringify(discovered));
        return discovered.endpoints;
      },
      fetchImpl: () => {
        throw new Error("unexpected request");
      },
      execToken: () => {
        throw new Error("unexpected credential call");
      },
    });
    assert.equal(code, 1);
    if (drift === "missing-evidence")
      assert.match(
        JSON.parse(readFileSync(join(config.out, "summary.json"), "utf8")).stopped,
        /shape evidence/,
      );
    else assert.match(messages, /discovery differs from frozen/);
    const rows = readFileSync(config.sandboxLedger, "utf8").trim().split("\n").map(JSON.parse);
    const finished = rows.at(-1);
    assert.equal(finished.outcome, "stopped-clean");
    assert.equal(finished.requests, 0);
    assert.equal(finished.estimatedUsd, 0);
    assert.equal(finished.sandboxAtBaseline, true);
    assert.equal(finished.lockRetained, false);
    assert.equal(existsSync(join(config.lockDir, `${manifest.project}.lock`)), false);
  }
});

test("H partial deploy inventories managed children before their function DELETE cascade", async () => {
  const world = hWorld({ partial: true });
  const result = await recordH(world.options);
  assert.equal(result.identities.length, 1);
  assert.equal(
    result.cleanup.unconfirmed.some((n) => n.includes("managed-inventory")),
    false,
  );
  const deletion = world.calls.findIndex((c) => c.host === "functions" && c.method === "DELETE");
  assert.ok(
    deletion >
      world.calls.findIndex(
        (c) =>
          c.host === "eventarc" && c.label?.case === "h-cleanup" && c.path.endsWith("/triggers"),
      ),
  );
  assert.equal(world.deleted.includes(m.observe), true);
  const unreadable = hWorld({ partial: true, badChild: true });
  await recordH(unreadable.options);
  assert.equal(unreadable.deleted.includes(m.observe), true);
});

// Projection of H1 v4 summary.json and summary-a2-20261006T075832Z.json; no native secrets.
const hV4Recording = {
  manifest: {
    project: "fireemu-oracle-events",
    runId: "a4b6c8d0e2f4",
    channel: "projects/fireemu-oracle-events/locations/us-central1/channels/firebase",
  },
  stopped: "H deploy failed; no redeploy",
  cleanup: {
    unconfirmed: [
      "projects/fireemu-oracle-events/locations/us-central1/functions/fea4b6c8d0e2f4HFiltered",
      "projects/fireemu-oracle-events/locations/us-central1/channels/firebase",
    ],
    unsettled: ["projects/fireemu-oracle-events/topics/eventarc-channel-us-central1-firebase-956"],
  },
  baseline: { status: 404 },
  identities: [
    {
      function:
        "projects/fireemu-oracle-events/locations/us-central1/functions/fea4b6c8d0e2f4HObserve",
      service:
        "projects/fireemu-oracle-events/locations/us-central1/services/fea4b6c8d0e2f4hobserve",
      trigger:
        "projects/fireemu-oracle-events/locations/us-central1/triggers/fea4b6c8d0e2f4hobserve-705370",
      topic: "projects/fireemu-oracle-events/topics/eventarc-channel-us-central1-firebase-956",
      subscription:
        "projects/fireemu-oracle-events/subscriptions/eventarc-us-central1-fea4b6c8d0e2f4hobserve-705370-sub-863",
    },
  ],
  writes: [
    {
      name: "projects/fireemu-oracle-events/locations/us-central1/functions/fea4b6c8d0e2f4HObserve",
      host: "functions",
      action: "create",
      state: "confirmed",
    },
    {
      name: "projects/fireemu-oracle-events/locations/us-central1/channels/firebase",
      host: "eventarc",
      action: "create",
      state: "confirmed",
    },
    {
      name: "projects/fireemu-oracle-events/locations/us-central1/functions/fea4b6c8d0e2f4HFiltered",
      host: "functions",
      action: "create",
      state: "unknown",
    },
    {
      name: "projects/fireemu-oracle-events/locations/us-central1/functions/fea4b6c8d0e2f4HObserve",
      host: "functions",
      action: "delete",
      state: "confirmed",
    },
  ],
  lastRequestAt: 0,
};
const hV4Facts = [
  {
    name: "projects/fireemu-oracle-events/locations/us-central1/functions/fea4b6c8d0e2f4HObserve",
    read: "absent",
    confirmed: true,
    closed: true,
    canDelete: false,
    unconfirmed: false,
  },
  {
    name: "projects/fireemu-oracle-events/locations/us-central1/functions/fea4b6c8d0e2f4HFiltered",
    read: "absent",
    confirmed: false,
    closed: false,
    canDelete: false,
    unconfirmed: true,
  },
  {
    name: "projects/fireemu-oracle-events/locations/us-central1/services/fea4b6c8d0e2f4hobserve",
    read: "absent",
    confirmed: true,
    closed: true,
    canDelete: false,
    unconfirmed: false,
  },
  {
    name: "projects/fireemu-oracle-events/locations/us-central1/triggers/fea4b6c8d0e2f4hobserve-705370",
    read: "absent",
    confirmed: true,
    closed: true,
    canDelete: false,
    unconfirmed: false,
  },
  {
    name: "projects/fireemu-oracle-events/topics/eventarc-channel-us-central1-firebase-956",
    read: "present",
    confirmed: true,
    closed: false,
    canDelete: false,
    unconfirmed: false,
  },
  {
    name: "projects/fireemu-oracle-events/subscriptions/eventarc-us-central1-fea4b6c8d0e2f4hobserve-705370-sub-863",
    read: "absent",
    confirmed: true,
    closed: true,
    canDelete: false,
    unconfirmed: false,
  },
  {
    name: "projects/fireemu-oracle-events/locations/us-central1/channels/firebase",
    read: "present",
    confirmed: true,
    closed: false,
    canDelete: true,
    unconfirmed: false,
  },
];

test("H A2 replays v4 channel topic dependency without accepting the refused unknown CREATE", async () => {
  const { hA2 } = await import("./eventarc-production/h-record.mjs");
  for (const scenario of [
    "original",
    "settled",
    "settled-marker",
    "unrelated-topic",
    "topic-stays",
    "unknown-delete",
    "missing-topic",
    "foreign-topic",
    "dependent-trigger",
    "preexisting-channel",
  ]) {
    const recording = structuredClone(hV4Recording);
    const channel = recording.manifest.channel;
    const topic = recording.identities[0].topic;
    // Only the replay input models external settlement; production code never accepts unknown CREATE.
    if (scenario !== "original")
      recording.writes.find((w) => w.name.endsWith("HFiltered")).state = "failed";
    if (scenario === "unrelated-topic") recording.cleanup.unsettled.push(`${topic}-unowned`);
    if (scenario === "preexisting-channel") recording.baseline.status = 200;
    if (scenario === "settled-marker") {
      recording.marker =
        "projects/fireemu-oracle-events/databases/(default)/documents/fe_h_a4b6c8d0e2f4/owned";
      recording.writes.push({
        name: recording.marker,
        host: "firestore",
        action: "create",
        state: "confirmed",
      });
      recording.cleanup.unsettled.push(recording.marker);
    }
    let deleted = false;
    let markerDeleted = false;
    const calls = [];
    const result = await hA2({
      recording,
      now: () => 600000,
      note: () => {},
      evidence: {
        a2ListRuling: true,
        readiness: () => true,
        notFound: (r) => r.status === 404,
        retention: async () => ({ complete: true, atBaseline: true }),
      },
      transports: Object.fromEntries(
        ["functions", "run", "eventarc", "pubsub", "firestore"].map((host) => [
          host,
          {
            request: async (spec) => {
              calls.push({ host, ...spec });
              if (host === "firestore") {
                if (spec.method === "DELETE") {
                  assert.equal(deleted, true);
                  assert.equal(spec.path, `/v1/${recording.marker}`);
                  markerDeleted = true;
                  return { status: 200, body: {} };
                }
                return markerDeleted
                  ? { status: 404, body: {} }
                  : { status: 200, body: { name: recording.marker } };
              }
              if (spec.method === "DELETE") {
                assert.equal(host, "eventarc");
                assert.equal(spec.path, `/v1/${channel}`);
                deleted = true;
                return scenario === "unknown-delete"
                  ? { status: 503, unknown: true, body: {} }
                  : {
                      status: 200,
                      body: {
                        name: "projects/fireemu-oracle-events/locations/us-central1/operations/delete-channel",
                        metadata: { target: channel },
                        done: true,
                      },
                    };
              }
              if (spec.path === `/v1/${channel}`)
                return deleted
                  ? { status: 404, body: {} }
                  : {
                      status: 200,
                      body: {
                        name: channel,
                        ...(scenario === "missing-topic"
                          ? {}
                          : {
                              pubsubTopic:
                                scenario === "foreign-topic"
                                  ? "projects/foreign-project/topics/foreign"
                                  : topic,
                            }),
                      },
                    };
              const key = spec.path.split("?")[0].split("/").at(-1);
              const items =
                key === "topics" && (!deleted || scenario === "topic-stays")
                  ? [{ name: topic }]
                  : key === "triggers" && scenario === "dependent-trigger"
                    ? [{ name: "dependent", channel }]
                    : [];
              return { status: 200, body: { [key]: items } };
            },
          },
        ]),
      ),
    });
    if (scenario === "original") {
      assert.deepEqual(result.facts, hV4Facts);
      assert.deepEqual(result.unresolvedInventory, [
        ...recording.cleanup.unconfirmed,
        ...recording.cleanup.unsettled,
      ]);
      assert.equal(recording.writes.find((w) => w.name.endsWith("HFiltered")).state, "unknown");
    }
    const shouldDelete = ["settled", "settled-marker", "topic-stays", "unknown-delete"].includes(
      scenario,
    );
    assert.equal(deleted, shouldDelete, scenario);
    assert.equal(result.cleanupReady, ["settled", "settled-marker"].includes(scenario), scenario);
    if (shouldDelete) {
      const deletionIndex = calls.findIndex((c) => c.method === "DELETE");
      assert.equal(
        calls
          .slice(deletionIndex + 1)
          .some((c) => c.host === "pubsub" && c.path.includes("/topics")),
        true,
        scenario,
      );
      assert.equal(
        result.facts.find((f) => f.name === topic).read,
        scenario === "topic-stays" ? "present" : "absent",
        scenario,
      );
      assert.equal(
        result.facts.find((f) => f.name === topic).closed,
        ["settled", "settled-marker"].includes(scenario),
        scenario,
      );
    }
    assert.equal(result.closureReady, false, scenario);
  }
});

test("H controls require a matching type receipt for each handler before continuing", async () => {
  const world = hWorld();
  const request = world.options.transports.logging.request;
  world.options.transports.logging.request = async (spec) => {
    const reply = await request(spec);
    const entries = structuredClone(reply.body.entries ?? []);
    const observed = entries
      .map((e) => JSON.parse(e.textPayload.slice("FE_EVENTS_FRAME ".length)))
      .find((f) => f.handler === m.observe);
    for (const entry of entries) {
      const frame = JSON.parse(entry.textPayload.slice("FE_EVENTS_FRAME ".length));
      if (frame.handler !== m.filtered || !observed) continue;
      frame.event = observed.event;
      frame.correlation = observed.correlation;
      frame.eventKeys = observed.eventKeys;
      entry.textPayload = `FE_EVENTS_FRAME ${JSON.stringify(frame)}`;
    }
    return { ...reply, body: { ...reply.body, entries } };
  };
  const result = await recordH(world.options);
  assert.equal(result.stopped, "H control missing");
  assert.equal(result.publishes.length, 1);
  assert.equal(result.closureReady, false);
});

test("H2 successor authority is exact to one fresh run and preserves legacy default loader guards", async (t) => {
  const { spawnSync } = await import("node:child_process");
  const { H_A2_RULING, H2_A2_RULING, H2_SUCCESSOR_RUN_ID, H2_SUCCESSOR_A2_RULING } =
    await import("./eventarc-production/h-run.mjs");
  const runId = "ea3c9a8129ff";
  const expectedRuling = H2_A2_RULING.replace(
    "- 2026-10-07 | EVENTARC-H2 A2 list settlement |",
    "- 2026-10-08 | EVENTARC-H2-A-SUCCESSOR A2 list settlement |",
  )
    .replace(
      "for EVENTARC packet H2 recordings (H2-A and H2-B) on fireemu-oracle-events,",
      `for only the fresh EVENTARC H2-A successor recording run ${runId} on fireemu-oracle-events, with seven original A exports and the unchanged A2 maximum of 105 REST requests, three-hour invocation wall, and at least 600 seconds after its latest persisted request,`,
    )
    .replace(
      "Claude（委任。オーナーの裁量の委任 2026-09-28）",
      "Codex coordinator（委任。オーナー台帳365/395/996/998）",
    )
    .replace(
      "docs.local/reviews/2026-10-07-eventarc-h2-presend-review.md",
      "docs.local/runs/coordinator-codex-20261007/eventarc-h2-successor-packet/packet.md",
    );
  const dir = mkdtempSync(join(tmpdir(), "h2-successor-guard-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const preload = join(dir, "no-wire.mjs");
  writeFileSync(
    preload,
    `import fs from 'node:fs'; import cp from 'node:child_process'; import http from 'node:http'; import https from 'node:https'; import net from 'node:net'; import { syncBuiltinESMExports } from 'node:module';
const refuse = name => () => { fs.appendFileSync(process.env.H_NO_WIRE_LOG, name + '\\n'); throw new Error('OFFLINE_GUARD: ' + name); };
for (const name of ['execFile','execFileSync','execSync','spawn','spawnSync','exec']) cp[name] = refuse(name);
for (const mod of [http,https]) for (const name of ['request','get']) mod[name] = refuse(name);
net.Socket.prototype.connect = refuse('connect'); globalThis.fetch = refuse('fetch'); syncBuiltinESMExports();`,
  );
  const cases = [
    { name: "fresh", cap: 25, ruling: expectedRuling, accepted: true },
    { name: "legacy-a", cap: 14, runId: "012345abcdef", ruling: H2_A2_RULING, accepted: true },
    {
      name: "legacy-b",
      cap: 14,
      runId: "012345abcdef",
      recording: "h2-b",
      reserve: 6,
      ruling: H2_A2_RULING,
      accepted: true,
    },
    { name: "legacy-h1", recording: "h1", ruling: H_A2_RULING, accepted: true },
    { name: "fresh-old-cap", cap: 14, ruling: expectedRuling, gate: /parent budget/ },
    {
      name: "fresh-previous-proposal-cap",
      cap: 20.3,
      ruling: expectedRuling,
      gate: /parent budget/,
    },
    { name: "fresh-low-cap", cap: 24.99, ruling: expectedRuling, gate: /parent budget/ },
    { name: "fresh-high-cap", cap: 25.01, ruling: expectedRuling, gate: /parent budget/ },
    {
      name: "fresh-wrong-reserve",
      cap: 25,
      reserve: 6,
      ruling: expectedRuling,
      gate: /parent budget/,
    },
    {
      name: "other-run-new-cap",
      cap: 25,
      runId: "012345abcdef",
      ruling: expectedRuling,
      gate: /parent budget/,
    },
    {
      name: "other-recording-new-cap",
      cap: 25,
      recording: "h2-b",
      reserve: 6,
      ruling: expectedRuling,
      gate: /parent budget/,
    },
    {
      name: "legacy-a-new-cap",
      cap: 25,
      runId: "012345abcdef",
      ruling: H2_A2_RULING,
      gate: /parent budget/,
    },
    { name: "fresh-old-ruling", cap: 25, ruling: H2_A2_RULING, gate: /exact A2 RULING/ },
    {
      name: "fresh-pending-ruling",
      cap: 25,
      ruling: expectedRuling.replace("decision=APPROVE;", "decision=PENDING;"),
      gate: /exact A2 RULING/,
    },
    {
      name: "fresh-wrong-scope",
      cap: 25,
      ruling: expectedRuling.replace(runId, "012345abcdef"),
      gate: /exact A2 RULING/,
    },
    {
      name: "fresh-partial-ruling",
      cap: 25,
      ruling: expectedRuling.slice(0, -1),
      gate: /exact A2 RULING/,
    },
    { name: "fresh-missing-ruling", cap: 25, ruling: "", gate: /exact A2 RULING/ },
    {
      name: "fresh-config-ruling",
      cap: 25,
      ruling: H2_A2_RULING,
      configRuling: H2_A2_RULING,
      gate: /exact A2 RULING/,
    },
    {
      name: "fresh-invalid-source",
      cap: 25,
      ruling: expectedRuling,
      sourceCommit: "not-a-commit",
      gate: /source commit/,
    },
  ];
  for (const item of cases) {
    const child = join(dir, item.name);
    mkdirSync(child);
    const config = {
      project: "fireemu-oracle-events",
      runId: item.runId ?? runId,
      recording: item.recording ?? "h2-a",
      sourceCommit: item.sourceCommit ?? "c314c45e749a442a1d1fd07c2069f38ba3f0849a",
      reserveUsd: item.reserve ?? 7,
      parentBudgetUsd: item.cap,
      out: join(child, "missing-issued-sentinel"),
      ownerLedger: join(child, "owner.md"),
      sandboxLedger: join(child, "ledger.jsonl"),
      lockDir: join(child, "locks"),
      frozenManifest: "unused",
      adcFile: join(child, "no-credentials.json"),
      depsDir: "unused",
      firebaseJs: "unused",
      ...(item.configRuling ? { a2Ruling: item.configRuling } : {}),
    };
    const input = join(child, "input.json"),
      log = join(child, "wire.log");
    writeFileSync(input, JSON.stringify(config));
    writeFileSync(config.ownerLedger, item.ruling + "\n");
    writeFileSync(log, "");
    const answer = spawnSync(
      process.execPath,
      [
        "--import",
        preload,
        new URL("./eventarc-production/h-run.mjs", import.meta.url).pathname,
        "--config",
        input,
        "--a2",
      ],
      {
        encoding: "utf8",
        timeout: 10_000,
        env: {
          PATH: dirname(realpathSync(process.execPath)) + ":/usr/bin:/bin",
          H_NO_WIRE_LOG: log,
        },
      },
    );
    assert.equal(answer.error, undefined, item.name);
    assert.equal(answer.status, item.accepted ? 1 : 2, `${item.name}: ${answer.stderr}`);
    assert.match(
      answer.stderr,
      item.accepted ? /ENOENT.*missing-issued-sentinel/s : item.gate,
      item.name,
    );
    assert.equal(readFileSync(log, "utf8"), "", item.name);
    for (const path of [config.out, config.lockDir, config.sandboxLedger, config.adcFile])
      assert.equal(existsSync(path), false, item.name);
  }
  assert.equal(H2_SUCCESSOR_RUN_ID, runId);
  assert.equal(H2_SUCCESSOR_A2_RULING, expectedRuling);
});

test("H2 successor A2 channel authority uses the same fresh ruling as admission", async (t) => {
  const { main, H2_A2_RULING } = await import("./eventarc-production/h-run.mjs");
  const runId = "ea3c9a8129ff";
  const ruling = H2_A2_RULING.replace(
    "- 2026-10-07 | EVENTARC-H2 A2 list settlement |",
    "- 2026-10-08 | EVENTARC-H2-A-SUCCESSOR A2 list settlement |",
  )
    .replace(
      "for EVENTARC packet H2 recordings (H2-A and H2-B) on fireemu-oracle-events,",
      `for only the fresh EVENTARC H2-A successor recording run ${runId} on fireemu-oracle-events, with seven original A exports and the unchanged A2 maximum of 105 REST requests, three-hour invocation wall, and at least 600 seconds after its latest persisted request,`,
    )
    .replace(
      "Claude（委任。オーナーの裁量の委任 2026-09-28）",
      "Codex coordinator（委任。オーナー台帳365/395/996/998）",
    )
    .replace(
      "docs.local/reviews/2026-10-07-eventarc-h2-presend-review.md",
      "docs.local/runs/coordinator-codex-20261007/eventarc-h2-successor-packet/packet.md",
    );
  const dir = mkdtempSync(join(tmpdir(), "h2-successor-channel-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const manifest = hManifest({ project: "fireemu-oracle-events", runId, recording: "h2-a" });
  const config = {
    ...manifest,
    reserveUsd: 7,
    parentBudgetUsd: 25,
    sourceCommit: "c314c45e749a442a1d1fd07c2069f38ba3f0849a",
    out: join(dir, "out"),
    ownerLedger: join(dir, "owner.md"),
    sandboxLedger: join(dir, "sandbox.jsonl"),
    lockDir: join(dir, "locks"),
    frozenManifest: "unused",
    adcFile: "unused",
    depsDir: "unused",
    firebaseJs: "unused",
  };
  mkdirSync(config.out);
  writeFileSync(config.ownerLedger, ruling + "\n");
  writeFileSync(
    join(config.out, `issued-${runId}.jsonl`),
    [
      {
        kind: "h-state",
        value: {
          manifest: { ...manifest, projectNumber: "123456789012" },
          writes: [],
          identities: [],
          cleanup: { unconfirmed: [], unsettled: [] },
        },
      },
      { kind: "request", at: 0 },
    ]
      .map(JSON.stringify)
      .join("\n") + "\n",
  );
  const input = join(dir, "input.json");
  writeFileSync(input, JSON.stringify(config));
  let credentialSentinels = 0;
  await main(
    ["--config", input, "--a2"],
    { PATH: dirname(realpathSync(process.execPath)) },
    { stdout: { write: () => {} }, stderr: { write: () => {} } },
    {
      now: () => 600_000,
      execToken: () => {
        credentialSentinels++;
        throw new Error("OFFLINE_A2_CHANNEL_AUTHORITY_SENTINEL");
      },
      fetchImpl: () => {
        throw new Error("unexpected wire");
      },
    },
  );
  assert.ok(
    credentialSentinels > 0,
    "the fresh channel ruling must reach the offline credential sentinel",
  );
});

test("H2 successor emitted checkpoint and settlement lines use the truthful coordinator", async (t) => {
  const { openSync, fsyncSync, closeSync } = await import("node:fs");
  const { createHash } = await import("node:crypto");
  const { createFileJournal } = await import("./pubsub-production/capture.mjs");
  const { H2_SUCCESSOR_RUN_ID } = await import("./eventarc-production/h-run.mjs");
  const text = readFileSync(new URL("./eventarc-production/h-run.mjs", import.meta.url), "utf8");
  const start = text.indexOf("async ({ segment, result, settlement }) => {");
  const end = text.indexOf("\n          const sleep = deps.sleep", start);
  assert.ok(start > 0 && end > start);
  const expression = text.slice(start, end).trim().replace(/;$/, "");
  const dir = mkdtempSync(join(tmpdir(), "h2-actual-admission-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const [runId, recording, actor] of [
    ["ea3c9a8129ff", "h2-a", "Codex coordinator（委任。オーナー台帳365/395/996/998）"],
    ["012345abcdef", "h2-a", "Claude（委任。オーナーの裁量の委任 2026-09-28）"],
    ["ea3c9a8129ff", "h2-b", "Claude（委任。オーナーの裁量の委任 2026-09-28）"],
  ]) {
    for (const settlement of [undefined, "extension"]) {
      const out = join(dir, `${runId}-${recording}-${settlement ?? "admission"}`);
      mkdirSync(out);
      const config = {
        out,
        ownerLedger: join(out, "owner.md"),
        sourceCommit: "187addf46659d5f3b493dcfe5861fd7a0f6d7b70",
      };
      writeFileSync(config.ownerLedger, "");
      const journalPath = join(out, "issued.jsonl");
      const journal = createFileJournal(journalPath);
      let emitted;
      const callback = new Function(
        "m",
        "config",
        "now",
        "controller",
        "sleep",
        "note",
        "join",
        "openSync",
        "writeFileSync",
        "fsyncSync",
        "closeSync",
        "readFileSync",
        "H2_SUCCESSOR_RUN_ID",
        `return (${expression});`,
      )(
        hManifest({ project: "fireemu-oracle-events", runId, recording }),
        config,
        () => Date.UTC(2026, 9, 8),
        { signal: { aborted: false } },
        async () => {
          writeFileSync(config.ownerLedger, emitted.line + "\n");
        },
        (kind, value) => {
          emitted = value;
          journal.write({ kind, value });
        },
        join,
        openSync,
        writeFileSync,
        fsyncSync,
        closeSync,
        readFileSync,
        H2_SUCCESSOR_RUN_ID,
      );
      const result = { startedAt: Date.UTC(2026, 9, 8), observed: "checkpoint" };
      try {
        assert.equal(await callback({ segment: "multi", settlement, result }), true);
      } finally {
        journal.close();
      }
      const row = JSON.parse(readFileSync(journalPath, "utf8").trim());
      assert.equal(row.kind, "h-segment-admission-required");
      const columns = row.value.line.split(" | ");
      assert.equal(columns[3], actor);
      assert.equal(
        columns[1],
        `EVENTARC-H2 segment ${settlement ? "settlement (extension) and " : ""}admission`,
      );
      const checkpoint = readFileSync(row.value.checkpoint);
      assert.equal(checkpoint.toString(), JSON.stringify(result));
      assert.ok(
        columns[2].includes(`checkpoint=${createHash("sha256").update(checkpoint).digest("hex")}`),
      );
      assert.equal(readFileSync(config.ownerLedger, "utf8"), row.value.line + "\n");
    }
  }
});

test("H2 A2 closes both owned channel topics only after their own channel DELETE", async () => {
  const { hA2 } = await import("./eventarc-production/h-record.mjs");
  for (const scenario of [
    "actual",
    "reverse",
    "foreign-topic",
    "foreign-owner",
    "unknown-owner",
    "pending-owner",
    "preexisting-owner",
    "prior-delete",
  ]) {
    const manifest = hManifest({
      project: "fireemu-oracle-events",
      runId: "ea3c9a8129ff",
      recording: "h2-a",
    });
    const channels = [manifest.namedChannel, manifest.channel];
    const topics = channels.map(
      (name, i) => `projects/${manifest.project}/topics/owned-channel-${i}`,
    );
    const fn = `projects/${manifest.project}/locations/us-central1/functions/feea3c9a8129ffHExtension`;
    const marker = `projects/${manifest.project}/databases/(default)/documents/fe_h_${manifest.runId}/owned`;
    const recording = {
      manifest,
      lastRequestAt: 0,
      marker,
      publishes: [{ retry: true, body: { events: [{ id: "retry-id" }] } }],
      writes: [
        ...channels.map((name) => ({
          name,
          host: "eventarc",
          action: "create",
          state: "confirmed",
        })),
        { name: fn, host: "functions", action: "create", state: "confirmed" },
        {
          name: fn,
          host: "functions",
          action: "delete",
          state: "pending",
          operation: "original-function-delete",
        },
        { name: marker, host: "firestore", action: "create", state: "unknown" },
      ],
      identities: topics.map((topic) => ({ function: fn, topic })),
      channelTopics: Object.fromEntries(channels.map((name, i) => [name, topics[i]])),
      baseline: { status: 404 },
      namedBaseline: { status: 404 },
      baselineLists: {},
      cleanup: {
        unconfirmed: [],
        unsettled: [fn, topics[0], topics[1], topics[1], topics[1], ...channels],
      },
    };
    if (scenario === "reverse") recording.writes.reverse();
    if (scenario === "foreign-topic")
      recording.cleanup.unsettled.push("projects/fireemu-oracle-events/topics/foreign");
    if (scenario === "foreign-owner") {
      delete recording.channelTopics[channels[1]];
      recording.channelTopics[
        "projects/fireemu-oracle-events/locations/us-central1/channels/foreign"
      ] = topics[1];
      recording.writes.push({
        name: "projects/fireemu-oracle-events/locations/us-central1/channels/foreign",
        host: "eventarc",
        action: "create",
        state: "confirmed",
      });
    }
    if (["unknown-owner", "pending-owner"].includes(scenario))
      recording.writes[1].state = scenario === "unknown-owner" ? "unknown" : "pending";
    if (scenario === "preexisting-owner") recording.baseline.status = 200;
    if (scenario === "prior-delete")
      recording.writes.push({
        name: channels[0],
        host: "eventarc",
        action: "delete",
        state: "unknown",
      });
    const deleted = new Set();
    const calls = [];
    const channelDone = new Set();
    let markerDeleted = false;
    const result = await hA2({
      recording,
      now: () => 600000,
      note: () => {},
      sleep: async () => {},
      evidence: {
        a2ListRuling: true,
        a2ChannelRuling: true,
        readiness: () => true,
        notFound: (r) => r.status === 404,
        operation: () => true,
        retention: async () => ({ complete: true, atBaseline: true }),
      },
      transports: Object.fromEntries(
        ["functions", "run", "eventarc", "pubsub", "firestore"].map((host) => [
          host,
          {
            request: async (spec) => {
              calls.push({ host, ...spec });
              if (spec.method === "DELETE") {
                if (host === "firestore") {
                  if (["actual", "reverse"].includes(scenario))
                    assert.equal(channelDone.size, 2, scenario);
                  markerDeleted = true;
                  return { status: 200, body: {} };
                }
                const name = spec.path.slice(4);
                assert.equal(host, "eventarc");
                assert.ok(channels.includes(name));
                assert.equal(deleted.has(name), false);
                deleted.add(name);
                return {
                  status: 200,
                  body: {
                    name: `projects/${manifest.project}/locations/us-central1/operations/delete-${channels.indexOf(name)}`,
                    metadata: { target: name },
                    done: true,
                  },
                };
              }
              if (host === "firestore")
                return markerDeleted
                  ? { status: 404, body: {} }
                  : {
                      status: 200,
                      body: {
                        name: marker,
                        fields: {
                          run: { stringValue: manifest.runId },
                          source: { stringValue: manifest.source },
                          eventId: { stringValue: "retry-id" },
                        },
                      },
                    };
              const channel = channels.find((name) => spec.path === `/v1/${name}`);
              if (channel) {
                if (
                  ["unknown-owner", "pending-owner"].includes(scenario) &&
                  channel === channels[1]
                )
                  return { status: 404, body: {} };
                if (deleted.has(channel)) {
                  channelDone.add(channel);
                  return { status: 404, body: {} };
                }
                return {
                  status: 200,
                  body: { name: channel, pubsubTopic: topics[channels.indexOf(channel)] },
                };
              }
              const key = spec.path.split("?")[0].split("/").at(-1);
              if (key === "topics")
                return {
                  status: 200,
                  body: {
                    topics: topics
                      .filter((topic, i) => !channelDone.has(channels[i]))
                      .map((name) => ({ name })),
                  },
                };
              return { status: 200, body: { [key]: [] } };
            },
          },
        ]),
      ),
    });
    const success = ["actual", "reverse"].includes(scenario);
    assert.equal(result.cleanupReady, success, scenario);
    assert.equal(result.closureReady, false, scenario);
    assert.equal(
      recording.writes.find((w) => w.name === fn && w.action === "delete").state,
      "pending",
      scenario,
    );
    for (const [i, topic] of topics.entries())
      assert.equal(
        result.facts.find((f) => f.name === topic)?.closed ?? false,
        success || (scenario === "prior-delete" && i === 1),
        scenario,
      );
    assert.equal(
      calls.some((c) => c.host === "pubsub" && c.method === "DELETE"),
      false,
      scenario,
    );
    if (success) {
      assert.equal(deleted.size, 2);
      assert.equal(markerDeleted, true);
    }
    if (
      [
        "foreign-topic",
        "foreign-owner",
        "unknown-owner",
        "pending-owner",
        "preexisting-owner",
      ].includes(scenario)
    )
      assert.equal(deleted.size, 0, scenario);
    if (scenario === "prior-delete") {
      assert.equal(
        calls.some((c) => c.method === "DELETE" && c.path === `/v1/${channels[0]}`),
        false,
      );
      assert.deepEqual([...deleted], [channels[1]]);
      assert.equal(markerDeleted, true);
      assert.equal(result.facts.find((f) => f.name === channels[0]).closed, false);
    }
  }
});

test("H2 successor A2 binds recovery source adoption before credentials and preserves the recording", async (t) => {
  const { main, H2_SUCCESSOR_A2_RULING } = await import("./eventarc-production/h-run.mjs");
  const origin = "2f13f34e54049dc7393946a618544cb5fdcda2f1";
  const recovery = "1234567890abcdef1234567890abcdef12345678";
  const adoption = `- 2026-10-08 | EVENTARC-H-ea3c9a8129ff A2 recovery source adoption | decision=APPROVE; project=fireemu-oracle-events; recordingSourceCommit=${origin}; recoverySourceCommit=${recovery}; A2 only; unchanged owner1041 scope, 105 REST requests, three-hour wall, latest request age at least 600 seconds and no DELETE resend; no normal recording | Codex coordinator（委任。オーナー台帳365/395/996/998） | docs.local/runs/coordinator-codex-20261007/eventarc-h2-a2-fix-source/clean-index.json`;
  for (const scenario of [
    "original-lock",
    "recovery-lock",
    "missing-adoption",
    "wrong-adoption",
    "wrong-origin",
    "old-source",
    "normal",
    "foreign-run",
    "foreign-lock",
    "live",
    "body",
    "inode",
  ]) {
    const dir = mkdtempSync(join(tmpdir(), "h2-source-adoption-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const manifest = hManifest({
      project: "fireemu-oracle-events",
      runId: scenario === "foreign-run" ? "abcdef012345" : "ea3c9a8129ff",
      recording: "h2-a",
    });
    const config = {
      ...manifest,
      parentBudgetUsd: 25,
      sourceCommit: scenario === "old-source" ? origin : recovery,
      recordingSourceCommit: scenario === "wrong-origin" ? "0".repeat(40) : origin,
      out: join(dir, "out"),
      sandboxLedger: join(dir, "sandbox.jsonl"),
      lockDir: join(dir, "locks"),
      ownerLedger: join(dir, "owner.md"),
      frozenManifest: "unused",
      adcFile: "unused",
      depsDir: "unused",
      firebaseJs: "unused",
    };
    mkdirSync(config.out);
    mkdirSync(config.lockDir, { mode: 0o700 });
    writeFileSync(
      config.ownerLedger,
      `${H2_SUCCESSOR_A2_RULING}\n${scenario === "missing-adoption" ? "" : scenario === "wrong-adoption" ? adoption.replace(recovery, "a".repeat(40)) : adoption}\n`,
    );
    const original = `${JSON.stringify({ kind: "h-state", value: { manifest: { ...manifest, projectNumber: "123456789012" }, writes: [], identities: [], cleanup: { unconfirmed: [], unsettled: [] } } })}\n${JSON.stringify({ kind: "request", at: 0 })}\n`;
    const originalPath = join(config.out, `issued-${manifest.runId}.jsonl`);
    writeFileSync(originalPath, original);
    const input = join(dir, "input.json");
    writeFileSync(input, JSON.stringify(config));
    const path = join(config.lockDir, `${manifest.project}.lock`);
    const lock = {
      taskId: "PUBSUB-EVENTARC",
      packetId: `EVENTARC-H-${manifest.runId}`,
      sourceCommit:
        scenario === "recovery-lock"
          ? recovery
          : scenario === "foreign-lock"
            ? "f".repeat(40)
            : origin,
      pid: process.pid,
    };
    const raw = JSON.stringify(lock);
    writeFileSync(path, raw);
    let credentials = 0,
      requests = 0,
      message = "";
    const observed = [];
    const code = await main(
      ["--config", input, ...(scenario === "normal" ? [] : ["--a2"])],
      { HOME: dir, PATH: dirname(realpathSync(process.execPath)) },
      {
        stdout: { write: () => {} },
        stderr: {
          write: (s) => {
            message += s;
          },
        },
      },
      {
        now: () => 600000,
        checkPid: () => {
          if (scenario === "live") return;
          if (scenario === "body") writeFileSync(path, JSON.stringify({ ...lock, changed: true }));
          if (scenario === "inode") {
            renameSync(path, path + ".old");
            writeFileSync(path, raw);
          }
          throw Object.assign(new Error("dead fixture PID"), { code: "ESRCH" });
        },
        fetchImpl: () => {
          requests++;
          throw new Error("network forbidden");
        },
        execToken: () => {
          credentials++;
          const lockSource = JSON.parse(readFileSync(path)).sourceCommit;
          const rows = readFileSync(
            join(config.out, `issued-${manifest.runId}-a2-19700101T001000Z.jsonl`),
            "utf8",
          )
            .trim()
            .split("\n")
            .map(JSON.parse);
          const started = rows.find((row) => row.kind === "a2-recovery-start");
          observed.push({ lockSource, started: started?.value });
          throw new Error("source adoption credential sentinel");
        },
      },
    );
    assert.equal(requests, 0, scenario);
    assert.equal(readFileSync(originalPath, "utf8"), original, scenario);
    if (["original-lock", "recovery-lock"].includes(scenario)) {
      assert.equal(code, 1, scenario);
      assert.ok(credentials > 0, `${scenario}: ${message}`);
      assert.ok(observed.length > 0, scenario);
      for (const value of observed)
        assert.deepEqual(
          value,
          {
            lockSource: recovery,
            started: { recordingSourceCommit: origin, recoverySourceCommit: recovery },
          },
          scenario,
        );
      assert.match(message, /project locks retained/, scenario);
      assert.equal(JSON.parse(readFileSync(path)).sourceCommit, recovery, scenario);
    } else {
      assert.equal(credentials, 0, scenario);
      assert.equal(existsSync(config.sandboxLedger), false, scenario);
      assert.match(
        message,
        scenario === "live"
          ? /recorder process is still alive/
          : ["body", "inode"].includes(scenario)
            ? /recovery lock changed/
            : scenario === "foreign-lock"
              ? /foreign recovery lock/
              : /recovery source adoption/,
        scenario,
      );
      assert.equal(existsSync(path), true, scenario);
    }
  }
});
