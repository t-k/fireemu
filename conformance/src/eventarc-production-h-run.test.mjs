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
  const dir = mkdtempSync(new URL("../../target/codex-out/h-entry-", import.meta.url));
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
    assert.equal(await main(["--config", input], {}, io, deps), 2);
    assert.equal(existsSync(config.sandboxLedger), false);
    writeFileSync(ownerLedger, `${H_A2_RULING}\n`);
    const prepareFake = deps.prepare;
    const discoverFake = deps.discover;
    delete deps.prepare;
    delete deps.discover;
    const code = await main(["--config", input], {}, io, deps);
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
    const a2code = await main(["--config", input, "--a2"], {}, io, deps);
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
    assert.ok(rows.filter((r) => r.event === "finished").every((r) => r.sandboxAtBaseline));
    config.out = join(dir, "signal-out");
    writeFileSync(input, JSON.stringify(config));
    a2Mode = false;
    stopOnPublish = true;
    assert.equal(await main(["--config", input], {}, io, deps), 3);
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
    assert.equal(await main(["--config", input, "--a2"], {}, io, deps), 1);
    world.setClock(interrupted.lastRequestAt + 600000);
    deps.checkPid = () => {
      throw Object.assign(new Error("fake reaped recorder"), { code: "ESRCH" });
    };
    a2Mode = true;
    assert.equal(await main(["--config", input, "--a2"], {}, io, deps), 1);
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
      assert.equal(await main(["--config", input], {}, io, deps), 3);
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
  const dir = mkdtempSync(new URL("../../target/codex-out/h-tail-", import.meta.url));
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
  const dir = mkdtempSync(new URL("../../target/codex-out/h-native-", import.meta.url));
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
  const dir = mkdtempSync(new URL("../../target/codex-out/h-fetch-", import.meta.url));
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
