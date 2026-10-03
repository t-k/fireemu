import assert from "node:assert/strict";
import test from "node:test";

const timeOffset = Number(process.env.NATIVE_TEST_TIME_OFFSET_MS ?? 0);
if (timeOffset) {
  const now = Date.now;
  Date.now = () => now() + timeOffset;
}

const entry = () => import("./storage-rules/management-native-entry.mjs");

test("the fixed native entry holds without inspecting caller authority or invoking effects", async () => {
  const module = await entry();
  let observed = 0;
  const forged = new Proxy(
    { kind: "ROOT_CURRENT_ADMISSION", go: true },
    {
      get() {
        observed++;
        throw new Error("caller authority must not be read");
      },
      ownKeys() {
        observed++;
        throw new Error("caller authority must not be enumerated");
      },
    },
  );
  const result = await module.withNativeRootRecording(forged, () => {
    observed++;
  });
  assert.deepEqual(result, {
    status: "HOLD",
    reason: "fresh ROOT authority unavailable",
    sendAuthorized: false,
    closureReady: false,
    parentClaim: false,
  });
  assert.equal(observed, 0);
  const lines = [];
  assert.equal(await module.runNativeEntryCommand({ out: (line) => lines.push(line) }), 3);
  assert.deepEqual(lines, ["HOLD: fresh ROOT authority unavailable"]);
});

test("the adapter retains exact raw bytes and headers while recording transport timing separately", async () => {
  const { projectNativeTransportResponse } =
    await import("./storage-rules/management-native-record.mjs");
  const frame = {
    status: 403,
    rawHeaders: ["X-Test", "first", "x-test", "second", "Content-Length", "3"],
    bytes: Buffer.from([0, 255, 1]),
    startedAtMs: 10,
    finishedAtMs: 12,
  };
  const projected = projectNativeTransportResponse(frame);
  assert.deepEqual(projected, {
    raw: { status: frame.status, rawHeaders: frame.rawHeaders, bytes: frame.bytes },
    timing: { startedAtMs: 10, finishedAtMs: 12 },
  });
  frame.bytes.fill(9);
  frame.rawHeaders[1] = "changed";
  assert.deepEqual(projected.raw.bytes, Buffer.from([0, 255, 1]));
  assert.equal(projected.raw.rawHeaders[1], "first");
  assert.deepEqual(Object.keys(projected.raw), ["status", "rawHeaders", "bytes"]);
  assert.deepEqual(Object.keys(projected.timing), ["startedAtMs", "finishedAtMs"]);
});

test("synthetic transport records intent and attempt before one independently observed local request", async () => {
  const { createServer, request } = await import("node:http");
  const { once } = await import("node:events");
  const { mkdtemp, open, readFile, rm } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { createNativeSyntheticTransport } = await entry();
  const directory = await mkdtemp(join(tmpdir(), "native-entry-observer-"));
  const durable = async (name, receipt) => {
    const handle = await open(join(directory, name), "wx", 0o600);
    try {
      await handle.writeFile(JSON.stringify(receipt));
      await handle.sync();
    } finally {
      await handle.close();
    }
  };
  const events = [];
  const wires = [];
  let adapter;
  const server = createServer(async (incoming, response) => {
    const chunks = [];
    for await (const chunk of incoming) chunks.push(chunk);
    assert.equal(JSON.parse(await readFile(join(directory, "intent.json"), "utf8")).attempt, 1);
    assert.equal(JSON.parse(await readFile(join(directory, "attempt.json"), "utf8")).attempt, 1);
    wires.push({
      method: incoming.method,
      bytes: Buffer.concat(chunks),
      counted: adapter.snapshot(),
    });
    events.push("observed-wire");
    response.writeHead(403, [
      "Content-Type",
      "application/json",
      "X-Receipt",
      "a",
      "X-Receipt",
      "b",
    ]);
    response.end(Buffer.from([0, 255, 1]));
  });
  server.listen(Number(process.env.PORT ?? 0), "127.0.0.1");
  await once(server, "listening");
  try {
    adapter = createNativeSyntheticTransport({
      requestImpl(url, options, callback) {
        assert.equal(url.origin, "https://firebaserules.googleapis.com");
        assert.deepEqual(events, ["intent", "attempt"]);
        assert.equal(adapter.snapshot().physicalAttempts, 1);
        return request(
          {
            host: "127.0.0.1",
            port: server.address().port,
            path: url.pathname,
            method: options.method,
            headers: options.headers,
            agent: false,
          },
          callback,
        );
      },
      async writeIntent(receipt) {
        await durable("intent.json", receipt);
        events.push("intent");
      },
      async writeAttempt(receipt) {
        await durable("attempt.json", receipt);
        events.push("attempt");
      },
      async writeTiming(receipt) {
        assert.deepEqual(Object.keys(receipt), ["attempt", "startedAtMs", "finishedAtMs"]);
        await durable("timing.json", receipt);
        events.push("timing");
      },
      maxAttempts: 1,
    });
    const raw = await adapter.send({
      url: "https://firebaserules.googleapis.com/v1/projects/fireemu-oracle-query:test",
      method: "POST",
      headers: { "content-type": "application/json" },
      body: Buffer.from("{}"),
    });
    assert.deepEqual(Object.keys(raw), ["status", "rawHeaders", "bytes"]);
    assert.equal(raw.status, 403);
    assert.deepEqual(raw.bytes, Buffer.from([0, 255, 1]));
    assert.deepEqual(events, ["intent", "attempt", "observed-wire", "timing"]);
    assert.equal(wires.length, 1);
    assert.deepEqual(wires[0].bytes, Buffer.from("{}"));
    assert.equal(wires[0].counted.physicalAttempts, 1);
    assert.equal(wires[0].counted.attempts, 1);
    assert.equal(adapter.snapshot().evidenceKind, "SYNTHETIC_ONLY");
    assert.equal(adapter.snapshot().sendAuthorized, false);
    await assert.rejects(
      adapter.send({
        url: "https://firebaserules.googleapis.com/v1/projects/fireemu-oracle-query:test",
        method: "POST",
        headers: {},
        body: Buffer.from("{}"),
      }),
      /synthetic transport unavailable/,
    );
    assert.equal(wires.length, 1);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
    assert.equal(server.listening, false);
    await rm(directory, { recursive: true });
  }
});

const syntheticSpec = () => ({
  url: "https://firebaserules.googleapis.com/v1/projects/fireemu-oracle-query:test",
  method: "POST",
  headers: {},
  body: Buffer.from("{}"),
});

async function modelTransport(fault = "none", maxAttempts = 2) {
  const { EventEmitter } = await import("node:events");
  const { createNativeSyntheticTransport } = await entry();
  const events = [];
  let observed = 0;
  const adapter = createNativeSyntheticTransport({
    maxAttempts,
    async writeIntent() {
      events.push("intent");
      if (fault === "intent") throw Error("intent unavailable");
    },
    async writeAttempt() {
      events.push("attempt");
      if (fault === "attempt") throw Error("attempt unavailable");
    },
    async writeTiming() {
      events.push("timing");
      if (fault === "timing") throw Error("timing unavailable");
    },
    requestImpl(_url, _options, callback) {
      observed++;
      events.push("physical");
      if (fault === "request") throw Error("request failed");
      const request = new EventEmitter();
      request.destroy = () => {};
      request.end = () =>
        queueMicrotask(() => {
          if (fault === "unknown") return request.emit("error", Error("response lost"));
          const response = new EventEmitter();
          response.statusCode = 403;
          response.rawHeaders = ["Content-Length", "2"];
          response.complete = true;
          response.destroy = () => {};
          callback(response);
          response.emit("data", Buffer.from("{}"));
          response.emit("end");
        });
      return request;
    },
  });
  return { adapter, events, observed: () => observed };
}

test("an independent state model accounts for failures, finite caps and sticky no-retry outcomes", async () => {
  let cases = 0;
  for (const cap of [1, 2, 3]) {
    for (const fault of ["none", "intent", "attempt", "request", "unknown", "timing"]) {
      const ctx = await modelTransport(fault, cap);
      const model = { attempts: 0, wires: 0, poisoned: false, unknown: false };
      for (let step = 0; step < cap + 2; step++) {
        const available = !model.poisoned && model.attempts < cap;
        const succeeds = available && fault === "none";
        if (available) {
          if (fault !== "intent") model.attempts++;
          if (!["intent", "attempt"].includes(fault)) model.wires++;
          model.poisoned = fault !== "none";
          model.unknown = ["request", "unknown"].includes(fault);
        }
        if (succeeds) await ctx.adapter.send(syntheticSpec());
        else await assert.rejects(ctx.adapter.send(syntheticSpec()));
        const actual = ctx.adapter.snapshot();
        assert.deepEqual(
          {
            attempts: actual.attempts,
            wires: actual.physicalAttempts,
            poisoned: actual.poisoned,
            unknown: actual.unknown,
          },
          model,
          `cap=${cap},fault=${fault},step=${step}`,
        );
        assert.equal(ctx.observed(), model.wires);
        assert.equal(actual.busy, false);
        assert.equal(actual.parentClaim, false);
        cases++;
      }
    }
  }
  assert.equal(cases, 72);
});

test("same or different concurrent requests are refused before the first intent await completes", async () => {
  const { createNativeSyntheticTransport } = await entry();
  let release;
  let observed = 0;
  const blocked = new Promise((resolve) => {
    release = resolve;
  });
  const adapter = createNativeSyntheticTransport({
    requestImpl() {
      observed++;
      throw Error("response unknown");
    },
    writeIntent: () => blocked,
    writeAttempt: async () => {},
    writeTiming: async () => {},
    maxAttempts: 2,
  });
  const first = adapter.send(syntheticSpec());
  assert.equal(adapter.snapshot().busy, true);
  await assert.rejects(adapter.send(syntheticSpec()), /unavailable/);
  await assert.rejects(
    adapter.send({
      ...syntheticSpec(),
      url: "https://firebaserules.googleapis.com/v1/projects/fireemu-oracle-query/rulesets",
    }),
    /unavailable/,
  );
  assert.equal(observed, 0);
  release();
  await assert.rejects(first, /outcome unknown/);
  assert.equal(observed, 1);
  assert.equal(adapter.snapshot().unknown, true);
  await assert.rejects(adapter.send(syntheticSpec()), /unavailable/);
  assert.equal(observed, 1);
});

test("caller bytes are copied before any durable callback can change the request", async () => {
  const { EventEmitter } = await import("node:events");
  const { createNativeSyntheticTransport } = await entry();
  const spec = syntheticSpec();
  let sent;
  const adapter = createNativeSyntheticTransport({
    requestImpl(_url, _options, callback) {
      const request = new EventEmitter();
      request.destroy = () => {};
      request.end = (body) => {
        sent = Buffer.from(body);
        queueMicrotask(() => {
          const response = new EventEmitter();
          response.statusCode = 200;
          response.rawHeaders = [];
          response.complete = true;
          response.destroy = () => {};
          callback(response);
          response.emit("end");
        });
      };
      return request;
    },
    async writeIntent() {
      spec.body.fill(88);
      spec.url = "https://example.com/";
    },
    writeAttempt: async () => {},
    writeTiming: async () => {},
    maxAttempts: 1,
  });
  await adapter.send(spec);
  assert.deepEqual(sent, Buffer.from("{}"));
});

test("unapproved synthetic destinations and accessor inputs leave intent, count and wire untouched", async () => {
  const ctx = await modelTransport();
  for (const spec of [
    { ...syntheticSpec(), url: "https://example.com/" },
    { ...syntheticSpec(), method: "GET" },
    Object.defineProperty(syntheticSpec(), "body", {
      enumerable: true,
      get() {
        assert.fail("request accessor invoked");
      },
    }),
    new Proxy(syntheticSpec(), {
      ownKeys() {
        assert.fail("request proxy inspected");
      },
    }),
  ])
    await assert.rejects(ctx.adapter.send(spec));
  assert.deepEqual(ctx.events, []);
  assert.equal(ctx.adapter.snapshot().attempts, 0);
  assert.equal(ctx.adapter.snapshot().poisoned, false);
  assert.equal(ctx.observed(), 0);
});

test("projection rejects malformed, relabelled and aliased frames without invoking external behavior", async () => {
  const { projectNativeTransportResponse } =
    await import("./storage-rules/management-native-record.mjs");
  const valid = () => ({
    status: 200,
    rawHeaders: [],
    bytes: Buffer.from("{}"),
    startedAtMs: 1,
    finishedAtMs: 2,
  });
  const malformed = [
    { ...valid(), extra: true },
    { ...valid(), status: "200" },
    { ...valid(), status: 600 },
    { ...valid(), rawHeaders: ["X-Test"] },
    { ...valid(), rawHeaders: ["X-Test", "a\r\nb"] },
    { ...valid(), bytes: "{}" },
    { ...valid(), finishedAtMs: 0 },
    { ...valid(), startedAtMs: -1 },
    { ...valid(), finishedAtMs: 2.5 },
    Object.defineProperty(valid(), "status", {
      enumerable: true,
      get() {
        assert.fail("frame accessor invoked");
      },
    }),
    new Proxy(valid(), {
      ownKeys() {
        assert.fail("frame proxy inspected");
      },
    }),
  ];
  for (const frame of malformed) assert.throws(() => projectNativeTransportResponse(frame));
});

test("deterministic generated frames preserve all raw status, bytes and duplicate headers", async () => {
  const { projectNativeTransportResponse } =
    await import("./storage-rules/management-native-record.mjs");
  let state = 0x794795;
  const next = () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state;
  };
  for (let sample = 0; sample < 128; sample++) {
    const bytes = Buffer.from(Array.from({ length: next() % 128 }, () => next() % 256));
    const rawHeaders = [
      "X-Value",
      String(next()),
      "x-value",
      String(next()),
      "Content-Length",
      "999",
    ];
    const status = 100 + (next() % 500);
    const frame = {
      status,
      bytes,
      rawHeaders,
      startedAtMs: sample,
      finishedAtMs: sample + (next() % 1000),
    };
    const { raw, timing } = projectNativeTransportResponse(frame);
    assert.equal(raw.status, status);
    assert.deepEqual(raw.bytes, bytes);
    assert.deepEqual(raw.rawHeaders, rawHeaders);
    assert.equal(timing.finishedAtMs, frame.finishedAtMs);
    bytes.fill(0);
    rawHeaders.fill("external mutation");
    assert.notEqual(raw.rawHeaders[0], "external mutation");
    assert.equal(raw.rawHeaders.at(-1), "999");
  }
});

test("the runner receipt binds the entry, actual single-attempt transport and both test models by bytes", async () => {
  const { readFile } = await import("node:fs/promises");
  const { createHash } = await import("node:crypto");
  const { nativeRunnerDigest } = await import("./storage-rules/management-native-record.mjs");
  const digest = (value) => createHash("sha256").update(value).digest("hex");
  const paths = [
    "./management-native-manifest.mjs",
    "./management-native-schedule.mjs",
    "./management-native-record.mjs",
    "../storage-rules-management-native.test.mjs",
    "./management-native-entry.mjs",
    "./http-transport.mjs",
    "../storage-rules-management-native-entry.test.mjs",
  ];
  const entries = [];
  for (const path of paths)
    entries.push([
      path,
      digest(await readFile(new URL(`./storage-rules/${path}`, import.meta.url))),
    ]);
  assert.equal(nativeRunnerDigest(), digest(JSON.stringify(Object.fromEntries(entries))));
});

test("self-attested GO, actor, files, times and transport markers cannot become actual authority", async () => {
  const { withNativeRootRecording } = await entry();
  let effects = 0;
  for (const forged of [
    null,
    true,
    "ROOT_CURRENT_ADMISSION",
    {},
    { kind: "ROOT_CURRENT_ADMISSION", go: true },
    {
      schema: "storage-native-root-current/v1",
      actor: "Codex（調整役。台帳790/795によるClaude代行）",
      expiresAt: Number.MAX_SAFE_INTEGER,
    },
    {
      evidencePath: "self-attested.json",
      validationPath: "self-attested.json",
      review: { verdict: "APPROVE", must: [], should: [] },
    },
    {
      sendAuthorized: true,
      admitted: true,
      transport: {
        send() {
          effects++;
        },
      },
    },
  ]) {
    const result = await withNativeRootRecording(forged, () => {
      effects++;
    });
    assert.equal(result.status, "HOLD");
    assert.equal(result.sendAuthorized, false);
    assert.equal(result.closureReady, false);
    assert.equal(result.parentClaim, false);
  }
  assert.equal(effects, 0);
});

test("two distinct synthetic inventories derive 2N from their fixed branch without granting native authority", async () => {
  const { buildNativeManifest } = await import("./storage-rules/management-native-manifest.mjs");
  const { withNativeRootRecording } = await entry();
  for (const branch of ["absent", "present"]) {
    const input = {
      runId: "synthetic-entry-a",
      sourceCommit: "0".repeat(40),
      sourceTree: "1".repeat(40),
      bucket: "fireemu-oracle-query.firebasestorage.app",
      baseline:
        branch === "absent"
          ? { kind: "absent", observedAt: 1000, bucketAbsent: true, bucketlessAbsent: true }
          : {
              kind: "present",
              observedAt: 1000,
              release: {
                name: "projects/fireemu-oracle-query/releases/firebase.storage/fireemu-oracle-query.firebasestorage.app",
                rulesetName: "projects/fireemu-oracle-query/rulesets/synthetic-baseline",
                updateTime: "2026-10-03T00:00:00Z",
              },
              source:
                "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow get: if true; } } }",
              bucketlessAbsent: true,
            },
      limits: {
        settleCycles: 4,
        intervalMs: 1,
        listPages: 2,
        credentialAttempts: 2,
        deadlineSeconds: 120,
      },
      priorCompileProofs: ["c", "d"].map((tag) => ({
        runId: `stage3-20260930${tag}`,
        journalSha256: tag.repeat(64),
        validSourceCount: 338,
      })),
    };
    const manifests = [input, { ...input, runId: "synthetic-entry-b" }].map(buildNativeManifest);
    const { settleCycles: s, listPages: pages, credentialAttempts: credentials } = input.limits;
    const perRecording =
      72 + 3 * Number(branch === "present") + 6 * s + 2 * pages + 2 * credentials;
    assert.notEqual(manifests[0].manifestSha256, manifests[1].manifestSha256);
    assert.notEqual(manifests[0].runId, manifests[1].runId);
    assert.equal(
      manifests.reduce((sum, manifest) => sum + manifest.rows.length, 0),
      2 * perRecording,
    );
    assert.equal(perRecording, branch === "absent" ? 104 : 107);
    for (const manifest of manifests) {
      const ctx = await modelTransport("none", manifest.rows.length);
      for (let request = 0; request < perRecording; request++)
        await ctx.adapter.send(syntheticSpec());
      await assert.rejects(ctx.adapter.send(syntheticSpec()), /unavailable/);
      assert.equal(ctx.observed(), perRecording);
      const result = await withNativeRootRecording({
        manifest,
        packetSha256: manifest.manifestSha256,
      });
      assert.equal(result.status, "HOLD");
      assert.equal(result.parentClaim, false);
    }
  }
});
