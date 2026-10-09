import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { makePlan, PROJECT } from "./pubsub-observation-b/plan.mjs";
import { graph } from "./pubsub-observation-b/scenarios.mjs";
import { encodeRequest, route } from "./pubsub-observation-b/wire.mjs";
import {
  importRecording,
  replayRecording,
  compareReply,
} from "./pubsub-observation-b/replay-core.mjs";
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const runId = "123456abcdef";
function fixture() {
  const rows = [],
    results = [];
  let requestId = 0;
  const context = {
    suite: "pubsub-observation-b-v1",
    project: PROJECT,
    runId,
    sourceHead: "a".repeat(40),
    envelopeId: "PUBSUB-OBSERVATION-B-TEST",
    packetSha256: "b".repeat(64),
  };
  const add = (row) =>
    rows.push({
      n: rows.length + 1,
      at: new Date(1700000000000 + rows.length).toISOString(),
      ...row,
    });
  add({ event: "run-start", ...context });
  for (const cell of makePlan().cells.filter((c) => !c.reserve)) {
    const manifest = graph(cell, runId),
      pages = [];
    add({
      event: "cell-manifest",
      cellId: cell.id,
      manifest,
      creationOrder: manifest.resources.map((r) => r.name),
      canonicalCoordinates: cell.coordinates,
    });
    const send = (category, method, request, reply, stage) => {
      const id = ++requestId,
        service = /Topic|Publish/.test(method) ? "Publisher" : "Subscriber";
      const address = cell.transport === "rest" ? route(method, request) : null;
      const bytes = address
        ? Buffer.from(address.body === undefined ? "" : JSON.stringify(address.body))
        : encodeRequest(service, method, request);
      add({
        event: "request-dispatch",
        cellId: cell.id,
        requestId: id,
        transport: cell.transport,
        category,
        method,
        request,
        requestBodyBytes: bytes.length,
        requestSha256: hash(bytes),
        ...(address ? { url: address.url, verb: address.verb } : {}),
        requestDeadlineAt: new Date(1700000100000).toISOString(),
      });
      add({
        event: "response",
        cellId: cell.id,
        requestId: id,
        transport: cell.transport,
        method,
        reply,
      });
      if (stage) {
        const observation = {
          stage,
          names: reply.body[cell.kind]?.map((r) => r.name) ?? [],
          nextPageToken: reply.body.nextPageToken ?? null,
          requestToken: request.pageToken ?? null,
          projection: (reply.body[cell.kind] ?? [])
            .map((r) => r.name)
            .filter((n) => n.split("/").at(-1).startsWith(`fe${runId}-`)),
          reply,
        };
        pages.push(observation);
        add({ event: "page-observation", cellId: cell.id, ...observation });
      }
    };
    const ok = (body) => ({
      ok: true,
      code: "OK",
      unknown: false,
      body,
      ...(cell.transport === "rest" ? { status: 200 } : {}),
    });
    for (const r of manifest.resources) {
      send("create", r.method, r.request, ok({ name: r.name }));
      send("get", r.method.replace("Create", "Get"), { name: r.name }, ok({ name: r.name }));
    }
    const names = manifest.members.toSorted(),
      first = names[0],
      original = `production-${cell.id}-first`;
    const list = (stage, memberNames, token, next) =>
      send(
        "list",
        `List${cell.kind[0].toUpperCase() + cell.kind.slice(1)}`,
        {
          project: `projects/${PROJECT}`,
          pageSize: stage === "baseline" || stage === "ownership-control" ? 1000 : 1,
          ...(token ? { pageToken: token } : {}),
        },
        ok({
          [cell.kind]: memberNames.map((name) => ({ name })),
          ...(next ? { nextPageToken: next } : {}),
        }),
        stage,
      );
    list("baseline", names);
    list("first", [first], undefined, original);
    send(
      "cursorDelete",
      `Delete${cell.kind === "topics" ? "Topic" : cell.kind === "subscriptions" ? "Subscription" : "Snapshot"}`,
      { name: first },
      ok({}),
    );
    const refused = {
      ok: false,
      code: "NOT_FOUND",
      unknown: false,
      body: { error: { status: "NOT_FOUND", message: "missing" } },
      ...(cell.transport === "rest"
        ? { status: 404 }
        : { bodyBytes: null, layoutVerdict: "NOT_COMPARABLE_NATIVE_ERROR_BODY_NOT_CAPTURED" }),
    };
    send(
      "cursorGet",
      `Get${cell.kind === "topics" ? "Topic" : cell.kind === "subscriptions" ? "Subscription" : "Snapshot"}`,
      { name: first },
      refused,
    );
    list("after-delete", [names[1]], original, `production-${cell.id}-next`);
    list("continuation-1", [names[2]], `production-${cell.id}-next`, `production-${cell.id}-last`);
    list("continuation-2", [names[3]], `production-${cell.id}-last`);
    const altered = (original[0] === "A" ? "B" : "A") + original.slice(1);
    send(
      "list",
      `List${cell.kind[0].toUpperCase() + cell.kind.slice(1)}`,
      { project: `projects/${PROJECT}`, pageSize: 1, pageToken: altered },
      {
        ok: false,
        code: "INVALID_ARGUMENT",
        unknown: false,
        body: { error: { status: "INVALID_ARGUMENT", message: "invalid token" } },
        ...(cell.transport === "rest"
          ? { status: 400 }
          : { bodyBytes: null, layoutVerdict: "NOT_COMPARABLE_NATIVE_ERROR_BODY_NOT_CAPTURED" }),
      },
      "altered-token",
    );
    list("ownership-control", names.slice(1));
    for (const r of manifest.resources.toReversed())
      if (r.name !== first)
        send("cleanupDelete", r.method.replace("Create", "Delete"), { name: r.name }, ok({}));
    const result = { cellId: cell.id, complete: true, cleanupClosed: true, observations: pages };
    results.push(result);
    add({ event: "case-result", ...result });
  }
  return {
    rows,
    summary: {
      ...context,
      a2: false,
      recordingComplete: true,
      resourcesClosed: true,
      error: null,
      signalled: false,
      closureReady: false,
      parentClosureReady: false,
      results,
      meter: { requests: requestId },
    },
  };
}
function localModel() {
  const owned = new Set(),
    calls = [],
    tokens = new Map();
  return {
    calls,
    async call({ method, request, cellId }) {
      calls.push({ method, request, cellId });
      if (method.startsWith("Create")) {
        owned.add(request.name);
        return { ok: true, code: "OK", unknown: false, body: { name: request.name }, status: 200 };
      }
      if (method.startsWith("Delete")) {
        owned.delete(request.name);
        return { ok: true, code: "OK", unknown: false, body: {}, status: 200 };
      }
      if (method.startsWith("Get"))
        return owned.has(request.name)
          ? { ok: true, code: "OK", unknown: false, body: { name: request.name }, status: 200 }
          : {
              ok: false,
              code: "NOT_FOUND",
              unknown: false,
              message: "missing",
              body: { error: { status: "NOT_FOUND", message: "missing" } },
              status: 404,
            };
      const kind = method.slice(4).toLowerCase(),
        names = [...owned].filter((n) => n.split("/")[2] === kind).toSorted();
      let offset = 0;
      if (request.pageToken) {
        if (!tokens.has(request.pageToken))
          return {
            ok: false,
            code: "INVALID_ARGUMENT",
            unknown: false,
            message: "invalid token",
            body: { error: { status: "INVALID_ARGUMENT", message: "invalid token" } },
            status: 400,
          };
        const cursor = tokens.get(request.pageToken);
        offset = names.findIndex((n) => n > cursor);
        if (offset < 0) offset = names.length;
      }
      const page = names.slice(offset, offset + request.pageSize),
        next = offset + page.length < names.length ? `local-${cellId}-${page.at(-1)}` : null;
      if (next) tokens.set(next, page.at(-1));
      return {
        ok: true,
        code: "OK",
        unknown: false,
        status: 200,
        body: { [kind]: page.map((name) => ({ name })), ...(next ? { nextPageToken: next } : {}) },
      };
    },
  };
}
test("B importer preserves all18 manifests and real event/summary closure", () => {
  const f = fixture(),
    input = importRecording(f.rows, f.summary);
  assert.equal(input.cells.length, 18);
  assert.equal(input.metadata.suite, "pubsub-observation-b-v1");
  assert.ok(f.rows.every((r) => r.note !== "run-end"));
  for (const edit of [
    (x) => (x.summary.recordingComplete = false),
    (x) => (x.rows.find((r) => r.event === "request-dispatch").requestSha256 = "0".repeat(64)),
    (x) => {
      const row = x.rows.find((r) => r.event === "cell-manifest");
      row.creationOrder = row.creationOrder.toReversed();
    },
    (x) => (x.rows.find((r) => r.event === "response").requestId = 9999),
  ]) {
    const bad = structuredClone(f);
    edit(bad);
    assert.throws(() => importRecording(bad.rows, bad.summary));
  }
});
test("B replay recreates graph in recorded order and binds only exact witnessed pages", async () => {
  const f = fixture(),
    local = localModel(),
    r = await replayRecording(importRecording(f.rows, f.summary), local.call);
  assert.equal(r.rows.filter((x) => x.semantic !== "MATCH").length, 0);
  assert.equal(r.layoutDebts.length, 18);
  assert.ok(
    r.layoutDebts.every((x) => x.verdict === "NOT_COMPARABLE_NATIVE_ERROR_BODY_NOT_CAPTURED"),
  );
  assert.equal(r.parentClosureReady, false);
  assert.deepEqual(
    local.calls.filter((c) => c.method.startsWith("Create")).map((c) => c.request.name),
    f.rows
      .filter((row) => row.event === "request-dispatch" && row.method.startsWith("Create"))
      .map((row) => row.request.name),
  );
  assert.ok(
    local.calls
      .filter((c) => c.request.pageToken)
      .every((c) => !c.request.pageToken.startsWith("production-")),
  );
});
test("B mismatched first page never binds cursor or sends dependent deletion/continuation", async () => {
  const f = fixture(),
    local = localModel(),
    call = async (q) => {
      const r = await local.call(q);
      if (
        q.cellId === "R1" &&
        q.method === "ListTopics" &&
        q.request.pageSize === 1 &&
        !q.request.pageToken
      )
        r.body.topics = [];
      return r;
    };
  const r = await replayRecording(importRecording(f.rows, f.summary), call);
  assert.ok(r.rows.some((x) => x.semantic === "DIVERGES"));
  assert.ok(r.rows.some((x) => x.semantic === "NOT_COMPARABLE" && x.reason.includes("cursor")));
  assert.equal(
    local.calls.some((c) => c.cellId === "R1" && c.request.pageToken),
    false,
  );
});
test("B native refusal compares actual code/details while preserving raw-layout NC", () => {
  const expected = {
    ok: false,
    code: "NOT_FOUND",
    unknown: false,
    body: { error: { status: "NOT_FOUND", message: "missing" } },
    bodyBytes: null,
    layoutVerdict: "NOT_COMPARABLE_NATIVE_ERROR_BODY_NOT_CAPTURED",
  };
  assert.equal(
    compareReply("grpc", expected, { code: "NOT_FOUND", unknown: false, message: "missing" })
      .semantic,
    "MATCH",
  );
  assert.equal(
    compareReply("grpc", expected, { code: "INVALID_ARGUMENT", unknown: false, message: "missing" })
      .semantic,
    "DIVERGES",
  );
  assert.equal(
    compareReply("grpc", expected, { code: "NOT_FOUND", unknown: false, message: "changed" })
      .semantic,
    "DIVERGES",
  );
  assert.equal(
    compareReply("grpc", expected, { code: "NOT_FOUND", unknown: true, message: "missing" })
      .semantic,
    "NOT_COMPARABLE",
  );
  assert.equal(
    compareReply("grpc", expected, { code: "NOT_FOUND", unknown: false }).semantic,
    "NOT_COMPARABLE",
  );
});
test("B importer refuses edited cell closure and oversized page evidence", () => {
  for (const edit of [
    (f) => (f.rows.find((r) => r.event === "case-result").cleanupClosed = false),
    (f) =>
      (f.rows.find(
        (r) => r.event === "request-dispatch" && r.method.startsWith("List"),
      ).requestDeadlineAt = "invalid"),
  ]) {
    const f = fixture();
    edit(f);
    assert.throws(() => importRecording(f.rows, f.summary));
  }
});
test("B binding requires whole reply match, not only matching member names", async () => {
  const f = fixture(),
    local = localModel();
  const r = await replayRecording(importRecording(f.rows, f.summary), async (q) => {
    const answer = await local.call(q);
    if (
      q.cellId === "R1" &&
      q.method === "ListTopics" &&
      q.request.pageSize === 1 &&
      !q.request.pageToken
    )
      answer.body.extra = "unexpected";
    return answer;
  });
  assert.ok(r.rows.some((x) => x.semantic === "DIVERGES"));
  assert.equal(
    local.calls.some((c) => c.cellId === "R1" && c.request.pageToken),
    false,
  );
});
test("B native selectors use the existing protobuf schema rather than normalized name", async () => {
  const { nativeRequest } = await import("./pubsub-observation-b/replay.mjs");
  for (const kind of ["Topic", "Subscription", "Snapshot"])
    for (const verb of ["Get", "Delete"])
      assert.deepEqual(nativeRequest(verb + kind, { name: "owned" }), {
        [kind.toLowerCase()]: "owned",
      });
  assert.deepEqual(nativeRequest("CreateTopic", { name: "owned" }), { name: "owned" });
});
test("B local transport executes witnessed dispatch clocks and closes on failures", async () => {
  const { replayLocal } = await import("./pubsub-observation-b/replay.mjs");
  const f = fixture(),
    input = importRecording(f.rows, f.summary),
    clocks = [];
  let closed = 0;
  const pin = {
      profile: "release",
      rustcWrapper: "",
      sha256: "a".repeat(64),
      head: "b".repeat(40),
      command: ["cargo", "build", "--release"],
      path: "/fixture/release/fireemu",
    },
    env = {
      PUBSUB_EMULATOR_HOST: "127.0.0.1:1234",
      FIREEMU_CONTROL_URL: "http://127.0.0.1:1235/v1/",
      FIREEMU_CONTROL_TOKEN: "local-test",
    };
  const factories = {
    fetch: async (url, opts) => {
      clocks.push(JSON.parse(opts.body).instant);
      return { ok: true, arrayBuffer: async () => new ArrayBuffer(0) };
    },
    rest: () => ({ request: async () => ({ status: 200, body: {} }) }),
    grpc: () => ({
      close: () => closed++,
      call: async () => ({ code: "UNAVAILABLE", unknown: true }),
    }),
  };
  await replayLocal(input, env, pin, factories);
  assert.equal(closed, 1);
  assert.ok(clocks.length > 0);
  assert.ok(
    clocks.every((at) => f.rows.some((r) => r.event === "request-dispatch" && r.at === at)),
  );
  await assert.rejects(
    replayLocal(input, env, pin, { ...factories, fetch: async () => ({ ok: false }) }),
    /clock advance/,
  );
  assert.equal(closed, 2);
  await assert.rejects(
    replayLocal(
      input,
      { ...env, PUBSUB_EMULATOR_HOST: "pubsub.googleapis.com:443" },
      pin,
      factories,
    ),
    /loopback/,
  );
});
test("B cursor deletion must target the recorded first page member", () => {
  const f = fixture(),
    dispatch = f.rows.find((r) => r.category === "cursorDelete");
  dispatch.request.name = graph(makePlan().cells[0], runId).members.find(
    (n) => n !== dispatch.request.name,
  );
  const address = route(dispatch.method, dispatch.request);
  dispatch.url = address.url;
  dispatch.verb = address.verb;
  dispatch.requestSha256 = hash(Buffer.from(""));
  assert.throws(() => importRecording(f.rows, f.summary), /cursor deletion/);
});
test("B input byte pins and strict parent provenance fail closed before replay", async () => {
  const { pinnedBytes, validateLaunch } = await import("./pubsub-observation-b/replay.mjs");
  const { mkdtempSync, writeFileSync, rmSync } = await import("node:fs"),
    { tmpdir } = await import("node:os"),
    { join } = await import("node:path");
  const temporary = mkdtempSync(join(tmpdir(), "b-replay-guard-test-"));
  try {
    const path = join(temporary, "config.json"),
      input = importRecording(fixture().rows, fixture().summary),
      pin = { path: "/fixture/release/fireemu" };
    const bytes = Buffer.from(
      JSON.stringify({
        profile: "strict",
        bind: "127.0.0.1",
        daemon: { pubsubPort: 0, authProject: PROJECT, clockStart: input.metadata.at },
      }),
    );
    writeFileSync(path, bytes);
    const launch = { serverPid: 123, parentPid: 122, config: path, configSha256: hash(bytes) },
      ancestry = `122 ${pin.path} exec --config ${path} --only pubsub -- node`;
    assert.deepEqual(pinnedBytes(path, hash(bytes)), bytes);
    assert.throws(() => pinnedBytes(path, "0".repeat(64)), /pin refused/);
    validateLaunch(launch, pin, input, ancestry, 123);
    assert.throws(() => validateLaunch(launch, pin, input, ancestry, 124), /provenance/);
    assert.throws(
      () =>
        validateLaunch(launch, pin, input, ancestry.replace("--only pubsub", "--only auth"), 123),
      /provenance/,
    );
    writeFileSync(path, bytes.toString().replace("strict", "legacy"));
    assert.throws(
      () =>
        validateLaunch(
          {
            ...launch,
            configSha256: hash(Buffer.from(bytes.toString().replace("strict", "legacy"))),
          },
          pin,
          input,
          ancestry,
          123,
        ),
      /strict B config/,
    );
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});
test("B exec setup deadline escalates only verified owned PID and removes listeners", async () => {
  const { waitForExec } = await import("./pubsub-observation-b/replay.mjs");
  const { EventEmitter } = await import("node:events");
  const child = new EventEmitter(),
    signals = new EventEmitter(),
    sent = [];
  child.pid = 123;
  child.kill = (signal) => {
    sent.push(signal);
    if (signal === "SIGKILL") queueMicrotask(() => child.emit("exit", null, "SIGKILL"));
    return true;
  };
  await assert.rejects(
    waitForExec(
      child,
      {
        path: "/fixture/release/fireemu",
        args: ["exec", "--config", "owned.json"],
        parentPid: 122,
      },
      {
        setupMs: 5,
        replayMs: 100,
        graceMs: 5,
        killMs: 5,
        ready: () => false,
        signals,
        inspect: () => "122 fireemu /fixture/release/fireemu exec --config owned.json",
      },
    ),
    /setup deadline/,
  );
  assert.deepEqual(sent, ["SIGTERM", "SIGKILL"]);
  assert.equal(signals.listenerCount("SIGTERM"), 0);
  assert.equal(child.listenerCount("exit"), 0);
});
test("B exec refuses escalation when exact owned identity differs", async () => {
  const { waitForExec } = await import("./pubsub-observation-b/replay.mjs");
  const { EventEmitter } = await import("node:events");
  const child = new EventEmitter(),
    signals = new EventEmitter(),
    sent = [];
  child.pid = 123;
  child.kill = (s) => {
    sent.push(s);
    return true;
  };
  await assert.rejects(
    waitForExec(
      child,
      { path: "/fixture/release/fireemu", args: ["exec"], parentPid: 122 },
      {
        setupMs: 5,
        replayMs: 100,
        graceMs: 5,
        killMs: 5,
        ready: () => false,
        signals,
        inspect: () => "999 fireemu /fixture/release/fireemu exec",
      },
    ),
    /identity/,
  );
  assert.deepEqual(sent, ["SIGTERM"]);
  assert.equal(signals.listenerCount("SIGINT"), 0);
});
test("B exec completion clears deadlines and ignored TERM has a finite final wait", async () => {
  const { waitForExec } = await import("./pubsub-observation-b/replay.mjs");
  const { EventEmitter } = await import("node:events");
  const expected = { path: "/fixture/release/fireemu", args: ["exec"], parentPid: 122 };
  let inspected = 0;
  const child = new EventEmitter(),
    signals = new EventEmitter();
  child.pid = 123;
  child.kill = () => {
    throw Error("completed child must not be signalled");
  };
  const options = {
    setupMs: 5,
    replayMs: 10,
    graceMs: 5,
    killMs: 5,
    ready: () => true,
    signals,
    inspect: () => {
      inspected++;
      return "122 fireemu /fixture/release/fireemu exec";
    },
  };
  const done = waitForExec(child, expected, options);
  child.emit("exit", 0);
  assert.equal(await done, 0);
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(inspected, 0);
  assert.equal(child.listenerCount("error"), 0);
  const stuck = new EventEmitter(),
    sent = [];
  stuck.pid = 124;
  stuck.kill = (s) => {
    sent.push(s);
    return true;
  };
  await assert.rejects(waitForExec(stuck, expected, options), /shutdown completion/);
  assert.deepEqual(sent, ["SIGTERM", "SIGKILL"]);
  assert.equal(signals.listenerCount("SIGTERM"), 0);
});
test("B exec identity inspection checks command and parent independently", async () => {
  const { waitForExec } = await import("./pubsub-observation-b/replay.mjs");
  const { EventEmitter } = await import("node:events");
  for (const identity of [
    "122 other /fixture/release/fireemu exec",
    "122 fireemu /fixture/release/fireemu unrelated",
  ]) {
    const child = new EventEmitter(),
      signals = new EventEmitter(),
      sent = [];
    child.pid = 123;
    child.kill = (s) => {
      sent.push(s);
      return true;
    };
    await assert.rejects(
      waitForExec(
        child,
        { path: "/fixture/release/fireemu", args: ["exec"], parentPid: 122 },
        { setupMs: 5, replayMs: 100, graceMs: 5, killMs: 5, signals, inspect: () => identity },
      ),
      /identity/,
    );
    assert.deepEqual(sent, ["SIGTERM"]);
  }
});
test("B public deadline removes temporary config without launching a server", async (t) => {
  const childProcess = await import("node:child_process"),
    { syncBuiltinESMExports } = await import("node:module"),
    { EventEmitter } = await import("node:events"),
    fs = await import("node:fs"),
    { tmpdir } = await import("node:os"),
    { join } = await import("node:path");
  const { main } = await import("./pubsub-observation-b/replay.mjs");
  const temporary = fs.mkdtempSync(join(tmpdir(), "b-public-lifecycle-test-")),
    f = fixture();
  let config, child;
  t.mock.timers.enable({ apis: ["setTimeout"] });
  t.mock.method(childProcess.default, "spawn", (_path, args) => {
    config = args[2];
    child = new EventEmitter();
    child.pid = 123;
    child.stdin = new EventEmitter();
    child.stdin.end = () => {};
    child.kill = () => {
      queueMicrotask(() => child.emit("exit", null, "SIGTERM"));
      return true;
    };
    return child;
  });
  syncBuiltinESMExports();
  try {
    const capture = join(temporary, "capture.jsonl"),
      summary = join(temporary, "summary.json"),
      build = join(temporary, "pin.json"),
      binary = join(temporary, "release", "fireemu");
    fs.mkdirSync(join(temporary, "release"));
    const captureBytes = Buffer.from(f.rows.map((r) => JSON.stringify(r)).join("\n")),
      summaryBytes = Buffer.from(JSON.stringify(f.summary)),
      binaryBytes = Buffer.from("mock-no-server");
    fs.writeFileSync(capture, captureBytes);
    fs.writeFileSync(summary, summaryBytes);
    fs.writeFileSync(binary, binaryBytes);
    const pinBytes = Buffer.from(
      JSON.stringify({
        path: binary,
        sha256: hash(binaryBytes),
        head: "a".repeat(40),
        profile: "release",
        rustcWrapper: "",
        command: ["cargo", "build", "--release"],
      }),
    );
    fs.writeFileSync(build, pinBytes);
    const done = main(
      [
        "--capture",
        capture,
        "--capture-sha256",
        hash(captureBytes),
        "--summary",
        summary,
        "--summary-sha256",
        hash(summaryBytes),
        "--build-pin",
        build,
        "--build-pin-sha256",
        hash(pinBytes),
        "--out",
        join(temporary, "out"),
      ],
      {},
    );
    assert.equal(fs.existsSync(config), true);
    t.mock.timers.tick(30000);
    await assert.rejects(done, /setup deadline/);
    assert.equal(fs.existsSync(config), false);
    assert.equal(child.listenerCount("exit"), 0);
    t.mock.method(childProcess.default, "execFileSync", () => {
      throw Error("fixture ps refused");
    });
    syncBuiltinESMExports();
    const unresolvedOut = join(temporary, "unresolved-out");
    const refused = main(
      [
        "--capture",
        capture,
        "--capture-sha256",
        hash(captureBytes),
        "--summary",
        summary,
        "--summary-sha256",
        hash(summaryBytes),
        "--build-pin",
        build,
        "--build-pin-sha256",
        hash(pinBytes),
        "--out",
        unresolvedOut,
      ],
      {},
    );
    let destroyed = 0,
      unreferenced = 0;
    child.kill = () => true;
    child.stdin.destroy = () => destroyed++;
    child.unref = () => unreferenced++;
    t.mock.timers.tick(30000);
    t.mock.timers.tick(12000);
    await assert.rejects(refused, /fixture ps refused/);
    const receipt = JSON.parse(
      fs.readFileSync(join(unresolvedOut, "lifecycle-failure.json"), "utf8"),
    );
    assert.equal(receipt.unresolvedProcess.pid, 123);
    assert.equal(receipt.unresolvedProcess.terminationConfirmed, false);
    assert.equal(receipt.cleanupComplete, false);
    assert.equal(destroyed, 1);
    assert.equal(unreferenced, 1);
    assert.equal(fs.existsSync(config), false);
  } finally {
    t.mock.restoreAll();
    syncBuiltinESMExports();
    t.mock.timers.reset();
    fs.rmSync(temporary, { recursive: true, force: true });
  }
});
test("B real child refusal releases public handles and retains unresolved ownership", async () => {
  const { spawn, execFileSync } = await import("node:child_process"),
    { once } = await import("node:events");
  const moduleUrl = new URL("./pubsub-observation-b/replay.mjs", import.meta.url).href;
  const harmless =
    "process.on('SIGTERM',()=>{});setInterval(()=>{},1000);process.stdout.write('ready');";
  const harness = `import {spawn,execFileSync} from 'node:child_process';import {once} from 'node:events';import {waitForExec} from ${JSON.stringify(moduleUrl)};const child=spawn(process.execPath,['--eval',${JSON.stringify(harmless)}],{stdio:['pipe','pipe','ignore']});await once(child.stdout,'data');const identity=execFileSync('ps',['-ww','-p',String(child.pid),'-o','ppid=,lstart=,comm=,args='],{encoding:'utf8',timeout:1000}).trim();console.log(JSON.stringify({receipt:{pid:child.pid,parentPid:process.pid,identity,stableIdentity:identity.replace(/^\\d+\\s+/,''),args:[process.execPath,'--eval',${JSON.stringify(harmless)}]}}));try{await waitForExec(child,{path:process.execPath,args:['--eval',${JSON.stringify(harmless)}],parentPid:process.pid},{setupMs:10,replayMs:1000,graceMs:10,killMs:10,inspect:()=>{throw Error('simulated bounded ps refusal');}});}catch(error){console.log(JSON.stringify({refused:error.message,unresolved:error.unresolvedProcess??null}));process.exitCode=2;}`;
  const outer = spawn(process.execPath, ["--input-type=module", "--eval", harness], {
    stdio: ["ignore", "pipe", "pipe"],
    env: { PATH: process.env.PATH, LANG: "C", LC_ALL: "C", TZ: "UTC" },
  });
  let text = "",
    errors = "",
    exited = false;
  outer.stdout.on("data", (b) => (text += b));
  outer.stderr.on("data", (b) => (errors += b));
  const completion = once(outer, "exit").then(([code]) => {
    exited = true;
    return code;
  });
  let timer,
    receipt,
    result,
    cleanup = false;
  try {
    result = await Promise.race([
      completion,
      new Promise((resolve) => {
        timer = setTimeout(() => resolve("deadline"), 2000);
      }),
    ]);
    receipt = text
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line))
      .find((row) => row.receipt)?.receipt;
    assert.ok(receipt, "durable actual pid/birth/comm/args receipt required");
    console.log(JSON.stringify({ actualChildReceipt: receipt, outerExit: result }));
    assert.equal(result, 2, errors);
    const refused = text
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line))
      .find((row) => row.refused);
    assert.equal(refused.unresolved?.pid, receipt.pid);
    assert.equal(refused.unresolved?.terminationConfirmed, false);
    assert.equal(refused.unresolved?.identityVerified, false);
  } finally {
    clearTimeout(timer);
    if (!receipt)
      receipt = text
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line))
        .find((row) => row.receipt)?.receipt;
    if (receipt) {
      const current = execFileSync(
        "ps",
        ["-ww", "-p", String(receipt.pid), "-o", "ppid=,lstart=,comm=,args="],
        {
          encoding: "utf8",
          timeout: 1000,
          env: { ...process.env, LANG: "C", LC_ALL: "C", TZ: "UTC" },
        },
      ).trim();
      assert.equal(
        current.replace(/^\d+\s+/, ""),
        receipt.stableIdentity,
        "external cleanup requires exact birth/comm/args match",
      );
      process.kill(receipt.pid, "SIGTERM");
      await new Promise((resolve) => setTimeout(resolve, 20));
      const again = execFileSync(
        "ps",
        ["-ww", "-p", String(receipt.pid), "-o", "ppid=,lstart=,comm=,args="],
        {
          encoding: "utf8",
          timeout: 1000,
          env: { ...process.env, LANG: "C", LC_ALL: "C", TZ: "UTC" },
        },
      ).trim();
      assert.equal(again.replace(/^\d+\s+/, ""), receipt.stableIdentity);
      process.kill(receipt.pid, "SIGKILL");
      cleanup = true;
    }
    if (!exited) {
      outer.kill("SIGTERM");
      await Promise.race([
        completion,
        new Promise((_, reject) => setTimeout(() => reject(Error("outer cleanup deadline")), 2000)),
      ]);
    }
    console.log(
      JSON.stringify({
        externalCleanup: {
          exactPid: receipt?.pid,
          birthCommArgsRechecked: cleanup,
          targetedKill: cleanup,
          outerReaped: exited,
          servers: 0,
        },
      }),
    );
  }
});
test("B credential-free local transports send no PubSub Authorization", async () => {
  const { replayLocal } = await import("./pubsub-observation-b/replay.mjs"),
    { createRest } = await import("./pubsub-production/rest.mjs"),
    { createGrpc } = await import("./pubsub-production/grpc.mjs"),
    { default: grpcLibrary } = await import("@grpc/grpc-js");
  const f = fixture(),
    input = importRecording(f.rows, f.summary),
    restHeaders = [],
    nativeMetadata = [];
  let closed = 0;
  class NoNetworkClient {
    close() {
      closed++;
    }
    makeUnaryRequest(_path, serialize, _deserialize, request, metadata, _options, callback) {
      serialize(request);
      nativeMetadata.push(metadata.getMap());
      callback(null, {});
    }
  }
  const pin = {
      profile: "release",
      rustcWrapper: "",
      sha256: "a".repeat(64),
      head: "b".repeat(40),
      command: ["cargo", "build", "--release"],
      path: "/fixture/release/fireemu",
    },
    environment = {
      PUBSUB_EMULATOR_HOST: "127.0.0.1:1234",
      FIREEMU_CONTROL_URL: "http://127.0.0.1:1235/v1/",
      FIREEMU_CONTROL_TOKEN: "control-only-test",
    };
  await replayLocal(input, environment, pin, {
    fetch: async () => ({ ok: true, arrayBuffer: async () => new ArrayBuffer(0) }),
    rest: (options) =>
      createRest({
        ...options,
        fetchImpl: async (_url, request) => {
          restHeaders.push(request.headers);
          return {
            status: 200,
            headers: { get: () => null },
            arrayBuffer: async () => Buffer.from("{}"),
          };
        },
      }),
    grpc: (options) =>
      createGrpc({ ...options, grpc: { ...grpcLibrary, Client: NoNetworkClient } }),
  });
  assert.ok(restHeaders.length > 0);
  assert.ok(nativeMetadata.length > 0);
  assert.equal(closed, 2);
  for (const headers of [...restHeaders, ...nativeMetadata])
    assert.equal(
      Object.keys(headers).some((key) => key.toLowerCase() === "authorization"),
      false,
      "PubSub REST/native requests must omit Authorization",
    );
});
