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
      return {
        ok: true,
        status: 200,
        arrayBuffer: async () =>
          Buffer.from(JSON.stringify({ clock: JSON.parse(opts.body).instant })),
      };
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
    fetch: async (_url, opts) => ({
      ok: true,
      status: 200,
      arrayBuffer: async () =>
        Buffer.from(JSON.stringify({ clock: JSON.parse(opts.body).instant })),
    }),
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

// Independent local cursor evidence never changes the original recorded judgments.
function independentListModel(input, edit = (reply) => reply, ownOrder = null) {
  const resources = new Map(),
    tokens = new Map(),
    calls = [];
  const order = ownOrder ?? input.cells[0].manifest.manifest.members.toReversed();
  return {
    calls,
    async call(q) {
      calls.push(structuredClone(q));
      let reply;
      if (q.method.startsWith("Create")) {
        resources.set(q.request.name, { name: q.request.name });
        reply = { code: "OK", status: 200, ok: true, body: { name: q.request.name } };
      } else if (q.method.startsWith("Delete")) {
        const existed = resources.delete(q.request.name);
        reply = {
          code: existed ? "OK" : "NOT_FOUND",
          status: existed ? 200 : 404,
          body: existed ? {} : { error: { status: "NOT_FOUND", message: "missing" } },
        };
      } else if (q.method.startsWith("Get"))
        reply = resources.has(q.request.name)
          ? { code: "OK", status: 200, body: resources.get(q.request.name) }
          : {
              code: "NOT_FOUND",
              status: 404,
              message: "missing",
              body: { error: { status: "NOT_FOUND", message: "missing" } },
            };
      else {
        const anchor = q.request.pageToken ? tokens.get(q.request.pageToken) : null;
        if (q.request.pageToken && !anchor)
          reply = {
            code: "INVALID_ARGUMENT",
            status: 400,
            message: "invalid token",
            body: { error: { status: "INVALID_ARGUMENT", message: "invalid token" } },
          };
        else {
          const offset = anchor ? order.indexOf(anchor) + 1 : 0,
            available = order.slice(offset).filter((n) => resources.has(n)),
            names = available.slice(0, q.request.pageSize);
          const token = names.length < available.length ? `issued-${names.at(-1)}` : null;
          if (token) tokens.set(token, names.at(-1));
          reply = {
            code: "OK",
            status: 200,
            body: {
              topics: names.map((n) => resources.get(n)),
              ...(token ? { nextPageToken: token } : {}),
            },
          };
        }
      }
      return edit(reply, q);
    },
  };
}
function oneListInput() {
  const input = importRecording(fixture().rows, fixture().summary);
  input.cells = input.cells.slice(0, 1);
  return input;
}
test("B independent cursor witness preserves raw mismatch and proves its own deletion and full walks", async () => {
  const input = oneListInput(),
    local = independentListModel(input),
    report = await replayRecording(input, local.call);
  assert.equal(report.rows.find((r) => r.requestId === 9).semantic, "DIVERGES");
  assert.equal(report.rows.find((r) => r.requestId === 11).semantic, "NOT_COMPARABLE");
  assert.ok(Array.isArray(report.semanticWitnesses), "independent witnesses required");
  const witness = report.semanticWitnesses[0];
  assert.equal(witness.verdict, "MATCH");
  assert.equal(witness.selectedMember, input.cells[0].manifest.manifest.members.at(-1));
  assert.equal(witness.before.members.length, 4);
  assert.equal(witness.after.members.length, 3);
  assert.equal(witness.deleted.status, 200);
  assert.equal(witness.absence.status, 404);
  assert.ok(witness.requests.every((r) => r.originalRequest && r.actualSemanticRequest && r.ref));
  assert.ok(
    local.calls
      .filter((c) => c.request.pageToken)
      .every((c) => !c.request.pageToken.startsWith("production-")),
  );
  assert.equal(report.parentClosureReady, false);
});
test("B independent cursor witness rejects malformed fields, duplicate and missing inventory and overflow", async () => {
  for (const change of [
    (r) => {
      r.body.topics[0].unexpected = true;
    },
    (r) => {
      r.body.topics = [r.body.topics[0], r.body.topics[0]];
    },
    (r) => {
      r.body.topics = [];
      delete r.body.nextPageToken;
    },
    (r) => {
      r.body.topics.push({ ...r.body.topics[0], name: "projects/foreign/topics/not-owned" });
    },
    (r) => {
      r.body.topics = [...r.body.topics, ...r.body.topics];
    },
  ]) {
    const input = oneListInput(),
      local = independentListModel(input, (r, q) => {
        if (q.semanticRef && q.method === "ListTopics") change(r);
        return r;
      });
    const report = await replayRecording(input, local.call);
    assert.ok(Array.isArray(report.semanticWitnesses), "independent witnesses required");
    assert.equal(report.semanticWitnesses[0].verdict, "DIVERGES");
  }
});
test("B independent cursor witness never follows repeated or foreign cursor or unknown native effects", async () => {
  for (const mode of ["cursor", "unknown"]) {
    const input = oneListInput();
    if (mode === "unknown") input.cells[0].cell.transport = "grpc";
    const local = independentListModel(input, (r, q) => {
      if (q.semanticRef && q.method === "ListTopics") {
        if (mode === "cursor") r.body.nextPageToken = "foreign-repeat";
        else r = { code: "UNAVAILABLE", unknown: true };
      }
      return r;
    });
    const report = await replayRecording(input, local.call);
    assert.ok(Array.isArray(report.semanticWitnesses), "independent witnesses required");
    assert.equal(
      report.semanticWitnesses[0].verdict,
      mode === "unknown" ? "NOT_COMPARABLE" : "DIVERGES",
    );
    assert.ok(local.calls.filter((c) => c.request.pageToken === "foreign-repeat").length <= 1);
  }
});

function generatedInput() {
  const base = oneListInput(),
    cell = base.cells[0].cell,
    topic = `projects/${PROJECT}/topics/fe${runId}-r7-prereq`,
    name = `projects/${PROJECT}/snapshots/fe${runId}-r7-a`,
    at = "2026-10-09T00:00:00.123Z",
    sourceExpiry = "2026-10-16T00:00:00.234Z";
  cell.kind = "snapshots";
  cell.id = "R7";
  const make = (id, method, request, body) => ({
    dispatch: { requestId: id, n: id, at, cellId: "R7", transport: "rest", method, request },
    response: { reply: { code: "OK", status: 200, ok: true, body } },
  });
  base.cells[0] = {
    cell,
    manifest: { manifest: { members: [name], resources: [] } },
    exchanges: [
      make(
        1,
        "Publish",
        { topic, messages: [{ data: "eA==" }] },
        { messageIds: ["12345678901234567"] },
      ),
      make(
        2,
        "CreateSnapshot",
        { name, subscription: `projects/${PROJECT}/subscriptions/fe${runId}-r7-prereq` },
        { name, topic, expireTime: sourceExpiry },
      ),
      make(3, "GetSnapshot", { name }, { name, topic, expireTime: sourceExpiry }),
    ],
  };
  return { input: base, at, name, topic };
}
test("B generated snapshot witness binds successful publication and stable Create/Get while expiry effects stay unobserved", async () => {
  const { input, at, name, topic } = generatedInput();
  const report = await replayRecording(input, async (q) => ({
    code: "OK",
    status: 200,
    body:
      q.method === "Publish"
        ? { messageIds: ["22222222222222222"] }
        : { name, topic, expireTime: "2026-10-16T00:00:00.123Z" },
    clockReadback: { clock: at, sourceRequestId: q.requestId },
  }));
  assert.ok(Array.isArray(report.generatedWitnesses), "generated witnesses required");
  assert.equal(report.generatedWitnesses.length, 3);
  assert.ok(report.generatedWitnesses.every((w) => w.verdict === "MATCH"));
  assert.ok(report.rows.every((r) => r.semantic === "DIVERGES"));
  assert.equal(report.generatedWitnesses[1].expiryEffects, "NOT_COMPARABLE_NOT_OBSERVED");
  assert.equal(report.parentClosureReady, false);
});
test("B generated witness rejects ID width/alphabet/collision and lifetime or stable-value drift", async () => {
  for (const mode of ["width", "alphabet", "unbound", "lifetime", "drift", "extra", "unknown"]) {
    const { input, at, name, topic } = generatedInput();
    const report = await replayRecording(input, async (q) => {
      let reply = {
        code: "OK",
        status: 200,
        body:
          q.method === "Publish"
            ? {
                messageIds: [
                  mode === "width"
                    ? "1"
                    : mode === "alphabet"
                      ? "a".repeat(17)
                      : "22222222222222222",
                ],
              }
            : {
                name,
                topic,
                expireTime:
                  mode === "lifetime" || (mode === "drift" && q.method === "GetSnapshot")
                    ? "2026-10-16T00:00:00.124Z"
                    : "2026-10-16T00:00:00.123Z",
              },
        ...(mode === "unbound"
          ? {}
          : { clockReadback: { clock: at, sourceRequestId: q.requestId } }),
      };
      if (mode === "extra" && q.method === "CreateSnapshot") reply.body.extra = true;
      if (mode === "unknown" && q.method === "CreateSnapshot")
        reply = { code: "UNAVAILABLE", unknown: true };
      return reply;
    });
    assert.ok(Array.isArray(report.generatedWitnesses), "generated witnesses required");
    assert.ok(
      report.generatedWitnesses.some((w) => w.verdict !== "MATCH"),
      mode,
    );
  }
});

test("B public virtual clock rejects nanosecond readback drift without a transport dispatch", async () => {
  const { replayLocal } = await import("./pubsub-observation-b/replay.mjs"),
    input = oneListInput();
  let sent = 0;
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
  await assert.rejects(
    replayLocal(input, env, pin, {
      fetch: async (_url, opts) => ({
        ok: true,
        status: 200,
        arrayBuffer: async () =>
          Buffer.from(
            JSON.stringify({
              clock: JSON.parse(opts.body).instant.replace(/(\.\d{3})Z$/, "$1000001Z"),
            }),
          ),
      }),
      rest: () => ({
        request: async () => {
          sent++;
          return { status: 200, body: {} };
        },
      }),
      grpc: () => ({
        close() {},
        call: async () => {
          sent++;
          return { code: "OK", body: {} };
        },
      }),
    }),
    /readback/,
  );
  assert.equal(sent, 0);
});

test("B independent unknown selected DELETE stays unresolved and is never retried by cleanup", async () => {
  const input = oneListInput(),
    selected = input.cells[0].manifest.manifest.members.at(-1),
    local = independentListModel(input, (reply, q) =>
      q.semanticRef && q.method === "DeleteTopic" && q.request.name === selected
        ? { code: "UNAVAILABLE", unknown: true }
        : reply,
    );
  const report = await replayRecording(input, local.call),
    witness = report.semanticWitnesses[0];
  assert.equal(witness.verdict, "NOT_COMPARABLE");
  assert.equal(witness.cleanup.complete, false);
  assert.deepEqual(witness.cleanup.unknownDeletes, [selected]);
  assert.equal(
    local.calls.filter((q) => q.method === "DeleteTopic" && q.request.name === selected).length,
    1,
  );
});
test("B generated ID correspondence refuses collision across distinct successful publications", async () => {
  const { input, at } = generatedInput();
  const original = input.cells[0].exchanges[0],
    second = structuredClone(original);
  second.dispatch.requestId = 4;
  second.dispatch.n = 4;
  second.response.reply.body.messageIds = ["12345678901234568"];
  input.cells[0].exchanges = [original, second];
  const report = await replayRecording(input, async (q) => ({
    code: "OK",
    status: 200,
    body: { messageIds: ["22222222222222222"] },
    clockReadback: { clock: at, sourceRequestId: q.requestId },
  }));
  assert.equal(report.generatedWitnesses[0].verdict, "MATCH");
  assert.equal(report.generatedWitnesses[1].verdict, "DIVERGES");
});
test("B independent inventory decisions agree with a finite permutation reference", async () => {
  const permutations = [];
  const visit = (remaining, prefix = []) => {
    if (!remaining.length) {
      permutations.push(prefix);
      return;
    }
    remaining.forEach((value, index) =>
      visit(
        remaining.filter((_, i) => i !== index),
        [...prefix, value],
      ),
    );
  };
  visit([0, 1, 2, 3]);
  for (const permutation of permutations) {
    const input = oneListInput(),
      names = input.cells[0].manifest.manifest.members;
    const firstOriginal = input.cells[0].exchanges.find((e) => e.page?.stage === "first").page
      .names[0];
    const transformed = {
      ...input,
      cells: [
        {
          ...input.cells[0],
          manifest: {
            ...input.cells[0].manifest,
            manifest: {
              ...input.cells[0].manifest.manifest,
              members: permutation.map((i) => names[i]),
            },
          },
        },
      ],
    };
    const model = independentListModel(transformed),
      report = await replayRecording(input, model.call),
      witness = report.semanticWitnesses[0];
    assert.equal(witness.verdict, "MATCH");
    assert.equal(witness.before.members.length, 4);
    assert.equal(witness.after.members.length, 3);
    assert.equal(witness.sameSelectedMember, witness.selectedMember === firstOriginal);
    assert.equal(witness.cleanup.complete, true);
    assert.equal(report.parentClosureReady, false);
  }
});

test("B independent page-size bound rejects an oversized otherwise complete unique walk", async () => {
  const input = oneListInput(),
    local = independentListModel(input);
  const report = await replayRecording(input, (q) =>
    local.call(
      q.semanticRef && q.method === "ListTopics"
        ? { ...q, request: { ...q.request, pageSize: 2 } }
        : q,
    ),
  );
  assert.equal(report.semanticWitnesses[0].verdict, "DIVERGES");
  assert.match(report.semanticWitnesses[0].reason, /overflow/);
});
test("B independent own cursor cannot repeat even when a server advances its response members", async () => {
  const input = oneListInput(),
    local = independentListModel(input);
  let issued;
  const report = await replayRecording(input, async (q) => {
    const mapped =
      q.request.pageToken === "repeat-cursor"
        ? { ...q, request: { ...q.request, pageToken: issued } }
        : q;
    const reply = await local.call(mapped);
    if (q.semanticRef && q.method === "ListTopics" && reply.body?.nextPageToken) {
      issued = reply.body.nextPageToken;
      reply.body.nextPageToken = "repeat-cursor";
    }
    return reply;
  });
  assert.equal(report.semanticWitnesses[0].verdict, "DIVERGES");
  assert.match(report.semanticWitnesses[0].reason, /repeated cursor/);
});
test("B snapshot backlog lifetime is exact even when a wrong value stays within creation bounds", async () => {
  const { input, at, name, topic } = generatedInput();
  input.cells[0].exchanges[1].dispatch.at = "2026-10-09T00:00:00.223Z";
  input.cells[0].exchanges[2].dispatch.at = "2026-10-09T00:00:00.224Z";
  const report = await replayRecording(input, async (q) => ({
    code: "OK",
    status: 200,
    body:
      q.method === "Publish"
        ? { messageIds: ["22222222222222222"] }
        : { name, topic, expireTime: "2026-10-16T00:00:00.124Z" },
    clockReadback: { clock: q.method === "Publish" ? at : q.at, sourceRequestId: q.requestId },
  }));
  assert.equal(report.generatedWitnesses[1].verdict, "DIVERGES");
  assert.match(report.generatedWitnesses[1].reason, /backlog lifetime/);
});

test("B observed selected DELETE and absence require confirmed actual replies", async () => {
  for (const mode of ["refused-delete", "unknown-absence"]) {
    const input = oneListInput();
    const order = input.cells[0].exchanges.find((e) => e.page?.stage === "baseline").page.names;
    const local = independentListModel(
      input,
      (reply, q) => {
        if (!q.semanticRef && q.category === "cursorDelete" && mode === "refused-delete")
          return { code: "PERMISSION_DENIED", status: 403, body: {} };
        if (!q.semanticRef && q.category === "cursorGet" && mode === "unknown-absence")
          return { ...reply, unknown: true };
        return reply;
      },
      order,
    );
    const report = await replayRecording(input, local.call);
    assert.notEqual(report.semanticWitnesses[0].verdict, "MATCH", mode);
    assert.equal(
      local.calls.filter((q) => q.method === "DeleteTopic" && q.request.name === order[0]).length,
      1,
      "selected DELETE never retried",
    );
  }
});
test("B snapshot disposition remains provisional without successful stable Get", async () => {
  for (const mode of ["missing", "unknown", "refused", "drift"]) {
    const { input, at, name, topic } = generatedInput();
    if (mode === "missing") input.cells[0].exchanges.pop();
    const report = await replayRecording(input, async (q) => {
      if (q.method === "GetSnapshot" && mode === "unknown")
        return { code: "UNAVAILABLE", unknown: true };
      if (q.method === "GetSnapshot" && mode === "refused")
        return { code: "PERMISSION_DENIED", status: 403 };
      return {
        code: "OK",
        status: 200,
        body:
          q.method === "Publish"
            ? { messageIds: ["22222222222222222"] }
            : {
                name,
                topic,
                expireTime:
                  q.method === "GetSnapshot" && mode === "drift"
                    ? "2026-10-16T00:00:00.124Z"
                    : "2026-10-16T00:00:00.123Z",
              },
        clockReadback: { clock: at, sourceRequestId: q.requestId },
      };
    });
    assert.notEqual(report.generatedWitnesses[1].verdict, "MATCH", mode);
  }
});
test("B cleanup completion requires its actual absence readback", async () => {
  for (const mode of ["present", "unknown"]) {
    const input = oneListInput();
    const local = independentListModel(input, (reply, q) => {
      if (
        q.semanticRef &&
        q.method === "GetTopic" &&
        q.category === "semanticWitness" &&
        q.request.name !== input.cells[0].manifest.manifest.members.at(-1)
      )
        return mode === "unknown"
          ? { code: "UNAVAILABLE", unknown: true }
          : { code: "OK", status: 200, body: { name: q.request.name } };
      return reply;
    });
    const report = await replayRecording(input, local.call);
    assert.equal(report.semanticWitnesses[0].cleanup.complete, false, mode);
  }
});

test("B failed or missing Snapshot Get cannot authorize LIST expiry substitution", async () => {
  for (const mode of ["missing", "unknown", "drift"]) {
    const { input, at, name, topic } = generatedInput();
    if (mode === "missing") input.cells[0].exchanges.pop();
    input.cells[0].manifest.manifest.resources = [{ name, method: "CreateSnapshot" }];
    for (const stage of ["baseline", "first"])
      input.cells[0].exchanges.push({
        dispatch: {
          requestId: stage === "baseline" ? 4 : 5,
          n: stage === "baseline" ? 4 : 5,
          at,
          cellId: "R7",
          transport: "rest",
          method: "ListSnapshots",
          request: { project: `projects/${PROJECT}`, pageSize: 1 },
        },
        response: {
          reply: {
            code: "OK",
            status: 200,
            ok: true,
            body: { snapshots: [{ name, topic, expireTime: "2026-10-16T00:00:00.234Z" }] },
          },
        },
        page: { stage, names: [name], nextPageToken: null },
      });
    const report = await replayRecording(input, async (q) => {
      if (q.semanticRef && q.method === "GetSnapshot")
        return { code: "NOT_FOUND", status: 404, body: {} };
      if (q.method === "GetSnapshot" && mode === "unknown")
        return { code: "UNAVAILABLE", unknown: true };
      return {
        code: "OK",
        status: 200,
        body:
          q.method === "Publish"
            ? { messageIds: ["22222222222222222"] }
            : q.method === "ListSnapshots"
              ? { snapshots: [{ name, topic, expireTime: "2026-10-16T00:00:00.123Z" }] }
              : {
                  name,
                  topic,
                  expireTime:
                    q.method === "GetSnapshot" && mode === "drift"
                      ? "2026-10-16T00:00:00.124Z"
                      : "2026-10-16T00:00:00.123Z",
                },
        clockReadback: { clock: at, sourceRequestId: q.requestId },
      };
    });
    assert.match(
      report.semanticWitnesses[0].reason,
      /snapshot generated lifetime binding missing/,
      mode,
    );
  }
});

test("B verified Snapshot pair survives its recorded selected DELETE and confirmed absence only", async () => {
  for (const mode of ["confirmed", "unknown", "unexpected", "unconfirmed-pair"]) {
    const { input, at, name, topic } = generatedInput();
    const expiry = "2026-10-16T00:00:00.123Z",
      snapshot = { name, topic, expireTime: expiry };
    for (const e of input.cells[0].exchanges)
      if (e.dispatch.method !== "Publish") e.response.reply.body = structuredClone(snapshot);
    const append = (id, method, category, request, reply, page = undefined) =>
      input.cells[0].exchanges.push({
        dispatch: {
          requestId: id,
          n: id,
          at,
          cellId: "R7",
          transport: "rest",
          method,
          category,
          request,
        },
        response: { reply },
        ...(page ? { page } : {}),
      });
    append(
      4,
      "ListSnapshots",
      "list",
      { project: `projects/${PROJECT}`, pageSize: 100 },
      { code: "OK", status: 200, ok: true, body: { snapshots: [snapshot] } },
      { stage: "baseline", names: [name], nextPageToken: null },
    );
    append(
      5,
      "ListSnapshots",
      "list",
      { project: `projects/${PROJECT}`, pageSize: 1 },
      {
        code: "OK",
        status: 200,
        ok: true,
        body: { snapshots: [snapshot], nextPageToken: "issued-empty" },
      },
      { stage: "first", names: [name], nextPageToken: "issued-empty" },
    );
    append(
      6,
      "DeleteSnapshot",
      "cursorDelete",
      { name },
      { code: "OK", status: 200, ok: true, body: {} },
    );
    const absent = {
      code: "NOT_FOUND",
      status: 404,
      body: { error: { status: "NOT_FOUND", message: "missing" } },
    };
    append(7, "GetSnapshot", "cursorGet", { name }, structuredClone(absent));
    let deleted = false;
    const report = await replayRecording(input, async (q) => {
      if (q.method === "Publish")
        return {
          code: "OK",
          status: 200,
          body: { messageIds: ["22222222222222222"] },
          clockReadback: { clock: at, sourceRequestId: q.requestId },
        };
      if (q.method === "DeleteSnapshot") {
        deleted = true;
        return { code: "OK", status: 200, body: {} };
      }
      if (q.method === "GetSnapshot" && deleted)
        return mode === "unknown"
          ? { ...absent, unknown: true }
          : mode === "unexpected"
            ? { code: "PERMISSION_DENIED", status: 403, body: {} }
            : structuredClone(absent);
      if (q.method === "ListSnapshots")
        return {
          code: "OK",
          status: 200,
          body: q.request.pageToken
            ? { snapshots: [] }
            : {
                snapshots: [snapshot],
                ...(q.request.pageSize === 1 ? { nextPageToken: "issued-empty" } : {}),
              },
        };
      if (q.method === "GetSnapshot" && mode === "unconfirmed-pair")
        return { code: "UNAVAILABLE", unknown: true };
      return {
        code: "OK",
        status: 200,
        body: structuredClone(snapshot),
        clockReadback: { clock: at, sourceRequestId: q.requestId },
      };
    });
    if (mode === "confirmed") {
      assert.equal(report.rows.find((r) => r.requestId === 7).semantic, "MATCH");
      assert.equal(report.semanticWitnesses[0].verdict, "MATCH");
      assert.ok(report.generatedWitnesses.every((w) => w.verdict === "MATCH"));
      assert.equal(report.generatedWitnesses.length, 3, "absence has its own existing witness");
    } else assert.notEqual(report.generatedWitnesses[1].verdict, "MATCH", mode);
  }
});

test("B verified generated Snapshot success survives only confirmed owned cleanup absence", async () => {
  for (const mode of [
    "confirmed",
    "unknown",
    "wrong-status",
    "wrong-code",
    "unverified-pair",
    "missing-delete",
    "unknown-delete",
    "source-unknown",
    "source-wrong-status",
    "refused-delete",
  ]) {
    const { input, at, name, topic } = generatedInput();
    const absent = {
      code: "NOT_FOUND",
      status: 404,
      body: { error: { status: "NOT_FOUND", message: "missing" } },
    };
    const append = (id, method, reply) =>
      input.cells[0].exchanges.push({
        dispatch: {
          requestId: id,
          n: id,
          at,
          cellId: "R7",
          transport: "rest",
          method,
          category: method === "GetSnapshot" ? "cleanupGet" : "cleanupDelete",
          request: { name },
        },
        response: { reply },
      });
    if (mode !== "missing-delete")
      append(4, "DeleteSnapshot", { code: "OK", status: 200, body: {} });
    append(
      5,
      "GetSnapshot",
      mode === "source-unknown"
        ? { ...absent, unknown: true }
        : mode === "source-wrong-status"
          ? { ...absent, status: 200 }
          : structuredClone(absent),
    );
    const report = await replayRecording(input, async (q) => {
      if (q.method === "Publish")
        return {
          code: "OK",
          status: 200,
          body: { messageIds: ["22222222222222222"] },
          clockReadback: { clock: at, sourceRequestId: q.requestId },
        };
      if (q.method === "DeleteSnapshot")
        return mode === "unknown-delete"
          ? { code: "OK", status: 200, body: {}, unknown: true }
          : mode === "refused-delete"
            ? { code: "PERMISSION_DENIED", status: 403, body: {} }
            : { code: "OK", status: 200, body: {} };
      if (q.requestId === 5)
        return mode === "unknown"
          ? { ...absent, unknown: true }
          : mode === "wrong-status"
            ? { ...absent, status: 200 }
            : mode === "wrong-code"
              ? { code: "PERMISSION_DENIED", status: 403, body: {} }
              : structuredClone(absent);
      if (q.method === "GetSnapshot" && mode === "unverified-pair")
        return { code: "UNAVAILABLE", unknown: true };
      return {
        code: "OK",
        status: 200,
        body: { name, topic, expireTime: "2026-10-16T00:00:00.123Z" },
        clockReadback: { clock: at, sourceRequestId: q.requestId },
      };
    });
    if (mode === "confirmed") {
      assert.equal(report.rows.find((r) => r.requestId === 5).semantic, "MATCH");
      assert.equal(report.generatedWitnesses.length, 3);
      assert.ok(report.generatedWitnesses.every((w) => w.verdict === "MATCH"));
      assert.equal(report.generatedWitnesses[1].expiryEffects, "NOT_COMPARABLE_NOT_OBSERVED");
    } else assert.notEqual(report.generatedWitnesses[1].verdict, "MATCH", mode);
  }
});

test("B supplemental owned Snapshot deletion preserves a stable pair through redundant recorded cleanup", async () => {
  for (const mode of [
    "confirmed",
    "delete-unknown",
    "delete-refused",
    "absence-unknown",
    "absence-wrong-status",
    "predelete-get-failure",
    "drift",
    "wrong-name",
    "wrong-cell",
    "redundant-unknown",
    "redundant-refused",
  ]) {
    const { input, at, name, topic } = generatedInput();
    if (mode === "wrong-cell") input.cells[0].cell.id = "R8";
    const other = name.replace(/-a$/, "-b"),
      sourceExpiry = "2026-10-16T00:00:00.234Z",
      localExpiry = "2026-10-16T00:00:00.123Z";
    const source = (n) => ({ name: n, topic, expireTime: sourceExpiry });
    const absent = {
      code: "NOT_FOUND",
      status: 404,
      body: { error: { status: "NOT_FOUND", message: "missing" } },
    };
    const append = (id, method, category, request, reply, page) =>
      input.cells[0].exchanges.push({
        dispatch: {
          requestId: id,
          n: id,
          at,
          cellId: "R7",
          transport: "rest",
          method,
          category,
          request,
        },
        response: { reply },
        ...(page ? { page } : {}),
      });
    input.cells[0].manifest.manifest.members = [name, other];
    input.cells[0].manifest.manifest.resources = [name, other].map((name) => ({
      name,
      method: "CreateSnapshot",
    }));
    append(
      4,
      "CreateSnapshot",
      "create",
      { name: other, subscription: `projects/${PROJECT}/subscriptions/fe${runId}-r7-prereq` },
      { code: "OK", status: 200, body: source(other) },
    );
    append(
      5,
      "GetSnapshot",
      "get",
      { name: other },
      { code: "OK", status: 200, body: source(other) },
    );
    append(
      6,
      "ListSnapshots",
      "list",
      { project: `projects/${PROJECT}`, pageSize: 100 },
      { code: "OK", status: 200, ok: true, body: { snapshots: [source(name), source(other)] } },
      { stage: "baseline", names: [name, other], nextPageToken: null },
    );
    append(
      7,
      "ListSnapshots",
      "list",
      { project: `projects/${PROJECT}`, pageSize: 1 },
      {
        code: "OK",
        status: 200,
        ok: true,
        body: { snapshots: [source(other)], nextPageToken: "source-issued" },
      },
      { stage: "first", names: [other], nextPageToken: "source-issued" },
    );
    append(
      8,
      "DeleteSnapshot",
      "cursorDelete",
      { name: other },
      { code: "OK", status: 200, body: {} },
    );
    append(9, "GetSnapshot", "cursorGet", { name: other }, structuredClone(absent));
    append(10, "DeleteSnapshot", "cleanupDelete", { name }, { code: "OK", status: 200, body: {} });
    append(11, "GetSnapshot", "cleanupGet", { name }, structuredClone(absent));
    const local = independentListModel(
      input,
      (reply, q) => {
        if (q.method === "ListSnapshots" && reply.body?.topics) {
          reply.body.snapshots = reply.body.topics.map((r) => ({
            ...r,
            topic,
            expireTime: localExpiry,
          }));
          delete reply.body.topics;
          if (mode === "wrong-name" && q.requestId === 7)
            reply.body.snapshots[0].name += "-unowned";
        }
        if (["CreateSnapshot", "GetSnapshot"].includes(q.method) && reply.code === "OK")
          reply.body = {
            ...reply.body,
            topic,
            expireTime: mode === "drift" && q.requestId === 3 ? sourceExpiry : localExpiry,
          };
        if (mode === "predelete-get-failure" && q.requestId === 3)
          return { code: "UNAVAILABLE", unknown: true };
        if (q.semanticRef && q.method === "DeleteSnapshot") {
          if (mode === "delete-unknown") return { ...reply, unknown: true };
          if (mode === "delete-refused")
            return { code: "PERMISSION_DENIED", status: 403, body: {} };
        }
        if (q.semanticRef && q.method === "GetSnapshot") {
          if (mode === "absence-unknown") return { ...reply, unknown: true };
          if (mode === "absence-wrong-status") return { ...reply, status: 200 };
        }
        if (q.requestId === 10 && mode === "redundant-unknown") return { ...reply, unknown: true };
        if (q.requestId === 10 && mode === "redundant-refused")
          return { code: "PERMISSION_DENIED", status: 403, body: {} };
        return reply;
      },
      [name, other],
    );
    const report = await replayRecording(input, async (q) =>
      q.method === "Publish"
        ? {
            code: "OK",
            status: 200,
            body: { messageIds: ["22222222222222222"] },
            clockReadback: { clock: at, sourceRequestId: q.requestId },
          }
        : { ...(await local.call(q)), clockReadback: { clock: at, sourceRequestId: q.requestId } },
    );
    if (mode === "confirmed") {
      assert.equal(
        report.semanticWitnesses[0].verdict,
        "MATCH",
        report.semanticWitnesses[0].reason,
      );
      assert.equal(
        report.rows.find((r) => r.requestId === 10).semantic,
        "DIVERGES",
        "redundant DELETE physical error remains",
      );
      assert.equal(report.rows.find((r) => r.requestId === 11).semantic, "MATCH");
      assert.ok(report.generatedWitnesses.every((w) => w.verdict === "MATCH"));
      assert.ok(
        report.generatedWitnesses.every((w) => w.expiryEffects === "NOT_COMPARABLE_NOT_OBSERVED"),
      );
    } else if (mode === "wrong-name") assert.notEqual(report.semanticWitnesses[0].verdict, "MATCH");
    else assert.notEqual(report.generatedWitnesses[1].verdict, "MATCH", mode);
  }
});

async function standaloneBFixture(t) {
  const fs = await import("node:fs");
  const { join } = await import("node:path");
  const { tmpdir } = await import("node:os");
  const directory = fs.mkdtempSync(join(tmpdir(), "b-standalone-admission-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const put = (name, value) => {
    const path = join(directory, name);
    const bytes = Buffer.from(typeof value === "string" ? value : JSON.stringify(value));
    fs.writeFileSync(path, bytes, { mode: 0o600 });
    return { path, sha256: hash(bytes) };
  };
  const binary = put("fireemu", "pinned binary");
  const adapter = put("adapter.mjs", "pinned adapter");
  const supervisor = put("caller.py", "pinned supervisor");
  const clockStart = "2026-10-01T00:00:00Z";
  const configBody = {
    schemaVersion: 1,
    profile: "strict",
    bind: "127.0.0.1",
    daemon: {
      pubsubPort: 0,
      httpPort: 0,
      hubPort: 0,
      loggingPort: 0,
      authProject: "demo-b",
      clockStart,
    },
  };
  const config = put("config.json", configBody);
  const environment = {
    GOOGLE_CLOUD_PROJECT: "demo-b",
    GCLOUD_PROJECT: "demo-b",
    PUBSUB_EMULATOR_HOST: "127.0.0.1:12345",
    FIREEMU_CONTROL_URL: "http://127.0.0.1:12346/v1/",
    FIREEMU_CONTROL_TOKEN: "local-test",
  };
  const readyBody = {
    schemaVersion: 1,
    pid: 102,
    projectId: "demo-b",
    controlUrl: "http://127.0.0.1:12346",
    controlToken: "local-test",
    environment,
  };
  const ready = put("ready.json", readyBody);
  const identity = (pid, ppid, comm, args) => ({
    pid,
    ppid,
    birth: "Thu Oct 1 00:00:00 2026",
    comm,
    args,
  });
  const ownerIdentity = identity(101, 100, "node", `/node ${adapter.path}`);
  const supervisorIdentity = identity(100, 99, "python3", `/python3 ${supervisor.path}`);
  const serverIdentity = identity(
    102,
    101,
    binary.path,
    `${binary.path} up --config ${config.path} --only pubsub --ready-file ${ready.path} --owner-stdin`,
  );
  const observed = new Map(
    [ownerIdentity, supervisorIdentity, serverIdentity].map((value) => [
      value.pid,
      structuredClone(value),
    ]),
  );
  return {
    pin: { path: binary.path, sha256: binary.sha256 },
    input: { metadata: { project: "demo-b", at: clockStart } },
    context: { environment, worker: { pid: 103, ppid: 101 }, observe: (pid) => observed.get(pid) },
    observed,
    put,
    configBody,
    readyBody,
    launch: {
      mode: "standalone",
      parentPid: 101,
      serverPid: 102,
      config: config.path,
      configSha256: config.sha256,
      clockStart,
      ready: ready.path,
      readySha256: ready.sha256,
      adapter,
      supervisor,
      nodePath: "/node",
      pythonPath: "/python3",
      ownerIdentity,
      supervisorIdentity,
      serverIdentity,
    },
  };
}

test("B standalone admission accepts the original source project and clock through shared provenance", async (t) => {
  const { validateLaunch } = await import("./pubsub-observation-b/replay.mjs");
  const f = await standaloneBFixture(t);
  assert.doesNotThrow(() => validateLaunch(f.launch, f.pin, f.input, null, 101, f.context));
});

test("B standalone admission rejects changed source clock and rehashed process/config/readiness near misses", async (t) => {
  const { validateLaunch } = await import("./pubsub-observation-b/replay.mjs");
  for (const change of [
    (f) => {
      f.context.worker.ppid = 999;
    },
    (f) => {
      f.observed.get(101).birth += " changed";
    },
    (f) => {
      f.observed.get(102).args += " changed";
    },
    (f) => {
      f.observed.get(100).birth += " changed";
    },
    (f) => {
      f.input.metadata.project = "demo-other";
    },
    (f) => {
      f.input.metadata.at = "2026-10-02T00:00:00Z";
    },
    (f) => {
      f.configBody.daemon.clockStart = "2026-10-02T00:00:00Z";
      const config = f.put("changed-clock.json", f.configBody);
      f.launch.config = config.path;
      f.launch.configSha256 = config.sha256;
      f.launch.clockStart = f.configBody.daemon.clockStart;
      const args = `${f.pin.path} up --config ${config.path} --only pubsub --ready-file ${f.launch.ready} --owner-stdin`;
      f.launch.serverIdentity.args = args;
      f.observed.get(102).args = args;
    },
    (f) => {
      f.readyBody.pid = 999;
      const ready = f.put("changed-ready.json", f.readyBody);
      f.launch.ready = ready.path;
      f.launch.readySha256 = ready.sha256;
      const args = `${f.pin.path} up --config ${f.launch.config} --only pubsub --ready-file ${ready.path} --owner-stdin`;
      f.launch.serverIdentity.args = args;
      f.observed.get(102).args = args;
    },
  ]) {
    const f = await standaloneBFixture(t);
    change(f);
    assert.throws(
      () => validateLaunch(f.launch, f.pin, f.input, null, 101, f.context),
      /standalone|source clock/,
    );
  }
});
