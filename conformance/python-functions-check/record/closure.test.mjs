// The A2 read-back as a closure of its own: it compares a fresh inventory with the preflight's by identity, carries what the
// result leaves open, and the journal and result files survive production-sized rows through the real write path.
import assert from "node:assert/strict";
import { closeSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { tempDir } from "./testtmp.mjs";
import { READBACK_MAX_REQUESTS, readbackNames, readbackRun } from "./readback.mjs";
import { lastActivity, resultOf, writeAll } from "./main.mjs";
import { sourceBuckets } from "./plan.mjs";
import { record } from "./run.mjs";
import { BUCKET, NUMBER, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const [UPLOADS, SOURCES] = sourceBuckets(NUMBER);
async function afterRun(worldOptions = {}) {
  const world = createWorld({ runId: RUN, ...worldOptions });
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    send: world.send,
    runCli: world.runCli,
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
  });
  return { world, result };
}
const a2 = (world, result, over = {}) =>
  readbackRun({
    runId: RUN,
    projectNumber: NUMBER,
    bucket: BUCKET,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    send: over.send ?? world.send,
    clock: () => world.now,
    uploadObjects: result.cleanup.uploadObjectsDeleted,
    baseline: world.baseline,
    enabled: result.servicesEnabled,
    channel: result.cleanup.channel,
    ...over,
  });

test("after a clean run the read-back finds the inventory as the preflight had it", async () => {
  const { world, result } = await afterRun();
  const rb = await a2(world, result);
  assert.equal(rb.allAbsent, true);
  assert.deepEqual(rb.inventory, { baseline: true, complete: true, missing: [], differences: [] });
  assert.ok(rb.attempted <= READBACK_MAX_REQUESTS, String(rb.attempted));
});

test("a difference from the preflight inventory keeps the read-back from saying all is gone, whatever it is", async () => {
  const changes = [
    ["services", (w) => w.services.add("extra.googleapis.com")],
    ["subscriptions", (w) => w.subscriptions.add("stray-sub")],
    ["triggers", (w) => w.triggers.add("stray-trigger")],
    ["topics", (w) => w.topics.add("stray-topic")],
    ["packages", (w) => w.packages.add("stray-package")],
    ["channels", (w) => w.channels.add("stray-channel")],
    ["uploadObjects", (w) => w.sourceBuckets.get(UPLOADS).push("stray.zip")],
    ["sourceObjects", (w) => w.sourceBuckets.get(SOURCES).push("pcps/other.zip")],
  ];
  for (const [kind, change] of changes) {
    const { world, result } = await afterRun();
    change(world);
    const rb = await a2(world, result);
    assert.equal(rb.allAbsent, false, kind);
    assert.ok(
      rb.inventory.differences.some((d) => d.kind === kind),
      kind + " " + JSON.stringify(rb.inventory),
    );
  }
});

test("an inventory list that cannot be read, or no baseline at all, closes nothing", async () => {
  for (const needle of [
    "/subscriptions",
    "/channels",
    "services?filter",
    "gcf-v2-uploads",
    "gcf-v2-sources",
    "/triggers",
  ]) {
    const { world, result } = await afterRun();
    const rb = await a2(world, result, {
      send: async (request) =>
        request.method === "GET" && request.url.includes(needle) && world.cliRuns.includes("delete")
          ? reply(500, { error: { code: 500, status: "INTERNAL" } })
          : world.send(request),
    });
    assert.equal(rb.allAbsent, false, needle);
    assert.equal(rb.inventory.complete, false, needle);
  }
  const { world, result } = await afterRun();
  const none = await a2(world, result, { baseline: null });
  assert.equal(none.allAbsent, false);
  assert.deepEqual(none.inventory, {
    baseline: false,
    complete: false,
    missing: ["baseline"],
    differences: [],
  });
  const partial = await a2(world, result, {
    baseline: { ...world.baseline, subscriptions: undefined },
  });
  assert.equal(partial.allAbsent, false);
});

test("the enabled services of the run are expected in the read-back; others are not", async () => {
  const { world, result } = await afterRun({ withoutServices: ["cloudtasks.googleapis.com"] });
  const rb = await a2(world, result);
  assert.equal(rb.allAbsent, true, JSON.stringify(rb.inventory));
  const without = await a2(world, result, { enabled: [] });
  assert.equal(without.allAbsent, false);
  assert.deepEqual(without.inventory.differences, [
    { kind: "services", added: ["cloudtasks.googleapis.com"], removed: [] },
  ]);
});

test("the channel the run owned and its topic are read again; the carried obligations are echoed", async () => {
  const { world, result } = await afterRun({ seedChannels: [] });
  assert.ok(
    readbackNames(RUN, BUCKET, [], result.cleanup.channel).some(
      ([label]) => label === "channel-topic",
    ),
  );
  const rb = await a2(world, result, { carried: ["upload:no-receipt"] });
  assert.equal(rb.allAbsent, true, JSON.stringify(rb));
  assert.deepEqual(rb.carried, ["upload:no-receipt"]);
  assert.equal(rb.names.channel.absent, true);
  assert.equal(rb.names["channel-topic"].absent, true);
  world.channels.add("firebase");
  world.topics.add("eventarc-channel-us-central1-firebase-450");
  const back = await a2(world, result);
  assert.equal(back.allAbsent, false);
  assert.equal(back.names.channel.absent, false);
  assert.equal(
    readbackNames(RUN, BUCKET, [], { ownedByRun: false }).some(([l]) => l === "channel"),
    false,
  );
  assert.equal(
    readbackNames(RUN, BUCKET, [], { ownedByRun: true, topic: "somebody-elses" }).some(
      ([l]) => l === "channel-topic",
    ),
    false,
  );
  assert.equal(
    readbackNames(RUN, BUCKET, [], { ownedByRun: true }).some(([l]) => l === "channel"),
    true,
  );
});

test("resultOf hands the baseline, the enabled services, the channel and every open obligation to the read-back", () => {
  const d = tempDir("pc-cl-");
  try {
    const path = join(d, "r.json");
    writeFileSync(
      path,
      JSON.stringify({
        unconfirmedCreates: [],
        bucket: "b",
        servicesEnabled: ["s"],
        channel: { ownedByRun: true },
        inventory: {
          before: { channels: [] },
          complete: false,
          differences: [{ kind: "services", added: ["x"], removed: [] }],
        },
        cleanup: {
          channel: { ownedByRun: true, topic: "t" },
          uploadReasons: ["no-receipt"],
          uploadObjectsUnexplained: [{ bucket: "b", name: "n.zip" }],
          uploadObjectsDeleted: [],
        },
      }),
    );
    const judged = resultOf(path);
    assert.deepEqual(judged.baseline, { channels: [] });
    assert.deepEqual(judged.enabled, ["s"]);
    assert.deepEqual(judged.channel, { ownedByRun: true, topic: "t" });
    assert.deepEqual(judged.carried, [
      "upload:no-receipt",
      "unexplained-upload-object:n.zip",
      'inventory:{"kind":"services","added":["x"],"removed":[]}',
      "inventory-incomplete",
    ]);
    writeFileSync(path, JSON.stringify({ unconfirmedCreates: [], channel: { ownedByRun: true } }));
    assert.deepEqual(resultOf(path).channel, { ownedByRun: true });
    writeFileSync(path, JSON.stringify({ unconfirmedCreates: [], servicesEnabled: "x" }));
    assert.deepEqual(resultOf(path).enabled, []);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

// ---- the journal write -----------------------------------------------------------------------------------------

test("writeAll writes everything even when the descriptor takes a few bytes at a time, and refuses to spin", () => {
  const taken = [];
  const slow = (fd, bytes, offset, length) => {
    const n = Math.min(3, length);
    taken.push(Buffer.from(bytes.subarray(offset, offset + n)));
    return n;
  };
  writeAll(1, "héllo wörld", slow);
  assert.deepEqual(Buffer.concat(taken), Buffer.from("héllo wörld"));
  const asked = [];
  writeAll(1, "abcdefgh", (fd, b, offset, length) => {
    asked.push([offset, length]);
    return Math.min(length, 5);
  });
  assert.deepEqual(asked, [
    [0, 8],
    [5, 3],
  ]);
  const seen = [];
  writeAll(1, "abcdefgh", (fd, b, offset, length) => {
    seen.push(b.subarray(offset, offset + length).toString());
    return Math.min(length, 5);
  });
  assert.deepEqual(seen, ["abcdefgh", "fgh"]);
  assert.throws(() => writeAll(1, "x", () => 0), /no progress/);
  assert.throws(() => writeAll(1, "x", () => -1), /no progress/);
  assert.throws(() => writeAll(1, "x", () => undefined), /no progress/);
  writeAll(1, "", () => assert.fail("nothing to write"));
});

test("a production-sized journal row and result survive the real write path and are read back", () => {
  const d = tempDir("pc-cl-");
  try {
    const body = Buffer.alloc(11 * 1024 * 1024, "a")
      .toString("base64")
      .slice(0, 11 * 1024 * 1024);
    const row = {
      id: "logs-final-frames",
      state: "response-persisted",
      status: 200,
      dispatchAt: "2026-11-05T00:00:00.000Z",
      responseAt: "2026-11-05T00:30:00.000Z",
      bodyBase64: body,
    };
    const path = join(d, "journal.jsonl");
    const fd = openSync(path, "a", 0o600);
    writeAll(fd, JSON.stringify(row) + "\n");
    writeAll(fd, JSON.stringify({ id: "x", dispatchAt: "2026-11-05T00:40:00.000Z" }) + "\n");
    closeSync(fd);
    assert.equal(readFileSync(path, "utf8").split("\n")[0].length, JSON.stringify(row).length);
    assert.equal(lastActivity(path), Date.parse("2026-11-05T00:40:00.000Z"));
    const resultPath = join(d, "result.json");
    writeFileSync(
      resultPath,
      JSON.stringify({
        unconfirmedCreates: [],
        bucket: "b",
        cleanup: { uploadObjectsDeleted: [{ bucket: "b", name: "n" }] },
        big: body,
      }),
    );
    assert.deepEqual(resultOf(resultPath).uploadObjects, [{ bucket: "b", name: "n" }]);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("the read-back lists the trigger names of the run's functions, names its inventory reads, and a function still listed is not 'all gone'", async () => {
  const { world, result } = await afterRun();
  const ids = [];
  const rb = await a2(world, result, {
    save: async (row) => {
      if (row.state === "before-send") ids.push(row.id);
    },
  });
  assert.ok(ids.includes("list-uploads") && ids.includes("list-sources"), ids.join());
  assert.ok(
    ids.includes("list-subscriptions") &&
      ids.includes("list-channels") &&
      ids.includes("list-services"),
  );
  world.triggers.add("pcps-123");
  world.triggers.add("somebody-elses-1");
  const left = await a2(world, result);
  assert.deepEqual(left.lists.triggers, ["pcps-123"]);
  assert.equal(left.allAbsent, false);
  assert.equal(rb.allAbsent, true);
  const seen = await afterRun();
  seen.world.functions.set(`projects/fireemu-oracle-events/locations/us-central1/functions/pcps`, {
    name: "projects/fireemu-oracle-events/locations/us-central1/functions/pcps",
    state: "ACTIVE",
  });
  const direct =
    "GET cloudfunctions.googleapis.com/v2/projects/fireemu-oracle-events/locations/us-central1/functions/pcps";
  const hidden = await a2(seen.world, seen.result, {
    baseline: seen.world.baseline,
    send: async (request) => {
      const u = new URL(request.url);
      if (request.method + " " + u.hostname + u.pathname === direct)
        return reply(404, { error: { code: 404, status: "NOT_FOUND" } });
      return seen.world.send(request);
    },
  });
  assert.equal(hidden.lists.functionsAndServices, false);
  assert.equal(
    hidden.allAbsent,
    false,
    "the list still shows the function although its direct read says gone",
  );
});
