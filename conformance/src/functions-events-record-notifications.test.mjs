// The primary bucket's notification configs (the one GCF-managed config, id cloud-functions-<project>-<tenant>-tp,
// whose topic lives in a Google tenant project): read in the preflight and after the cleanup, recorded, never written.
// Only a NEW config is a problem; a removed or changed one is recorded. Shapes are the two real responses (the primary
// bucket: {kind, items[1]}; a bucket without any: {kind}), committed with the tenant ids replaced.

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

import { runCleanup } from "./functions-events/record/cleanup.mjs";
import { RULES, destination } from "./functions-events/record/guard.mjs";
import {
  PREFLIGHT,
  notificationConfigs,
  notificationDiff,
  runPreflight,
} from "./functions-events/record/preflight.mjs";
import { createTransport } from "./functions-events/record/rest.mjs";
import { record } from "./functions-events/record/run.mjs";
import { PRIMARY_BUCKET } from "./functions-events/record/script.mjs";
import { createWorld, healthy } from "./functions-events-record-world.mjs";
import { tempDir } from "./test-tmpdir.mjs";

const recorded = (name) =>
  JSON.parse(
    readFileSync(
      new URL(`./functions-events/record/recorded/v4-run/${name}`, import.meta.url),
      "utf8",
    ),
  );
const one = () => recorded("notification-configs.json");
const none = () => recorded("notification-configs-empty.json");
const ID = "cloud-functions-fireemu-oracle-events-tenantprojectid-tp";

// ---- the shapes ---------------------------------------------------------------------------------

test("the recorded primary bucket answer is one GCF-managed config; the answer of a bucket without any has no items", () => {
  const configs = notificationConfigs(one());
  assert.deepEqual(configs, [
    {
      id: ID,
      topic:
        "//pubsub.googleapis.com/projects/tenantprojectid-tp/topics/cloud-functions-topicsuffixplaceholder",
      eventTypes: null,
      payloadFormat: "JSON_API_V1",
      etag: ID,
    },
  ]);
  assert.deepEqual(notificationConfigs(none()), []);
});

test("anything that is not a list of configs is not read as one", () => {
  for (const json of [
    undefined,
    null,
    {},
    { kind: "storage#object" },
    { kind: "storage#notifications", items: null },
    { kind: "storage#notifications", items: {} },
    { kind: "storage#notifications", items: [null] },
    { kind: "storage#notifications", items: ["x"] },
    { kind: "storage#notifications", items: [{ topic: "t" }] },
    { kind: "storage#notifications", items: [{ id: "" }] },
    { kind: "storage#notifications", items: [{ id: 7 }] },
    { kind: "storage#notifications", items: [{ id: "a" }, { topic: "b" }] },
  ])
    assert.equal(notificationConfigs(json), null, JSON.stringify(json));
  const sorted = notificationConfigs({
    kind: "storage#notifications",
    items: [{ id: "b", event_types: ["OBJECT_FINALIZE", "OBJECT_DELETE"] }, { id: "a" }],
  });
  assert.deepEqual(
    sorted.map((c) => c.id),
    ["a", "b"],
  );
  assert.deepEqual(sorted[1].eventTypes, ["OBJECT_DELETE", "OBJECT_FINALIZE"]);
});

test("the diff names new, removed and changed configs by id", () => {
  const config = (id, extra = {}) => ({
    id,
    topic: "t",
    eventTypes: null,
    payloadFormat: "JSON_API_V1",
    etag: id,
    ...extra,
  });
  const same = notificationDiff([config("a")], [config("a")]);
  assert.deepEqual(same, { before: ["a"], after: ["a"], added: [], removed: [], changed: [] });
  assert.deepEqual(notificationDiff([], [config("n")]).added, ["n"]);
  assert.deepEqual(notificationDiff([config("a")], []).removed, ["a"]);
  assert.deepEqual(notificationDiff([config("a")], [config("a", { topic: "other" })]).changed, [
    "a",
  ]);
  assert.deepEqual(
    notificationDiff([config("a")], [config("a", { payloadFormat: "NONE" })]).changed,
    ["a"],
  );
  assert.deepEqual(notificationDiff([config("a")], [config("a", { etag: "e2" })]).changed, ["a"]);
  assert.deepEqual(
    notificationDiff([config("a")], [config("a", { eventTypes: ["OBJECT_DELETE"] })]).changed,
    ["a"],
  );
  const mixed = notificationDiff(
    [config("a"), config("b")],
    [config("b", { topic: "x" }), config("c")],
  );
  assert.deepEqual([mixed.added, mixed.removed, mixed.changed], [["c"], ["a"], ["b"]]);
});

// ---- the preflight ----------------------------------------------------------------------------------

const preflightWith = async (answer) => {
  const bodies = healthy();
  bodies["preflight.notification-configs"] = answer;
  const seen = [];
  const result = await runPreflight(async (spec) => {
    seen.push(spec.id);
    const body = bodies[spec.id];
    return {
      id: spec.id,
      status: body.status,
      json: body.json,
      kind: body.status >= 500 ? "unknown" : "success",
    };
  });
  return { ...result, seen };
};

test("the preflight reads the primary bucket's configs and keeps them for the comparison", async () => {
  const withOne = await preflightWith({ status: 200, json: one() });
  assert.deepEqual(withOne.problems, []);
  assert.deepEqual(
    withOne.notificationsBefore.map((c) => c.id),
    [ID],
  );
  assert.ok(withOne.seen.includes("preflight.notification-configs"));
  const withNone = await preflightWith({ status: 200, json: none() });
  assert.deepEqual([withNone.problems, withNone.notificationsBefore], [[], []]);
  const spec = PREFLIGHT.find((s) => s.id === "preflight.notification-configs");
  assert.equal(
    spec.url,
    `https://storage.googleapis.com/storage/v1/b/${encodeURIComponent(PRIMARY_BUCKET)}/notificationConfigs`,
  );
  assert.equal(spec.mutation, false);
});

test("a preflight answer that is no list of configs, is unreadable or is not a 200 stops the run before anything is written", async () => {
  for (const [answer, pattern] of [
    [{ status: 200, json: { kind: "storage#object" } }, /not a list of configs/],
    [
      { status: 200, json: { kind: "storage#notifications", items: [{}] } },
      /not a list of configs/,
    ],
    [{ status: 503, json: {} }, /no usable answer/],
    [{ status: 403, json: {} }, /HTTP 403/],
    [{ status: 404, json: {} }, /HTTP 404/],
  ]) {
    const { problems, notificationsBefore } = await preflightWith(answer);
    assert.ok(
      problems.some((p) => p.startsWith("preflight.notification-configs") && pattern.test(p)),
      JSON.stringify([answer.status, problems]),
    );
    assert.equal(notificationsBefore, null);
  }
});

// ---- the cleanup ------------------------------------------------------------------------------------

function cleanupSetup({ before, after }) {
  const world = createWorld({ now: () => Date.UTC(2026, 9, 5) });
  world.notificationConfigs = after;
  const transport = createTransport({
    directory: tempDir("fe-notif-"),
    ceiling: 1000,
    token: async () => "t",
    apiKey: "k",
    fetch: world.fetch,
  });
  const run = () =>
    runCleanup({
      transport,
      cli: async (action) => ({ action, exitCode: 0 }),
      sleep: async () => {},
      ran: { deployStarted: false },
      notificationsBefore: before,
    });
  return { world, run };
}
const cfg = (id, extra = {}) => ({
  kind: "storage#notification",
  id,
  topic: "//t",
  payload_format: "JSON_API_V1",
  etag: id,
  ...extra,
});
const read = (items) => notificationConfigs({ kind: "storage#notifications", items });

test("unchanged is clean; the recorded config is read after the cleanup and recorded", async () => {
  const { run } = cleanupSetup({ before: notificationConfigs(one()), after: one().items });
  const result = await run();
  assert.equal(result.verified, true, JSON.stringify(result.problems));
  assert.deepEqual(result.steps.inventory.notificationConfigs, {
    before: [ID],
    after: [ID],
    added: [],
    removed: [],
    changed: [],
  });
  const empty = cleanupSetup({ before: [], after: [] });
  const second = await empty.run();
  assert.equal(second.verified, true);
  assert.deepEqual(second.steps.inventory.notificationConfigs.added, []);
});

test("a new config is a problem (needs-recovery); a removed or changed one is recorded and the run stays verified", async () => {
  const added = await cleanupSetup({ before: read([cfg("a")]), after: [cfg("a"), cfg("n")] }).run();
  assert.equal(added.verified, false);
  assert.ok(added.problems.some((p) => p.startsWith("inventory:")));
  assert.deepEqual(added.steps.inventory.notificationConfigs.added, ["n"]);
  const fromNone = await cleanupSetup({ before: [], after: [cfg("n")] }).run();
  assert.equal(fromNone.verified, false);
  const removed = await cleanupSetup({ before: read([cfg("a")]), after: [] }).run();
  assert.equal(removed.verified, true);
  assert.deepEqual(removed.steps.inventory.notificationConfigs.removed, ["a"]);
  const changed = await cleanupSetup({
    before: read([cfg("a")]),
    after: [cfg("a", { topic: "//other" })],
  }).run();
  assert.equal(changed.verified, true);
  assert.deepEqual(changed.steps.inventory.notificationConfigs.changed, ["a"]);
});

test("an unreadable read after the cleanup cannot show 'unchanged': it is a problem; without a preflight read the step is skipped", async () => {
  for (const status of [503, 403, 404]) {
    const { world, run } = cleanupSetup({ before: read([cfg("a")]), after: [cfg("a")] });
    world.failures.push({
      match: (m, u) => m === "GET" && u.endsWith("/notificationConfigs"),
      status,
    });
    const result = await run();
    assert.equal(result.verified, false, String(status));
    assert.deepEqual(result.steps.inventory.notificationConfigs, { unreadable: true });
  }
  const shape = cleanupSetup({ before: read([cfg("a")]), after: [cfg("a")] });
  shape.world.failures.push({
    match: (m, u) => m === "GET" && u.endsWith("/notificationConfigs"),
    status: 200,
  });
  assert.equal((await shape.run()).verified, false, "a 200 that is no list of configs");
  const skipped = cleanupSetup({ before: null, after: [cfg("n")] });
  const result = await skipped.run();
  assert.equal(result.steps.inventory.notificationConfigs, null);
});

// ---- the whole run ------------------------------------------------------------------------------------

function runSetup(configs) {
  const clock = { t: Date.UTC(2026, 9, 5) };
  const world = createWorld({ now: () => clock.t });
  world.notificationConfigs = configs;
  const transport = createTransport({
    directory: tempDir("fe-notif-run-"),
    ceiling: 1000,
    token: async () => "t",
    apiKey: "k",
    fetch: world.fetch,
    now: () => clock.t,
  });
  let n = 0;
  const deps = {
    transport,
    cli: async (action) => {
      if (action === "deploy") world.deploy();
      else if (action === "delete") world.undeploy();
      return { action, exitCode: 0 };
    },
    sleep: async (seconds) => {
      clock.t += seconds * 1000;
    },
    now: () => clock.t,
    newId: (role) => `e${String(++n).padStart(5, "0")}${role}`,
    corpusDigest: "0".repeat(64),
  };
  return { world, deps };
}

test("a run records the preflight configs, reads them again after the cleanup, and never writes them", async () => {
  const { world, deps } = runSetup(one().items);
  const { outcome, run } = await record(deps);
  assert.equal(outcome, "recorded", JSON.stringify([run.stops, run.cleanup?.problems]));
  assert.deepEqual(run.preflight.notificationConfigs, [ID]);
  assert.deepEqual(run.cleanup.steps.inventory.notificationConfigs.added, []);
  const sent = world.requests.filter((r) => r.url.includes("/notificationConfigs"));
  assert.equal(sent.length, 2, "once before, once after");
  assert.ok(sent.every((r) => r.method === "GET"));
});

test("a Gen1 delete that removes the config is recorded, not failed; a config that appears is needs-recovery", async () => {
  const removing = runSetup(one().items);
  const original = removing.deps.cli;
  removing.deps.cli = async (action) => {
    if (action === "delete") removing.world.notificationConfigs = [];
    return original(action);
  };
  const first = await record(removing.deps);
  assert.equal(first.outcome, "recorded");
  assert.deepEqual(first.run.cleanup.steps.inventory.notificationConfigs.removed, [ID]);
  const adding = runSetup([]);
  const cli = adding.deps.cli;
  adding.deps.cli = async (action) => {
    if (action === "deploy") adding.world.notificationConfigs = [cfg("created-by-deploy")];
    return cli(action);
  };
  const second = await record(adding.deps);
  assert.equal(second.outcome, "needs-recovery");
  assert.deepEqual(second.run.cleanup.steps.inventory.notificationConfigs.added, [
    "created-by-deploy",
  ]);
});

// ---- the guard and the real bodies --------------------------------------------------------------------

test("the rule allows the primary bucket's configs as a read and nothing else", () => {
  const url = `https://storage.googleapis.com/storage/v1/b/${PRIMARY_BUCKET}/notificationConfigs`;
  assert.equal(
    destination({ method: "GET", url, mutation: false }).rule,
    "storage-notification-configs",
  );
  const refused = [
    { method: "DELETE", url: `${url}/${ID}`, mutation: true },
    { method: "POST", url, mutation: true, body: {} },
    { method: "PUT", url, mutation: true, body: {} },
    { method: "GET", url: `${url}/${ID}`, mutation: false },
    { method: "GET", url: `${url}?x=1`, mutation: false },
    {
      method: "GET",
      url: "https://storage.googleapis.com/storage/v1/b/fireemu-oracle-events-fe-events-control/notificationConfigs",
      mutation: false,
    },
    {
      method: "GET",
      url: "https://storage.googleapis.com/storage/v1/b/other-bucket/notificationConfigs",
      mutation: false,
    },
    {
      method: "GET",
      url: `https://storage.googleapis.com/storage/v1/b/${PRIMARY_BUCKET}x/notificationConfigs`,
      mutation: false,
    },
    { method: "GET", url, mutation: true },
  ];
  for (const request of refused)
    assert.ok(destination(request).problem, `${request.method} ${request.url}`);
  assert.equal(RULES.filter((r) => r.name === "storage-notification-configs").length, 1);
});

const realRuns =
  process.env.FE_SANDBOX_RUNS ?? join(import.meta.dirname, "../../../../docs.local/runs");
const realFile = (name) => join(realRuns, "fe-formal-v5", name);
const haveReal = existsSync(realFile("notification-configs-real.json"));

test(
  "real bodies: the committed copies are the two real responses with only the tenant ids replaced",
  { skip: !haveReal },
  () => {
    const real = readFileSync(realFile("notification-configs-real.json"), "utf8");
    const tenant = /cloud-functions-fireemu-oracle-events-(.+?)"/.exec(real)[1];
    const suffix = /topics\/cloud-functions-([a-z0-9]+)"/.exec(real)[1];
    const sanitized = real
      .replaceAll(tenant, "tenantprojectid-tp")
      .replaceAll(suffix, "topicsuffixplaceholder");
    assert.deepEqual(one(), JSON.parse(sanitized));
    assert.deepEqual(
      none(),
      JSON.parse(readFileSync(realFile("notification-configs-empty-real.json"), "utf8")),
    );
    const parsed = notificationConfigs(JSON.parse(real));
    assert.equal(parsed.length, 1);
    assert.equal(parsed[0].id, `cloud-functions-fireemu-oracle-events-${tenant}`);
  },
);
