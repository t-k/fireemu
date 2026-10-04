import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test, { beforeEach } from "node:test";
import { cleanup } from "./eventarc-production/cleanup.mjs";
import { createClient } from "./eventarc-production/client.mjs";
import { createOwnership } from "./eventarc-production/names.mjs";

const RUN = "0123456789ab";
let own;
beforeEach(() => {
  own = createOwnership({ project: "demo-project", runId: RUN });
});
const mine = (key, location = "us-central1") => own.channel(location, key);
const sleep = async () => {};
const NOT_FOUND = { status: 404, body: { error: { status: "NOT_FOUND" } }, unknown: false };

/** A service of channels with pages and long-running deletions, with optional faults. */
function fakeService({
  channels,
  pageSize = 2,
  listFault = {},
  deleteFault,
  doneAfter = 2,
  stay = new Set(),
}) {
  const live = new Set(channels);
  const calls = [];
  const operations = new Map();
  const eventarc = {
    name: "rest",
    async request({ method, path }) {
      calls.push(`${method} ${path}`);
      const bare = decodeURIComponent(path.split("?")[0].replace(/^\/v1\//, ""));
      const list = /^projects\/[^/]+\/locations\/([^/]+)\/channels$/.exec(bare);
      if (method === "GET" && list) {
        if (listFault[list[1]]) return listFault[list[1]];
        const items = [...live].filter((name) => name.split("/")[3] === list[1]).toSorted();
        const offset = Number(new URL(`http://x${path}`).searchParams.get("pageToken") ?? 0);
        const next = offset + pageSize < items.length ? String(offset + pageSize) : undefined;
        return {
          status: 200,
          body: {
            channels: items.slice(offset, offset + pageSize).map((name) => ({ name })),
            ...(next ? { nextPageToken: next } : {}),
          },
          unknown: false,
        };
      }
      if (method === "GET" && bare.includes("/operations/")) {
        const state = operations.get(bare);
        state.reads += 1;
        return {
          status: 200,
          body: { name: bare, done: state.reads >= doneAfter },
          unknown: false,
        };
      }
      if (method === "GET")
        return live.has(bare) ? { status: 200, body: { name: bare }, unknown: false } : NOT_FOUND;
      if (method === "DELETE") {
        const fault = deleteFault?.(bare);
        if (fault) return fault;
        if (!live.has(bare)) return NOT_FOUND;
        if (!stay.has(bare)) live.delete(bare);
        const name = `projects/demo-project/locations/us-central1/operations/op-${operations.size}`;
        operations.set(name, { reads: 0 });
        return { status: 200, body: { name, done: false }, unknown: false };
      }
      throw new Error(`unexpected ${method} ${path}`);
    },
  };
  return {
    live,
    calls,
    operations,
    client: createClient({
      transports: { eventarc },
      ownership: own,
      caseId: "cleanup",
      usageProject: "p",
    }),
  };
}

test("only the run's channels are deleted, across pages and locations, each operation polled to done and read back", async () => {
  const resources = [
    mine("a"),
    mine("b"),
    mine("c"),
    mine("d", "europe-west1"),
    "projects/demo-project/locations/us-central1/channels/someone-else",
    "projects/demo-project/locations/us-central1/channels/fe999999999999-x",
  ];
  const service = fakeService({ channels: resources });
  const report = await cleanup({
    client: service.client,
    ownership: own,
    project: "demo-project",
    sleep,
  });
  assert.deepEqual(report, {
    deleted: [mine("d", "europe-west1"), mine("a"), mine("b"), mine("c")],
    alreadyGone: [],
    leftover: [],
    errors: [],
    listed: ["europe-west1", "us-central1"],
  });
  assert.equal(service.live.size, 2);
  assert.equal(
    [...service.operations.values()].every((state) => state.reads === 2),
    true,
    "polled until done",
  );
  assert.equal(service.calls.filter((call) => call.startsWith("DELETE")).length, 4);
});

test("a location whose list cannot be read is an error and nothing is deleted there, however the channel is known", async () => {
  const name = mine("a");
  const service = fakeService({
    channels: [name],
    listFault: { "us-central1": { status: 503, body: {}, unknown: true } },
  });
  own.registerProbe("projects/demo-project/locations/us-central1/channels/probe");
  const report = await cleanup({
    client: service.client,
    ownership: own,
    project: "demo-project",
    sleep,
  });
  assert.deepEqual(report.errors, ["listChannels us-central1: UNAVAILABLE"]);
  assert.deepEqual([report.deleted, report.listed], [[], []]);
  assert.equal(
    service.calls.some((call) => call.startsWith("DELETE")),
    false,
  );
  assert.equal(service.live.has(name), true);
});

test("a probe is deleted only when a fresh list shows it, and a list that never ends is an error", async () => {
  const probe = own.registerProbe(
    "projects/demo-project/locations/us-central1/channels/GOOG-Upper",
  );
  own.registerProbe("projects/demo-project/locations/us-central1/channels/never-created");
  const service = fakeService({ channels: [probe] });
  const report = await cleanup({
    client: service.client,
    ownership: own,
    project: "demo-project",
    sleep,
  });
  assert.deepEqual(report.deleted, [probe]);
  assert.equal(
    service.calls.filter((call) => call.startsWith("DELETE")).length,
    1,
    "the probe that was not listed is not touched",
  );
  const endless = createOwnership({ project: "demo-project", runId: RUN });
  endless.channel("us-central1", "x");
  const calls = [];
  const transport = {
    name: "rest",
    request: async ({ path }) => (
      calls.push(path),
      { status: 200, body: { nextPageToken: "more" }, unknown: false }
    ),
  };
  const client = createClient({
    transports: { eventarc: transport },
    ownership: endless,
    caseId: "cleanup",
    usageProject: "p",
  });
  const stuck = await cleanup({ client, ownership: endless, project: "demo-project", sleep });
  assert.equal(calls.length, 20);
  assert.ok(calls[0].includes("pageSize=100") && calls[1].includes("pageToken=more"));
  assert.deepEqual(stuck.errors, ["listChannels us-central1: more than 20 pages"]);
});

test("an unknown deletion is repeated once, a refusal is an error, and an operation that does not finish is reported", async () => {
  let flaky = 0;
  const service = fakeService({
    channels: [mine("flaky"), mine("denied"), mine("slow")],
    doneAfter: 99,
    deleteFault: (name) =>
      name.endsWith("-flaky") && flaky++ === 0
        ? { status: 503, body: {}, unknown: true }
        : name.endsWith("-denied")
          ? { status: 403, body: { error: { status: "PERMISSION_DENIED" } }, unknown: false }
          : undefined,
  });
  const report = await cleanup({
    client: service.client,
    ownership: own,
    project: "demo-project",
    sleep,
    pollAttempts: 3,
  });
  assert.equal(flaky, 2);
  assert.ok(report.errors.includes(`deleteChannel ${mine("denied")}: PERMISSION_DENIED`));
  assert.ok(report.errors.some((error) => /^operation .*: not done$/.test(error)));
  assert.deepEqual(report.deleted.toSorted(), [mine("flaky"), mine("slow")].toSorted());
  assert.deepEqual(report.leftover, []);
});

test("a channel that stays after its deletion is left over, with two seconds between the three reads", async () => {
  const name = mine("stubborn");
  const service = fakeService({ channels: [name], stay: new Set([name]) });
  const sleeps = [];
  const report = await cleanup({
    client: service.client,
    ownership: own,
    project: "demo-project",
    sleep: async (ms) => sleeps.push(ms),
  });
  assert.deepEqual(report.leftover, [name]);
  assert.deepEqual(sleeps.filter((ms) => ms === 2000).length >= 2, true);
  assert.equal(service.calls.filter((call) => call === `GET /v1/${name}`).length, 3);
});

test("a channel that is already gone is not an error", async () => {
  const name = mine("gone");
  let service;
  service = fakeService({
    channels: [name],
    deleteFault: () => {
      service.live.delete(name);
      return NOT_FOUND;
    },
  });
  const report = await cleanup({
    client: service.client,
    ownership: own,
    project: "demo-project",
    sleep,
  });
  assert.deepEqual([report.alreadyGone, report.errors, report.leftover], [[name], [], []]);
});

test("replay on the recorded answers: the empty channel list and the 404 of channels/firebase", async () => {
  const fixture = (name) =>
    JSON.parse(
      readFileSync(
        new URL(`./eventarc-production/fixtures/preflight-002/${name}`, import.meta.url),
        "utf8",
      ),
    );
  const list = fixture("channels-list.json");
  const missing = fixture("channel-firebase-404.json");
  assert.equal(list.url.endsWith("/locations/us-central1/channels?pageSize=100"), true);
  const calls = [];
  const eventarc = {
    name: "rest",
    request: async ({ method, path }) => {
      calls.push(`${method} ${path}`);
      const recorded = path.includes("?") ? list : missing;
      return { status: recorded.status, body: JSON.parse(recorded.body), unknown: false };
    },
  };
  const ownership = createOwnership({ project: "fireemu-oracle-idp", runId: RUN });
  ownership.channel("us-central1", "x");
  const client = createClient({
    transports: { eventarc },
    ownership,
    caseId: "cleanup",
    usageProject: "p",
  });
  const report = await cleanup({ client, ownership, project: "fireemu-oracle-idp", sleep });
  assert.deepEqual(report, {
    deleted: [],
    alreadyGone: [],
    leftover: [],
    errors: [],
    listed: ["us-central1"],
  });
  const answer = await client.getChannel(
    "projects/fireemu-oracle-idp/locations/us-central1/channels/firebase",
  );
  assert.deepEqual([answer.ok, answer.code, answer.status], [false, "NOT_FOUND", 404]);
});
