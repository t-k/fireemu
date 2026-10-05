// `listNames`: the names of a location in pages of 100, for at most three pages, and null whenever the answer
// is not a complete one (a failed list, more channels than the pages hold).

import assert from "node:assert/strict";
import test from "node:test";
import { createLedger } from "./pubsub-production/ledger.mjs";
import { listNames } from "./eventarc-production/cases/support.mjs";
import { createClient } from "./eventarc-production/client.mjs";
import { createOwnership } from "./eventarc-production/names.mjs";
import { createWorld } from "./eventarc-production/testing/world.mjs";

const PROJECT = "demo-project";
const PARENT = `projects/${PROJECT}/locations/us-central1`;

function ctxOver(world) {
  const transport = { name: "rest", request: (call) => world.request(call) };
  const ownership = createOwnership({ project: PROJECT, runId: "0123456789ab" });
  return {
    project: PROJECT,
    client: createClient({
      transports: { eventarc: transport },
      ownership,
      caseId: "lists",
      usageProject: PROJECT,
      ledger: createLedger(),
    }),
  };
}
const channels = (count) =>
  Array.from({ length: count }, (_, i) => `${PARENT}/channels/c-${String(i).padStart(4, "0")}`);

test("listNames: pages of exactly 100, every token carried, every name returned, in at most three pages", async () => {
  for (const [count, pages] of [
    [0, 1],
    [1, 1],
    [100, 1],
    [101, 2],
    [250, 3],
    [300, 3],
  ]) {
    const world = createWorld({ project: PROJECT, existing: channels(count) });
    const names = await listNames(ctxOver(world), "us-central1");
    const lists = world.calls.filter((call) => call.op === "listChannels");
    assert.equal(lists.length, pages, `${count} channels`);
    assert.deepEqual(names?.toSorted(), channels(count), `${count} channels`);
    lists.forEach((call, index) => {
      assert.match(call.path, /pageSize=100/);
      assert.equal(call.path.includes("pageToken="), index > 0, `${count}: page ${index + 1}`);
    });
  }
});

test("listNames: more channels than three pages hold is null, after exactly three requests", async () => {
  const world = createWorld({ project: PROJECT, existing: channels(301) });
  assert.equal(await listNames(ctxOver(world), "us-central1"), null);
  assert.equal(world.calls.filter((call) => call.op === "listChannels").length, 3);
});

test("listNames: a list that does not answer is null; a page cap is a parameter", async () => {
  const world = createWorld({ project: PROJECT, existing: channels(5) });
  const failing = ctxOver({ request: async () => ({ status: 503, body: {}, unknown: true }) });
  assert.equal(await listNames(failing, "us-central1"), null);
  assert.deepEqual(await listNames(ctxOver(world), "us-central1", 1), channels(5));
  const two = createWorld({ project: PROJECT, existing: channels(150) });
  assert.equal(await listNames(ctxOver(two), "us-central1", 1), null);
  assert.equal((await listNames(ctxOver(two), "us-central1", 2)).length, 150);
});

// `settleCreation`: a request that may have created two channels is settled for both by its own operation.
import { settleCreation } from "./eventarc-production/cases/support.mjs";

function settleSetup(answer) {
  const ownership = createOwnership({ project: PROJECT, runId: "0123456789ab" });
  const ledger = createLedger();
  const requests = [];
  const client = createClient({
    transports: {
      eventarc: {
        name: "rest",
        request: async (call) => {
          requests.push(call);
          return call.op === "getOperation"
            ? {
                status: 200,
                body: { name: answer.body.name, done: true, response: {} },
                unknown: false,
              }
            : answer;
        },
      },
    },
    ownership,
    caseId: "settle",
    usageProject: PROJECT,
    ledger,
  });
  const names = ["a", "b"].map((key) => ownership.channel("us-central1", `s-${key}`));
  return { client, ledger, names, requests, ctx: { client, sleep: async () => {} } };
}

test("settleCreation: both names are settled by the request's own operation, once each", async () => {
  const operation = `${PARENT}/operations/operation-7`;
  const { client, ledger, names, requests, ctx } = settleSetup({
    status: 200,
    body: { name: operation, done: false },
    unknown: false,
  });
  const [a, b] = names.map((name) => name.split("/").at(-1));
  const reply = await client.createChannelVariant(PROJECT, "us-central1", "name-mismatch", a, b);
  await settleCreation(ctx, reply, names);
  for (const name of names)
    assert.deepEqual(ledger.state().get(name).creates, [`unknown@${operation}`, `ok@${operation}`]);
  assert.equal(requests.filter((call) => call.op === "getOperation").length, 1);
});

test("settleCreation: an answer that names no operation is settled once, by itself, for every name", async () => {
  const { client, ledger, names, ctx } = settleSetup({
    status: 200,
    body: { done: true, response: {} },
    unknown: false,
  });
  const [a, b] = names.map((name) => name.split("/").at(-1));
  const reply = await client.createChannelVariant(PROJECT, "us-central1", "name-mismatch", a, b);
  await settleCreation(ctx, reply, names);
  assert.deepEqual(
    ledger.state().get(names[1]).creates,
    ["ok"],
    "the second name has no extra settlement",
  );
});
