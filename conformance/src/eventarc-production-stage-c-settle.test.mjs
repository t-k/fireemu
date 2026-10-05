// `settleCreation`: a request that may have created two channels is settled for both by its own operation.

import assert from "node:assert/strict";
import test from "node:test";
import { createLedger } from "./pubsub-production/ledger.mjs";
import { createClient } from "./eventarc-production/client.mjs";
import { createOwnership } from "./eventarc-production/names.mjs";
import { settleCreation } from "./eventarc-production/cases/support.mjs";

const PROJECT = "demo-project";
const PARENT = `projects/${PROJECT}/locations/us-central1`;

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
