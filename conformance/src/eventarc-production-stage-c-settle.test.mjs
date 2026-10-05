// `settleCreation`: a request that may have created two channels is settled for both by its own operation.

import assert from "node:assert/strict";
import test from "node:test";
import { createLedger } from "./pubsub-production/ledger.mjs";
import { createClient } from "./eventarc-production/client.mjs";
import { createOwnership } from "./eventarc-production/names.mjs";
import { ledgerFacts } from "./eventarc-production/cleanup.mjs";
import { settleCreation } from "./eventarc-production/cases/support.mjs";

const PROJECT = "demo-project";
const PARENT = `projects/${PROJECT}/locations/us-central1`;

function settleSetup(answer, response = {}, error = undefined, done = true) {
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
                body: { name: answer.body.name, done, ...(error ? { error } : {}), response },
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

test("settleCreation: the operation's response names the channel it created; only that name is created and the other is settled as not created", async () => {
  const operation = `${PARENT}/operations/operation-8`;
  for (const created of [0, 1]) {
    const probe = settleSetup({
      status: 200,
      body: { name: operation, done: false },
      unknown: false,
    });
    const [a, b] = probe.names.map((name) => name.split("/").at(-1));
    // The project may be spelled by number in the response: only the location and the ID are compared.
    const response = { name: probe.names[created].replace("demo-project", "123456789012") };
    const { client, ledger, names, ctx } = settleSetup(
      { status: 200, body: { name: operation, done: false }, unknown: false },
      response,
    );
    const reply = await client.createChannelVariant(PROJECT, "us-central1", "name-mismatch", a, b);
    await settleCreation(ctx, reply, names);
    const kinds = names.map((name) => ledger.state().get(name).creates);
    assert.deepEqual(kinds[created], [`unknown@${operation}`, `ok@${operation}`]);
    assert.deepEqual(kinds[1 - created], [`unknown@${operation}`, `error@${operation}`]);
    // So the other name is not a confirmed creation that reads 404, and no A2 is needed for it.
    assert.equal(ledgerFacts(ledger.state().get(names[1 - created])).mayExist, false);
    assert.equal(ledgerFacts(ledger.state().get(names[created])).mayExist, true);
  }
});

test("settleCreation: a response that names neither channel, or none, settles both by the operation as before", async () => {
  const operation = `${PARENT}/operations/operation-9`;
  for (const response of [{}, { name: `${PARENT}/channels/somebody-else` }, { name: 5 }]) {
    const { client, ledger, names, ctx } = settleSetup(
      { status: 200, body: { name: operation, done: false }, unknown: false },
      response,
    );
    const [a, b] = names.map((name) => name.split("/").at(-1));
    const reply = await client.createChannelVariant(PROJECT, "us-central1", "name-mismatch", a, b);
    await settleCreation(ctx, reply, names);
    for (const name of names)
      assert.deepEqual(ledger.state().get(name).creates, [
        `unknown@${operation}`,
        `ok@${operation}`,
      ]);
  }
});

test("settleCreation: an operation that ended with an error, or is not done, never makes a name created, whatever its response says", async () => {
  const operation = `${PARENT}/operations/operation-10`;
  for (const [error, done, expected] of [
    [{ code: 3, message: "invalid" }, true, "error@"],
    [undefined, false, "unknown@"],
  ]) {
    const probe = settleSetup({
      status: 200,
      body: { name: operation, done: false },
      unknown: false,
    });
    const [a, b] = probe.names.map((name) => name.split("/").at(-1));
    // The response names the second channel: it must not be taken as evidence of a creation.
    const { client, ledger, names, ctx } = settleSetup(
      { status: 200, body: { name: operation, done: false }, unknown: false },
      { name: probe.names[1] },
      error,
      done,
    );
    const reply = await client.createChannelVariant(PROJECT, "us-central1", "name-mismatch", a, b);
    await settleCreation(ctx, reply, names);
    for (const name of names)
      assert.deepEqual(ledger.state().get(name).creates, [
        `unknown@${operation}`,
        `${expected}${operation}`,
      ]);
  }
});
