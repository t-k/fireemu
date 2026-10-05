// The requests the recorder builds, against a model of production that refuses what production refuses
// (checklist section 2, "Request shapes, not only answers"). Stage A sent `{}` as the body of every
// channel creation, production answered `channel.name is empty` 28 times, and the test doubles that
// accepted `{}` hid it for three review rounds.

import assert from "node:assert/strict";
import test from "node:test";
import { createCapture } from "./pubsub-production/capture.mjs";
import { createLedger } from "./pubsub-production/ledger.mjs";
import { createClient } from "./eventarc-production/client.mjs";
import { createOwnership } from "./eventarc-production/names.mjs";
import { createWorld, recorded } from "./eventarc-production/testing/world.mjs";

const RUN = "0123456789ab";
const PROJECT = "demo-project";

function clientOn(world) {
  const ownership = createOwnership({ project: PROJECT, runId: RUN });
  const transport = { name: "rest", request: (call) => world.request(call) };
  const client = createClient({
    transports: { eventarc: transport, publishing: transport, usage: transport },
    ownership,
    caseId: "shape",
    usageProject: PROJECT,
    ledger: createLedger(),
  });
  return { client, ownership };
}

test("the recorded refusal of a creation without a name is what the model answers, byte for byte", async () => {
  const world = createWorld({ project: PROJECT });
  const answer = await world.request({
    op: "createChannel",
    method: "POST",
    path: `/v1/projects/${PROJECT}/locations/us-central1/channels?channelId=fe${RUN}-x`,
    body: {},
  });
  assert.equal(answer.status, 400);
  assert.deepEqual(answer.body, recorded("createChannel-no-name").body);
  assert.equal(answer.body.error.message, "The request was invalid: channel.name is empty");
  assert.deepEqual(answer.body.error.details[0].fieldViolations, [{ field: "channel.name" }]);
});

test("the model refuses a creation whose name is missing, empty, not a string, or not the path's channel", async () => {
  const world = createWorld({ project: PROJECT });
  const path = `/v1/projects/${PROJECT}/locations/us-central1/channels?channelId=fe${RUN}-x`;
  const full = `projects/${PROJECT}/locations/us-central1/channels/fe${RUN}-x`;
  const bodies = [
    undefined,
    null,
    [],
    {},
    { name: "" },
    { name: 5 },
    { name: null },
    { provider: "projects/p/locations/l/providers/x" },
    { name: `${full}-other` },
    { name: `projects/${PROJECT}/locations/europe-west1/channels/fe${RUN}-x` },
  ];
  for (const body of bodies) {
    const answer = await world.request({ op: "createChannel", method: "POST", path, body });
    assert.equal(answer.status, 400, JSON.stringify(body));
  }
  assert.equal(world.channels.size, 0);
  assert.equal(world.refusals.length, bodies.length);
  const accepted = await world.request({
    op: "createChannel",
    method: "POST",
    path,
    body: { name: full },
  });
  assert.equal(accepted.status, 200);
  assert.ok(world.channels.has(full));
});

test("the builder's creation carries the full resource name of the path and the channelId in the query, and nothing else (firebase-tools 15.28.2 createChannel)", async () => {
  const world = createWorld({ project: PROJECT });
  const { client } = clientOn(world);
  const id = `fe${RUN}-cl-c1`;
  const answer = await client.createChannel(PROJECT, "us-central1", id);
  const sent = world.calls.at(-1);
  assert.equal(sent.path, `/v1/projects/${PROJECT}/locations/us-central1/channels?channelId=${id}`);
  assert.deepEqual(sent.body, {
    name: `projects/${PROJECT}/locations/us-central1/channels/${id}`,
  });
  assert.equal(answer.ok, true, "the model answers a well-formed creation");
  assert.deepEqual(world.refusals, []);
});

test("no caller can pass a body to the creation: the client builds it", async () => {
  const world = createWorld({ project: PROJECT });
  const { client } = clientOn(world);
  await assert.rejects(
    () => client.createChannel(PROJECT, "us-central1", `fe${RUN}-cl-c1`, {}),
    /builds the body/,
  );
  assert.deepEqual(world.calls, [], "nothing was sent");
});

test("property: for any location and channel ID the builder produces a body the model accepts", async () => {
  let seed = 7;
  const next = (n) => {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    return seed % n;
  };
  const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-";
  for (let round = 0; round < 200; round += 1) {
    const world = createWorld({ project: PROJECT, locations: ["us-central1", "europe-west1", "asia-east1"] });
    const { client } = clientOn(world);
    const location = ["us-central1", "europe-west1", "asia-east1"][next(3)];
    let id = `fe${RUN}-`;
    for (let i = next(20) + 1; i > 0; i -= 1) id += alphabet[next(alphabet.length)];
    const answer = await client.createChannel(PROJECT, location, id.slice(0, 63));
    assert.equal(answer.status, 200, id);
    assert.equal(world.calls[0].body.name, `projects/${PROJECT}/locations/${location}/channels/${id.slice(0, 63)}`);
    assert.deepEqual(world.refusals, []);
  }
});
