// Stage C: the one creation that deviates from the official request on purpose (the body names another
// channel than the path's ID). It is the only request whose body or query is not firebase-tools 15.28.2's
// `createChannel`, so it is a named variant with its own tests: an unknown variant is refused before anything
// is sent, both names it may create are owned (or probes) and ledgered, and the model of production lists it
// as the refusal it is. A creation without a `channelId` (the other variant of the first version of stage C)
// is gone: a run never creates a resource it cannot name.

import assert from "node:assert/strict";
import test from "node:test";
import { createLedger } from "./pubsub-production/ledger.mjs";
import { createClient } from "./eventarc-production/client.mjs";
import { createOwnership } from "./eventarc-production/names.mjs";
import { createWorld } from "./eventarc-production/testing/world.mjs";

const RUN = "0123456789ab";
const PROJECT = "demo-project";
const LOCATION = "us-central1";

function setup() {
  const world = createWorld({ project: PROJECT });
  const ownership = createOwnership({ project: PROJECT, runId: RUN });
  const ledger = createLedger();
  const transport = { name: "rest", request: (call) => world.request(call) };
  const client = createClient({
    transports: { eventarc: transport },
    ownership,
    caseId: "variant",
    usageProject: PROJECT,
    ledger,
  });
  return { world, ownership, ledger, client };
}

test("name-mismatch: the path's channelId is one owned channel and the body's name is another, nothing else differs", async () => {
  const { world, ownership, ledger, client } = setup();
  const one = ownership.channel(LOCATION, "v-a");
  const other = ownership.channel(LOCATION, "v-b");
  await client.createChannelVariant(
    PROJECT,
    LOCATION,
    "name-mismatch",
    one.split("/").at(-1),
    other.split("/").at(-1),
  );
  const sent = world.calls.at(-1);
  assert.equal(
    sent.path,
    `/v1/projects/${PROJECT}/locations/${LOCATION}/channels?channelId=${one.split("/").at(-1)}`,
  );
  assert.deepEqual(sent.body, { name: other });
  // Both names the request may create are in the ledger, before and after the answer.
  assert.deepEqual([...ledger.state().keys()].toSorted(), [one, other].toSorted());
  // The model refuses it as a mismatch, and that is the only refusal in the run.
  assert.deepEqual(
    world.refusals.map((refusal) => refusal.kind),
    ["create-name-mismatch"],
  );
});

test("a creation without a channelId can no longer be built: a run never creates a resource it cannot name (coordinator ruling 2026-10-05)", async () => {
  const { world, ownership, client } = setup();
  const one = ownership.channel(LOCATION, "v-c").split("/").at(-1);
  await assert.rejects(
    () => client.createChannelVariant(PROJECT, LOCATION, "no-channel-id", one),
    /unknown createChannel variant/,
  );
  assert.deepEqual(world.calls, [], "nothing was sent");
  // The variant that is left is sent with a channelId in its path.
  await client.createChannelVariant(
    PROJECT,
    LOCATION,
    "name-mismatch",
    one,
    ownership.channel(LOCATION, "v-h").split("/").at(-1),
  );
  assert.ok(world.calls.every((call) => call.path.includes("channelId=")));
});

test("an unknown variant, a name that is not the run's, and a surplus argument are refused before anything is sent", async () => {
  const { world, ownership, client } = setup();
  const own = ownership.channel(LOCATION, "v-d").split("/").at(-1);
  const stranger = "somebody-elses-channel";
  await assert.rejects(
    () => client.createChannelVariant(PROJECT, LOCATION, "provider", own),
    /variant/,
  );
  await assert.rejects(
    () => client.createChannelVariant(PROJECT, LOCATION, "name-mismatch", own),
    /other/,
  );
  await assert.rejects(
    () => client.createChannelVariant(PROJECT, LOCATION, "name-mismatch", stranger, own),
    /not a channel of this run/,
  );
  await assert.rejects(
    () => client.createChannelVariant(PROJECT, LOCATION, "name-mismatch", own, stranger),
    /not a channel of this run/,
  );
  // One surplus argument is one too many for each variant, and a body cannot be smuggled in as one.
  const other = ownership.channel(LOCATION, "v-g").split("/").at(-1);
  await assert.rejects(
    () => client.createChannelVariant(PROJECT, LOCATION, "name-mismatch", own, other, {}),
    /no more arguments/,
  );
  await assert.rejects(
    () => client.createChannelVariant(PROJECT, LOCATION, "name-mismatch", own, other, "x", "y"),
    /no more arguments/,
  );
  assert.deepEqual(world.calls, [], "nothing was sent");
});

test("a variant the service accepts is a 2xx with an operation: the ledger holds it unknown until the operation is read, for both names", async () => {
  const { world, ownership, ledger } = setup();
  const one = ownership.channel(LOCATION, "v-e");
  const other = ownership.channel(LOCATION, "v-f");
  // A service that accepts the body whatever the path says (the model's answer is a refusal, so the answer is replaced).
  const accepting = createClient({
    transports: {
      eventarc: {
        name: "rest",
        request: async () => ({
          status: 200,
          body: { name: `projects/${PROJECT}/locations/${LOCATION}/operations/operation-9` },
          unknown: false,
        }),
      },
    },
    ownership,
    caseId: "variant",
    usageProject: PROJECT,
    ledger,
  });
  const reply = await accepting.createChannelVariant(
    PROJECT,
    LOCATION,
    "name-mismatch",
    one.split("/").at(-1),
    other.split("/").at(-1),
  );
  assert.equal(reply.ok, true);
  for (const name of [one, other]) assert.deepEqual(ledger.state().get(name).open, [], name);
  for (const name of [one, other])
    assert.deepEqual(
      ledger.state().get(name).creates,
      [`unknown@projects/${PROJECT}/locations/${LOCATION}/operations/operation-9`],
      name,
    );
  assert.equal(world.calls.length, 0);
});
