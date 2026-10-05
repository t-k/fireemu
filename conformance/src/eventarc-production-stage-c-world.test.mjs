// Stage C: the refusals of the attribute quotas (recorded in stage B, rows 148 and 149) and the model's new
// modes (operations still running, a location that does not exist, page sizes). The predicates that read
// production's answers are replayed on the recorded bodies and refuse the near misses.

import assert from "node:assert/strict";
import test from "node:test";
import {
  isAttributeCountRefusal,
  isAttributeKeyRefusal,
  isCountRefusal,
  isSizeRefusal,
} from "./eventarc-production/bisect.mjs";
import { createWorld, recorded } from "./eventarc-production/testing/world.mjs";

const PROJECT = "demo-project";
const CHANNEL = `projects/${PROJECT}/locations/us-central1/channels/fe0123456789ab-pb-c`;

const answer = (reply) => ({ status: reply.status, body: reply.body, unknown: false });

test("the quota refusals are recognised on the recorded bodies, byte for byte, and on nothing else", () => {
  const count = answer(recorded("publishEvents-too-many-attributes"));
  const key = answer(recorded("publishEvents-key-too-large"));
  assert.equal(isAttributeCountRefusal(count), true);
  assert.equal(isAttributeKeyRefusal(key), true);
  // Each predicate refuses the other's answer and the other limits' answers.
  assert.equal(isAttributeCountRefusal(key), false);
  assert.equal(isAttributeKeyRefusal(count), false);
  for (const other of [
    answer(recorded("publishEvents-too-many-events")),
    answer(recorded("publishEvents-event-too-large")),
    answer(recorded("publishEvents-empty-list")),
  ]) {
    assert.equal(isAttributeCountRefusal(other), false);
    assert.equal(isAttributeKeyRefusal(other), false);
  }
  assert.equal(isCountRefusal(count) || isSizeRefusal(count), false);
  assert.equal(isCountRefusal(key) || isSizeRefusal(key), false);
  // Near misses: the status, the code and the wording all matter; a 404 or an unknown answer is no refusal.
  for (const broken of [
    { ...count, status: 404 },
    { ...count, unknown: true, status: 503 },
    { status: 400, body: { error: { ...count.body.error, status: "OUT_OF_RANGE" } } },
    {
      status: 400,
      body: { error: { ...count.body.error, message: "There are too many attributes." } },
    },
    {
      status: 400,
      body: { error: { ...count.body.error, message: `x ${count.body.error.message}` } },
    },
    undefined,
    null,
  ]) {
    assert.equal(isAttributeCountRefusal(broken), false, JSON.stringify(broken));
  }
  for (const broken of [
    { ...key, status: 500 },
    { status: 400, body: { error: { ...key.body.error, status: "NOT_FOUND" } } },
    { status: 400, body: { error: { ...key.body.error, message: "The attribute is too large." } } },
    undefined,
  ]) {
    assert.equal(isAttributeKeyRefusal(broken), false, JSON.stringify(broken));
  }
});

const event = (attributes, extra = {}) => ({
  id: "e",
  source: "s",
  specVersion: "1.0",
  type: "t",
  attributes,
  textData: "{}",
  ...extra,
});
const attributesOf = (extras, nameOf = (i) => `ext${i}`) => ({
  time: { ceTimestamp: "2026-10-05T00:00:00Z" },
  datacontenttype: { ceString: "application/json" },
  ...Object.fromEntries(Array.from({ length: extras }, (_, i) => [nameOf(i), { ceString: "v" }])),
});
const publish = (world, events, channel = CHANNEL) =>
  world.request({
    op: "publishEvents",
    method: "POST",
    path: `/v1/${channel}:publishEvents`,
    body: { events },
  });

async function worldWithChannel(options) {
  const world = createWorld({ project: PROJECT, ...options });
  const created = await world.request({
    op: "createChannel",
    method: "POST",
    path: `/v1/projects/${PROJECT}/locations/us-central1/channels?channelId=fe0123456789ab-pb-c`,
    body: { name: CHANNEL },
  });
  assert.equal(created.status, 200);
  return world;
}

test("the model counts attributes as production does (the four required ones included) and refuses beyond its limit with the recorded wording", async () => {
  const world = await worldWithChannel({ attributeLimit: 100 });
  // time + datacontenttype + 4 required + extras: 94 extras is exactly 100.
  assert.equal((await publish(world, [event(attributesOf(94))])).status, 200);
  const refused = await publish(world, [event(attributesOf(95))]);
  assert.equal(refused.status, 400);
  assert.equal(isAttributeCountRefusal(refused), true);
  assert.match(
    refused.body.error.message,
    /The request contains 101 attributes, but the maximum allowed is 100\./,
  );
  assert.deepEqual(
    world.limits.map((limit) => limit.kind),
    ["publish-too-many-attributes"],
  );
});

test("the model measures a key as `ce-` and the name, and refuses beyond its limit with the recorded wording", async () => {
  const world = await worldWithChannel({ keyLimit: 256 });
  const named = (length) => attributesOf(1, () => `n${"a".repeat(length - 1)}`);
  assert.equal((await publish(world, [event(named(253))])).status, 200);
  const refused = await publish(world, [event(named(254))]);
  assert.equal(refused.status, 400);
  assert.equal(isAttributeKeyRefusal(refused), true);
  assert.match(
    refused.body.error.message,
    /The size is 257 bytes, but the maximum allowed is 256\./,
  );
  assert.deepEqual(
    world.limits.map((limit) => limit.kind),
    ["publish-key-too-large"],
  );
});

test("without limits the model refuses neither (the stage B modes are unchanged)", async () => {
  const world = await worldWithChannel({});
  assert.equal((await publish(world, [event(attributesOf(300))])).status, 200);
  assert.deepEqual(world.limits, []);
});

const PARENT = `projects/${PROJECT}/locations/us-central1`;
const call = (world, op, method, path, body) => world.request({ op, method, path, body });
const create = (world, id) =>
  call(world, "createChannel", "POST", `/v1/${PARENT}/channels?channelId=${id}`, {
    name: `${PARENT}/channels/${id}`,
  });
const operationOf = (reply) => reply.body.name;
const read = (world, name) => call(world, "getOperation", "GET", `/v1/${name}`);

test("busy mode: a channel being created is visible, cannot be published to, and is ready when its operation is read done", async () => {
  const world = createWorld({ project: PROJECT, busy: "reject", duplicate: "409", doneAfter: 3 });
  const id = "fe0123456789ab-bz-a";
  const name = `${PARENT}/channels/${id}`;
  const started = await create(world, id);
  assert.equal(started.status, 200);
  assert.equal((await call(world, "getChannel", "GET", `/v1/${name}`)).status, 200);
  const listed = await call(world, "listChannels", "GET", `/v1/${PARENT}/channels`);
  assert.deepEqual(
    listed.body.channels.map((channel) => channel.name),
    [name],
  );
  assert.equal((await publish(world, [event(attributesOf(0))], name)).status, 404);
  assert.equal((await create(world, id)).status, 409, "a second creation while the first runs");
  assert.equal(
    (await call(world, "deleteChannel", "DELETE", `/v1/${name}`)).status,
    409,
    "a deletion while the creation runs (reject)",
  );
  await read(world, operationOf(started));
  await read(world, operationOf(started));
  assert.equal((await publish(world, [event(attributesOf(0))], name)).status, 404, "not done yet");
  assert.equal((await read(world, operationOf(started))).body.done, true);
  assert.equal((await publish(world, [event(attributesOf(0))], name)).status, 200);
});

test("busy mode: a channel being deleted is still there until its operation is read done; a second deletion is refused (reject) or started (accept)", async () => {
  for (const [mode, second] of [
    ["reject", 409],
    ["accept", 200],
  ]) {
    const world = createWorld({ project: PROJECT, busy: mode, doneAfter: 2 });
    const id = "fe0123456789ab-bz-b";
    const name = `${PARENT}/channels/${id}`;
    const created = await create(world, id);
    await read(world, operationOf(created));
    await read(world, operationOf(created));
    const deleted = await call(world, "deleteChannel", "DELETE", `/v1/${name}`);
    assert.equal(deleted.status, 200, mode);
    assert.equal((await call(world, "getChannel", "GET", `/v1/${name}`)).status, 200, mode);
    assert.equal((await publish(world, [event(attributesOf(0))], name)).status, 200, mode);
    assert.equal(
      (await call(world, "deleteChannel", "DELETE", `/v1/${name}`)).status,
      second,
      mode,
    );
    await read(world, operationOf(deleted));
    assert.equal((await read(world, operationOf(deleted))).body.done, true, mode);
    assert.equal((await call(world, "getChannel", "GET", `/v1/${name}`)).status, 404, mode);
    assert.equal((await call(world, "deleteChannel", "DELETE", `/v1/${name}`)).status, 404, mode);
  }
});

test("a location that does not exist is a 403 for a list, and `-` gathers every location", async () => {
  const world = createWorld({ project: PROJECT });
  for (const location of ["us-east99", "europe-north99", "global"])
    assert.equal(
      (
        await call(
          world,
          "listChannels",
          "GET",
          `/v1/projects/${PROJECT}/locations/${location}/channels`,
        )
      ).status,
      403,
      location,
    );
  for (const location of ["us-central1", "europe-west1", "-"])
    assert.equal(
      (
        await call(
          world,
          "listChannels",
          "GET",
          `/v1/projects/${PROJECT}/locations/${location}/channels`,
        )
      ).status,
      200,
      location,
    );
});

test("page sizes: a negative or fractional size is a 400, zero is the default, and a size above 1000 is clamped", async () => {
  const world = createWorld({ project: PROJECT });
  const ids = Array.from(
    { length: 1002 },
    (_, i) => `fe0123456789ab-pg-${String(i).padStart(4, "0")}`,
  );
  for (const id of ids)
    world.channels.set(`${PARENT}/channels/${id}`, { createTime: "2026-01-01T00:00:00Z" });
  const list = (query) => call(world, "listChannels", "GET", `/v1/${PARENT}/channels${query}`);
  assert.equal((await list("?pageSize=-1")).status, 400);
  assert.equal((await list("?pageSize=1.5")).status, 400);
  assert.equal((await list("?pageSize=abc")).status, 400);
  assert.equal((await list("?pageSize=0")).body.channels.length, 50);
  assert.equal((await list("?pageSize=3")).body.channels.length, 3);
  assert.equal((await list("?pageSize=100000")).body.channels.length, 1000);
  assert.equal((await list("")).body.channels.length, 50);
});
