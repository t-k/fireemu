import assert from "node:assert/strict";
import test from "node:test";
import {
  OPERATION_NAMES,
  PUBLISHING_API,
  createClient,
  kindOfOperation,
} from "./eventarc-production/client.mjs";
import { createOwnership } from "./eventarc-production/names.mjs";

const RUN = "0123456789ab";
const own = () => createOwnership({ project: "demo-project", runId: RUN });

function fakeTransports(reply = { status: 200, body: {}, unknown: false }) {
  const calls = [];
  const make = (host) => ({
    name: "rest",
    request: async (call) => (calls.push({ host, ...call }), reply),
  });
  return {
    calls,
    transports: {
      eventarc: make("eventarc"),
      publishing: make("publishing"),
      usage: make("usage"),
    },
  };
}

test("the channel names of a run carry the prefix and are checked, with the locations they use remembered", () => {
  const ownership = own();
  const name = ownership.channel("us-central1", "pe-env");
  assert.equal(name, "projects/demo-project/locations/us-central1/channels/fe0123456789ab-pe-env");
  assert.equal(ownership.isOwned(name), true);
  assert.equal(
    ownership.isOwned("projects/demo-project/locations/us-central1/channels/other"),
    false,
  );
  assert.equal(
    ownership.isOwned("projects/other-project/locations/us-central1/channels/fe0123456789ab-x"),
    false,
  );
  assert.equal(
    ownership.isOwned("projects/demo-project/locations/us-central1/channels/fe999999999999-x"),
    false,
  );
  assert.deepEqual(ownership.issued(), [name]);
  assert.deepEqual(ownership.locations(), ["us-central1"]);
  ownership.channel("europe-west1", "x");
  assert.deepEqual(ownership.locations(), ["europe-west1", "us-central1"]);
  assert.throws(() => ownership.channel("Bad Location", "x"), /not a location/);
  assert.throws(() => ownership.channel("us-central1", "UPPER"), /not a usable channel ID/);
  assert.throws(() => ownership.channel("us-central1", "x".repeat(64)), /not a usable channel ID/);
  assert.throws(() => createOwnership({ project: "x", runId: RUN }), /not a project ID/);
  assert.throws(() => createOwnership({ project: "demo-project", runId: "xyz" }), /12 hex/);
});

test("a probe is a changeable name once registered, and its location is listed unless it cannot exist", () => {
  const ownership = own();
  const probe = ownership.registerProbe(
    "projects/demo-project/locations/us-central1/channels/GOOG-Upper",
  );
  assert.equal(ownership.isOwned(probe), true);
  assert.deepEqual(ownership.probes(), [probe]);
  assert.deepEqual(ownership.locations(), ["us-central1"]);
  ownership.registerProbe("projects/demo-project/locations/no-such-location1/channels/x", {
    listable: false,
  });
  assert.deepEqual(ownership.locations(), ["us-central1"]);
  assert.throws(
    () => ownership.registerProbe("projects/demo-project/locations/us-central1"),
    /one channel/,
  );
  assert.throws(
    () => ownership.registerProbe("projects/other/locations/us-central1/channels/x"),
    /one channel/,
  );
  assert.throws(
    () => ownership.assertOwned("projects/demo-project/locations/us-central1/channels/nope"),
    /not a channel of this run/,
  );
});

test("every operation is the request the API documents, on its host", async () => {
  const ownership = own();
  const channel = ownership.channel("us-central1", "c");
  const expected = {
    getService: [[], "usage", "GET", `/v1/projects/123/services/${PUBLISHING_API}`, undefined],
    enableService: [[], "usage", "POST", `/v1/projects/123/services/${PUBLISHING_API}:enable`, {}],
    listEnabledServices: [
      [{ pageToken: "a b" }],
      "usage",
      "GET",
      "/v1/projects/123/services?filter=state%3AENABLED&pageSize=200&pageToken=a%20b",
      undefined,
    ],
    getOperation: [
      ["eventarc", "projects/p/locations/l/operations/op-1"],
      "eventarc",
      "GET",
      "/v1/projects/p/locations/l/operations/op-1",
      undefined,
    ],
    createChannel: [
      ["demo-project", "us-central1", "fe0123456789ab-c", { a: 1 }],
      "eventarc",
      "POST",
      "/v1/projects/demo-project/locations/us-central1/channels?channelId=fe0123456789ab-c",
      { a: 1 },
    ],
    getChannel: [[channel], "eventarc", "GET", `/v1/${channel}`, undefined],
    listChannels: [
      ["demo-project", "-", { pageSize: 5, pageToken: "a b" }],
      "eventarc",
      "GET",
      "/v1/projects/demo-project/locations/-/channels?pageSize=5&pageToken=a%20b",
      undefined,
    ],
    deleteChannel: [[channel], "eventarc", "DELETE", `/v1/${channel}`, undefined],
    publishEvents: [
      [channel, { events: [] }],
      "publishing",
      "POST",
      `/v1/${channel}:publishEvents`,
      { events: [] },
    ],
  };
  assert.deepEqual(OPERATION_NAMES.toSorted(), Object.keys(expected).toSorted());
  for (const [operation, [args, host, method, path, body]] of Object.entries(expected)) {
    const { calls, transports } = fakeTransports();
    const client = createClient({ transports, ownership, caseId: "c", usageProject: "123" });
    const reply = await client[operation](...args);
    assert.deepEqual(
      calls,
      [{ host, label: { case: "c", step: "01" }, op: operation, method, path, body }],
      operation,
    );
    assert.deepEqual([reply.ok, reply.code, reply.step], [true, "OK", "01"], operation);
  }
});

test("the publish route has no /v1 against the emulator, and the operation names are encoded", async () => {
  const ownership = own();
  const channel = ownership.channel("us-central1", "c");
  const { calls, transports } = fakeTransports();
  const client = createClient({
    transports,
    ownership,
    caseId: "c",
    usageProject: "p",
    publishPrefix: "",
  });
  await client.publishEvents(channel, {});
  assert.equal(calls[0].path, `/${channel}:publishEvents`);
});

test("a changing operation on a channel that is not the run's is refused before anything is sent", async () => {
  const ownership = own();
  const { calls, transports } = fakeTransports();
  const client = createClient({ transports, ownership, caseId: "c", usageProject: "p" });
  const foreign = "projects/demo-project/locations/us-central1/channels/firebase";
  await assert.rejects(client.deleteChannel(foreign), /not a channel of this run/);
  await assert.rejects(client.publishEvents(foreign, {}), /not a channel of this run/);
  await assert.rejects(
    client.createChannel("demo-project", "us-central1", "firebase", {}),
    /not a channel of this run/,
  );
  await assert.rejects(
    client.createChannel("other-project", "us-central1", "fe0123456789ab-x", {}),
    /not a channel of this run/,
  );
  assert.equal(calls.length, 0);
  // Reads of anything are allowed, and a registered probe may be changed.
  await client.getChannel(foreign);
  await client.listChannels("other-project", "us-central1");
  ownership.registerProbe(foreign);
  await client.publishEvents(foreign, {});
  assert.equal(calls.length, 3);
});

test("the steps are numbered, the answer is normalized, and a token choice or timeout is passed on", async () => {
  const ownership = own();
  const failing = fakeTransports({
    status: 404,
    body: { error: { status: "NOT_FOUND" } },
    unknown: false,
  });
  const client = createClient({
    transports: failing.transports,
    ownership,
    caseId: "c",
    usageProject: "p",
  });
  const first = await client.getChannel("projects/p/locations/l/channels/x");
  const second = await client.with({ token: "none", timeoutMs: 5 }).listChannels("p", "l");
  assert.deepEqual(
    [first.ok, first.code, first.status, first.step, second.step],
    [false, "NOT_FOUND", 404, "01", "02"],
  );
  assert.deepEqual([failing.calls[1].token, failing.calls[1].timeoutMs], ["none", 5]);
  assert.equal(failing.calls[0].token, undefined);
  const missing = createClient({
    transports: { eventarc: failing.transports.eventarc },
    ownership,
    caseId: "c",
    usageProject: "p",
  });
  await assert.rejects(missing.getService(), /no transport for usage/);
});

test("a publish target may be published to but is never a channel the cleanup could delete", async () => {
  const ownership = own();
  const { calls, transports } = fakeTransports();
  const client = createClient({ transports, ownership, caseId: "c", usageProject: "p" });
  const firebase = "projects/demo-project/locations/us-central1/channels/firebase";
  await assert.rejects(client.publishEvents(firebase, {}), /refusing to publish/);
  ownership.allowPublish(firebase);
  await client.publishEvents(firebase, {});
  assert.equal(calls.length, 1);
  await assert.rejects(client.deleteChannel(firebase), /not a channel of this run/);
  assert.equal(ownership.isOwned(firebase), false);
  assert.deepEqual(ownership.probes(), []);
  assert.throws(
    () => ownership.allowPublish("projects/demo-project/locations/us-central1"),
    /one channel/,
  );
  assert.throws(() => ownership.assertPublishable(5), /refusing to publish/);
});

test("an operation is settled by what it says: done without an error is ok, ALREADY_EXISTS is a conflict, any other error is an error, and anything not read as done is unknown", () => {
  const read = (body, ok = true) => ({ ok, body });
  assert.equal(kindOfOperation(read({ done: true })), "ok");
  assert.equal(kindOfOperation(read({ done: true, error: { code: 6 } })), "conflict");
  assert.equal(
    kindOfOperation(read({ done: true, error: { status: "ALREADY_EXISTS", code: 0 } })),
    "conflict",
  );
  assert.equal(kindOfOperation(read({ done: true, error: { code: 13 } })), "error");
  assert.equal(kindOfOperation(read({ done: true, error: { status: "INTERNAL" } })), "error");
  assert.equal(kindOfOperation(read({ done: false })), "unknown");
  assert.equal(kindOfOperation(read({})), "unknown");
  assert.equal(kindOfOperation(read({ done: true }, false)), "unknown");
  assert.equal(kindOfOperation(undefined), "unknown");
});
