import assert from "node:assert/strict";
import test from "node:test";
import { createSdk } from "./eventarc-production/sdk.mjs";

const RUN = "0123456789ab";
const CHANNEL = "projects/demo-project/locations/us-central1/channels/fe0123456789ab-sd-sdk";

async function setup(reply = { status: 200, body: {}, unknown: false }, prefix = "/v1") {
  const calls = [];
  const publishing = { name: "rest", request: async (call) => (calls.push(call), reply) };
  const sdk = await createSdk({
    project: "demo-project",
    runId: RUN,
    getToken: async () => "ya29.not-forwarded-token-value-0123456789",
    publishing,
    publishPrefix: prefix,
  });
  return { sdk, calls };
}

test("the SDK builds the request, the forwarder records it as the SDK made it, and the environment is restored", async (t) => {
  const { sdk, calls } = await setup();
  t.after(() => sdk.close());
  process.env.EVENTARC_CLOUD_EVENT_SOURCE = "kept-source";
  delete process.env.CLOUD_EVENTARC_EMULATOR_HOST;
  const outcome = await sdk.publish({
    caseId: "admin-sdk-publish",
    channel: CHANNEL,
    events: {
      type: "t.v1",
      source: "//s",
      id: "id-1",
      time: "2026-10-05T01:02:03.000Z",
      subject: "sub",
      custom: "x",
      data: { a: 1 },
    },
  });
  assert.deepEqual(outcome, { requests: 1, threw: false });
  assert.equal(calls.length, 1);
  assert.deepEqual(
    { op: calls[0].op, method: calls[0].method, path: calls[0].path, label: calls[0].label },
    {
      op: "sdk.publishEvents",
      method: "POST",
      path: `/v1/${CHANNEL}:publishEvents`,
      label: { case: "admin-sdk-publish", step: "s01-1" },
    },
  );
  assert.deepEqual(calls[0].body, {
    events: [
      {
        "@type": "type.googleapis.com/io.cloudevents.v1.CloudEvent",
        id: "id-1",
        type: "t.v1",
        specVersion: "1.0",
        source: "//s",
        attributes: {
          time: { ceTimestamp: "2026-10-05T01:02:03.000Z" },
          datacontenttype: { ceString: "application/json" },
          subject: { ceString: "sub" },
          custom: { ceString: "x" },
        },
        textData: '{"a":1}',
      },
    ],
  });
  assert.equal(process.env.EVENTARC_CLOUD_EVENT_SOURCE, "kept-source");
  assert.equal(process.env.CLOUD_EVENTARC_EMULATOR_HOST, undefined);
  delete process.env.EVENTARC_CLOUD_EVENT_SOURCE;
});

test("a relative channel name takes the project, the default channel is the firebase one, and a source can come from the environment", async (t) => {
  const { sdk, calls } = await setup(undefined, "");
  t.after(() => sdk.close());
  await sdk.publish({
    caseId: "c",
    channel: "locations/us-central1/channels/x",
    events: { type: "t", source: "//s", data: "text" },
  });
  await sdk.publish({ caseId: "c", events: { type: "t", data: { a: 1 } }, source: "//from-env" });
  assert.equal(
    calls[0].path,
    "/projects/demo-project/locations/us-central1/channels/x:publishEvents",
  );
  assert.equal(calls[0].body.events[0].attributes.datacontenttype.ceString, "text/plain");
  assert.equal(
    calls[1].path,
    "/projects/demo-project/locations/us-central1/channels/firebase:publishEvents",
  );
  assert.equal(calls[1].body.events[0].source, "//from-env");
  assert.deepEqual(
    calls.map((call) => call.label.step),
    ["s01-1", "s02-1"],
  );
});

test("a refusal before anything is sent is an outcome with no request, and an unexpected status is the SDK's error", async (t) => {
  const { sdk, calls } = await setup();
  t.after(() => sdk.close());
  const refused = async (events, extra = {}) =>
    sdk.publish({ caseId: "c", channel: CHANNEL, events, ...extra });
  const cases = [
    [{ type: "t", data: "x" }, /'source' is required/],
    [{ type: "t", source: "//s" }, /'data' is required/],
    [{ type: "t", source: "//s", data: "x", time: "yesterday" }, /ISO date format/],
    [{ type: "t", source: "//s", data: "x", custom: 5 }, /must be string/],
    [{ type: "t", source: "//s", data: 5 }, /string or an object/],
  ];
  for (const [events, message] of cases) {
    const outcome = await refused(events);
    assert.equal(outcome.requests, 0);
    assert.equal(outcome.threw, true);
    assert.match(outcome.error.message, message);
    assert.equal(outcome.error.code, "eventarc/invalid-argument");
  }
  const badName = await sdk.publish({
    caseId: "c",
    channel: "not/a/channel",
    events: { type: "t", source: "//s", data: "x" },
  });
  assert.deepEqual(
    [badName.requests, badName.threw, badName.error.code],
    [0, true, "eventarc/invalid-argument"],
  );
  const filtered = await refused(
    { type: "t", source: "//s", data: "x" },
    { channelOptions: { allowedEventTypes: ["other"] } },
  );
  assert.deepEqual(filtered, { requests: 0, threw: false });
  assert.equal(calls.length, 0);
});

test("an error status from the service is thrown by the SDK with that status, and the forwarder answered with it", async (t) => {
  const { sdk, calls } = await setup({
    status: 403,
    body: { error: { status: "PERMISSION_DENIED" } },
    unknown: false,
  });
  t.after(() => sdk.close());
  const outcome = await sdk.publish({
    caseId: "c",
    channel: CHANNEL,
    events: { type: "t", source: "//s", data: "x" },
  });
  assert.equal(outcome.requests, 1);
  assert.equal(outcome.threw, true);
  assert.equal(outcome.error.status, 403);
  assert.match(outcome.error.message, /Unexpected response with status: 403/);
  assert.equal(calls.length, 1);
});

test("a transport with no status is answered as a bad gateway", async (t) => {
  const { sdk } = await setup({ status: null, body: undefined, unknown: true });
  t.after(() => sdk.close());
  const outcome = await sdk.publish({
    caseId: "c",
    channel: CHANNEL,
    events: { type: "t", source: "//s", data: "x" },
  });
  assert.deepEqual([outcome.requests, outcome.threw, outcome.error.status], [1, true, 502]);
});
