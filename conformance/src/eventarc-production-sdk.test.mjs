import assert from "node:assert/strict";
import test from "node:test";
import { BudgetExceeded } from "./pubsub-production/capture.mjs";
import { createOwnership } from "./eventarc-production/names.mjs";
import { CaseLimit } from "./eventarc-production/runner.mjs";
import { createSdk } from "./eventarc-production/sdk.mjs";

const RUN = "0123456789ab";
const own = () => createOwnership({ project: "demo-project", runId: RUN });
const CHANNEL = "projects/demo-project/locations/us-central1/channels/fe0123456789ab-sd-sdk";

async function setup(
  reply = { status: 200, body: {}, unknown: false },
  { prefix = "/v1", ownership = own() } = {},
) {
  const calls = [];
  const notes = [];
  const transport = {
    name: "rest",
    request: async (call) => {
      calls.push(call);
      return typeof reply === "function" ? reply(call) : reply;
    },
  };
  const sdk = await createSdk({
    project: "demo-project",
    runId: RUN,
    caseId: "admin-sdk-publish",
    getToken: async () => "ya29.not-forwarded-token-value-0123456789",
    transport,
    ownership,
    publishPrefix: prefix,
    note: (kind, data) => notes.push([kind, data]),
  });
  return { sdk, calls, notes, ownership };
}

test("the SDK builds the request, the forwarder records it as the SDK made it, and the environment is restored", async (t) => {
  const { sdk, calls } = await setup();
  t.after(() => sdk.close());
  process.env.EVENTARC_CLOUD_EVENT_SOURCE = "kept-source";
  delete process.env.CLOUD_EVENTARC_EMULATOR_HOST;
  const outcome = await sdk.publish({
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
  assert.deepEqual(outcome, { threw: false, requests: 1, suppressed: 0 });
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

test("a relative channel name takes the project, the default channel needs its publish permission, and a source can come from the environment", async (t) => {
  const { sdk, calls, ownership } = await setup(undefined, { prefix: "" });
  t.after(() => sdk.close());
  await sdk.publish({
    channel: "locations/us-central1/channels/fe0123456789ab-sd-x",
    events: { type: "t", source: "//s", data: "text" },
  });
  await assert.rejects(
    sdk.publish({ events: { type: "t", data: { a: 1 } }, source: "//from-env" }),
    /refusing to publish to .*channels\/firebase/,
  );
  ownership.allowPublish("projects/demo-project/locations/us-central1/channels/firebase");
  await sdk.publish({ events: { type: "t", data: { a: 1 } }, source: "//from-env" });
  assert.equal(
    calls[0].path,
    "/projects/demo-project/locations/us-central1/channels/fe0123456789ab-sd-x:publishEvents",
  );
  assert.equal(calls[0].body.events[0].attributes.datacontenttype.ceString, "text/plain");
  assert.equal(
    calls[1].path,
    "/projects/demo-project/locations/us-central1/channels/firebase:publishEvents",
  );
  assert.equal(calls[1].body.events[0].source, "//from-env");
  assert.deepEqual(
    calls.map((call) => call.label.step),
    ["s01-1", "s03-1"],
  );
});

test("a channel that is not the run's is refused inside the forwarder before anything is sent, and the case sees the refusal", async (t) => {
  const { sdk, calls } = await setup();
  t.after(() => sdk.close());
  await assert.rejects(
    sdk.publish({
      channel: "projects/demo-project/locations/us-central1/channels/someone-else",
      events: { type: "t", source: "//s", data: "x" },
    }),
    /refusing to publish to .*someone-else/,
  );
  assert.equal(calls.length, 0);
});

test("a refusal before anything is sent is an outcome with no request, and an unexpected status is the SDK's error", async (t) => {
  const { sdk, calls } = await setup();
  t.after(() => sdk.close());
  const refused = async (events, extra = {}) => sdk.publish({ channel: CHANNEL, events, ...extra });
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
  assert.deepEqual(filtered, { threw: false, requests: 0, suppressed: 0 });
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
    channel: CHANNEL,
    events: { type: "t", source: "//s", data: "x" },
  });
  assert.equal(outcome.requests, 1);
  assert.equal(outcome.threw, true);
  assert.equal(outcome.error.status, 403);
  assert.match(outcome.error.message, /Unexpected response with status: 403/);
  assert.equal(calls.length, 1);
});

test("a 503 is forwarded once: the SDK's retry is answered here with a 409, never sent, noted, and ends the SDK's attempts", async (t) => {
  const { sdk, calls, notes } = await setup({ status: 503, body: {}, unknown: true });
  t.after(() => sdk.close());
  const outcome = await sdk.publish({
    channel: CHANNEL,
    events: { type: "t", source: "//s", data: "x" },
  });
  assert.equal(calls.length, 1, "one request reached the transport");
  assert.deepEqual([outcome.requests, outcome.suppressed, outcome.threw], [1, 1, true]);
  assert.equal(notes.filter(([kind]) => kind === "sdk-retry-suppressed").length, 1);
});

test("a transport with no status is answered as a bad gateway", async (t) => {
  const { sdk } = await setup({ status: null, body: undefined, unknown: true });
  t.after(() => sdk.close());
  const outcome = await sdk.publish({
    channel: CHANNEL,
    events: { type: "t", source: "//s", data: "x" },
  });
  assert.deepEqual([outcome.requests, outcome.threw, outcome.error.status], [1, true, 502]);
});

test("a ceiling or budget error inside the forwarder is raised again by the publish, and nothing escapes as an unhandled rejection", async (t) => {
  const rejections = [];
  const onRejection = (error) => rejections.push(error);
  process.on("unhandledRejection", onRejection);
  t.after(() => process.off("unhandledRejection", onRejection));
  for (const error of [new CaseLimit(14), new BudgetExceeded(200)]) {
    const { sdk, calls } = await setup(() => {
      throw error;
    });
    await assert.rejects(
      sdk.publish({ channel: CHANNEL, events: { type: "t", source: "//s", data: "x" } }),
      (raised) => raised === error,
    );
    assert.equal(calls.length, 1);
    await sdk.close();
  }
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(rejections, []);
});

test("the forwarder answers only a publish in progress, only the publish route under its token, and is closed after the case", async () => {
  const { sdk, calls } = await setup();
  const base = new URL(sdk.host);
  assert.equal(base.hostname, "127.0.0.1");
  assert.match(base.pathname, /^\/[0-9a-f]{24}$/);
  const route =
    "/projects/demo-project/locations/us-central1/channels/fe0123456789ab-sd-x:publishEvents";
  const post = (path) => fetch(`${base.origin}${path}`, { method: "POST", body: "{}" });
  const get = (path) => fetch(`${base.origin}${path}`);
  // No publish is in progress.
  assert.equal((await post(`${base.pathname}${route}`)).status, 403);
  assert.equal((await get(`${base.pathname}${route}`)).status, 403);
  assert.equal(calls.length, 0);
  // Once a publish is over, the forwarder is shut again.
  await sdk.publish({ channel: CHANNEL, events: { type: "t", source: "//s", data: "x" } });
  assert.equal(calls.length, 1);
  assert.equal(
    (await post(`${base.pathname}${route}`)).status,
    403,
    "closed to anything once the publish is over",
  );
  // A closed forwarder does not publish and does not listen.
  await sdk.close();
  await assert.rejects(
    sdk.publish({ channel: CHANNEL, events: { type: "t", source: "//s", data: "x" } }),
    /closed/,
  );
  await assert.rejects(
    fetch(`${base.origin}${base.pathname}${route}`, { method: "POST", body: "{}" }),
  );
  await sdk.close();
});

test("while a publish is in progress, a request under another token, with another method or for another project is refused and never sent", async (t) => {
  let release;
  const held = new Promise((resolve) => {
    release = resolve;
  });
  const calls = [];
  const sdk = await createSdk({
    project: "demo-project",
    runId: RUN,
    caseId: "c",
    getToken: async () => "ya29.token-value-0123456789012345",
    transport: {
      name: "rest",
      request: async (call) => {
        calls.push(call);
        await held;
        return { status: 200, body: {}, unknown: false };
      },
    },
    ownership: own(),
    publishPrefix: "/v1",
  });
  t.after(() => sdk.close());
  const base = new URL(sdk.host);
  const route =
    "/projects/demo-project/locations/us-central1/channels/fe0123456789ab-sd-x:publishEvents";
  const publishing = sdk.publish({
    channel: CHANNEL,
    events: { type: "t", source: "//s", data: "x" },
  });
  while (calls.length === 0) await new Promise((resolve) => setImmediate(resolve));
  const post = (path) => fetch(`${base.origin}${path}`, { method: "POST", body: "{}" });
  assert.equal((await post(`/0123456789abcdef01234567${route}`)).status, 404, "another token");
  assert.equal((await post(route)).status, 404, "no token");
  assert.equal(
    (await fetch(`${base.origin}${base.pathname}${route}`)).status,
    404,
    "another method",
  );
  assert.equal(
    (await fetch(`${base.origin}${base.pathname}${route}`, { method: "DELETE" })).status,
    404,
  );
  assert.equal(
    (
      await post(
        `${base.pathname}/projects/other-project/locations/us-central1/channels/x:publishEvents`,
      )
    ).status,
    404,
    "another project",
  );
  assert.equal(
    (await post(`${base.pathname}/projects/demo-project/topics/t:publish`)).status,
    404,
    "another route",
  );
  assert.equal((await post(`${base.pathname}${route}`)).status, 409, "a second publish is a retry");
  assert.equal(calls.length, 1, "nothing but the first request was sent");
  release();
  assert.deepEqual(await publishing, { threw: false, requests: 1, suppressed: 1 });
});
