import assert from "node:assert/strict";
import { test } from "node:test";
import { calendarRequests } from "./calendar.mjs";
import {
  nativeCalendarInput,
  exerciseCalendarSession,
  calendarFixture,
  localCalendarClient,
} from "./calendar-local.mjs";

function recording() {
  const request = calendarRequests(
    "a1".repeat(8),
    "123456789012",
    Date.parse("2026-09-30T09:00:01Z"),
  ).find((row) => row.id === "c01-create");
  const body = Buffer.from(
    JSON.stringify({ ...request.json, state: "ENABLED", scheduleTime: "2026-09-30T09:01:00Z" }),
  );
  return [
    { ...request, state: "before-send", dispatchAt: "2026-09-30T09:00:01.000Z" },
    {
      id: request.id,
      state: "response-headers",
      status: 200,
      responseAt: "2026-09-30T09:00:02.000Z",
    },
    {
      id: request.id,
      state: "response-persisted",
      status: 200,
      bodyBase64: body.toString("base64"),
      bodyBytes: body.length,
      dispatchAt: "2026-09-30T09:00:01.000Z",
      responseAt: "2026-09-30T09:00:03.000Z",
    },
  ];
}

test("calendar local input derives identity, advertised time and both creation anchors from raw journal", () => {
  const input = nativeCalendarInput({
    journal: recording(),
    runId: "a1".repeat(8),
    projectNumber: "123456789012",
    caseId: "c01",
  });
  assert.equal(input.scheduleTime, "2026-09-30T09:01:00Z");
  assert.deepEqual(input.anchors, ["2026-09-30T09:00:01.000Z", "2026-09-30T09:00:02.000Z"]);
  assert.equal(input.schedule, "* * * * *");
  assert.match(input.bodySha256, /^[a-f0-9]{64}$/);
});

test("calendar local input rejects unknown, duplicate, foreign or unordered native proof", () => {
  const alterations = [
    (rows) => {
      rows[2].state = "body-unknown";
    },
    (rows) => {
      rows.push(rows[2]);
    },
    (rows) => {
      rows[0].url += "-foreign";
    },
    (rows) => {
      rows[1].responseAt = "2026-09-30T08:59:59Z";
    },
    (rows) => {
      rows[2].bodyBytes++;
    },
    (rows) => {
      rows[2].status = 400;
    },
    (rows) => {
      const body = JSON.parse(Buffer.from(rows[2].bodyBase64, "base64"));
      body.pubsubTarget.topicName += "-foreign";
      const bytes = Buffer.from(JSON.stringify(body));
      rows[2].bodyBase64 = bytes.toString("base64");
      rows[2].bodyBytes = bytes.length;
    },
    (rows) => {
      const body = JSON.parse(Buffer.from(rows[2].bodyBase64, "base64"));
      delete body.scheduleTime;
      const bytes = Buffer.from(JSON.stringify(body));
      rows[2].bodyBase64 = bytes.toString("base64");
      rows[2].bodyBytes = bytes.length;
    },
  ];
  for (const alter of alterations) {
    const journal = recording();
    alter(journal);
    assert.throws(
      () =>
        nativeCalendarInput({
          journal,
          runId: "a1".repeat(8),
          projectNumber: "123456789012",
          caseId: "c01",
        }),
      /native|journal|calendar|proof/,
    );
  }
});

function client({
  missing = false,
  duplicate = false,
  runtime = true,
  alive = true,
  exports = true,
  callbackTime = "2026-09-30T09:01:00Z",
} = {}) {
  let now = "2026-09-30T09:00:01.000Z",
    receipts = [],
    boundaryAdvances = 0;
  return {
    control: async (path, body) => {
      if (path.endsWith("/functions"))
        return {
          status: runtime ? 200 : 404,
          json: {
            runnerAlive: alive,
            functions: exports ? ["calendarProbe", "calendarReceipt"] : ["calendarReceipt"],
          },
        };
      if (path.endsWith(":awaitIdle")) return { status: 200, json: { idle: true } };
      now = body.instant;
      if (Date.parse(now) >= Date.parse("2026-09-30T09:01:00Z")) {
        boundaryAdvances++;
        if (!missing && (!receipts.length || duplicate))
          receipts.push({ scheduleTime: callbackTime, sequence: boundaryAdvances });
      }
      return { status: 200, json: {} };
    },
    receipts: async () => structuredClone(receipts),
  };
}

test("calendar local session requires actual zero/one callback and no duplicate at the same instant", async () => {
  const result = await exerciseCalendarSession({
    input: { scheduleTime: "2026-09-30T09:01:00Z" },
    anchor: "2026-09-30T09:00:01Z",
    ...client(),
  });
  assert.equal(result.matched, true);
  assert.equal(result.receipts.length, 1);
  for (const options of [{ missing: true }, { duplicate: true }, { runtime: false }]) {
    const refusal = await exerciseCalendarSession({
      input: { scheduleTime: "2026-09-30T09:01:00Z" },
      anchor: "2026-09-30T09:00:01Z",
      ...client(options),
    });
    assert.equal(refusal.matched, false);
  }
});

test("calendar local idle success cannot substitute for a live runner with both loaded exports", async () => {
  for (const options of [{ alive: false }, { exports: false }]) {
    const result = await exerciseCalendarSession({
      input: { scheduleTime: "2026-09-30T09:01:00Z" },
      anchor: "2026-09-30T09:00:01Z",
      ...client(options),
    });
    assert.equal(result.matched, false);
    assert.match(result.reason, /runner|export/);
  }
});

test("calendar local callback comparison preserves nanosecond distinctions", async () => {
  const mismatch = await exerciseCalendarSession({
    input: { scheduleTime: "2026-09-30T09:01:00Z" },
    anchor: "2026-09-30T09:00:01Z",
    ...client({ callbackTime: "2026-09-30T09:01:00.000000001Z" }),
  });
  assert.equal(mismatch.matched, false);
  const equivalent = await exerciseCalendarSession({
    input: { scheduleTime: "2026-09-30T09:01:00.000000000Z" },
    anchor: "2026-09-30T09:00:01Z",
    ...client({ callbackTime: "2026-09-30T10:01:00+01:00" }),
  });
  assert.equal(equivalent.matched, true);
});

test("calendar fixture preserves exact SDK declaration and callback supplied time", () => {
  const source = calendarFixture({ schedule: "every 5 minutes", timeZone: "UTC" });
  assert.ok(source.includes('"every 5 minutes"'));
  assert.ok(source.includes("event.scheduleTime"));
  assert.ok(!source.includes("Date.now"));
  assert.ok(source.includes("exports.calendarReceipt"));
});

test("calendar local client refuses remote origins and confines requests to local control/receipt routes", async () => {
  for (const controlUrl of [
    "https://127.0.0.1:1234/v1/",
    "http://example.com:1234/v1/",
    "http://user@127.0.0.1:1234/v1/",
    "http://127.0.0.1:1234/",
  ])
    assert.throws(
      () =>
        localCalendarClient({
          controlUrl,
          functionsHost: "127.0.0.1:1235",
          token: "fake-local-token",
        }),
      /loopback|control/,
    );
  const calls = [];
  const localClient = localCalendarClient({
    controlUrl: "http://127.0.0.1:1234/v1/",
    functionsHost: "127.0.0.1:1235",
    token: "fake-local-token",
    send: async (url, options) => {
      calls.push({ url: String(url), options });
      return new Response("[]", { status: 200 });
    },
  });
  await localClient.control("sessions/default:awaitIdle", { timeoutSeconds: 30 });
  await localClient.receipts();
  assert.equal(calls[0].url, "http://127.0.0.1:1234/v1/sessions/default:awaitIdle");
  assert.equal(calls[0].options.headers.authorization, "Bearer fake-local-token");
  assert.equal(
    calls[1].url,
    "http://127.0.0.1:1235/demo-scheduled-calendar/us-central1/calendarReceipt",
  );
  assert.equal(calls[1].options.headers.authorization, undefined);
  assert.equal(calls[0].options.redirect, "error");
  await assert.rejects(localClient.control("https://example.com/"), /route/);
});

test("native calendar brackets reject reversed nanosecond ordering within one millisecond", () => {
  const journal = recording();
  journal[0].dispatchAt = "2026-09-30T09:00:01.000000900Z";
  journal[1].responseAt = "2026-09-30T09:00:01.000000100Z";
  journal[2].dispatchAt = journal[0].dispatchAt;
  assert.throws(
    () =>
      nativeCalendarInput({
        journal,
        runId: "a1".repeat(8),
        projectNumber: "123456789012",
        caseId: "c01",
      }),
    /proof/,
  );
});
test("malformed callback time retains the actual invocation receipt", async () => {
  const result = await exerciseCalendarSession({
    input: { scheduleTime: "2026-09-30T09:01:00Z" },
    anchor: "2026-09-30T09:00:01Z",
    ...client({ callbackTime: "malformed" }),
  });
  assert.equal(result.matched, false);
  assert.equal(result.receipts.length, 1);
  assert.equal(result.receipts[0].scheduleTime, "malformed");
});
