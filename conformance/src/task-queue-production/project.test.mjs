import assert from "node:assert/strict";
import test from "node:test";

import {
  MASK_PROJECT,
  digestOf,
  maskText,
  projectAnswer,
  projectHeaders,
  projectRecording,
  refuseUnmaskedNumbers,
  shapeOfValue,
  timingsOf,
} from "./project.mjs";

// A deterministic generator, so that a failing property is reproducible.
const prng = (seed) => () => {
  seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
  return seed / 2 ** 32;
};
const digits = (next, n) => Array.from({ length: n }, () => Math.floor(next() * 10)).join("");

test("a mask keeps the form of a time and of an id, never its value", () => {
  assert.equal(maskText("at 2026-11-11T09:01:37.123456Z"), "at TIME(f6,Z)");
  assert.equal(maskText("2026-11-11T09:01:37Z"), "TIME(f0,Z)");
  assert.equal(maskText("2026-11-11T09:01:37.5-08:00"), "TIME(f1,offset)");
  assert.equal(maskText("2026-11-11T09:01:37.500Z", { messageTimes: true }), "TIME(Z)");
  assert.equal(maskText("1789000000.123456"), "UNIX(f6)");
  assert.equal(maskText("tasks/1234567890123456789"), "tasks/ID(19)");
  assert.equal(
    maskText("projects/fireemu-oracle-abc/queues/tqdefab12cd"),
    `projects/${MASK_PROJECT}/queues/tqdef`,
  );
  assert.equal(maskText("run tqrun-0123456789abcdef"), "run tqrun-RUN");
  assert.equal(
    maskText("https://tqretryab12cd-xyz0123456-uc.a.run.app/x"),
    "https://tqretry-HOST-uc.a.run.app/x",
  );
});

test("the project number never survives a mask, whatever surrounds it", () => {
  const next = prng(7);
  for (let i = 0; i < 200; i++) {
    const number = "5" + digits(next, 11);
    const text = `a ${number}-compute@developer.gserviceaccount.com b projects/${number}/locations/x c`;
    const masked = maskText(text, { projectNumber: number });
    assert.ok(!masked.includes(number), masked);
    assert.doesNotThrow(() => refuseUnmaskedNumbers(masked, number));
  }
});

test("a mask is idempotent and only ever removes digits of ids", () => {
  const next = prng(11);
  for (let i = 0; i < 300; i++) {
    const text = `${digits(next, 10)}.${digits(next, 1 + Math.floor(next() * 7))} ${digits(next, 16 + Math.floor(next() * 5))} 20${digits(next, 2)}-01-02T03:04:05.${digits(next, 3)}Z`;
    const once = maskText(text);
    assert.equal(maskText(once), once);
    assert.doesNotMatch(once, /\d{10,}/);
  }
});

test("the unmasked-number guard refuses a twelve or thirteen digit number and takes the placeholder", () => {
  assert.doesNotThrow(() => refuseUnmaskedNumbers('{"a":"123456789012-compute"}'));
  assert.throws(() => refuseUnmaskedNumbers('{"a":"592603257418"}'), /twelve or thirteen/);
  assert.throws(() => refuseUnmaskedNumbers('{"a":"5926032574181"}'), /twelve or thirteen/);
  assert.throws(() => refuseUnmaskedNumbers("has 98765 inside", "98765"), /project number/);
});

test("an answer is projected as its error or as its masked body with its shape", () => {
  const err = projectAnswer(
    {
      status: 400,
      json: {
        error: { code: 400, status: "INVALID_ARGUMENT", message: "bad 2026-11-11T00:00:00.5Z" },
      },
    },
    {},
  );
  assert.deepEqual(err, {
    status: 400,
    error: { code: 400, status: "INVALID_ARGUMENT", message: "bad TIME(Z)" },
  });
  const ok = projectAnswer(
    { status: 200, json: { name: "projects/p/tasks/1234567890123456789", n: 1 } },
    {},
  );
  assert.equal(ok.body.name, "projects/p/tasks/ID(19)");
  assert.deepEqual(ok.shape, { name: "string", n: "number" });
  assert.equal(projectAnswer(null, {}), null);
});

test("the shape of a value keeps key order and leaf types", () => {
  assert.deepEqual(shapeOfValue({ b: [1, "x"], a: null, c: { d: true } }), {
    b: ["number", "string"],
    a: "null",
    c: { d: "boolean" },
  });
});

test("headers keep every name sorted, the fixed values and the forms of the others", () => {
  const projected = projectHeaders(
    {
      "x-cloudtasks-queuename": "tqdefab12cd",
      "x-cloudtasks-taskname": "1234567890123456789",
      "x-cloudtasks-tasketa": "1789000000.123456",
      "x-cloudtasks-taskretrycount": "2",
      "content-length": "17",
      "content-type": "application/json",
      b: "x",
    },
    {},
  );
  assert.deepEqual(projected.names, [
    "b",
    "content-length",
    "content-type",
    "x-cloudtasks-queuename",
    "x-cloudtasks-tasketa",
    "x-cloudtasks-taskname",
    "x-cloudtasks-taskretrycount",
  ]);
  assert.deepEqual(projected.fixed, {
    "content-type": "application/json",
    "x-cloudtasks-taskretrycount": "2",
  });
  assert.equal(projected.queueName, "tqdef");
  assert.equal(projected.taskName, "ID(19)");
  assert.equal(projected.eta, "UNIX(f6)");
  assert.equal(projected.contentLength, "present");
});

test("timings are the first start from creation, the gaps, and offsets from the earliest delivery", () => {
  const t = timingsOf(
    [
      {
        startFromCreateMs: 100,
        startMs: 0,
        endMs: 50,
        startedAt: "2026-11-11T00:00:10.000Z",
        endedAt: "2026-11-11T00:00:10.050Z",
      },
      {
        startFromCreateMs: 1100,
        startMs: 1000,
        endMs: 1010,
        startedAt: "2026-11-11T00:00:11.000Z",
        endedAt: "2026-11-11T00:00:11.010Z",
      },
    ],
    Date.parse("2026-11-11T00:00:10.000Z"),
  );
  assert.deepEqual(t, {
    firstMs: 100,
    gapsMs: [1000],
    startsAtMs: [0, 1000],
    endsAtMs: [50, 1010],
    holdMs: [50, 10],
  });
});

test("a digest depends on every byte of the value", () => {
  assert.notEqual(digestOf({ a: 1 }), digestOf({ a: 2 }));
  assert.equal(digestOf({ a: 1 }), digestOf({ a: 1 }));
});

test("a time in a message keeps its zone kind: Z or an offset", () => {
  assert.equal(
    maskText("at 2026-11-11T09:01:37.5-08:00", { messageTimes: true }),
    "at TIME(offset)",
  );
  assert.equal(maskText("at 2026-11-11T09:01:37.5Z", { messageTimes: true }), "at TIME(Z)");
});

test("a header with no value is not a fixed header, and a missing content-length is null", () => {
  const projected = projectHeaders(
    { "content-type": null, "user-agent": "Google-Cloud-Tasks" },
    {},
  );
  assert.deepEqual(projected.fixed, { "user-agent": "Google-Cloud-Tasks" });
  assert.equal(projected.contentLength, null);
  assert.equal(projected.queueName, "");
});

test("a recording's offsets are from its earliest delivery, whichever case it belongs to", () => {
  const delivery = (startedAt) => ({
    startedAt,
    endedAt: startedAt,
    startMs: 0,
    endMs: 0,
    startFromCreateMs: 5,
    retryCount: 0,
    request: { method: "POST", path: "/", headers: {}, bodyLength: 0, bodyText: null },
    context: {
      retryCount: 0,
      executionCount: 0,
      previousResponse: null,
      retryReason: null,
      hasAuth: false,
    },
  });
  const result = {
    judged: {
      cases: {
        a: {
          kind: "create",
          sent: true,
          answer: null,
          deliveries: [delivery("2026-11-11T00:00:12.000Z")],
        },
        b: {
          kind: "create",
          sent: true,
          answer: null,
          deliveries: [delivery("2026-11-11T00:00:10.000Z")],
        },
      },
    },
  };
  const projected = projectRecording({
    result,
    alias: "x",
    corpusSha256: "c",
    projectNumber: null,
  });
  assert.deepEqual(projected.cases.a.timing.startsAtMs, [2000]);
  assert.deepEqual(projected.cases.b.timing.startsAtMs, [0]);
  assert.equal(projected.cases.a.admission, null);
});

test("the body of a FULL view task is decoded and masked as text", () => {
  const body = Buffer.from(
    '{"run":"tqrun-0123456789abcdef","at":"2026-11-11T00:00:00.25Z"}',
  ).toString("base64");
  const answer = projectAnswer(
    { status: 200, json: { name: "n", httpRequest: { body, url: "u" } } },
    {},
  );
  assert.deepEqual(answer.body.httpRequest.body, {
    base64Of: '{"run":"tqrun-RUN","at":"TIME(f2,Z)"}',
  });
  assert.equal(answer.body.httpRequest.url, "u");
});
