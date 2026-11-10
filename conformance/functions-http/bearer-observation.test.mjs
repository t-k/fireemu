import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { forAll, pick, between } from "../src/fs-ent-pipeline/test-support.mjs";
import { CASE_IDS, judgeObservation } from "./bearer-judge.mjs";
import {
  CAPS,
  MAX_ATTEMPTS,
  PROGRAM_ID,
  TASK_ID,
  admit,
  captureFetch,
  recordBearer,
  validateBearerCorpus,
} from "./bearer-observation.mjs";
import { FAKE_RECEIPT_SCRIPT, UPLOAD_OBJECT, deployWorld } from "./production.fake.mjs";

const json = (name) => JSON.parse(readFileSync(new URL(name, import.meta.url), "utf8"));
const CORPUS = json("./bearer-observation.corpus.json");
const BASELINE = json("./bearer-observation.baseline.json");
const SOURCE_PINS_CORPUS = "ee831856d3b54a6d53d6f4081dd872d28023ac3803370661ce6e348a8d0e308f";
const sha = (text) => createHash("sha256").update(text).digest("hex");
const REQUEST_BODY = JSON.stringify({ data: { op: "auth" } });
const PROVISIONAL = BASELINE.provisional.body;

// The echo the fixture answers for the frozen request (fixtures/index.js httpHandler), in its compact layout.
const ECHO = JSON.stringify({
  method: "POST",
  path: "/",
  query: {},
  contentType: "application/json",
  customHeader: null,
  forwardedForPresent: true,
  forwardedForHopCount: 1,
  forwardedProto: "https",
  executionIdPresent: false,
  body: { data: { op: "auth" } },
  rawBodyLength: Buffer.byteLength(REQUEST_BODY),
  rawBodySha256: sha(REQUEST_BODY),
});

function capture(index, answer) {
  const caseId = CASE_IDS[index % 2];
  const text = answer.bodyText ?? "";
  const headers = { ...answer.headers };
  if (answer.contentType !== undefined) headers["content-type"] = answer.contentType;
  return {
    seq: index + 1,
    pass: Math.floor(index / 2) + 1,
    caseId,
    method: "POST",
    path: "/",
    authorization: caseId === "malformed-bearer" ? "Bearer malformed" : null,
    latencyMs: 40,
    status: answer.error ? null : answer.status,
    headers: answer.error ? {} : headers,
    headerNames: Object.keys(headers).toSorted(),
    bodyBytes: answer.error
      ? null
      : "bodyBytes" in answer
        ? answer.bodyBytes
        : Buffer.byteLength(text),
    bodySha256: answer.error ? null : "bodySha256" in answer ? answer.bodySha256 : sha(text),
    bodyText: answer.error ? null : text,
    error: answer.error ?? null,
  };
}

const control = { status: 200, contentType: "application/json; charset=utf-8", bodyText: ECHO };
const provisional = {
  status: 401,
  contentType: "text/html; charset=UTF-8",
  bodyText: PROVISIONAL,
};
const captures = (controlAnswer, malformedAnswer, second = malformedAnswer) => [
  capture(0, controlAnswer),
  capture(1, malformedAnswer),
  capture(2, controlAnswer),
  capture(3, second),
];

// ---- corpus and baseline ----------------------------------------------------------------------

test("the frozen corpus is one program of two cases that differ only in the Authorization header", () => {
  const program = validateBearerCorpus(CORPUS);
  assert.equal(program.id, PROGRAM_ID);
  assert.deepEqual(
    program.cases.map((step) => step.id),
    CASE_IDS,
  );
  const [plain, bearer] = program.cases;
  const { authorization, ...rest } = bearer.request.headers;
  assert.equal(authorization, "Bearer malformed");
  assert.deepEqual({ ...bearer.request, headers: rest }, plain.request);
});

test("a corpus that changes a request, a case or the target is refused", () => {
  const variants = [
    (c) => (c.programs[0].cases[1].request.headers.authorization = "Bearer other"),
    (c) => (c.programs[0].cases[0].request.headers.authorization = "Bearer malformed"),
    (c) => (c.programs[0].cases[0].request.path = "/echo"),
    (c) => (c.programs[0].cases[1].request.method = "GET"),
    (c) => (c.programs[0].cases[1].request.body = { data: { op: "other" } }),
    (c) => (c.programs[0].cases[1].target = "callable"),
    (c) => c.programs[0].cases.push(structuredClone(c.programs[0].cases[0])),
    (c) => (c.programs[0].cases = c.programs[0].cases.toReversed()),
    (c) => (c.programs[0].id = "functions-http/callable/auth-refusal"),
    (c) => c.programs.push(structuredClone(c.programs[0])),
    (c) => (c.project = "fireemu-oracle-sbx"),
    (c) => (c.programs[0].cases[0].capture = "first-chunk-then-abort"),
    (c) => (c.programs[0].cases[0].request.headers["x-fireemu-probe"] = "1"),
  ];
  for (const [index, change] of variants.entries()) {
    const copy = structuredClone(CORPUS);
    change(copy);
    assert.throws(() => validateBearerCorpus(copy), Error, `variant ${index}`);
  }
});

test("the baseline is the stage 3 recorded 401 page: 294 bytes, the committed recording digest", () => {
  assert.equal(BASELINE.provisional.status, 401);
  assert.equal(BASELINE.provisional.contentType, "text/html; charset=UTF-8");
  assert.equal(Buffer.byteLength(PROVISIONAL), 294);
  assert.equal(BASELINE.provisional.bodyBytes, 294);
  assert.equal(sha(PROVISIONAL), BASELINE.provisional.bodySha256);
  const committed = JSON.parse(
    readFileSync(
      new URL(
        "../../spec/compatibility/closure/evidence/FUNCTIONS-HTTP-comparison.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  assert.deepEqual(committed.productionRecordingSha256, [
    BASELINE.source.recordingSha256,
    BASELINE.source.recordingSha256,
  ]);
});

// ---- judge ------------------------------------------------------------------------------------

test("the recorded provisional page on both passes, with the recorded echo control, is the same", () => {
  const result = judgeObservation(captures(control, provisional), BASELINE);
  assert.equal(result.verdict, "same-as-provisional");
  assert.deepEqual(result.differences, []);
  assert.equal(result.needsReview, false);
  assert.equal(result.lockKept, false);
});

test("a malformed Bearer served by the function is different and names every field", () => {
  const result = judgeObservation(captures(control, control), BASELINE);
  assert.equal(result.verdict, "different");
  assert.equal(result.servedByFunction, true);
  assert.deepEqual(
    result.differences.map((d) => d.field),
    ["status", "contentType", "bodyBytes", "bodySha256"],
  );
  assert.deepEqual(result.differences[0], { field: "status", provisional: 401, observed: 200 });
  assert.equal(result.needsReview, true);
  assert.equal(result.lockKept, false);
});

test("a 401 page of another length is different by its bytes, never by its stored text", () => {
  const other = {
    ...provisional,
    bodyText: PROVISIONAL.replace("<code>/</code>", "<code>/x</code>"),
  };
  const result = judgeObservation(captures(control, other), BASELINE);
  assert.equal(result.verdict, "different");
  assert.equal(result.servedByFunction, false);
  assert.deepEqual(
    result.differences.map((d) => d.field),
    ["bodyBytes", "bodySha256"],
  );
  // Same length, other bytes: still different (the digest), never the same.
  const sameLength = { ...provisional, bodyText: PROVISIONAL.replace("Error", "Errar") };
  const near = judgeObservation(captures(control, sameLength), BASELINE);
  assert.equal(near.verdict, "different");
  assert.deepEqual(
    near.differences.map((d) => d.field),
    ["bodySha256"],
  );
});

test("a content-type that differs only in case is different (a mask never hides a format)", () => {
  const lower = { ...provisional, contentType: "text/html; charset=utf-8" };
  const result = judgeObservation(captures(control, lower), BASELINE);
  assert.equal(result.verdict, "different");
  assert.deepEqual(
    result.differences.map((d) => d.field),
    ["contentType"],
  );
});

test("answers that are not complete 2xx or 4xx answers are unknown and keep the lock", () => {
  for (const status of [101, 199, 301, 302, 304, 500, 502, 503, 504]) {
    for (const where of ["control", "malformed"]) {
      const odd = { status, contentType: "text/plain", bodyText: "x" };
      const list = where === "control" ? captures(odd, provisional) : captures(control, odd);
      const result = judgeObservation(list, BASELINE);
      assert.equal(result.verdict, "unknown", `${where} ${status}`);
      assert.equal(result.lockKept, true);
      assert.equal(result.needsReview, true);
      assert.match(result.reasons.join("\n"), new RegExp(`status ${status}`));
    }
  }
  const timeout = judgeObservation(
    captures(control, { error: "AbortError: This operation was aborted" }),
    BASELINE,
  );
  assert.equal(timeout.verdict, "unknown");
  assert.match(timeout.reasons[0], /transport/);
});

test("an unreadable body, a content-length that disagrees and missing captures are unknown", () => {
  const unreadable = { ...provisional, bodyBytes: null, bodySha256: null };
  assert.equal(judgeObservation(captures(control, unreadable), BASELINE).verdict, "unknown");
  const lying = { ...provisional, headers: { "content-length": "295" } };
  const lyingResult = judgeObservation(captures(control, lying), BASELINE);
  assert.equal(lyingResult.verdict, "unknown");
  assert.match(lyingResult.reasons.join("\n"), /content-length/);
  const honest = { ...provisional, headers: { "content-length": "294" } };
  assert.equal(
    judgeObservation(captures(control, honest), BASELINE).verdict,
    "same-as-provisional",
  );
  const all = captures(control, provisional);
  assert.equal(judgeObservation(all.slice(0, 3), BASELINE).verdict, "unknown");
  assert.equal(judgeObservation([], BASELINE).verdict, "unknown");
  assert.equal(judgeObservation([...all, all[0]], BASELINE).verdict, "unknown");
});

test("captures out of order or sent with the wrong credential are unknown", () => {
  const all = captures(control, provisional);
  assert.equal(judgeObservation([all[1], all[0], all[2], all[3]], BASELINE).verdict, "unknown");
  const swapped = structuredClone(all);
  swapped[1].authorization = null;
  assert.equal(judgeObservation(swapped, BASELINE).verdict, "unknown");
  const leaked = structuredClone(all);
  leaked[0].authorization = "Bearer malformed";
  assert.equal(judgeObservation(leaked, BASELINE).verdict, "unknown");
  const renumbered = structuredClone(all);
  renumbered[2].pass = 1;
  assert.equal(judgeObservation(renumbered, BASELINE).verdict, "unknown");
});

test("passes that disagree are unknown, whichever field differs", () => {
  const second = { ...provisional, bodyText: `${PROVISIONAL} ` };
  assert.equal(
    judgeObservation(captures(control, provisional, second), BASELINE).verdict,
    "unknown",
  );
  const otherStatus = { ...provisional, status: 403 };
  assert.equal(
    judgeObservation(captures(control, provisional, otherStatus), BASELINE).verdict,
    "unknown",
  );
  const list = captures(control, provisional);
  list[2] = capture(2, {
    ...control,
    bodyText: ECHO.replace('"forwardedForHopCount":1', '"forwardedForHopCount":2'),
  });
  assert.equal(judgeObservation(list, BASELINE).verdict, "unknown");
});

test("a control that is not the recorded echo shape is unknown, field by field", () => {
  const echo = JSON.parse(ECHO);
  const variants = [
    { ...control, status: 201 },
    { ...control, contentType: "application/json" },
    { ...control, bodyText: "not json" },
    { ...control, bodyText: JSON.stringify({ ...echo, extra: 1 }) },
    { ...control, bodyText: JSON.stringify({ path: echo.path, ...echo }) },
    { ...control, bodyText: JSON.stringify({ ...echo, method: "GET" }) },
    { ...control, bodyText: JSON.stringify({ ...echo, path: "/echo" }) },
    { ...control, bodyText: JSON.stringify({ ...echo, contentType: null }) },
    { ...control, bodyText: JSON.stringify({ ...echo, body: {} }) },
    { ...control, bodyText: JSON.stringify({ ...echo, rawBodyLength: 0 }) },
    { ...control, bodyText: JSON.stringify({ ...echo, rawBodySha256: sha("") }) },
    { ...control, bodyText: JSON.stringify({ ...echo, forwardedForPresent: "yes" }) },
    { ...control, bodyText: JSON.stringify({ ...echo, forwardedForHopCount: "1" }) },
    { ...control, bodyText: JSON.stringify({ ...echo, executionIdPresent: 0 }) },
    { ...control, bodyText: JSON.stringify({ ...echo, query: [] }) },
    { ...control, bodyText: JSON.stringify(echo, null, 2) },
    { ...control, bodyText: "[1]" },
  ];
  for (const [index, variant] of variants.entries()) {
    const result = judgeObservation(captures(variant, provisional), BASELINE);
    assert.equal(result.verdict, "unknown", `variant ${index}`);
    assert.match(result.reasons.join("\n"), /control/, `variant ${index}`);
  }
  // The local fireemu emulator profile answers forwardedProto null and no forwarded hop: a type, not a value.
  const local = JSON.stringify({
    ...echo,
    forwardedForPresent: false,
    forwardedForHopCount: 0,
    forwardedProto: null,
  });
  assert.equal(
    judgeObservation(captures({ ...control, bodyText: local }, provisional), BASELINE).verdict,
    "same-as-provisional",
  );
});

// Every combination of the PICT axes (the PICT table is a subset of these 140 rows), with the verdict
// from an independent rule.
test("every combination of the four judge axes gets the verdict of the stated rule", () => {
  const controls = {
    Echo: control,
    OtherComplete: { ...control, status: 404, contentType: "text/html", bodyText: "nope" },
    Status3xx: { status: 302, contentType: "text/html", bodyText: "" },
    Status5xx: { status: 503, contentType: "text/html", bodyText: "busy" },
    Transport: { error: "TypeError: fetch failed" },
  };
  const malformed = {
    Provisional: provisional,
    Diff401Bytes: { ...provisional, bodyText: `${PROVISIONAL}\n` },
    Served200: control,
    Status403: { status: 403, contentType: "text/html; charset=UTF-8", bodyText: "forbidden" },
    Status5xx: { status: 500, contentType: "text/html", bodyText: "x" },
    Transport: { error: "AbortError" },
    LengthMismatch: { ...provisional, headers: { "content-length": "1" } },
  };
  let rows = 0;
  for (const [c, cAnswer] of Object.entries(controls)) {
    for (const [m, mAnswer] of Object.entries(malformed)) {
      for (const passes of ["Agree", "Disagree"]) {
        for (const count of ["Four", "Three"]) {
          const second =
            passes === "Agree"
              ? mAnswer
              : { status: 418, contentType: "text/plain", bodyText: "t" };
          let list = captures(cAnswer, mAnswer, second);
          if (count === "Three") list = list.slice(0, 3);
          const expected =
            count === "Three" ||
            c !== "Echo" ||
            passes === "Disagree" ||
            ["Status5xx", "Transport", "LengthMismatch"].includes(m)
              ? "unknown"
              : m === "Provisional"
                ? "same-as-provisional"
                : "different";
          assert.equal(
            judgeObservation(list, BASELINE).verdict,
            expected,
            `${c} ${m} ${passes} ${count}`,
          );
          rows += 1;
        }
      }
    }
  }
  assert.equal(rows, 140);
});

test("property: an answer that differs from the provisional page in any field is never the same", () => {
  forAll(
    300,
    (random) => {
      const status = pick(random, [200, 201, 204, 400, 401, 403, 404, 405, 429]);
      const bodyText = random() < 0.3 ? PROVISIONAL : "x".repeat(between(random, 0, 600));
      const contentType = pick(random, [
        "text/html; charset=UTF-8",
        "text/html; charset=utf-8",
        "text/plain",
        "application/json; charset=utf-8",
      ]);
      return { status, bodyText, contentType };
    },
    (answer) => {
      const result = judgeObservation(captures(control, answer), BASELINE);
      const fields = [];
      if (answer.status !== 401) fields.push("status");
      if (answer.contentType !== "text/html; charset=UTF-8") fields.push("contentType");
      if (Buffer.byteLength(answer.bodyText) !== 294) fields.push("bodyBytes");
      if (answer.bodyText !== PROVISIONAL) fields.push("bodySha256");
      assert.equal(result.verdict, fields.length ? "different" : "same-as-provisional");
      assert.deepEqual(
        result.differences.map((d) => d.field),
        fields,
      );
    },
  );
});

test("property: response headers other than content-type and content-length never change the verdict", () => {
  forAll(
    200,
    (random) => {
      const headers = {};
      for (let i = 0; i < between(random, 0, 5); i += 1) {
        headers[
          pick(random, ["www-authenticate", "server", "date", "x-cloud-trace-context", "alt-svc"])
        ] = "v".repeat(between(random, 1, 20));
      }
      return { headers, served: random() < 0.5 };
    },
    ({ headers, served }) => {
      const answer = { ...(served ? control : provisional), headers };
      const result = judgeObservation(captures(control, answer), BASELINE);
      assert.equal(result.verdict, served ? "different" : "same-as-provisional");
      assert.deepEqual(result.headersNotInBaseline, Object.keys(headers).toSorted());
    },
  );
});

test("property: any capture that failed in transport or answered outside 2xx/4xx makes the verdict unknown", () => {
  forAll(
    300,
    (random) => {
      const index = between(random, 0, 3);
      const status = pick(random, [
        100,
        102,
        300,
        301,
        307,
        308,
        500,
        501,
        502,
        503,
        504,
        599,
        null,
      ]);
      return { index, status };
    },
    ({ index, status }) => {
      const list = captures(control, provisional);
      list[index] = capture(
        index,
        status === null
          ? { error: "TypeError: fetch failed" }
          : { status, contentType: "text/plain", bodyText: "b" },
      );
      const result = judgeObservation(list, BASELINE);
      assert.equal(result.verdict, "unknown");
      assert.equal(result.lockKept, true);
    },
  );
});

// ---- capture ------------------------------------------------------------------------------------

test("the capture keeps the status, the selected headers, the byte count and digest, never the host or a token", async () => {
  const seen = [];
  const fetchImpl = async (url, init) => {
    seen.push({ url, init });
    return new Response(PROVISIONAL, {
      status: 401,
      headers: {
        "content-type": "text/html; charset=UTF-8",
        "content-length": "294",
        "www-authenticate": "Bearer error=x",
        date: "Mon, 10 Nov 2026 00:00:00 GMT",
      },
    });
  };
  const records = [];
  const wrapped = captureFetch({ fetchImpl, onCapture: (c) => records.push(c), now: () => 1000 });
  const response = await wrapped("https://fireemuhttpprobe-abc-uc.a.run.app/", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: "Bearer malformed" },
    body: REQUEST_BODY,
    redirect: "manual",
  });
  assert.equal(response.status, 401);
  assert.equal(await response.text(), PROVISIONAL, "the session still reads the same bytes");
  assert.equal(seen[0].init.redirect, "manual");
  const [record] = records;
  assert.equal(
    record.caseId,
    "no-authorization",
    "by order: the first capture is the control case",
  );
  assert.equal(record.authorization, "Bearer malformed");
  assert.equal(record.bodyBytes, 294);
  assert.equal(record.bodySha256, BASELINE.provisional.bodySha256);
  assert.equal(record.bodyText, PROVISIONAL);
  assert.equal(record.path, "/");
  assert.deepEqual(record.headers, {
    "content-type": "text/html; charset=UTF-8",
    "content-length": "294",
    "www-authenticate": "Bearer error=x",
  });
  assert.deepEqual(record.headerNames, [
    "content-length",
    "content-type",
    "date",
    "www-authenticate",
  ]);
  assert.ok(!JSON.stringify(record).includes("run.app"));
});

test("the capture records a transport failure and rethrows it; an oversized body is unreadable", async () => {
  const records = [];
  const failing = captureFetch({
    fetchImpl: async () => {
      throw new TypeError("fetch failed");
    },
    onCapture: (c) => records.push(c),
  });
  await assert.rejects(
    failing("http://127.0.0.1:1/", { method: "POST", headers: {} }),
    /fetch failed/,
  );
  assert.equal(records[0].status, null);
  assert.match(records[0].error, /TypeError: fetch failed/);
  const big = captureFetch({
    fetchImpl: async () => new Response("x".repeat(70 * 1024), { status: 200 }),
    onCapture: (c) => records.push(c),
  });
  await assert.rejects(big("http://127.0.0.1:1/", { method: "POST", headers: {} }), /64 KiB/);
  assert.equal(records[1].status, 200);
  assert.equal(records[1].bodyBytes, null);
  assert.match(records[1].error, /64 KiB/);
});

test("the capture passes a 3xx and a 204 through without following or failing", async () => {
  const records = [];
  const wrapped = captureFetch({
    fetchImpl: async (url) =>
      url.endsWith("/a")
        ? new Response("moved", { status: 302, headers: { location: "https://elsewhere/" } })
        : new Response(null, { status: 204 }),
    onCapture: (c) => records.push(c),
  });
  assert.equal(
    (await wrapped("http://127.0.0.1:1/a", { method: "POST", headers: {} })).status,
    302,
  );
  assert.equal(
    (await wrapped("http://127.0.0.1:1/b", { method: "POST", headers: {} })).status,
    204,
  );
  assert.deepEqual(
    records.map((r) => [r.status, r.bodyBytes]),
    [
      [302, 5],
      [204, 0],
    ],
  );
});

// ---- admission ----------------------------------------------------------------------------------

const T0 = Date.parse("2026-11-10T12:00:00Z");
const row = (fields) => JSON.stringify({ project: "fireemu-oracle-query", ...fields });
const closed = row({
  task: "RTDB-2350",
  event: "observation-complete-cleanup-verified",
  recordedAt: "2026-11-10T11:00:00Z",
});

test("admission: a closed last row an hour old admits attempt 1", () => {
  assert.deepEqual(admit({ ledgerText: `${closed}\n`, now: T0, env: {} }), { attempt: 1 });
});

test("admission: a last row younger than 30 minutes waits unless the coordinator is the only sender", () => {
  const young = row({ event: "cleanup-verified", ts: "2026-11-10T11:45:00Z" });
  assert.throws(() => admit({ ledgerText: young, now: T0, env: {} }), /30 minutes/);
  assert.deepEqual(
    admit({ ledgerText: young, now: T0, env: { FIREEMU_BEARER_SOLE_SENDER: "1" } }),
    {
      attempt: 1,
    },
  );
  assert.throws(
    () => admit({ ledgerText: young, now: T0, env: { FIREEMU_BEARER_SOLE_SENDER: "yes" } }),
    /30 minutes/,
  );
  const exactly = row({ event: "cleanup-verified", ts: "2026-11-10T11:30:00Z" });
  assert.deepEqual(admit({ ledgerText: exactly, now: T0, env: {} }), { attempt: 1 });
});

test("admission: an open or unrecognised last row for the project refuses", () => {
  for (const open of [
    { event: "started", ts: "2026-11-10T10:00:00Z" },
    { event: "needs-recovery", ts: "2026-11-10T10:00:00Z" },
    { outcome: "needs-recovery", ts: "2026-11-10T10:00:00Z" },
    { event: "campaign-reservation-booked", recordedAt: "2026-11-10T10:00:00Z" },
    { outcome: "stopped-needs-review", ts: "2026-11-10T10:00:00Z" },
    { event: "finished", outcome: "observed-unknown", ts: "2026-11-10T10:00:00Z" },
    { event: "change", ts: "2026-11-10T10:00:00Z" },
    { event: "cleanup-verified" },
  ]) {
    assert.throws(
      () => admit({ ledgerText: `${closed}\n${row(open)}\n`, now: T0, env: {} }),
      /last row|time/,
      JSON.stringify(open),
    );
  }
  // Rows of other projects do not count.
  const other = JSON.stringify({
    project: "fireemu-oracle-idp",
    event: "started",
    ts: "2026-11-10T11:59:00Z",
  });
  assert.deepEqual(admit({ ledgerText: `${closed}\n${other}\n`, now: T0, env: {} }), {
    attempt: 1,
  });
  assert.throws(() => admit({ ledgerText: "", now: T0, env: {} }), /no ledger row/);
});

test("admission: own attempts are counted and a fourth is refused", () => {
  const own = (n) =>
    [
      row({ taskId: TASK_ID, event: "started", ts: `2026-11-10T0${n}:00:00Z` }),
      row({
        taskId: TASK_ID,
        event: "finished",
        outcome: "recorded",
        ts: `2026-11-10T0${n}:10:00Z`,
      }),
    ].join("\n");
  assert.deepEqual(admit({ ledgerText: `${own(1)}\n${closed}`, now: T0, env: {} }), { attempt: 2 });
  assert.deepEqual(admit({ ledgerText: `${own(1)}\n${own(2)}\n${closed}`, now: T0, env: {} }), {
    attempt: 3,
  });
  assert.equal(MAX_ATTEMPTS, 3);
  assert.throws(
    () => admit({ ledgerText: `${own(1)}\n${own(2)}\n${own(3)}\n${closed}`, now: T0, env: {} }),
    /attempt 4/,
  );
  // An own started row without an own terminal row is an attempt that needs recovery first.
  const dangling = row({ taskId: TASK_ID, event: "started", ts: "2026-11-10T01:00:00Z" });
  assert.throws(
    () => admit({ ledgerText: `${dangling}\n${closed}`, now: T0, env: {} }),
    /no terminal/,
  );
});

// ---- orchestration in the fake world ----------------------------------------------------------

const CLOUDBUILD =
  "https://cloudbuild.googleapis.com/v1/projects/fireemu-oracle-query/locations/us-central1/builds?pageSize=10";

async function fakeRun({
  deployScript = FAKE_RECEIPT_SCRIPT("process.exit(0);", 200),
  answer = provisional,
  builds,
  failFetch = false,
  ledgerText = `${closed}\n`,
  deleteFails = false,
  tweak = () => {},
} = {}) {
  const world = await deployWorld({ deployScript, caps: CAPS });
  const ledger = [];
  const files = {};
  const requests = [];
  let deleteSent = 0;
  const restControl = async (method, url, body, kind = "control", allowed = [200]) => {
    requests.push(`${method} ${url}`);
    if (url === CLOUDBUILD) {
      world.budget.take(kind);
      return {
        status: 200,
        value: {
          builds: builds ?? [
            {
              id: "b1",
              status: "SUCCESS",
              createTime: "2026-11-10T12:00:30Z",
              finishTime: "2026-11-10T12:01:10Z",
            },
            { id: "old", status: "WORKING", createTime: "2026-11-09T12:00:30Z" },
          ],
        },
        bytes: 10,
      };
    }
    if (
      url.startsWith(
        "https://cloudresourcemanager.googleapis.com/v3/projects/123456789012:getIamPolicy",
      )
    ) {
      world.budget.take(kind);
      return { status: 200, value: { bindings: [] }, bytes: 10 };
    }
    return world.control(method, url, body, kind, allowed);
  };
  const run = async (args, adc, budget, kind, runDir, track) => {
    if (kind === "cliDelete") {
      deleteSent += 1;
      if (deleteFails) {
        budget.take("cliDelete");
        throw new Error("cliDelete failed or attempted API enablement (exit 1)");
      }
    }
    return world.run(args, adc, budget, kind, runDir, track);
  };
  const fetchImpl = async (url, init) => {
    if (failFetch) throw new TypeError("fetch failed");
    const authorized = init.headers.authorization === "Bearer malformed";
    const chosen = authorized ? answer : control;
    return new Response(chosen.bodyText, {
      status: chosen.status,
      headers: { "content-type": chosen.contentType },
    });
  };
  let clock = Date.parse("2026-11-10T12:00:00Z");
  const deps = {
    now: () => (clock += 1000),
    assertCleanTree: async () => {},
    gitSha: async () => "a".repeat(40),
    readSources: async () => ({ corpus: CORPUS, baseline: BASELINE, digests: { corpus: "c" } }),
    readLedger: async () => ledgerText,
    appendLedger: async (text) => ledger.push(JSON.parse(text)),
    ownerAdc: async () => ({ path: "/adc", file: { refresh_token: "REFRESH-SECRET" } }),
    projectNumber: async () => "123456789012",
    makeRunDir: async () => join(world.dir, "run"),
    writeRunFile: async (dir, name, text) => {
      files[name] = text;
    },
    createBudget: () => world.budget,
    createControl: () => restControl,
    openUploads: () => world.uploads,
    run,
    fetchImpl,
    installSignals: () => {},
    log: () => {},
    warn: () => {},
  };
  tweak(world, deps);
  const result = await recordBearer({}, deps);
  return { world, result, ledger, files, requests, deleteSent: () => deleteSent };
}

test("fake world: the whole path records twice, cleans up, writes two ledger lines and judges by content", async () => {
  const { world, result, ledger, files, requests } = await fakeRun();
  try {
    assert.equal(result.verdict, "same-as-provisional", files["judgement.json"]);
    assert.equal(result.outcome, "recorded", ledger[1]?.reason);
    assert.equal(result.exitCode, 0);
    assert.deepEqual(
      ledger.map((line) => [line.event, line.taskId, line.project]),
      [
        ["started", TASK_ID, "fireemu-oracle-query"],
        ["finished", TASK_ID, "fireemu-oracle-query"],
      ],
    );
    const [started, terminal] = ledger;
    assert.equal(started.attempt, 1);
    assert.equal(terminal.outcome, "recorded");
    assert.equal(terminal.closureReady, true);
    assert.equal(terminal.verdict, "same-as-provisional");
    assert.equal(terminal.requests.invocation, 4);
    assert.equal(terminal.requests.cliDeploy, 1);
    assert.equal(terminal.requests.cliDelete, 1);
    assert.equal(terminal.estimatedUsd, 0.57);
    assert.equal(terminal.reservedUsd, 1);
    for (const [kind, cap] of Object.entries(CAPS)) {
      assert.ok(terminal.requests[kind] <= cap, `${kind} ${terminal.requests[kind]} <= ${cap}`);
    }
    const recorded = JSON.parse(files["captures.json"]);
    assert.deepEqual(
      recorded.map((c) => [c.pass, c.caseId, c.status, c.bodyBytes]),
      [
        [1, "no-authorization", 200, Buffer.byteLength(ECHO)],
        [1, "malformed-bearer", 401, 294],
        [2, "no-authorization", 200, Buffer.byteLength(ECHO)],
        [2, "malformed-bearer", 401, 294],
      ],
    );
    assert.equal(JSON.parse(files["judgement.json"]).verdict, "same-as-provisional");
    assert.deepEqual(
      JSON.parse(files["builds.json"]).builds.map((b) => b.id),
      ["b1"],
      "only builds created during the run are read",
    );
    const changes = new Set(
      files["changes.jsonl"]
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line).action),
    );
    assert.ok(changes.has("function-deployed") && changes.has("function-deleted"));
    assert.ok(changes.has("source-upload-deleted") && changes.has("public-invoker-revoked"));
    assert.ok(!world.gcs.objects.has(UPLOAD_OBJECT));
    assert.deepEqual(world.argv[0], [
      "deploy",
      "--only",
      "functions:functions-http-oracle:fireemuHttpProbe",
    ]);
    assert.ok(requests.includes(`GET ${CLOUDBUILD}`));
    for (const text of Object.values(files)) {
      assert.ok(!text.includes("123456789012") && !text.includes("REFRESH-SECRET"));
    }
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("fake world: a production answer that differs is recorded as different, not refused", async () => {
  const { world, result, ledger } = await fakeRun({ answer: control });
  try {
    assert.equal(result.outcome, "recorded");
    assert.equal(result.verdict, "different");
    assert.equal(ledger[1].needsReview, true);
    assert.equal(ledger[1].closureReady, true);
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("fake world: an invocation transport failure is an unknown answer, cleaned, and the lock is kept", async () => {
  const { world, result, ledger } = await fakeRun({ failFetch: true });
  try {
    assert.equal(result.verdict, "unknown");
    assert.equal(result.outcome, "observed-unknown");
    assert.equal(result.exitCode, 1);
    assert.equal(ledger[1].event, "finished");
    assert.equal(ledger[1].lockKept, true);
    assert.equal(ledger[1].requests.cliDelete, 1, "the function was still deleted");
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("fake world: a failed deploy (unknown create) needs recovery even when every read shows 404", async () => {
  const { world, result, ledger, deleteSent } = await fakeRun({
    deployScript: FAKE_RECEIPT_SCRIPT('console.error("Error: Failed"); process.exit(1);', 200),
  });
  try {
    assert.equal(result.outcome, "needs-recovery");
    assert.equal(ledger[1].event, "needs-recovery");
    assert.equal(ledger[1].closureReady, false);
    assert.equal(deleteSent(), 0, "nothing to delete was read, and a 404 settles nothing");
    assert.match(ledger[1].reason, /A2|review/);
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("fake world: a CLI delete that fails is never re-sent and needs recovery", async () => {
  const { world, result, ledger, deleteSent } = await fakeRun({ deleteFails: true });
  try {
    assert.equal(result.outcome, "needs-recovery");
    assert.equal(deleteSent(), 1);
    assert.equal(ledger[1].closureReady, false);
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("fake world: a confirmed create that later reads 404 without our delete is left for A2", async () => {
  // The deploy CLI exits 0 but the function never reads back (read-after-write lag).
  const lag = await deployWorld({
    deployScript: FAKE_RECEIPT_SCRIPT("process.exit(0);", 200),
    caps: CAPS,
  });
  try {
    const ledgerLines = [];
    const baseRun = lag.run;
    const deps = {
      now: () => Date.parse("2026-11-10T12:00:00Z"),
      assertCleanTree: async () => {},
      gitSha: async () => "a".repeat(40),
      readSources: async () => ({ corpus: CORPUS, baseline: BASELINE, digests: {} }),
      readLedger: async () => closed,
      appendLedger: async (text) => ledgerLines.push(JSON.parse(text)),
      ownerAdc: async () => ({ path: "/adc", file: {} }),
      projectNumber: async () => "123456789012",
      makeRunDir: async () => join(lag.dir, "run"),
      writeRunFile: async () => {},
      createBudget: () => lag.budget,
      createControl: () => async (method, url, body, kind, allowed) => {
        if (url.includes("cloudbuild") || url.includes("cloudresourcemanager")) {
          lag.budget.take(kind ?? "control");
          return { status: 200, value: {}, bytes: 2 };
        }
        return lag.control(method, url, body, kind, allowed);
      },
      openUploads: () => lag.uploads,
      run: async (args, adc, budget, kind, runDir, track) => {
        const out = await baseRun(args, adc, budget, kind, runDir, track);
        if (kind === "cliDeploy") lag.deployed.present = false;
        return out;
      },
      fetchImpl: async () => new Response("x"),
      installSignals: () => {},
      log: () => {},
      warn: () => {},
    };
    const lagged = await recordBearer({}, deps);
    assert.equal(lagged.outcome, "needs-recovery");
    assert.equal(ledgerLines[1].closureReady, false);
    assert.match(ledgerLines[1].reason, /A2/);
  } finally {
    await rm(lag.dir, { recursive: true, force: true });
  }
});

test("fake world: a build still running after cleanup keeps the run open", async () => {
  const { world, result, ledger } = await fakeRun({
    builds: [{ id: "b1", status: "WORKING", createTime: "2026-11-10T12:00:30Z" }],
  });
  try {
    assert.equal(result.outcome, "needs-recovery");
    assert.match(ledger[1].reason, /build/);
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("fake world: admission refuses before any request and writes no ledger line", async () => {
  const world = await deployWorld({ deployScript: "", caps: CAPS });
  try {
    const appended = [];
    let controlMade = false;
    await assert.rejects(
      recordBearer(
        {},
        {
          now: () => T0,
          assertCleanTree: async () => {},
          gitSha: async () => "a".repeat(40),
          readSources: async () => ({ corpus: CORPUS, baseline: BASELINE, digests: {} }),
          readLedger: async () => row({ event: "started", ts: "2026-11-10T11:00:00Z" }),
          appendLedger: async (text) => appended.push(text),
          ownerAdc: async () => ({ path: "/adc", file: {} }),
          createControl: () => {
            controlMade = true;
          },
        },
      ),
      /last row/,
    );
    assert.deepEqual(appended, []);
    assert.equal(controlMade, false);
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("source pins: the corpus, fixture, firebase.json and fixture package files are the reviewed bytes", async () => {
  const { SOURCE_PINS } = await import("./bearer-observation.mjs");
  for (const [file, expected] of Object.entries(SOURCE_PINS)) {
    assert.equal(sha(await readFile(new URL(`./${file}`, import.meta.url))), expected, file);
  }
  assert.deepEqual(Object.keys(SOURCE_PINS).toSorted(), [
    "bearer-observation.baseline.json",
    "bearer-observation.corpus.json",
    "firebase.json",
    "fixtures/index.js",
    "fixtures/package-lock.json",
    "fixtures/package.json",
  ]);
});

// ---- near misses added after mutation pass 2 ------------------------------------------------------

test("a capture relabelled to the other case, or a body digest or byte count missing alone, is unknown", () => {
  const relabelled = captures(control, provisional);
  relabelled[0] = { ...relabelled[0], caseId: "malformed-bearer" };
  assert.equal(judgeObservation(relabelled, BASELINE).verdict, "unknown");
  const noBytes = { ...provisional, bodyBytes: null };
  assert.equal(judgeObservation(captures(control, noBytes), BASELINE).verdict, "unknown");
  const noDigest = { ...provisional, bodySha256: null };
  assert.equal(judgeObservation(captures(control, noDigest), BASELINE).verdict, "unknown");
  const shortDigest = { ...provisional, bodySha256: "ab" };
  assert.equal(judgeObservation(captures(control, shortDigest), BASELINE).verdict, "unknown");
});

test("six captures with a well-labelled third pass are still unknown", () => {
  const list = captures(control, provisional);
  const extra = [
    { ...list[0], seq: 5, pass: 3 },
    { ...list[1], seq: 6, pass: 3 },
  ];
  assert.equal(judgeObservation([...list, ...extra], BASELINE).verdict, "unknown");
});

test("a control body that is not JSON or not an object says so", () => {
  const notJson = judgeObservation(
    captures({ ...control, bodyText: "not json" }, provisional),
    BASELINE,
  );
  assert.match(notJson.reasons[0], /body is not JSON/);
  const array = judgeObservation(captures({ ...control, bodyText: "[1]" }, provisional), BASELINE);
  assert.match(array.reasons[0], /body is not an object/);
});

test("a 200 answer with another body is not taken for the function's own echo", () => {
  const other = {
    ...control,
    bodyText: ECHO.replace('"forwardedForHopCount":1', '"forwardedForHopCount":3'),
  };
  const result = judgeObservation(captures(control, other), BASELINE);
  assert.equal(result.verdict, "different");
  assert.equal(result.servedByFunction, false);
});

test("content-type and content-length are compared, so they are not listed as unrecorded headers", () => {
  const list = captures(control, {
    ...provisional,
    headers: { "content-length": "294", server: "x" },
  });
  assert.deepEqual(judgeObservation(list, BASELINE).headersNotInBaseline, ["server"]);
});

test("a corpus request with an extra field is refused", () => {
  const copy = structuredClone(CORPUS);
  copy.programs[0].cases[0].request.query = { a: "1" };
  assert.throws(() => validateBearerCorpus(copy), /request/);
});

test("the capture strips a local route prefix so local and production paths read alike", async () => {
  const records = [];
  const wrapped = captureFetch({
    fetchImpl: async () => new Response("x", { status: 200 }),
    onCapture: (c) => records.push(c),
  });
  await wrapped("http://127.0.0.1:9/demo-functions-http/us-central1/fireemuHttpProbe/", {
    method: "POST",
    headers: {},
  });
  assert.equal(records[0].path, "/");
});

test("admission: a needs-recovery event is open even when it carries a closing outcome", () => {
  const odd = row({ event: "needs-recovery", outcome: "recorded", ts: "2026-11-10T10:00:00Z" });
  assert.throws(() => admit({ ledgerText: odd, now: T0, env: {} }), /last row/);
});

test("the caps of one attempt are the counted bounds of one deploy", () => {
  assert.deepEqual(CAPS, {
    invocation: 4,
    control: 19,
    cleanup: 37,
    auth: 0,
    cliDeploy: 1,
    cliDelete: 1,
    token: 3,
    upload: 15,
  });
});

test("fake world: a dirty tree refuses before the ledger is read", async () => {
  let read = false;
  await assert.rejects(
    recordBearer(
      {},
      {
        assertCleanTree: async () => {
          throw new Error("the worktree is not clean");
        },
        readSources: async () => {
          read = true;
          return {};
        },
      },
    ),
    /not clean/,
  );
  assert.equal(read, false);
});

test("fake world: an open source upload ledger keeps the run open even when observation ended cleanly", async () => {
  const { world, result, ledger } = await fakeRun({
    tweak: (w, deps) => {
      const report = w.uploads.report.bind(w.uploads);
      let calls = 0;
      deps.openUploads = () => ({
        ...w.uploads,
        beginDeploy: (...args) => w.uploads.beginDeploy(...args),
        report: () => {
          calls += 1;
          return calls === 1 ? { closureReady: false, reasons: ["deploy:x"] } : report();
        },
        close: () => w.uploads.close?.(),
      });
    },
  });
  try {
    assert.equal(result.outcome, "needs-recovery");
    assert.equal(ledger[1].closureReady, false);
    assert.equal(ledger[1].reason, "source upload ledger is not closed");
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("fake world: an image version delete that fails after our own function delete needs recovery", async () => {
  const { world, result, ledger } = await fakeRun({
    tweak: (w) => {
      w.deployed.versionDeleteStatus = 500;
    },
  });
  try {
    assert.equal(result.outcome, "needs-recovery");
    assert.equal(ledger[1].closureReady, false);
    assert.match(ledger[1].reason, /cleanup requires review/);
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("fake world: an answer carrying the project number is not written and the run needs review", async () => {
  const leaking = { ...provisional, bodyText: `${PROVISIONAL}123456789012` };
  const { world, result, ledger, files } = await fakeRun({ answer: leaking });
  try {
    assert.equal(files["captures.json"], undefined);
    assert.equal(result.exitCode, 1);
    assert.equal(ledger[1].needsReview, true);
    assert.equal(ledger[1].lockKept, true);
    assert.match(ledger[1].reason, /private value/);
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("fake world: more builds than deploys since the start keeps the run open", async () => {
  const { world, result, ledger } = await fakeRun({
    builds: [
      { id: "b1", status: "SUCCESS", createTime: "2026-11-10T12:00:30Z" },
      { id: "b2", status: "SUCCESS", createTime: "2026-11-10T12:00:40Z" },
    ],
  });
  try {
    assert.equal(result.outcome, "needs-recovery");
    assert.match(ledger[1].reason, /more builds/);
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

// ---- the production recording (FUNCTIONS-HTTP-BEARER-20261110-01) ------------------------------

const RECORDED = JSON.parse(
  readFileSync(new URL("../functions-http-bearer-production.json", import.meta.url), "utf8"),
);

test("replay: the recorded production answers are judged different, served by the function", () => {
  const result = judgeObservation(RECORDED.captures, BASELINE);
  assert.equal(result.verdict, "different");
  assert.equal(result.servedByFunction, true);
  assert.deepEqual(result, RECORDED.judgement, "the judge reads the recording as the run did");
  assert.deepEqual(
    result.differences.map((d) => [d.field, d.observed]),
    [
      ["status", 200],
      ["contentType", "application/json; charset=utf-8"],
      ["bodyBytes", 328],
      ["bodySha256", "288da076ec757b37d34dc97ae87c6d52a15ae1ed4d5367c229f5e8f51532465a"],
    ],
  );
});

test("replay: every recorded answer is the fixture's echo, its bytes match content-length and its digest", () => {
  for (const answer of RECORDED.captures) {
    assert.equal(answer.status, 200);
    assert.equal(Number(answer.headers["content-length"]), answer.bodyBytes);
    assert.equal(Buffer.byteLength(answer.bodyText), answer.bodyBytes);
    assert.equal(sha(answer.bodyText), answer.bodySha256);
    assert.equal(answer.error, null);
  }
  // The malformed Bearer reached the function: its answer is byte-equal to the control's.
  assert.equal(RECORDED.captures[1].bodySha256, RECORDED.captures[0].bodySha256);
  assert.deepEqual(
    RECORDED.captures.map((c) => c.authorization),
    [null, "Bearer malformed", null, "Bearer malformed"],
  );
});

test("replay: a recorded answer changed in any compared field is no longer the recorded verdict", () => {
  const changed = structuredClone(RECORDED.captures);
  changed[3].bodySha256 = sha("other");
  assert.equal(judgeObservation(changed, BASELINE).verdict, "unknown", "passes disagree");
  const same = structuredClone(RECORDED.captures);
  for (const index of [1, 3]) {
    Object.assign(same[index], {
      status: 401,
      headers: { "content-type": "text/html; charset=UTF-8" },
      bodyBytes: 294,
      bodySha256: BASELINE.provisional.bodySha256,
      bodyText: PROVISIONAL,
    });
  }
  assert.equal(judgeObservation(same, BASELINE).verdict, "same-as-provisional");
});

test("the recording names no project, number or bucket", () => {
  const text = readFileSync(
    new URL("../functions-http-bearer-production.json", import.meta.url),
    "utf8",
  );
  for (const forbidden of [
    "fireemu-oracle",
    "gcf-v2-uploads",
    "appspot",
    "run.app",
    ["", "Users", ""].join("/"),
  ]) {
    assert.ok(!text.includes(forbidden), forbidden);
  }
  assert.equal(RECORDED.corpusDigest, SOURCE_PINS_CORPUS);
});

// ---- the real write path (presend review S3) -------------------------------------------------------

test("productionDeps writes run files and ledger lines of production size byte-equal, and never overwrites", async () => {
  const { productionDeps } = await import("./bearer-observation.mjs");
  const root = await mkdtemp(join(tmpdir(), "bearer-write-"));
  try {
    const ledger = join(root, "sandbox-ledger.jsonl");
    const deps = productionDeps({ ledger, privateRoot: root });
    await mkdir(join(root, "runs"));
    const runDir = await deps.makeRunDir("onrequest-bearer-obs-test");
    assert.equal(runDir, join(root, "runs", "onrequest-bearer-obs-test"));
    await assert.rejects(deps.makeRunDir("onrequest-bearer-obs-test"), /EEXIST/);
    const capturesText = `${JSON.stringify(RECORDED.captures, null, 2)}\n`;
    const judgement = `${JSON.stringify(RECORDED.judgement, null, 2)}\n`;
    assert.ok(Buffer.byteLength(capturesText) > 3500, "production-sized");
    await deps.writeRunFile(runDir, "captures.json", capturesText);
    await deps.writeRunFile(runDir, "judgement.json", judgement);
    assert.equal(await readFile(join(runDir, "captures.json"), "utf8"), capturesText);
    assert.equal(await readFile(join(runDir, "judgement.json"), "utf8"), judgement);
    assert.equal((await stat(join(runDir, "captures.json"))).mode & 0o777, 0o600);
    await assert.rejects(deps.writeRunFile(runDir, "captures.json", "x"), /EEXIST/);
    assert.equal(await readFile(join(runDir, "captures.json"), "utf8"), capturesText);
    const started = `${JSON.stringify({ event: "started", taskId: TASK_ID, captures: RECORDED.captures })}\n`;
    const terminal = `${JSON.stringify({ event: "finished", taskId: TASK_ID, ...RECORDED.judgement, requests: RECORDED.requests })}\n`;
    await writeFile(ledger, '{"existing":1}\n');
    await deps.appendLedger(started);
    await deps.appendLedger(terminal);
    assert.equal(await readFile(ledger, "utf8"), `{"existing":1}\n${started}${terminal}`);
    assert.equal(await deps.readLedger(), `{"existing":1}\n${started}${terminal}`);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
