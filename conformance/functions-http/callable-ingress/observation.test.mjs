import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { forAll, pick, between } from "../../src/fs-ent-pipeline/test-support.mjs";
import { CASES, CASE_IDS, judgeObservation } from "./judge.mjs";
import {
  CAPS,
  MAX_ATTEMPTS,
  PROGRAM_ID,
  TASK_ID,
  VARIANTS,
  captureHeaders,
  ingressSpec,
  makeCliRunner,
  productionDeps,
  recordCallableIngress,
  sourcePins,
  validateIngressCorpus,
} from "./observation.mjs";
import { admit, captureFetch } from "../bearer-observation.mjs";
import { FAKE_RECEIPT_SCRIPT, UPLOAD_OBJECT, deployWorld } from "../production.fake.mjs";
import { createBudget } from "../harness.mjs";

const here = (name) => new URL(name, import.meta.url);
const json = (name) => JSON.parse(readFileSync(here(name), "utf8"));
const CORPUS = json("./corpus.json");
const BASELINE = {
  frontEndPage: json("../bearer-observation.baseline.json").provisional,
  ...json("./baseline.json"),
};
const sha = (text) => createHash("sha256").update(text).digest("hex");
const PAGE = BASELINE.frontEndPage.body;
// What the callable wrapper sends for a request without Authorization (stage 3 auth-context#no-authorization).
const CONTROL_BODY = '{"result":{"auth":null}}';
// What the SDK's callable wrapper throws for a credential it rejects (HttpsError unauthenticated), as
// firebase-functions 7.3.2 serializes it. Used only as a made-up "other" answer in these tests: the
// production answer is what the observation records.
const WRAPPER_BODY = '{"error":{"message":"Unauthenticated","status":"UNAUTHENTICATED"}}';

const control = {
  status: 200,
  contentType: "application/json; charset=utf-8",
  bodyText: CONTROL_BODY,
};
const page = { status: 401, contentType: "text/html; charset=UTF-8", bodyText: PAGE };
const wrapper = {
  status: 401,
  contentType: "application/json; charset=utf-8",
  bodyText: WRAPPER_BODY,
};

function capture(index, answer) {
  const per = CASE_IDS.length;
  const text = answer.bodyText ?? "";
  const headers = { ...answer.headers };
  if (answer.contentType !== undefined) headers["content-type"] = answer.contentType;
  const step = CASES[index % per];
  return {
    seq: index + 1,
    pass: Math.floor(index / per) + 1,
    caseId: step.id,
    method: "POST",
    path: "/",
    authorization: step.authorization,
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

/** Both passes: `answers` maps a case id to its answer; every other case answers `control`/`page` as given. */
const passes = (answers, fallback = control) =>
  [0, 1].flatMap((pass) =>
    CASES.map((step, i) =>
      capture(pass * CASES.length + i, step.id in answers ? answers[step.id] : fallback),
    ),
  );
// A full run where only the control answers as the function does and every credential case gets `refusal`.
const allRefused = (refusal) =>
  passes(Object.fromEntries(CASE_IDS.slice(1).map((id) => [id, refusal])));

// ---- corpus -------------------------------------------------------------------------------------

test("the frozen corpus is one program of six cases that differ only in the Authorization header", () => {
  const program = validateIngressCorpus(CORPUS);
  assert.equal(program.id, PROGRAM_ID);
  assert.deepEqual(
    program.cases.map((step) => step.id),
    CASE_IDS,
  );
  const [plain, ...others] = program.cases;
  assert.equal(plain.request.headers.authorization, undefined);
  for (const [index, step] of others.entries()) {
    const { authorization, ...rest } = step.request.headers;
    assert.equal(authorization, CASES[index + 1].authorization);
    assert.deepEqual({ ...step.request, headers: rest }, plain.request);
  }
});

test("the six credentials are the shapes the strict callable check branches on", () => {
  assert.deepEqual(CASES, [
    { id: "no-authorization", authorization: null },
    { id: "malformed-bearer", authorization: "Bearer malformed" },
    { id: "lowercase-scheme", authorization: "bearer malformed" },
    { id: "bare-scheme", authorization: "Bearer" },
    { id: "basic-scheme", authorization: "Basic dXNlcjpwYXNz" },
    {
      id: "unsigned-jwt",
      authorization: "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4In0.c2ln",
    },
  ]);
  // The unsigned JWT is three base64url parts: a header and a payload that decode, a signature that is no signature.
  const [header, payload, signature] = CASES[5].authorization.slice("Bearer ".length).split(".");
  assert.deepEqual(JSON.parse(Buffer.from(header, "base64url")), { alg: "RS256", typ: "JWT" });
  assert.deepEqual(JSON.parse(Buffer.from(payload, "base64url")), { sub: "x" });
  assert.equal(Buffer.from(signature, "base64url").toString(), "sig");
});

test("a corpus that changes a request, a case, the order or the target is refused", () => {
  const variants = [
    (c) => (c.programs[0].cases[1].request.headers.authorization = "Bearer other"),
    (c) => (c.programs[0].cases[0].request.headers.authorization = "Bearer malformed"),
    (c) => (c.programs[0].cases[3].request.headers.authorization = "Bearer "),
    (c) => (c.programs[0].cases[5].request.headers.authorization = "Bearer {{idToken}}"),
    (c) => (c.programs[0].cases[0].request.path = "/echo"),
    (c) => (c.programs[0].cases[1].request.method = "GET"),
    (c) => (c.programs[0].cases[2].request.body = { data: { op: "other" } }),
    (c) => (c.programs[0].cases[1].target = "callable"),
    (c) => c.programs[0].cases.push(structuredClone(c.programs[0].cases[0])),
    (c) => c.programs[0].cases.pop(),
    (c) => (c.programs[0].cases = c.programs[0].cases.toReversed()),
    (c) => c.programs[0].cases.splice(1, 0, c.programs[0].cases.splice(2, 1)[0]),
    (c) => (c.programs[0].id = "functions-http/callable/auth-refusal"),
    (c) => c.programs.push(structuredClone(c.programs[0])),
    (c) => (c.project = "fireemu-oracle-sbx"),
    (c) => (c.region = "europe-west1"),
    (c) => (c.functions.http = "fireemuOther"),
    (c) => (c.programs[0].cases[0].capture = "first-chunk-then-abort"),
    (c) => (c.programs[0].cases[0].request.headers["x-fireemu-probe"] = "1"),
    (c) => (c.programs[0].cases[4].request.extra = true),
  ];
  for (const [index, change] of variants.entries()) {
    const copy = structuredClone(CORPUS);
    change(copy);
    assert.throws(() => validateIngressCorpus(copy), Error, `variant ${index}`);
  }
});

test("the baseline: the front-end page is the 294-byte stage 3 page, the control is the compact callable answer", () => {
  assert.equal(BASELINE.frontEndPage.status, 401);
  assert.equal(BASELINE.frontEndPage.contentType, "text/html; charset=UTF-8");
  assert.equal(Buffer.byteLength(PAGE), 294);
  assert.equal(sha(PAGE), BASELINE.frontEndPage.bodySha256);
  assert.equal(BASELINE.control.status, 200);
  assert.equal(BASELINE.control.contentType, "application/json; charset=utf-8");
  assert.equal(BASELINE.control.body, CONTROL_BODY);
  assert.equal(BASELINE.control.bodyBytes, Buffer.byteLength(CONTROL_BODY));
  assert.equal(BASELINE.control.bodySha256, sha(CONTROL_BODY));
  // The recorded stage 3 control carries the same parsed body.
  const committed = JSON.parse(
    readFileSync(
      here("../../../spec/compatibility/closure/evidence/FUNCTIONS-HTTP-comparison.json"),
      "utf8",
    ),
  );
  assert.ok(Array.isArray(committed.productionRecordingSha256));
  assert.ok(
    committed.productionRecordingSha256.includes(
      "555c1150e708606a6f21ac931d9196a5e75e62486398b760d9e9cfafc8d94e0f",
    ),
  );
});

// ---- judge --------------------------------------------------------------------------------------

test("the callable wrapper's own refusal on every credential case is recorded as a new shape for each case", () => {
  const result = judgeObservation(allRefused(wrapper), BASELINE);
  assert.equal(result.verdict, "recorded", result.reasons.join("; "));
  assert.deepEqual(result.reasons, []);
  assert.deepEqual(
    result.answers.map((a) => [a.caseId, a.class, a.status, a.bodyBytes]),
    [
      ["no-authorization", "served-by-function", 200, 24],
      ...CASE_IDS.slice(1).map((id) => [id, "other", 401, Buffer.byteLength(WRAPPER_BODY)]),
    ],
  );
  assert.deepEqual(result.newShapes, CASE_IDS.slice(1));
  assert.equal(result.needsReview, true);
  assert.equal(result.lockKept, false);
});

test("the front end's page on every credential case is recorded as that page, nothing new", () => {
  const result = judgeObservation(allRefused(page), BASELINE);
  assert.equal(result.verdict, "recorded");
  assert.deepEqual(
    result.answers.map((a) => a.class),
    ["served-by-function", ...CASE_IDS.slice(1).map(() => "front-end-page")],
  );
  assert.deepEqual(result.newShapes, []);
  assert.equal(result.needsReview, false);
});

test("credential cases the function answers like the control are served by the function", () => {
  const result = judgeObservation(passes({}), BASELINE);
  assert.equal(result.verdict, "recorded");
  assert.ok(result.answers.every((a) => a.class === "served-by-function"));
  assert.equal(result.needsReview, false);
});

test("a mix is classified case by case, never as one verdict for the run", () => {
  const result = judgeObservation(
    passes({
      "malformed-bearer": wrapper,
      "lowercase-scheme": wrapper,
      "bare-scheme": page,
      "basic-scheme": control,
      "unsigned-jwt": wrapper,
    }),
    BASELINE,
  );
  assert.deepEqual(
    result.answers.map((a) => a.class),
    ["served-by-function", "other", "other", "front-end-page", "served-by-function", "other"],
  );
  assert.deepEqual(result.newShapes, ["malformed-bearer", "lowercase-scheme", "unsigned-jwt"]);
});

test("a page of another length or a control with another status is a new shape, by bytes", () => {
  const longer = { ...page, bodyText: `${PAGE}x` };
  const result = judgeObservation(passes({ "bare-scheme": longer }, control), BASELINE);
  assert.equal(result.answers[3].class, "other");
  assert.equal(result.answers[3].bodyBytes, 295);
  const status = { ...control, status: 201 };
  assert.equal(
    judgeObservation(passes({ "bare-scheme": status }), BASELINE).answers[3].class,
    "other",
  );
  const type = { ...page, contentType: "text/html; charset=utf-8" };
  assert.equal(
    judgeObservation(passes({ "bare-scheme": type }), BASELINE).answers[3].class,
    "other",
  );
});

test("answers that are not complete 2xx or 4xx answers are unknown and keep the lock", () => {
  for (const status of [100, 199, 300, 302, 307, 500, 502, 503]) {
    for (const index of [0, 1, 5, 6, 11]) {
      const list = allRefused(wrapper);
      list[index] = capture(index, { status, contentType: "text/plain", bodyText: "b" });
      const result = judgeObservation(list, BASELINE);
      assert.equal(result.verdict, "unknown", `${status}@${index}`);
      assert.equal(result.lockKept, true);
      assert.equal(result.needsReview, true);
      assert.deepEqual(result.answers, []);
    }
  }
  const failed = allRefused(wrapper);
  failed[4] = capture(4, { error: "TypeError: fetch failed" });
  assert.equal(judgeObservation(failed, BASELINE).verdict, "unknown");
});

test("an unreadable body, a content-length that disagrees and missing captures are unknown", () => {
  const base = allRefused(wrapper);
  for (const tweak of [
    (list) => (list[2].bodySha256 = null),
    (list) => (list[2].bodyBytes = null),
    (list) => (list[7].bodyBytes = 3),
    (list) => (list[3].headers["content-length"] = "5"),
  ]) {
    const list = structuredClone(base);
    tweak(list);
    assert.equal(judgeObservation(list, BASELINE).verdict, "unknown");
  }
  for (const count of [0, 1, 6, 11, 13]) {
    const list = [...base, ...base].slice(0, count);
    assert.equal(judgeObservation(list, BASELINE).verdict, "unknown", `${count} captures`);
  }
  assert.equal(judgeObservation(null, BASELINE).verdict, "unknown");
  assert.equal(judgeObservation({ length: 12 }, BASELINE).verdict, "unknown");
});

test("captures out of order, relabelled or sent with the wrong credential are unknown", () => {
  const base = allRefused(wrapper);
  const swapped = structuredClone(base);
  [swapped[1], swapped[2]] = [swapped[2], swapped[1]];
  assert.equal(judgeObservation(swapped, BASELINE).verdict, "unknown");
  const relabelled = structuredClone(base);
  relabelled[3].caseId = "basic-scheme";
  assert.equal(judgeObservation(relabelled, BASELINE).verdict, "unknown");
  for (const index of [0, 1, 3, 5, 8, 11]) {
    const wrong = structuredClone(base);
    wrong[index].authorization = index === 0 ? "Bearer malformed" : null;
    assert.equal(judgeObservation(wrong, BASELINE).verdict, "unknown", `credential@${index}`);
  }
  const thirdPass = [
    ...base,
    ...structuredClone(base).map((c, i) => Object.assign(c, { pass: 3, seq: 13 + i })),
  ];
  assert.equal(judgeObservation(thirdPass, BASELINE).verdict, "unknown");
});

test("passes that disagree are unknown, whichever case or field differs", () => {
  for (let index = 0; index < CASES.length; index += 1) {
    for (const tweak of [
      (c) => (c.status = c.status === 401 ? 403 : 401),
      (c) => (c.headers = { ...c.headers, "content-type": "text/plain" }),
      (c) => {
        c.bodyText = `${c.bodyText}z`;
        c.bodyBytes += 1;
        c.bodySha256 = sha(c.bodyText);
      },
      (c) => (c.bodySha256 = sha("other")),
    ]) {
      const list = allRefused(wrapper);
      tweak(list[CASES.length + index]);
      const result = judgeObservation(list, BASELINE);
      assert.equal(result.verdict, "unknown", `case ${index}`);
      assert.match(result.reasons.join(), /passes disagree|control/);
    }
  }
});

test("a control that is not the recorded callable answer is unknown, field by field", () => {
  const problems = [
    [{ ...control, status: 201 }, /status/],
    [{ ...control, contentType: "text/plain" }, /content-type/],
    [{ ...control, bodyText: '{"result":{"auth":1}}' }, /body/],
    [{ ...control, bodyText: '{ "result": { "auth": null } }' }, /body/],
    [{ ...control, bodyText: "[]" }, /body/],
    [{ ...control, bodyText: "not json" }, /body/],
    [wrapper, /status/],
    [page, /status/],
  ];
  for (const [answer, pattern] of problems) {
    const list = passes({ "no-authorization": answer }, wrapper);
    const result = judgeObservation(list, BASELINE);
    assert.equal(result.verdict, "unknown", JSON.stringify(answer));
    assert.match(result.reasons.join(), pattern);
    assert.match(result.reasons.join(), /control/);
  }
});

test("a body whose stored text disagrees with its recorded byte count is judged by the byte count, never the text", () => {
  // The recorders store compact JSON; the layout is judged from bodyBytes (checklist 2, byte layout).
  const spaced = { ...control, bodyText: '{"result":{"auth":null}}', bodyBytes: 28 };
  assert.equal(
    judgeObservation(passes({ "no-authorization": spaced }), BASELINE).verdict,
    "unknown",
  );
});

test("a wrapper answer whose JSON is the same in a different layout is a different shape by its bytes", () => {
  const spaced = '{"error": {"message": "Unauthenticated", "status": "UNAUTHENTICATED"}}';
  const result = judgeObservation(
    allRefused({ ...wrapper, bodyText: spaced, bodyBytes: Buffer.byteLength(spaced) }),
    BASELINE,
  );
  assert.equal(result.answers[1].bodyBytes, Buffer.byteLength(spaced));
  assert.notEqual(result.answers[1].bodyBytes, Buffer.byteLength(WRAPPER_BODY));
});

test("property: the class of a case depends only on status, content-type, byte count and digest", () => {
  forAll(
    300,
    (random) => {
      const kind = pick(random, ["control", "page", "wrapper", "random"]);
      const base =
        kind === "control"
          ? control
          : kind === "page"
            ? page
            : kind === "wrapper"
              ? wrapper
              : {
                  status: pick(random, [200, 400, 401, 403, 404]),
                  contentType: pick(random, ["text/html; charset=UTF-8", "application/json"]),
                  bodyText: "y".repeat(between(random, 0, 300)),
                };
      const headers = {};
      for (let i = 0; i < between(random, 0, 5); i += 1)
        headers[pick(random, ["server", "date", "vary", "x-powered-by", "etag", "alt-svc"])] =
          "v".repeat(between(random, 1, 12));
      return { kind, base, headers, index: between(random, 1, 5) };
    },
    ({ kind, base, headers, index }) => {
      const plain = judgeObservation(passes({ [CASE_IDS[index]]: base }), BASELINE);
      const decorated = judgeObservation(
        passes({ [CASE_IDS[index]]: { ...base, headers } }),
        BASELINE,
      );
      assert.equal(plain.verdict, "recorded");
      assert.deepEqual(
        decorated.answers.map((a) => a.class),
        plain.answers.map((a) => a.class),
      );
      const expected =
        kind === "control" ? "served-by-function" : kind === "page" ? "front-end-page" : "other";
      if (kind !== "random") assert.equal(plain.answers[index].class, expected);
      assert.deepEqual(decorated.newShapes, plain.newShapes);
    },
  );
});

test("property: any capture that failed in transport or answered outside 2xx/4xx makes the verdict unknown", () => {
  forAll(
    300,
    (random) => ({
      index: between(random, 0, 11),
      status: pick(random, [100, 102, 300, 301, 307, 308, 500, 501, 502, 503, 504, 599, null]),
    }),
    ({ index, status }) => {
      const list = allRefused(wrapper);
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

test("property: passes that agree give the same answers as one pass, and needsReview is exactly 'a new shape exists'", () => {
  forAll(
    300,
    (random) => {
      const answers = {};
      for (const id of CASE_IDS.slice(1))
        answers[id] = pick(random, [control, page, wrapper, { ...wrapper, status: 403 }]);
      return answers;
    },
    (answers) => {
      const result = judgeObservation(passes(answers), BASELINE);
      assert.equal(result.verdict, "recorded");
      const others = CASE_IDS.slice(1).filter(
        (id) => answers[id] !== control && answers[id] !== page,
      );
      assert.deepEqual(result.newShapes, others);
      assert.equal(result.needsReview, others.length > 0);
      assert.equal(result.answers.length, CASES.length);
    },
  );
});

// ---- capture (generalised) -----------------------------------------------------------------------

test("the capture numbers six cases per pass and keeps the headers it is told to", async () => {
  const seen = [];
  const fetchImpl = async () =>
    new Response(CONTROL_BODY, {
      status: 200,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "access-control-allow-origin": "*",
        vary: "Origin",
        "x-powered-by": "Express",
        etag: 'W/"x"',
        server: "Google Frontend",
        "set-cookie": "a=b",
      },
    });
  const fetchCapture = captureFetch({
    fetchImpl,
    onCapture: (c) => seen.push(c),
    caseIds: CASE_IDS,
    keptHeaders: captureHeaders,
  });
  for (let i = 0; i < 12; i += 1) {
    await fetchCapture(`https://example.invalid/fireemuHttpProbe/`, {
      method: "POST",
      headers: CASES[i % 6].authorization ? { authorization: CASES[i % 6].authorization } : {},
    });
  }
  assert.deepEqual(
    seen.map((c) => [c.seq, c.pass, c.caseId]),
    Array.from({ length: 12 }, (_, i) => [i + 1, Math.floor(i / 6) + 1, CASE_IDS[i % 6]]),
  );
  assert.deepEqual(seen[0].authorization, null);
  assert.equal(seen[1].authorization, "Bearer malformed");
  assert.deepEqual(Object.keys(seen[0].headers).toSorted(), [
    "access-control-allow-origin",
    "content-type",
    "etag",
    "server",
    "vary",
    "x-powered-by",
  ]);
  assert.ok(seen[0].headerNames.includes("set-cookie"));
  assert.equal(seen[0].headers["set-cookie"], undefined);
  assert.equal(seen[0].path, "/");
});

test("the kept headers of this observation are a superset of the default, with no credential or cookie", () => {
  assert.ok(
    ["content-type", "content-length", "www-authenticate", "server"].every((h) =>
      captureHeaders.includes(h),
    ),
  );
  assert.ok(captureHeaders.includes("access-control-allow-origin"));
  assert.ok(captureHeaders.includes("vary"));
  assert.ok(!captureHeaders.includes("set-cookie"));
  assert.ok(!captureHeaders.includes("authorization"));
});

// ---- admission (own rows are those of the task) -------------------------------------------------------

const row = (fields) => JSON.stringify({ project: "fireemu-oracle-query", ...fields });
const closed = row({
  event: "finished",
  outcome: "recorded",
  taskId: "OTHER-TASK",
  ts: "2026-11-10T12:00:00Z",
});
const NOW = Date.parse("2026-11-10T14:00:00Z");

test("admission counts the rows of this task, not the other observation's", () => {
  const other = [
    row({ event: "started", taskId: "FUNCTIONS-HTTP-BEARER", ts: "2026-11-10T09:00:00Z" }),
    row({
      event: "finished",
      outcome: "recorded",
      taskId: "FUNCTIONS-HTTP-BEARER",
      ts: "2026-11-10T09:30:00Z",
    }),
  ];
  const text = `${[...other, closed].join("\n")}\n`;
  assert.deepEqual(admit({ ledgerText: text, now: NOW, env: {}, taskId: TASK_ID }), { attempt: 1 });
  assert.deepEqual(admit({ ledgerText: text, now: NOW, env: {} }), { attempt: 2 });
});

test("admission refuses the fourth attempt and an own started row without a terminal row", () => {
  const own = (n) => [
    row({ event: "started", taskId: TASK_ID, attempt: n, ts: "2026-11-10T09:00:00Z" }),
    row({ event: "finished", outcome: "recorded", taskId: TASK_ID, ts: "2026-11-10T09:30:00Z" }),
  ];
  const three = `${[...own(1), ...own(2), ...own(3), closed].join("\n")}\n`;
  assert.equal(MAX_ATTEMPTS, 3);
  assert.throws(
    () => admit({ ledgerText: three, now: NOW, env: {}, taskId: TASK_ID }),
    /attempt 4/,
  );
  const two = `${[...own(1), ...own(2), closed].join("\n")}\n`;
  assert.deepEqual(admit({ ledgerText: two, now: NOW, env: {}, taskId: TASK_ID }), { attempt: 3 });
  const open = `${[
    row({ event: "started", taskId: TASK_ID, ts: "2026-11-10T09:00:00Z" }),
    closed,
  ].join("\n")}\n`;
  // the closing row belongs to another task, so it does not terminate this attempt
  assert.throws(
    () => admit({ ledgerText: open, now: NOW, env: {}, taskId: TASK_ID }),
    /started row/,
  );
});

// ---- variants, caps and pins --------------------------------------------------------------------------

test("two variants: the callable's code served as onRequest, and the same code as a real callable", () => {
  assert.deepEqual(Object.keys(VARIANTS), ["wrapper", "callable"]);
  assert.equal(VARIANTS.wrapper.directory, "wrapper");
  assert.equal(VARIANTS.callable.directory, "callable");
});

test("the caps of one attempt: twelve invocations, one deploy, one CLI delete, no Auth request", () => {
  assert.equal(CAPS.invocation, 12);
  assert.equal(CAPS.cliDeploy, 1);
  assert.equal(CAPS.cliDelete, 1);
  assert.equal(CAPS.auth, 0);
  assert.equal(CAPS.control, 19);
  assert.equal(CAPS.cleanup, 37);
  assert.equal(CAPS.upload, 15);
});

test("source pins: shared bytes and both variants' fixtures are the reviewed bytes", async () => {
  for (const variant of Object.keys(VARIANTS)) {
    const pins = sourcePins(variant);
    for (const [file, expected] of Object.entries(pins)) {
      assert.equal(sha(await readFile(here(file))), expected, `${variant}: ${file}`);
    }
    assert.deepEqual(
      Object.keys(pins).toSorted(),
      [
        "../bearer-observation.baseline.json",
        "baseline.json",
        "corpus.json",
        `${variant}/firebase.json`,
        `${variant}/fixtures/index.js`,
        `${variant}/fixtures/package-lock.json`,
        `${variant}/fixtures/package.json`,
      ].toSorted(),
    );
  }
  assert.throws(() => sourcePins("other"), /variant/);
  // The two variants differ in index.js only; the package files are the stage 3 fixture's bytes.
  const wrapperPins = sourcePins("wrapper");
  const callablePins = sourcePins("callable");
  assert.notEqual(
    wrapperPins["wrapper/fixtures/index.js"],
    callablePins["callable/fixtures/index.js"],
  );
  for (const file of ["firebase.json", "fixtures/package.json", "fixtures/package-lock.json"]) {
    assert.equal(wrapperPins[`wrapper/${file}`], callablePins[`callable/${file}`], file);
  }
  const stage3 = (file) => sha(readFileSync(here(`../${file}`)));
  assert.equal(wrapperPins["wrapper/fixtures/package.json"], stage3("fixtures/package.json"));
  assert.equal(
    wrapperPins["wrapper/fixtures/package-lock.json"],
    stage3("fixtures/package-lock.json"),
  );
  assert.equal(wrapperPins["wrapper/firebase.json"], stage3("firebase.json"));
});

// ---- orchestration in the fake world ------------------------------------------------------------------

const CLOUDBUILD =
  "https://cloudbuild.googleapis.com/v1/projects/fireemu-oracle-query/locations/us-central1/builds?pageSize=10";
const ledgerClosed = row({
  event: "observation-complete-cleanup-verified",
  task: "RTDB-2350",
  recordedAt: "2026-11-10T11:00:00Z",
});

async function fakeRun({
  variant = "wrapper",
  deployScript = FAKE_RECEIPT_SCRIPT("process.exit(0);", 200),
  answers = {},
  failFetch = false,
  ledgerText = `${ledgerClosed}\n`,
} = {}) {
  const world = await deployWorld({ deployScript, caps: CAPS });
  const ledger = [];
  const files = {};
  const runDirs = [];
  const restControl = async (method, url, body, kind = "control", allowed = [200]) => {
    if (url === CLOUDBUILD) {
      world.budget.take(kind);
      return {
        status: 200,
        value: {
          builds: [
            {
              id: "b1",
              status: "SUCCESS",
              createTime: "2026-11-10T12:00:30Z",
              finishTime: "2026-11-10T12:01:10Z",
            },
          ],
        },
        bytes: 10,
      };
    }
    if (url.startsWith("https://cloudresourcemanager.googleapis.com/v3/projects/")) {
      world.budget.take(kind);
      return { status: 200, value: { bindings: [] }, bytes: 10 };
    }
    return world.control(method, url, body, kind, allowed);
  };
  const sent = [];
  const fetchImpl = async (url, init) => {
    if (failFetch) throw new TypeError("fetch failed");
    const authorization = init.headers.authorization ?? null;
    sent.push(authorization);
    const step = CASES.find((c) => c.authorization === authorization);
    const chosen = answers[step.id] ?? (authorization === null ? control : wrapper);
    return new Response(chosen.bodyText, {
      status: chosen.status,
      headers: { "content-type": chosen.contentType, ...chosen.headers },
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
    makeRunDir: async (name) => {
      runDirs.push(name);
      return join(world.dir, "run");
    },
    writeRunFile: async (dir, name, text) => {
      files[name] = text;
    },
    createBudget: () => world.budget,
    createControl: () => restControl,
    openUploads: () => world.uploads,
    run: world.run,
    fetchImpl,
    installSignals: () => {},
    log: () => {},
    warn: () => {},
  };
  const result = await recordCallableIngress({}, deps, variant);
  return { world, result, ledger, files, runDirs, sent };
}

test("fake world: the wrapper run records twelve answers, cleans up and writes two ledger lines", async () => {
  const { world, result, ledger, files, runDirs, sent } = await fakeRun();
  try {
    assert.equal(result.verdict, "recorded", files["judgement.json"]);
    assert.equal(result.outcome, "recorded", ledger[1]?.reason);
    assert.equal(result.exitCode, 0);
    assert.match(runDirs[0], /^callable-ingress-obs-wrapper-2026-11-10T12\d{4}\.\d{3}Z$/);
    assert.deepEqual(
      ledger.map((line) => [line.event, line.taskId, line.variant, line.attempt]),
      [
        ["started", TASK_ID, "wrapper", 1],
        ["finished", TASK_ID, "wrapper", 1],
      ],
    );
    const [started, terminal] = ledger;
    assert.equal(started.reservedUsd, 1);
    assert.equal(terminal.outcome, "recorded");
    assert.equal(terminal.closureReady, true);
    assert.equal(terminal.lockKept, false);
    assert.equal(terminal.needsReview, true, "five new shapes");
    assert.equal(terminal.requests.invocation, 12);
    assert.equal(terminal.requests.cliDeploy, 1);
    assert.equal(terminal.requests.cliDelete, 1);
    assert.equal(terminal.estimatedUsd, 0.58);
    assert.deepEqual(terminal.newShapes, CASE_IDS.slice(1));
    assert.deepEqual(terminal.answers[0], ["no-authorization", "served-by-function", 200, 24]);
    assert.equal(terminal.answers.length, 6);
    for (const [kind, cap] of Object.entries(CAPS)) {
      assert.ok(terminal.requests[kind] <= cap, `${kind} ${terminal.requests[kind]} <= ${cap}`);
    }
    assert.deepEqual(
      sent,
      [...CASES, ...CASES].map((c) => c.authorization),
      "every credential is sent, in corpus order, twice",
    );
    const recorded = JSON.parse(files["captures.json"]);
    assert.equal(recorded.length, 12);
    assert.deepEqual(
      recorded.map((c) => [c.pass, c.caseId]),
      [...CASE_IDS, ...CASE_IDS].map((id, i) => [Math.floor(i / 6) + 1, id]),
    );
    assert.equal(JSON.parse(files["judgement.json"]).verdict, "recorded");
    assert.deepEqual(world.argv[0], [
      "deploy",
      "--only",
      "functions:functions-http-oracle:fireemuHttpProbe",
    ]);
    assert.ok(!world.gcs.objects.has(UPLOAD_OBJECT));
    for (const text of Object.values(files)) {
      assert.ok(!text.includes("123456789012") && !text.includes("REFRESH-SECRET"));
    }
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("fake world: the callable control run is the same path under its own variant", async () => {
  const { world, result, ledger, runDirs } = await fakeRun({
    variant: "callable",
    answers: Object.fromEntries(CASE_IDS.slice(1).map((id) => [id, page])),
  });
  try {
    assert.equal(result.outcome, "recorded");
    assert.match(runDirs[0], /^callable-ingress-obs-callable-/);
    assert.deepEqual(
      ledger.map((line) => line.variant),
      ["callable", "callable"],
    );
    assert.deepEqual(ledger[1].newShapes, []);
    assert.equal(ledger[1].needsReview, false);
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("fake world: an unknown variant is refused before anything is read or written", async () => {
  await assert.rejects(fakeRun({ variant: "other" }), /variant/);
  assert.throws(() => ingressSpec("other"), /variant/);
  assert.throws(() => productionDeps({ variant: "other" }), /variant/);
  assert.throws(() => productionDeps(), /variant/);
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
    assert.deepEqual(ledger[1].answers, []);
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("fake world: one 5xx among the twelve answers makes the run unknown, not recorded", async () => {
  const { world, result, ledger } = await fakeRun({
    answers: { "basic-scheme": { status: 503, contentType: "text/plain", bodyText: "no" } },
  });
  try {
    assert.equal(result.verdict, "unknown");
    assert.equal(ledger[1].lockKept, true);
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("fake world: a failed deploy (unknown create) needs recovery even when every read shows 404", async () => {
  const { world, result, ledger } = await fakeRun({
    deployScript: FAKE_RECEIPT_SCRIPT('console.error("Error: Failed"); process.exit(1);', 200),
  });
  try {
    assert.equal(result.outcome, "needs-recovery");
    assert.equal(ledger[1].event, "needs-recovery");
    assert.equal(ledger[1].closureReady, false);
    assert.equal(ledger[1].lockKept, true);
    assert.equal(ledger[1].variant, "wrapper");
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("fake world: admission refuses before any request and writes no ledger line", async () => {
  const openRow = row({ event: "started", task: "RTDB-2350", recordedAt: "2026-11-10T11:00:00Z" });
  await assert.rejects(fakeRun({ ledgerText: `${openRow}\n` }), /does not close its run/);
  const young = row({
    event: "cleanup-verified",
    task: "RTDB-2350",
    recordedAt: "2026-11-10T11:50:00Z",
  });
  await assert.rejects(fakeRun({ ledgerText: `${young}\n` }), /30 minutes/);
});

// ---- the deploy directory and the real effects ------------------------------------------------------------

test("the deploy runs from the variant's directory, not the stage 3 fixture's", async () => {
  const dir = await mkdtemp(join(tmpdir(), "callable-ingress-cwd-"));
  try {
    const out = join(dir, "cwd.txt");
    const script = join(dir, "fake-cli.mjs");
    await writeFile(
      script,
      `import { writeFileSync } from "node:fs";\nwriteFileSync(${JSON.stringify(out)}, JSON.stringify([process.cwd(), process.argv.slice(2)]));\n`,
    );
    const cwd = await mkdtemp(join(dir, "variant-"));
    const run = makeCliRunner(cwd, [process.execPath, script]);
    const runDir = join(dir, "run");
    await mkdir(runDir);
    await run(["functions:delete", "x"], "/adc", createBudget(CAPS), "cliDelete", runDir);
    const [seen, args] = JSON.parse(await readFile(out, "utf8"));
    assert.equal(await realpath(seen), await realpath(cwd));
    assert.deepEqual(args.slice(0, 2), ["functions:delete", "x"]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("productionDeps: this observation's sources, caps and deploy directory replace the stage 3 ones", async () => {
  for (const variant of Object.keys(VARIANTS)) {
    const deps = productionDeps({ variant });
    const { corpus, baseline, digests } = await deps.readSources();
    assert.equal(validateIngressCorpus(corpus).id, PROGRAM_ID);
    assert.equal(baseline.frontEndPage.bodyBytes, 294);
    assert.equal(baseline.control.bodyBytes, 24);
    assert.equal(digests.corpus, sourcePins(variant)["corpus.json"]);
    const budget = deps.createBudget();
    for (let i = 0; i < 12; i += 1) budget.take("invocation");
    assert.throws(() => budget.take("invocation"));
    assert.equal(typeof deps.run, "function");
  }
});

test("fixtures: the wrapper variant deploys a plain HTTPS function, the callable variant a callable", async (t) => {
  let functionsPackage;
  try {
    functionsPackage = readFileSync(
      here("./wrapper/fixtures/node_modules/firebase-functions/package.json"),
      "utf8",
    );
  } catch {
    t.skip("fixture dependencies are not installed (npm ci --prefix <variant>/fixtures)");
    return;
  }
  assert.equal(JSON.parse(functionsPackage).version, "7.3.2");
  const { createRequire } = await import("node:module");
  for (const variant of Object.keys(VARIANTS)) {
    const required = createRequire(here(`./${variant}/fixtures/index.js`))("./index.js");
    assert.deepEqual(Object.keys(required), ["fireemuHttpProbe"], variant);
    const endpoint = required.fireemuHttpProbe.__endpoint;
    assert.deepEqual(endpoint.region, ["us-central1"]);
    assert.equal(endpoint.maxInstances, 1);
    if (variant === "wrapper") {
      assert.ok(endpoint.httpsTrigger && !endpoint.callableTrigger);
    } else {
      assert.ok(endpoint.callableTrigger && !endpoint.httpsTrigger);
    }
  }
});
