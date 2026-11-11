import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { gzipSync } from "node:zlib";

import { forAll, pick, between } from "../../src/fs-ent-pipeline/test-support.mjs";
import { admit } from "../bearer-observation.mjs";
import { createBudget } from "../harness.mjs";
import { FAKE_RECEIPT_SCRIPT, deployWorld } from "../production.fake.mjs";
import { MASKED_TOKEN, PROGRAMS, SLOTS, classOf, judgeRerecord } from "./rerecord-judge.mjs";
import {
  CAPS,
  PASS_DELAY_MS,
  RESERVED_USD_PER_ATTEMPT,
  SOURCE_PINS,
  TASK_ID,
  createFactsCollector,
  createTransport,
  enrichCapture,
  functionFacts,
  hostForm,
  maskAuthorization,
  productionDeps,
  readSources,
  recordRerecord,
  rerecordSpec,
  requestHeaders,
  serviceFacts,
  validateRerecordCorpus,
} from "./rerecord.mjs";

const here = (name) => new URL(name, import.meta.url);
const json = (name) => JSON.parse(readFileSync(here(name), "utf8"));
const sha = (text) => createHash("sha256").update(text).digest("hex");
const CORPUS = json("./rerecord.corpus.json");
const BASELINE = {
  frontEndPage: json("../bearer-observation.baseline.json").provisional,
  control: json("./baseline.json").control,
  ...json("./rerecord.baseline.json"),
};
const PAGE = BASELINE.frontEndPage.body;
const CONTROL_BODY = BASELINE.control.body;
const ENVELOPE = BASELINE.wrapperEnvelope.body;
const VALID_BODY =
  '{"result":{"uid":"u1","email":"a@example.com","emailVerified":false,"signInProvider":"password"}}';

const answers = {
  control: { status: 200, contentType: "application/json; charset=utf-8", bodyText: CONTROL_BODY },
  page: { status: 401, contentType: "text/html; charset=UTF-8", bodyText: PAGE },
  envelope: { status: 401, contentType: "application/json; charset=utf-8", bodyText: ENVELOPE },
  valid: { status: 200, contentType: "application/json; charset=utf-8", bodyText: VALID_BODY },
};

function capture(index, answer) {
  const slot = SLOTS[index];
  const step = PROGRAMS.find(({ id }) => id === slot.program).cases.find(
    ({ id }) => id === slot.caseId,
  );
  const text = answer.bodyText ?? "";
  const headers = { ...answer.headers };
  if (answer.contentType !== undefined) headers["content-type"] = answer.contentType;
  return {
    seq: index + 1,
    pass: slot.pass,
    program: slot.program,
    caseId: slot.caseId,
    method: "POST",
    path: "/",
    authorization:
      step.authorization === "none"
        ? null
        : step.authorization === "token"
          ? MASKED_TOKEN
          : step.authorization,
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

/** All twelve captures: `rule(slot)` names the answer of each slot. */
const run = (rule) => SLOTS.map((slot, index) => capture(index, rule(slot, index)));
const standard = (refusal) => (slot) =>
  slot.caseId === "no-authorization"
    ? answers.control
    : slot.caseId === "valid-project-id-token"
      ? answers.valid
      : refusal;

// ---- corpus ---------------------------------------------------------------------------------------

test("the frozen corpus is the stage 3 requests of auth-context and auth-refusal with a leading control", () => {
  const programs = validateRerecordCorpus(CORPUS);
  assert.deepEqual(
    programs.map((p) => [p.id, p.cases.map((c) => c.id)]),
    [
      ["functions-http/callable/auth-context", ["no-authorization", "valid-project-id-token"]],
      [
        "functions-http/callable/auth-refusal",
        ["no-authorization", "malformed-bearer", "invalid-signature", "expired-id-token"],
      ],
    ],
  );
  const stage3 = json("../corpus.json");
  for (const program of programs) {
    const original = stage3.programs.find(({ id }) => id === program.id);
    for (const step of program.cases) {
      const earlier = original.cases.find(({ id }) => id === step.id);
      // The control is new for auth-refusal; stage 3 has it in auth-context.
      const reference =
        earlier ??
        stage3.programs
          .find(({ id }) => id === "functions-http/callable/auth-context")
          .cases.find(({ id }) => id === step.id);
      assert.deepEqual(step, reference, step.id);
    }
  }
});

test("a corpus that changes a request, a case, an order, a program or the target is refused with its reason", () => {
  const refused = (change, pattern) => {
    const copy = structuredClone(CORPUS);
    change(copy);
    assert.throws(() => validateRerecordCorpus(copy), pattern);
  };
  refused(
    (c) => (c.programs[1].cases[1].request.headers.authorization = "Bearer other"),
    /malformed-bearer request/,
  );
  refused(
    (c) => (c.programs[1].cases[0].request.headers.authorization = "Bearer malformed"),
    /no-authorization request/,
  );
  refused(
    (c) => (c.programs[0].cases[1].request.headers.authorization = "Bearer {{expiredIdToken}}"),
    /valid-project-id-token request/,
  );
  refused((c) => (c.programs[1].cases[2].request.path = "/x"), /invalid-signature request/);
  refused((c) => (c.programs[1].cases[2].request.method = "GET"), /invalid-signature request/);
  refused((c) => (c.programs[1].cases[3].request.body = {}), /expired-id-token request/);
  refused(
    (c) => (c.programs[1].cases[3].request.headers["x-fireemu-probe"] = "1"),
    /expired-id-token request/,
  );
  refused((c) => (c.programs[1].cases[1].target = "http"), /malformed-bearer target/);
  refused((c) => delete c.programs[1].cases[1].target, /malformed-bearer target/);
  refused(
    (c) => (c.programs[1].cases[1].capture = "first-chunk-then-abort"),
    /malformed-bearer capture/,
  );
  refused((c) => (c.programs[1].cases[1].note = "x"), /malformed-bearer fields/);
  refused((c) => (c.programs[1].cases[1].id = "other"), /case 2 id/);
  refused((c) => c.programs[1].cases.pop(), /auth-refusal cases/);
  refused((c) => c.programs[0].cases.push(c.programs[0].cases[0]), /auth-context cases/);
  refused((c) => (c.programs = c.programs.toReversed()), /program 1 id/);
  refused((c) => c.programs.pop(), /programs/);
  refused((c) => (c.programs[0].id = "x"), /program 1 id/);
  refused((c) => (c.project = "fireemu-oracle-sbx"), /project or region/);
  refused((c) => (c.region = "europe-west1"), /project or region/);
  refused((c) => (c.schemaVersion = 2), /project or region/);
  refused((c) => (c.functions.callable = "x"), /functions/);
  refused((c) => (c.placeholders = c.placeholders.toReversed()), /placeholders/);
  assert.throws(() => validateRerecordCorpus(null), /project or region/);
});

test("the frozen order: each program, pass 1 then pass 2, every case in order", () => {
  assert.equal(SLOTS.length, 12);
  assert.deepEqual(
    SLOTS.map((s) => `${s.program.split("/").at(-1)}:${s.pass}:${s.caseId}`),
    [
      "auth-context:1:no-authorization",
      "auth-context:1:valid-project-id-token",
      "auth-context:2:no-authorization",
      "auth-context:2:valid-project-id-token",
      "auth-refusal:1:no-authorization",
      "auth-refusal:1:malformed-bearer",
      "auth-refusal:1:invalid-signature",
      "auth-refusal:1:expired-id-token",
      "auth-refusal:2:no-authorization",
      "auth-refusal:2:malformed-bearer",
      "auth-refusal:2:invalid-signature",
      "auth-refusal:2:expired-id-token",
    ],
  );
});

// ---- judge --------------------------------------------------------------------------------------

test("the wrapper's envelope on every refusal row, in both passes, is recorded and needs review", () => {
  const result = judgeRerecord(run(standard(answers.envelope)), BASELINE);
  assert.equal(result.verdict, "recorded", result.reasons.join("; "));
  assert.deepEqual(result.timingDiffers, []);
  assert.equal(result.needsReview, true);
  assert.equal(result.lockKept, false);
  assert.deepEqual(
    result.rows.map((r) => [r.caseId, r.passes.map((p) => p.class)]),
    [
      ["no-authorization", ["function-answer", "function-answer"]],
      ["valid-project-id-token", ["valid-token-answer", "valid-token-answer"]],
      ["no-authorization", ["function-answer", "function-answer"]],
      ["malformed-bearer", ["wrapper-envelope", "wrapper-envelope"]],
      ["invalid-signature", ["wrapper-envelope", "wrapper-envelope"]],
      ["expired-id-token", ["wrapper-envelope", "wrapper-envelope"]],
    ],
  );
});

test("the front end's page on the refusal rows is recognized as that page", () => {
  const result = judgeRerecord(run(standard(answers.page)), BASELINE);
  assert.equal(result.verdict, "recorded");
  assert.deepEqual(
    result.rows.slice(3).map((r) => r.passes.map((p) => p.class)),
    [
      ["front-end-page", "front-end-page"],
      ["front-end-page", "front-end-page"],
      ["front-end-page", "front-end-page"],
    ],
  );
});

test("a row whose answer changes between the immediate pass and the pass 60 s later is named", () => {
  const list = run((slot) =>
    slot.caseId === "malformed-bearer"
      ? slot.pass === 1
        ? answers.page
        : answers.envelope
      : standard(answers.envelope)(slot),
  );
  const result = judgeRerecord(list, BASELINE);
  assert.equal(result.verdict, "recorded");
  assert.deepEqual(result.timingDiffers, ["auth-refusal#malformed-bearer"]);
  assert.equal(result.needsReview, true);
});

test("a control that is not the callable's own answer is unknown: the public invoker was not in effect", () => {
  for (const index of [0, 2, 4, 8]) {
    for (const wrong of [answers.page, answers.envelope, { ...answers.control, status: 403 }]) {
      const list = run(standard(answers.envelope));
      list[index] = capture(index, wrong);
      const result = judgeRerecord(list, BASELINE);
      assert.equal(result.verdict, "unknown", `${index}`);
      assert.match(result.reasons.join(), /the control is not the callable's own answer/);
      assert.equal(result.lockKept, true);
    }
  }
});

test("a valid token that is refused is another answer, not an unknown run", () => {
  const list = run((slot) =>
    slot.caseId === "valid-project-id-token" ? answers.envelope : standard(answers.envelope)(slot),
  );
  const result = judgeRerecord(list, BASELINE);
  assert.equal(result.verdict, "recorded");
  assert.equal(result.rows[1].passes[0].class, "wrapper-envelope");
});

test("the valid-token class needs the callable result of the recorded shape", () => {
  const classOfBody = (body, extra = {}) =>
    classOf(capture(1, { ...answers.valid, bodyText: body, ...extra }), BASELINE);
  assert.equal(classOfBody(VALID_BODY), "valid-token-answer");
  for (const body of [
    '{"result":{"uid":"","email":"a","emailVerified":false,"signInProvider":"password"}}',
    '{"result":{"uid":1,"email":"a","emailVerified":false,"signInProvider":"password"}}',
    '{"result":{"email":"a","uid":"u","emailVerified":false,"signInProvider":"password"}}',
    '{"result":{"uid":"u"}}',
    '{ "result": { "uid": "u", "email": "a", "emailVerified": false, "signInProvider": "password" } }',
    "not json",
    '{"result":null}',
  ]) {
    assert.equal(classOfBody(body), "other", body);
  }
  assert.equal(classOfBody(VALID_BODY, { status: 201 }), "other");
  assert.equal(classOfBody(VALID_BODY, { contentType: "text/plain" }), "other");
  // The same body for another case is not the valid-token answer.
  assert.equal(classOf(capture(5, answers.valid), BASELINE), "other");
});

test("answers that are not complete 2xx or 4xx answers are unknown and keep the lock", () => {
  for (const status of [100, 199, 300, 302, 500, 503]) {
    for (const index of [0, 1, 5, 7, 11]) {
      const list = run(standard(answers.envelope));
      list[index] = capture(index, { status, contentType: "text/plain", bodyText: "b" });
      const result = judgeRerecord(list, BASELINE);
      assert.equal(result.verdict, "unknown", `${status}@${index}`);
      assert.match(result.reasons.join(), /is an unknown answer/);
      assert.equal(result.lockKept, true);
      assert.deepEqual(result.rows, []);
    }
  }
  const failed = run(standard(answers.envelope));
  failed[6] = capture(6, { error: "TypeError: fetch failed" });
  assert.match(judgeRerecord(failed, BASELINE).reasons.join(), /transport failure/);
});

test("single-fault captures are refused for their own reason", () => {
  const edit = (index, tweak) => {
    const list = run(standard(answers.envelope));
    tweak(list[index]);
    return judgeRerecord(list, BASELINE);
  };
  for (let index = 0; index < SLOTS.length; index += 1) {
    assert.match(edit(index, (c) => (c.bodySha256 = null)).reasons.join(), /body unreadable/);
    assert.match(edit(index, (c) => (c.bodyBytes = null)).reasons.join(), /body unreadable/);
    assert.match(edit(index, (c) => (c.bodySha256 = "x")).reasons.join(), /body unreadable/);
    assert.match(
      edit(index, (c) => (c.headers["content-length"] = "5")).reasons.join(),
      /content-length 5 disagrees/,
    );
    assert.match(
      edit(index, (c) => (c.pass = c.pass === 1 ? 2 : 1)).reasons.join(),
      /capture \d+ is not pass/,
    );
    assert.match(
      edit(index, (c) => (c.program = "other")).reasons.join(),
      /capture \d+ is not pass/,
    );
    assert.match(
      edit(index, (c) => (c.caseId = "other")).reasons.join(),
      /capture \d+ is not pass/,
    );
    assert.match(
      edit(index, (c) => (c.authorization = "Bearer other")).reasons.join(),
      /wrong Authorization/,
    );
  }
  // an unmasked token, or a credential on a control, is a wrong Authorization
  assert.match(
    edit(1, (c) => (c.authorization = "Bearer eyJ.x.y")).reasons.join(),
    /wrong Authorization/,
  );
  assert.match(
    edit(0, (c) => (c.authorization = MASKED_TOKEN)).reasons.join(),
    /wrong Authorization/,
  );
  assert.match(edit(5, (c) => (c.authorization = null)).reasons.join(), /wrong Authorization/);
});

test("missing, extra, null and misordered captures are unknown, never an exception", () => {
  const base = run(standard(answers.envelope));
  for (const count of [0, 1, 6, 11, 13]) {
    const list = [...base, ...base].slice(0, count);
    assert.match(judgeRerecord(list, BASELINE).reasons.join(), /expected 12 captures/);
  }
  assert.equal(judgeRerecord(null, BASELINE).verdict, "unknown");
  assert.equal(judgeRerecord({ length: 12 }, BASELINE).verdict, "unknown");
  for (const hole of [null, undefined, {}, 7]) {
    const list = structuredClone(base);
    list[3] = hole;
    assert.match(judgeRerecord(list, BASELINE).reasons.join(), /capture 4 is not/);
  }
  const swapped = structuredClone(base);
  [swapped[5], swapped[6]] = [swapped[6], swapped[5]];
  assert.equal(judgeRerecord(swapped, BASELINE).verdict, "unknown");
});

test("every combination of the judge axes gets the verdict and classes of the stated rule", () => {
  const controls = {
    Recorded: answers.control,
    Page: answers.page,
    Transport: { error: "TypeError: fetch failed" },
  };
  const refusals = { Envelope: answers.envelope, Page: answers.page, Function: answers.control };
  const timings = ["Same", "PageThenEnvelope"];
  const shapes = ["Twelve", "Eleven", "Misordered"];
  let rows = 0;
  for (const [controlName, control] of Object.entries(controls)) {
    for (const [refusalName, refusal] of Object.entries(refusals)) {
      for (const timing of timings) {
        for (const shape of shapes) {
          let list = run((slot) => {
            if (slot.caseId === "no-authorization") return control;
            if (slot.caseId === "valid-project-id-token") return answers.valid;
            if (timing === "PageThenEnvelope" && slot.caseId === "malformed-bearer")
              return slot.pass === 1 ? answers.page : answers.envelope;
            return refusal;
          });
          if (shape === "Eleven") list = list.slice(0, 11);
          if (shape === "Misordered") [list[5], list[6]] = [list[6], list[5]];
          const result = judgeRerecord(list, BASELINE);
          const label = `${controlName}/${refusalName}/${timing}/${shape}`;
          const recorded = controlName === "Recorded" && shape === "Twelve";
          assert.equal(result.verdict, recorded ? "recorded" : "unknown", label);
          assert.equal(result.lockKept, !recorded, label);
          if (recorded) {
            const classOfRefusal = {
              Envelope: "wrapper-envelope",
              Page: "front-end-page",
              Function: "function-answer",
            }[refusalName];
            const malformed = result.rows
              .find((r) => r.caseId === "malformed-bearer")
              .passes.map((p) => p.class);
            assert.deepEqual(
              malformed,
              timing === "PageThenEnvelope"
                ? ["front-end-page", "wrapper-envelope"]
                : [classOfRefusal, classOfRefusal],
              label,
            );
            assert.equal(
              result.timingDiffers.length,
              timing === "PageThenEnvelope" && refusalName !== "Function"
                ? 1
                : timing === "PageThenEnvelope"
                  ? 1
                  : 0,
              label,
            );
          } else assert.deepEqual(result.rows, [], label);
          rows += 1;
        }
      }
    }
  }
  assert.equal(rows, 54);
});

test("property: the class depends only on status, content-type, byte count and digest", () => {
  forAll(
    300,
    (random) => {
      const base = pick(random, Object.values(answers));
      const headers = {};
      for (let i = 0; i < between(random, 0, 5); i += 1)
        headers[pick(random, ["server", "date", "vary", "x-powered-by", "etag", "alt-svc"])] =
          "v".repeat(between(random, 1, 12));
      return { base, headers, index: pick(random, [1, 3, 5, 6, 7, 9, 10, 11]) };
    },
    ({ base, headers, index }) => {
      const plain = classOf(capture(index, base), BASELINE);
      const decorated = classOf(capture(index, { ...base, headers }), BASELINE);
      assert.equal(decorated, plain);
    },
  );
});

test("property: any transport failure or non-2xx/4xx answer anywhere makes the run unknown", () => {
  forAll(
    300,
    (random) => ({
      index: between(random, 0, 11),
      status: pick(random, [100, 102, 300, 307, 500, 502, 503, 599, null]),
    }),
    ({ index, status }) => {
      const list = run(standard(answers.envelope));
      list[index] = capture(
        index,
        status === null
          ? { error: "TypeError: fetch failed" }
          : { status, contentType: "text/plain", bodyText: "b" },
      );
      const result = judgeRerecord(list, BASELINE);
      assert.equal(result.verdict, "unknown");
      assert.equal(result.lockKept, true);
    },
  );
});

// ---- the transport ------------------------------------------------------------------------------------

async function withServer(handler, check) {
  const seen = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      seen.push({
        httpVersion: req.httpVersion,
        rawHeaders: req.rawHeaders,
        method: req.method,
        url: req.url,
        body: Buffer.concat(chunks).toString(),
      });
      handler(req, res, seen.length);
    });
  });
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  try {
    await check(`http://127.0.0.1:${server.address().port}`, seen);
  } finally {
    await new Promise((done) => server.close(done));
  }
}

const init = (authorization) => ({
  method: "POST",
  headers: { "content-type": "application/json", ...(authorization ? { authorization } : {}) },
  body: JSON.stringify({ data: { op: "auth" } }),
  redirect: "manual",
});

test("the transport sends the request head Node's fetch sends, header for header and in the same order", async () => {
  await withServer(
    (req, res) => res.end("ok"),
    async (origin, seen) => {
      const transport = createTransport({ delayMs: 0 });
      await transport.fetchImpl(`${origin}/`, init("Bearer malformed"));
      await transport.fetchImpl(`${origin}/`, init(null));
      await fetch(`${origin}/`, init("Bearer malformed"));
      await fetch(`${origin}/`, init(null));
      transport.close();
      const names = (entry) => entry.rawHeaders.filter((_, i) => i % 2 === 0);
      const values = (entry) => entry.rawHeaders.filter((_, i) => i % 2 === 1);
      assert.deepEqual(names(seen[0]), names(seen[2]));
      assert.deepEqual(names(seen[1]), names(seen[3]));
      const strip = (entry) => values(entry).filter((v) => !v.startsWith("127.0.0.1"));
      assert.deepEqual(strip(seen[0]), strip(seen[2]));
      assert.deepEqual(strip(seen[1]), strip(seen[3]));
      assert.equal(seen[0].httpVersion, "1.1");
      assert.equal(seen[0].body, seen[2].body);
    },
  );
});

test("requestHeaders lists the head in fetch's order and leaves out a missing Authorization", () => {
  assert.deepEqual(
    requestHeaders({
      host: "h",
      headers: { "content-type": "application/json", authorization: "Bearer x" },
      bodyBytes: 22,
    }).map(([n]) => n),
    [
      "host",
      "connection",
      "content-type",
      "authorization",
      "accept",
      "accept-language",
      "sec-fetch-mode",
      "user-agent",
      "accept-encoding",
      "content-length",
    ],
  );
  assert.ok(
    !requestHeaders({
      host: "h",
      headers: { "content-type": "application/json" },
      bodyBytes: 22,
    }).some(([n]) => n === "authorization"),
  );
  assert.deepEqual(
    requestHeaders({ host: "h", headers: { "content-type": "a" }, bodyBytes: 7 }).find(
      ([n]) => n === "content-length",
    ),
    ["content-length", "7"],
  );
});

test("the transport records the version, the head, the response headers in order, server, www-authenticate and the trace header's presence", async () => {
  await withServer(
    (req, res) => {
      res.writeHead(401, [
        ["Content-Type", "application/json; charset=utf-8"],
        ["WWW-Authenticate", 'Bearer error="invalid_token"'],
        ["Server", "Google Frontend"],
        ["X-Cloud-Trace-Context", "abc;o=1"],
        ["Vary", "Origin"],
      ]);
      res.end(ENVELOPE);
    },
    async (origin) => {
      const transport = createTransport({
        delayMs: 0,
        now: () => Date.parse("2026-11-12T00:00:00Z"),
      });
      const response = await transport.fetchImpl(`${origin}/x?y=1`, init("Bearer malformed"));
      transport.close();
      assert.equal(response.status, 401);
      assert.equal(await response.text(), ENVELOPE);
      const extra = response.fireemuExtra;
      assert.equal(extra.sentAt, "2026-11-12T00:00:00.000Z");
      assert.equal(extra.httpVersion, "1.1");
      assert.equal(extra.host, origin.slice("http://".length));
      assert.equal(extra.alpn, null);
      assert.equal(extra.tlsProtocol, null);
      assert.deepEqual(
        extra.responseHeaderNames,
        [
          "content-type",
          "www-authenticate",
          "server",
          "x-cloud-trace-context",
          "vary",
          "date",
          "connection",
          "keep-alive",
          "transfer-encoding",
        ].filter((n) => extra.responseHeaderNames.includes(n)),
      );
      assert.deepEqual(extra.responseHeaderNames.slice(0, 5), [
        "content-type",
        "www-authenticate",
        "server",
        "x-cloud-trace-context",
        "vary",
      ]);
      assert.equal(extra.server, "Google Frontend");
      assert.equal(extra.wwwAuthenticate, 'Bearer error="invalid_token"');
      assert.equal(extra.traceContextPresent, true);
      assert.equal(extra.contentEncoding, null);
      assert.match(
        extra.requestHead,
        /^POST \/x\?y=1 HTTP\/1\.1\r\nhost: 127\.0\.0\.1:\d+\r\nconnection: keep-alive\r\ncontent-type: application\/json\r\nauthorization: Bearer malformed\r\n/,
      );
      assert.ok(extra.requestHead.endsWith("\r\n\r\n"));
    },
  );
  await withServer(
    (req, res) => res.end("x"),
    async (origin) => {
      const transport = createTransport({ delayMs: 0 });
      const response = await transport.fetchImpl(
        `${origin}/`,
        init("Bearer eyJhbGciOi.payload.sig"),
      );
      transport.close();
      assert.ok(
        !response.fireemuExtra.requestHead.includes("eyJhbGciOi"),
        "a token never reaches the recorded head",
      );
      assert.match(response.fireemuExtra.requestHead, /authorization: Bearer \{\{jwt\}\}\r\n/);
      assert.equal(response.fireemuExtra.wwwAuthenticate, null);
      assert.equal(response.fireemuExtra.traceContextPresent, false);
      assert.equal(response.fireemuExtra.server, null);
    },
  );
});

test("a compressed answer is decoded and its content-length is not passed on", async () => {
  const body = gzipSync(Buffer.from(ENVELOPE));
  await withServer(
    (req, res) => {
      res.writeHead(401, {
        "content-type": "application/json",
        "content-encoding": "gzip",
        "content-length": String(body.length),
      });
      res.end(body);
    },
    async (origin) => {
      const transport = createTransport({ delayMs: 0 });
      const response = await transport.fetchImpl(`${origin}/`, init(null));
      transport.close();
      assert.equal(await response.text(), ENVELOPE);
      assert.equal(response.headers.get("content-length"), null);
      assert.equal(response.headers.get("content-encoding"), null);
      assert.equal(response.fireemuExtra.contentEncoding, "gzip");
    },
  );
});

test("the transport pauses once before the first request of each second pass, and nowhere else", async () => {
  await withServer(
    (req, res) => res.end("ok"),
    async (origin) => {
      const slept = [];
      const calls = [];
      const transport = createTransport({
        delayMs: 1234,
        sleep: async (ms) => slept.push([calls.length - 1, ms]),
      });
      for (let i = 0; i < SLOTS.length; i += 1) {
        calls.push(i);
        await transport.fetchImpl(`${origin}/`, init(null));
      }
      transport.close();
      // before request index 2 (auth-context pass 2) and index 8 (auth-refusal pass 2)
      assert.deepEqual(slept, [
        [2, 1234],
        [8, 1234],
      ]);
      assert.equal(PASS_DELAY_MS, 60_000);
    },
  );
});

test("the transport refuses an unsupported scheme, a status outside 200-599 and an oversized body", async () => {
  const transport = createTransport({ delayMs: 0 });
  await assert.rejects(transport.fetchImpl("ftp://127.0.0.1/", init(null)), /unsupported protocol/);
  transport.close();
  await withServer(
    (req, res) => {
      res.writeHead(199);
      res.end();
    },
    async (origin) => {
      const t = createTransport({ delayMs: 0 });
      await assert.rejects(t.fetchImpl(`${origin}/`, init(null)));
      t.close();
    },
  );
  await withServer(
    (req, res) => res.end("x".repeat(70 * 1024)),
    async (origin) => {
      const t = createTransport({ delayMs: 0 });
      await assert.rejects(t.fetchImpl(`${origin}/`, init(null)), /64 KiB/);
      t.close();
    },
  );
  const t = createTransport({ delayMs: 0 });
  await assert.rejects(t.fetchImpl("http://127.0.0.1:1/", init(null)));
  t.close();
});

test("an https request goes through the https module with ALPN limited to http/1.1, a keep-alive agent and the same head", async () => {
  await withServer(
    (req, res) => res.end("ok"),
    async (origin, seen) => {
      const calls = [];
      const agents = [];
      const fakeHttps = {
        Agent: class {
          constructor(options) {
            agents.push(options);
          }
          destroy() {}
        },
        request(options, callback) {
          calls.push(options);
          const plain = { ...options, ALPNProtocols: undefined };
          return http.request(
            { ...plain, hostname: "127.0.0.1", port: new URL(origin).port, agent: undefined },
            callback,
          );
        },
      };
      const transport = createTransport({
        delayMs: 0,
        modules: { "https:": fakeHttps, "http:": http },
      });
      const response = await transport.fetchImpl(
        "https://service-123456789012.us-central1.run.app/",
        init("Bearer malformed"),
      );
      transport.close();
      assert.deepEqual(calls[0].ALPNProtocols, ["http/1.1"]);
      assert.equal(calls[0].hostname, "service-123456789012.us-central1.run.app");
      assert.equal(calls[0].method, "POST");
      assert.equal(calls[0].path, "/");
      assert.deepEqual(agents[0], { keepAlive: true, maxSockets: 1 });
      assert.equal(response.fireemuExtra.host, "service-123456789012.us-central1.run.app");
      assert.equal(seen[0].body, JSON.stringify({ data: { op: "auth" } }));
    },
  );
});

// ---- what a capture records ---------------------------------------------------------------------------------

test("a capture masks the project number in the host and the head, and records the form of the host", () => {
  const extra = {
    sentAt: "t",
    host: "fireemucallableprobe-123456789012.us-central1.run.app",
    httpVersion: "1.1",
    alpn: "http/1.1",
    tlsProtocol: "TLSv1.3",
    requestHead:
      "POST / HTTP/1.1\r\nhost: fireemucallableprobe-123456789012.us-central1.run.app\r\n\r\n",
    responseHeaderNames: ["server"],
    server: "Google Frontend",
    wwwAuthenticate: null,
    traceContextPresent: true,
    contentEncoding: null,
  };
  const record = {};
  enrichCapture(record, { fireemuExtra: extra }, { projectNumber: "123456789012" });
  assert.equal(record.transport.host, "fireemucallableprobe-{{projectNumber}}.us-central1.run.app");
  assert.equal(record.transport.hostForm, "service-{{projectNumber}}.region.run.app");
  assert.ok(!JSON.stringify(record).includes("123456789012"));
  assert.equal(record.transport.alpn, "http/1.1");
  assert.equal(record.transport.tlsProtocol, "TLSv1.3");
  assert.equal(record.transport.traceContextPresent, true);
  // no extra, no change; a failed request (an error without the property) is left alone
  const untouched = { a: 1 };
  enrichCapture(untouched, new Error("x"), { projectNumber: "123456789012" });
  enrichCapture(untouched, undefined, {});
  assert.deepEqual(untouched, { a: 1 });
});

test("the host forms: the number form, the hash form, the cloudfunctions.net form, anything else", () => {
  assert.equal(
    hostForm("svc-{{projectNumber}}.us-central1.run.app"),
    "service-{{projectNumber}}.region.run.app",
  );
  assert.equal(
    hostForm("fireemucallableprobe-abc123xyz-uc.a.run.app"),
    "service-hash-region.a.run.app",
  );
  assert.equal(
    hostForm("us-central1-fireemu-oracle-query.cloudfunctions.net"),
    "region-project.cloudfunctions.net",
  );
  assert.equal(hostForm("127.0.0.1:8080"), "other");
  assert.equal(hostForm("example.com"), "other");
});

test("an Authorization is recorded as a literal or as the shape of a token, never as the token", () => {
  assert.equal(maskAuthorization(null), null);
  assert.equal(maskAuthorization("Bearer malformed"), "Bearer malformed");
  for (const value of ["Bearer eyJ.a.b", "Bearer other", "Basic x", ""]) {
    assert.equal(maskAuthorization(value), MASKED_TOKEN, value);
  }
});

// ---- facts ------------------------------------------------------------------------------------------------

test("function, service and policy facts keep the identifying fields and nothing else", () => {
  const record = {
    name: "projects/p/locations/l/functions/f",
    environment: "GEN_2",
    state: "ACTIVE",
    url: "https://us-central1-fireemu-oracle-query.cloudfunctions.net/fireemuCallableProbe",
    buildConfig: {
      runtime: "nodejs22",
      entryPoint: "fireemuCallableProbe",
      source: { storageSource: { bucket: "b" } },
    },
    serviceConfig: {
      uri: "https://x",
      ingressSettings: "ALLOW_ALL",
      environmentVariables: { A: "1" },
      timeoutSeconds: 10,
    },
    labels: { "deployment-callable": "true", other: "x" },
  };
  const facts = functionFacts(record);
  assert.deepEqual(Object.keys(facts).toSorted(), [
    "buildConfig",
    "environment",
    "labels",
    "serviceConfig",
    "state",
    "url",
  ]);
  assert.deepEqual(facts.buildConfig, { runtime: "nodejs22", entryPoint: "fireemuCallableProbe" });
  assert.deepEqual(facts.serviceConfig, {
    uri: "https://x",
    ingressSettings: "ALLOW_ALL",
    timeoutSeconds: 10,
  });
  assert.deepEqual(facts.labels, { "deployment-callable": "true" });
  assert.deepEqual(
    serviceFacts({
      ingress: "INGRESS_TRAFFIC_ALL",
      invokerIamDisabled: false,
      template: { x: 1 },
      uri: "u",
    }),
    {
      ingress: "INGRESS_TRAFFIC_ALL",
      invokerIamDisabled: false,
      uri: "u",
    },
  );
});

test("the collector records only the replies of the function, service and policy reads, and adds no request", async () => {
  const collector = createFactsCollector();
  const sent = [];
  const control = async (method, url, ...rest) => {
    sent.push([method, url, rest]);
    return {
      status: url.includes("missing") ? 404 : 200,
      value: {
        environment: "GEN_2",
        ingress: "I",
        bindings: [{ role: "roles/run.invoker", members: ["allUsers"] }],
        buildConfig: {},
      },
    };
  };
  const watched = collector.watch(control);
  const base = "projects/fireemu-oracle-query/locations/us-central1";
  await watched(
    "GET",
    `https://cloudfunctions.googleapis.com/v2/${base}/functions/f`,
    undefined,
    "control",
  );
  await watched("GET", `https://run.googleapis.com/v2/${base}/services/f`);
  await watched("GET", `https://run.googleapis.com/v2/${base}/services/f:getIamPolicy`);
  await watched("GET", `https://run.googleapis.com/v2/${base}/services/missing`);
  await watched("POST", `https://run.googleapis.com/v2/${base}/services/f:setIamPolicy`);
  await watched("GET", `https://cloudfunctions.googleapis.com/v2/${base}/functions`);
  assert.equal(collector.facts.functions.length, 1);
  assert.equal(collector.facts.services.length, 1);
  assert.equal(collector.facts.policies.length, 1);
  assert.deepEqual(collector.facts.policies[0].bindings, [
    { role: "roles/run.invoker", members: ["allUsers"] },
  ]);
  assert.equal(sent.length, 6, "every call is passed on once, with its arguments");
  assert.deepEqual(sent[0][2], [undefined, "control"]);
});

// ---- caps, pins, sources ----------------------------------------------------------------------------------

test("the caps of one attempt: two deployments of the bearer recorder's bounds, twelve invocations, six Auth requests", () => {
  assert.deepEqual(CAPS, {
    invocation: 12,
    control: 38,
    cleanup: 74,
    auth: 6,
    cliDeploy: 2,
    cliDelete: 2,
    token: 6,
    upload: 30,
  });
  assert.equal(RESERVED_USD_PER_ATTEMPT, 2);
  const budget = createBudget(CAPS);
  for (let i = 0; i < 12; i += 1) budget.take("invocation");
  assert.throws(() => budget.take("invocation"));
});

test("source pins: the corpus, baselines and the stage 3 fixture are the reviewed bytes", async () => {
  for (const [file, expected] of Object.entries(SOURCE_PINS)) {
    assert.equal(sha(await readFile(here(file))), expected, file);
  }
  assert.deepEqual(Object.keys(SOURCE_PINS).toSorted(), [
    "../bearer-observation.baseline.json",
    "../firebase.json",
    "../fixtures/index.js",
    "../fixtures/package-lock.json",
    "../fixtures/package.json",
    "baseline.json",
    "rerecord.baseline.json",
    "rerecord.corpus.json",
  ]);
});

test("readSources refuses a changed reviewed byte and a Firebase CLI other than 15.28.2", async () => {
  const dir = await mkdtemp(join(tmpdir(), "rerecord-sources-"));
  try {
    const copy = join(dir, "callable-ingress");
    await cp(new URL(".", import.meta.url).pathname, copy, {
      recursive: true,
      filter: (s) => !s.includes("node_modules"),
    });
    for (const file of ["bearer-observation.baseline.json", "firebase.json"])
      await cp(here(`../${file}`), join(dir, file));
    await cp(here("../fixtures"), join(dir, "fixtures"), {
      recursive: true,
      filter: (s) => !s.includes("node_modules"),
    });
    const conformance = join(dir, "conformance");
    await mkdir(join(conformance, "node_modules/firebase-tools"), { recursive: true });
    const cliPackage = join(conformance, "node_modules/firebase-tools/package.json");
    await writeFile(cliPackage, JSON.stringify({ version: "15.28.2" }));
    const good = await readSources({ directory: copy, conformance });
    assert.equal(good.digests.corpus, SOURCE_PINS["rerecord.corpus.json"]);
    assert.equal(good.baseline.frontEndPage.bodyBytes, 294);
    assert.equal(good.baseline.control.bodyBytes, 24);
    assert.equal(good.baseline.wrapperEnvelope.bodyBytes, 66);
    await writeFile(cliPackage, JSON.stringify({ version: "15.28.1" }));
    await assert.rejects(readSources({ directory: copy, conformance }), /15\.28\.2/);
    await writeFile(cliPackage, JSON.stringify({ version: "15.28.2" }));
    for (const file of [
      "rerecord.corpus.json",
      "rerecord.baseline.json",
      "baseline.json",
      "../fixtures/index.js",
      "../firebase.json",
    ]) {
      const path = join(copy, file);
      const original = await readFile(path);
      await writeFile(path, Buffer.concat([original, Buffer.from(" ")]));
      await assert.rejects(
        readSources({ directory: copy, conformance }),
        /reviewed source changed/,
        file,
      );
      await writeFile(path, original);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ---- the whole path in the stage 3 fake world ---------------------------------------------------------------

const CLOUDBUILD =
  "https://cloudbuild.googleapis.com/v1/projects/fireemu-oracle-query/locations/us-central1/builds?pageSize=10";
const row = (fields) => JSON.stringify({ project: "fireemu-oracle-query", ...fields });
const ledgerClosed = row({
  event: "observation-complete-cleanup-verified",
  task: "RTDB-2350",
  recordedAt: "2026-11-11T22:00:00Z",
});
const FAKE_JWT = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.";

async function fakeRun({
  rule = standard(answers.envelope),
  deployScript = FAKE_RECEIPT_SCRIPT("process.exit(0);", 200),
  ledgerText = `${ledgerClosed}\n`,
  useTransport = false,
  failProgram = null,
} = {}) {
  const world = await deployWorld({
    deployScript,
    caps: CAPS,
    functionName: "fireemuCallableProbe",
  });
  const ledger = [];
  const files = {};
  const waits = [];
  const authCalls = [];
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
              createTime: "2026-11-12T00:00:30Z",
              finishTime: "2026-11-12T00:01:10Z",
            },
            {
              id: "b2",
              status: "SUCCESS",
              createTime: "2026-11-12T00:03:30Z",
              finishTime: "2026-11-12T00:04:10Z",
            },
          ],
        },
        bytes: 10,
      };
    }
    if (url.startsWith("https://cloudresourcemanager.googleapis.com/")) {
      world.budget.take(kind);
      return { status: 200, value: { bindings: [] }, bytes: 10 };
    }
    if (url.startsWith("https://identitytoolkit.googleapis.com/")) {
      world.budget.take(kind);
      return { status: 200, value: url.endsWith("accounts:lookup") ? {} : {}, bytes: 2 };
    }
    return world.control(method, url, body, kind, allowed);
  };
  const sent = [];
  let index = 0;
  const plainFetch = async (url, requestInit) => {
    const slot = SLOTS[index];
    index += 1;
    sent.push([
      slot.program.split("/").at(-1),
      slot.pass,
      slot.caseId,
      requestInit.headers.authorization ?? null,
    ]);
    const chosen = rule(slot, index - 1);
    return new Response(chosen.bodyText, {
      status: chosen.status,
      headers: { "content-type": chosen.contentType },
    });
  };
  let transport;
  let loopback;
  if (useTransport) {
    loopback = http.createServer((req, res) => {
      const chosen = rule(SLOTS[index - 1], index - 1);
      res.writeHead(chosen.status, {
        "content-type": chosen.contentType,
        server: "Google Frontend",
        "x-cloud-trace-context": "t;o=1",
      });
      res.end(chosen.bodyText);
    });
    await new Promise((done) => loopback.listen(0, "127.0.0.1", done));
    const fakeHttps = {
      Agent: class {
        destroy() {}
      },
      request(options, callback) {
        index += 0;
        const plain = { ...options, ALPNProtocols: undefined };
        return http.request(
          { ...plain, hostname: "127.0.0.1", port: loopback.address().port, agent: undefined },
          callback,
        );
      },
    };
    let counter = 0;
    transport = createTransport({
      delayMs: 60_000,
      sleep: async (ms) => waits.push([counter - 1, ms]),
      modules: { "https:": fakeHttps, "http:": http },
    });
    const inner = transport.fetchImpl;
    transport.fetchImpl = (url, requestInit) => {
      index = counter + 1;
      counter += 1;
      return inner(url, requestInit);
    };
  }
  const collector = createFactsCollector();
  let clock = Date.parse("2026-11-12T00:00:00Z");
  const user = { localId: "local-1", idToken: FAKE_JWT, email: "u@example.com" };
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
    createControl: () => collector.watch(restControl),
    openUploads: () => world.uploads,
    run: world.run,
    fetchImpl: transport ? transport.fetchImpl : plainFetch,
    auth: {
      readKey: async () => JSON.stringify({ keyString: "k".repeat(24) }),
      createUser: async (_key, budget, _runDir, programId) => {
        budget.take("auth");
        authCalls.push(["createUser", programId]);
        if (failProgram === programId) throw new Error("Auth signUp returned 400");
        return { ...user, idToken: `${FAKE_JWT}x` };
      },
      waitForExpiry: async (token) => {
        authCalls.push(["waitForExpiry", token]);
      },
    },
    installSignals: () => {},
    log: () => {},
    warn: () => {},
  };
  const result = await recordRerecord({}, deps, collector);
  transport?.close();
  loopback?.close();
  return { world, result, ledger, files, sent, waits, collector, authCalls };
}

test("fake world: the whole path records twelve answers over two deployments, cleans up and writes two ledger lines", async () => {
  const { world, result, ledger, files, sent } = await fakeRun();
  try {
    assert.equal(result.verdict, "recorded", files["judgement.json"]);
    assert.equal(result.outcome, "recorded", ledger[1]?.reason);
    assert.equal(result.exitCode, 0);
    assert.deepEqual(
      ledger.map((line) => [line.event, line.taskId, line.attempt]),
      [
        ["started", TASK_ID, 1],
        ["finished", TASK_ID, 1],
      ],
    );
    const [started, terminal] = ledger;
    assert.equal(started.reservedUsd, 2);
    assert.equal(started.cumulativeReservedUsd, 2);
    assert.equal(terminal.closureReady, true);
    assert.equal(terminal.lockKept, false);
    assert.equal(terminal.needsReview, true);
    assert.equal(terminal.requests.invocation, 12);
    assert.equal(terminal.requests.cliDeploy, 2);
    assert.equal(terminal.requests.cliDelete, 2);
    assert.equal(terminal.requests.auth, 6, "a user per program: created, deleted, looked up");
    assert.equal(terminal.estimatedUsd, 1.13);
    for (const [kind, cap] of Object.entries(CAPS)) {
      assert.ok(terminal.requests[kind] <= cap, `${kind} ${terminal.requests[kind]} <= ${cap}`);
    }
    assert.deepEqual(terminal.rows[3], [
      "auth-refusal",
      "malformed-bearer",
      [
        ["wrapper-envelope", 401, 66],
        ["wrapper-envelope", 401, 66],
      ],
    ]);
    assert.deepEqual(terminal.timingDiffers, []);
    assert.deepEqual(
      sent.map(([program, pass, caseId, authorization]) => [
        program,
        pass,
        caseId,
        authorization === null
          ? null
          : authorization.startsWith("Bearer eyJ")
            ? "token"
            : authorization,
      ]),
      SLOTS.map((slot) => [
        slot.program.split("/").at(-1),
        slot.pass,
        slot.caseId,
        slot.caseId === "no-authorization"
          ? null
          : slot.caseId === "malformed-bearer"
            ? "Bearer malformed"
            : "token",
      ]),
    );
    const captures = JSON.parse(files["captures.json"]);
    assert.equal(captures.length, 12);
    assert.ok(
      captures.every(
        (c) =>
          c.authorization === null ||
          c.authorization === "Bearer malformed" ||
          c.authorization === MASKED_TOKEN,
      ),
    );
    assert.deepEqual(
      world.argv.filter((a) => a[0] === "deploy").map((a) => a.at(-1)),
      [
        "functions:functions-http-oracle:fireemuCallableProbe",
        "functions:functions-http-oracle:fireemuCallableProbe",
      ],
    );
    assert.equal(JSON.parse(files["judgement.json"]).verdict, "recorded");
    assert.ok("facts.json" in files, "the facts file is written");
    assert.deepEqual(
      JSON.parse(files["builds.json"]).builds.map((b) => b.id),
      ["b1", "b2"],
    );
    for (const text of Object.values(files)) {
      assert.ok(
        !text.includes("123456789012") &&
          !text.includes("REFRESH-SECRET") &&
          !text.includes(FAKE_JWT),
      );
    }
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("fake world: a user is made for each program, the wait for expiry is only for auth-refusal, and the user is deleted and read back", async () => {
  const { world, files, authCalls } = await fakeRun();
  try {
    assert.deepEqual(authCalls, [
      ["createUser", "functions-http/callable/auth-context"],
      ["createUser", "functions-http/callable/auth-refusal"],
      ["waitForExpiry", `${FAKE_JWT}x`],
    ]);
    const actions = files["changes.jsonl"]
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line).action);
    assert.equal(
      actions.filter((a) => a === "auth-user-deleted").length,
      2,
      "each user is deleted through the run's own log",
    );
    assert.equal(actions.filter((a) => a === "function-deleted").length, 2);
    assert.equal(actions.filter((a) => a === "function-deployed").length, 2);
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("createUser logs through the log it is given and never writes the sandbox ledger", async () => {
  const { createUser } = await import("../production.mjs");
  const dir = await mkdtemp(join(tmpdir(), "rerecord-user-"));
  const original = globalThis.fetch;
  try {
    const payload = Buffer.from(
      JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 3600 }),
    ).toString("base64url");
    const token = `e30.${payload}.sig`;
    globalThis.fetch = async (url) => {
      assert.match(String(url), /accounts:signUp/);
      return Response.json({ localId: "l1", idToken: token, email: "x@example.com" });
    };
    const logged = [];
    const user = await createUser(
      "k".repeat(24),
      createBudget(CAPS),
      dir,
      "program-x",
      async (action, detail) => logged.push([action, detail]),
    );
    assert.equal(user.localId, "l1");
    assert.deepEqual(logged, [["auth-user-created", "program-x; owned user journaled privately"]]);
    assert.match(await readFile(join(dir, "owned-users.jsonl"), "utf8"), /signup-accepted/);
  } finally {
    globalThis.fetch = original;
    await rm(dir, { recursive: true, force: true });
  }
});

test("fake world: with the real transport the captures carry the transport facts and the pass delay is taken twice", async () => {
  const { world, result, files, waits } = await fakeRun({ useTransport: true });
  try {
    assert.equal(result.verdict, "recorded", files["judgement.json"]);
    assert.deepEqual(waits, [
      [2, 60_000],
      [8, 60_000],
    ]);
    const captures = JSON.parse(files["captures.json"]);
    for (const recorded of captures) {
      assert.equal(recorded.transport.httpVersion, "1.1");
      assert.equal(recorded.transport.server, "Google Frontend");
      assert.equal(recorded.transport.traceContextPresent, true);
      assert.equal(recorded.transport.wwwAuthenticate, null);
      assert.equal(recorded.transport.host, "fireemucallableprobe-abc-uc.a.run.app");
      assert.equal(recorded.transport.hostForm, "service-hash-region.a.run.app");
      assert.ok(
        recorded.transport.requestHead.startsWith(
          "POST / HTTP/1.1\r\nhost: fireemucallableprobe-abc-uc.a.run.app\r\n",
        ),
      );
    }
    assert.ok(!files["captures.json"].includes(FAKE_JWT));
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("fake world: the facts file holds the function, service and policy fields and the project number nowhere", async () => {
  const { world, files, collector } = await fakeRun();
  try {
    const facts = JSON.parse(files["facts.json"]);
    assert.ok(facts.functions.length >= 2, "the function is read at least once per deployment");
    assert.equal(facts.functions[0].environment, "GEN_2");
    assert.equal(facts.functions[0].buildConfig.entryPoint, "fireemuCallableProbe");
    assert.ok(facts.services.length >= 2);
    assert.ok(facts.policies.length >= 2);
    assert.equal(collector.facts.functions.length, facts.functions.length);
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("fake world: a front-end page on the refusal rows is recorded, not refused, and a pass difference is named", async () => {
  const { world, result, ledger } = await fakeRun({
    rule: (slot) =>
      standard(answers.envelope)(slot).bodyText === ENVELOPE &&
      slot.caseId === "malformed-bearer" &&
      slot.pass === 1
        ? answers.page
        : standard(answers.envelope)(slot),
  });
  try {
    assert.equal(result.outcome, "recorded");
    assert.deepEqual(ledger[1].timingDiffers, ["auth-refusal#malformed-bearer"]);
    assert.equal(ledger[1].closureReady, true);
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("fake world: a control that is refused is an unknown run, cleaned, with the lock kept", async () => {
  const { world, result, ledger } = await fakeRun({
    rule: (slot) =>
      slot.caseId === "no-authorization" ? answers.page : standard(answers.envelope)(slot),
  });
  try {
    assert.equal(result.verdict, "unknown");
    assert.equal(result.outcome, "observed-unknown");
    assert.equal(ledger[1].lockKept, true);
    assert.equal(ledger[1].requests.cliDelete, 2, "both functions were deleted");
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("fake world: a program that fails stops the run, and the next program is not deployed", async () => {
  const { world, result, ledger } = await fakeRun({
    failProgram: "functions-http/callable/auth-context",
  });
  try {
    assert.equal(result.verdict, "unknown");
    assert.equal(
      ledger[1].requests.cliDeploy,
      0,
      "the user was refused before the first deployment",
    );
    assert.match(ledger[1].reason, /auth-context: cleanup requires review/);
    assert.equal(ledger[1].requests.invocation, 0);
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
    assert.equal(ledger[1].closureReady, false);
    assert.equal(ledger[1].lockKept, true);
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("fake world: admission counts this task's rows and refuses before any request", async () => {
  const own = (n) => [
    row({ event: "started", taskId: TASK_ID, attempt: n, ts: "2026-11-11T09:00:00Z" }),
    row({ event: "finished", outcome: "recorded", taskId: TASK_ID, ts: "2026-11-11T09:30:00Z" }),
  ];
  await assert.rejects(
    fakeRun({ ledgerText: `${[...own(1), ...own(2), ...own(3), ledgerClosed].join("\n")}\n` }),
    /attempt 4/,
  );
  const insert = `${[
    row({
      event: "started",
      taskId: "FUNCTIONS-HTTP-CALLABLE-INGRESS",
      ts: "2026-11-11T09:00:00Z",
    }),
    row({
      event: "finished",
      outcome: "recorded",
      taskId: "FUNCTIONS-HTTP-CALLABLE-INGRESS",
      ts: "2026-11-11T09:30:00Z",
    }),
    ledgerClosed,
  ].join("\n")}\n`;
  const ok = await fakeRun({ ledgerText: insert });
  try {
    assert.equal(ok.ledger[0].attempt, 1);
  } finally {
    await rm(ok.world.dir, { recursive: true, force: true });
  }
  await assert.rejects(
    fakeRun({
      ledgerText: `${row({ event: "started", task: "X", recordedAt: "2026-11-12T00:00:00Z" })}\n`,
    }),
    /does not close its run/,
  );
  assert.deepEqual(
    admit({
      ledgerText: `${ledgerClosed}\n`,
      now: Date.parse("2026-11-12T01:00:00Z"),
      env: {},
      taskId: TASK_ID,
    }),
    { attempt: 1 },
  );
});

test("the spec carries the ledger reservation, the slots and the masks", () => {
  const spec = rerecordSpec(undefined);
  assert.equal(spec.taskId, TASK_ID);
  assert.equal(spec.reservedUsd, 2);
  assert.equal(spec.slots, SLOTS);
  assert.equal(spec.maskAuthorization, maskAuthorization);
  assert.equal(spec.enrichCapture, enrichCapture);
  assert.deepEqual(spec.extraFiles({ projectNumber: "1" }), {});
  assert.deepEqual(spec.startFields(), {});
  const collector = createFactsCollector();
  collector.facts.functions.push({ url: "https://svc-123456789012.run.app" });
  assert.deepEqual(rerecordSpec(collector).extraFiles({ projectNumber: "123456789012" }), {
    "facts.json": {
      functions: [{ url: "https://svc-{{projectNumber}}.run.app" }],
      services: [],
      policies: [],
    },
  });
});

test("productionDeps writes the run files and ledger lines of this recorder byte-equal, and never overwrites", async () => {
  const root = await mkdtemp(join(tmpdir(), "rerecord-write-"));
  try {
    const ledger = join(root, "sandbox-ledger.jsonl");
    const { deps, close } = productionDeps({ ledger, privateRoot: root });
    await mkdir(join(root, "runs"));
    const runDir = await deps.makeRunDir("callable-rerecord-test");
    assert.equal(runDir, join(root, "runs", "callable-rerecord-test"));
    await assert.rejects(deps.makeRunDir("callable-rerecord-test"), /EEXIST/);
    const list = run(standard(answers.envelope));
    const capturesText = `${JSON.stringify(list, null, 2)}\n`;
    await deps.writeRunFile(runDir, "captures.json", capturesText);
    assert.equal(await readFile(join(runDir, "captures.json"), "utf8"), capturesText);
    await assert.rejects(deps.writeRunFile(runDir, "captures.json", "x"), /EEXIST/);
    await writeFile(ledger, '{"existing":1}\n');
    const line = `${JSON.stringify({ event: "started", taskId: TASK_ID })}\n`;
    await deps.appendLedger(line);
    assert.equal(await deps.readLedger(), `{"existing":1}\n${line}`);
    const budget = deps.createBudget();
    for (let i = 0; i < 12; i += 1) budget.take("invocation");
    assert.throws(() => budget.take("invocation"));
    close();
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("productionDeps reads the reviewed sources", async () => {
  const { deps, close } = productionDeps();
  const sources = await deps.readSources();
  assert.equal(validateRerecordCorpus(sources.corpus).length, 2);
  assert.equal(typeof deps.fetchImpl, "function");
  close();
});
