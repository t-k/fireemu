import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  answerFamily,
  channelIdOf,
  classifyPair,
  cloudEventSize,
  compareAnswer,
  comparePair,
  diffPaths,
  isServiceDisabled,
  loadRows,
  main,
  maskEcho,
  maskRequestIds,
  maskRun,
  maskSizes,
  publishRequestSize,
  publishedChannel,
  replay,
  requestBody,
  runIdOf,
  sameJson,
  sizesFollowRequest,
  skipReason,
  summarize,
  tokenModes,
} from "./eventarc-production/compare.mjs";

const fixture = JSON.parse(
  readFileSync(
    new URL("./eventarc-production/fixtures/stage-a-001/publish-size-rows.json", import.meta.url),
    "utf8",
  ),
);
const row = (recording, n) => fixture.find((item) => item.recording === recording && item.n === n);
const sizeOf = (r) => Number(/\((\d+) bytes\)/.exec(JSON.stringify(r.response.body))[1]);
const RUN = "0123456789ab";

test("the size the publishing API reports is the serialized size of the whole request, reproduced for every recorded row", () => {
  // The four recorded rows of the second recording and the three of the first with a size in the answer.
  for (const [recording, n] of [
    ["r2", 63],
    ["r2", 64],
    ["r2", 65],
    ["r2", 67],
    ["r1", 74],
    ["r1", 75],
    ["r1", 76],
    ["r1", 78],
  ]) {
    const r = row(recording, n);
    assert.ok(r, `${recording} ${n}`);
    const body = requestBody(r);
    assert.notEqual(body, null);
    const channel = publishedChannel(r.request.path);
    assert.equal(publishRequestSize(channel, body.events), sizeOf(r), `${recording} row ${n}`);
    assert.equal(sizesFollowRequest(r), true);
  }
  // Rows without a byte count follow trivially, and a count that is not the request's size does not.
  assert.equal(sizesFollowRequest(row("r2", 62)), true);
  const forged = structuredClone(row("r2", 63));
  forged.response.body.error.message = forged.response.body.error.message.replace(
    "1048883",
    "1048882",
  );
  assert.equal(sizesFollowRequest(forged), false);
});

test("the pieces of the size: a varint grows at 128, a tag is one byte, a timestamp counts only what is not zero", () => {
  const event = { id: "a", source: "b", specVersion: "1.0", type: "t" };
  // id, source, specVersion, type: 3 + 3 + 5 + 3 bytes (tag, length, text).
  assert.equal(cloudEventSize(event), 14);
  assert.equal(cloudEventSize({ ...event, id: "a".repeat(127) }), 14 - 3 + 129);
  assert.equal(cloudEventSize({ ...event, id: "a".repeat(128) }), 14 - 3 + 131);
  assert.equal(cloudEventSize({ ...event, textData: "xyz" }), 14 + 5);
  // An attribute: map entry { key, value { string } }.
  const withAttribute = { ...event, attributes: { k: { ceString: "v" } } };
  // key "k": 3 bytes; value: a string field of 3 bytes inside a 5-byte message field; the entry is 10 bytes.
  assert.equal(cloudEventSize(withAttribute), 14 + 10);
  // The epoch has neither seconds nor nanos: an empty Timestamp message.
  const epoch = { ...event, attributes: { t: { ceTimestamp: "1970-01-01T00:00:00Z" } } };
  assert.equal(cloudEventSize(epoch), 14 + 9);
  assert.equal(cloudEventSize({ ...event, attributes: { t: { ceTimestamp: "nope" } } }), null);
  assert.equal(cloudEventSize({ ...event, attributes: { t: { ceBoolean: true } } }), null);
  assert.equal(cloudEventSize({ ...event, binaryData: "AAEC" }), null);
  assert.equal(cloudEventSize({ ...event, id: 5 }), null);
  assert.equal(
    publishRequestSize("projects/p/locations/l/channels/c", [event, { ...event, id: 5 }]),
    null,
  );
  assert.equal(
    publishedChannel("/v1/projects/p/locations/l/channels/c:publishEvents"),
    "projects/p/locations/l/channels/c",
  );
  assert.equal(
    publishedChannel("/projects/p/locations/l/channels/c:publishEvents"),
    "projects/p/locations/l/channels/c",
  );
  assert.equal(publishedChannel("/v1/projects/p/locations/l/channels/c"), null);
});

test("omitted text is rebuilt from its length and refused unless it matches the recorded digest", () => {
  const text = JSON.stringify("x".repeat(30));
  const good = {
    request: {
      body: {
        events: [
          {
            textData: {
              omitted: {
                length: text.length,
                sha256: createHash("sha256").update(text).digest("hex"),
              },
            },
          },
        ],
      },
    },
  };
  assert.equal(requestBody(good).events[0].textData, text);
  const bad = structuredClone(good);
  bad.request.body.events[0].textData.omitted.sha256 = "0".repeat(64);
  assert.equal(requestBody(bad), null);
  const wrongLength = structuredClone(good);
  wrongLength.request.body.events[0].textData.omitted.length += 1;
  assert.equal(requestBody(wrongLength), null);
  assert.equal(requestBody({ request: { method: "GET", path: "/x" } }), undefined);
  assert.equal(
    skipReason({ op: "createChannel", request: { body: bad.request.body }, response: {} }),
    "unreplayable-body",
  );
  assert.equal(requestBody({ request: { body: { a: [1, { b: "c" }] } } }).a[1].b, "c");
});

test("the credential of the first six requests of auth-errors is default, none, none, invalid, invalid, none; every other request has the default", () => {
  const rows = [
    { case: "service-state" },
    ...Array.from({ length: 8 }, () => ({ case: "auth-errors" })),
    { case: "cleanup" },
  ];
  assert.deepEqual(tokenModes(rows), [
    "default",
    "default",
    "none",
    "none",
    "invalid",
    "invalid",
    "none",
    "default",
    "default",
    "default",
  ]);
});

test("the masks hide the request ID, the run ID in either case, a byte count and the echoed channel ID, and nothing else", () => {
  const answer = {
    error: {
      message: `Resource 'x-${RUN}-y' and ${RUN.toUpperCase()} (12 bytes) c1`,
      details: [
        { requestId: "0123456789abcdef" },
        { requestId: "short" },
        { other: "0123456789abcdef" },
      ],
    },
  };
  assert.deepEqual(maskRequestIds(answer).error.details, [
    { requestId: "<requestId>" },
    { requestId: "short" },
    { other: "0123456789abcdef" },
  ]);
  assert.equal(maskRun(answer, RUN).error.message, "Resource 'x-<run>-y' and <RUN> (12 bytes) c1");
  assert.equal(maskSizes(answer).error.message.includes("(<size> bytes)"), true);
  assert.equal(maskEcho("a c1 b", "c1"), "a <id> b");
  assert.equal(maskEcho("a c1 b", null), "a c1 b");
  assert.equal(maskEcho("a c1 b", ""), "a c1 b");
  assert.equal(maskEcho(["c1", { k: "c1" }], "c1")[1].k, "<id>");
  assert.equal(maskRun(5, RUN), 5);
  assert.equal(channelIdOf({ path: "/v1/projects/p/locations/l/channels?channelId=abc" }), "abc");
  assert.equal(
    channelIdOf({ path: "/v1/projects/p/locations/l/channels/xyz:publishEvents" }),
    "xyz",
  );
  assert.equal(channelIdOf({ path: "/v1/projects/p/locations/l/channels" }), null);
});

test("JSON equality ignores member order, and the differing paths are named", () => {
  assert.equal(sameJson({ a: 1, b: [1, { c: 2 }] }, { b: [1, { c: 2 }], a: 1 }), true);
  assert.equal(sameJson({ a: 1 }, { a: 1, b: 2 }), false);
  assert.equal(sameJson([1], { 0: 1 }), false);
  assert.equal(sameJson(null, {}), false);
  assert.equal(sameJson([1, 2], [1]), false);
  assert.deepEqual(diffPaths({ a: { b: 1, c: 2 } }, { a: { b: 1, c: 3 }, d: 4 }), ["$.a.c", "$.d"]);
  assert.deepEqual(diffPaths([1, 2], [1, 3]), ["$.1"]);
  assert.deepEqual(diffPaths({ a: 1 }, [1]), ["$"]);
});

const answered = (status, body) => ({ status, body });
const entry = (overrides) => ({
  n: 1,
  case: "channel-lifecycle",
  op: "createChannel",
  request: {
    method: "POST",
    path: "/v1/projects/p/locations/us-central1/channels?channelId=c",
    body: {},
  },
  response: answered(400, { error: { code: 400, details: [{ requestId: "0123456789abcdef" }] } }),
  ...overrides,
});

test("two rows are identical, masked, different because of the state of the project, or different", () => {
  const same = classifyPair(entry({}), entry({}), "aaaaaaaaaaaa", "bbbbbbbbbbbb");
  assert.deepEqual(same, { kind: "identical", paths: [] });
  const other = entry({
    response: answered(400, { error: { code: 400, details: [{ requestId: "fedcba9876543210" }] } }),
  });
  const masked = classifyPair(entry({}), other, "aaaaaaaaaaaa", "bbbbbbbbbbbb");
  assert.equal(masked.kind, "masked");
  assert.deepEqual(masked.paths, ["$.body.error.details.0.requestId"]);
  const named = (id) =>
    entry({
      request: { method: "GET", path: `/v1/projects/p/locations/l/channels/${id}` },
      response: answered(404, { error: { message: `Resource '${id}' was not found` } }),
    });
  assert.equal(
    classifyPair(named("ad"), named("a9"), "aaaaaaaaaaaa", "bbbbbbbbbbbb").kind,
    "masked",
  );
  const run = (id) => entry({ response: answered(404, { error: { message: `no fe${id}-x` } }) });
  assert.equal(
    classifyPair(run("aaaaaaaaaaaa"), run("bbbbbbbbbbbb"), "aaaaaaaaaaaa", "bbbbbbbbbbbb").kind,
    "identical",
  );
  const enabled = entry({
    case: "service-state",
    response: answered(403, { error: { code: 403 } }),
  });
  const disabled = entry({
    case: "service-state",
    response: answered(404, { error: { code: 404 } }),
  });
  assert.equal(classifyPair(enabled, disabled, "aaaaaaaaaaaa", "bbbbbbbbbbbb").kind, "state");
  const apart = entry({ response: answered(404, { error: { code: 404 } }) });
  assert.equal(classifyPair(entry({}), apart, "aaaaaaaaaaaa", "bbbbbbbbbbbb").kind, "different");
  // Byte counts that follow their own requests are masked; a count that does not is a difference.
  const [a, b] = [row("r2", 63), row("r1", 74)];
  assert.equal(classifyPair(a, b, "9e560c404162", "d011709742b6").kind, "masked");
  const forged = structuredClone(b);
  forged.response.body.error.message = forged.response.body.error.message.replace(
    "1048882",
    "1048999",
  );
  assert.equal(classifyPair(a, forged, "9e560c404162", "d011709742b6").kind, "different");
});

test("two recordings are aligned by case, operation and position, and a row in only one is unpaired outside service-state", () => {
  const a = [
    entry({ n: 1 }),
    entry({ n: 2 }),
    entry({ n: 3, case: "service-state", op: "getChannel" }),
  ];
  const b = [entry({ n: 1 }), entry({ n: 2, case: "publish-envelope" })];
  const rows = comparePair(a, b, "aaaaaaaaaaaa", "bbbbbbbbbbbb");
  assert.deepEqual(
    rows.map((item) => [item.key, item.kind]),
    [
      ["channel-lifecycle/createChannel#0", "identical"],
      ["channel-lifecycle/createChannel#1", "unpaired"],
      ["service-state/getChannel#0", "state"],
      ["publish-envelope/createChannel#0", "unpaired"],
    ],
  );
  assert.deepEqual(rows[0].a, 1);
  assert.equal(rows[3].a, null);
});

test("the Service Usage rows and the publishes answered while the API was disabled are skipped, not replayed", () => {
  for (const op of ["getService", "enableService", "listEnabledServices", "getOperation"])
    assert.equal(skipReason({ op, request: {}, response: {} }), "service-usage");
  const disabled = {
    op: "publishEvents",
    request: { body: {} },
    response: answered(403, { error: { details: [{ reason: "SERVICE_DISABLED" }] } }),
  };
  assert.equal(isServiceDisabled(disabled), true);
  assert.equal(skipReason(disabled), "service-disabled");
  const refused = {
    ...disabled,
    response: answered(403, { error: { details: [{ reason: "CONSUMER_INVALID" }] } }),
  };
  assert.equal(isServiceDisabled(refused), false);
  assert.equal(skipReason(refused), null);
  assert.equal(isServiceDisabled({ response: { status: 500, body: null } }), false);
});

test("an answer family names the status, the canonical status and the message with its numbers and names removed", () => {
  assert.equal(answerFamily(answered(200, {})), "200 {}");
  assert.equal(answerFamily(answered(200, null)), "200");
  assert.equal(
    answerFamily(
      answered(403, {
        error: {
          status: "PERMISSION_DENIED",
          message: "Permission denied on resource project fireemu-no-such-project-0.",
        },
      }),
    ),
    "403 PERMISSION_DENIED Permission denied on resource projects/<p>.".replace(
      "projects/<p>",
      "project fireemu-no-such-project-<n>",
    ),
  );
  assert.equal(
    answerFamily(
      answered(404, {
        error: { status: "NOT_FOUND", message: "Resource 'projects/p/x' was not found" },
      }),
    ),
    "404 NOT_FOUND Resource '<x>' was not found",
  );
});

test("an answer matches when the status and the body agree after the request ID is masked", () => {
  const recorded = answered(400, {
    error: { code: 400, details: [{ requestId: "0123456789abcdef" }] },
  });
  assert.deepEqual(
    compareAnswer(
      recorded,
      answered(400, { error: { code: 400, details: [{ requestId: "fedcba9876543210" }] } }),
    ),
    { verdict: "match", paths: [] },
  );
  assert.deepEqual(compareAnswer(recorded, answered(404, null)), {
    verdict: "diverge",
    reason: "status",
    paths: ["$.status"],
  });
  assert.deepEqual(compareAnswer(answered(200, {}), answered(200, { raw: "OK" })), {
    verdict: "diverge",
    reason: "body",
    paths: ["$.body.raw"],
  });
  assert.deepEqual(compareAnswer(answered(200, null), answered(200, null)), {
    verdict: "match",
    paths: [],
  });
});

async function listener(handler) {
  const seen = [];
  const server = createServer(async (request, response) => {
    let body = "";
    for await (const chunk of request) body += chunk;
    seen.push({
      method: request.method,
      url: request.url,
      authorization: request.headers.authorization,
      contentType: request.headers["content-type"],
      body,
    });
    const answer = handler(seen.at(-1));
    response.statusCode = answer.status;
    response.end(answer.text);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { seen, base: `http://127.0.0.1:${server.address().port}`, close: () => server.close() };
}

test("a replay sends each row with its credential, skips what a local listener does not serve, and reports every divergence", async (t) => {
  const server = await listener(({ url }) =>
    url.includes("channels/x")
      ? { status: 404, text: JSON.stringify({ error: { code: 404 } }) }
      : { status: 200, text: "OK" },
  );
  t.after(server.close);
  const rows = [
    {
      n: 1,
      case: "service-state",
      op: "getService",
      request: { method: "GET", path: "/v1/s" },
      response: answered(200, {}),
    },
    ...[2, 3, 4, 5, 6, 7].map((n) => ({
      n,
      case: "auth-errors",
      op: "listChannels",
      request: { method: "GET", path: "/v1/projects/p/locations/l/channels" },
      response: answered(401, null),
    })),
    {
      n: 8,
      case: "channel-lifecycle",
      op: "getChannel",
      request: { method: "GET", path: "/v1/projects/p/locations/l/channels/x" },
      response: answered(404, { error: { code: 404 } }),
    },
    {
      n: 9,
      case: "channel-lifecycle",
      op: "createChannel",
      request: {
        method: "POST",
        path: "/v1/projects/p/locations/l/channels?channelId=c",
        body: {},
      },
      response: answered(400, { error: { code: 400 } }),
    },
  ];
  const results = await replay(rows, { base: server.base });
  assert.deepEqual(
    results.map((result) => [result.n, result.verdict, result.reason ?? ""]),
    [
      [1, "skipped", "service-usage"],
      [2, "diverge", "status"],
      [3, "diverge", "status"],
      [4, "diverge", "status"],
      [5, "diverge", "status"],
      [6, "diverge", "status"],
      [7, "diverge", "status"],
      [8, "match", ""],
      [9, "diverge", "status"],
    ],
  );
  assert.deepEqual(
    server.seen.map((item) => item.authorization),
    [
      "Bearer replay-token",
      undefined,
      undefined,
      "Bearer invalid-token-for-the-recording",
      "Bearer invalid-token-for-the-recording",
      undefined,
      "Bearer replay-token",
      "Bearer replay-token",
    ],
  );
  assert.equal(server.seen.at(-1).body, "{}");
  assert.equal(server.seen[0].body, "");
  assert.deepEqual(results[1].actual, { status: 200, body: { raw: "OK" } });
  const summary = summarize(results);
  assert.deepEqual(summary.total, { skipped: 1, diverge: 7, match: 1 });
  assert.equal(summary.families["401"].diverge, 6);
  const dead = await replay([rows[7]], { base: "http://127.0.0.1:1" });
  assert.match(dead[0].reason, /^transport: /);
});

test("a replay can drop the /v1 of the path, as the Admin SDK does against an emulator host", async (t) => {
  const server = await listener(() => ({ status: 200, text: "OK" }));
  t.after(server.close);
  const rows = [entry({ request: { method: "GET", path: "/v1/projects/p/locations/l/channels" } })];
  await replay(rows, { base: server.base });
  await replay(rows, { base: server.base, stripV1: true });
  await replay([entry({ request: { method: "GET", path: "/v10/projects/p" } })], {
    base: server.base,
    stripV1: true,
  });
  assert.deepEqual(
    server.seen.map((item) => item.url),
    ["/v1/projects/p/locations/l/channels", "/projects/p/locations/l/channels", "/v10/projects/p"],
  );
});

test("the command line pairs two captures and replays one, and refuses a call without its arguments", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "eventarc-compare-"));
  const capture = (runId, requestId) => {
    const path = join(dir, `capture-${runId}.jsonl`);
    const lines = [
      { at: "x", note: "run-start", runId },
      entry({ response: answered(400, { error: { code: 400, details: [{ requestId }] } }) }),
    ];
    writeFileSync(path, `${lines.map((line) => JSON.stringify(line)).join("\n")}\n`);
    return path;
  };
  const a = capture("aaaaaaaaaaaa", "0123456789abcdef");
  const b = capture("bbbbbbbbbbbb", "fedcba9876543210");
  assert.equal(runIdOf(a), "aaaaaaaaaaaa");
  assert.equal(loadRows(a).length, 1);
  assert.throws(() => runIdOf(join(dir, "missing")), /ENOENT/);
  writeFileSync(join(dir, "empty.jsonl"), "{}\n");
  assert.throws(() => runIdOf(join(dir, "empty.jsonl")), /no run-start note/);
  let printed = "";
  const io = {
    stdout: { write: (text) => (printed += text) },
    stderr: { write: (text) => (printed += text) },
  };
  assert.equal(await main(["pair", "--a", a, "--b", b], io), 0);
  const report = JSON.parse(printed);
  assert.deepEqual(report.counts, { masked: 1 });
  assert.equal(report.rows.length, 1);
  printed = "";
  assert.equal(await main(["pair", "--a", a], io), 2);
  assert.match(printed, /pair needs --a and --b/);
  printed = "";
  assert.equal(await main(["replay", "--capture", a], io), 2);
  assert.match(printed, /replay needs --capture, --base and --profile/);
  printed = "";
  assert.equal(await main(["nothing"], io), 2);
  const server = await listener(() => ({
    status: 400,
    text: JSON.stringify({ error: { code: 400, details: [{ requestId: "ffffffffffffffff" }] } }),
  }));
  t.after(server.close);
  const out = join(dir, "report.json");
  printed = "";
  assert.equal(
    await main(
      ["replay", "--capture", a, "--base", server.base, "--profile", "strict", "--out", out],
      io,
    ),
    0,
  );
  const replayed = JSON.parse(readFileSync(out, "utf8"));
  assert.equal(replayed.profile, "strict");
  assert.deepEqual(replayed.total, { match: 1 });
  assert.equal(printed, "");
});

test("a length field grows a byte at 128, 16384 and 2097152, and an epoch second grows at 2^28", () => {
  const event = { id: "a", source: "b", specVersion: "1.0", type: "t" };
  const base = cloudEventSize(event) - 3;
  for (const [length, prefix] of [
    [127, 1],
    [128, 2],
    [16_383, 2],
    [16_384, 3],
    [2_097_151, 3],
    [2_097_152, 4],
  ])
    assert.equal(
      cloudEventSize({ ...event, id: "a".repeat(length) }),
      base + 1 + prefix + length,
      length,
    );
  // 2^28 seconds is the first value that needs five bytes: 1978-07-04T21:24:16Z.
  const at = (text) => cloudEventSize({ ...event, attributes: { t: { ceTimestamp: text } } });
  assert.equal(at("1978-07-04T21:24:15Z") + 1, at("1978-07-04T21:24:16Z"));
  assert.equal(
    cloudEventSize({ id: "a", source: "b", specVersion: "1.0" }),
    11,
    "a member that is absent counts nothing",
  );
  assert.equal(
    cloudEventSize({ ...event, type: "" }),
    11,
    "and an empty one counts nothing either",
  );
});

test("a byte count follows its request only for a publish whose body is known", () => {
  const sized = {
    request: {
      method: "POST",
      path: "/v1/projects/p/locations/l/channels/c:publishEvents",
      body: { events: [] },
    },
    response: answered(400, { error: { message: "The event size (12 bytes) is too large." } }),
  };
  assert.equal(sizesFollowRequest(sized), false, "12 is not the size of this request");
  assert.equal(
    sizesFollowRequest({
      ...sized,
      request: { ...sized.request, path: "/v1/projects/p/locations/l/channels/c" },
    }),
    false,
    "not a publish",
  );
  assert.equal(
    sizesFollowRequest({ ...sized, request: { method: "POST", path: sized.request.path } }),
    false,
    "no body",
  );
  const rebuilt = {
    ...sized,
    request: {
      ...sized.request,
      body: { events: [{ textData: { omitted: { length: 5, sha256: "0".repeat(64) } } }] },
    },
  };
  assert.equal(sizesFollowRequest(rebuilt), false, "a body that cannot be rebuilt");
  const none = {
    request: { method: "GET", path: "/v1/projects/p/locations/l/channels" },
    response: answered(404, { error: { message: "no count" } }),
  };
  assert.equal(sizesFollowRequest(none), true, "no byte count to check");
  assert.equal(sizesFollowRequest({ ...none, response: undefined }), true);
  const right = structuredClone(sized);
  right.response.body.error.message = `The event size (${publishRequestSize("projects/p/locations/l/channels/c", [])} bytes) is too large.`;
  assert.equal(sizesFollowRequest(right), true);
  const one = structuredClone(right);
  one.response.body.error.message = `${right.response.body.error.message} and (${publishRequestSize("projects/p/locations/l/channels/c", [])} bytes)`;
  assert.equal(sizesFollowRequest(one), true, "every count in the answer is checked");
  one.response.body.error.message += " and (3 bytes)";
  assert.equal(sizesFollowRequest(one), false);
});

test("JSON of different kinds is never the same, and the path of a difference is the point where the kinds part", () => {
  for (const [a, b] of [
    [null, {}],
    [{}, null],
    ["x", {}],
    [{}, "x"],
    [1, 2],
    [[], null],
    [null, []],
    [{ a: 1 }, "x"],
    ["x", { a: 1 }],
    [{ a: 1 }, null],
  ])
    assert.equal(sameJson(a, b), false, `${JSON.stringify(a)} ${JSON.stringify(b)}`);
  for (const [a, b] of [
    [null, { a: 1 }],
    [{ a: 1 }, null],
    ["x", { a: 1 }],
    [{ a: 1 }, "x"],
    ["x", "y"],
    [1, 2],
    [[], {}],
  ])
    assert.deepEqual(diffPaths(a, b), ["$"], `${JSON.stringify(a)} ${JSON.stringify(b)}`);
  assert.deepEqual(diffPaths({ a: 1 }, { a: 1 }), []);
});

test("an answer family cuts the message at 70 characters, and a summary names its rows", () => {
  const message = "a".repeat(100);
  assert.equal(
    answerFamily(answered(400, { error: { status: "X", message } })),
    `400 X ${"a".repeat(70)}`,
  );
  assert.equal(answerFamily(answered(400, { error: { status: "X" } })), "400 X");
  const results = [
    { n: 1, family: "f", verdict: "match" },
    { n: 2, family: "f", verdict: "diverge" },
    { n: 3, family: "g", verdict: "skipped" },
  ];
  assert.deepEqual(summarize(results), {
    total: { match: 1, diverge: 1, skipped: 1 },
    families: {
      f: { match: 1, diverge: 1, skipped: 0, rows: [1, 2] },
      g: { match: 0, diverge: 0, skipped: 1, rows: [3] },
    },
  });
});

test("a replay sends a content type only with a body, and keeps at most 4096 characters of an answer that is not JSON", async (t) => {
  const server = await listener(({ method }) => ({
    status: 200,
    text: method === "GET" ? "x".repeat(5000) : "{}",
  }));
  t.after(server.close);
  const post = entry({ request: { method: "POST", path: "/p", body: {} } });
  const get = entry({ request: { method: "GET", path: "/g" } });
  const results = await replay([get, post], { base: server.base });
  assert.deepEqual(
    server.seen.map((item) => item.contentType),
    [undefined, "application/json"],
  );
  assert.equal(results[0].actual.body.raw.length, 4096);
});

test("the command line refuses each missing argument of a replay and says what it takes", async () => {
  let printed = "";
  const io = {
    stdout: { write: (text) => (printed += text) },
    stderr: { write: (text) => (printed += text) },
  };
  for (const args of [
    ["--base", "http://x", "--profile", "p"],
    ["--capture", "c", "--profile", "p"],
    ["--capture", "c", "--base", "http://x"],
  ]) {
    printed = "";
    assert.equal(await main(["replay", ...args], io), 2, args.join(" "));
    assert.match(printed, /replay needs --capture, --base and --profile/);
  }
  printed = "";
  assert.equal(await main(["other"], io), 2);
  assert.equal(printed, "usage: compare.mjs pair|replay ...\n");
  printed = "";
  assert.equal(await main(["pair", "--b", "x"], io), 2);
  assert.match(printed, /pair needs --a and --b/);
});

test("run as a program, the tool takes its command from the first argument", () => {
  const dir = mkdtempSync(join(tmpdir(), "eventarc-compare-cli-"));
  const capture = (runId) => {
    const path = join(dir, `capture-${runId}.jsonl`);
    const lines = [{ at: "x", note: "run-start", runId }, entry({})];
    writeFileSync(path, `${lines.map((line) => JSON.stringify(line)).join("\n")}\n`);
    return path;
  };
  const program = fileURLToPath(new URL("./eventarc-production/compare.mjs", import.meta.url));
  const done = spawnSync(
    process.execPath,
    [program, "pair", "--a", capture("aaaaaaaaaaaa"), "--b", capture("bbbbbbbbbbbb")],
    { encoding: "utf8" },
  );
  assert.equal(done.status, 0, done.stderr);
  assert.deepEqual(JSON.parse(done.stdout).counts, { identical: 1 });
  const refused = spawnSync(process.execPath, [program], { encoding: "utf8" });
  assert.equal(refused.status, 2);
  assert.match(refused.stderr, /usage: compare.mjs pair\|replay/);
});
