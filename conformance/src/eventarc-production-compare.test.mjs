import assert from "node:assert/strict";
import test from "node:test";
import { compareAnswer, replay, replayRow, tokenModes } from "./eventarc-production/compare.mjs";

const parent = "projects/demo-reference/locations/us-central1";
const collection = `/v1/${parent}/channels`;
const channel = `${parent}/channels/one`;
const operation = (id) =>
  `${parent}/operations/operation-1791198689276-65d15f198b319-e46b83a2-${id.repeat(8)}`;
const issued = operation("a"),
  local = operation("b"),
  second = operation("c"),
  secondLocal = operation("d"),
  unknown = operation("e");
const pending = (name, target = channel, verb = "create") => ({
  name,
  metadata: { target, verb },
  done: false,
});
const row = (op, path, body, method = "GET", status = 200) => ({
  op,
  request: { method, path },
  response: { status, body },
  case: "references",
});
const create = (name = issued, target = channel) =>
  row(
    "createChannel",
    `${collection}?channelId=${target.split("/").at(-1)}`,
    pending(name, target),
    "POST",
  );
const token = (text) => Buffer.from(text).toString("base64url");
const originalToken = token("original issued token"),
  localToken = token("local issued token");
const page = (nextPageToken, names = [channel]) => ({
  channels: names.map((name) => ({ name })),
  ...(nextPageToken === undefined ? {} : { nextPageToken }),
});

async function capture(rows, answers) {
  const urls = [];
  const results = await replay(rows, {
    base: "http://127.0.0.1:9999",
    fetchImpl: async (url) => {
      urls.push(url);
      const answer = answers[urls.length - 1];
      assert.ok(answer, "each actual request has a supplied answer");
      return { status: answer.status ?? 200, text: async () => JSON.stringify(answer.body) };
    },
  });
  return { urls: urls.map((url) => url.replace("http://127.0.0.1:9999", "")), results };
}

test("replay binds two issued operations independently and repeats the first without binding an unknown name", async () => {
  const two = `${parent}/channels/two`;
  const rows = [
    create(),
    create(second, two),
    row("getOperation", `/v1/${issued}`, pending(issued)),
    row("getOperation", `/v1/${second}`, pending(second, two)),
    row("getOperation", `/v1/${issued}?alt=json`, pending(issued)),
    row("getOperation", `/v1/${unknown}`, {}, "GET", 404),
  ];
  const got = await capture(rows, [
    { body: pending(local) },
    { body: pending(secondLocal, two) },
    { body: pending(local) },
    { body: pending(secondLocal, two) },
    { body: pending(local) },
    { status: 404, body: {} },
  ]);
  assert.deepEqual(got.urls, [
    rows[0].request.path,
    rows[1].request.path,
    `/v1/${local}`,
    `/v1/${secondLocal}`,
    `/v1/${local}?alt=json`,
    `/v1/${unknown}`,
  ]);
  assert.equal(
    got.results[0].verdict,
    "diverge",
    "opaque response names are still compared exactly",
  );
  assert.equal(got.results.at(-1).verdict, "match");
});

test("replay binds a delete operation from its own successful exchange", async () => {
  const rows = [
    row("deleteChannel", `/v1/${channel}`, pending(issued, channel, "delete"), "DELETE"),
    row("getOperation", `/v1/${issued}`, pending(issued, channel, "delete")),
  ];
  const got = await capture(rows, [
    { body: pending(local, channel, "delete") },
    { body: pending(local, channel, "delete") },
  ]);
  assert.equal(got.urls[1], `/v1/${local}`);
});

test("replay binds an issued page token while preserving every trailing query parameter", async () => {
  const rows = [
    row("listChannels", `${collection}?pageSize=1&filter=state%3DACTIVE`, page(originalToken)),
    row(
      "listChannels",
      `${collection}?pageToken=${originalToken}&pageSize=1&filter=state%3DACTIVE&alt=json`,
      page(undefined),
    ),
  ];
  const got = await capture(rows, [{ body: page(localToken) }, { body: page(undefined) }]);
  assert.equal(
    got.urls[1],
    `${collection}?pageToken=${localToken}&pageSize=1&filter=state%3DACTIVE&alt=json`,
  );
  assert.equal(got.results[0].verdict, "diverge", "token responses are not newly masked");
});

test("page tokens stay unbound when missing, unissued, malformed or from a different collection or filter", async () => {
  for (const [actualPage, consumer] of [
    [page(undefined), `${collection}?pageToken=${originalToken}&pageSize=1`],
    [page(localToken), `${collection}?pageToken=garbage&pageSize=1`],
    [page("not+base64!"), `${collection}?pageToken=${originalToken}&pageSize=1`],
    [
      page(localToken),
      `/v1/projects/another/locations/us-central1/channels?pageToken=${originalToken}`,
    ],
    [page(localToken), `${collection}?pageToken=${originalToken}&filter=different`],
    [page(localToken, [`${parent}/channels/two`]), `${collection}?pageToken=${originalToken}`],
  ]) {
    const rows = [
      row("listChannels", collection, page(originalToken)),
      row("listChannels", consumer, page(undefined)),
    ];
    const got = await capture(rows, [{ body: actualPage }, { body: page(undefined) }]);
    assert.equal(got.urls[1], consumer);
  }
});

test("operation binding rejects wrong target, authority, verb, shape and unsuccessful issuing answers", async () => {
  for (const answer of [
    { body: pending(local, `${parent}/channels/wrong`) },
    { body: pending(local.replace("demo-reference", "another")) },
    { body: pending(local, channel, "delete") },
    { body: { ...pending(local), name: `${parent}/operations/malformed` } },
    { body: { ...pending(local), done: "false" } },
    { status: 500, body: pending(local) },
  ]) {
    const rows = [create(), row("getOperation", `/v1/${issued}`, {})];
    const got = await capture(rows, [answer, { body: {} }]);
    assert.equal(got.urls[1], `/v1/${issued}`);
    assert.equal(got.results[0].verdict, "diverge");
  }
});

test("reference bindings do not survive a second replay run", async () => {
  await capture([create()], [{ body: pending(local) }]);
  const got = await capture([row("getOperation", `/v1/${issued}`, {})], [{ body: {} }]);
  assert.equal(got.urls[0], `/v1/${issued}`);
});

test("exact comparison still rejects wrong target, done, state and topic", () => {
  const wanted = {
    status: 200,
    body: {
      ...pending(issued),
      response: {
        name: channel,
        state: "ACTIVE",
        pubsubTopic: "projects/demo-reference/topics/channel-123",
      },
    },
  };
  for (const body of [
    { ...wanted.body, metadata: { target: `${parent}/channels/wrong`, verb: "create" } },
    { ...wanted.body, done: true },
    { ...wanted.body, response: { ...wanted.body.response, state: "INACTIVE" } },
    { ...wanted.body, response: { ...wanted.body.response, pubsubTopic: "" } },
  ])
    assert.equal(compareAnswer(wanted, { status: 200, body }).verdict, "diverge");
  assert.equal(compareAnswer(wanted, wanted).verdict, "match");
});

test("malformed original operation identities never bind or prevent later requests", async () => {
  for (const malformed of [null, 123, {}, `${parent}/operations/malformed`]) {
    const first = create();
    first.response.body = { ...pending(issued), name: malformed };
    const got = await capture(
      [first, row("getOperation", `/v1/${issued}`, {})],
      [{ body: pending(local) }, { body: {} }],
    );
    assert.equal(got.urls.length, 2);
    assert.equal(got.urls[1], `/v1/${issued}`);
  }
});

test("conflicting operation issuers invalidate rather than overwrite a previously bound identity", async () => {
  const got = await capture(
    [create(), create(), row("getOperation", `/v1/${issued}`, {})],
    [{ body: pending(local) }, { body: pending(secondLocal) }, { body: {} }],
  );
  assert.equal(got.urls[2], `/v1/${issued}`);
});

test("page binding preserves arbitrary query suffixes without changing the capture", async () => {
  for (let i = 0; i < 32; i += 1) {
    const suffix = `&pageSize=${i + 1}&alt=json&extra=${encodeURIComponent(`x + ${i} / &`)}&extra=second`;
    const rows = [
      row("listChannels", collection, page(originalToken)),
      row("listChannels", `${collection}?pageToken=${originalToken}${suffix}`, page(undefined)),
    ];
    const frozen = JSON.stringify(rows);
    const got = await capture(rows, [{ body: page(localToken) }, { body: page(undefined) }]);
    assert.equal(got.urls[1], `${collection}?pageToken=${localToken}${suffix}`);
    assert.equal(JSON.stringify(rows), frozen);
  }
});

test("duplicate pageToken parameters remain an unchanged invalid request", async () => {
  const path = `${collection}?pageToken=${originalToken}&pageToken=garbage&pageSize=1`;
  const got = await capture(
    [row("listChannels", collection, page(originalToken)), row("listChannels", path, {})],
    [{ body: page(localToken) }, { body: {} }],
  );
  assert.equal(got.urls[1], path);
});

test("page binding rejects original failure and wrong method even when both bodies look issued", async () => {
  for (const [method, status] of [
    ["GET", 500],
    ["POST", 200],
  ]) {
    const path = `${collection}?pageToken=${originalToken}`;
    const rows = [
      row("listChannels", collection, page(originalToken), method, status),
      row("listChannels", path, {}),
    ];
    const got = await capture(rows, [{ body: page(localToken) }, { body: {} }]);
    assert.equal(got.urls[1], path);
  }
});

test("a wrong-method consumer remains unchanged even after its identity was issued", async () => {
  const opRows = [create(), row("getOperation", `/v1/${issued}`, {}, "POST")];
  const operationResult = await capture(opRows, [{ body: pending(local) }, { body: {} }]);
  assert.equal(operationResult.urls[1], `/v1/${issued}`);
  const pagePath = `${collection}?pageToken=${originalToken}`;
  const pageRows = [
    row("listChannels", collection, page(originalToken)),
    row("listChannels", pagePath, {}, "POST"),
  ];
  const pageResult = await capture(pageRows, [{ body: page(localToken) }, { body: {} }]);
  assert.equal(pageResult.urls[1], pagePath);
});

test("binding keeps the existing strip-v1 request option", async () => {
  const urls = [];
  const answers = [pending(local), pending(local)];
  await replay([create(), row("getOperation", `/v1/${issued}`, pending(issued))], {
    base: "http://127.0.0.1:9999",
    stripV1: true,
    fetchImpl: async (url) => {
      urls.push(url);
      return { status: 200, text: async () => JSON.stringify(answers.shift()) };
    },
  });
  assert.equal(urls[1], `http://127.0.0.1:9999/${local}`);
});

test("reference parsing preserves literal question marks after the first query delimiter", async () => {
  const suffix = "?alt=json&extra=a?b&last=kept";
  const issuing = create();
  issuing.request.path = `${collection}?extra=a?b&channelId=one`;
  const rows = [issuing, row("getOperation", `/v1/${issued}${suffix}`, pending(issued))];
  const before = JSON.stringify(rows);
  const got = await capture(rows, [{ body: pending(local) }, { body: pending(local) }]);
  assert.equal(got.urls[1], `/v1/${local}${suffix}`);
  assert.equal(JSON.stringify(rows), before);
  const pageRows = [
    row("listChannels", `${collection}?filter=a?b`, page(originalToken)),
    row("listChannels", `${collection}?pageToken=${originalToken}&filter=a?c`, page(undefined)),
  ];
  const pages = await capture(pageRows, [{ body: page(localToken) }, { body: page(undefined) }]);
  assert.equal(
    pages.urls[1],
    pageRows[1].request.path,
    "different full filters must remain separate",
  );
});

test("page binding rejects empty and nested channel identifiers under a matching collection prefix", async () => {
  for (const name of [
    `${parent}/channels/`,
    `${parent}/channels/one/extra`,
    `${parent}/channels/one?extra`,
    `${parent}/channels/one#extra`,
  ]) {
    const path = `${collection}?pageToken=${originalToken}&pageSize=1`;
    const rows = [
      row("listChannels", collection, page(originalToken, [name])),
      row("listChannels", path, page(undefined)),
    ];
    const before = JSON.stringify(rows);
    const got = await capture(rows, [
      { body: page(localToken, [name]) },
      { body: page(undefined) },
    ]);
    assert.equal(got.urls[1], path);
    assert.equal(JSON.stringify(rows), before);
  }
});

const authFixtures = {
  default: "ya29.replay-token",
  none: null,
  invalid: "invalid-token-for-the-recording",
  "ya29-garbage": "ya29.fireemu-recorder-not-a-token-0000000000000000",
  "jwt-garbage":
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmaXJlZW11LXJlY29yZGVyIiwic3ViIjoieCJ9.fireemu-recorder-not-a-signature",
  "jwt-expired-unsigned":
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhdWQiOiJmaXJlZW11LXJlY29yZGVyIiwiaWF0IjowLCJleHAiOjF9.fireemu-recorder-not-a-signature",
  "wrong-scope": "ya29.a-token-of-another-scope",
};

async function authCapture(rows) {
  const requests = [];
  const results = await replay(rows, {
    base: "http://127.0.0.1:9999",
    fetchImpl: async (url, init) => {
      requests.push({ url, ...init });
      return { status: 200, text: async () => "{}" };
    },
  });
  return { requests, results };
}

const authRow = (op = "listChannels", mode) => {
  const value = { ...row(op, collection, {}), case: "auth-errors" };
  if (op === "createChannel")
    value.request = {
      method: "POST",
      path: `${collection}?channelId=one`,
      body: { channel: { name: channel } },
    };
  else if (op === "publishEvents")
    value.request = { method: "POST", path: `/v1/${channel}:publishEvents`, body: { events: [] } };
  else if (op === "getOperation") value.request.path = `/v1/${issued}`;
  else if (op === "getChannel") value.request.path = `/v1/${channel}`;
  if (mode !== undefined) value.tokenMode = mode;
  return value;
};

test("absent legacy A auth metadata preserves its nine-row credential sequence", async () => {
  const ops = [
    "createChannel",
    "listChannels",
    "publishEvents",
    "listChannels",
    "publishEvents",
    "createChannel",
    "publishEvents",
    "publishEvents",
    "getChannel",
  ];
  const rows = ops.map((op) => authRow(op));
  rows.unshift({ ...row("listChannels", collection, {}), case: "other" });
  const got = await authCapture(rows);
  const modes = [
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
  ];
  assert.deepEqual(
    got.requests.map((r) => r.headers.authorization),
    modes.map((m) => (authFixtures[m] === null ? undefined : `Bearer ${authFixtures[m]}`)),
  );
});

test("explicit B/C setup modes stay default through create and operation/channel reads", async () => {
  const rows = ["createChannel", "getOperation", "getOperation", "getOperation", "getChannel"].map(
    (op) => authRow(op, "default"),
  );
  rows.push(authRow("listChannels", "none"), authRow("publishEvents", "invalid"));
  const got = await authCapture(rows);
  assert.deepEqual(
    got.requests.map((r) => r.method),
    ["POST", "GET", "GET", "GET", "GET", "GET", "POST"],
  );
  assert.deepEqual(
    got.requests.map((r) => r.headers.authorization),
    [
      ...Array(5).fill(`Bearer ${authFixtures.default}`),
      undefined,
      `Bearer ${authFixtures.invalid}`,
    ],
  );
});

test("all seven recorded modes send exact public fixture headers independently of expected answers", async () => {
  const modes = Object.keys(authFixtures);
  const rows = modes.map((mode) => ({
    ...row("listChannels", collection, {}),
    case: "outside-auth",
    tokenMode: mode,
  }));
  const got = await authCapture(rows);
  assert.deepEqual(
    got.requests.map((r) => r.headers.authorization),
    modes.map((m) => (authFixtures[m] === null ? undefined : `Bearer ${authFixtures[m]}`)),
  );
  assert.notEqual(authFixtures["jwt-garbage"], authFixtures["jwt-expired-unsigned"]);
  assert.equal(
    JSON.parse(Buffer.from(authFixtures["jwt-expired-unsigned"].split(".")[1], "base64url")).exp,
    1,
  );
});

test("explicit modes override legacy positions without consuming absent-only fallback slots", async () => {
  const rows = [
    authRow(),
    authRow("listChannels", "default"),
    authRow(),
    authRow("listChannels", "invalid"),
    authRow(),
    authRow(),
  ];
  const got = await authCapture(rows);
  assert.deepEqual(
    got.requests.map((r) => r.headers.authorization),
    ["default", "default", "none", "invalid", "none", "invalid"].map((m) =>
      authFixtures[m] === null ? undefined : `Bearer ${authFixtures[m]}`,
    ),
  );
  const inherited = Object.assign(
    Object.create({ tokenMode: "none" }),
    row("listChannels", collection, {}),
  );
  assert.deepEqual(
    tokenModes([inherited]),
    ["default"],
    "inherited metadata is not recorded input",
  );
});

test("malformed explicit metadata anywhere rejects the entire replay before its first fetch", async () => {
  for (const mode of ["unknown", "", null, undefined, 7, {}, "toString", "__proto__"]) {
    const rows = [authRow("listChannels", "default"), { ...authRow(), tokenMode: mode }];
    assert.throws(() => tokenModes(rows), /unknown credential mode/);
    let sent = 0;
    await assert.rejects(
      () =>
        replay(rows, {
          base: "http://127.0.0.1:9999",
          fetchImpl: async () => {
            sent += 1;
            return { status: 200, text: async () => "{}" };
          },
        }),
      /unknown credential mode/,
    );
    assert.equal(sent, 0);
  }
});

test("direct replayRow rejects unsupported modes before fetch", async () => {
  for (const mode of ["unknown", "", null, undefined, 7, {}, "toString", "__proto__"]) {
    let sent = 0;
    await assert.rejects(
      () =>
        replayRow(row("listChannels", collection, {}), mode, {
          base: "http://127.0.0.1:9999",
          fetchImpl: async () => {
            sent += 1;
            return { status: 200, text: async () => "{}" };
          },
        }),
      /unknown credential mode/,
    );
    assert.equal(sent, 0);
  }
});

const b28Rows = JSON.parse("[]");
{
  const { readFileSync } = await import("node:fs");
  b28Rows.push(
    ...readFileSync(new URL("./eventarc-production/fixtures/ad/B.jsonl", import.meta.url), "utf8")
      .trim()
      .split("\n")
      .map(JSON.parse)
      .filter((captured) => [26, 27, 28].includes(captured.n)),
  );
}
const sourceContinuationToken = token("synthetic source B27 continuation");
b28Rows[1].response.body.nextPageToken = sourceContinuationToken;
b28Rows[2].request.path = b28Rows[2].request.path.replace(
  /pageToken=[^&]+/,
  `pageToken=${sourceContinuationToken}`,
);
const ownContinuationToken = token("own positive B27 continuation");
async function captureB28({
  changePlacement = true,
  modifyRows = () => {},
  modifyAnswers = () => {},
} = {}) {
  const rows = structuredClone(b28Rows);
  const inventory = rows[0].response.body.channels;
  const originalFirst = rows[1].response.body.channels[0];
  const first = inventory.find((member) =>
    changePlacement ? member.name !== originalFirst.name : member.name === originalFirst.name,
  );
  const last = inventory.find((member) => member.name !== first.name);
  const answers = [
    { status: 200, body: structuredClone(rows[0].response.body) },
    {
      status: 200,
      body: { channels: [structuredClone(first)], nextPageToken: ownContinuationToken },
    },
  ];
  modifyRows(rows);
  modifyAnswers(answers);
  const urls = [],
    localPages = [];
  const results = await replay(rows, {
    base: "http://127.0.0.1:9999",
    fetchImpl: async (url) => {
      urls.push(url);
      const answer =
        urls.length <= 2
          ? answers[urls.length - 1]
          : new URL(url).searchParams.get("pageToken") === ownContinuationToken
            ? { status: 200, body: { channels: [structuredClone(last)] } }
            : { status: 400, body: { error: { code: 400, status: "INVALID_ARGUMENT" } } };
      if (urls.length >= 2 && answer.status === 200) localPages.push(...answer.body.channels);
      return { status: answer.status, text: async () => JSON.stringify(answer.body) };
    },
  });
  return { rows, urls, results, localPages, inventory };
}
test("original B26/B27/B28 follows its own positive cursor despite reversed default page placement", async () => {
  for (const changePlacement of [true, false]) {
    const got = await captureB28({ changePlacement });
    assert.equal(new URL(got.urls[2]).searchParams.get("pageToken"), ownContinuationToken);
    assert.deepEqual(
      new Set(got.localPages.map((member) => member.name)),
      new Set(got.inventory.map((member) => member.name)),
    );
    assert.equal(got.localPages.length, got.inventory.length);
    assert.equal(
      got.results.at(-1).verdict,
      changePlacement ? "diverge" : "match",
      "raw page differences remain visible",
    );
    if (changePlacement) {
      assert.equal(got.results.at(-1).reason, "body");
      assert.equal(got.results.at(-1).actual.status, 200);
    }
  }
});
test("B28 positive binding rejects malformed, incomplete, foreign or changed inventory and page resources", async () => {
  for (const [name, modifyAnswers] of [
    ["missing inventory member", (answers) => answers[0].body.channels.pop()],
    [
      "duplicate inventory member",
      (answers) => (answers[0].body.channels[1] = structuredClone(answers[0].body.channels[0])),
    ],
    [
      "duplicate inventory uid",
      (answers) => {
        answers[0].body.channels[1].uid = answers[0].body.channels[0].uid;
      },
    ],
    [
      "wrong collection",
      (answers) =>
        (answers[1].body.channels[0].name = answers[1].body.channels[0].name.replace(
          "/channels/",
          "/foreign/",
        )),
    ],
    ["foreign member", (answers) => (answers[1].body.channels[0].name += "-foreign")],
    ["extra member field", (answers) => (answers[1].body.channels[0].unexpected = true)],
    ["missing member field", (answers) => delete answers[1].body.channels[0].uid],
    ["invalid member type", (answers) => (answers[1].body.channels[0].uid = 42)],
    ["invalid member state", (answers) => (answers[1].body.channels[0].state = "UNKNOWN")],
    ["malformed local cursor", (answers) => (answers[1].body.nextPageToken = "not+base64!")],
    ["unsuccessful local issuance", (answers) => (answers[1].status = 400)],
  ]) {
    const got = await captureB28({ modifyAnswers });
    assert.equal(
      new URL(got.urls[2]).searchParams.get("pageToken"),
      new URL(got.rows[2].request.path, "http://local").searchParams.get("pageToken"),
      name,
    );
    assert.equal(got.results.at(-1).actual.status, 400, name);
  }
});
test("B28 unissued malformed and unsupported-collection consumers remain original requests", async () => {
  for (const [name, modifyRows] of [
    [
      "unissued cursor",
      (rows) =>
        (rows[2].request.path = rows[2].request.path.replace(
          /pageToken=[^&]+/,
          "pageToken=dW5pc3N1ZWQ",
        )),
    ],
    [
      "malformed original cursor",
      (rows) => {
        rows[1].response.body.nextPageToken = "not+base64!";
        rows[2].request.path = rows[2].request.path.replace(
          /pageToken=[^&]+/,
          "pageToken=not%2Bbase64%21",
        );
      },
    ],
    [
      "different collection",
      (rows) => (rows[2].request.path = rows[2].request.path.replace("/channels?", "/foreign?")),
    ],
  ]) {
    const got = await captureB28({ modifyRows });
    assert.equal(got.urls[2].slice("http://127.0.0.1:9999".length), got.rows[2].request.path, name);
  }
});
test("conflicting positive B27 issuers invalidate continuation lineage", async () => {
  const original = structuredClone(b28Rows[1]),
    consumer = structuredClone(b28Rows[2]);
  const answers = [
    { body: original.response.body },
    { body: { ...original.response.body, nextPageToken: ownContinuationToken } },
    { body: {} },
  ];
  const got = await capture([original, structuredClone(original), consumer], answers);
  assert.equal(got.urls[2], consumer.request.path);
});

test("a failed same-scope complete inventory invalidates cached page authority", async () => {
  for (const failed of [
    { status: 200, body: { channels: [structuredClone(b28Rows[0].response.body.channels[0])] } },
    { status: 400, body: { error: { code: 400 } } },
    { status: 200, body: { unexpected: true } },
  ]) {
    const rows = structuredClone(b28Rows);
    const first = rows[0].response.body.channels.find(
      (member) => member.name !== rows[1].response.body.channels[0].name,
    );
    const answers = [
      { status: 200, body: rows[0].response.body },
      failed,
      { status: 200, body: { channels: [first], nextPageToken: ownContinuationToken } },
      { status: 400, body: { error: { code: 400 } } },
    ];
    const urls = [];
    await replay([rows[0], structuredClone(rows[0]), rows[1], rows[2]], {
      base: "http://127.0.0.1:9999",
      fetchImpl: async (url) => {
        urls.push(url);
        const answer = answers[urls.length - 1];
        return { status: answer.status, text: async () => JSON.stringify(answer.body) };
      },
    });
    assert.equal(new URL(urls[3]).searchParams.get("pageToken"), sourceContinuationToken);
  }
});

async function captureIndependentWalks({
  rootQuery = "",
  originalStatus = 200,
  localStatus = 200,
  withoutInventory = false,
} = {}) {
  const inventory = structuredClone(b28Rows[0]),
    firstRoot = structuredClone(b28Rows[1]),
    secondRoot = structuredClone(b28Rows[1]),
    consumer = structuredClone(b28Rows[2]);
  secondRoot.request.path += rootQuery;
  secondRoot.response.status = originalStatus;
  const other = inventory.response.body.channels.find(
    (member) => member.name !== firstRoot.response.body.channels[0].name,
  );
  const secondOwn = token("second independent own cursor");
  const rows = [inventory, firstRoot, secondRoot, consumer];
  const answers = [
    { body: inventory.response.body },
    { body: { channels: [other], nextPageToken: ownContinuationToken } },
    {
      status: localStatus,
      body: { channels: secondRoot.response.body.channels, nextPageToken: secondOwn },
    },
    { body: consumer.response.body },
  ];
  if (withoutInventory) {
    answers[1].body.channels = firstRoot.response.body.channels;
    rows.shift();
    answers.shift();
  }
  return { ...(await capture(rows, answers)), consumer, secondOwn };
}
test("independent validated token-free walks bind a repeated source cursor to their own current cursor", async () => {
  for (const rootQuery of ["", "&pageToken="]) {
    const got = await captureIndependentWalks({ rootQuery });
    assert.equal(
      new URL(got.urls.at(-1), "http://local").searchParams.get("pageToken"),
      got.secondOwn,
    );
  }
});
test("unknown malformed duplicate or nonempty incoming cursors cannot reset same-walk conflicts", async () => {
  for (const rootQuery of [
    `&pageToken=${sourceContinuationToken}`,
    `&pageToken=${token("unissued incoming cursor")}`,
    "&pageToken=not%2Bbase64%21",
    "&pageToken=&pageToken=",
  ]) {
    const got = await captureIndependentWalks({ rootQuery });
    assert.equal(got.urls.at(-1), got.consumer.request.path);
  }
});
test("negative and foreign-scope roots cannot reset an existing scoped walk", async () => {
  for (const options of [
    { originalStatus: 400 },
    { localStatus: 400 },
    { rootQuery: "&filter=state%3DINACTIVE" },
    { rootQuery: "&orderBy=name" },
  ]) {
    const got = await captureIndependentWalks(options);
    assert.equal(
      new URL(got.urls.at(-1), "http://local").searchParams.get("pageToken"),
      ownContinuationToken,
    );
  }
  const unproven = await captureIndependentWalks({ withoutInventory: true });
  assert.equal(unproven.urls.at(-1), unproven.consumer.request.path);
});

async function capturePersistentIssuer({
  consumerToken = sourceContinuationToken,
  consumerQuery = "",
  conflicting = false,
  malformedIssuer = false,
} = {}) {
  const inventory = structuredClone(b28Rows[0]),
    issuer = structuredClone(b28Rows[1]),
    intervening = structuredClone(b28Rows[1]),
    consumer = structuredClone(b28Rows[2]);
  const interveningNative = conflicting
    ? sourceContinuationToken
    : token("different native walk boundary");
  intervening.response.body.nextPageToken = interveningNative;
  consumer.request.path =
    consumer.request.path
      .replace("/locations/us-central1/", "/locations/other-region/")
      .replace(/pageToken=[^&]+/, `pageToken=${consumerToken}`) + consumerQuery;
  consumer.response.status = 500;
  const other = inventory.response.body.channels.find(
    (member) => member.name !== issuer.response.body.channels[0].name,
  );
  const issuerAnswer = { channels: [other], nextPageToken: ownContinuationToken };
  if (malformedIssuer) issuerAnswer.channels[0] = { ...other, unexpected: true };
  const got = await capture(
    [inventory, issuer, intervening, consumer],
    [
      { body: inventory.response.body },
      { body: issuerAnswer },
      {
        body: {
          channels: intervening.response.body.channels,
          nextPageToken: token("intervening own walk cursor"),
        },
      },
      { status: 500, body: consumer.response.body },
    ],
  );
  return { ...got, consumer };
}
test("a uniquely validated persistent issuer survives intervening walks for negative foreign-scope requests", async () => {
  for (const consumerQuery of [
    "",
    "&filter=state%3DACTIVE&alt=json",
    "&filter=state%3DINACTIVE",
    "&orderBy=name&pageSize=9",
    "&aggregate=true",
  ]) {
    const got = await capturePersistentIssuer({ consumerQuery });
    assert.equal(
      got.urls.at(-1),
      got.consumer.request.path.replace(sourceContinuationToken, ownContinuationToken),
    );
  }
  const negative = await captureB28({ modifyRows: (rows) => (rows[2].response.status = 400) });
  assert.equal(new URL(negative.urls[2]).searchParams.get("pageToken"), ownContinuationToken);
});
test("persistent rebinding rejects unknown mutated malformed ambiguous and duplicate-token inputs", async () => {
  for (const options of [
    { consumerToken: token("unknown native token") },
    { consumerToken: sourceContinuationToken.slice(0, -1) + "A" },
    { consumerToken: "not%2Bbase64%21" },
    { conflicting: true },
    { malformedIssuer: true },
    { consumerQuery: "&pageToken=" },
    { consumerQuery: `&pageToken=${sourceContinuationToken}` },
    { consumerQuery: `&%70ageToken=${sourceContinuationToken}` },
  ]) {
    const got = await capturePersistentIssuer(options);
    assert.equal(got.urls.at(-1), got.consumer.request.path);
  }
});

test("original C and D cross-region aggregate and changed-size consumers retain their unique issuer cursor", async () => {
  const { readFileSync } = await import("node:fs");
  for (const [label, issuerN, consumerNs] of [
    ["C", 102, [124, 126, 127]],
    ["D", 41, [57, 59, 60]],
  ]) {
    const nativeRows = readFileSync(
      new URL(`./eventarc-production/fixtures/ad/${label}.jsonl`, import.meta.url),
      "utf8",
    )
      .trim()
      .split("\n")
      .map(JSON.parse);
    const issuerIndex = nativeRows.findIndex((captured) => captured.n === issuerN);
    const sourceIssuer = nativeRows[issuerIndex];
    const inventoryRow = nativeRows
      .slice(0, issuerIndex)
      .findLast(
        (captured) =>
          captured.op === "listChannels" &&
          captured.response.status === 200 &&
          Array.isArray(captured.response.body?.channels) &&
          !Object.hasOwn(captured.response.body, "nextPageToken") &&
          !new URL(captured.request.path, "http://local").searchParams.has("pageToken") &&
          captured.request.path.split("?")[0] === sourceIssuer.request.path.split("?")[0],
      );
    assert.ok(inventoryRow, `${label}: source complete inventory`);
    for (const consumerN of consumerNs) {
      const inventory = structuredClone(inventoryRow),
        issuer = structuredClone(sourceIssuer),
        intervening = structuredClone(sourceIssuer),
        consumer = structuredClone(nativeRows.find((captured) => captured.n === consumerN));
      issuer.response.body.nextPageToken = sourceContinuationToken;
      intervening.response.body.nextPageToken = token("intervening source cursor");
      consumer.request.path = consumer.request.path.replace(
        /pageToken=[^&]+/,
        `pageToken=${sourceContinuationToken}`,
      );
      const got = await capture(
        [inventory, issuer, intervening, consumer],
        [
          { body: inventory.response.body },
          { body: { ...issuer.response.body, nextPageToken: ownContinuationToken } },
          {
            body: {
              ...intervening.response.body,
              nextPageToken: token("intervening local cursor"),
            },
          },
          { status: consumer.response.status, body: consumer.response.body },
        ],
      );
      assert.equal(
        got.urls.at(-1),
        consumer.request.path.replace(sourceContinuationToken, ownContinuationToken),
        `${label}${consumerN}`,
      );
      assert.equal(
        got.results.at(-1).verdict,
        "match",
        `${label}${consumerN}: original status/body retained`,
      );
    }
  }
});

test("current-walk ambiguity dominates persistent fallback after inventory invalidation for every expected status", async () => {
  for (const status of [200, 400]) {
    const inventory = structuredClone(b28Rows[0]),
      issuer = structuredClone(b28Rows[1]),
      consumer = structuredClone(b28Rows[2]);
    consumer.response.status = status;
    if (status === 400)
      consumer.response.body = { error: { code: 400, status: "INVALID_ARGUMENT" } };
    const got = await capture(
      [inventory, issuer, structuredClone(inventory), structuredClone(issuer), consumer],
      [
        { body: inventory.response.body },
        { body: { ...issuer.response.body, nextPageToken: ownContinuationToken } },
        { body: { channels: [inventory.response.body.channels[0]] } },
        {
          body: {
            ...issuer.response.body,
            nextPageToken: token("conflicting own cursor after invalidation"),
          },
        },
        { status, body: consumer.response.body },
      ],
    );
    assert.equal(
      got.urls.at(-1),
      consumer.request.path,
      `expected${status}: conflict stays unbound`,
    );
  }
});

test("original C124 and D57 internal-error wrappers normalize only their generated hex UUID", async () => {
  const { readFileSync } = await import("node:fs");
  for (const [label, ordinal] of [
    ["C", 124],
    ["D", 57],
  ]) {
    const native = readFileSync(
      new URL(`./eventarc-production/fixtures/ad/${label}.jsonl`, import.meta.url),
      "utf8",
    )
      .trim()
      .split("\n")
      .map(JSON.parse)
      .find((captured) => captured.n === ordinal).response;
    const actual = structuredClone(native);
    actual.body.error.message =
      "An internal error has occurred (00000000-0000-0000-0000-000000000001)";
    assert.equal(compareAnswer(native, actual).verdict, "match", `${label}${ordinal}`);
    assert.notEqual(
      native.body.error.message,
      actual.body.error.message,
      "raw generated IDs remain different",
    );
  }
});
test("internal-error ID normalization retains wrapper, status, code, details and unrelated-message differences", () => {
  const message = "An internal error has occurred (12345678-1234-4ABC-8abc-123456789aBC)";
  const native = { status: 500, body: { error: { code: 500, status: "INTERNAL", message } } };
  const own = "An internal error has occurred (00000000-0000-0000-0000-000000000001)";
  for (const changed of [
    own.replace("000000000001", "00000000001"),
    own.replace("000000000001", "0000000000001"),
    own.replace("000000000001", "00000000000g"),
    own.replace("0000-0000", "000-0000"),
    own.replace("An internal", "an internal"),
    own.replace("has occurred", "occurred"),
    own + "suffix",
    own + "\n",
    own.replace(")", ""),
    own.replace(" (", ": "),
    "another message (00000000-0000-0000-0000-000000000001)",
    null,
    500,
  ]) {
    assert.equal(
      compareAnswer(native, {
        status: 500,
        body: { error: { ...native.body.error, message: changed } },
      }).verdict,
      "diverge",
    );
  }
  for (const changed of [
    { status: 400, body: { error: { ...native.body.error, message: own } } },
    { status: 500, body: { error: { ...native.body.error, code: 400, message: own } } },
    { status: 500, body: { error: { ...native.body.error, status: "UNKNOWN", message: own } } },
    {
      status: 500,
      body: { error: { ...native.body.error, details: [{ reason: "unexpected" }], message: own } },
    },
  ])
    assert.equal(compareAnswer(native, changed).verdict, "diverge");
  assert.equal(
    compareAnswer(native, { status: 500, body: { error: { ...native.body.error, message: own } } })
      .verdict,
    "match",
  );
  assert.equal(
    compareAnswer(
      { status: 500, body: { description: message } },
      { status: 500, body: { description: own } },
    ).verdict,
    "diverge",
  );
});
