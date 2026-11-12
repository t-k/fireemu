// The deployed fixture, run in this process against a stand-in request and response: the frames it prints, the status each
// scripted answer becomes, and that nothing secret is printed. The SDK's own request handling runs (FUNCTIONS_EMULATOR makes
// it skip the token check, as it does under an emulator); Cloud Tasks itself does not exist here.
import "./record/isolation.mjs";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cpSync, existsSync, symlinkSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { FRAME_MARK, ROLES, ROLE_IDS } from "./plan.mjs";
import { tempDir } from "./record/testtmp.mjs";

const conformance = join(fileURLToPath(new URL(".", import.meta.url)), "../..");
const SUFFIX = "ab12cd";
const copy = tempDir("tq-fixture-");
cpSync(join(conformance, "task-queue-functions/functions"), join(copy, "functions"), {
  recursive: true,
});
writeFileSync(join(copy, "functions/suffix.json"), JSON.stringify({ suffix: SUFFIX }));
assert.ok(existsSync(join(conformance, "node_modules/firebase-functions/package.json")));
symlinkSync(join(conformance, "node_modules"), join(copy, "functions/node_modules"));
process.env.FUNCTIONS_EMULATOR = "true";
const fixture = createRequire(join(copy, "functions/index.js"))("./index.js");

const HEADERS = {
  "content-type": "application/json",
  "content-length": "99",
  "user-agent": "Google-Cloud-Tasks",
  "accept-encoding": "gzip",
  "x-forwarded-proto": "https",
  "x-cloudtasks-queuename": "tqretry" + SUFFIX,
  "x-cloudtasks-taskname": "task-1",
  "x-cloudtasks-taskretrycount": "0",
  "x-cloudtasks-taskexecutioncount": "0",
  "x-cloudtasks-tasketa": "1234567890.938251",
  authorization: "Bearer secret.token.value",
  host: "internal.example",
  traceparent: "00-secret-trace",
};

/** Runs one delivery and returns the response and the frames it printed, in order. */
async function deliver(role, { data, headers = {}, rawBody = undefined } = {}) {
  const all = { ...HEADERS, ...headers };
  const raw = rawBody ?? Buffer.from(JSON.stringify({ data }));
  const req = {
    method: "POST",
    headers: all,
    body: JSON.parse(raw.toString("utf8")),
    rawBody: raw,
    originalUrl: "/",
    url: "/",
    header: (name) => all[name.toLowerCase()],
    get: (name) => all[name.toLowerCase()],
    is: (type) => type === "json" || type === "application/json",
  };
  const res = {
    statusCode: 0,
    status(code) {
      this.statusCode = code;
      return this;
    },
    end() {
      return this;
    },
    send(body) {
      this.sent = body;
      return this;
    },
    json(body) {
      this.sent = body;
      return this;
    },
    set() {
      return this;
    },
    setHeader() {
      return this;
    },
  };
  const lines = [];
  const log = console.log;
  console.log = (...args) => lines.push(args.join(" "));
  try {
    await fixture[role + SUFFIX](req, res);
  } finally {
    console.log = log;
  }
  const frames = lines
    .filter((line) => line.startsWith(FRAME_MARK + " "))
    .map((line) => JSON.parse(line.slice(FRAME_MARK.length + 1)));
  return { res, frames, lines };
}

test("the fixture exports one task queue function per role, named with the run's suffix, with the role's settings", () => {
  assert.deepEqual(Object.keys(fixture).toSorted(), ROLE_IDS.map((r) => r + SUFFIX).toSorted());
  for (const role of ROLE_IDS) {
    const trigger = fixture[role + SUFFIX].__endpoint.taskQueueTrigger;
    for (const group of ["retryConfig", "rateLimits"])
      for (const [key, value] of Object.entries(ROLES[role][group] ?? {}))
        assert.equal(trigger[group][key], value, `${role} ${group}.${key}`);
    assert.deepEqual(fixture[role + SUFFIX].__endpoint.region, ["us-central1"]);
  }
});

test("a delivery prints a start frame before it works and an end frame after, and answers 204", async () => {
  const data = { run: "tqrun-x", case: "c1" };
  const { res, frames } = await deliver("tqdef", { data });
  assert.equal(res.statusCode, 204);
  assert.deepEqual(
    frames.map((f) => f.kind),
    ["start", "end"],
  );
  const [start, end] = frames;
  assert.equal(start.function, "tqdef" + SUFFIX);
  assert.equal(start.role, "tqdef");
  assert.equal(start.run, "tqrun-x");
  assert.equal(start.case, "c1");
  assert.deepEqual(start.step, { status: "ok", sleepMs: 0 });
  assert.equal(end.startedAt, start.at);
  assert.equal(end.status, "ok");
  assert.equal(end.id, "task-1");
  assert.equal(end.retryCount, 0);
  assert.ok(Date.parse(end.at) >= Date.parse(start.at));
  assert.deepEqual(start.context, {
    id: "task-1",
    queueName: "tqretry" + SUFFIX,
    retryCount: 0,
    executionCount: 0,
    scheduledTime: "1234567890.938251",
    previousResponse: null,
    retryReason: null,
    hasAuth: false,
  });
});

test("the request is described by name, with a value only for the headers that are listed, and a credential by its shape", async () => {
  const { frames } = await deliver("tqdef", { data: { run: "tqrun-x", case: "c1" } });
  const { request } = frames[0];
  assert.equal(request.method, "POST");
  assert.equal(request.path, "/");
  assert.deepEqual(request.headers.authorization, { scheme: "Bearer", segments: 3 });
  assert.equal(request.headers["user-agent"], "Google-Cloud-Tasks");
  assert.equal(request.headers["x-cloudtasks-tasketa"], "1234567890.938251");
  assert.equal(request.headers["content-type"], "application/json");
  assert.equal(request.headers.host, null);
  assert.equal(request.headers.traceparent, null);
  assert.deepEqual(Object.keys(request.headers).toSorted(), Object.keys(HEADERS).toSorted());
});

test("nothing secret is printed: no token, no trace value, no host", async () => {
  const { lines } = await deliver("tqdef", { data: { run: "tqrun-x", case: "c1" } });
  const text = lines.join("\n");
  for (const secret of ["secret.token.value", "secret-trace", "internal.example"])
    assert.equal(text.includes(secret), false, secret);
});

test("the body is described by length and digest, and shown up to 4096 bytes", async () => {
  const small = Buffer.from('{ "data" :  {"run":"tqrun-x","case":"c" } }');
  const { frames } = await deliver("tqdef", { rawBody: small });
  assert.equal(frames[0].request.bodyLength, small.length);
  assert.equal(frames[0].request.bodyText, small.toString("utf8"));
  assert.equal(frames[0].request.bodySha256, createHash("sha256").update(small).digest("hex"));
  const withPad = (n) =>
    Buffer.from(JSON.stringify({ data: { run: "tqrun-x", case: "c", pad: "p".repeat(n) } }));
  const exactly = withPad(4096 - withPad(0).length);
  assert.equal(exactly.length, 4096);
  const edge = await deliver("tqdef", { rawBody: exactly });
  assert.equal(edge.frames[0].request.bodyText, exactly.toString("utf8"));
  const big = withPad(4097 - withPad(0).length);
  assert.equal(big.length, 4097);
  const over = await deliver("tqdef", { rawBody: big });
  assert.equal(over.frames[0].request.bodyText, null);
  assert.equal(over.frames[0].request.bodyLength, big.length);
  assert.equal(over.frames[0].request.bodySha256, createHash("sha256").update(big).digest("hex"));
});

test("a step is chosen by the retry count, the last step repeats, and an unknown status is an ok", async () => {
  const script = [{ status: "internal" }, { status: "unavailable" }, { status: "ok" }];
  const at = async (retryCount) =>
    (
      await deliver("tqretry", {
        data: { run: "tqrun-x", case: "c", script },
        headers: { "x-cloudtasks-taskretrycount": String(retryCount) },
      })
    ).res.statusCode;
  assert.deepEqual(
    [await at(0), await at(1), await at(2), await at(3), await at(9)],
    [500, 503, 204, 204, 204],
  );
  const status = async (code) =>
    (await deliver("tqdef", { data: { run: "tqrun-x", case: "c", script: [{ status: code }] } }))
      .res.statusCode;
  assert.equal(await status("bogus"), 204);
  assert.equal(await status(undefined), 204);
  assert.equal(await status("unauthenticated"), 204, "only the six listed codes are scripted");
  const none = await deliver("tqdef", { data: { run: "tqrun-x", case: "c", script: [] } });
  assert.equal(none.res.statusCode, 204);
  const absent = await deliver("tqdef", { data: { run: "tqrun-x", case: "c" } });
  assert.equal(absent.res.statusCode, 204);
});

test("each scripted code becomes the status the SDK maps it to, and the end frame names it", async () => {
  const expected = {
    internal: 500,
    "resource-exhausted": 429,
    unavailable: 503,
    "invalid-argument": 400,
    "not-found": 404,
    "permission-denied": 403,
  };
  for (const [code, status] of Object.entries(expected)) {
    const { res, frames } = await deliver("tqdef", {
      data: { run: "tqrun-x", case: "c", script: [{ status: code }] },
    });
    assert.equal(res.statusCode, status, code);
    assert.equal(frames.at(-1).kind, "end");
    assert.equal(frames.at(-1).status, code);
  }
});

test("a sleep is honoured only as a positive integer, and the end frame follows it", async () => {
  const run = async (sleepMs) =>
    deliver("tqdef", { data: { run: "tqrun-x", case: "c", script: [{ status: "ok", sleepMs }] } });
  const slept = await run(60);
  const [a, b] = slept.frames;
  assert.equal(a.step.sleepMs, 60);
  assert.ok(Date.parse(b.at) - Date.parse(a.at) >= 55);
  for (const bad of [-5, 1.5, "10", null, 0]) {
    const out = await run(bad);
    assert.equal(out.frames[0].step.sleepMs, 0, String(bad));
  }
});
