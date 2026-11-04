// The command line: nothing is sent without --send and the approved digest, the local checks refuse a wrong environment, the
// API key is used only for the sign-up and never written anywhere, the read-back waits ten minutes and never closes an unknown
// create, the digest binds every module the packet imports, and the exit codes mean what the header says.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { tempDir } from "./testtmp.mjs";
import {
  PACKET_FILES,
  envProblems,
  lastActivity,
  localChecks,
  main,
  packetDigest,
  parseArgs,
  readApiKey,
  realDeps,
  resultOf,
} from "./main.mjs";
import { SIGN_UP_URL } from "./plan.mjs";
import { SETTLE_MS } from "./readback.mjs";

const SHA = "a".repeat(40);
const RUN = "0123456789abcdef";
const DIGEST = "d".repeat(64);
const KEY = "AIzaSyTESTKEYTESTKEYTESTKEYTESTKEY12";
const env = { HOME: "/h", PATH: "/usr/bin" };
const goodDeps = (over = {}) => ({
  nodeVersion: () => "22.22.1",
  firebaseToolsVersion: () => "15.28.2",
  gitHead: () => SHA,
  gitDirty: () => false,
  adcExists: () => true,
  sdkProblems: () => [],
  repoRoot: () => "/repo",
  prepareSource: () => ({ configPath: "/s/firebase.json", fixtureDir: "/s/fixture" }),
  sourceProblems: () => [],
  token: () => "tok-abcdefgh12345",
  send: async () => new Response("{}"),
  runCli: async () => ({}),
  signals: () => {},
  readFile: () => JSON.stringify({ projectId: "fireemu-oracle-idp", apiKey: KEY }),
  ...over,
});
const dir = () => tempDir("pcb-main-");
const args = (d, over = {}) => {
  const values = {
    "run-dir": d,
    "project-number": "123456789012",
    "source-commit": SHA,
    "venv-dir": "/v",
    node: "/n/node",
    "firebase-js": "/f/lib/bin.js",
    ...over,
  };
  return Object.entries(values).flatMap(([k, v]) => (v === undefined ? [] : ["--" + k, v]));
};
const run = async (argv, deps = goodDeps(), environment = env) => {
  const out = [];
  const err = [];
  const code = await main(argv, {
    env: environment,
    deps,
    out: (m) => out.push(m),
    err: (m) => err.push(m),
    digest: DIGEST,
  });
  return { code, out, err: err.join("\n"), outText: out.join("\n") };
};
const RECORD = (d, extra = []) => [
  "record",
  ...args(d),
  "--web-config",
  "/w.json",
  "--send",
  "--expect-digest",
  DIGEST,
  ...extra,
];

test("arguments: a command, flags with values, --send without one", () => {
  assert.deepEqual(parseArgs(["check", "--run-dir", "x", "--send"]), {
    command: "check",
    values: { "run-dir": "x", send: true },
  });
  assert.match(parseArgs(["check", "x"]).error, /unexpected argument/);
  assert.match(parseArgs(["check", "--run-dir"]).error, /needs a value/);
  assert.match(parseArgs(["check", "--run-dir", "--send"]).error, /needs a value/);
});

test("an unknown command or bad arguments exit 2 with the reason and send nothing", async () => {
  assert.equal((await run(["deploy"])).err, "the command is check, record or readback");
  assert.equal((await run([])).code, 2);
  assert.equal((await run(["check", "oops"])).err, "unexpected argument oops");
});

test("ambient credentials and emulator variables are refused", () => {
  const bad = {
    GOOGLE_APPLICATION_CREDENTIALS: "x",
    FIREBASE_TOKEN: "x",
    CLOUDSDK_CORE_PROJECT: "x",
    GCLOUD_PROJECT: "x",
    GOOGLE_CLOUD_PROJECT: "x",
    FIREBASE_AUTH_EMULATOR_HOST: "x",
    HOME: "/h",
  };
  assert.equal(envProblems(bad).length, 6);
  assert.deepEqual(envProblems({ HOME: "/h", PATH: "/bin" }), []);
});

const CHECKS = [
  ["a wrong Node", { nodeVersion: () => "20.0.0" }, /Node is 20/],
  ["a wrong firebase-tools", { firebaseToolsVersion: () => "14.0.0" }, /firebase-tools is 14/],
  ["another HEAD", { gitHead: () => "b".repeat(40) }, /HEAD is not the source commit/],
  ["a dirty tree", { gitDirty: () => true }, /not clean/],
  [
    "a wrong SDK",
    { sdkProblems: () => ["firebase-functions is 0.7.0, not 0.6.0"] },
    /firebase-functions is 0\.7/,
  ],
  ["a missing credential file", { adcExists: () => false }, /credential file is missing/],
];
for (const [name, over, pattern] of CHECKS)
  test(`check fails on ${name}`, async () => {
    const { code, err } = await run(["check", ...args(dir())], goodDeps(over));
    assert.equal(code, 2);
    assert.match(err, pattern);
  });

test("a missing flag or a bad value is the only problem reported, and no check runs before the arguments are valid", () => {
  const full = {
    "run-dir": "x",
    "project-number": "123456789012",
    "source-commit": SHA,
    "venv-dir": "/v",
    node: "n",
    "firebase-js": "f",
  };
  const forbidden = Object.fromEntries(
    ["nodeVersion", "firebaseToolsVersion", "gitHead", "gitDirty", "adcExists", "sdkProblems"].map(
      (name) => [name, () => assert.fail(name + " called")],
    ),
  );
  const only = (over, environment = { HOME: "/h" }) =>
    localChecks({ values: { ...full, ...over }, env: environment, deps: forbidden });
  assert.deepEqual(only({ "venv-dir": undefined }), ["--venv-dir is required"]);
  assert.deepEqual(only({ "project-number": undefined }), ["--project-number is required"]);
  assert.deepEqual(only({ "source-commit": undefined }), ["--source-commit is required"]);
  assert.deepEqual(only({ "project-number": "1" }), ["--project-number is 12 or 13 digits"]);
  assert.deepEqual(only({ "project-number": "12345678901234" }), [
    "--project-number is 12 or 13 digits",
  ]);
  assert.deepEqual(only({ "source-commit": "x" }), ["--source-commit is a full SHA"]);
  assert.deepEqual(only({}, {}), ["HOME is not set"]);
  const ok = {
    ...forbidden,
    nodeVersion: () => "22.22.1",
    firebaseToolsVersion: () => "15.28.2",
    gitHead: () => "0123456789abcdef0123456789abcdef01234567",
    gitDirty: () => false,
    adcExists: () => true,
    sdkProblems: () => [],
  };
  assert.deepEqual(
    localChecks({
      values: {
        ...full,
        "source-commit": "0123456789abcdef0123456789abcdef01234567",
        "project-number": "1234567890123",
      },
      env: { HOME: "/h" },
      deps: ok,
    }),
    [],
  );
});

test("check passes, prepares the source, and sends nothing", async () => {
  let sent = 0;
  let recorded = 0;
  const { code, out } = await run(
    ["check", ...args(dir())],
    goodDeps({ send: async () => sent++, record: async () => recorded++ }),
  );
  assert.equal(code, 0);
  assert.match(out.join("\n"), /check passed: nothing was sent/);
  assert.equal(sent + recorded, 0);
  assert.equal(
    out[0],
    JSON.stringify(
      { project: "fireemu-oracle-idp", command: "check", maxRequests: 250, packetDigest: DIGEST },
      null,
      2,
    ),
  );
  const failing = await run(
    ["check", ...args(dir())],
    goodDeps({ sourceProblems: () => ["entry point x"] }),
  );
  assert.equal(failing.code, 2);
  assert.match(failing.err, /the source copy failed its offline checks:\n- entry point x/);
});

test("check validates a named web config but prints nothing of it", async () => {
  const ok = await run(["check", ...args(dir()), "--web-config", "/w.json"]);
  assert.equal(ok.code, 0);
  assert.ok(!ok.outText.includes(KEY) && !ok.err.includes(KEY));
  const wrong = await run(
    ["check", ...args(dir()), "--web-config", "/w.json"],
    goodDeps({ readFile: () => JSON.stringify({ projectId: "fireemu-oracle-sbx", apiKey: KEY }) }),
  );
  assert.equal(wrong.code, 2);
  assert.match(wrong.err, /not the identity sandbox project's/);
  assert.ok(!wrong.err.includes(KEY));
});

test("the web config must be JSON, name this project and carry a usable key", () => {
  const read = (value) => () => (typeof value === "string" ? value : JSON.stringify(value));
  assert.deepEqual(readApiKey("/w", read({ projectId: "fireemu-oracle-idp", apiKey: KEY })), {
    apiKey: KEY,
  });
  assert.match(readApiKey("/w", read("not json")).error, /cannot be read as JSON/);
  assert.match(
    readApiKey("/w", () => {
      throw new Error("ENOENT");
    }).error,
    /cannot be read as JSON/,
  );
  assert.match(
    readApiKey("/w", read({ projectId: "other", apiKey: KEY })).error,
    /not the identity sandbox project's/,
  );
  assert.match(readApiKey("/w", read({ apiKey: KEY })).error, /not the identity sandbox project's/);
  for (const apiKey of [
    undefined,
    "",
    "short",
    "x".repeat(65),
    "has space has space has space",
    5,
    "AIza\nSyKEYKEYKEYKEYKEYKEYKEY",
  ])
    assert.match(
      readApiKey("/w", read({ projectId: "fireemu-oracle-idp", apiKey })).error,
      /no usable apiKey/,
      String(apiKey),
    );
});

test("record needs --send, the exact digest and a usable web config, and says which digest this packet has", async () => {
  let recorded = 0;
  const deps = goodDeps({ record: async () => (recorded++, {}) });
  for (const extra of [
    [],
    ["--send"],
    ["--expect-digest", DIGEST],
    ["--send", "--expect-digest", "e".repeat(64)],
    ["--send", "--expect-digest", "D".repeat(64)],
  ]) {
    const { code, err } = await run(
      ["record", ...args(dir()), "--web-config", "/w.json", ...extra],
      deps,
    );
    assert.equal(code, 2, extra.join(" "));
    assert.equal(
      err,
      `record needs --send and the approved --expect-digest; this packet's digest is ${DIGEST}`,
    );
  }
  const noConfig = await run(["record", ...args(dir()), "--send", "--expect-digest", DIGEST], deps);
  assert.equal(noConfig.code, 2);
  assert.match(noConfig.err, /record needs --web-config/);
  const badConfig = await run(
    RECORD(dir()),
    goodDeps({ record: deps.record, readFile: () => "{}" }),
  );
  assert.equal(badConfig.code, 2);
  assert.match(
    badConfig.err,
    /record cannot use the web config: the web config is not the identity sandbox project's/,
  );
  assert.equal(recorded, 0);
});

test("record passes the run to the recorder, writes the journal and the result, and exits 0 only when closable", async () => {
  for (const [closureReady, expected] of [
    [true, 0],
    [false, 3],
  ]) {
    const d = join(dir(), "a", "b");
    let seen;
    const result = {
      outcome: "pcblock-recorded",
      closureReady,
      readBackRequired: !closureReady,
      attempted: 2,
    };
    const deps = goodDeps({
      record: async (options) => {
        seen = options;
        await options.save({ id: "a", state: "before-send" });
        await options.save({ id: "b", state: "response-persisted" });
        return result;
      },
    });
    const { code, out } = await run(RECORD(d), deps);
    assert.equal(code, expected);
    assert.match(seen.runId, /^[0-9a-f]{16}$/);
    assert.equal(seen.projectNumber, "123456789012");
    assert.equal(seen.accessToken, "tok-abcdefgh12345");
    assert.equal(
      readFileSync(join(d, `journal-${seen.runId}.jsonl`), "utf8"),
      '{"id":"a","state":"before-send"}\n{"id":"b","state":"response-persisted"}\n',
    );
    assert.equal(
      readFileSync(join(d, `result-${seen.runId}.json`), "utf8"),
      JSON.stringify(result, null, 2) + "\n",
    );
    assert.equal(lstatSync(join(d, `result-${seen.runId}.json`)).mode & 0o777, 0o600);
    assert.equal(lstatSync(join(d, `journal-${seen.runId}.jsonl`)).mode & 0o777, 0o600);
    assert.equal(lstatSync(d).mode & 0o777, 0o700);
    assert.equal(
      out.at(-1),
      JSON.stringify(
        {
          runId: seen.runId,
          outcome: "pcblock-recorded",
          closureReady,
          readBackRequired: !closureReady,
          attempted: 2,
        },
        null,
        2,
      ),
    );
    assert.equal(
      out[0],
      JSON.stringify(
        {
          project: "fireemu-oracle-idp",
          command: "record",
          maxRequests: 250,
          packetDigest: DIGEST,
        },
        null,
        2,
      ),
    );
  }
});

test("the API key goes only in the sign-up's header, with none of the owner's credential; every other request carries the owner's token", async () => {
  const sent = [];
  const d = dir();
  const deps = goodDeps({
    send: async (request) => (sent.push(request), new Response(JSON.stringify({ localId: "x" }))),
    record: async (o) => {
      await o.send({
        url: SIGN_UP_URL,
        method: "POST",
        headers: {
          authorization: "Bearer should-not-survive",
          "x-goog-user-project": "p",
          "content-type": "application/json",
        },
        body: "{}",
      });
      await o.send({ url: "https://example.com/other", method: "GET", headers: { accept: "x" } });
      await o.save({ id: "sign-up", state: "before-send", url: SIGN_UP_URL });
      return { outcome: "x", closureReady: true, attempted: 2 };
    },
  });
  const { out, err } = await run(RECORD(d), deps);
  assert.deepEqual(sent[0].headers, { "content-type": "application/json", "x-goog-api-key": KEY });
  assert.deepEqual(sent[1].headers, { accept: "x", authorization: "Bearer tok-abcdefgh12345" });
  const files = readdirSync(d)
    .filter((f) => f.endsWith(".json") || f.endsWith(".jsonl"))
    .map((f) => readFileSync(join(d, f), "utf8"))
    .join("\n");
  assert.ok(files.length > 0);
  assert.ok(!files.includes(KEY) && !out.join("\n").includes(KEY) && !err.includes(KEY));
});

test("a response that reflects the API key or the token is refused", async () => {
  for (const reflected of [KEY, "tok-abcdefgh12345"]) {
    const deps = goodDeps({
      send: async () => new Response("echo " + reflected),
      record: async (o) => {
        await assert.rejects(
          o.send({ url: SIGN_UP_URL, method: "POST", headers: {}, body: "{}" }),
          /reflected a credential/,
        );
        return { outcome: "x", closureReady: true, attempted: 1 };
      },
    });
    assert.equal((await run(RECORD(dir()), deps)).code, 0, reflected);
  }
});

test("the token is asked again when it is old, and a response that reflects the new token is refused", async () => {
  let now = 0;
  let issued = 0;
  const sent = [];
  let respond = () => new Response("{}");
  const deps = goodDeps({
    now: () => now,
    token: () => `tok-${++issued}-abcdefgh`,
    send: async (request) => (sent.push(request.headers.authorization), respond()),
    record: async (o) => {
      await o.prepareRequest({ id: "one" });
      await o.send({ url: "https://example.com/1", method: "GET", headers: {} });
      now += 41 * 60 * 1000;
      await o.prepareRequest({ id: "two" });
      await o.send({ url: "https://example.com/2", method: "GET", headers: {} });
      respond = () => new Response("echo tok-2-abcdefgh");
      await assert.rejects(
        o.send({ url: "https://example.com/3", method: "GET", headers: {} }),
        /reflected a credential/,
      );
      return { outcome: "x", closureReady: true, attempted: 3 };
    },
  });
  await run(RECORD(dir()), deps);
  assert.deepEqual(sent, [
    "Bearer tok-1-abcdefgh",
    "Bearer tok-2-abcdefgh",
    "Bearer tok-2-abcdefgh",
  ]);
  assert.equal(issued, 2);
});

test("the CLI the recorder gets runs the pinned plan from the prepared source, with a private configuration directory", async () => {
  let call;
  const deps = goodDeps({
    runCli: async (o) => ((call = o), {}),
    record: async (o) => (
      await o.runCli({ action: "delete" }),
      { outcome: "x", closureReady: true, attempted: 0 }
    ),
  });
  await run(RECORD(dir()), deps);
  assert.equal(call.action, "delete");
  assert.equal(call.plan.args[0], "functions:delete");
  assert.equal(call.node, "/n/node");
  assert.equal(call.firebaseJs, "/f/lib/bin.js");
  assert.equal(call.plan.cwd, "/s");
  assert.ok(call.plan.env.PATH.startsWith("/n:"));
  assert.equal(lstatSync(call.plan.env.XDG_CONFIG_HOME).mode & 0o777, 0o700);
});

test("a recorder that throws exits 4 and leaves a result saying so; a stop signal is passed on once", async () => {
  const d = dir();
  const { code, err } = await run(
    RECORD(d),
    goodDeps({
      record: async () => {
        throw new Error("boom");
      },
    }),
  );
  assert.equal(code, 4);
  assert.match(err, /boom/);
  const file = readdirSync(d).find((f) => f.startsWith("result-"));
  assert.equal(
    readFileSync(join(d, file), "utf8"),
    JSON.stringify({ outcome: "pcblock-recorder-threw", message: "boom" }, null, 2) + "\n",
  );
  let handler;
  const errors = [];
  let seen;
  await main(RECORD(dir()), {
    env,
    deps: goodDeps({
      signals: (h) => (handler = h),
      record: async (o) => (
        (seen = o.signal),
        handler("SIGINT"),
        handler("SIGINT"),
        { outcome: "x", closureReady: false, attempted: 0 }
      ),
    }),
    out: () => {},
    err: (m) => errors.push(m),
    digest: DIGEST,
  });
  assert.equal(seen.aborted, true);
  assert.match(errors[0], /stopping at the next request/);
  assert.match(errors[1], /already under way/);
});

// ---- readback -----------------------------------------------------------------------------------------

function finishedRun(
  result = {
    unconfirmedCreates: [],
    signUp: { localId: "L".repeat(28) },
    inventory: { before: { accounts: 3 } },
    configBefore: { sha256: "c".repeat(64) },
  },
  at = Date.parse("2026-11-05T00:00:00Z"),
) {
  const d = dir();
  writeFileSync(
    join(d, `journal-${RUN}.jsonl`),
    JSON.stringify({
      id: "x",
      dispatchAt: new Date(at).toISOString(),
      responseAt: new Date(at + 1000).toISOString(),
    }) + "\n",
  );
  if (result) writeFileSync(join(d, `result-${RUN}.json`), JSON.stringify(result));
  return { d, at };
}
const rbArgs = (d, extra = []) => [
  "readback",
  "--run-dir",
  d,
  "--project-number",
  "123456789012",
  "--run-id",
  RUN,
  "--send",
  "--expect-digest",
  DIGEST,
  ...extra,
];
const rbDeps = (at, over = {}) =>
  goodDeps({
    now: () => at + 1000 + SETTLE_MS,
    readback: async () => ({ allAbsent: true, attempted: 5, unknown: 0 }),
    ...over,
  });

test("readback needs --send, the digest, a run id and a journal, and says why", async () => {
  const { d, at } = finishedRun();
  const without = rbArgs(d).filter((a) => a !== "--send");
  assert.equal(
    (await run(without, rbDeps(at))).err,
    `readback needs --send and the approved --expect-digest; this packet's digest is ${DIGEST}`,
  );
  const noRun = await run(
    [
      "readback",
      "--run-dir",
      d,
      "--project-number",
      "123456789012",
      "--send",
      "--expect-digest",
      DIGEST,
    ],
    rbDeps(at),
  );
  assert.equal(noRun.code, 2);
  assert.match(noRun.err, /- --run-id is required/);
  const badIds = await run(
    ["readback", "--run-dir", "x", "--project-number", "12", "--run-id", "zz", "--send"],
    rbDeps(at),
  );
  assert.match(
    badIds.err,
    /--project-number is 12 or 13 digits\n- --run-id is 16 hexadecimal digits/,
  );
  const noHome = await run(rbArgs(d), rbDeps(at), { PATH: "/usr/bin" });
  assert.match(noHome.err, /HOME is not set/);
  const missing = await run(
    [
      "readback",
      "--run-dir",
      dir(),
      "--project-number",
      "123456789012",
      "--run-id",
      RUN,
      "--send",
      "--expect-digest",
      DIGEST,
    ],
    rbDeps(at),
  );
  assert.equal(missing.err, `there is no journal of run ${RUN} in the run directory`);
  const thirteen = await run(
    [
      "readback",
      "--run-dir",
      d,
      "--project-number",
      "1234567890123",
      "--run-id",
      RUN,
      "--send",
      "--expect-digest",
      DIGEST,
    ],
    rbDeps(at),
  );
  assert.equal(thirteen.code, 0);
});

test("readback waits ten minutes after the last request", async () => {
  const { d, at } = finishedRun();
  let ran = 0;
  const early = await run(
    rbArgs(d),
    rbDeps(at, { now: () => at + 1000 + 599_000, readback: async () => (ran++, {}) }),
  );
  assert.equal(early.code, 2);
  assert.equal(ran, 0);
  assert.equal(
    early.err,
    `the last request of run ${RUN} was 599 seconds ago; wait until ten minutes have passed`,
  );
  assert.equal((await run(rbArgs(d), rbDeps(at))).code, 0);
});

test("readback hands the recorded baselines to the read, journals privately and prints pretty", async () => {
  const { d, at } = finishedRun();
  let seen;
  const stamp = at + 1000 + SETTLE_MS;
  const { out, code } = await run(
    rbArgs(d),
    rbDeps(at, {
      readback: async (o) => (
        (seen = o),
        await o.save({ id: "r" }),
        { allAbsent: true, attempted: 1, unknown: 0 }
      ),
    }),
  );
  assert.equal(code, 0);
  assert.equal(seen.runId, RUN);
  assert.equal(seen.localId, "L".repeat(28));
  assert.equal(seen.accountsBefore, 3);
  assert.equal(seen.configBeforeDigest, "c".repeat(64));
  assert.deepEqual(seen.uploadObjects, []);
  assert.equal(readFileSync(join(d, `readback-${RUN}-${stamp}.jsonl`), "utf8"), '{"id":"r"}\n');
  assert.equal(lstatSync(join(d, `readback-${RUN}-${stamp}.jsonl`)).mode & 0o777, 0o600);
  assert.equal(
    readFileSync(join(d, `readback-result-${RUN}-${stamp}.json`), "utf8"),
    JSON.stringify(
      { allAbsent: true, attempted: 1, unknown: 0, unconfirmedCreates: [], judged: true },
      null,
      2,
    ) + "\n",
  );
  assert.equal(
    out.at(-1),
    JSON.stringify(
      {
        runId: RUN,
        allAbsent: true,
        attempted: 1,
        unknown: 0,
        unconfirmedCreates: [],
        inventory: null,
        carried: [],
      },
      null,
      2,
    ),
  );
  assert.equal(
    out[0],
    JSON.stringify(
      { project: "fireemu-oracle-idp", command: "readback", maxRequests: 60, packetDigest: DIGEST },
      null,
      2,
    ),
  );
});

test("readback exits 3 when something is still there, never closes an unknown create, and exits 4 when it stops", async () => {
  const left = finishedRun();
  assert.equal(
    (
      await run(
        rbArgs(left.d),
        rbDeps(left.at, { readback: async () => ({ allAbsent: false, attempted: 5, unknown: 0 }) }),
      )
    ).code,
    3,
  );
  const unconfirmed = finishedRun({
    unconfirmedCreates: [{ label: "account", name: "a@example.com" }],
    signUp: { localId: null },
    inventory: { before: { accounts: 3 } },
    configBefore: { sha256: "c".repeat(64) },
  });
  const r = await run(rbArgs(unconfirmed.d), rbDeps(unconfirmed.at));
  assert.equal(r.code, 3);
  assert.match(r.err, /a 404 never settles an unknown create, here or in the run\): a@example.com/);
  for (const result of [null, { outcome: "x" }]) {
    const f = finishedRun(result);
    const x = await run(rbArgs(f.d), rbDeps(f.at));
    assert.equal(x.code, 3);
    assert.match(x.err, /cannot be judged/);
  }
  const broken = finishedRun();
  const stopped = await run(
    rbArgs(broken.d),
    rbDeps(broken.at, {
      readback: async () => {
        throw new Error("net down");
      },
    }),
  );
  assert.equal(stopped.code, 4);
  assert.equal(stopped.err, "the read-back stopped: net down");
});

test("the latest time in a journal wins, and a file that cannot be read has none; resultOf reads what the read-back needs", () => {
  const d = dir();
  const path = join(d, "j.jsonl");
  writeFileSync(
    path,
    [
      '{"dispatchAt":"2026-11-05T00:20:00.000Z"}',
      "",
      "not json",
      '{"responseAt":"2026-11-05T00:30:00.000Z"}',
      '{"responseAt":"2026-11-05T00:25:00.000Z"}',
      '{"responseAt":"bad"}',
      "{}",
      "",
    ].join("\n"),
  );
  assert.equal(lastActivity(path), Date.parse("2026-11-05T00:30:00Z"));
  assert.equal(lastActivity(join(d, "nope")), null);
  const file = join(d, "r.json");
  writeFileSync(
    file,
    JSON.stringify({
      unconfirmedCreates: [],
      signUp: { localId: 5 },
      inventory: { before: { accounts: 1.5 } },
      configBefore: { sha256: 5 },
    }),
  );
  assert.deepEqual(resultOf(file), {
    ok: true,
    creates: [],
    localId: null,
    accountsBefore: null,
    configBeforeDigest: null,
    uploadObjects: [],
    baseline: { accounts: 1.5 },
    carried: [],
  });
  writeFileSync(file, "{");
  assert.equal(resultOf(file).why, "the run's result file cannot be read (not JSON)");
  assert.equal(resultOf(join(d, "none")).why, "the run's result file cannot be read (ENOENT)");
  writeFileSync(file, "{}");
  assert.equal(resultOf(file).why, "the run's result has no list of unconfirmed creates");
});

// ---- the packet ---------------------------------------------------------------------------------------

test("the digest is the sha256 of 'name TAB sha256(content) LF' lines in packet order", () => {
  const contents = Object.fromEntries(
    PACKET_FILES.map((name) => [name, Buffer.from("content of " + name)]),
  );
  const expected = createHash("sha256")
    .update(
      PACKET_FILES.map(
        (name) => `${name}\t${createHash("sha256").update(contents[name]).digest("hex")}\n`,
      ).join(""),
    )
    .digest("hex");
  assert.equal(
    packetDigest((name) => contents[name]),
    expected,
  );
  for (const name of PACKET_FILES)
    assert.notEqual(
      packetDigest((n) => (n === name ? Buffer.from("changed") : contents[n])),
      expected,
      name,
    );
  assert.equal(PACKET_FILES.length, 17);
  assert.equal(new Set(PACKET_FILES).size, 17);
  assert.deepEqual(PACKET_FILES.slice(-3), [
    "fixture/main.py",
    "fixture/requirements.txt",
    "firebase.json",
  ]);
});

test("every local module a packet module imports is itself part of the packet, and every listed file exists", () => {
  const root = join(dirname(fileURLToPath(import.meta.url)), "..");
  const listed = new Set(PACKET_FILES.map((name) => join(root, name)));
  const missing = [];
  for (const name of PACKET_FILES.filter((n) => n.endsWith(".mjs"))) {
    const file = join(root, name);
    for (const match of readFileSync(file, "utf8").matchAll(
      /(?:from|import)\s*\(?\s*"(\.{1,2}\/[^"]+)"/g,
    ))
      if (!listed.has(join(dirname(file), match[1]))) missing.push(`${name} imports ${match[1]}`);
  }
  assert.deepEqual(missing, []);
  for (const file of listed) assert.ok(existsSync(file), file);
  assert.match(packetDigest(), /^[0-9a-f]{64}$/);
});

test("the real adapters answer for this machine", () => {
  assert.equal(realDeps.nodeVersion(process.execPath), process.versions.node);
  const home = dir();
  assert.equal(realDeps.adcExists(home), false);
  mkdirSync(join(home, ".config/gcloud"), { recursive: true });
  writeFileSync(join(home, ".config/gcloud/application_default_credentials.json"), "{}");
  assert.equal(realDeps.adcExists(home), true);
  const root = join(dir(), "firebase-tools");
  mkdirSync(join(root, "lib", "bin"), { recursive: true });
  writeFileSync(join(root, "package.json"), JSON.stringify({ version: "15.28.2" }));
  assert.equal(realDeps.firebaseToolsVersion(join(root, "lib", "bin", "firebase.js")), "15.28.2");
  const here = dirname(fileURLToPath(import.meta.url));
  assert.equal(
    realDeps.gitHead(),
    execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8", cwd: here }).trim(),
  );
  assert.equal(
    realDeps.gitDirty(),
    execFileSync("git", ["status", "--porcelain", "--ignored=no"], {
      encoding: "utf8",
      cwd: here,
    }).trim() !== "",
  );
  assert.match(realDeps.repoRoot(), /^\//);
  assert.equal(typeof realDeps.signals, "function");
});

test("readback never exits 0 while the run carries an open obligation: a clean A2 cannot settle an unknown upload, an unexplained object or a difference", async () => {
  const base = {
    unconfirmedCreates: [],
    signUp: { localId: "L".repeat(28) },
    inventory: { before: { accounts: 3 }, differences: [], complete: true },
    configBefore: { sha256: "c".repeat(64) },
  };
  const clean = finishedRun(base);
  const ok = await run(rbArgs(clean.d), rbDeps(clean.at));
  assert.equal(ok.code, 0, ok.err);
  for (const [label, patch] of [
    [
      "an upload reason",
      {
        cleanup: {
          uploadReasons: ["receipt-unconfirmed:514cacbe-3258-46fd-9a02-54b7485b0001.zip"],
        },
      },
    ],
    [
      "an unexplained object",
      { cleanup: { uploadObjectsUnexplained: [{ bucket: "b", name: "n.zip" }] } },
    ],
    [
      "an inventory difference",
      {
        inventory: {
          before: { accounts: 3 },
          differences: [{ kind: "topics", added: ["t"], removed: [] }],
        },
      },
    ],
    [
      "an incomplete inventory",
      { inventory: { before: { accounts: 3 }, complete: false, differences: [] } },
    ],
    ["a configuration difference", { cleanup: { configDifference: ["blockingFunctions"] } }],
    [
      "an invoker refusal",
      { cleanup: { invoker: { refused: "public-member-outside-the-invoker-binding" } } },
    ],
  ]) {
    const f = finishedRun({ ...base, ...patch });
    const r = await run(rbArgs(f.d), rbDeps(f.at));
    assert.equal(r.code, 3, label);
    assert.match(r.err, /open obligations that a read-back cannot settle/, label);
  }
});
