// The command line: nothing is sent without --send and the approved digest, the local checks refuse a wrong
// environment, the read-back waits ten minutes and never closes an unknown create, and the exit codes mean what the
// header says.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  PACKET_FILES,
  envProblems,
  lastActivity,
  localChecks,
  main,
  packetDigest,
  parseArgs,
  realDeps,
  resultOf,
} from "./main.mjs";
import { SETTLE_MS } from "./readback.mjs";

const SHA = "a".repeat(40);
const RUN = "0123456789abcdef";
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
  ...over,
});
const baseArgs = (dir) => [
  "--run-dir",
  dir,
  "--project-number",
  "123456789012",
  "--source-commit",
  SHA,
  "--venv-dir",
  "/v",
  "--node",
  "/n/node",
  "--firebase-js",
  "/f/lib/bin.js",
];
const env = { HOME: "/h", PATH: "/usr/bin" };
const run = async (argv, deps = goodDeps(), environment = env) => {
  const out = [];
  const err = [];
  const code = await main(argv, {
    env: environment,
    deps,
    out: (m) => out.push(m),
    err: (m) => err.push(m),
    digest: "d".repeat(64),
  });
  return { code, out, err };
};
const dir = () => mkdtempSync(join(tmpdir(), "pc-main-"));

test("arguments: a command, flags with values, --send without one", () => {
  assert.deepEqual(parseArgs(["check", "--run-dir", "x", "--send"]), {
    command: "check",
    values: { "run-dir": "x", send: true },
  });
  assert.match(parseArgs(["check", "x"]).error, /unexpected argument/);
  assert.match(parseArgs(["check", "--run-dir"]).error, /needs a value/);
  assert.match(parseArgs(["check", "--run-dir", "--send"]).error, /needs a value/);
});

test("an unknown command or bad arguments exit 2 and send nothing", async () => {
  assert.equal((await run(["deploy"])).code, 2);
  assert.equal((await run([])).code, 2);
  assert.equal((await run(["check", "oops"])).code, 2);
});

test("ambient credentials and emulator variables are refused", () => {
  const bad = {
    GOOGLE_APPLICATION_CREDENTIALS: "x",
    FIREBASE_TOKEN: "x",
    CLOUDSDK_CORE_PROJECT: "x",
    GCLOUD_PROJECT: "x",
    GOOGLE_CLOUD_PROJECT: "x",
    FIRESTORE_EMULATOR_HOST: "x",
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
    const { code, err } = await run(["check", ...baseArgs(dir())], goodDeps(over));
    assert.equal(code, 2);
    assert.match(err.join("\n"), pattern);
  });

test("check fails on a missing flag, a bad project number and a short commit", () => {
  const deps = goodDeps();
  const full = {
    "run-dir": "x",
    "project-number": "123456789012",
    "source-commit": SHA,
    "venv-dir": "/v",
    node: "n",
    "firebase-js": "f",
  };
  assert.deepEqual(localChecks({ values: full, env, deps }), []);
  for (const key of Object.keys(full))
    assert.ok(
      localChecks({ values: { ...full, [key]: undefined }, env, deps }).some((p) =>
        p.includes("--" + key),
      ),
    );
  assert.ok(
    localChecks({ values: { ...full, "project-number": "12" }, env, deps }).some((p) =>
      /12 or 13 digits/.test(p),
    ),
  );
  assert.ok(
    localChecks({ values: { ...full, "source-commit": "abc" }, env, deps }).some((p) =>
      /full SHA/.test(p),
    ),
  );
  assert.ok(localChecks({ values: full, env: {}, deps }).some((p) => /HOME/.test(p)));
});

test("check passes, prepares the source, and sends nothing", async () => {
  let sent = 0;
  let recorded = 0;
  const { code, out } = await run(
    ["check", ...baseArgs(dir())],
    goodDeps({ send: async () => sent++, record: async () => recorded++ }),
  );
  assert.equal(code, 0);
  assert.match(out.join("\n"), /check passed: nothing was sent/);
  assert.equal(sent + recorded, 0);
});

test("a source copy that fails its offline checks stops the command", async () => {
  const { code, err } = await run(
    ["check", ...baseArgs(dir())],
    goodDeps({ sourceProblems: () => ["pcps: topic other"] }),
  );
  assert.equal(code, 2);
  assert.match(err.join("\n"), /pcps: topic other/);
});

test("record needs --send and the exact digest, and says which digest this packet has", async () => {
  let recorded = 0;
  const deps = goodDeps({ record: async () => (recorded++, {}) });
  for (const extra of [
    [],
    ["--send"],
    ["--expect-digest", "d".repeat(64)],
    ["--send", "--expect-digest", "e".repeat(64)],
    ["--send", "--expect-digest", "D".repeat(64)],
  ]) {
    const { code, err } = await run(["record", ...baseArgs(dir()), ...extra], deps);
    assert.equal(code, 2, extra.join(" "));
    assert.match(err.join("\n"), /d{64}/);
  }
  assert.equal(recorded, 0);
});

test("record passes the run to the recorder, writes the journal and the result, and exits 0 only when closable", async () => {
  for (const [closureReady, expected] of [
    [true, 0],
    [false, 3],
  ]) {
    const d = dir();
    let seen;
    const deps = goodDeps({
      record: async (options) => {
        seen = options;
        await options.save({
          id: "x",
          state: "before-send",
          dispatchAt: "2026-11-05T00:00:00.000Z",
        });
        return {
          outcome: "pycheck-recorded",
          closureReady,
          readBackRequired: !closureReady,
          attempted: 1,
        };
      },
    });
    const { code } = await run(
      ["record", ...baseArgs(d), "--send", "--expect-digest", "d".repeat(64)],
      deps,
    );
    assert.equal(code, expected);
    assert.match(seen.runId, /^[0-9a-f]{16}$/);
    assert.equal(seen.projectNumber, "123456789012");
    assert.equal(seen.accessToken, "tok-abcdefgh12345");
    const files = readdirSync(d);
    assert.ok(
      files.includes("journal-" + seen.runId + ".jsonl") &&
        files.includes("result-" + seen.runId + ".json"),
    );
    assert.equal(
      JSON.parse(readFileSync(join(d, "result-" + seen.runId + ".json"), "utf8")).closureReady,
      closureReady,
    );
  }
});

test("the CLI the recorder gets runs the pinned plan from the prepared source", async () => {
  let call;
  const deps = goodDeps({
    runCli: async (options) => ((call = options), {}),
    record: async (options) => (
      await options.runCli({ action: "delete" }),
      { outcome: "x", closureReady: true, attempted: 0 }
    ),
  });
  await run(["record", ...baseArgs(dir()), "--send", "--expect-digest", "d".repeat(64)], deps);
  assert.equal(call.action, "delete");
  assert.equal(call.plan.args[0], "functions:delete");
  assert.equal(call.node, "/n/node");
  assert.equal(call.firebaseJs, "/f/lib/bin.js");
  assert.equal(call.plan.cwd, "/s");
  assert.ok(call.plan.env.PATH.startsWith("/n:"));
});

test("a recorder that throws exits 4 and leaves a result saying so", async () => {
  const d = dir();
  const { code, err } = await run(
    ["record", ...baseArgs(d), "--send", "--expect-digest", "d".repeat(64)],
    goodDeps({
      record: async () => {
        throw new Error("boom");
      },
    }),
  );
  assert.equal(code, 4);
  assert.match(err.join("\n"), /boom/);
  const result = readdirSync(d).find((f) => f.startsWith("result-"));
  assert.equal(JSON.parse(readFileSync(join(d, result), "utf8")).outcome, "pycheck-recorder-threw");
});

test("a stop signal is passed on to the recorder once and answered twice without a second stop", async () => {
  let handler;
  const err = [];
  let seenSignal;
  await main(["record", ...baseArgs(dir()), "--send", "--expect-digest", "d".repeat(64)], {
    env,
    deps: goodDeps({
      signals: (h) => (handler = h),
      record: async (o) => (
        (seenSignal = o.signal),
        handler("SIGINT"),
        handler("SIGINT"),
        { outcome: "x", closureReady: false, attempted: 0 }
      ),
    }),
    out: () => {},
    err: (m) => err.push(m),
    digest: "d".repeat(64),
  });
  assert.equal(seenSignal.aborted, true);
  assert.match(err[0], /stopping at the next request/);
  assert.match(err[1], /already under way/);
});

// ---- readback -----------------------------------------------------------------------------------------

function finishedRun(
  result = { unconfirmedCreates: [], bucket: "b.firebasestorage.app" },
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
const rbArgs = (d) => [
  "readback",
  "--run-dir",
  d,
  "--project-number",
  "123456789012",
  "--run-id",
  RUN,
  "--send",
  "--expect-digest",
  "d".repeat(64),
];
const rbDeps = (at, over = {}) =>
  goodDeps({
    now: () => at + 1000 + SETTLE_MS,
    readback: async () => ({ allAbsent: true, attempted: 5, unknown: 0 }),
    ...over,
  });

test("readback needs --send, the digest, a run id and a journal", async () => {
  const { d, at } = finishedRun();
  for (const argv of [
    rbArgs(d).filter((a) => a !== "--send"),
    [
      "readback",
      "--run-dir",
      d,
      "--project-number",
      "123456789012",
      "--send",
      "--expect-digest",
      "d".repeat(64),
    ],
    [...rbArgs(d).slice(0, 6), "--run-id", "nothex", ...rbArgs(d).slice(8)],
  ]) {
    assert.equal((await run(argv, rbDeps(at))).code, 2);
  }
  const empty = dir();
  assert.equal((await run(rbArgs(empty), rbDeps(at))).code, 2);
});

test("readback waits ten minutes after the last request", async () => {
  const { d, at } = finishedRun();
  let ran = 0;
  const early = await run(
    rbArgs(d),
    rbDeps(at, { now: () => at + 1000 + SETTLE_MS - 1, readback: async () => (ran++, {}) }),
  );
  assert.equal(early.code, 2);
  assert.equal(ran, 0);
  const ok = await run(rbArgs(d), rbDeps(at));
  assert.equal(ok.code, 0);
  assert.equal(ran, 0);
});

test("readback exits 3 when something is still there, and 0 when all is absent", async () => {
  const gone = finishedRun();
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
  assert.equal((await run(rbArgs(gone.d), rbDeps(gone.at))).code, 0);
});

test("readback never closes an unknown create, however the names read, and never closes an unreadable result", async () => {
  const unconfirmed = finishedRun({
    unconfirmedCreates: [{ label: "document", name: "fs-create" }],
    bucket: "b.firebasestorage.app",
  });
  const r = await run(rbArgs(unconfirmed.d), rbDeps(unconfirmed.at));
  assert.equal(r.code, 3);
  assert.match(r.err.join("\n"), /a 404 never settles/);
  for (const result of [null, { outcome: "x" }]) {
    const f = finishedRun(result);
    const x = await run(rbArgs(f.d), rbDeps(f.at));
    assert.equal(x.code, 3);
    assert.match(x.err.join("\n"), /cannot be judged/);
  }
});

test("readback hands the recorded bucket to the read and journals privately", async () => {
  const { d, at } = finishedRun();
  let seen;
  await run(
    rbArgs(d),
    rbDeps(at, {
      readback: async (o) => (
        (seen = o),
        await o.save({ id: "r" }),
        { allAbsent: true, attempted: 1, unknown: 0 }
      ),
    }),
  );
  assert.equal(seen.bucket, "b.firebasestorage.app");
  assert.equal(seen.runId, RUN);
  assert.ok(readdirSync(d).some((f) => f.startsWith("readback-" + RUN) && f.endsWith(".jsonl")));
  assert.ok(readdirSync(d).some((f) => f.startsWith("readback-result-" + RUN)));
});

test("a read-back that throws exits 4", async () => {
  const { d, at } = finishedRun();
  assert.equal(
    (
      await run(
        rbArgs(d),
        rbDeps(at, {
          readback: async () => {
            throw new Error("x");
          },
        }),
      )
    ).code,
    4,
  );
});

test("lastActivity is the latest dispatch or response time, skipping broken lines", () => {
  const d = dir();
  const path = join(d, "j.jsonl");
  writeFileSync(
    path,
    [
      '{"dispatchAt":"2026-11-05T00:00:00.000Z"}',
      "not json",
      '{"responseAt":"2026-11-05T00:10:00.000Z"}',
      '{"responseAt":"bad"}',
      "",
    ].join("\n"),
  );
  assert.equal(lastActivity(path), Date.parse("2026-11-05T00:10:00Z"));
  assert.equal(lastActivity(join(d, "missing")), null);
});

test("resultOf reads the unconfirmed creates and the bucket, and refuses anything else", () => {
  const d = dir();
  mkdirSync(d, { recursive: true });
  const path = join(d, "r.json");
  writeFileSync(path, JSON.stringify({ unconfirmedCreates: [], bucket: 5 }));
  assert.deepEqual(resultOf(path), { ok: true, creates: [], bucket: null });
  writeFileSync(path, "{");
  assert.equal(resultOf(path).ok, false);
  assert.equal(resultOf(join(d, "none")).ok, false);
});

// ---- the packet ---------------------------------------------------------------------------------------

test("the digest covers the listed files by name and content, in a fixed order", () => {
  const contents = Object.fromEntries(
    PACKET_FILES.map((name) => [name, Buffer.from("content of " + name)]),
  );
  const base = packetDigest((name) => contents[name]);
  assert.match(base, /^[0-9a-f]{64}$/);
  assert.equal(
    packetDigest((name) => contents[name]),
    base,
  );
  for (const name of PACKET_FILES)
    assert.notEqual(
      packetDigest((n) => (n === name ? Buffer.from("changed") : contents[n])),
      base,
      name,
    );
  assert.equal(new Set(PACKET_FILES).size, PACKET_FILES.length);
});

test("the real packet reads, and every file it lists exists", () => {
  assert.match(packetDigest(), /^[0-9a-f]{64}$/);
  assert.ok(
    PACKET_FILES.includes("record/judge.mjs") &&
      PACKET_FILES.includes("fixture/main.py") &&
      PACKET_FILES.includes("record/guard.mjs"),
  );
  assert.equal(typeof realDeps.send, "function");
});
