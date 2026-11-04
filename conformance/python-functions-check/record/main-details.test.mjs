// The command line's details, pinned by mutation testing of the first suite: the exact digest formula, the shapes of
// the arguments, the messages an operator reads, what is written to the journal and the result, the token refresh, and
// the adapters that touch the real machine.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { PACKET_FILES, lastActivity, localChecks, main, packetDigest, realDeps } from "./main.mjs";
import { SETTLE_MS } from "./readback.mjs";

const SHA = "a".repeat(40);
const RUN = "0123456789abcdef";
const DIGEST = "d".repeat(64);
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
  ...over,
});
const args = (dir, over = {}) => {
  const values = {
    "run-dir": dir,
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
const dir = () => mkdtempSync(join(tmpdir(), "pc-md-"));

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
  assert.equal(PACKET_FILES.length, 17);
  assert.deepEqual(PACKET_FILES.slice(-3), [
    "fixture/main.py",
    "fixture/requirements.txt",
    "firebase.json",
  ]);
});

test("the project number is twelve or thirteen digits, the commit forty hexadecimal characters with zeros allowed", () => {
  const full = {
    "run-dir": "x",
    "project-number": "123456789012",
    "source-commit": SHA,
    "venv-dir": "/v",
    node: "n",
    "firebase-js": "f",
  };
  const check = (over) =>
    localChecks({
      values: { ...full, ...over },
      env,
      deps: goodDeps({ gitHead: () => over["source-commit"] ?? SHA }),
    });
  assert.deepEqual(check({}), []);
  assert.deepEqual(check({ "project-number": "1234567890123" }), []);
  assert.ok(check({ "project-number": "12345678901" }).length > 0);
  assert.ok(check({ "project-number": "12345678901234" }).length > 0);
  assert.ok(check({ "project-number": "12345678901a" }).length > 0);
  assert.deepEqual(check({ "source-commit": "0123456789abcdef0123456789abcdef01234567" }), []);
  assert.ok(check({ "source-commit": "A".repeat(40) }).length > 0);
  assert.ok(check({ "source-commit": "a".repeat(41) }).length > 0);
});

test("the messages an operator reads name the flag and the rule", async () => {
  const missing = await run(["check", ...args(dir(), { "venv-dir": undefined })]);
  assert.match(missing.err, /^check failed:\n- --venv-dir is required$/);
  const noHome = await run(["check", ...args(dir())], goodDeps(), { PATH: "/usr/bin" });
  assert.match(noHome.err, /- HOME is not set/);
  const badNumber = await run(["check", ...args(dir(), { "project-number": "12" })]);
  assert.match(badNumber.err, /- --project-number is 12 or 13 digits/);
  const badArg = await run(["check", "oops"]);
  assert.equal(badArg.err, "unexpected argument oops");
  const badCommand = await run(["deploy"]);
  assert.equal(badCommand.err, "the command is check, record or readback");
  const credential = await run(["check", ...args(dir())], goodDeps(), {
    ...env,
    GOOGLE_APPLICATION_CREDENTIALS: "x",
  });
  assert.match(credential.err, /GOOGLE_APPLICATION_CREDENTIALS is set/);
  const noJournal = await run([
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
  ]);
  assert.equal(noJournal.err, `there is no journal of run ${RUN} in the run directory`);
  const noFlags = await run(["readback", "--send"]);
  assert.match(
    noFlags.err,
    /- --run-dir is required\n- --project-number is 12 or 13 digits|- --run-dir is required\n- --project-number is required\n- --run-id is required/,
  );
  const badIds = await run([
    "readback",
    "--run-dir",
    "x",
    "--project-number",
    "12",
    "--run-id",
    "zz",
    "--send",
  ]);
  assert.match(
    badIds.err,
    /--project-number is 12 or 13 digits\n- --run-id is 16 hexadecimal digits/,
  );
  const noHomeRb = await run(
    ["readback", "--run-dir", "x", "--project-number", "123456789012", "--run-id", RUN],
    goodDeps(),
    { PATH: "/usr/bin" },
  );
  assert.match(noHomeRb.err, /HOME is not set/);
  const noSend = await run([
    "readback",
    "--run-dir",
    "x",
    "--project-number",
    "123456789012",
    "--run-id",
    RUN,
  ]);
  assert.equal(
    noSend.err,
    `readback needs --send and the approved --expect-digest; this packet's digest is ${DIGEST}`,
  );
  const noSendRecord = await run(["record", ...args(dir())]);
  assert.equal(
    noSendRecord.err,
    `record needs --send and the approved --expect-digest; this packet's digest is ${DIGEST}`,
  );
});

test("the run directory is created when it is missing, and the CLI's configuration directory is private", async () => {
  const parent = dir();
  const runDir = join(parent, "a", "b");
  let call;
  const deps = goodDeps({
    runCli: async (o) => ((call = o), {}),
    record: async (o) => (
      await o.runCli({ action: "deploy" }),
      { outcome: "x", closureReady: true, attempted: 0 }
    ),
  });
  const { code } = await run(
    ["record", ...args(runDir), "--send", "--expect-digest", DIGEST],
    deps,
  );
  assert.equal(code, 0);
  assert.equal(lstatSync(runDir).mode & 0o777, 0o700);
  const config = call.plan.env.XDG_CONFIG_HOME;
  assert.equal(existsSync(config), true);
  assert.equal(lstatSync(config).mode & 0o777, 0o700);
});

test("the journal holds every saved row as a line of JSON, in order, and the result file is the pretty-printed result", async () => {
  const d = dir();
  const result = {
    outcome: "pycheck-recorded",
    closureReady: true,
    readBackRequired: false,
    attempted: 2,
  };
  let runId;
  const deps = goodDeps({
    record: async (o) => {
      runId = o.runId;
      await o.save({ id: "a", state: "before-send" });
      await o.save({ id: "b", state: "response-persisted" });
      return result;
    },
  });
  const { out } = await run(["record", ...args(d), "--send", "--expect-digest", DIGEST], deps);
  assert.equal(
    readFileSync(join(d, `journal-${runId}.jsonl`), "utf8"),
    '{"id":"a","state":"before-send"}\n{"id":"b","state":"response-persisted"}\n',
  );
  assert.equal(
    readFileSync(join(d, `result-${runId}.json`), "utf8"),
    JSON.stringify(result, null, 2) + "\n",
  );
  assert.equal(lstatSync(join(d, `result-${runId}.json`)).mode & 0o777, 0o600);
  assert.equal(lstatSync(join(d, `journal-${runId}.jsonl`)).mode & 0o777, 0o600);
  assert.equal(
    out.at(-1),
    JSON.stringify(
      {
        runId,
        outcome: "pycheck-recorded",
        closureReady: true,
        readBackRequired: false,
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
        project: "fireemu-oracle-events",
        command: "record",
        maxRequests: 500,
        packetDigest: DIGEST,
      },
      null,
      2,
    ),
  );
});

test("a recorder that throws leaves a pretty result and its journal closed", async () => {
  const d = dir();
  await run(
    ["record", ...args(d), "--send", "--expect-digest", DIGEST],
    goodDeps({
      record: async () => {
        throw new Error("boom");
      },
    }),
  );
  const file = readdirSync(d).find((f) => f.startsWith("result-"));
  assert.equal(
    readFileSync(join(d, file), "utf8"),
    JSON.stringify({ outcome: "pycheck-recorder-threw", message: "boom" }, null, 2) + "\n",
  );
});

test("the read-back journals privately and prints its result pretty", async () => {
  const d = dir();
  const at = Date.parse("2026-11-05T00:00:00Z");
  writeFileSync(
    join(d, `journal-${RUN}.jsonl`),
    JSON.stringify({ dispatchAt: new Date(at).toISOString() }) + "\n",
  );
  writeFileSync(
    join(d, `result-${RUN}.json`),
    JSON.stringify({ unconfirmedCreates: [], bucket: "b" }),
  );
  const stamp = at + SETTLE_MS + 5;
  const deps = goodDeps({
    now: () => stamp,
    readback: async (o) => (
      await o.save({ id: "r" }),
      { allAbsent: true, attempted: 1, unknown: 0 }
    ),
  });
  const { out, code, err } = await run(
    [
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
    ],
    deps,
  );
  assert.equal(code, 0, err);
  assert.equal(readFileSync(join(d, `readback-${RUN}-${stamp}.jsonl`), "utf8"), '{"id":"r"}\n');
  assert.equal(lstatSync(join(d, `readback-${RUN}-${stamp}.jsonl`)).mode & 0o777, 0o600);
  const saved = readFileSync(join(d, `readback-result-${RUN}-${stamp}.json`), "utf8");
  assert.equal(
    saved,
    JSON.stringify(
      { allAbsent: true, attempted: 1, unknown: 0, unconfirmedCreates: [], judged: true },
      null,
      2,
    ) + "\n",
  );
  assert.equal(lstatSync(join(d, `readback-result-${RUN}-${stamp}.json`)).mode & 0o777, 0o600);
  assert.equal(
    out.at(-1),
    JSON.stringify(
      { runId: RUN, allAbsent: true, attempted: 1, unknown: 0, unconfirmedCreates: [] },
      null,
      2,
    ),
  );
  const waited = await run(
    [
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
    ],
    goodDeps({ now: () => at + 61_500 }),
  );
  assert.match(waited.err, /was 61 seconds ago; wait until ten minutes have passed/);
});

test("a read-back that stops says so", async () => {
  const d = dir();
  const at = Date.parse("2026-11-05T00:00:00Z");
  writeFileSync(
    join(d, `journal-${RUN}.jsonl`),
    JSON.stringify({ dispatchAt: new Date(at).toISOString() }) + "\n",
  );
  const { err, code } = await run(
    [
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
    ],
    goodDeps({
      now: () => at + SETTLE_MS,
      readback: async () => {
        throw new Error("net down");
      },
    }),
  );
  assert.equal(code, 4);
  assert.equal(err, "the read-back stopped: net down");
});

test("the latest time in a journal wins, equal times and blank lines are fine, and a file that cannot be read has none", () => {
  const d = dir();
  const path = join(d, "j.jsonl");
  writeFileSync(
    path,
    [
      '{"dispatchAt":"2026-11-05T00:20:00.000Z"}',
      "",
      '{"responseAt":"2026-11-05T00:10:00.000Z"}',
      '{"dispatchAt":"2026-11-05T00:20:00.000Z","responseAt":"2026-11-05T00:30:00.000Z"}',
      '{"responseAt":"2026-11-05T00:25:00.000Z"}',
      "{}",
      "",
    ].join("\n"),
  );
  assert.equal(lastActivity(path), Date.parse("2026-11-05T00:30:00Z"));
  writeFileSync(
    path,
    '{"responseAt":"2026-11-05T00:10:00.000Z"}\n{"dispatchAt":"2026-11-05T00:20:00.000Z"}\n',
  );
  assert.equal(lastActivity(path), Date.parse("2026-11-05T00:20:00Z"));
  writeFileSync(
    path,
    '{"responseAt":"2026-11-05T00:10:00.000Z"}\n{"responseAt":"2026-11-05T00:10:00.000Z"}\n',
  );
  assert.equal(lastActivity(path), Date.parse("2026-11-05T00:10:00Z"));
  assert.equal(lastActivity(join(d, "nope")), null);
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
      await o.send({ url: "https://example.com/1", method: "GET", headers: { accept: "x" } });
      now += 41 * 60 * 1000;
      await o.prepareRequest({ id: "two" });
      const reply = await o.send({ url: "https://example.com/2", method: "GET", headers: {} });
      assert.equal(reply.status, 200);
      assert.equal(await reply.arrayBuffer().then((b) => Buffer.from(b).toString()), "{}");
      respond = () => new Response("echo tok-2-abcdefgh");
      await assert.rejects(
        o.send({ url: "https://example.com/3", method: "GET", headers: {} }),
        /reflected a credential/,
      );
      return { outcome: "x", closureReady: true, attempted: 3 };
    },
  });
  await run(["record", ...args(dir()), "--send", "--expect-digest", DIGEST], deps);
  assert.deepEqual(sent, [
    "Bearer tok-1-abcdefgh",
    "Bearer tok-2-abcdefgh",
    "Bearer tok-2-abcdefgh",
  ]);
  assert.equal(issued, 2);
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
  assert.equal(
    realDeps.gitHead(),
    execFileSync("git", ["rev-parse", "HEAD"], {
      encoding: "utf8",
      cwd: dirname(fileURLToPath(import.meta.url)),
    }).trim(),
  );
  assert.equal(typeof realDeps.gitDirty(), "boolean");
  assert.match(realDeps.repoRoot(), /^\//);
  assert.equal(typeof realDeps.signals, "function");
});

test("every local module a packet module imports is itself part of the packet", () => {
  const root = join(dirname(fileURLToPath(import.meta.url)), "..");
  const listed = new Set(PACKET_FILES.map((name) => join(root, name)));
  const missing = [];
  for (const name of PACKET_FILES.filter((n) => n.endsWith(".mjs"))) {
    const file = join(root, name);
    const text = readFileSync(file, "utf8");
    for (const match of text.matchAll(/(?:from|import)\s*\(?\s*"(\.{1,2}\/[^"]+)"/g)) {
      const target = join(dirname(file), match[1]);
      if (!listed.has(target)) missing.push(`${name} imports ${match[1]}`);
    }
  }
  assert.deepEqual(missing, []);
  for (const file of listed) assert.ok(existsSync(file), file);
});
