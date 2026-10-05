// The second group of survivors: the allowlist's mutation flags and boundaries, the plan's exact values, the
// log windows, the deploy side's constants and real processes, and the command line's messages and codes.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import {
  CLI_TIMEOUT_MS,
  DELETE_TIMEOUT_MS,
  DEPLOY_TIMEOUT_MS,
  DRY_RUN_TIMEOUT_MS,
  READY_MAX_POLLS,
  READY_POLL_SECONDS,
  cliFailed,
  escapingLinks,
  prepareSource,
  regionProblems,
  runCli,
  sourceProblems,
} from "./deploy.mjs";
import { createGuard } from "./guard.mjs";
import { frameFilter, parseFrames, schedulerFilter } from "./logs.mjs";
import { PACKET_FILES, localChecks, main, packetDigest, parseArgs, realDeps } from "./main.mjs";
import { EXTRA_JOBS, FRAME_MARK, subscriptionName } from "./plan.mjs";
import { NUMBER, createWorld } from "./world.mjs";

const RUN = "0123456789abcdef";
const P = "fireemu-oracle-sbx";
const tmp = () => mkdtempSync(join(tmpdir(), "coverage2-"));

// ---- the allowlist -------------------------------------------------------------------------------

const guard = createGuard(RUN, NUMBER);
const SCHED = `https://cloudscheduler.googleapis.com/v1/projects/${P}/locations/us-central1/jobs`;
const PUBSUB = `https://pubsub.googleapis.com/v1/projects/${P}`;
const GCF = "https://cloudfunctions.googleapis.com";
const FN = `/projects/${P}/locations/us-central1/functions`;
const AR = `https://artifactregistry.googleapis.com/v1/projects/${P}/locations/us-central1/repositories`;
const JOB = "firebase-schedule-schedOkV2-us-central1";
const SUB = "fe-sd-" + RUN + "-pull-schedokv1";
const spec = (method, url, json) => ({
  id: "t",
  method,
  url,
  ...(json === undefined ? {} : { json }),
});

const TABLE = [
  [
    "GET",
    `https://firebaserules.googleapis.com/v1/projects/${P}/releases/cloud.firestore`,
    undefined,
    false,
  ],
  [
    "GET",
    `https://serviceusage.googleapis.com/v1/projects/${NUMBER}/services?filter=state:ENABLED&pageSize=200`,
    undefined,
    false,
  ],
  ["POST", `https://cloudresourcemanager.googleapis.com/v1/projects/${P}:getIamPolicy`, {}, false],
  ["GET", `https://firebase.googleapis.com/v1beta1/projects/${P}/adminSdkConfig`, undefined, false],
  ["GET", `https://appengine.googleapis.com/v1/apps/${P}`, undefined, false],
  ["GET", `${GCF}/v1/projects/${P}/locations/-/functions`, undefined, false],
  ["GET", `${GCF}/v2/projects/${P}/locations/us-central1/functions`, undefined, false],
  ["GET", `${GCF}/v1${FN}/schedOkV1`, undefined, false],
  ["GET", `${GCF}/v2${FN}/schedOkV2`, undefined, false],
  ["DELETE", `${GCF}/v1${FN}/schedOkV1`, undefined, true],
  ["DELETE", `${GCF}/v2${FN}/schedOkV2`, undefined, true],
  ["GET", `${GCF}/v1/operations/del-1`, undefined, false],
  ["GET", `${GCF}/v2/projects/${P}/locations/us-central1/operations/del-1`, undefined, false],
  ["GET", `https://run.googleapis.com/v2/projects/${P}/locations/-/services`, undefined, false],
  ["GET", `${AR}?pageSize=100`, undefined, false],
  ["GET", `${AR}/gcf-artifacts`, undefined, false],
  ["GET", `${AR}/gcf-artifacts/packages?pageSize=100`, undefined, false],
  ["GET", `${SCHED}?pageSize=500`, undefined, false],
  ["GET", `${SCHED}/${JOB}`, undefined, false],
  ["POST", `${SCHED}/${JOB}:run`, {}, true],
  ["POST", `${SCHED}/${JOB}:pause`, {}, true],
  ["DELETE", `${SCHED}/${JOB}`, undefined, true],
  ["POST", SCHED, { name: `projects/${P}/locations/us-central1/jobs/fe-sd-${RUN}-zero` }, true],
  ["GET", `${PUBSUB}/topics?pageSize=1000`, undefined, false],
  ["GET", `${PUBSUB}/subscriptions?pageSize=1000`, undefined, false],
  ["GET", `${PUBSUB}/topics/firebase-schedule-schedOkV1-us-central1`, undefined, false],
  ["DELETE", `${PUBSUB}/topics/firebase-schedule-schedOkV1-us-central1`, undefined, true],
  [
    "PUT",
    `${PUBSUB}/subscriptions/${SUB}`,
    {
      topic: `projects/${P}/topics/firebase-schedule-schedOkV1-us-central1`,
      ackDeadlineSeconds: 10,
    },
    true,
  ],
  ["GET", `${PUBSUB}/subscriptions/${SUB}`, undefined, false],
  ["DELETE", `${PUBSUB}/subscriptions/${SUB}`, undefined, true],
  [
    "POST",
    `${PUBSUB}/subscriptions/${SUB}:pull`,
    { maxMessages: 10, returnImmediately: true },
    true,
  ],
  ["POST", `${PUBSUB}/subscriptions/${SUB}:acknowledge`, { ackIds: ["a"] }, true],
  [
    "POST",
    "https://logging.googleapis.com/v2/entries:list",
    { resourceNames: ["projects/" + P], filter: "x", orderBy: "timestamp asc", pageSize: 200 },
    false,
  ],
];

test("every request class is allowed, and says whether it is a mutation", () => {
  for (const [method, url, json, mutation] of TABLE) {
    assert.equal(guard.allow(spec(method, url, json)), true, method + " " + url);
    assert.equal(guard.isMutation(spec(method, url, json)), mutation, method + " " + url);
  }
  assert.equal(guard.isMutation(spec("GET", "https://example.com/")), false);
});

const ack = (ackIds) => spec("POST", `${PUBSUB}/subscriptions/${SUB}:acknowledge`, { ackIds });
test("an acknowledge holds one to ten ids, each a non-empty string below 4096 characters", () => {
  assert.equal(guard.allow(ack(Array(10).fill("a"))), true);
  assert.equal(guard.allow(ack(Array(11).fill("a"))), false);
  assert.equal(guard.allow(ack([])), false);
  assert.equal(guard.allow(ack(["a".repeat(4095)])), true);
  assert.equal(guard.allow(ack(["a".repeat(4096)])), false);
  assert.equal(guard.allow(ack([""])), false);
  assert.equal(guard.allow(ack(["a", ""])), false);
  assert.equal(guard.allow(ack([5])), false);
  assert.equal(guard.allow(ack([{ length: 5 }])), false);
  assert.equal(
    guard.allow(
      spec("POST", `${PUBSUB}/subscriptions/${SUB}:acknowledge`, { ackIds: ["a"], x: 1 }),
    ),
    false,
  );
});

test("the page size of a read and a log page are bounded, and a token may be one character", () => {
  assert.equal(guard.allow(spec("GET", `${AR}?pageSize=101`)), false);
  assert.equal(guard.allow(spec("GET", `${AR}/gcf-artifacts/packages?pageSize=101`)), false);
  assert.equal(guard.allow(spec("GET", `${AR}?pageSize=100&pageToken=a`)), true);
  assert.equal(guard.allow(spec("GET", `${AR}?pageToken=`)), false);
  const logs = (pageSize) =>
    spec("POST", "https://logging.googleapis.com/v2/entries:list", {
      resourceNames: ["projects/" + P],
      filter: "x",
      orderBy: "timestamp asc",
      pageSize,
    });
  assert.equal(guard.allow(logs(200)), true);
  assert.equal(guard.allow(logs(201)), false);
});

test("a URL with a foreign scheme, credentials or a fragment is refused, each by itself", () => {
  const good = `${SCHED}/${JOB}`;
  assert.equal(guard.allow(spec("GET", good)), true);
  assert.equal(guard.allow(spec("GET", good.replace("https:", "http:"))), false);
  assert.equal(guard.allow(spec("GET", good.replace("https://", "https://user@"))), false);
  assert.equal(guard.allow(spec("GET", good.replace("https://", "https://:pass@"))), false);
  assert.equal(guard.allow(spec("GET", good + "#x")), false);
  assert.equal(guard.allow(spec("GET", good.replace(".com", ".com:8443"))), false);
});

// ---- the plan and the logs -----------------------------------------------------------------------

test("the extra jobs and the subscription name are exactly what the packet states", () => {
  assert.deepEqual(
    EXTRA_JOBS.map((j) => [j.key, j.retryConfig]),
    [
      ["zero", { retryCount: 0 }],
      [
        "duration",
        { maxRetryDuration: "30s", minBackoffDuration: "4s", maxBackoffDuration: "10s" },
      ],
      [
        "count",
        {
          retryCount: 3,
          maxRetryDuration: "20s",
          minBackoffDuration: "4s",
          maxBackoffDuration: "10s",
        },
      ],
      [
        "fraction",
        {
          retryCount: 3,
          maxRetryDuration: "20.5s",
          minBackoffDuration: "2.5s",
          maxBackoffDuration: "20s",
          maxDoublings: 1,
        },
      ],
      [
        "zerobackoff",
        { maxRetryDuration: "10s", minBackoffDuration: "0s", maxBackoffDuration: "0s" },
      ],
      ["retry5", { retryCount: 5 }],
    ],
  );
  assert.equal(subscriptionName("x"), "projects/fireemu-oracle-sbx/subscriptions/x");
});

test("a log window is an RFC 3339 UTC time with one to nine fractional digits", () => {
  const w = (start) => () => frameFilter({ start, end: "2026-10-06T00:00:30Z" });
  assert.doesNotThrow(w("2026-10-06T00:00:30.5Z"));
  assert.doesNotThrow(w("2026-10-06T00:00:30.123456789Z"));
  assert.throws(w("2026-10-06T00:00:30.1234567890Z"), /RFC 3339/);
  assert.throws(w("2026-10-06T00:00:30.Z"), /RFC 3339/);
  assert.throws(w("2026-10-06T00:00:30+09:00"), /RFC 3339/);
});

test("the Scheduler filter is inclusive at both ends", () => {
  const f = schedulerFilter({
    runId: RUN,
    start: "2026-10-06T00:00:00Z",
    end: "2026-10-06T00:01:00Z",
  });
  assert.ok(f.includes('timestamp>="2026-10-06T00:00:00Z" AND timestamp<="2026-10-06T00:01:00Z"'));
});

test("a frame that is null, has no known handler or a non-string one is counted unparsed, never thrown on", () => {
  const entry = (n, text) => ({
    insertId: "i" + n,
    timestamp: "2026-10-06T00:00:00Z",
    textPayload: FRAME_MARK + " " + text,
  });
  const { frames, ignored } = parseFrames([
    entry(1, "null"),
    entry(2, '{"handler":"bogus"}'),
    entry(3, '{"handler":5}'),
    entry(4, "{}"),
  ]);
  assert.deepEqual(frames, []);
  assert.deepEqual(ignored, { notFrame: 0, unparsed: 4, foreignOrigin: 0 });
});

// ---- the deploy side -----------------------------------------------------------------------------

test("the timeouts and the poll bounds are the ones the packet states", () => {
  assert.equal(DEPLOY_TIMEOUT_MS, 2_400_000);
  assert.equal(DELETE_TIMEOUT_MS, 1_200_000);
  assert.equal(DRY_RUN_TIMEOUT_MS, 600_000);
  assert.deepEqual(CLI_TIMEOUT_MS, { deploy: 2_400_000, "dry-run": 600_000, delete: 1_200_000 });
  assert.equal(READY_POLL_SECONDS, 30);
  assert.equal(READY_MAX_POLLS, 40);
});

test("a link to the tree's own root is not a link out", () => {
  const dir = tmp();
  try {
    mkdirSync(join(dir, "sub"));
    symlinkSync(dir, join(dir, "self"));
    symlinkSync(join(dir, "sub"), join(dir, "inside"));
    assert.deepEqual(escapingLinks(dir), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a function without a region is named as having none, whether it is absent or null", () => {
  assert.match(regionProblems({ a: {} }).join(), /a: no region is set/);
  assert.match(regionProblems({ a: { region: null } }).join(), /a: no region is set/);
  assert.match(
    regionProblems({ a: { region: ["us-east1"] } }).join(),
    /the region is \["us-east1"\]/,
  );
});

// A throwaway repository with no user configuration at all (an empty global and system config), so its
// commit needs no identity and no key; nothing here touches the real repository's configuration.
const ISOLATED = {
  PATH: process.env.PATH,
  HOME: tmpdir(),
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_SYSTEM: "/dev/null",
  GIT_AUTHOR_NAME: "t",
  GIT_AUTHOR_EMAIL: "t@example.com",
  GIT_COMMITTER_NAME: "t",
  GIT_COMMITTER_EMAIL: "t@example.com",
};
const git = (cwd, ...args) =>
  execFileSync("git", ["-C", cwd, ...args], { encoding: "utf8", env: ISOLATED }).trim();
function sourceRepo() {
  const repo = tmp();
  git(repo, "init", "-q");
  mkdirSync(join(repo, "conformance/scheduled-delivery-004/fixture"), { recursive: true });
  writeFileSync(join(repo, "conformance/scheduled-delivery-004/firebase.json"), "{}");
  writeFileSync(join(repo, "conformance/scheduled-delivery-004/fixture/index.js"), "x");
  writeFileSync(join(repo, "conformance/scheduled-delivery-004/untracked-later.txt"), "x");
  git(
    repo,
    "add",
    "conformance/scheduled-delivery-004/firebase.json",
    "conformance/scheduled-delivery-004/fixture/index.js",
  );
  git(repo, "commit", "-q", "-m", "x");
  return { repo, commit: git(repo, "rev-parse", "HEAD") };
}

test("the source copy takes the tracked files of the commit into a nested target and the dependency tree verbatim", () => {
  const { repo, commit } = sourceRepo();
  const deps = tmp();
  const out = tmp();
  try {
    writeFileSync(join(deps, "a.txt"), "a");
    mkdirSync(join(deps, "pkg"));
    writeFileSync(join(deps, "pkg/b.txt"), "b");
    symlinkSync("a.txt", join(deps, "link"));
    const target = join(out, "deep/er/source");
    const { configPath, fixtureDir } = prepareSource({
      repoRoot: repo,
      commit,
      target,
      depsDir: deps,
    });
    assert.equal(configPath, join(target, "conformance/scheduled-delivery-004/firebase.json"));
    assert.equal(readFileSync(configPath, "utf8"), "{}");
    assert.equal(readFileSync(join(fixtureDir, "index.js"), "utf8"), "x");
    assert.throws(() =>
      readFileSync(join(target, "conformance/scheduled-delivery-004/untracked-later.txt")),
    );
    assert.equal(readFileSync(join(fixtureDir, "node_modules/pkg/b.txt"), "utf8"), "b");
    assert.equal(readlinkSync(join(fixtureDir, "node_modules/link")), "a.txt");
    const bare = prepareSource({ repoRoot: repo, commit, target: join(out, "bare") });
    assert.equal(bare.fixtureDir, join(out, "bare/conformance/scheduled-delivery-004/fixture"));
  } finally {
    for (const d of [repo, deps, out]) rmSync(d, { recursive: true, force: true });
  }
});

test("a commit is a full SHA of forty hexadecimal digits, zeros included", () => {
  const target = tmp();
  try {
    assert.throws(
      () => prepareSource({ repoRoot: ".", commit: "a".repeat(41), target }),
      /full SHA/,
    );
    assert.throws(
      () => prepareSource({ repoRoot: ".", commit: "a".repeat(39), target }),
      /full SHA/,
    );
    for (const commit of ["a".repeat(40), "0".repeat(40)])
      assert.throws(
        () => prepareSource({ repoRoot: tmpdir(), commit, target }),
        (error) => !/full SHA/.test(error.message),
        commit,
      );
  } finally {
    rmSync(target, { recursive: true, force: true });
  }
});

test("a failed SDK discovery is reported with the first 300 characters of its stderr only", () => {
  const dir = tmp();
  try {
    const root = join(dir, "fixture");
    const sdk = join(root, "node_modules/firebase-functions");
    mkdirSync(join(sdk, "lib/bin"), { recursive: true });
    writeFileSync(join(root, "package.json"), "{}");
    writeFileSync(
      join(sdk, "package.json"),
      '{"name":"firebase-functions","version":"7.3.2","main":"i.js"}',
    );
    writeFileSync(join(sdk, "i.js"), "");
    writeFileSync(
      join(sdk, "lib/bin/firebase-functions.js"),
      'process.stderr.write("A".repeat(300) + "B".repeat(200)); process.exit(1);\n',
    );
    const problems = sourceProblems({
      fixtureDir: root,
      node: process.execPath,
      directory: join(dir, "d/e"),
    });
    assert.equal(problems.length, 1);
    assert.ok(problems[0].endsWith("failed: " + "A".repeat(300)), problems[0]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a CLI run in a nested directory, in its own process group, reports a true duration and no timeout", async () => {
  const dir = tmp();
  try {
    const script = join(dir, "pg.mjs");
    writeFileSync(
      script,
      `import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
const pgid = execFileSync("ps", ["-o", "pgid=", "-p", String(process.pid)], { encoding: "utf8" }).trim();
writeFileSync(${JSON.stringify(join(dir, "pg.json"))}, JSON.stringify({ pid: process.pid, pgid: Number(pgid) }));
`,
    );
    const result = await runCli({
      action: "dry-run",
      plan: { args: [], cwd: dir, env: { PATH: "/usr/bin:/bin" } },
      firebaseJs: script,
      node: process.execPath,
      directory: join(dir, "a/b/out"),
      timeoutMs: 20_000,
    });
    assert.equal(result.exitCode, 0);
    assert.equal(result.timedOut, false);
    assert.equal(cliFailed(result), false);
    assert.ok(result.durationMs >= 0 && result.durationMs < 20_000, String(result.durationMs));
    const seen = JSON.parse(readFileSync(join(dir, "pg.json"), "utf8"));
    assert.equal(seen.pgid, seen.pid, "the child leads its own process group");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---- the command line -----------------------------------------------------------------------------

const COMMIT = "a".repeat(40);
const ENV = { HOME: "/home/test", PATH: "/usr/bin" };
const ARGS = (command, run, extra = []) => [
  command,
  "--run-dir",
  run,
  "--project-number",
  NUMBER,
  "--source-commit",
  COMMIT,
  "--deps-dir",
  "/deps",
  "--node",
  "/node22/bin/node",
  "--firebase-js",
  "/tools/node_modules/firebase-tools/lib/bin/firebase.js",
  ...extra,
];
const fakeDeps = (overrides = {}) => ({
  nodeVersion: () => "22.22.1",
  firebaseToolsVersion: () => "15.28.2",
  gitHead: () => COMMIT,
  gitDirty: () => false,
  adcExists: () => true,
  token: () => "test-token",
  send: createWorld().send,
  runCli: async () => ({}),
  prepareSource: ({ target }) => ({
    configPath: join(target, "firebase.json"),
    fixtureDir: join(target, "fixture"),
  }),
  sourceProblems: () => [],
  repoRoot: () => "/repo",
  record: async () => ({}),
  ...overrides,
});
const io = () => {
  const lines = [];
  return {
    out: (t) => lines.push(["out", String(t)]),
    err: (t) => lines.push(["err", String(t)]),
    lines,
  };
};

test("the packet digest of known contents is pinned", () => {
  assert.equal(
    packetDigest((name) => Buffer.from("content of " + name)),
    "c40420cfb325d979f1fcda1791a827f20bd1d7a9f4854ad0f94e66d3dc320fc0",
  );
  assert.equal(PACKET_FILES.length, 11);
});

test("a project number is twelve or thirteen digits and a commit is forty hexadecimal digits, zeros included", () => {
  const base = parseArgs(ARGS("check", "/r")).values;
  const run = (values) =>
    localChecks({ values: { ...base, ...values }, env: ENV, deps: fakeDeps() });
  assert.deepEqual(run({}), []);
  assert.deepEqual(run({ "project-number": "1".repeat(12) }), []);
  assert.deepEqual(run({ "project-number": "1".repeat(13) }), []);
  assert.match(run({ "project-number": "1".repeat(14) }).join(), /12 or 13 digits/);
  assert.match(run({ "project-number": "1".repeat(11) }).join(), /12 or 13 digits/);
  assert.doesNotMatch(run({ "source-commit": "0".repeat(40) }).join(), /full SHA/);
  assert.match(run({ "source-commit": "a".repeat(41) }).join(), /full SHA/);
});

test("the real git readings agree with git", () => {
  const here = dirname(new URL(import.meta.url).pathname);
  assert.equal(realDeps.gitHead(), git(here, "rev-parse", "HEAD"));
  assert.equal(realDeps.gitDirty(), git(here, "status", "--porcelain", "--ignored=no") !== "");
});

test("a bad command or a malformed argument is refused with its message and code 2", async () => {
  const bad = io();
  assert.equal(await main(["check", "stray"], { env: ENV, deps: fakeDeps(), ...bad }), 2);
  assert.deepEqual(bad.lines, [["err", "unexpected argument stray"]]);
  const other = io();
  assert.equal(
    await main(["bogus", ...ARGS("check", "/r").slice(1)], {
      env: ENV,
      deps: fakeDeps(),
      ...other,
    }),
    2,
  );
  assert.deepEqual(other.lines, [["err", "the command is check, record or readback"]]);
});

test("the first line says what is about to run, indented by two, and a failed check names each problem", async () => {
  const run = tmp();
  try {
    const failing = io();
    const code = await main(ARGS("check", run), {
      env: ENV,
      deps: fakeDeps({ gitDirty: () => true, nodeVersion: () => "1" }),
      digest: "d".repeat(64),
      ...failing,
    });
    assert.equal(code, 2);
    assert.equal(
      failing.lines[0][1],
      JSON.stringify(
        { project: P, command: "check", maxRequests: 500, packetDigest: "d".repeat(64) },
        null,
        2,
      ),
    );
    assert.equal(
      failing.lines[1][1],
      "check failed:\n- the CLI's Node is 1, not 22.22.1\n- the working tree is not clean",
    );
    const source = io();
    assert.equal(
      await main(ARGS("check", join(run, "x")), {
        env: ENV,
        deps: fakeDeps({ sourceProblems: () => ["p1", "p2"] }),
        ...source,
      }),
      2,
    );
    assert.equal(source.lines.at(-1)[1], "the source copy failed its offline checks:\n- p1\n- p2");
  } finally {
    rmSync(run, { recursive: true, force: true });
  }
});

test("record without the approved digest says what the digest is", async () => {
  const run = tmp();
  try {
    const refused = io();
    const code = await main(ARGS("record", run, ["--send", "--expect-digest", "e".repeat(64)]), {
      env: ENV,
      deps: fakeDeps(),
      digest: "d".repeat(64),
      ...refused,
    });
    assert.equal(code, 2);
    assert.equal(
      refused.lines.at(-1)[1],
      "record needs --send and the approved --expect-digest; this packet's digest is " +
        "d".repeat(64),
    );
  } finally {
    rmSync(run, { recursive: true, force: true });
  }
});

test("the files and the summary a send leaves are indented by two, and a thrown recorder is exit 4 with its message", async () => {
  const run = tmp();
  try {
    const digest = "d".repeat(64);
    const result = {
      outcome: "calendar-delivery-recorded",
      closureReady: true,
      readBackRequired: false,
      attempted: 7,
    };
    const done = io();
    assert.equal(
      await main(ARGS("record", run, ["--send", "--expect-digest", digest]), {
        env: ENV,
        deps: fakeDeps({ record: async () => result }),
        digest,
        ...done,
      }),
      0,
    );
    const { runId } = JSON.parse(done.lines.at(-1)[1]);
    assert.equal(
      done.lines.at(-1)[1],
      JSON.stringify(
        {
          runId,
          outcome: result.outcome,
          closureReady: true,
          readBackRequired: false,
          attempted: 7,
        },
        null,
        2,
      ),
    );
    assert.equal(
      readFileSync(join(run, `result-${runId}.json`), "utf8"),
      JSON.stringify(result, null, 2) + "\n",
    );
    const run2 = join(run, "again");
    const thrown = io();
    assert.equal(
      await main(ARGS("record", run2, ["--send", "--expect-digest", digest]), {
        env: ENV,
        deps: fakeDeps({
          record: async () => {
            throw new Error("boom");
          },
        }),
        digest,
        ...thrown,
      }),
      4,
    );
    assert.equal(thrown.lines.at(-1)[1], "the recorder stopped: boom");
    const file = readFileSync(
      join(
        run2,
        readdirSync(run2).find((n) => n.startsWith("result-")),
      ),
      "utf8",
    );
    assert.equal(
      file,
      JSON.stringify({ outcome: "calendar-delivery-recorder-threw", message: "boom" }, null, 2) +
        "\n",
    );
  } finally {
    rmSync(run, { recursive: true, force: true });
  }
});
