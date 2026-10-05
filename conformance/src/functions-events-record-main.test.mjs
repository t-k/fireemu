import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import test from "node:test";

import {
  cliAttemptCounter,
  envProblems,
  firebaseToolsProblems,
  harnessDigest,
  main,
  nodeProblems,
  parseArgs,
} from "./functions-events/record/main.mjs";
import { ENVELOPE_TOPIC, TOPIC } from "./functions-events/record/sandbox.mjs";
import { createWorld } from "./functions-events-record-world.mjs";
import { tempDir } from "./test-tmpdir.mjs";

const root = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  cwd: new URL(".", import.meta.url).pathname,
})
  .toString()
  .trim();
const head = execFileSync("git", ["-C", root, "rev-parse", "HEAD"]).toString().trim();

test("the environment, Node and firebase-tools checks", () => {
  assert.deepEqual(envProblems({ PATH: "x", HOME: "y" }), []);
  for (const name of [
    "GOOGLE_APPLICATION_CREDENTIALS",
    "FIREBASE_TOKEN",
    "CLOUDSDK_CORE_PROJECT",
    "FIRESTORE_EMULATOR_HOST",
    "GCLOUD_PROJECT",
  ])
    assert.equal(envProblems({ [name]: "x" }).length, 1, name);
  assert.deepEqual(nodeProblems("22.22.1"), []);
  assert.equal(nodeProblems("24.14.0").length, 1);
  assert.deepEqual(firebaseToolsProblems({ version: "15.28.2" }), []);
  assert.equal(firebaseToolsProblems({ version: "15.29.0" }).length, 1);
  assert.equal(firebaseToolsProblems(undefined).length, 1);
});

test("the CLI runs at most once per action, the dry run included, and counts each attempt", () => {
  const { attempts, count } = cliAttemptCounter();
  assert.deepEqual(attempts, { dryRun: 0, deploy: 0, delete: 0 });
  for (const [action, key] of [
    ["dry-run", "dryRun"],
    ["deploy", "deploy"],
    ["delete", "delete"],
  ]) {
    count(action);
    assert.equal(attempts[key], 1, action);
    assert.throws(() => count(action), /already run once/, action);
    assert.equal(attempts[key], 1, `${action} is not counted twice`);
  }
  assert.deepEqual(attempts, { dryRun: 1, deploy: 1, delete: 1 });
  assert.throws(() => cliAttemptCounter().count("dryRun"), /unknown CLI action/);
  assert.throws(() => cliAttemptCounter().count("functions:delete"), /unknown CLI action/);
});

test("the arguments are strict", () => {
  const ok = ["record", "--packet", "p", "--source-commit", "a".repeat(40), "--api-key-file", "k"];
  assert.equal(parseArgs(ok).command, "record");
  assert.throws(() => parseArgs(["go"]), /usage/);
  assert.throws(() => parseArgs(ok.slice(0, 5)), /api-key-file|bad argument/);
  assert.throws(
    () => parseArgs(["record", "--packet", "p", "--source-commit", "HEAD", "--api-key-file", "k"]),
    /full SHA/,
  );
});

test("the harness digest covers the recorder, the fixture and the dotenv, and is stable", () => {
  const a = harnessDigest(root);
  assert.equal(a.digest, harnessDigest(root).digest);
  assert.ok(a.lines.some((l) => l.startsWith("conformance/src/functions-events/record/run.mjs ")));
  assert.ok(a.lines.some((l) => l.startsWith("conformance/functions-events/fixtures/index.js ")));
  assert.ok(a.lines.some((l) => l.startsWith("dotenv ")));
  const withTree = harnessDigest(root, { git: () => "t".repeat(40) });
  assert.ok(withTree.lines.includes(`tree ${"t".repeat(40)}`));
  assert.notEqual(withTree.digest, a.digest);
});

function arrange({ approve = true } = {}) {
  const dir = tempDir("fe-main-");
  const packet = join(dir, "packet.md");
  writeFileSync(packet, "the packet text");
  const keyFile = join(dir, "key.json");
  writeFileSync(keyFile, JSON.stringify({ apiKey: "synthetic-key" }));
  const ledgerPath = join(dir, "ledger.jsonl");
  writeFileSync(
    ledgerPath,
    `${JSON.stringify({ ts: "2026-10-01T08:30:00Z", event: "finished", taskId: "FUNCTIONS-EVENTS-SANDBOX", project: "fireemu-oracle-events", outcome: "prepared", lockRetained: false, runDir: "old", estimatedUsd: 2 })}\n`,
  );
  const packetSha256 = execFileSync("shasum", ["-a", "256", packet]).toString().split(" ")[0];
  const { digest } = harnessDigest(root, {
    git: (args) => (args[0] === "rev-parse" ? head : ""),
  });
  const ownerPath = join(dir, "owner.md");
  writeFileSync(
    ownerPath,
    approve
      ? `- 2026-10-04 | ${ENVELOPE_TOPIC} | envelopeId=E1; project=fireemu-oracle-events; maxRequests=520; cliMax=3; reserveUsd=4.00; retries=none | オーナー | x\n- 2026-10-04 | ${TOPIC} | decision=APPROVE; envelopeId=E1; packetSha256=${packetSha256}; harnessSha256=${digest}; sourceCommit=${head} | Claude（委任 | y\n`
      : "",
  );
  let t = Date.parse("2026-10-04T12:00:00Z");
  const world = createWorld({ now: () => t });
  const cliCalls = [];
  const deps = {
    root,
    env: { PATH: "/usr/bin", HOME: dir },
    log: () => {},
    fetch: world.fetch,
    printAccessToken: async () => "ya29.synthetic-token-aaaaaaaaaaaaaaaaaaaa",
    prepareSource: ({ target }) => {
      mkdirSync(join(target, "fixtures"), { recursive: true });
      return { configPath: join(target, "firebase.json"), fixtureDir: join(target, "fixtures") };
    },
    sourceProblems: () => [],
    runCli: async ({ action }) => {
      cliCalls.push(action);
      if (action === "deploy") world.deploy();
      else if (action === "delete") world.undeploy();
      return { action, exitCode: 0 };
    },
    sleep: async (seconds) => {
      t += seconds * 1000;
    },
    now: () => t,
    ledgerPath,
    ownerPath,
    lockDir: join(dir, "locks"),
    legacyLock: join(dir, "ledger.lock"),
    runsDir: join(dir, "runs"),
    nodeVersion: "22.1.0",
    git: (args) => (args[0] === "rev-parse" ? head : ""),
    readTools: () => ({ version: "15.28.2" }),
  };
  const argv = (command) => [
    command,
    "--packet",
    packet,
    "--source-commit",
    head,
    "--api-key-file",
    keyFile,
  ];
  return { deps, argv, world, cliCalls, ledgerPath, dir };
}

test("check reads locally, sends nothing, and says what it pinned", async () => {
  const { deps, argv, world } = arrange();
  const result = await main(argv("check"), deps);
  assert.deepEqual(result.problems, []);
  assert.equal(result.ok, true);
  assert.equal(world.requests.length, 0);
  assert.match(result.pins.packetSha256, /^[0-9a-f]{64}$/);
});

/** The lines and the journal of a run that wrote nothing, finished ten minutes before the check (t = 12:00Z). */
function quietRun(runs, { mutation = false } = {}) {
  const runDir = join(runs, "quiet");
  mkdirSync(join(runDir, "transport"), { recursive: true });
  const send = (seq) => [
    { seq, state: "before-send", mutation },
    { seq, state: "response-persisted", kind: "success" },
  ];
  writeFileSync(
    join(runDir, "transport", "journal.jsonl"),
    [...send(1), ...send(2)].map((entry) => JSON.stringify(entry)).join("\n"),
  );
  const line = (ts, over) =>
    JSON.stringify({
      ts,
      taskId: "FUNCTIONS-EVENTS-SANDBOX",
      project: "fireemu-oracle-events",
      runDir,
      ...over,
    });
  return [
    line("2026-10-04T11:49:00Z", { event: "started", estimatedUsd: 4 }),
    line("2026-10-04T11:49:10Z", {
      event: "finished",
      estimatedUsd: 4,
      outcome: "stopped-clean",
      requests: 2,
      cliAttempts: { deploy: 0, delete: 0 },
      lockRetained: false,
    }),
    line("2026-10-04T11:50:00Z", {
      event: "cleanup-verified",
      sandboxAtBaseline: true,
      requests: 2,
      unknownAnswers: 0,
      estimatedUsd: 0,
    }),
  ].join("\n");
}

test("check does not wait out the spacing after a run that wrote nothing, and does after one that did", async () => {
  const quiet = arrange();
  // the runs directory is not the ledger's directory
  quiet.deps.runsDir = tempDir("fe-runs-");
  appendFileSync(quiet.ledgerPath, `${quietRun(quiet.deps.runsDir)}\n`);
  const ok = await main(quiet.argv("check"), quiet.deps);
  assert.deepEqual(ok.problems, []);
  const wrote = arrange();
  wrote.deps.runsDir = tempDir("fe-runs-");
  appendFileSync(wrote.ledgerPath, `${quietRun(wrote.deps.runsDir, { mutation: true })}\n`);
  const refused = await main(wrote.argv("check"), wrote.deps);
  assert.ok(refused.problems.some((p) => p.includes("30 minutes")));
  const gone = arrange();
  gone.deps.runsDir = tempDir("fe-runs-");
  appendFileSync(gone.ledgerPath, `${quietRun(gone.deps.runsDir)}\n`);
  rmSync(join(gone.deps.runsDir, "quiet", "transport"), { recursive: true });
  const unreadable = await main(gone.argv("check"), gone.deps);
  assert.ok(unreadable.problems.some((p) => p.includes("30 minutes")));
});

test("check refuses without the approval lines", async () => {
  const { deps, argv } = arrange({ approve: false });
  const result = await main(argv("check"), deps);
  assert.equal(result.ok, false);
  assert.ok(result.problems.some((p) => p.includes("no approval line")));
});

test("record runs end to end: lock, started line, the run, SHA256SUMS, finished line, lock released", async () => {
  const { deps, argv, cliCalls, ledgerPath, dir } = arrange();
  const result = await main(argv("record"), deps);
  assert.equal(result.outcome, "recorded", JSON.stringify(result));
  assert.deepEqual(cliCalls, ["dry-run", "deploy", "delete"]);
  const rows = readFileSync(ledgerPath, "utf8")
    .trim()
    .split("\n")
    .map((l) => JSON.parse(l));
  assert.deepEqual(
    rows.slice(-2).map((r) => r.event),
    ["started", "finished"],
  );
  assert.equal(rows.at(-1).outcome, "recorded");
  assert.equal(rows.at(-1).lockRetained, false);
  assert.deepEqual(rows.at(-1).cliAttempts, { dryRun: 1, deploy: 1, delete: 1 });
  assert.equal(rows.at(-2).cliMax, 3);
  assert.equal(existsSync(join(dir, "locks", "fireemu-oracle-events.lock")), false);
  assert.equal(statSync(join(result.runDir, "production-run.json")).mode & 0o077, 0);
  assert.ok(existsSync(join(result.runDir, "SHA256SUMS")));
  const run = JSON.parse(readFileSync(join(result.runDir, "production-run.json"), "utf8"));
  assert.equal(run.passes.length, 2);
  assert.ok(
    !readFileSync(join(result.runDir, "transport/journal.jsonl"), "utf8").includes("synthetic-key"),
    "the API key is never journaled",
  );
  // the same packet cannot run twice
  const again = await main(argv("record"), deps);
  assert.equal(again.ok, false);
  assert.ok(again.problems.some((p) => p.includes("already started")));
});

test("a CLI dry run that fails stops the run with nothing written, and the ledger says one CLI attempt", async () => {
  const { deps, argv, cliCalls, ledgerPath, dir, world } = arrange();
  deps.runCli = async ({ action }) => {
    cliCalls.push(action);
    return { action, exitCode: 1 };
  };
  const result = await main(argv("record"), deps);
  assert.equal(result.outcome, "stopped-clean");
  assert.deepEqual(cliCalls, ["dry-run"]);
  const last = JSON.parse(readFileSync(ledgerPath, "utf8").trim().split("\n").at(-1));
  assert.equal(last.outcome, "stopped-clean");
  assert.equal(last.lockRetained, false);
  assert.deepEqual(last.cliAttempts, { dryRun: 1, deploy: 0, delete: 0 });
  assert.equal(existsSync(join(dir, "locks", "fireemu-oracle-events.lock")), false);
  assert.ok(
    world.requests.every(
      (r) =>
        r.method === "GET" ||
        r.url.includes(":getIamPolicy") ||
        r.url.includes(":runQuery") ||
        r.url.includes("oauth2"),
    ),
    "only reads were sent",
  );
});

test("a run that cannot verify its cleanup keeps the lock and says so in the ledger", async () => {
  const { deps, argv, world, ledgerPath, dir } = arrange();
  deps.runCli = async ({ action }) => {
    if (action === "deploy") world.deploy();
    return { action, exitCode: 0 };
  };
  const result = await main(argv("record"), deps);
  assert.equal(result.outcome, "needs-recovery");
  assert.equal(existsSync(join(dir, "locks", "fireemu-oracle-events.lock")), true);
  const last = JSON.parse(readFileSync(ledgerPath, "utf8").trim().split("\n").at(-1));
  assert.deepEqual([last.outcome, last.lockRetained], ["needs-recovery", true]);
});

test("a dirty tree, another HEAD, a set credential variable or a held lock refuse the start", async () => {
  for (const [label, change, pattern] of [
    [
      "dirty",
      (d) => {
        d.git = (args) => (args[0] === "rev-parse" ? head : " M file");
      },
      /not clean/,
    ],
    [
      "head",
      (d) => {
        d.git = (args) => (args[0] === "rev-parse" ? "f".repeat(40) : "");
      },
      /HEAD is/,
    ],
    [
      "env",
      (d) => {
        d.env = { ...d.env, FIREBASE_TOKEN: "x" };
      },
      /FIREBASE_TOKEN/,
    ],
    [
      "node",
      (d) => {
        d.nodeVersion = "24.14.0";
      },
      /Node 22/,
    ],
  ]) {
    const { deps, argv } = arrange();
    change(deps);
    const result = await main(argv("record"), deps);
    assert.equal(result.ok, false, label);
    assert.ok(
      result.problems.some((p) => pattern.test(p)),
      label,
    );
    assert.equal(deps.fetchCalled, undefined);
  }
});

test("a local preparation failure leaves no lock, no started line and no run directory", async () => {
  for (const [label, change] of [
    [
      "the credential command fails",
      (d) =>
        (d.printAccessToken = async () => {
          throw new Error("gcloud exited 1");
        }),
    ],
    [
      "the credential command prints no token",
      (d) => (d.printAccessToken = async () => "ERROR: reauthentication needed"),
    ],
    [
      "the source copy cannot be made",
      (d) =>
        (d.prepareSource = () => {
          throw new Error("git archive failed");
        }),
    ],
    [
      "the source copy has no dependencies",
      (d) => (d.sourceProblems = () => ["firebase-functions cannot be resolved from the fixture"]),
    ],
  ]) {
    const { deps, argv, ledgerPath, dir, world } = arrange();
    change(deps);
    const before = readFileSync(ledgerPath, "utf8");
    const result = await main(argv("record"), deps);
    assert.equal(result.ok, false, label);
    assert.equal(readFileSync(ledgerPath, "utf8"), before, label);
    assert.equal(existsSync(join(dir, "locks", "fireemu-oracle-events.lock")), false, label);
    assert.equal(world.requests.length, 0, label);
    assert.deepEqual(
      existsSync(join(dir, "runs")) ? readdirSync(join(dir, "runs")) : [],
      [],
      label,
    );
  }
});

test("check refuses a source copy without its dependencies", async () => {
  const { deps, argv } = arrange();
  deps.sourceProblems = () => ["firebase-functions cannot be resolved from the fixture"];
  const result = await main(argv("check"), deps);
  assert.equal(result.ok, false);
  assert.ok(result.problems.some((p) => p.includes("cannot be resolved")));
});

test("SHA256SUMS skips node_modules and does not follow links, even a loop", async () => {
  const { deps, argv } = arrange();
  deps.prepareSource = ({ target }) => {
    mkdirSync(join(target, "fixtures/node_modules/pkg"), { recursive: true });
    writeFileSync(join(target, "fixtures/node_modules/pkg/index.js"), "x");
    symlinkSync("..", join(target, "fixtures/node_modules/pkg/loop"));
    symlinkSync(".", join(target, "fixtures/self"));
    return { configPath: join(target, "firebase.json"), fixtureDir: join(target, "fixtures") };
  };
  const result = await main(argv("record"), deps);
  assert.equal(result.outcome, "recorded", JSON.stringify(result));
  const sums = readFileSync(join(result.runDir, "SHA256SUMS"), "utf8");
  assert.ok(!sums.includes("node_modules") && !sums.includes("self"));
  assert.ok(sums.includes("production-run.json"));
});
