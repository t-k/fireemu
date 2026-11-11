// The command line: the arguments, the environment, the checks that need no network, and the rule that nothing is sent
// without `--send` and the approved packet digest. The send path runs against the in-memory world.
import assert from "node:assert/strict";
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { FIREBASE_TOOLS_VERSION, NODE_VERSION } from "../plan.mjs";
import {
  PACKET_FILES,
  envProblems,
  lastActivity,
  localChecks,
  main,
  packetDigest,
  parseArgs,
  resultOf,
  writeAll,
} from "./main.mjs";
import { NUMBER, createWorld } from "./world.mjs";
import { tempDir } from "./testtmp.mjs";

const COMMIT = "a".repeat(40);
const values = (dir) => ({
  "run-dir": dir,
  "project-number": NUMBER,
  "source-commit": COMMIT,
  "deps-dir": "/deps/node_modules",
  node: "/node/bin/node",
  "firebase-js": "/tools/firebase.js",
});
const argv = (command, dir, extra = []) => [
  command,
  ...Object.entries(values(dir)).flatMap(([k, v]) => ["--" + k, v]),
  ...extra,
];
const okDeps = (world = null, calls = []) => ({
  nodeVersion: () => NODE_VERSION,
  firebaseToolsVersion: () => FIREBASE_TOOLS_VERSION,
  gitHead: () => COMMIT,
  gitDirty: () => false,
  adcExists: () => true,
  sdkProblems: () => [],
  token: () => "test-token-abcdefgh",
  repoRoot: () => "/repo",
  prepareSource: (o) => {
    calls.push(["prepareSource", o]);
    return { configPath: "/s/firebase.json", fixtureDir: "/s/functions" };
  },
  sourceProblems: (o) => {
    calls.push(["sourceProblems", o]);
    return [];
  },
  signals: () => {},
  send: world ? world.send : async () => new Response("{}"),
  runCli: (o) => world?.runCli({ action: o.action }),
  now: () => world?.now ?? Date.now(),
  record: async (o) => {
    calls.push(["record", o.runId]);
    return { outcome: "tq-recorded", closureReady: true, readBackRequired: false, attempted: 1 };
  },
  readback: async (o) => ({ allAbsent: true, attempted: 1, unknown: 0, inventory: null, o }),
});
const capture = () => {
  const lines = { out: [], err: [] };
  return { lines, out: (t) => lines.out.push(t), err: (t) => lines.err.push(t) };
};

test("the arguments are a command and --name value pairs, and --send takes none", () => {
  assert.deepEqual(parseArgs(["check", "--run-dir", "/x", "--send"]), {
    command: "check",
    values: { "run-dir": "/x", send: true },
  });
  assert.match(parseArgs(["check", "x"]).error, /unexpected argument x/);
  assert.match(parseArgs(["check", "--run-dir"]).error, /needs a value/);
  assert.match(parseArgs(["check", "--run-dir", "--send"]).error, /needs a value/);
});

test("the environment may not carry a credential, an emulator host or a project override", () => {
  assert.deepEqual(envProblems({ HOME: "/h", PATH: "/p" }), []);
  for (const name of [
    "GOOGLE_APPLICATION_CREDENTIALS",
    "FIREBASE_TOKEN",
    "CLOUDSDK_CORE_PROJECT",
    "GCLOUD_PROJECT",
    "GOOGLE_CLOUD_PROJECT",
    "FIRESTORE_EMULATOR_HOST",
  ])
    assert.deepEqual(envProblems({ [name]: "x" }), [name + " is set"]);
});

test("the local checks name every missing argument, every pin that is wrong and a dirty tree", () => {
  const deps = okDeps();
  const env = { HOME: "/h" };
  assert.deepEqual(localChecks({ values: values("/r"), env, deps }), []);
  assert.ok(localChecks({ values: {}, env, deps }).length >= 6);
  assert.match(localChecks({ values: values("/r"), env: {}, deps })[0], /HOME/);
  assert.match(
    localChecks({ values: { ...values("/r"), "project-number": "12" }, env, deps })[0],
    /12 or 13 digits/,
  );
  assert.match(
    localChecks({ values: { ...values("/r"), "source-commit": "abc" }, env, deps })[0],
    /full SHA/,
  );
  assert.match(
    localChecks({ values: values("/r"), env, deps: { ...deps, nodeVersion: () => "20.0.0" } })[0],
    /not 22/,
  );
  assert.match(
    localChecks({
      values: values("/r"),
      env,
      deps: { ...deps, firebaseToolsVersion: () => "15.0.0" },
    })[0],
    /not 15\.28\.2/,
  );
  assert.match(
    localChecks({ values: values("/r"), env, deps: { ...deps, gitHead: () => "b".repeat(40) } })[0],
    /HEAD is not/,
  );
  assert.match(
    localChecks({ values: values("/r"), env, deps: { ...deps, gitDirty: () => true } })[0],
    /not clean/,
  );
  assert.match(
    localChecks({ values: values("/r"), env, deps: { ...deps, sdkProblems: () => ["sdk"] } })[0],
    /sdk/,
  );
  assert.match(
    localChecks({ values: values("/r"), env, deps: { ...deps, adcExists: () => false } })[0],
    /application-default/,
  );
});

test("the packet digest covers each packet file by name and bytes, in a fixed order", () => {
  const files = new Map(PACKET_FILES.map((name, i) => [name, Buffer.from("file " + i)]));
  const digest = packetDigest((name) => files.get(name));
  assert.match(digest, /^[0-9a-f]{64}$/);
  assert.equal(
    digest,
    packetDigest((name) => files.get(name)),
  );
  for (const name of PACKET_FILES) {
    const changed = new Map(files);
    changed.set(name, Buffer.from("changed"));
    assert.notEqual(
      packetDigest((n) => changed.get(n)),
      digest,
      name,
    );
  }
  const swapped = new Map(files);
  swapped.set(PACKET_FILES[0], files.get(PACKET_FILES[1]));
  swapped.set(PACKET_FILES[1], files.get(PACKET_FILES[0]));
  assert.notEqual(
    packetDigest((n) => swapped.get(n)),
    digest,
  );
  // The real files exist, and the fixture and the recorder are among them.
  assert.match(packetDigest(), /^[0-9a-f]{64}$/);
  for (const needed of [
    "task-queue-functions/functions/index.js",
    "src/task-queue-production/record/run.mjs",
    "src/task-queue-production/corpus.mjs",
    "src/task-queue-production/plan.mjs",
    "src/task-queue-production/record/guard.mjs",
  ])
    assert.ok(PACKET_FILES.includes(needed), needed);
});

test("check sends nothing and prepares the source with the run's own identity", async () => {
  const dir = tempDir("tq-main-");
  const calls = [];
  const io = capture();
  const code = await main(argv("check", dir), {
    env: { HOME: "/h" },
    deps: okDeps(null, calls),
    out: io.out,
    err: io.err,
    digest: "d",
  });
  assert.equal(code, 0);
  assert.deepEqual(
    calls.map((c) => c[0]),
    ["prepareSource", "sourceProblems"],
  );
  const prepared = calls[0][1];
  assert.match(prepared.runId, /^[a-f0-9]{16}$/);
  assert.equal(prepared.depsDir, "/deps/node_modules");
  assert.equal(
    calls[1][1].runId,
    prepared.runId,
    "the discovery checks the run's own function ids",
  );
  assert.match(io.lines.out.at(-1), /nothing was sent/);
});

test("record needs --send and the approved digest; with both it runs once and exits by closureReady", async () => {
  const dir = tempDir("tq-main-");
  for (const extra of [
    [],
    ["--send"],
    ["--expect-digest", "d"],
    ["--send", "--expect-digest", "other"],
  ]) {
    const calls = [];
    const io = capture();
    const code = await main(argv("record", dir, extra), {
      env: { HOME: "/h" },
      deps: okDeps(null, calls),
      out: io.out,
      err: io.err,
      digest: "d",
    });
    assert.equal(code, 2, extra.join(" "));
    assert.equal(
      calls.some((c) => c[0] === "record"),
      false,
    );
    assert.match(io.lines.err.at(-1), /needs --send and the approved --expect-digest/);
  }
  const calls = [];
  const io = capture();
  const code = await main(argv("record", dir, ["--send", "--expect-digest", "d"]), {
    env: { HOME: "/h" },
    deps: okDeps(null, calls),
    out: io.out,
    err: io.err,
    digest: "d",
  });
  assert.equal(code, 0);
  assert.equal(calls.filter((c) => c[0] === "record").length, 1);
  // The summary says whether the observation is complete, not only whether the run may close.
  const summary = JSON.parse(io.lines.out.at(-1));
  assert.equal(summary.closureReady, true);
  assert.ok("observationComplete" in summary && "findings" in summary);
  const runId = calls.find((c) => c[0] === "record")[1];
  assert.equal(
    calls.find((c) => c[0] === "prepareSource")[1].runId,
    runId,
    "one identity for the source and the run",
  );
  assert.ok(readdirSync(dir).includes("result-" + runId + ".json"));
  assert.ok(readdirSync(dir).includes("journal-" + runId + ".jsonl"));
});

test("a recorder that throws leaves a result file and exits 4; an open run exits 3", async () => {
  const dir = tempDir("tq-main-");
  const io = capture();
  const deps = {
    ...okDeps(),
    record: async () => {
      throw new Error("boom");
    },
  };
  assert.equal(
    await main(argv("record", dir, ["--send", "--expect-digest", "d"]), {
      env: { HOME: "/h" },
      deps,
      out: io.out,
      err: io.err,
      digest: "d",
    }),
    4,
  );
  const result = readdirSync(dir).find((f) => f.startsWith("result-"));
  assert.equal(JSON.parse(readFileSync(join(dir, result), "utf8")).outcome, "tq-recorder-threw");
  const dir2 = tempDir("tq-main-");
  const open = {
    ...okDeps(),
    record: async () => ({
      outcome: "tq-needs-review",
      closureReady: false,
      readBackRequired: true,
      attempted: 2,
    }),
  };
  assert.equal(
    await main(argv("record", dir2, ["--send", "--expect-digest", "d"]), {
      env: { HOME: "/h" },
      deps: open,
      out: io.out,
      err: io.err,
      digest: "d",
    }),
    3,
  );
});

test("a source copy that fails its offline checks stops before anything is sent", async () => {
  const dir = tempDir("tq-main-");
  const io = capture();
  const calls = [];
  const deps = { ...okDeps(null, calls), sourceProblems: () => ["the fixture exports x"] };
  assert.equal(
    await main(argv("record", dir, ["--send", "--expect-digest", "d"]), {
      env: { HOME: "/h" },
      deps,
      out: io.out,
      err: io.err,
      digest: "d",
    }),
    2,
  );
  assert.equal(
    calls.some((c) => c[0] === "record"),
    false,
  );
});

test("a bad command or a missing argument is exit 2 and prints the maximum number of requests", async () => {
  const io = capture();
  assert.equal(
    await main(["nope"], { env: {}, deps: okDeps(), out: io.out, err: io.err, digest: "d" }),
    2,
  );
  assert.equal(
    await main(["check"], {
      env: { HOME: "/h" },
      deps: okDeps(),
      out: io.out,
      err: io.err,
      digest: "d",
    }),
    2,
  );
  assert.match(io.lines.out[0], /maxRequests": 600/);
});

test("the read-back waits ten minutes after the run's last request, and closes nothing the run left open", async () => {
  const dir = tempDir("tq-main-");
  const runId = "0123456789abcdef";
  const stamp = Date.parse("2026-11-12T01:00:00Z");
  const world = createWorld({ runId });
  writeFileSync(
    join(dir, `journal-${runId}.jsonl`),
    JSON.stringify({ dispatchAt: new Date(stamp).toISOString() }) + "\n",
  );
  const args = [
    "readback",
    "--run-dir",
    dir,
    "--project-number",
    NUMBER,
    "--run-id",
    runId,
    "--send",
    "--expect-digest",
    "d",
  ];
  let calls = 0;
  const go = async (base, result) => {
    const now = base + ++calls;
    if (result) writeFileSync(join(dir, `result-${runId}.json`), JSON.stringify(result));
    const io = capture();
    const code = await main(args, {
      env: { HOME: "/h" },
      deps: { ...okDeps(world), now: () => now },
      out: io.out,
      err: io.err,
      digest: "d",
    });
    return { code, io };
  };
  const early = await go(stamp + 9 * 60_000, { unconfirmedCreates: [] });
  assert.equal(early.code, 2);
  assert.match(early.io.lines.err.at(-1), /ten minutes/);
  const clean = await go(stamp + 11 * 60_000, {
    unconfirmedCreates: [],
    inventory: { before: {} },
    cleanup: {},
  });
  assert.equal(clean.code, 0);
  const open = await go(stamp + 11 * 60_000, {
    unconfirmedCreates: [{ label: "queue-x", name: "projects/p/queues/x" }],
    cleanup: {},
  });
  assert.equal(open.code, 3);
  assert.match(open.io.lines.err.at(-1), /unconfirmed creates remain/);
  const unreadable = await go(stamp + 11 * 60_000, "not a result");
  assert.equal(unreadable.code, 3);
  const carried = await go(stamp + 11 * 60_000, {
    unconfirmedCreates: [],
    cleanup: { uploadReasons: ["receipt-unconfirmed:x.zip"] },
  });
  assert.equal(carried.code, 3);
  assert.match(carried.io.lines.err.at(-1), /open obligations/);
  const noRun = await main(args, {
    env: { HOME: "/h" },
    deps: okDeps(world),
    out: () => {},
    err: () => {},
    digest: "x",
  });
  assert.equal(noRun, 2, "the digest is checked first");
});

test("resultOf reads the unconfirmed creates and the obligations a read-back must carry", () => {
  const dir = tempDir("tq-result-");
  const path = join(dir, "r.json");
  assert.equal(resultOf(path).ok, false);
  writeFileSync(path, "x");
  assert.equal(resultOf(path).ok, false);
  writeFileSync(path, JSON.stringify({ nope: 1 }));
  assert.match(resultOf(path).why, /no list of unconfirmed creates/);
  writeFileSync(
    path,
    JSON.stringify({
      unconfirmedCreates: [{ label: "a" }],
      cleanup: {
        uploadReasons: ["r"],
        uploadObjectsUnexplained: [{ name: "n" }],
        uploadObjectsDeleted: [{ bucket: "b", name: "o" }],
      },
      inventory: { complete: false, differences: [{ kind: "queues" }], before: { queues: [] } },
    }),
  );
  const r = resultOf(path);
  assert.deepEqual(r.carried, [
    "upload:r",
    "unexplained-upload-object:n",
    'inventory:{"kind":"queues"}',
    "inventory-incomplete",
  ]);
  assert.deepEqual(r.uploadObjects, [{ bucket: "b", name: "o" }]);
  assert.deepEqual(r.baseline, { queues: [] });
  assert.equal(r.creates.length, 1);
});

test("the last activity of a journal is the latest dispatch or response, and a journal that is not there is null", () => {
  const dir = tempDir("tq-journal-");
  const path = join(dir, "j.jsonl");
  assert.equal(lastActivity(path), null);
  writeFileSync(
    path,
    [
      { dispatchAt: "2026-11-12T01:00:00.000Z" },
      { responseAt: "2026-11-12T01:00:05.000Z" },
      "garbage",
      { responseAt: "x" },
    ]
      .map((r) => (typeof r === "string" ? r : JSON.stringify(r)))
      .join("\n") + "\n",
  );
  assert.equal(lastActivity(path), Date.parse("2026-11-12T01:00:05.000Z"));
});

test("a journal write that makes no progress is an error, and a short write is continued", () => {
  const written = [];
  writeAll(1, "abcdef", (fd, bytes, offset, length) => {
    const n = Math.min(2, length);
    written.push(bytes.subarray(offset, offset + n).toString());
    return n;
  });
  assert.equal(written.join(""), "abcdef");
  let calls = 0;
  assert.throws(
    () =>
      writeAll(1, "abc", () => {
        // A loop that never ends would hang the run: the stand-in gives up after a hundred calls and says so.
        if (++calls > 100) throw new Error("looped");
        return 0;
      }),
    /no progress/,
  );
  assert.equal(calls, 1);
  mkdirSync(tempDir("tq-x-"), { recursive: true });
});

test("the packet is these files in this order: a reordered list is another packet", () => {
  assert.deepEqual(PACKET_FILES, [
    "src/task-queue-production/plan.mjs",
    "src/task-queue-production/corpus.mjs",
    "src/task-queue-production/record/guard.mjs",
    "src/task-queue-production/record/logs.mjs",
    "src/task-queue-production/record/judge.mjs",
    "src/task-queue-production/record/deploy.mjs",
    "src/task-queue-production/record/run.mjs",
    "src/task-queue-production/record/readback.mjs",
    "src/task-queue-production/record/main.mjs",
    "src/task-queue-production/record/bin.mjs",
    "scheduled-delivery/capture.mjs",
    "scheduled-delivery/record/deploy.mjs",
    "scheduled-delivery/record/plan.mjs",
    "scheduled-delivery/record/token.mjs",
    "task-queue-functions/functions/index.js",
    "task-queue-functions/functions/package.json",
    "task-queue-functions/functions/suffix.json",
    "task-queue-functions/firebase.json",
  ]);
});

test("a read-back with a wrong digest or no --send sends nothing, even when its run is ready to be read", async () => {
  const dir = tempDir("tq-main-");
  const runId = "0123456789abcdef";
  const world = createWorld({ runId });
  const stamp = Date.parse("2026-11-11T01:00:00Z");
  writeFileSync(
    join(dir, `journal-${runId}.jsonl`),
    JSON.stringify({ dispatchAt: new Date(stamp).toISOString() }) + "\n",
  );
  writeFileSync(join(dir, `result-${runId}.json`), JSON.stringify({ unconfirmedCreates: [] }));
  const base = ["readback", "--run-dir", dir, "--project-number", NUMBER, "--run-id", runId];
  for (const extra of [
    ["--send"],
    ["--send", "--expect-digest", "wrong"],
    ["--expect-digest", "d"],
  ]) {
    const io = capture();
    const code = await main([...base, ...extra], {
      env: { HOME: "/h" },
      deps: { ...okDeps(world), now: () => stamp + 3_600_000 },
      out: io.out,
      err: io.err,
      digest: "d",
    });
    assert.equal(code, 2, extra.join(" "));
    assert.match(io.lines.err.at(-1), /readback needs --send and the approved --expect-digest/);
  }
  assert.deepEqual(world.calls, []);
  const bad = await main(
    [
      "readback",
      "--run-dir",
      dir,
      "--project-number",
      "12",
      "--run-id",
      runId,
      "--send",
      "--expect-digest",
      "d",
    ],
    { env: { HOME: "/h" }, deps: okDeps(world), out: () => {}, err: () => {}, digest: "d" },
  );
  assert.equal(bad, 2, "the project number is twelve or thirteen digits");
});

test("a read-back that finds a name still there exits 3, and one that finds none exits 0", async () => {
  const dir = tempDir("tq-main-");
  const runId = "0123456789abcdef";
  const stamp = Date.parse("2026-11-11T01:00:00Z");
  writeFileSync(
    join(dir, `journal-${runId}.jsonl`),
    JSON.stringify({ dispatchAt: new Date(stamp).toISOString() }) + "\n",
  );
  writeFileSync(
    join(dir, `result-${runId}.json`),
    JSON.stringify({ unconfirmedCreates: [], inventory: { before: {} }, cleanup: {} }),
  );
  const args = [
    "readback",
    "--run-dir",
    dir,
    "--project-number",
    NUMBER,
    "--run-id",
    runId,
    "--send",
    "--expect-digest",
    "d",
  ];
  let n = 0;
  const run = async (readback) => {
    const io = capture();
    const code = await main(args, {
      env: { HOME: "/h" },
      deps: { ...okDeps(), readback, now: () => stamp + 3_600_000 + ++n },
      out: io.out,
      err: io.err,
      digest: "d",
    });
    return code;
  };
  assert.equal(
    await run(async () => ({ allAbsent: false, attempted: 1, unknown: 0, inventory: null })),
    3,
  );
  assert.equal(
    await run(async () => ({ allAbsent: true, attempted: 1, unknown: 0, inventory: null })),
    0,
  );
});

test("the first signal asks for a stop at the next request and the second only reminds", async () => {
  const dir = tempDir("tq-main-");
  const io = capture();
  let handler;
  const deps = { ...okDeps(), signals: (h) => (handler = h) };
  await main(argv("record", dir, ["--send", "--expect-digest", "d"]), {
    env: { HOME: "/h" },
    deps,
    out: io.out,
    err: io.err,
    digest: "d",
  });
  io.lines.err.length = 0;
  handler("SIGINT");
  handler("SIGTERM");
  assert.match(io.lines.err[0], /SIGINT: stopping at the next request/);
  assert.match(io.lines.err[1], /SIGTERM: a stop is already under way/);
});
