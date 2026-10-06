// The recorder's command line: arguments, the local checks, the packet digest, and the whole send path with
// fakes in the same process (the real CLI, token and network replaced), including the exit codes and files.
import assert from "node:assert/strict";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  PACKET_FILES,
  envProblems,
  localChecks,
  main,
  packetDigest,
  parseArgs,
  realDeps,
} from "./main.mjs";
import { record } from "./run.mjs";
import { NUMBER, createWorld, reply } from "./world.mjs";

const COMMIT = "a".repeat(40);
const ENV = { HOME: "/tmp/fireemu-test/user", PATH: "/usr/bin" };
const argv = (command, run, extra = []) => [
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
const goodDeps = (world, overrides = {}) => {
  const plans = [];
  return {
    plans,
    deps: {
      nodeVersion: () => "22.22.1",
      firebaseToolsVersion: () => "15.28.2",
      gitHead: () => COMMIT,
      gitDirty: () => false,
      adcExists: () => true,
      token: () => "test-token",
      send: world.send,
      runCli: async ({ action, plan }) => {
        plans.push({ action, plan });
        return world.runCli({ action });
      },
      prepareSource: ({ target }) => ({
        configPath: join(target, "firebase.json"),
        fixtureDir: join(target, "fixture"),
      }),
      sourceProblems: () => [],
      repoRoot: () => "/repo",
      record: (options) =>
        record({ ...options, clock: () => world.now, sleep: async (ms) => world.advance(ms) }),
      ...overrides,
    },
  };
};
const tmp = () => mkdtempSync(join(tmpdir(), "main-test-"));
const quiet = () => {
  const lines = [];
  return { out: (t) => lines.push(String(t)), err: (t) => lines.push("ERR " + String(t)), lines };
};

test("arguments: a command and named values, a flag, and the refusal of anything else", () => {
  assert.deepEqual(parseArgs(["record", "--run-dir", "/r", "--send"]), {
    command: "record",
    values: { "run-dir": "/r", send: true },
  });
  assert.equal(parseArgs(["record", "stray"]).error, "unexpected argument stray");
  assert.equal(parseArgs(["record", "--run-dir"]).error, "--run-dir needs a value");
  assert.equal(parseArgs(["record", "--run-dir", "--send"]).error, "--run-dir needs a value");
});

test("the environment may not carry a credential, a project or an emulator host", () => {
  const bad = {
    GOOGLE_APPLICATION_CREDENTIALS: "x",
    FIREBASE_TOKEN: "x",
    CLOUDSDK_CORE_PROJECT: "x",
    GCLOUD_PROJECT: "x",
    FIRESTORE_EMULATOR_HOST: "x",
    GOOGLE_CLOUD_PROJECT: "x",
  };
  assert.equal(envProblems(bad).length, 6);
  assert.deepEqual(envProblems({ PATH: "/bin", HOME: "/h" }), []);
});

test("local checks: each required value, the Node and firebase-tools pins, the commit and a clean tree", () => {
  const world = createWorld();
  const { deps } = goodDeps(world);
  const run = tmp();
  const base = parseArgs(argv("check", run)).values;
  assert.deepEqual(localChecks({ values: base, env: ENV, deps }), []);
  for (const key of [
    "run-dir",
    "project-number",
    "source-commit",
    "deps-dir",
    "node",
    "firebase-js",
  ]) {
    const values = { ...base };
    delete values[key];
    assert.match(
      localChecks({ values, env: ENV, deps }).join(),
      new RegExp("--" + key + " is required"),
    );
  }
  assert.match(
    localChecks({ values: { ...base, "project-number": "12" }, env: ENV, deps }).join(),
    /12 or 13 digits/,
  );
  assert.match(
    localChecks({ values: { ...base, "source-commit": "abc" }, env: ENV, deps }).join(),
    /full SHA/,
  );
  assert.match(
    localChecks({ values: base, env: ENV, deps: { ...deps, nodeVersion: () => "24.14.0" } }).join(),
    /24\.14\.0, not 22\.22\.1/,
  );
  assert.match(
    localChecks({
      values: base,
      env: ENV,
      deps: { ...deps, firebaseToolsVersion: () => "15.29.0" },
    }).join(),
    /15\.29\.0, not 15\.28\.2/,
  );
  assert.match(
    localChecks({
      values: base,
      env: ENV,
      deps: { ...deps, gitHead: () => "b".repeat(40) },
    }).join(),
    /HEAD is not the source commit/,
  );
  assert.match(
    localChecks({ values: base, env: ENV, deps: { ...deps, gitDirty: () => true } }).join(),
    /not clean/,
  );
  assert.match(
    localChecks({ values: base, env: { FIREBASE_TOKEN: "x" }, deps }).join(),
    /FIREBASE_TOKEN is set/,
  );
  rmSync(run, { recursive: true, force: true });
});

test("the packet digest covers every packet file by name and content", () => {
  const files = Object.fromEntries(PACKET_FILES.map((f) => [f, Buffer.from("content of " + f)]));
  const read = (name) => files[name];
  const digest = packetDigest(read);
  assert.match(digest, /^[0-9a-f]{64}$/);
  assert.equal(packetDigest(read), digest);
  for (const name of PACKET_FILES) {
    const changed = { ...files, [name]: Buffer.from("other") };
    assert.notEqual(
      packetDigest((n) => changed[n]),
      digest,
      name,
    );
  }
  assert.equal(PACKET_FILES.length, 11);
  assert.match(packetDigest(), /^[0-9a-f]{64}$/, "the real files hash");
});

test("check passes with fakes and sends nothing; a source copy that fails stops it", async () => {
  const run = tmp();
  const world = createWorld();
  const { deps } = goodDeps(world);
  const io = quiet();
  assert.equal(await main(argv("check", run), { env: ENV, deps, ...io }), 0);
  assert.deepEqual(world.calls, []);
  assert.ok(io.lines.at(-1).includes("nothing was sent"));
  const bad = goodDeps(world, { sourceProblems: () => ["a region is not pinned"] });
  const io2 = quiet();
  assert.equal(
    await main(argv("check", join(run, "again")), { env: ENV, deps: bad.deps, ...io2 }),
    2,
  );
  assert.ok(io2.lines.join().includes("a region is not pinned"));
  rmSync(run, { recursive: true, force: true });
});

test("record refuses without --send, with another digest, and with bad arguments", async () => {
  const run = tmp();
  const world = createWorld();
  const { deps } = goodDeps(world);
  const digest = "d".repeat(64);
  assert.equal(await main(argv("record", run), { env: ENV, deps, digest, ...quiet() }), 2);
  assert.equal(
    await main(argv("record", run, ["--send", "--expect-digest", "0".repeat(64)]), {
      env: ENV,
      deps,
      digest,
      ...quiet(),
    }),
    2,
  );
  assert.equal(await main(["nonsense"], { env: ENV, deps, digest, ...quiet() }), 2);
  assert.equal(await main(["record", "--run-dir"], { env: ENV, deps, digest, ...quiet() }), 2);
  assert.deepEqual(world.calls, []);
  rmSync(run, { recursive: true, force: true });
});

test("a clean send exits 0, runs the CLI three times with the planned argv, and writes private files", async () => {
  const run = tmp();
  const world = createWorld();
  const { deps, plans } = goodDeps(world);
  const digest = "d".repeat(64);
  const io = quiet();
  const code = await main(argv("record", run, ["--send", "--expect-digest", digest]), {
    env: ENV,
    deps,
    digest,
    ...io,
  });
  assert.equal(code, 0, io.lines.join("\n"));
  assert.deepEqual(
    plans.map((p) => p.action),
    ["dry-run", "deploy", "delete"],
  );
  assert.ok(plans[0].plan.args.includes("--dry-run") && !plans[1].plan.args.includes("--dry-run"));
  assert.equal(plans[0].plan.env.PATH, "/node22/bin:/usr/bin");
  assert.equal(
    plans[0].plan.env.HOME,
    "/tmp/fireemu-test/user",
    "the CLI finds the owner's credential under the real HOME",
  );
  assert.notEqual(
    plans[0].plan.env.XDG_CONFIG_HOME,
    "/tmp/fireemu-test/user/.config",
    "no firebase login account is read",
  );
  assert.equal(plans[0].plan.cwd, join(run, "source"));
  assert.equal(plans[0].plan.env.GOOGLE_CLOUD_QUOTA_PROJECT, "fireemu-oracle-sbx");
  const files = readdirSync(run);
  const journal = files.find((f) => /^journal-[0-9a-f]{16}\.jsonl$/.test(f));
  const result = files.find((f) => /^result-[0-9a-f]{16}\.json$/.test(f));
  assert.ok(journal && result, files.join());
  assert.equal(statSync(run).mode & 0o777, 0o700);
  assert.equal(statSync(join(run, journal)).mode & 0o777, 0o600);
  assert.equal(statSync(join(run, result)).mode & 0o777, 0o600);
  const text = readFileSync(join(run, result), "utf8");
  assert.equal(text, JSON.stringify(JSON.parse(text), null, 2) + "\n");
  assert.equal(JSON.parse(text).closureReady, true);
  assert.ok(readFileSync(join(run, journal), "utf8").endsWith("\n"));
  rmSync(run, { recursive: true, force: true });
});

test("answers that need review exit 3; an exception exits 4 and says so in a result file", async () => {
  const digest = "d".repeat(64);
  const run = tmp();
  const world = createWorld({
    hooks: {
      ["POST /v1/projects/fireemu-oracle-sbx/locations/us-central1/jobs/firebase-schedule-schedOkV2-us-central1:run"]:
        async () => reply(503, { error: { code: 503, status: "UNAVAILABLE", message: "x" } }),
    },
  });
  const { deps } = goodDeps(world);
  assert.equal(
    await main(argv("record", run, ["--send", "--expect-digest", digest]), {
      env: ENV,
      deps,
      digest,
      ...quiet(),
    }),
    3,
  );
  rmSync(run, { recursive: true, force: true });
  const run2 = tmp();
  const boom = goodDeps(createWorld(), {
    record: async () => {
      throw new Error("boom");
    },
  });
  const io = quiet();
  assert.equal(
    await main(argv("record", run2, ["--send", "--expect-digest", digest]), {
      env: ENV,
      deps: boom.deps,
      digest,
      ...io,
    }),
    4,
  );
  assert.ok(io.lines.join().includes("the recorder stopped: boom"));
  const resultFile = readdirSync(run2).find((f) => f.startsWith("result-"));
  assert.equal(
    JSON.parse(readFileSync(join(run2, resultFile), "utf8")).outcome,
    "calendar-delivery-recorder-threw",
  );
  rmSync(run2, { recursive: true, force: true });
});

// ---- the review's findings for the command line ----------------------------------------------------

test("the REST token is asked for again after 40 minutes, at most twice again, and every request carries the one in use (M2)", async () => {
  const run = tmp();
  const world = createWorld();
  const used = [];
  let issued = 0;
  const { deps } = goodDeps(world, {
    now: () => world.now,
    token: () => "token-number-" + ++issued,
    send: async (request) => {
      used.push(request.headers.authorization);
      return world.send(request);
    },
    runCli: async ({ action }) => {
      const result = await world.runCli({ action });
      world.advance(45 * 60_000);
      return result;
    },
  });
  const digest = "d".repeat(64);
  const code = await main(argv("record", run, ["--send", "--expect-digest", digest]), {
    env: ENV,
    deps,
    digest,
    ...quiet(),
  });
  assert.equal(code, 0);
  assert.equal(issued, 3, "the first call and two refreshes");
  const order = [...new Set(used)];
  assert.deepEqual(order, [
    "Bearer token-number-1",
    "Bearer token-number-2",
    "Bearer token-number-3",
  ]);
  assert.equal(used.at(-1), "Bearer token-number-3", "the cleanup runs on the newest token");
  assert.deepEqual(used, [...used].toSorted(), "a token is never used after a newer one");
  rmSync(run, { recursive: true, force: true });
});

test("a run that fits in one token asks for it once", async () => {
  const run = tmp();
  const world = createWorld();
  let issued = 0;
  const { deps } = goodDeps(world, {
    now: () => world.now,
    token: () => "token-number-" + ++issued,
  });
  const digest = "d".repeat(64);
  await main(argv("record", run, ["--send", "--expect-digest", digest]), {
    env: ENV,
    deps,
    digest,
    ...quiet(),
  });
  assert.equal(issued, 1);
  rmSync(run, { recursive: true, force: true });
});

test("an answer that reflects a refreshed token is never kept (M2)", async () => {
  const run = tmp();
  const world = createWorld();
  let issued = 0;
  const { deps } = goodDeps(world, {
    now: () => world.now,
    token: () => "token-number-" + ++issued,
    send: async (request) => {
      if (request.url.includes("/topics?") && request.headers.authorization.endsWith("-2"))
        return new Response(JSON.stringify({ echo: "token-number-2" }), { status: 200 });
      return world.send(request);
    },
    runCli: async ({ action }) => {
      const result = await world.runCli({ action });
      if (action === "deploy") world.advance(45 * 60_000);
      return result;
    },
  });
  const digest = "d".repeat(64);
  await main(argv("record", run, ["--send", "--expect-digest", digest]), {
    env: ENV,
    deps,
    digest,
    ...quiet(),
  });
  const journalName = readdirSync(run).find((f) => f.startsWith("journal-"));
  const journal = readFileSync(join(run, journalName), "utf8");
  assert.equal(journal.includes("token-number-2"), false);
  assert.ok(journal.includes("transport-unknown"));
  rmSync(run, { recursive: true, force: true });
});

test("the local checks need HOME and the application-default credential file, by existence only (M1)", () => {
  const { deps } = goodDeps(createWorld());
  const base = parseArgs(argv("check", "/r")).values;
  assert.match(
    localChecks({ values: base, env: { PATH: "/usr/bin" }, deps }).join(),
    /HOME is not set/,
  );
  assert.match(
    localChecks({ values: base, env: ENV, deps: { ...deps, adcExists: () => false } }).join(),
    /application-default credential file is missing/,
  );
  const seen = [];
  localChecks({
    values: base,
    env: ENV,
    deps: { ...deps, adcExists: (home) => (seen.push(home), true) },
  });
  assert.deepEqual(seen, ["/tmp/fireemu-test/user"]);
});

test("the real credential check looks under the home's gcloud directory and nowhere else (M1)", () => {
  const home = tmp();
  try {
    assert.equal(realDeps.adcExists(home), false);
    mkdirSync(join(home, ".config/gcloud"), { recursive: true });
    assert.equal(realDeps.adcExists(home), false);
    writeFileSync(join(home, ".config/gcloud/application_default_credentials.json"), "{}");
    assert.equal(realDeps.adcExists(home), true);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test("a signal moves the recording to its cleanup, the second one only says so (S5)", async () => {
  const run = tmp();
  const world = createWorld();
  let handler;
  const { deps } = goodDeps(world, { signals: (h) => (handler = h) });
  const lines = quiet();
  const digest = "d".repeat(64);
  const aborted = [];
  const code = await main(argv("record", run, ["--send", "--expect-digest", digest]), {
    env: ENV,
    deps: {
      ...deps,
      record: (options) =>
        record({
          ...options,
          clock: () => world.now,
          sleep: async (ms) => {
            if (!aborted.length && ms === 60_000) {
              handler("SIGTERM");
              handler("SIGINT");
              aborted.push(true);
            }
            world.advance(ms);
          },
        }),
    },
    digest,
    ...lines,
  });
  assert.equal(code, 3, "an interrupted run needs review");
  assert.ok(lines.lines.some((l) => l.includes("SIGTERM: stopping at the next request")));
  assert.ok(lines.lines.some((l) => l.includes("SIGINT: a stop is already under way")));
  assert.deepEqual(world.cliRuns, ["dry-run", "deploy", "delete"]);
  assert.equal(world.jobs.size + world.functionsV2.size + world.functionsV1.size, 0);
  rmSync(run, { recursive: true, force: true });
});

test("the real signal handler is installed for the three terminating signals", () => {
  const before = ["SIGINT", "SIGTERM", "SIGHUP"].map((n) => process.listenerCount(n));
  realDeps.signals(() => {});
  const after = ["SIGINT", "SIGTERM", "SIGHUP"].map((n) => process.listenerCount(n));
  assert.deepEqual(
    after,
    before.map((n) => n + 1),
  );
  for (const name of ["SIGINT", "SIGTERM", "SIGHUP"])
    process.removeListener(name, process.listeners(name).at(-1));
});
