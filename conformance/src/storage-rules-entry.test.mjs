import { heldPaths } from "./test-held-paths.mjs";
import { tmpdir } from "node:os";
import assert from "node:assert/strict";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  symlink,
  writeFile,
  chmod,
} from "node:fs/promises";
import { execFileSync, spawn } from "node:child_process";
import { request as httpsRequest } from "node:https";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  bindStorageRulesEntry,
  entryRoot,
  mainRepositoryRoot,
  pinnedPaths,
  realBinding,
  systemClock,
  withStorageRulesRecording,
} from "./storage-rules/entry.mjs";
import { ADC, BUCKET, KEY_IDS, NUMBERS, privatePacket } from "./storage-rules-runner-support.mjs";
import {
  buildRunManifest,
  manifestParams,
  TEMPLATE_RUN_ID,
} from "./storage-rules/run-manifest.mjs";
import { codeDigests, gitOutput, manifestPin } from "./storage-rules/pins.mjs";

// The real entry point against a scratch main checkout: which files it reads, takes and writes, and what a caller cannot name.
const closure = JSON.parse(
  readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url)),
);
const sourceCommit = "a".repeat(40);
const pins = [
  "packetSha256",
  "sourceCommit",
  "runnerSha256",
  "manifestSha256",
  "fixtureSchemaSha256",
];
// A scratch code tree the entry hashes for its runner and fixture-schema pins (the same layout as the real checkout).
const codeRoot = mkdtempSync(join(tmpdir(), "storage-rules-entry-code-"));
process.on("exit", () => rmSync(codeRoot, { recursive: true, force: true }));
mkdirSync(join(codeRoot, "conformance", "src", "storage-rules", "nested"), { recursive: true });
mkdirSync(join(codeRoot, "spec", "compatibility", "closure"), { recursive: true });
for (const name of [
  "corpus",
  "rulesets",
  "fixture-proof",
  "private-inputs",
  "controller",
  "nested/extra",
])
  writeFileSync(
    join(codeRoot, "conformance", "src", "storage-rules", `${name}.mjs`),
    `export const name = "${name}";\n`,
  );
writeFileSync(join(codeRoot, "conformance", "src", "storage-rules", "README.md"), "not a module\n");
writeFileSync(
  join(codeRoot, "spec", "compatibility", "closure", "STORAGE-RULES.json"),
  JSON.stringify(closure),
);
const runId = "entry-test-run";
const manifestFor = (id) =>
  buildRunManifest(closure, {
    bucket: BUCKET,
    runId: id,
    sourceCommit,
    queryProjectNumber: NUMBERS.query,
    idpProjectNumber: NUMBERS.idp,
    queryApiKeyId: KEY_IDS.query,
    idpApiKeyId: KEY_IDS.idp,
  });
const digests = await codeDigests(codeRoot);
const packet = {
  taskId: "STORAGE-RULES",
  packetName: "stage3-v1",
  packetSha256: "1".repeat(64),
  sourceCommit,
  runnerSha256: digests.runnerSha256,
  manifestSha256: manifestPin(manifestFor(runId), closure),
  fixtureSchemaSha256: digests.fixtureSchemaSha256,
  projects: ["fireemu-oracle-idp", "fireemu-oracle-query"],
  maxRequests: 12344,
  reserveUsd: 2,
};
const envelopeId = "STORAGE-RULES-stage3-v1-001";
const review = {
  verdict: "APPROVE",
  must: [],
  should: [],
  ...Object.fromEntries(pins.map((key) => [key, packet[key]])),
  envelopeId,
  withinEnvelope: true,
};
const ledger = [
  "- 2026-09-28 | 調整役への委任（本番の送信） | decision=APPROVE; local fixture | オーナー（ローカル試験） | private.md",
  "- 2026-09-28 | 調整役への委任（枠の承認） | decision=APPROVE; local fixture | オーナー（ローカル試験） | private.md",
  `- 2026-09-28 | STORAGE-RULES stage3-v1 envelope | envelopeId=${envelopeId}; project=${packet.projects.join(",")}; maxRequests=12344; reserveUsd=2; writes=owned fixtures; iamConfig=Storage release only; retries=none; 根拠=2026-09-28 調整役への委任（本番の送信） | Claude（委任。オーナーの裁量の委任 2026-09-28） | private.md`,
  `- 2026-09-28 | STORAGE-RULES stage3-v1 | decision=APPROVE; ${pins.map((key) => `${key}=${packet[key]}`).join("; ")}; envelopeId=${envelopeId} | Claude（委任。枠の内の承認し直し） | private.md`,
].join("\n");
const clock = {
  nowSeconds: () => 1_800_000_000,
  waitUntilSeconds: async () => {},
  sleep: async () => {},
};

async function checkout(
  t,
  {
    ledgerText = ledger,
    ledgerMode = 0o644,
    usage = [],
    gitHead = sourceCommit,
    gitStatus = "",
    gitExtra = "",
  } = {},
) {
  const root = await mkdtemp(join(tmpdir(), "storage-rules-entry-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, ".git"));
  await mkdir(join(root, "docs.local", "instructions"), { recursive: true });
  const runs = join(root, "docs.local", "runs");
  await mkdir(runs, { mode: 0o700 });
  await chmod(runs, 0o700);
  await mkdir(join(runs, "sandbox-locks"), { mode: 0o700 });
  await chmod(join(runs, "sandbox-locks"), 0o700);
  await writeFile(join(root, "docs.local", "instructions", "owner-decisions.md"), ledgerText, {
    mode: ledgerMode,
  });
  await chmod(join(root, "docs.local", "instructions", "owner-decisions.md"), ledgerMode);
  if (usage.length > 0)
    await writeFile(
      join(runs, "storage-rules-recording-usage.jsonl"),
      usage
        .map((id) => `${JSON.stringify({ packetSha256: packet.packetSha256, runId: id })}\n`)
        .join(""),
      { mode: 0o600 },
    );
  const adcPath = join(root, "adc.json");
  await writeFile(adcPath, JSON.stringify(ADC), { mode: 0o600 });
  const inputsPath = join(root, "inputs.json");
  await writeFile(inputsPath, JSON.stringify(privatePacket(adcPath)), { mode: 0o600 });
  const wire = [];
  const requestImpl = (...args) => {
    wire.push(args);
    throw new Error("the wire must not be reached");
  };
  const gitCalls = [];
  const git = async (where, args) => {
    gitCalls.push([where, ...args]);
    return args[0] === "rev-parse"
      ? `${gitHead}\n`
      : args.includes("--ignored")
        ? gitExtra
        : gitStatus;
  };
  const entry = bindStorageRulesEntry({ root, codeRoot, requestImpl, clock, git });
  const options = {
    inputsPath,
    closure,
    runId,
    sourceCommit,
    packet: structuredClone(packet),
    review: structuredClone(review),
  };
  return { root, runs, entry, options, wire, gitCalls };
}

test("the paths are constants under the main checkout root", () => {
  const paths = pinnedPaths("/repo");
  assert.deepEqual(
    { ...paths, runDirectory: paths.runDirectory("r-1") },
    {
      ownerLedger: "/repo/docs.local/instructions/owner-decisions.md",
      lockDir: "/repo/docs.local/runs/sandbox-locks",
      legacyLockPath: "/repo/docs.local/runs/sandbox-ledger.jsonl.lock",
      usagePath: "/repo/docs.local/runs/storage-rules-recording-usage.jsonl",
      runsDir: "/repo/docs.local/runs",
      runDirectory: "/repo/docs.local/runs/storage-rules-r-1",
    },
  );
  assert.equal(Object.isFrozen(paths), true);
});

test("the main checkout is found above a linked worktree, whose .git is a file", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "storage-rules-entry-root-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, ".git"));
  const worktree = join(root, ".worktree", "feature");
  await mkdir(join(worktree, "conformance", "src", "storage-rules"), { recursive: true });
  await writeFile(join(worktree, ".git"), "gitdir: elsewhere\n");
  assert.equal(mainRepositoryRoot(join(worktree, "conformance", "src", "storage-rules")), root);
  assert.equal(mainRepositoryRoot(root), root);
  await assert.rejects(
    async () => mainRepositoryRoot(join(tmpdir(), "storage-rules-no-such-root-anywhere")),
    /main repository root not found/,
  );
});

test("the real binding of this file resolves to a main checkout that has the runs directory the recordings use", async () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const root = mainRepositoryRoot(here);
  assert.equal((await stat(join(root, ".git"))).isDirectory(), true);
  assert.equal(entryRoot, root);
  assert.equal(typeof withStorageRulesRecording, "function");
  // The real binding is that checkout, the real HTTPS request function and the system clock, and nothing else.
  assert.deepEqual(Object.keys(realBinding).sort(), [
    "clock",
    "codeRoot",
    "git",
    "requestImpl",
    "root",
  ]);
  assert.equal(realBinding.git, gitOutput);
  assert.equal(realBinding.codeRoot, join(here, "..", ".."));
  assert.equal(realBinding.root, root);
  assert.equal(realBinding.requestImpl, httpsRequest);
  assert.equal(realBinding.clock, systemClock);
  assert.equal(Object.isFrozen(realBinding) && Object.isFrozen(systemClock), true);
});

test("the entry root comes from the file's location, not from the working directory", async (t) => {
  const elsewhere = await mkdtemp(join(tmpdir(), "storage-rules-entry-cwd-"));
  t.after(() => rm(elsewhere, { recursive: true, force: true }));
  const previous = process.cwd();
  process.chdir(elsewhere);
  try {
    const fresh = await import(`./storage-rules/entry.mjs?cwd=${Date.now()}`);
    assert.equal(fresh.entryRoot, entryRoot);
  } finally {
    process.chdir(previous);
  }
});

test("the system clock reads real time, waits until its target and sleeps for the given milliseconds", async () => {
  assert.ok(
    Math.abs(systemClock.nowSeconds() - Date.now() / 1000) < 2 &&
      Number.isInteger(systemClock.nowSeconds()),
  );
  let started = Date.now();
  await systemClock.sleep(60);
  assert.ok(Date.now() - started >= 50, `slept ${Date.now() - started} ms`);
  started = Date.now();
  await systemClock.waitUntilSeconds(Date.now() / 1000 + 0.4);
  assert.ok(Date.now() - started >= 300, `waited ${Date.now() - started} ms`);
  started = Date.now();
  await systemClock.waitUntilSeconds(Date.now() / 1000 - 5);
  assert.ok(Date.now() - started < 200);
});

test("finding the main checkout does not swallow a filesystem error other than a missing .git", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "storage-rules-entry-eacces-"));
  t.after(async () => {
    await chmod(join(root, "closed"), 0o700).catch(() => {});
    await rm(root, { recursive: true, force: true });
  });
  await mkdir(join(root, ".git"));
  await mkdir(join(root, "closed", "inner"), { recursive: true });
  await chmod(join(root, "closed"), 0o000);
  assert.throws(() => mainRepositoryRoot(join(root, "closed", "inner")), /EACCES/);
});

test("the binding is a closed record for a main checkout, the real request function and a clock", async (t) => {
  const f = await checkout(t);
  const good = { root: f.root, codeRoot, requestImpl() {}, clock, git: async () => "" };
  assert.doesNotThrow(() => bindStorageRulesEntry(good));
  const linked = join(f.root, ".worktree", "wt");
  await mkdir(linked, { recursive: true });
  await writeFile(join(linked, ".git"), "gitdir: x\n");
  for (const bad of [
    null,
    {},
    { ...good, extra: 1 },
    { root: f.root, requestImpl: good.requestImpl },
    { ...good, codeRoot: 5 },
    { ...good, git: 5 },
    { ...good, root: "relative" },
    { ...good, root: `${f.root}/` },
    { ...good, root: linked },
    { ...good, root: 5 },
    { ...good, requestImpl: 5 },
    { ...good, clock: { nowSeconds() {} } },
    { ...good, clock: [] },
  ]) {
    assert.throws(
      () => bindStorageRulesEntry(bad),
      /invalid entry binding|entry root is not a main checkout|main repository root not found/,
    );
  }
});

test("a caller cannot name the ledger, the locks, the usage ledger, the run directory, the transport or the clock", async (t) => {
  const f = await checkout(t);
  const overrides = {
    readLedger: async () => "",
    ledger: "/x",
    ledgerPath: "/x",
    locks: {},
    lockDir: "/x",
    legacyLockPath: "/x",
    usagePath: "/x",
    directory: "/x",
    transport: { send() {}, validate() {} },
    clock,
    root: "/x",
    requestImpl() {},
  };
  for (const [name, value] of Object.entries(overrides))
    await assert.rejects(
      f.entry({ ...f.options, [name]: value }, async () => assert.fail("must not run")),
      /invalid storage rules recording options/,
      name,
    );
  // Nor can a required option be left out or renamed, or the callback be something else.
  for (const key of Object.keys(f.options)) {
    const { [key]: _, ...rest } = f.options;
    await assert.rejects(
      f.entry(rest, async () => assert.fail("must not run")),
      /invalid storage rules recording options/,
      key,
    );
  }
  await assert.rejects(
    f.entry(f.options, "not a function"),
    /invalid storage rules recording options/,
  );
  for (const bad of ["Bad Id", 5, ["entry-test"], "a".repeat(49), ""])
    await assert.rejects(
      f.entry({ ...f.options, runId: bad }, async () => assert.fail("must not run")),
      /invalid storage rules recording options/,
      String(bad),
    );
  assert.deepEqual(await readdir(f.runs), ["sandbox-locks"]);
  assert.equal(f.wire.length, 0);
});

test("a run reads the pinned ledger, takes the pinned locks, marks the pinned usage ledger and writes its journals in a private run directory", async (t) => {
  const f = await checkout(t, { usage: ["first-run", "second-run"] });
  let seen;
  let result;
  await f.entry(f.options, async (run) => {
    seen = {
      locks: (await readdir(join(f.runs, "sandbox-locks"))).sort(),
      directoryMode: (await stat(join(f.runs, `storage-rules-${runId}`))).mode & 0o777,
    };
    const body = JSON.parse(
      await readFile(join(f.runs, "sandbox-locks", "fireemu-oracle-idp.lock"), "utf8"),
    );
    assert.deepEqual(
      [body.taskId, body.packetId, body.sourceCommit, body.pid],
      [packet.taskId, packet.packetName, sourceCommit, process.pid],
    );
    assert.ok(Math.abs(Date.parse(body.acquiredAt) - Date.now()) < 60_000, body.acquiredAt);
    result = await run.run();
  });
  // The third recording under this approval is refused by the pinned usage ledger, so the approval read from the pinned owner ledger was valid.
  assert.deepEqual([result.status, result.reason], ["stopped", "admission refused"]);
  assert.deepEqual(seen, {
    locks: ["fireemu-oracle-idp.lock", "fireemu-oracle-query.lock"],
    directoryMode: 0o700,
  });
  assert.deepEqual(await readdir(join(f.runs, "sandbox-locks")), []);
  assert.equal(
    await readFile(join(f.runs, "storage-rules-recording-usage.jsonl"), "utf8"),
    ["first-run", "second-run"]
      .map((id) => `${JSON.stringify({ packetSha256: packet.packetSha256, runId: id })}\n`)
      .join(""),
  );
  assert.ok((await readdir(join(f.runs, `storage-rules-${runId}`))).length >= 2);
  assert.equal(f.wire.length, 0);
});

test("a first recording is marked in the pinned usage ledger, and the wire is only the injected request function", async (t) => {
  const f = await checkout(t);
  let result;
  await assert.rejects(
    f.entry(f.options, async (run) => {
      result = await run.run();
    }),
  );
  // The first request (the owner's OAuth token refresh) reached the injected request function, which the test made throw: the attempt stops and keeps the locks.
  assert.equal(f.wire.length >= 1, true);
  assert.equal(result.status, "stopped");
  assert.equal(
    await readFile(join(f.runs, "storage-rules-recording-usage.jsonl"), "utf8"),
    `${JSON.stringify({ packetSha256: packet.packetSha256, runId })}\n`,
  );
  assert.deepEqual((await readdir(join(f.runs, "sandbox-locks"))).sort(), [
    "fireemu-oracle-idp.lock",
    "fireemu-oracle-query.lock",
  ]);
  const [url, requestOptions] = f.wire[0];
  assert.equal(new URL(url).origin, "https://oauth2.googleapis.com");
  assert.deepEqual(
    [requestOptions.method, requestOptions.agent, requestOptions.rejectUnauthorized],
    ["POST", false, true],
  );
});

test("a run directory that already exists, a missing or shared runs or lock directory, and a refused ledger stop the run before any lock or marker", async (t) => {
  const f = await checkout(t);
  await mkdir(join(f.runs, `storage-rules-${runId}`), { mode: 0o700 });
  await assert.rejects(
    f.entry(f.options, async () => assert.fail("must not run")),
    /run directory exists/,
  );
  const g = await checkout(t);
  await chmod(join(g.runs, "sandbox-locks"), 0o750);
  await assert.rejects(
    g.entry(g.options, async () => assert.fail("must not run")),
    /lock directory refused/,
  );
  const h = await checkout(t);
  await rm(join(h.runs, "sandbox-locks"), { recursive: true });
  await assert.rejects(
    h.entry(h.options, async () => assert.fail("must not run")),
    /lock directory missing/,
  );
  const i = await checkout(t);
  await chmod(i.runs, 0o755);
  await assert.rejects(
    i.entry(i.options, async () => assert.fail("must not run")),
    /runs directory refused/,
  );
  for (const state of [g, h, i]) assert.equal(state.wire.length, 0);
  assert.deepEqual(await readdir(join(f.runs, "sandbox-locks")), []);
});

test("the owner ledger must be a plain file of this user that nobody else can write", async (t) => {
  for (const setup of [
    async (f) => chmod(join(f.root, "docs.local", "instructions", "owner-decisions.md"), 0o664),
    async (f) => chmod(join(f.root, "docs.local", "instructions", "owner-decisions.md"), 0o646),
    async (f) => {
      const path = join(f.root, "docs.local", "instructions", "owner-decisions.md");
      await rm(path);
      await symlink(join(f.root, "elsewhere.md"), path);
      await writeFile(join(f.root, "elsewhere.md"), ledger);
    },
    async (f) => {
      const path = join(f.root, "docs.local", "instructions", "owner-decisions.md");
      await rm(path);
      await mkdir(path);
    },
    async (f) => rm(join(f.root, "docs.local", "instructions", "owner-decisions.md")),
    async (f) =>
      writeFile(
        join(f.root, "docs.local", "instructions", "owner-decisions.md"),
        Buffer.from([0xff, 0xfe, 0x41]),
      ),
  ]) {
    const f = await checkout(t);
    await setup(f);
    let result;
    await f.entry(f.options, async (run) => {
      result = await run.run();
    });
    assert.deepEqual([result.status, result.reason], ["stopped", "admission refused"]);
    assert.equal(f.wire.length, 0);
    assert.equal(
      await readFile(join(f.runs, "storage-rules-recording-usage.jsonl"), "utf8").catch(() => ""),
      "",
    );
  }
});

test("a runs or lock directory that is a file or a link, or another user's, is refused", async (t) => {
  const asFile = await checkout(t);
  await rm(join(asFile.runs, "sandbox-locks"), { recursive: true });
  await writeFile(join(asFile.runs, "sandbox-locks"), "", { mode: 0o600 });
  await assert.rejects(
    asFile.entry(asFile.options, async () => assert.fail("must not run")),
    /lock directory refused/,
  );
  const asLink = await checkout(t);
  await rm(join(asLink.runs, "sandbox-locks"), { recursive: true });
  await mkdir(join(asLink.root, "real-locks"), { mode: 0o700 });
  await symlink(join(asLink.root, "real-locks"), join(asLink.runs, "sandbox-locks"));
  await assert.rejects(
    asLink.entry(asLink.options, async () => assert.fail("must not run")),
    /lock directory refused/,
  );
  // Another user's directory: the check compares the owner with this process's user.
  for (const [name, message] of [["runs", /runs directory refused/]]) {
    const other = await checkout(t);
    const real = process.getuid;
    process.getuid = () => real() + 1;
    try {
      await assert.rejects(
        other.entry(other.options, async () => assert.fail("must not run")),
        message,
        name,
      );
    } finally {
      process.getuid = real;
    }
  }
  const foreignLocks = await checkout(t);
  await chmod(foreignLocks.runs, 0o700);
  const real = process.getuid;
  const calls = [];
  // The runs directory is checked first; only the lock directory sees a different user.
  process.getuid = () => {
    calls.push(1);
    return calls.length <= 1 ? real() : real() + 1;
  };
  try {
    await assert.rejects(
      foreignLocks.entry(foreignLocks.options, async () => assert.fail("must not run")),
      /lock directory refused/,
    );
  } finally {
    process.getuid = real;
  }
  for (const state of [asFile, asLink, foreignLocks]) assert.equal(state.wire.length, 0);
});

test("a legacy shared lock at the pinned path stops the run, and nothing is left held", async (t) => {
  const f = await checkout(t);
  await writeFile(join(f.runs, "sandbox-ledger.jsonl.lock"), "{}\n", { mode: 0o600 });
  await assert.rejects(
    f.entry(f.options, async () => assert.fail("must not run")),
    /legacy shared lock exists/,
  );
  assert.deepEqual(await readdir(join(f.runs, "sandbox-locks")), []);
  assert.equal(f.wire.length, 0);
});

const held = (path) => heldPaths(path);

test("an owner ledger that is over its size limit, is not valid UTF-8, or is another user's is refused, and the handle is closed each time", async (t) => {
  const path = (f) => join(f.root, "docs.local", "instructions", "owner-decisions.md");
  const refusedRun = async (f, between = async () => {}) => {
    let result;
    await f.entry(f.options, async (run) => {
      await between();
      result = await run.run();
    });
    assert.deepEqual([result.status, result.reason], ["stopped", "admission refused"]);
    assert.equal(f.wire.length, 0);
    assert.deepEqual(held(path(f)), []);
  };
  const big = await checkout(t, { ledgerText: `${ledger}\n${"x".repeat(8 * 1024 * 1024)}` });
  await refusedRun(big);
  const invalid = await checkout(t);
  await writeFile(path(invalid), Buffer.concat([Buffer.from(ledger), Buffer.from([0x0a, 0xff])]), {
    mode: 0o644,
  });
  await refusedRun(invalid);
  const foreign = await checkout(t);
  const real = process.getuid;
  await refusedRun(foreign, async () => {
    process.getuid = () => real() + 1;
    t.after(() => {
      process.getuid = real;
    });
  }).finally(() => {
    process.getuid = real;
  });
  // The same ledger is accepted for its own user (the runs above fail only for the stated reason).
  const fine = await checkout(t);
  let result;
  await assert.rejects(
    fine.entry(fine.options, async (run) => {
      result = await run.run();
    }),
  );
  assert.notEqual(result.reason, "admission refused");
  assert.deepEqual(held(path(fine)), []);
});

test("an owner ledger that is a named pipe is refused without blocking, even when a writer is ready", async (t) => {
  for (const withWriter of [false, true]) {
    const f = await checkout(t);
    const ledgerPath = join(f.root, "docs.local", "instructions", "owner-decisions.md");
    await rm(ledgerPath);
    execFileSync("mkfifo", ["-m", "600", ledgerPath]);
    let writer = null;
    if (withWriter) {
      await writeFile(join(f.root, "ledger-source.md"), ledger);
      writer = spawn(
        "sh",
        ["-c", 'cat "$0" > "$1"', join(f.root, "ledger-source.md"), ledgerPath],
        { stdio: "ignore" },
      );
    }
    try {
      let result;
      const run = f.entry(f.options, async (recording) => {
        result = await recording.run();
      });
      await Promise.race([
        run,
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error("blocked on the pipe")), 4000).unref(),
        ),
      ]);
      assert.deepEqual(
        [result.status, result.reason],
        ["stopped", "admission refused"],
        String(withWriter),
      );
      assert.equal(f.wire.length, 0);
    } finally {
      if (writer !== null && writer.exitCode === null) writer.kill("SIGTERM");
    }
  }
});

test("the run is refused, before anything is created, unless the code, the fixture schema, the checkout and the manifest reproduce the approval's pins", async (t) => {
  const cases = [
    [
      "runnerSha256",
      (f) => {
        f.options.packet.runnerSha256 = "0".repeat(64);
      },
      /pin mismatch: runnerSha256/,
    ],
    [
      "fixtureSchemaSha256",
      (f) => {
        f.options.packet.fixtureSchemaSha256 = "0".repeat(64);
      },
      /pin mismatch: fixtureSchemaSha256/,
    ],
    [
      "runner digest not hex",
      (f) => {
        f.options.packet.runnerSha256 = "X".repeat(64);
      },
      /invalid storage rules recording options/,
    ],
    [
      "runner digest upper case",
      (f) => {
        f.options.packet.runnerSha256 = f.options.packet.runnerSha256.toUpperCase();
      },
      /invalid storage rules recording options/,
    ],
    [
      "manifest digest not hex",
      (f) => {
        f.options.packet.manifestSha256 = "short";
      },
      /invalid storage rules recording options/,
    ],
    [
      "fixture digest not hex",
      (f) => {
        f.options.packet.fixtureSchemaSha256 = 5;
      },
      /invalid storage rules recording options/,
    ],
    [
      "runner digest with a prefix",
      (f) => {
        f.options.packet.runnerSha256 = `z${f.options.packet.runnerSha256}`;
      },
      /invalid storage rules recording options/,
    ],
    [
      "fixture digest with a suffix",
      (f) => {
        f.options.packet.fixtureSchemaSha256 = `${f.options.packet.fixtureSchemaSha256}0`;
      },
      /invalid storage rules recording options/,
    ],
    [
      "manifest digest with a suffix",
      (f) => {
        f.options.packet.manifestSha256 = `${f.options.packet.manifestSha256}0`;
      },
      /invalid storage rules recording options/,
    ],
    [
      "packet is a class instance",
      (f) => {
        f.options.packet = Object.assign(new (class Packet {})(), f.options.packet);
        f.options.sourceCommit = f.options.packet.sourceCommit;
      },
      /invalid storage rules recording options/,
    ],
    [
      "packet is null",
      (f) => {
        f.options.packet = null;
      },
      /invalid storage rules recording options/,
    ],
  ];
  for (const [name, change, message] of cases) {
    const f = await checkout(t);
    change(f);
    await assert.rejects(
      f.entry(f.options, async () => assert.fail("must not run")),
      message,
      name,
    );
    assert.deepEqual(await readdir(f.runs), ["sandbox-locks"], name);
    assert.deepEqual(await readdir(join(f.runs, "sandbox-locks")), [], name);
    assert.equal(f.wire.length, 0, name);
  }
  const unreadable = await checkout(t);
  const emptyCode = await mkdtemp(join(tmpdir(), "storage-rules-entry-empty-code-"));
  t.after(() => rm(emptyCode, { recursive: true, force: true }));
  unreadable.entry = bindStorageRulesEntry({
    root: unreadable.root,
    codeRoot: emptyCode,
    requestImpl() {},
    clock,
    git: async () => "",
  });
  await assert.rejects(
    unreadable.entry(unreadable.options, async () => assert.fail("must not run")),
    /pin source refused/,
  );
  assert.deepEqual(await readdir(unreadable.runs), ["sandbox-locks"]);
  const moved = await checkout(t, { gitHead: "b".repeat(40) });
  await assert.rejects(
    moved.entry(moved.options, async () => assert.fail("must not run")),
    /source commit mismatch/,
  );
  const dirty = await checkout(t, { gitStatus: " M conformance/src/storage-rules/entry.mjs\n" });
  await assert.rejects(
    dirty.entry(dirty.options, async () => assert.fail("must not run")),
    /working tree not clean/,
  );
  const untracked = await checkout(t, {
    gitExtra: "?? conformance/src/storage-rules/driver.mjs\n",
  });
  await assert.rejects(
    untracked.entry(untracked.options, async () => assert.fail("must not run")),
    /untracked or ignored runner files/,
  );
  const broken = await checkout(t);
  broken.entry = bindStorageRulesEntry({
    root: broken.root,
    codeRoot,
    requestImpl() {},
    clock,
    git: async () => {
      throw new Error("git missing");
    },
  });
  await assert.rejects(
    broken.entry(broken.options, async () => assert.fail("must not run")),
    /source commit unreadable/,
  );
  for (const state of [moved, dirty, untracked, broken]) {
    assert.deepEqual(await readdir(state.runs), ["sandbox-locks"]);
    assert.equal(state.wire.length, 0);
  }
  const ok = await checkout(t);
  await assert.rejects(
    ok.entry(ok.options, async (run) => {
      await run.run();
    }),
  );
  assert.deepEqual(
    ok.gitCalls.map(([where, ...args]) => [where, args.join(" ")]),
    [
      [codeRoot, "rev-parse HEAD"],
      [codeRoot, "status --porcelain --untracked-files=no"],
      [
        codeRoot,
        `status --porcelain --untracked-files=all --ignored -- conformance/src/storage-rules spec/compatibility/closure/STORAGE-RULES.json`,
      ],
    ],
  );
});

test("the caller receives the assembled recording itself, still frozen, and the entry's own return value", async (t) => {
  const f = await checkout(t);
  let frozen;
  await assert.rejects(
    f.entry(f.options, async (run) => {
      frozen = Object.isFrozen(run);
      await run.run();
    }),
  );
  assert.equal(frozen, true);
  const g = await checkout(t);
  assert.equal(await g.entry(g.options, async () => "value"), "value");
});

test("a manifest that does not reproduce the pinned digest stops the run before the caller runs, with the locks released and nothing marked", async (t) => {
  const f = await checkout(t);
  f.options.packet.manifestSha256 = "0".repeat(64);
  await assert.rejects(
    f.entry(f.options, async () => assert.fail("must not run")),
    /pin mismatch: manifestSha256/,
  );
  assert.deepEqual(await readdir(join(f.runs, "sandbox-locks")), []);
  await assert.rejects(readFile(join(f.runs, "storage-rules-recording-usage.jsonl")), /ENOENT/);
  assert.equal(f.wire.length, 0);
});

test("the manifest pin is the same for every run ID and changes with anything else", () => {
  const first = manifestFor("entry-test-run");
  const second = manifestFor("another-run-id-9");
  assert.notEqual(first.sha256, second.sha256);
  const pin = manifestPin(first, closure);
  assert.equal(manifestPin(second, closure), pin);
  assert.match(pin, /^[0-9a-f]{64}$/);
  assert.equal(
    manifestPin(
      buildRunManifest(closure, { ...manifestParams(first), runId: TEMPLATE_RUN_ID }),
      closure,
    ),
    pin,
  );
  for (const change of [
    { bucket: "another-bucket-name" },
    { sourceCommit: "b".repeat(40) },
    { queryProjectNumber: "333333333333" },
    { idpProjectNumber: "444444444444" },
    { queryApiKeyId: "00000000-0000-4000-8000-0000000000aa" },
    { idpApiKeyId: "00000000-0000-4000-8000-0000000000bb" },
  ]) {
    assert.notEqual(
      manifestPin(buildRunManifest(closure, { ...manifestParams(first), ...change }), closure),
      pin,
      JSON.stringify(change),
    );
  }
  assert.equal(TEMPLATE_RUN_ID, "manifest-pin-template");
  const params = manifestParams(first);
  assert.throws(
    () => buildRunManifest(closure, { ...params, extra: 1 }),
    /invalid run manifest input/,
  );
  for (const key of Object.keys(params)) {
    const { [key]: _, ...rest } = params;
    assert.throws(() => buildRunManifest(closure, rest), /invalid run manifest input/, key);
    assert.throws(
      () => buildRunManifest(closure, { ...rest, extra: params[key] }),
      /invalid run manifest input/,
      `${key} renamed`,
    );
  }
  assert.throws(() => buildRunManifest(closure, null), /invalid run manifest input/);
  // A manifest whose binding does not rebuild to it is refused.
  assert.throws(
    () =>
      manifestPin(
        { ...first, binding: { ...first.binding, bucket: "other-bucket-name" } },
        closure,
      ),
    /does not rebuild/,
  );
  assert.throws(
    () => manifestPin({ ...first, sha256: "0".repeat(64) }, closure),
    /does not rebuild/,
  );
  assert.throws(() => manifestPin(null, closure), /invalid run manifest input/);
});
