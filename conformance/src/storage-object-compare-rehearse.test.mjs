import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { rehearse, standinSha256 } from "./storage-object-compare/rehearse.mjs";
import { rehearseCommand } from "./storage-object-compare/run.mjs";
import { tempDir } from "./test-tmpdir.mjs";

const sha256 = (text) => createHash("sha256").update(text).digest("hex");
const COMMIT = "b0fc2485d5596439b515f4fd12f6c3ce68d4af91";
// A throwaway repository: the global git configuration (signing, hooks) is not this test's business.
const gitEnv = {
  ...process.env,
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_SYSTEM: "/dev/null",
  GIT_AUTHOR_NAME: "t",
  GIT_AUTHOR_EMAIL: "t@example.com",
  GIT_COMMITTER_NAME: "t",
  GIT_COMMITTER_EMAIL: "t@example.com",
};
const git = (cwd, ...args) => spawnSync("git", args, { cwd, env: gitEnv, encoding: "utf8" });

function setup({ clean = true, script } = {}) {
  const root = tempDir("compare-rehearse-");
  const recorder = join(root, "recorder");
  mkdirSync(join(recorder, "conformance"), { recursive: true });
  writeFileSync(join(recorder, "conformance", "file.txt"), "x");
  git(recorder, "init", "-q");
  git(recorder, "add", ".");
  git(recorder, "commit", "-q", "-m", "x");
  if (!clean) writeFileSync(join(recorder, "conformance", "dirty.txt"), "y");
  const events = join(root, "events");
  mkdirSync(events);
  writeFileSync(join(events, "aggregate-events.jsonl"), '{"type":"recipe-begin"}\n');
  const binary = join(root, "fireemu");
  writeFileSync(
    binary,
    script ??
      `#!/bin/sh
if [ "$1" = "--version" ]; then echo "fireemu 9.9.9"; exit 0; fi
echo '{"status":"LOCAL_COMPLETE","completedRecipes":[26,0],"requests":2446,"eventDirectory":"${events}"}'
`,
  );
  chmodSync(binary, 0o755);
  const rules = join(root, "rules.rules");
  writeFileSync(rules, "rules");
  const fixture = join(root, "fx");
  mkdirSync(fixture);
  writeFileSync(join(fixture, "index.json"), '{"recipes":[]}');
  return { root, recorder, binary, rules, fixture, out: join(root, "out"), events };
}
const input = (s, over = {}) => ({
  fireemuBinary: s.binary,
  fireemuCommit: COMMIT,
  recorderDir: s.recorder,
  rulesFile: s.rules,
  fixtureDir: s.fixture,
  outDir: s.out,
  sandbox: false,
  timeoutMs: 20_000,
  ...over,
});

test("the rehearsal runs the binary, copies the journal and writes a receipt that binds the binary, the commits and the journal", async () => {
  const s = setup();
  const receipt = await rehearse(input(s));
  const journal = join(s.out, "journal.jsonl");
  assert.equal(readFileSync(journal, "utf8"), '{"type":"recipe-begin"}\n');
  assert.equal(receipt.fireemu.binarySha256, sha256(readFileSync(s.binary)));
  assert.equal(receipt.fireemu.version, "fireemu 9.9.9");
  assert.equal(receipt.fireemu.commit, COMMIT);
  assert.equal(receipt.recorder.commit, git(s.recorder, "rev-parse", "HEAD").stdout.trim());
  assert.equal(receipt.recorder.clean, true);
  assert.equal(receipt.journalSha256, sha256('{"type":"recipe-begin"}\n'));
  assert.equal(receipt.standinSha256, standinSha256());
  assert.equal(receipt.fixtureIndexSha256, sha256('{"recipes":[]}'));
  assert.equal(receipt.rulesSha256, sha256("rules"));
  assert.deepEqual(receipt.result, {
    status: "LOCAL_COMPLETE",
    completedRecipes: [26, 0],
    requests: 2446,
    exitCode: 0,
  });
  assert.deepEqual(JSON.parse(readFileSync(join(s.out, "receipt.json"), "utf8")), receipt);
  for (const name of ["fireemu.config.json", "firebase.json"])
    assert.ok(existsSync(join(s.out, name)), name);
  assert.equal(
    existsSync(join(s.out, "loopback.sb")),
    false,
    "no sandbox profile when the sandbox is off",
  );
});

test("a commit that is not a full SHA, a missing path or an unclean recorder is refused before anything runs", async () => {
  const s = setup();
  for (const commit of [undefined, "", "abc123", "B".repeat(40), `${COMMIT}0`])
    await assert.rejects(rehearse(input(s, { fireemuCommit: commit })), /full commit SHA/);
  for (const name of ["fireemuBinary", "recorderDir", "rulesFile", "fixtureDir"])
    await assert.rejects(
      rehearse(input(s, { [name]: join(s.root, "absent") })),
      new RegExp(`${name} does not exist`),
    );
  await assert.rejects(
    rehearse(input(s, { fireemuBinary: undefined })),
    /fireemuBinary does not exist/,
  );
  const dirty = setup({ clean: false });
  await assert.rejects(rehearse(input(dirty)), /not clean/);
  assert.equal(existsSync(join(dirty.out, "receipt.json")), false);
});

test("a rehearsal that reports no journal is refused, with the exit code", async () => {
  const s = setup({ script: "#!/bin/sh\necho nothing useful\nexit 3\n" });
  await assert.rejects(
    rehearse(input(s)),
    /did not report its journal \(exit 3\); stderr tail: ""/,
  );
  assert.equal(existsSync(join(s.out, "receipt.json")), false);
});

test("what the rehearsal wrote to stderr is in the error, truncated to its tail", async () => {
  const s = setup({
    script: `#!/bin/sh\necho "$(printf 'x%.0s' $(seq 1 400))END" >&2\nexit 4\n`,
  });
  await assert.rejects(rehearse(input(s)), (error) => {
    assert.match(error.message, /\(exit 4\); stderr tail: "x+END\\n"$/);
    assert.ok(error.message.length < 400);
    return true;
  });
});

test("a rehearsal that runs too long is stopped", async () => {
  const s = setup({ script: "#!/bin/sh\nsleep 30\n" });
  await assert.rejects(rehearse(input(s, { timeoutMs: 300 })), /timed out/);
});

test("a binary that cannot be run is an error", async () => {
  const s = setup();
  writeFileSync(s.binary, "not executable");
  chmodSync(s.binary, 0o644);
  // The spawn error is reported at once, not after the timeout.
  await assert.rejects(rehearse(input(s, { timeoutMs: 60_000 })), (error) => {
    assert.match(error.message, /EACCES|ENOENT|spawn/);
    assert.doesNotMatch(error.message, /timed out/);
    return true;
  });
});

test("the sandbox is on by default on macOS only, and the out directory's missing parents are created", async () => {
  const s = setup();
  const { sandbox: _ignored, ...rest } = input(s);
  const nested = join(s.root, "x", "y", "out");
  await rehearse({ ...rest, outDir: nested });
  assert.equal(existsSync(join(nested, "loopback.sb")), process.platform === "darwin");
});

// The ready barrier controls only the timeout under test; cleanup timers remain real.
async function readyTimeoutFixture(t, s, check, setupMs = 5000, observations = {}) {
  const cp = (await import("node:child_process")).default;
  const { syncBuiltinESMExports } = await import("node:module");
  const actualSpawn = cp.spawn,
    actualSpawnSync = cp.spawnSync,
    schedule = globalThis.setTimeout;
  let owned,
    completed = false,
    mainTimer,
    mainCallback,
    intercepted = 0,
    released = 0;
  const identities = new Map();
  const identity = (pid) => {
    const result = actualSpawnSync("ps", ["-ww", "-p", String(pid), "-o", "lstart=,comm=,args="], {
      encoding: "utf8",
      timeout: 1000,
      env: { ...process.env, LANG: "C", LC_ALL: "C", TZ: "UTC" },
    });
    if (result.status === 1 && result.stdout.trim() === "") return null;
    if (result.error || result.status !== 0) throw Error("fixture identity inspection failed");
    return result.stdout.trim();
  };
  let resolveReady, rejectReady, resolveClose;
  const closed = new Promise((resolve) => {
    resolveClose = resolve;
  });
  const ready = new Promise((resolve, reject) => {
    resolveReady = resolve;
    rejectReady = reject;
  });
  t.mock.method(cp, "spawn", (...args) => {
    owned = actualSpawn(...args);
    owned.once("spawn", () => identities.set(owned.pid, identity(owned.pid)));
    owned.once("close", () => {
      completed = true;
      resolveClose();
    });
    let output = "";
    owned.stdout.on("data", (chunk) => {
      output += chunk;
      const lines = output.split("\n");
      output = lines.pop();
      for (const line of lines) {
        const row = JSON.parse(line);
        if (row.started) {
          identities.set(row.childPid, identity(row.childPid));
          observations.childPid = row.childPid;
          if (observations.expireOnChildStarted) rejectReady(Error("fixture ready deadline"));
        }
        if (row.reaped) observations.childReaped = true;
        if (row.ready) resolveReady(row);
      }
    });
    return owned;
  });
  t.mock.method(globalThis, "setTimeout", (callback, delay, ...args) => {
    if (delay !== 4321) return schedule(callback, delay, ...args);
    intercepted++;
    mainCallback = callback;
    mainTimer = schedule(() => {}, 60000);
    return mainTimer;
  });
  syncBuiltinESMExports();
  let pending, setupTimer;
  try {
    pending = rehearse(input(s, { timeoutMs: 4321 }));
    pending.catch(() => {});
    const receipt = await Promise.race([
      ready,
      new Promise((_, reject) => {
        setupTimer = schedule(() => reject(Error("fixture ready deadline")), setupMs);
      }),
    ]);
    clearTimeout(setupTimer);
    assert.equal(intercepted, 1);
    assert.ok(identities.get(owned.pid), "original leader identity captured before ready");
    if (receipt.childPid) assert.ok(identities.get(receipt.childPid));
    clearTimeout(mainTimer);
    released++;
    mainCallback();
    await assert.rejects(pending, (error) => check(error, receipt));
    assert.equal(released, 1);
    console.log(
      JSON.stringify({
        fixtureReadyBeforeTimeout: true,
        pid: owned.pid,
        childPid: receipt.childPid ?? null,
        intercepted,
        released,
      }),
    );
  } finally {
    clearTimeout(setupTimer);
    clearTimeout(mainTimer);
    t.mock.restoreAll();
    syncBuiltinESMExports();
    const awaitClose = async (milliseconds) => {
      if (completed) return true;
      let timer;
      try {
        return await Promise.race([
          closed.then(() => true),
          new Promise((resolve) => {
            timer = schedule(() => resolve(false), milliseconds);
          }),
        ]);
      } finally {
        clearTimeout(timer);
      }
    };
    const signalOriginal = (pid, signal) => {
      const current = identity(pid);
      if (current === null) return false;
      assert.ok(identities.get(pid), "fixture cleanup unresolved: original identity unavailable");
      assert.equal(
        current,
        identities.get(pid),
        "fixture cleanup unresolved: original identity changed",
      );
      process.kill(pid, signal);
      return true;
    };
    if (owned && !completed) {
      // The supervisor owns its child even when final readiness was never published.
      const sent = signalOriginal(owned.pid, "SIGTERM");
      if (sent && released === 0) observations.setupAbortRequested = true;
      if (!(await awaitClose(1500))) {
        // Force only individually verified original children while their parent can still reap.
        for (const pid of identities.keys()) {
          if (pid === owned.pid) continue;
          signalOriginal(pid, "SIGKILL");
          const deadline = Date.now() + 2000;
          while (identity(pid) !== null && Date.now() < deadline)
            await new Promise((resolve) => schedule(resolve, 20));
          assert.equal(
            identity(pid),
            null,
            "fixture cleanup unresolved: original child not reaped",
          );
        }
        signalOriginal(owned.pid, "SIGKILL");
        assert.equal(
          await awaitClose(2000),
          true,
          "fixture cleanup unresolved: supervisor not closed",
        );
      }
    }
    for (const pid of identities.keys())
      assert.equal(identity(pid), null, "fixture cleanup unresolved: original process remains");
    observations.pid = owned?.pid;
    observations.cleanupConfirmed = true;
    console.log(JSON.stringify({ fixtureCleanup: observations, supervisorPid: owned?.pid }));
  }
}

function supervisorScript(withholdReady = false) {
  const childCode = "setInterval(()=>{},1000);process.stdout.write('ready');";
  return `#!${process.execPath}
const {spawn}=require('node:child_process');
const hold=setInterval(()=>{},1000);
let child, childClosed=false, abortTimer;
const emit=row=>process.stdout.write(JSON.stringify(row)+'\\n');
process.on('SIGTERM',()=>{
  if(childClosed){clearInterval(hold);return;}
  if(child&&child.exitCode===null&&child.signalCode===null){
    child.kill('SIGTERM');
    abortTimer=setTimeout(()=>{if(!childClosed)child.kill('SIGKILL');},500);
  }
});
child=spawn(process.execPath,['--eval',${JSON.stringify(childCode)}],{stdio:['ignore','pipe','ignore']});
child.once('spawn',()=>emit({started:true,childPid:child.pid}));
child.once('close',()=>{childClosed=true;clearTimeout(abortTimer);emit({reaped:true,childPid:child.pid});setTimeout(()=>clearInterval(hold),200);});
child.stdout.once('data',()=>{if(!${withholdReady})emit({ready:true,childPid:child.pid});});
`;
}

test("a timed-out rehearsal takes its whole process group with it", async (t) => {
  const s = setup({ script: supervisorScript() });
  await readyTimeoutFixture(t, s, (error, receipt) => {
    assert.match(error.message, /timed out/);
    assert.equal(error.cleanup?.confirmed, true, JSON.stringify(error.cleanup));
    assert.throws(() => process.kill(error.cleanup.pid, 0), { code: "ESRCH" });
    assert.throws(() => process.kill(receipt.childPid, 0), { code: "ESRCH" });
    return true;
  });
});

test("a TERM-resistant rehearsal is reaped before timeout rejection", async (t) => {
  const s = setup({
    script: `#!${process.execPath}
process.on('SIGTERM',()=>{});
setInterval(()=>{},1000);
process.stdout.write(JSON.stringify({ready:true})+'\\n');
`,
  });
  await readyTimeoutFixture(t, s, (error) => {
    assert.equal(error.cleanup?.confirmed, true, JSON.stringify(error.cleanup));
    assert.equal(error.cleanup?.escalated, true);
    assert.throws(() => process.kill(error.cleanup.pid, 0), { code: "ESRCH" });
    return true;
  });
});

test("missing fixture readiness is bounded and cleans the original owned process", async (t) => {
  const s = setup({ script: `#!${process.execPath}\nsetInterval(()=>{},1000);\n` });
  await assert.rejects(
    readyTimeoutFixture(
      t,
      s,
      () => {
        throw Error("timeout must not start");
      },
      200,
    ),
    /fixture ready deadline/,
  );
});

test("setup expiry after child-started aborts and reaps before supervisor termination", async (t) => {
  const s = setup({ script: supervisorScript(true) });
  const observed = { expireOnChildStarted: true };
  await assert.rejects(
    readyTimeoutFixture(
      t,
      s,
      () => {
        throw Error("timeout must not start");
      },
      5000,
      observed,
    ),
    /fixture ready deadline/,
  );
  assert.ok(observed.childPid > 1, "original child must have started before setup expiry");
  assert.equal(
    observed.setupAbortRequested,
    true,
    "setup cleanup must request safe supervisor abort before forcekill",
  );
  assert.equal(observed.childReaped, true, "supervisor must acknowledge original child reaping");
  assert.throws(() => process.kill(observed.childPid, 0), { code: "ESRCH" });
  assert.throws(() => process.kill(observed.pid, 0), { code: "ESRCH" });
});

for (const exited of [true, false])
  test(`a ${exited ? "reaped" : "replacement"} leader cannot adopt a reused group`, async (t) => {
    const childProcess = await import("node:child_process");
    const { syncBuiltinESMExports } = await import("node:module");
    const { EventEmitter } = await import("node:events");
    const { PassThrough } = await import("node:stream");
    const s = setup();
    const actualSpawnSync = childProcess.default.spawnSync;
    const child = new EventEmitter();
    Object.assign(child, {
      pid: 43210,
      exitCode: null,
      signalCode: null,
      stdout: new PassThrough(),
      stderr: new PassThrough(),
      unref() {},
    });
    let originalExited = false;
    const signals = [];
    t.mock.method(childProcess.default, "spawn", () => {
      queueMicrotask(() => {
        child.emit("spawn");
        originalExited = true;
        if (exited) {
          child.exitCode = 0;
          child.emit("exit", 0, null);
        }
      });
      return child;
    });
    t.mock.method(childProcess.default, "spawnSync", (command, ...args) =>
      command === "ps"
        ? {
            status: 0,
            stdout: `43210 43210 ${originalExited ? "foreign birth foreign-command" : "original birth owned-command"}\n`,
          }
        : actualSpawnSync(command, ...args),
    );
    t.mock.method(process, "kill", (...args) => {
      signals.push(args);
      return true;
    });
    syncBuiltinESMExports();
    try {
      await assert.rejects(rehearse(input(s, { timeoutMs: 20 })), (error) => {
        assert.equal(error.cleanup?.confirmed, false);
        assert.equal(signals.length, 0, "reused foreign group must never receive a signal");
        return true;
      });
    } finally {
      t.mock.restoreAll();
      syncBuiltinESMExports();
      child.stdout.destroy();
      child.stderr.destroy();
    }
  });

test("failed ownership inspection reports unresolved cleanup without signalling", async (t) => {
  const childProcess = await import("node:child_process");
  const { syncBuiltinESMExports } = await import("node:module");
  const { once } = await import("node:events");
  const actualSpawn = childProcess.default.spawn;
  const actualSpawnSync = childProcess.default.spawnSync;
  const s = setup({ script: `#!${process.execPath}\nsetInterval(() => {}, 1000);\n` });
  let owned;
  t.mock.method(childProcess.default, "spawn", (...args) => {
    owned = actualSpawn(...args);
    return owned;
  });
  t.mock.method(childProcess.default, "spawnSync", (command, ...args) =>
    command === "ps" ? { status: 1, stdout: "" } : actualSpawnSync(command, ...args),
  );
  syncBuiltinESMExports();
  try {
    await assert.rejects(rehearse(input(s, { timeoutMs: 600 })), (error) => {
      assert.equal(error.cleanup?.confirmed, false);
      assert.match(error.cleanup?.error, /ownership inspection failed/);
      assert.equal(owned.exitCode, null);
      process.kill(owned.pid, 0);
      return true;
    });
  } finally {
    t.mock.restoreAll();
    syncBuiltinESMExports();
    if (owned && owned.exitCode === null && owned.signalCode === null) {
      const identity = actualSpawnSync("ps", ["-ww", "-p", String(owned.pid), "-o", "args="], {
        encoding: "utf8",
      });
      assert.equal(identity.status, 0);
      assert.ok(
        identity.stdout.includes(s.binary),
        "cleanup requires the exact owned fixture argv",
      );
      const closed = once(owned, "close");
      owned.kill("SIGKILL");
      await Promise.race([
        closed,
        new Promise((_, reject) => {
          const timer = setTimeout(() => reject(Error("owned fixture cleanup deadline")), 2000);
          timer.unref();
        }),
      ]);
      assert.throws(() => process.kill(owned.pid, 0), { code: "ESRCH" });
    }
  }
});

test("a recorder directory that is not a git checkout is refused, never taken as clean", async () => {
  const s = setup();
  const plain = join(s.root, "plain");
  mkdirSync(plain);
  await assert.rejects(
    rehearse(input(s, { recorderDir: plain })),
    /git rev-parse failed .*not a usable git checkout/,
  );
  assert.equal(existsSync(join(s.out, "receipt.json")), false);
  // A repository with no commit has no HEAD.
  const empty = join(s.root, "empty");
  mkdirSync(empty);
  git(empty, "init", "-q");
  await assert.rejects(rehearse(input(s, { recorderDir: empty })), /git rev-parse failed/);
});

test("git failing on the status of a checkout is an error too", async () => {
  const s = setup();
  // A checkout whose index is corrupt: rev-parse works, status does not.
  writeFileSync(join(s.recorder, ".git", "index"), "corrupt");
  await assert.rejects(rehearse(input(s)), /git status failed/);
});

test("the rehearsal leaves no timer behind, after a finished run or a failed spawn", async () => {
  const timers = () => process.getActiveResourcesInfo().filter((name) => name === "Timeout").length;
  const before = timers();
  const s = setup();
  await rehearse(input(s, { timeoutMs: 600_000 }));
  assert.equal(timers(), before);
  writeFileSync(s.binary, "not executable");
  chmodSync(s.binary, 0o644);
  await assert.rejects(rehearse(input(s, { timeoutMs: 600_000 })));
  assert.equal(timers(), before);
});

test("the rehearse command prints the receipt it wrote", async () => {
  const s = setup();
  const lines = [];
  const receipt = await rehearseCommand(
    {
      fireemu: s.binary,
      "fireemu-commit": COMMIT,
      recorder: s.recorder,
      rules: s.rules,
      fixture: s.fixture,
      out: s.out,
    },
    (line) => lines.push(line),
  );
  assert.equal(lines.length, 1);
  assert.equal(lines[0], JSON.stringify(receipt, null, 2));
  assert.match(lines[0], /\n {2}"/);
});
