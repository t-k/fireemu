// Real POSIX processes and inherited pipes, not child_process mocks.
import assert from "node:assert/strict";
import { test } from "node:test";
import { promises as fs } from "node:fs";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { setTimeout as sleep } from "node:timers/promises";
import { runProcess, cleanEnvironment } from "../io.mjs";
import { resultEnvelope, gateExitCode } from "../core.mjs";

const limits = { timeout: 12000 };
const run = (source, options = {}) =>
  runProcess(process.execPath, ["-e", source], {
    env: cleanEnvironment(tmpdir()),
    timeoutMs: 3000,
    ...options,
  });
function signal(pid, sig = "SIGKILL") {
  try {
    process.kill(pid, sig);
  } catch (error) {
    if (error.code !== "ESRCH") throw error;
  }
}
function alive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error.code === "ESRCH") return false;
    throw error;
  }
}
async function area(t) {
  const root = await fs.mkdtemp(join(tmpdir(), "pilot-process-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  return root;
}
async function readPid(path) {
  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    const pid = Number(await fs.readFile(path, "utf8").catch(() => 0));
    if (Number.isInteger(pid) && pid > 1) return pid;
    await sleep(10);
  }
  throw new Error("fixture-pid-not-ready");
}
async function holder(t, { detached = true, stream = "stdout", timeoutMs = 150 } = {}) {
  const root = await area(t);
  const pidFile = join(root, "holder.pid");
  const holderCode = `
    require('node:fs').writeFileSync(${JSON.stringify(pidFile)}, String(process.pid));
    setTimeout(()=>process.exit(0),9000);
  `;
  const stdio = ["ignore", stream === "stdout" ? 1 : "ignore", stream === "stderr" ? 2 : "ignore"];
  const leaderCode = `
    const fs=require('node:fs');
    const c=require('node:child_process').spawn(process.execPath,['-e',${JSON.stringify(holderCode)}],
      {detached:${detached},stdio:${JSON.stringify(stdio)}});
    c.unref();
    const timer=setInterval(()=>{if(fs.existsSync(${JSON.stringify(pidFile)}))process.exit(0);},5);
    setTimeout(()=>process.exit(2),3000).unref();
  `;
  let ownedPid = null;
  t.after(() => {
    if (ownedPid) signal(ownedPid);
  });
  const before = performance.now();
  const running = run(leaderCode, { timeoutMs });
  ownedPid = await readPid(pidFile);
  const result = await running;
  return { result, elapsed: performance.now() - before, pid: ownedPid };
}
function gate(result) {
  return resultEnvelope({
    entry: {
      id: "supervisor-control",
      parent: "FS-DATA-WRITE",
      profile: "strict",
      transport: "none",
      evidenceKind: "synthetic-control",
      oracleKind: "synthetic",
      compared: [],
      notEstablished: ["production compatibility"],
    },
    comparison: { verdict: "MATCH", counts: { match: 1, mismatch: 0, indeterminate: 0 } },
    execution: {
      state: result.code === 0 && !result.reason ? "completed" : "failed",
      cleanup: { state: "confirmed" },
      process: { state: result.state },
    },
    provenance: { synthetic: true },
  });
}

test(
  "ordinary completion drains stdout and stderr and removes signal handlers",
  limits,
  async () => {
    const before = [process.listenerCount("SIGINT"), process.listenerCount("SIGTERM")];
    const r = await run(`process.stdout.write('out');process.stderr.write('err');`);
    assert.equal(r.code, 0);
    assert.equal(r.reason, null);
    assert.equal(r.signal, null);
    assert.equal(r.state, "stopped");
    assert.ok(r.log.includes("out"));
    assert.ok(r.log.includes("err"));
    assert.deepEqual([process.listenerCount("SIGINT"), process.listenerCount("SIGTERM")], before);
  },
);
test("a nonzero exit is preserved and never passes the gate", limits, async () => {
  const r = await run("process.exit(23)");
  assert.equal(r.code, 23);
  assert.equal(r.signal, null);
  assert.equal(r.state, "stopped");
  assert.equal(gate(r).gatePassed, false);
});
test("self termination reports the real signal and is not a clean zero exit", limits, async () => {
  const r = await run("process.kill(process.pid,'SIGTERM')");
  assert.equal(r.code, null);
  assert.equal(r.signal, "SIGTERM");
  assert.equal(r.state, "stopped");
  assert.equal(gate(r).gatePassed, false);
});
for (const bad of [0, -1, NaN, Infinity, -Infinity, true, "200", 1.5, 2147483648, null]) {
  test(`refuse invalid timeout before spawn: ${String(bad)} (${typeof bad})`, limits, async (t) => {
    const root = await area(t);
    const marker = join(root, "spawned");
    await assert.rejects(
      run(`require('node:fs').writeFileSync(${JSON.stringify(marker)},'bad')`, { timeoutMs: bad }),
      /invalid-process-timeout/,
    );
    await assert.rejects(fs.stat(marker), { code: "ENOENT" });
  });
}
for (const bad of [-1, NaN, Infinity, "200", true, 1.5, null]) {
  test(`refuse invalid log cap before spawn: ${String(bad)} (${typeof bad})`, limits, async (t) => {
    const root = await area(t);
    const marker = join(root, "spawned");
    await assert.rejects(
      run(`require('node:fs').writeFileSync(${JSON.stringify(marker)},'bad')`, {
        maxLogBytes: bad,
      }),
      /invalid-process-log-limit/,
    );
    await assert.rejects(fs.stat(marker), { code: "ENOENT" });
  });
}
test("the largest supported timer delay does not get clamped to 1ms", limits, async () => {
  const r = await run("console.log('ok')", { timeoutMs: 2147483647 });
  assert.equal(r.code, 0);
  assert.equal(r.reason, null);
});
test("exactly the log limit succeeds, preserving the full captured content", limits, async () => {
  const r = await run("process.stdout.write('12345678')", { maxLogBytes: 8 });
  assert.equal(r.reason, null);
  assert.equal(r.log.toString(), "12345678");
});
test(
  "one byte over the log limit fails and preserves only the bounded prefix",
  limits,
  async () => {
    const r = await run("process.stdout.write('123456789');setInterval(()=>{},1000)", {
      maxLogBytes: 8,
    });
    assert.equal(r.reason, "process-log-limit");
    assert.equal(r.log.toString(), "12345678");
    assert.equal(gate(r).gatePassed, false);
  },
);
test("a zero byte cap accepts silence but rejects any output", limits, async () => {
  const silent = await run("process.exit(0)", { maxLogBytes: 0 });
  assert.equal(silent.reason, null);
  assert.equal(silent.log.length, 0);
  const loud = await run("console.log('x');setInterval(()=>{},1000)", { maxLogBytes: 0 });
  assert.equal(loud.reason, "process-log-limit");
  assert.equal(loud.log.length, 0);
});
test("stdout and stderr share one aggregate byte limit", limits, async () => {
  const r = await run(
    "process.stdout.write('abcd');process.stderr.write('efghi');setInterval(()=>{},1000)",
    { maxLogBytes: 8 },
  );
  assert.equal(r.reason, "process-log-limit");
  assert.equal(r.log.length, 8);
});
test(
  "missing executable settles immediately without leaking its path in the reason",
  limits,
  async (t) => {
    const root = await area(t);
    const before = performance.now();
    const r = await runProcess(join(root, "secret-missing-path"), [], {
      env: cleanEnvironment(root),
      timeoutMs: 9000,
    });
    assert.ok(performance.now() - before < 2000);
    assert.equal(r.reason, "spawn-failed");
    assert.equal(r.code, null);
    assert.equal(r.pid, null);
    assert.equal(r.state, "stopped");
    assert.equal(r.log.length, 0);
  },
);
test("missing working directory has the same bounded spawn-failure result", limits, async (t) => {
  const root = await area(t);
  const r = await run("process.exit(0)", { cwd: join(root, "missing") });
  assert.equal(r.reason, "spawn-failed");
  assert.equal(r.state, "stopped");
});
test("a timeout reaps an ordinary child and clears signal listeners", limits, async () => {
  const before = [process.listenerCount("SIGINT"), process.listenerCount("SIGTERM")];
  const r = await run("setInterval(()=>{},1000)", { timeoutMs: 150 });
  assert.equal(r.reason, "process-timeout");
  assert.equal(r.state, "stopped");
  assert.equal(alive(r.pid), false);
  assert.deepEqual([process.listenerCount("SIGINT"), process.listenerCount("SIGTERM")], before);
});
test(
  "TERM grace lets a cooperative child finish while retaining the timeout failure",
  limits,
  async () => {
    const r = await run(
      `process.on('SIGTERM',()=>{console.log('term');process.exit(0)});
    console.log('ready');setInterval(()=>{},1000);`,
      { timeoutMs: 400 },
    );
    assert.ok(r.log.includes("ready"));
    assert.ok(r.log.includes("term"));
    assert.equal(r.reason, "process-timeout");
    assert.equal(r.code, 0);
    assert.equal(r.state, "stopped");
    assert.equal(gate(r).gatePassed, false);
  },
);
test("a TERM-resistant child is escalated to KILL and reaped", limits, async () => {
  const before = performance.now();
  const r = await run(
    "process.on('SIGTERM',()=>{});console.log('ready');setInterval(()=>{},1000)",
    { timeoutMs: 400 },
  );
  assert.ok(r.log.includes("ready"));
  assert.equal(r.reason, "process-timeout");
  assert.equal(r.signal, "SIGKILL");
  assert.equal(r.state, "stopped");
  assert.equal(alive(r.pid), false);
  assert.ok(performance.now() - before >= 2200);
  assert.ok(performance.now() - before < 6000);
});
for (const stream of ["stdout", "stderr"]) {
  test(
    `detached ${stream} holder cannot hang timeout completion or become stopped`,
    limits,
    async (t) => {
      const before = [process.listenerCount("SIGINT"), process.listenerCount("SIGTERM")];
      const r = await holder(t, { stream });
      assert.ok(r.elapsed < 5500, `elapsed=${r.elapsed}`);
      assert.equal(r.result.reason, "process-timeout");
      assert.equal(r.result.code, 0);
      assert.equal(r.result.state, "unconfirmed");
      assert.ok(alive(r.pid), "the out-of-group holder was not killed by the supervisor");
      assert.equal(gate(r.result).comparison.verdict, "INDETERMINATE");
      assert.equal(gateExitCode(gate(r.result)), 2);
      assert.deepEqual([process.listenerCount("SIGINT"), process.listenerCount("SIGTERM")], before);
    },
  );
}
test(
  "leader exit with a held pipe starts a bounded drain without waiting for the run timeout",
  limits,
  async (t) => {
    const r = await holder(t, { timeoutMs: 10000 });
    assert.ok(r.elapsed < 5500, `elapsed=${r.elapsed}`);
    assert.equal(r.result.reason, "process-output-open");
    assert.equal(r.result.state, "unconfirmed");
    assert.ok(alive(r.pid));
  },
);
test(
  "same-group residue is stopped even when the leader's pipes are already closed",
  limits,
  async (t) => {
    const r = await holder(t, { detached: false, stream: "none", timeoutMs: 10000 });
    assert.ok(r.elapsed < 5500);
    assert.equal(r.result.reason, "remaining-process-group");
    assert.ok(["stopped", "unconfirmed"].includes(r.result.state));
    // Some container PID 1s retain reparented zombies. Never claim their group is gone.
    if (r.result.state === "stopped") assert.equal(alive(-r.result.pid), false);
    assert.equal(gate(r.result).gatePassed, false);
  },
);
for (const sig of ["SIGINT", "SIGTERM"]) {
  test(
    `external ${sig} cleans up the owned child and preserves interruption`,
    limits,
    async (t) => {
      const root = await area(t);
      const pidFile = join(root, "child.pid");
      const childCode = `require('node:fs').writeFileSync(${JSON.stringify(pidFile)},String(process.pid));setInterval(()=>{},1000);`;
      const output = join(root, "result.json");
      const script = `import {runProcess,cleanEnvironment} from ${JSON.stringify(new URL("../io.mjs", import.meta.url).href)};
      import fs from 'node:fs';
      const r=await runProcess(process.execPath,['-e',${JSON.stringify(childCode)}],{env:cleanEnvironment(${JSON.stringify(root)}),timeoutMs:9000});
      fs.writeFileSync(${JSON.stringify(output)},JSON.stringify({...r,log:r.log.toString()}));`;
      const p = spawn(process.execPath, ["--input-type=module", "-e", script], {
        env: cleanEnvironment(root),
        stdio: "ignore",
      });
      const closed = once(p, "close");
      let ownedPid = null;
      t.after(async () => {
        if (p.exitCode === null && p.signalCode === null) p.kill("SIGKILL");
        if (ownedPid) signal(ownedPid);
        await closed;
      });
      const pid = await readPid(pidFile);
      ownedPid = pid;
      p.kill(sig);
      const [code] = await closed;
      assert.equal(code, 0);
      const r = JSON.parse(await fs.readFile(output));
      assert.equal(r.reason, "interrupted");
      assert.equal(r.state, "stopped");
      assert.equal(alive(pid), false);
    },
  );
}
test(
  "multiple supervisors settle once and do not remove each other's handlers",
  limits,
  async () => {
    const before = [process.listenerCount("SIGINT"), process.listenerCount("SIGTERM")];
    const results = await Promise.all([
      run("console.log('a')"),
      run("console.log('b')"),
      run("setInterval(()=>{},1000)", { timeoutMs: 150 }),
    ]);
    assert.equal(results[0].reason, null);
    assert.equal(results[1].reason, null);
    assert.equal(results[2].reason, "process-timeout");
    assert.ok(results.every((r) => r.state === "stopped"));
    assert.deepEqual([process.listenerCount("SIGINT"), process.listenerCount("SIGTERM")], before);
  },
);
test(
  "captured result is stable and no late escalation hits a subsequent process",
  limits,
  async () => {
    const r = await run("console.log('first')");
    const log = Buffer.from(r.log);
    const second = await run("setTimeout(()=>{console.log('second')},2200)", { timeoutMs: 4000 });
    assert.equal(second.code, 0);
    assert.equal(second.reason, null);
    assert.deepEqual(r.log, log);
  },
);
test(
  "a killed first process's stop timers never signal a later, unrelated process",
  limits,
  async (t) => {
    const root = await area(t);
    const marker = join(root, "second-signalled");
    const first = await run(
      "process.on('SIGTERM',()=>{});console.log('ready');setInterval(()=>{},1000)",
      { timeoutMs: 400 },
    );
    assert.equal(first.reason, "process-timeout");
    assert.equal(first.signal, "SIGKILL");
    assert.equal(first.state, "stopped");
    // If the first call's killTimer/finalTimer ever escaped their closure and
    // outlived `finish()`, they would still hold the first child's own pid, but a
    // reused pid or a broadened kill target would show up as a signal here.
    const secondCode = `
      const fs = require('node:fs');
      for (const sig of ['SIGTERM', 'SIGUSR2']) {
        process.on(sig, () => { fs.writeFileSync(${JSON.stringify(marker)}, sig); process.exit(1); });
      }
      setTimeout(() => process.exit(0), 3200);
    `;
    const second = await run(secondCode, { timeoutMs: 9000 });
    assert.equal(second.code, 0);
    assert.equal(second.signal, null);
    assert.equal(second.reason, null);
    await assert.rejects(fs.stat(marker), { code: "ENOENT" });
  },
);

test(
  "ordinary multi-chunk output is fully drained before stopped is returned",
  limits,
  async () => {
    const size = 256 * 1024;
    const r = await run(`process.stdout.write(Buffer.alloc(${size},65),()=>process.exit(0))`, {
      maxLogBytes: size,
    });
    assert.equal(r.code, 0);
    assert.equal(r.reason, null);
    assert.equal(r.state, "stopped");
    assert.equal(r.log.length, size);
    assert.ok(r.log.every((b) => b === 65));
  },
);

test(
  "a standalone supervisor exits and saves unconfirmed while an escaped writer is still alive",
  limits,
  async (t) => {
    const root = await area(t);
    const pidFile = join(root, "holder.pid");
    const output = join(root, "result.json");
    const writerCode = `require('node:fs').writeFileSync(${JSON.stringify(pidFile)},String(process.pid));setTimeout(()=>process.exit(0),9000);`;
    const leaderCode = `const fs=require('node:fs');
    const c=require('node:child_process').spawn(process.execPath,['-e',${JSON.stringify(writerCode)}],{detached:true,stdio:['ignore',1,2]});
    c.unref();setInterval(()=>{if(fs.existsSync(${JSON.stringify(pidFile)}))process.exit(0)},5);`;
    const code = `import {runProcess,cleanEnvironment} from ${JSON.stringify(new URL("../io.mjs", import.meta.url).href)};
    import fs from 'node:fs';
    const r=await runProcess(process.execPath,['-e',${JSON.stringify(leaderCode)}],{env:cleanEnvironment(${JSON.stringify(root)}),timeoutMs:200});
    fs.writeFileSync(${JSON.stringify(output)},JSON.stringify({...r,log:r.log.toString()}));`;
    const before = performance.now();
    const p = spawn(process.execPath, ["--input-type=module", "-e", code], {
      env: cleanEnvironment(root),
      stdio: "ignore",
    });
    const closed = once(p, "close");
    let ownedPid = null;
    t.after(async () => {
      if (p.exitCode === null && p.signalCode === null) p.kill("SIGKILL");
      if (ownedPid) signal(ownedPid);
      await closed;
    });
    ownedPid = await readPid(pidFile);
    const [exitCode] = await closed;
    assert.equal(exitCode, 0);
    assert.ok(performance.now() - before < 5500);
    const result = JSON.parse(await fs.readFile(output));
    assert.equal(result.state, "unconfirmed");
    assert.equal(result.reason, "process-timeout");
    assert.ok(alive(ownedPid));
  },
);
