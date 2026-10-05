// The slow-handler scenario helpers: the patch that makes the recorded fixture's 100 s handler last 100 logical
// seconds (read from the clock file the local child keeps), and the shape of the run.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { INFLIGHT_RUN, SLEEP, logicalSlowHandler } from "./inflight.mjs";

const fixtureSource = readFileSync(
  fileURLToPath(new URL("../fixture/index.js", import.meta.url)),
  "utf8",
);

test("the recorded fixture holds the sleep the patch replaces, exactly once", () => {
  assert.equal(fixtureSource.split(SLEEP).length - 1, 1);
});

test("the patched handler lasts 100 logical seconds of the clock file, not real time, and leaves nothing running", async () => {
  const dir = mkdtempSync(join(tmpdir(), "inflight-test-"));
  let child;
  try {
    const clockFile = join(dir, "clock.txt");
    writeFileSync(clockFile, "1000");
    const patched = logicalSlowHandler(`before\n  ${SLEEP}\nafter`, { clockFile });
    assert.ok(patched.startsWith("before\n  "));
    assert.ok(patched.endsWith("\nafter"));
    assert.ok(!patched.includes("100_000"));
    // the patched statement, run on its own in a process of its own: a timer it left running would keep that process
    // alive, and a handler that never ends would never print
    const statement = patched.slice("before\n  ".length, -"\nafter".length);
    child = spawn(
      process.execPath,
      ["-e", `(async () => { ${statement} console.log("ENDED"); })();`],
      {
        stdio: ["ignore", "pipe", "inherit"],
      },
    );
    let output = "";
    child.stdout.on("data", (d) => (output += d));
    const exited = new Promise((resolve) => child.on("exit", resolve));
    const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    await sleep(300);
    assert.equal(output, "", "no logical time has passed");
    writeFileSync(clockFile, "1099");
    await sleep(300);
    assert.equal(output, "", "99 s is not 100 s");
    writeFileSync(clockFile, "1100");
    const code = await Promise.race([
      exited,
      sleep(4000).then(() => "the handler never ended or left a timer running"),
    ]);
    assert.equal(code, 0, String(code));
    assert.equal(output.trim(), "ENDED");
  } finally {
    child?.kill("SIGKILL");
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a source without the sleep, or a context without a clock file, is an error and not a silent no-op", () => {
  assert.throws(() => logicalSlowHandler("nothing to replace", { clockFile: "/x" }), /sleep/);
  assert.throws(() => logicalSlowHandler(`a ${SLEEP}`, {}), /clock file/);
});

test("the run is 700 seconds with a manual run of the slow job after 200 and no waiting for idle", () => {
  assert.deepEqual(INFLIGHT_RUN, {
    seconds: 700,
    awaitIdle: false,
    pauseMs: 60,
    clockFile: true,
    manualAt: [{ name: "schedSlowV2", afterSeconds: 200 }],
  });
});
