import assert from "node:assert/strict";
import { test } from "node:test";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { controlPreamble, controlFixture, CONTROL_VARIANTS } from "./calendar-controls.mjs";

const helperPath = fileURLToPath(new URL("./calendar-control-helper.py", import.meta.url));

async function scratch(t) {
  const directory = await mkdtemp(join(tmpdir(), "calendar-controls-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

const output = (file, args) =>
  new Promise((resolve, reject) => {
    const child = spawn(file, args, { stdio: ["ignore", "pipe", "ignore"] });
    let text = "";
    child.stdout.on("data", (chunk) => (text += chunk));
    child.once("error", reject);
    child.once("close", () => resolve(text.trim()));
  });
const sessionOf = async (pid) =>
  Number(await output("python3", ["-c", `import os; print(os.getsid(${pid}))`]));
const parentOf = async (pid) => Number(await output("ps", ["-o", "ppid=", "-p", String(pid)]));

// Runs a generated preamble the way discovery would (a short-lived parent), then reads what
// its helper reported. The helper is stopped by its own recorded PID after the checks.
async function runPreamble(t, directory, options) {
  const preamblePath = join(directory, "controls.cjs");
  await writeFile(preamblePath, controlPreamble({ helperPath, hold: 5, ...options }));
  const started = Date.now();
  const parent = spawn(process.execPath, [preamblePath], { stdio: "ignore" });
  const code = await new Promise((resolve) => parent.once("exit", resolve));
  const info = JSON.parse(await readFile(options.readyPath, "utf8"));
  t.after(() => {
    try {
      process.kill(info.pid, "SIGKILL");
    } catch {
      /* Already ended by itself. */
    }
  });
  return { code, info, elapsedMs: Date.now() - started, parentPid: parent.pid };
}

test("the orphan control leaves its group and its starter, and stays in the session", async (t) => {
  const directory = await scratch(t);
  const readyPath = join(directory, "ready.json");
  const { code, info, elapsedMs, parentPid } = await runPreamble(t, directory, {
    mode: "orphan",
    readyPath,
  });
  assert.equal(code, 0);
  assert.notEqual(info.pgid, info.pid, "in the group its middle process created, not its own");
  assert.notEqual(info.pgid, parentPid, "not in its starter's group");
  assert.equal(info.sid, await sessionOf(process.pid), "still in the session it was started in");
  assert.equal(await parentOf(info.pid), 1, "reparented to launchd once its middle process exited");
  assert.ok(elapsedMs >= 1000, "discovery blocks at least four polling intervals after ready (F2)");
});

test("the escaper control starts a session of its own first, and the leftover leaves its group", async (t) => {
  const directory = await scratch(t);
  const escaper = await runPreamble(t, directory, {
    mode: "escaper",
    readyPath: join(directory, "e.json"),
  });
  assert.equal(escaper.info.sid, escaper.info.pid, "setsid made it a session leader");
  const leftover = await runPreamble(t, directory, {
    mode: "leftover",
    readyPath: join(directory, "l.json"),
  });
  assert.equal(leftover.info.pgid, leftover.info.pid, "its own process group");
  assert.notEqual(leftover.info.sid, leftover.info.pid, "but still in its starter's session");
});

test("the listener control retries until the claimed port is free and records when it bound", async (t) => {
  const directory = await scratch(t);
  const holder = createServer();
  await new Promise((resolve) => holder.listen(0, "127.0.0.1", resolve));
  const { port } = holder.address();
  const portFile = join(directory, "port.json"),
    boundPath = join(directory, "bound.json");
  await writeFile(portFile, JSON.stringify({ port }));
  // The port is still held when the helper starts (as the daemon may still hold it).
  setTimeout(() => holder.close(), 300);
  const { info } = await runPreamble(t, directory, {
    mode: "listener",
    readyPath: join(directory, "r.json"),
    portFile,
    boundPath,
  });
  assert.equal(info.sid, info.pid);
  let bound;
  for (let i = 0; i < 50 && !bound; i++) {
    try {
      bound = JSON.parse(await readFile(boundPath, "utf8"));
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  assert.equal(bound?.port, port);
});

test("control fixtures prefix the refusal fixture and never change it; each control has its variant", () => {
  const input = { schedule: "every 5 minutes", timeZone: "Invalid/CalendarZone" };
  const { index, controls } = controlFixture(input, {
    mode: "orphan",
    helperPath,
    readyPath: "/r",
    hold: 60,
  });
  assert.ok(index.startsWith('require("./controls.cjs");\n'));
  assert.ok(controls.includes(JSON.stringify(helperPath)));
  assert.deepEqual(CONTROL_VARIANTS, {
    orphan: { fixture: "refusal", escalation: "off", rule: "session" },
    escaper: { fixture: "valid", escalation: "off", rule: "identity" },
    listener: { fixture: "refusal", escalation: "off", rule: "port" },
    leftover: { fixture: "valid", escalation: "on", rule: "harness-signal" },
  });
  assert.throws(() =>
    controlFixture(input, { mode: "other", helperPath, readyPath: "/r", hold: 60 }),
  );
});
