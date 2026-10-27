// Runs the CV14 fixture (the eight handlers) and the nine writes of the production recording against a local
// fireemu, and keeps the frames the handlers print. The frames are then compared with the production
// recording by compare-local.mjs. No credentials, no production request: the database is the local one.
// Usage: node local-run.mjs --fireemu <binary> --profile strict|emulator --out <new directory>

import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

import { FRAME_MARKER, INSTANCE } from "./frames.mjs";
import { MASKED_NONCE } from "./mask-recording.mjs";
import { buildSteps } from "./sequence.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const QUIET_MS = 2500;
const READY_MS = 120_000;

const freePort = () =>
  new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });

/** The frames in a stretch of daemon output (one `CV14_FRAME {json}` line each). */
export function parseFrames(text) {
  const frames = [];
  for (const line of text.split("\n")) {
    const at = line.indexOf(FRAME_MARKER);
    if (at < 0) continue;
    try {
      frames.push(JSON.parse(line.slice(at + FRAME_MARKER.length)));
    } catch {
      // a line cut in the middle is not a frame
    }
  }
  return frames;
}

async function write(db, step, stepNumber) {
  const headers = step.context === "admin" ? { authorization: "Bearer owner" } : {};
  const url = `${db}/${step.path}.json?ns=${INSTANCE}`;
  const init = { method: step.method, headers: { ...headers, "content-type": "application/json" } };
  if (step.body !== undefined) init.body = JSON.stringify(step.body);
  const response = await fetch(url, init);
  await response.text();
  return { step: step.id, n: stepNumber, status: response.status };
}

export async function runLocal({ fireemu, profile, out }) {
  if (!["strict", "emulator"].includes(profile)) throw new Error("--profile is strict or emulator");
  mkdirSync(out);
  const ports = {};
  for (const name of ["database", "http", "functions", "eventarc", "tasks"])
    ports[name] = await freePort();
  const config = path.join(out, "config.json");
  const ready = path.join(out, "ready.json");
  writeFileSync(
    config,
    `${JSON.stringify({
      schemaVersion: 1,
      profile,
      daemon: {
        authProject: "demo-cv14",
        databasePort: ports.database,
        httpPort: ports.http,
        functionsPort: ports.functions,
        hubPort: 0,
        uiPort: 0,
        loggingPort: 0,
      },
    })}\n`,
  );
  let output = "";
  const child = spawn(
    fireemu,
    [
      "up",
      "--no-config-discovery",
      "--config",
      config,
      "--firebase-json",
      path.join(here, "firebase.json"),
      "--only",
      "database,functions",
      "--database-port",
      String(ports.database),
      "--http-port",
      String(ports.http),
      "--functions-port",
      String(ports.functions),
      "--eventarc-port",
      String(ports.eventarc),
      "--tasks-port",
      String(ports.tasks),
      "--hub-port",
      "0",
      "--ui-port",
      "0",
      "--logging-port",
      "0",
      "--log-verbosity",
      "info",
      "--ready-file",
      ready,
      "--owner-stdin",
    ],
    {
      stdio: ["pipe", "pipe", "pipe"],
      detached: true,
      env: { ...process.env, GOOGLE_APPLICATION_CREDENTIALS: "" },
    },
  );
  for (const stream of [child.stdout, child.stderr])
    stream.on("data", (chunk) => (output += chunk));
  const stop = async () => {
    try {
      process.kill(-child.pid, "SIGTERM");
    } catch {
      // already gone
    }
    await delay(800);
    try {
      process.kill(-child.pid, "SIGKILL");
    } catch {
      // gone
    }
  };
  try {
    const deadline = Date.now() + READY_MS;
    while (!(existsSync(ready) && readFileSync(ready, "utf8").length > 0)) {
      if (Date.now() > deadline) throw new Error("fireemu was not ready in time");
      if (child.exitCode !== null)
        throw new Error(`fireemu exited ${child.exitCode} before it was ready`);
      await delay(250);
    }
    await delay(3000); // the Functions runner announces its triggers after the listeners are up
    const db = `http://127.0.0.1:${ports.database}`;
    const steps = buildSteps(MASKED_NONCE);
    const writes = [];
    for (const [index, step] of steps.entries()) {
      writes.push(await write(db, step, index + 1));
      let seen = parseFrames(output).length;
      let quietSince = Date.now();
      while (Date.now() - quietSince < QUIET_MS) {
        await delay(200);
        const now = parseFrames(output).length;
        if (now !== seen) {
          seen = now;
          quietSince = Date.now();
        }
      }
    }
    const frames = parseFrames(output);
    writeFileSync(path.join(out, "output.log"), output);
    writeFileSync(
      path.join(out, "frames.jsonl"),
      frames.map((f) => JSON.stringify(f)).join("\n") + "\n",
    );
    writeFileSync(path.join(out, "writes.json"), `${JSON.stringify(writes, null, 2)}\n`);
    return { frames, writes, profile };
  } finally {
    await stop();
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const argv = process.argv.slice(2);
  const opt = (name) => argv[argv.indexOf(name) + 1];
  const result = await runLocal({
    fireemu: opt("--fireemu") ?? "fireemu",
    profile: opt("--profile") ?? "strict",
    out: opt("--out"),
  });
  console.log(
    JSON.stringify({
      profile: result.profile,
      frames: result.frames.length,
      writes: result.writes,
    }),
  );
}
