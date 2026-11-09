// Runs the kinds fixture and writes against a local fireemu: the same steps the recorder sends to
// production, REST for the admin and user-rest steps and the long-polling page for the SDK steps.
// Usage: node kinds-local-run.mjs --fireemu <binary> --profile strict|emulator --out <new directory> [--steps v2]
// (v2: only the user writes k15 to k21 of packet v2)

import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

import { FRAME_MARKER, INSTANCE, PREFIX } from "./kinds-frames.mjs";
import { MASKED_NONCE } from "./mask-recording.mjs";
import { browserRunner, openSdk } from "./breadth-sdk.mjs";
import { KINDS_CLAIMS, KINDS_SCENARIO, KINDS_V2_SCENARIO, rulesFor } from "./kinds-scenario.mjs";
import { observe } from "./kinds-sequence.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const QUIET_MS = 2500;
const READY_MS = 120_000;
/** After the last step: the onDisconnect pair runs when the idle long-polling connection is dropped (about 105 s). */
const FINAL_WAIT_MS = 200_000;

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

async function write(db, step, stepNumber, token) {
  const headers = step.context === "admin" ? { authorization: "Bearer owner" } : {};
  const url = `${db}/${step.path}.json?ns=${INSTANCE}${step.context === "user-rest" ? `&auth=${encodeURIComponent(token)}` : ""}`;
  const init = { method: step.method, headers: { ...headers, "content-type": "application/json" } };
  if (step.body !== undefined) init.body = JSON.stringify(step.body);
  const response = await fetch(url, init);
  await response.text();
  return { step: step.id, n: stepNumber, status: response.status };
}

/** The scenario whose steps a local run sends: all 21 of the first packet, or the user writes of packet v2. */
export const scenarioFor = (stepSet) => (stepSet === "v2" ? KINDS_V2_SCENARIO : KINDS_SCENARIO);

export async function runLocal({ fireemu, profile, out, steps: stepSet = "all" }) {
  const scenario = scenarioFor(stepSet);
  if (!["strict", "emulator"].includes(profile)) throw new Error("--profile is strict or emulator");
  mkdirSync(out);
  const ports = {};
  for (const name of ["auth", "database", "http", "functions", "eventarc", "tasks"])
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
  const firebaseJson = path.join(out, "firebase.json");
  writeFileSync(path.join(out, "rules.json"), JSON.stringify(rulesFor(PREFIX, MASKED_NONCE)));
  writeFileSync(
    firebaseJson,
    JSON.stringify({
      functions: { source: path.join(here, "fixtures-kinds"), codebase: "rtdb-kinds-oracle" },
      database: { rules: "rules.json" },
    }),
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
      firebaseJson,
      "--only",
      "auth,database,functions",
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
    const email = "kinds-local@example.test",
      password = "local-password";
    const authBase = `http://127.0.0.1:${ports.http}/identitytoolkit.googleapis.com/v1`;
    const post = async (url, body, headers = {}) => {
      const reply = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", ...headers },
        body: JSON.stringify(body),
      });
      if (!reply.ok) throw Error(`local ${url.split("/").at(-1)} failed: ${reply.status}`);
      return reply.json();
    };
    const { localId } = await post(`${authBase}/accounts:signUp?key=fake-api-key`, {
      email,
      password,
      returnSecureToken: true,
    });
    // the same order as the production run: custom claims on the owned user, then the token
    await post(
      `${authBase}/projects/demo-cv14/accounts:update`,
      { localId, customAttributes: JSON.stringify(KINDS_CLAIMS) },
      { authorization: "Bearer owner" },
    );
    const { idToken } = await post(`${authBase}/accounts:signInWithPassword?key=fake-api-key`, {
      email,
      password,
      returnSecureToken: true,
    });
    let sdkCounts = null;
    const runner = browserRunner({
      modules: path.resolve(here, "../../node_modules"),
      pageFile: KINDS_SCENARIO.sdk.pageFile,
      ids: KINDS_SCENARIO.sdk.ids,
      caps: { http: 400, ws: 4 },
      allowHost: (host) =>
        [ports.http, ports.database].some(
          (port) => host === `127.0.0.1:${port}` || host === `localhost:${port}`,
        ),
    });
    const sdk = openSdk(
      async (...args) => {
        const done = await runner(...args);
        sdkCounts = done.counts;
        return done;
      },
      {
        apiKey: "fake-api-key",
        projectId: "demo-cv14",
        // The SDK names the same instance the REST writes use, or its writes land elsewhere.
        databaseURL: `${db}/?ns=${INSTANCE}`,
        emulator: {
          auth: `http://127.0.0.1:${ports.http}`,
          host: "127.0.0.1",
          dbPort: ports.database,
        },
      },
      () => ({ email, password, uid: localId, nonce: MASKED_NONCE }),
    );
    try {
      const steps = scenario.buildSteps(MASKED_NONCE);
      const writes = [];
      for (const [index, step] of steps.entries()) {
        writes.push(
          step.context === "user-sdk"
            ? { step: step.id, n: index + 1, ...(await sdk.write(step.id)) }
            : await write(db, step, index + 1, idToken),
        );
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
      // The last step registers onDisconnect writes on a long-polling connection and goes offline: wait
      // until every delivery the model expects has arrived, or the window ends.
      const expected = (frames) => {
        const report = observe({ writes: {}, frames, steps });
        return report.steps.every(
          (step) =>
            step.observeOnly ||
            [...step.leaves, ...step.groups].every((entry) =>
              Object.values(entry.handlers).every((seen) => seen.expected === 0 || seen.frames > 0),
            ),
        );
      };
      for (let waited = 0; waited < FINAL_WAIT_MS && !expected(parseFrames(output)); waited += 1000)
        await delay(1000);
      await delay(QUIET_MS);
      const frames = parseFrames(output);
      writeFileSync(path.join(out, "output.log"), output);
      writeFileSync(
        path.join(out, "frames.jsonl"),
        frames.map((f) => JSON.stringify(f)).join("\n") + "\n",
      );
      writeFileSync(path.join(out, "writes.json"), `${JSON.stringify(writes, null, 2)}\n`);
      return { frames, writes, profile };
    } finally {
      await sdk.close();
      // the browser's HTTP and WebSocket requests, counted against the run's caps (local hosts only)
      writeFileSync(path.join(out, "sdk-counts.json"), `${JSON.stringify(sdkCounts)}\n`);
    }
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
    steps: opt("--steps") ?? "all",
  });
  console.log(
    JSON.stringify({
      profile: result.profile,
      frames: result.frames.length,
      writes: result.writes,
    }),
  );
}
