// The local replay of the program: the same steps the recorder sent to production are sent to a real fireemu process (strict or
// emulator profile) that serves the same fixture, over its Tasks listener, and the deliveries are read from the fixture's own
// frames. The answers are shaped into the same projection as a recording. Nothing here reaches a network but loopback.
//
//   FIREEMU_BIN=<fireemu binary> node local.mjs --profile strict|emulator --out <new file>
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cpSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { mkdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { PROGRAM, corpusManifest, materialize, minStarts } from "./corpus.mjs";
import { layoutOfAnswer, projectRecording } from "./project.mjs";
import { ROLE_IDS, PROJECT, functionOfRole, functionsOf } from "./plan.mjs";
import { judge } from "./record/judge.mjs";
import { parseFramesFromText } from "./record/logs.mjs";

/**
 * Cases whose attempts the replay waits for beyond the program's own minimum: a queue that retries a hundred times shows
 * production's growing gaps (4, 8 and 10 s from the twelfth gap on) only after eighteen attempts.
 */
export const REPLAY_ATTEMPTS = Object.freeze({ "window-six": 20 });

export const LOCAL_RUN = "0000000000000000";
const READY_DEADLINE_MS = 30_000;
/** How far ahead of the burst program's start its tasks are due: room for 120 creates and the fixture's start. */
const BURST_LEAD_MS = 60_000;
const here = fileURLToPath(new URL(".", import.meta.url));
const conformance = join(here, "../..");

/** Writes the fixture (with the local suffix) and a firebase.json; returns the paths. */
export function materializeLocal(
  root,
  source = join(conformance, "task-queue-functions/functions"),
) {
  const functions = join(root, "functions");
  const own = join(source, "node_modules");
  // The installation is linked below, never copied: the release job runs `npm ci` in the fixture first.
  cpSync(source, functions, { recursive: true, filter: (path) => path !== own });
  writeFileSync(join(functions, "suffix.json"), JSON.stringify({ suffix: LOCAL_RUN.slice(0, 6) }));
  // The fixture's own installation (`npm ci` of its lockfile, as the release job does) when there is one, else the harness's.
  symlinkSync(
    existsSync(own) ? own : join(conformance, "node_modules"),
    join(functions, "node_modules"),
  );
  const firebaseJson = join(root, "firebase.json");
  writeFileSync(
    firebaseJson,
    JSON.stringify({
      functions: { source: functions, codebase: "task-queue", runtime: "nodejs22" },
      emulators: {
        functions: { port: 0 },
        tasks: { port: 0 },
        eventarc: { port: 0 },
        ui: { enabled: false },
        logging: { port: 0 },
        hub: { port: 0 },
      },
    }),
  );
  return firebaseJson;
}

async function startFireemu({ binary, profile, root, firebaseJson, productionExact, extraConfig }) {
  const ready = join(root, "ready.json");
  const profilePath = join(root, "profile.json");
  writeFileSync(
    profilePath,
    JSON.stringify(
      profile === "emulator"
        ? { schemaVersion: 1, profile: "emulator", ...extraConfig }
        : { schemaVersion: 1, profile: "strict", productionExact, ...extraConfig },
    ),
  );
  await mkdir(join(root, "home"), { recursive: true });
  const child = spawn(
    binary,
    [
      "up",
      "--config",
      profilePath,
      "--only",
      "functions,tasks",
      "--project",
      PROJECT,
      "--firebase-json",
      firebaseJson,
      "--ready-file",
      ready,
      "--owner-stdin",
    ],
    { env: { PATH: process.env.PATH, HOME: join(root, "home") }, stdio: ["pipe", "pipe", "pipe"] },
  );
  const log = { text: "" };
  child.stdout.on("data", (chunk) => (log.text += chunk));
  child.stderr.on("data", (chunk) => (log.text += chunk));
  const deadline = Date.now() + READY_DEADLINE_MS;
  while (Date.now() < deadline) {
    if (child.exitCode !== null)
      throw new Error(`fireemu exited ${child.exitCode}: ${log.text.slice(-2000)}`);
    try {
      const descriptor = JSON.parse(await readFile(ready, "utf8"));
      const host = descriptor.environment?.CLOUD_TASKS_EMULATOR_HOST;
      if (host) return { child, log, tasksHost: host };
    } catch {
      /* not there yet */
    }
    await new Promise((r) => setTimeout(r, 50));
  }
  child.kill("SIGTERM");
  throw new Error("fireemu readiness deadline: " + log.text.slice(-2000));
}

async function stop(child) {
  child.stdin.end();
  await Promise.race([
    new Promise((r) => child.once("exit", r)),
    new Promise((r) => setTimeout(r, 8000)),
  ]);
  if (child.exitCode === null) {
    child.kill("SIGTERM");
    await new Promise((r) => child.once("exit", r));
  }
}

/** One request to the Tasks listener, answered as `{status, json, text}` (json is null when the body is not JSON). */
async function send(tasksHost, request) {
  const url = request.url.replace("https://cloudtasks.googleapis.com/v2", `http://${tasksHost}`);
  const response = await fetch(url, {
    method: request.method,
    headers: { "content-type": "application/json", authorization: "Bearer owner" },
    ...(request.json === undefined ? {} : { body: JSON.stringify(request.json) }),
  });
  const text = await response.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  return {
    status: response.status,
    json,
    text,
    bodyBytes: Buffer.byteLength(text),
    layout: layoutOfAnswer(text, response.headers.get("content-type")),
  };
}

const answerClassOf = (status) => (status >= 200 && status < 300 ? "2xx" : "4xx");

/** Runs the whole program against one fireemu process and returns the recorder-shaped result. */
export async function runLocal({
  binary,
  profile,
  productionExact = true,
  extraConfig = {},
  waitSeconds = 120,
  steps = PROGRAM,
  scale = 1,
  burst = false,
}) {
  const root = mkdtempSync(join(tmpdir(), "task-queue-local-"));
  let started;
  try {
    const firebaseJson = materializeLocal(root);
    started = await startFireemu({
      binary,
      profile,
      root,
      firebaseJson,
      productionExact,
      extraConfig,
    });
    const targets = Object.fromEntries(
      // The URL is the daemon's own (an empty one is replaced by it); the identity and the audience are echoed as given, so
      // they are the values the recordings were made with, in their masked forms.
      ROLE_IDS.map((role) => [
        role,
        {
          uri: "",
          audience: `https://${functionOfRole(LOCAL_RUN, role)}-aaaaaaaaaa-uc.a.run.app`,
          serviceAccountEmail: "123456789012-compute@developer.gserviceaccount.com",
        },
      ]),
    );
    const due = burst ? Date.now() + BURST_LEAD_MS : null;
    if (burst) {
      const rate = PROGRAM.find((step) => step.key === "rate-a");
      steps = Array.from({ length: 120 }, (_, i) => {
        const key = `burst-${String(i + 1).padStart(3, "0")}`;
        return {
          ...rate,
          key,
          id: key,
          role: "tqrate",
          schedule: { raw: new Date(due).toISOString() },
        };
      });
    }
    const program = {};
    for (const spec of steps) {
      if (spec.pauseBefore)
        await new Promise((r) => setTimeout(r, (spec.pauseBefore * 1000) / scale));
      const request = materialize(spec, { runId: LOCAL_RUN, now: Date.now(), targets });
      // The packet's builder puts the URL in the audience; here the URL is empty (the daemon's own), so the audience is set.
      const oidc = request.json?.task?.httpRequest?.oidcToken;
      if (oidc) oidc.audience = targets[spec.role]?.audience ?? targets[ROLE_IDS[0]].audience;
      const dispatchedAt = Date.now();
      const answer = await send(started.tasksHost, request);
      program[spec.key] = {
        kind: spec.kind,
        sent: true,
        class: answerClassOf(answer.status),
        status: answer.status,
        dispatchedAt,
        answeredAt: Date.now(),
        answer: {
          status: answer.status,
          bodyBytes: answer.bodyBytes,
          json: answer.json,
          layout: answer.layout,
        },
      };
      if (!burst) await new Promise((r) => setTimeout(r, 200));
    }
    // Like the recorder's burst-late: a create answered after the due instant would make the burst unobservable.
    if (burst && Object.values(program).some((step) => step.answeredAt >= due))
      throw new Error("burst-late: a create was answered after the due instant");
    // Wait for every accepted task's first delivery (and the attempts of the retry cases).
    const fns = functionsOf(LOCAL_RUN);
    const want = Object.entries(program)
      .filter(([key, step]) => step.kind === "create" && step.class === "2xx" && minStarts(key) > 0)
      .map(([key]) => [key, Math.max(minStarts(key), REPLAY_ATTEMPTS[key] ?? 0)]);
    const deadline = burst ? due + 240_000 : Date.now() + waitSeconds * 1000;
    let frames = [];
    while (Date.now() < deadline) {
      frames = parseFramesFromText(started.log.text, fns).frames;
      const seen = {};
      for (const { frame } of frames)
        if (frame.kind === "start") seen[frame.case] = (seen[frame.case] ?? 0) + 1;
      if (
        burst
          ? steps.every(({ key }) =>
              frames.some(
                ({ frame }) =>
                  frame.kind === "start" &&
                  frame.case === key &&
                  Number(frame.context?.retryCount) === 0,
              ),
            )
          : want.every(([key, n]) => (seen[key] ?? 0) >= n)
      )
        break;
      await new Promise((r) => setTimeout(r, 500));
    }
    await new Promise((r) => setTimeout(r, 1500));
    frames = parseFramesFromText(started.log.text, fns).frames;
    if (burst) {
      const starts = frames.filter(
        ({ frame }) =>
          frame.kind === "start" &&
          steps.some(({ key }) => key === frame.case) &&
          Number(frame.context?.retryCount) === 0,
      );
      if (
        new Set(starts.map(({ frame }) => frame.case)).size !== 120 ||
        starts.length !== 120 ||
        starts.some(({ frame }) => !Number.isFinite(Date.parse(frame.at)))
      )
        throw new Error("burst observation incomplete or invalid");
      return {
        kind: "task-queue-burst-projection-v1",
        program: "burst",
        profile,
        tasks: 120,
        offsetsMs: starts.map(({ frame }) => Date.parse(frame.at) - due).sort((a, b) => a - b),
        anyAttemptRetryCounts: null,
        outcome: "tq-recorded",
        observationComplete: true,
      };
    }
    const judged = judge({ runId: LOCAL_RUN, program, frames });
    return {
      runId: LOCAL_RUN,
      // The daemon's own output, for a replay that delivered nothing (never part of a projection).
      log: started.log.text,
      judged,
      program,
      functions: fns.length,
      roles: ROLE_IDS.map((role) => functionOfRole(LOCAL_RUN, role)),
    };
  } finally {
    if (started) await stop(started.child);
    rmSync(root, { recursive: true, force: true });
  }
}

export async function localProjection(options) {
  const result = await runLocal(options);
  if (options.burst) return result;
  return projectRecording({
    result,
    alias: options.alias ?? options.profile,
    corpusSha256: corpusManifest().corpusSha256,
    projectNumber: null,
    meta: {
      profile: options.profile,
      productionExact: options.productionExact ?? true,
      ...options.meta,
    },
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const option = (name) => process.argv[process.argv.indexOf(name) + 1];
  const profile = option("--profile");
  const out = option("--out");
  const program = process.argv.includes("--program") ? option("--program") : null;
  if (program !== null && program !== "burst") throw new Error("--program burst");
  if (program === "burst" && profile !== "strict")
    throw new Error("burst requires --profile strict");
  if (!["strict", "emulator"].includes(profile)) throw new Error("--profile strict|emulator");
  if (!out || !process.env.FIREEMU_BIN)
    throw new Error("--out <new file> and FIREEMU_BIN are required");
  if (existsSync(resolve(out))) throw new Error("--out must not already exist");
  const binary = resolve(process.env.FIREEMU_BIN);
  // The digest of the binary that served the replay is part of the file, so that the evidence names its build.
  const binarySha256 = createHash("sha256").update(readFileSync(binary)).digest("hex");
  const projection = await localProjection({
    binary,
    profile,
    burst: program === "burst",
    meta: { binarySha256 },
  });
  (await import("node:fs")).writeFileSync(
    resolve(out),
    JSON.stringify(projection, null, 2) + "\n",
    { flag: "wx" },
  );
}
