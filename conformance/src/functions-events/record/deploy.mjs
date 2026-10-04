// Deploy and readiness. The one `firebase deploy` of the 22 handlers runs from a private copy of the
// fixture taken from the pinned commit; the recorder never retries it. Readiness is observed from four
// list reads (no per-function reads) and only recorded: a deploy that did not become ready means the
// passes are skipped, not that anything is judged.

import { spawn } from "node:child_process";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  closeSync,
  cpSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";

import { formalHandlers, buildCanaryBatchCli } from "../canary-cli.mjs";
import { HANDLERS } from "./logs.mjs";
import { PRIMARY_BUCKET, PRIMARY_COLLECTION, PRIMARY_TOPIC, PROJECT, REGION } from "./script.mjs";

export const DEPLOY_TIMEOUT_MS = 40 * 60 * 1000;
export const DELETE_TIMEOUT_MS = 20 * 60 * 1000;
export const READY_POLL_SECONDS = 30;
export const READY_MAX_POLLS = 40;
export const PROPAGATION_WAIT_SECONDS = 300;

/** The runtime environment of the deployed fixture, as the dotenv file the deploy reads. Deterministic, so its digest is a pin. */
export function dotenvText() {
  return [
    "FE_EVENTS_MODE=production",
    `FE_EVENTS_PROJECT_ID=${PROJECT}`,
    `FE_EVENTS_PRIMARY_COLLECTION=${PRIMARY_COLLECTION}`,
    `FE_EVENTS_PRIMARY_BUCKET=${PRIMARY_BUCKET}`,
    `FE_EVENTS_PRIMARY_TOPIC=${PRIMARY_TOPIC}`,
    "FE_EVENTS_CAPTURE_MODE=stdout",
    "",
  ].join("\n");
}
export const dotenvSha256 = () => createHash("sha256").update(dotenvText()).digest("hex");

// The dependencies the offline discovery loads; the functions framework is installed by Cloud Build from
// the pinned lockfile (a harness input), not from this copy.
export const PINNED_DEPENDENCIES = {
  "firebase-functions": "7.3.2",
  "firebase-admin": "14.3.0",
};

/** Every entry of a tree is inside it: no symlink leaves `root`. Returns the entries that do. */
export function escapingLinks(root) {
  const base = realpathSync(root);
  const escaped = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir)) {
      const path = join(dir, entry);
      const stat = lstatSync(path);
      if (stat.isSymbolicLink()) {
        let real;
        try {
          real = realpathSync(path);
        } catch {
          escaped.push(path);
          continue;
        }
        if (real !== base && !real.startsWith(`${base}/`)) escaped.push(path);
      } else if (stat.isDirectory()) walk(path);
    }
  };
  walk(root);
  return escaped;
}

/** Problems with the dependency tree the deploy will upload against: the pinned versions, resolvable from the fixture, no link out of the tree. */
export function dependencyProblems(fixtureDir) {
  const problems = [];
  const require_ = createRequire(join(fixtureDir, "package.json"));
  for (const [name, version] of Object.entries(PINNED_DEPENDENCIES)) {
    try {
      require_.resolve(name);
      const found = JSON.parse(
        readFileSync(join(fixtureDir, "node_modules", name, "package.json"), "utf8"),
      );
      if (found.version !== version) problems.push(`${name} is ${found.version}, not ${version}`);
    } catch {
      problems.push(`${name} cannot be resolved from the fixture`);
    }
  }
  try {
    const escaped = escapingLinks(join(fixtureDir, "node_modules"));
    if (escaped.length) problems.push(`${escaped.length} links in node_modules leave the tree`);
  } catch {
    problems.push("node_modules cannot be read");
  }
  return problems;
}

/**
 * Copies the tracked files of `conformance/functions-events` at `commit` into `target` (git archive,
 * so nothing untracked comes along), writes the dotenv, and copies the installed dependency tree
 * `depsDir` (a pnpm node_modules, symlinks kept relative) next to the fixture: firebase-tools resolves
 * firebase-functions from the source directory before it creates anything. Returns the paths the CLI needs.
 */
export function prepareSource({ repoRoot, commit, target, depsDir }) {
  if (!/^[0-9a-f]{40}$/.test(commit)) throw new Error("the source commit must be a full SHA");
  mkdirSync(target, { recursive: true, mode: 0o700 });
  const archive = execFileSync(
    "git",
    ["-C", repoRoot, "archive", commit, "conformance/functions-events"],
    { maxBuffer: 64 * 1024 * 1024 },
  );
  execFileSync("tar", ["-x", "-C", target], { input: archive });
  const fixtureDir = join(target, "conformance/functions-events/fixtures");
  writeFileSync(join(fixtureDir, `.env.${PROJECT}`), dotenvText(), { mode: 0o600 });
  if (depsDir)
    cpSync(realpathSync(depsDir), join(fixtureDir, "node_modules"), {
      recursive: true,
      verbatimSymlinks: true,
    });
  return { configPath: join(target, "conformance/functions-events/firebase.json"), fixtureDir };
}

/**
 * The SDK's own discovery of the fixture, offline, with the production environment: returns the names
 * of the endpoints it finds. A missing dependency, a refused environment or a handler that does not load
 * shows up here, before anything is sent.
 */
export function discoverEndpoints({ fixtureDir, node, directory }) {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const manifest = join(directory, "functions-manifest.json");
  const env = {
    PATH: dirname(node),
    HOME: directory,
    FUNCTIONS_MANIFEST_OUTPUT_PATH: manifest,
    GCLOUD_PROJECT: PROJECT,
    FIREBASE_CONFIG: JSON.stringify({ projectId: PROJECT }),
    ...Object.fromEntries(
      dotenvText()
        .split("\n")
        .filter(Boolean)
        .map((line) => line.split("=")),
    ),
  };
  execFileSync(
    node,
    [join(fixtureDir, "node_modules/firebase-functions/lib/bin/firebase-functions.js"), fixtureDir],
    { env, cwd: fixtureDir, timeout: 60_000, stdio: ["ignore", "ignore", "pipe"] },
  );
  return Object.keys(JSON.parse(readFileSync(manifest, "utf8")).endpoints ?? {});
}

/** Everything about the source copy that can be checked offline: the dependencies and the 22 discovered endpoints. */
export function sourceProblems({ fixtureDir, node, directory }) {
  const problems = dependencyProblems(fixtureDir);
  if (problems.length) return problems;
  let found;
  try {
    found = discoverEndpoints({ fixtureDir, node, directory });
  } catch (error) {
    return [
      `the SDK discovery of the fixture failed: ${String(error.stderr ?? error.message).slice(0, 300)}`,
    ];
  }
  const missing = formalHandlers.filter((name) => !found.includes(name));
  const extra = found.filter((name) => !formalHandlers.includes(name));
  if (missing.length || extra.length)
    return [
      `the fixture exports ${found.length} endpoints (missing: ${missing.join(", ") || "none"}; extra: ${extra.join(", ") || "none"})`,
    ];
  return [];
}

/** The CLI invocation (args, cwd, env) for deploy or delete of the formal set, from the reviewed helper. */
export function cliPlan(action, { configHome, configPath, workDir, home, path }) {
  return buildCanaryBatchCli(action, PROJECT, formalHandlers, {
    configHome,
    configPath,
    workDir,
    home,
    path,
    captureMode: "stdout",
  });
}

/**
 * Runs the pinned firebase-tools once. stdout and stderr go to private files in `directory`. Never
 * retried; a timeout stops the process group. Returns what happened, judging nothing.
 */
export function runCli({
  action,
  plan,
  firebaseJs,
  node,
  directory,
  spawnFn = spawn,
  timeoutMs,
  killGraceMs = 60_000,
}) {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const out = openSync(join(directory, `cli-${action}-stdout.txt`), "wx", 0o600);
  const err = openSync(join(directory, `cli-${action}-stderr.txt`), "wx", 0o600);
  return new Promise((resolve) => {
    const startedAt = Date.now();
    const child = spawnFn(node, [firebaseJs, ...plan.args], {
      cwd: plan.cwd,
      env: plan.env,
      stdio: ["ignore", out, err],
      detached: true,
    });
    let timedOut = false;
    let killTimer;
    let settled = false;
    const finish = (exitCode, signal, error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(killTimer);
      closeSync(out);
      closeSync(err);
      resolve({
        action,
        exitCode,
        signal,
        timedOut,
        error: error?.message ?? null,
        durationMs: Date.now() - startedAt,
      });
    };
    const timer = setTimeout(
      () => {
        timedOut = true;
        try {
          process.kill(-child.pid, "SIGTERM");
        } catch {}
        // A CLI that ignores SIGTERM is killed, so the cleanup that follows always runs.
        killTimer = setTimeout(() => {
          try {
            process.kill(-child.pid, "SIGKILL");
          } catch {}
          setTimeout(
            () => finish(null, "SIGKILL", new Error("the CLI had to be killed")),
            killGraceMs,
          );
        }, killGraceMs);
      },
      timeoutMs ?? (action === "deploy" ? DEPLOY_TIMEOUT_MS : DELETE_TIMEOUT_MS),
    );
    child.on("error", (error) => finish(null, null, error));
    child.on("exit", (code, signal) => finish(code, signal));
  });
}

// ---- readiness -------------------------------------------------------------------------------

const region = `projects/${PROJECT}/locations/${REGION}`;
const listSpec = (id, url) => ({
  id,
  role: "readiness",
  method: "GET",
  url,
  auth: "oauth",
  mutation: false,
  expect: [200],
});
export const LISTS = {
  v1: (page) =>
    listSpec(
      "lists.functions-v1",
      `https://cloudfunctions.googleapis.com/v1/${region}/functions${page ? `?pageToken=${encodeURIComponent(page)}` : ""}`,
    ),
  v2: (page) =>
    listSpec(
      "lists.functions-v2",
      `https://cloudfunctions.googleapis.com/v2/${region}/functions${page ? `?pageToken=${encodeURIComponent(page)}` : ""}`,
    ),
  run: (page) =>
    listSpec(
      "lists.run-services",
      `https://run.googleapis.com/v2/${region}/services${page ? `?pageToken=${encodeURIComponent(page)}` : ""}`,
    ),
  eventarc: (page) =>
    listSpec(
      "lists.eventarc-triggers",
      `https://eventarc.googleapis.com/v1/${region}/triggers${page ? `?pageToken=${encodeURIComponent(page)}` : ""}`,
    ),
};
const KEYS = { v1: "functions", v2: "functions", run: "services", eventarc: "triggers" };

/** Reads one list completely (follows nextPageToken, at most five pages); returns the items and whether the read was complete. */
export async function readList(transport, kind) {
  const items = [];
  let page;
  for (let i = 0; i < 5; i += 1) {
    const answer = await transport.request(LISTS[kind](page));
    if (answer.kind !== "success") return { items, complete: false, status: answer.status ?? null };
    items.push(...(answer.json?.[KEYS[kind]] ?? []));
    page = answer.json?.nextPageToken;
    if (!page) return { items, complete: true, status: answer.status };
  }
  return { items, complete: false, status: 200 };
}

const lastSegment = (name) =>
  String(name ?? "")
    .split("/")
    .at(-1);

/** What a four-list read says about the 22 handlers: which are listed and which are active. */
export function summarize({ v1, v2, run, eventarc }) {
  const v1Active = new Set(
    v1.items.filter((f) => f.status === "ACTIVE").map((f) => lastSegment(f.name)),
  );
  const v2Active = new Set(
    v2.items.filter((f) => f.state === "ACTIVE").map((f) => lastSegment(f.name)),
  );
  const services = new Set(run.items.map((s) => lastSegment(s.name)));
  const triggers = eventarc.items.map((t) => lastSegment(t.name));
  const listed = {
    functionsActive: HANDLERS.filter((h) =>
      h.generation === 1 ? v1Active.has(h.name) : v2Active.has(h.name.toLowerCase()),
    ).map((h) => h.name),
    functionsListed: v1.items.length + v2.items.length,
    runServices: HANDLERS.filter(
      (h) => h.generation === 2 && services.has(h.name.toLowerCase()),
    ).map((h) => h.name),
    eventarcTriggers: HANDLERS.filter(
      (h) => h.generation === 2 && triggers.some((t) => t.startsWith(`${h.name.toLowerCase()}-`)),
    ).map((h) => h.name),
  };
  return {
    ...listed,
    complete: [v1, v2, run, eventarc].every((l) => l.complete),
    ready:
      listed.functionsActive.length === HANDLERS.length &&
      listed.runServices.length === 11 &&
      listed.eventarcTriggers.length === 11,
    absent:
      [v1, v2, run, eventarc].every((l) => l.complete) &&
      listed.functionsListed === 0 &&
      run.items.length === 0 &&
      listed.eventarcTriggers.length === 0,
  };
}

export async function readLists(transport) {
  const out = {};
  for (const kind of ["v1", "v2", "run", "eventarc"]) out[kind] = await readList(transport, kind);
  return out;
}

const NOT_READ = { items: [], complete: true };

/**
 * Polls until the 22 handlers are active or the polls run out. A poll reads the two function lists;
 * only when all 22 are active does it read the Run and Eventarc lists to confirm. Returns the last
 * summary and the number of polls.
 */
export async function waitReady({
  transport,
  sleep,
  polls = READY_MAX_POLLS,
  everySeconds = READY_POLL_SECONDS,
  shouldStop = () => false,
}) {
  let summary;
  for (let i = 1; i <= polls; i += 1) {
    if (shouldStop()) return { ...summary, polls: i - 1, stopped: true };
    const v1 = await readList(transport, "v1");
    const v2 = await readList(transport, "v2");
    summary = summarize({ v1, v2, run: NOT_READ, eventarc: NOT_READ });
    if (summary.functionsActive.length === HANDLERS.length) {
      summary = summarize({
        v1,
        v2,
        run: await readList(transport, "run"),
        eventarc: await readList(transport, "eventarc"),
      });
      if (summary.ready) return { ...summary, polls: i };
    }
    if (i < polls) await sleep(everySeconds);
  }
  return { ...summary, polls };
}

export const fixtureDigest = (fixtureDir) =>
  createHash("sha256")
    .update(readFileSync(join(fixtureDir, "index.js")))
    .digest("hex");
