// The one `firebase deploy` of the five functions: the source copy taken from the pinned commit, the offline
// discovery and region check, the CLI plan (dry run, deploy, delete), the judgement of a CLI run, and the
// readiness reads. The recorder never retries a CLI action.
import { execFileSync, spawn } from "node:child_process";
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
import { dirname, isAbsolute, join } from "node:path";
import {
  ALL_FUNCTIONS,
  CODEBASE,
  DECLARED,
  FIREBASE_FUNCTIONS_VERSION,
  FUNCTIONS,
  PROJECT,
  REGION,
  functionName,
  runServiceId,
} from "./plan.mjs";

export const DEPLOY_TIMEOUT_MS = 40 * 60 * 1000;
export const DELETE_TIMEOUT_MS = 20 * 60 * 1000;
export const DRY_RUN_TIMEOUT_MS = 10 * 60 * 1000;
export const CLI_TIMEOUT_MS = {
  deploy: DEPLOY_TIMEOUT_MS,
  "dry-run": DRY_RUN_TIMEOUT_MS,
  delete: DELETE_TIMEOUT_MS,
};
export const READY_POLL_SECONDS = 30;
export const READY_MAX_POLLS = 40;

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

/** Problems with the dependency tree the deploy uploads against: the pinned SDK, resolvable, no link out. */
export function dependencyProblems(fixtureDir) {
  const problems = [];
  const require_ = createRequire(join(fixtureDir, "package.json"));
  try {
    require_.resolve("firebase-functions");
    const found = JSON.parse(
      readFileSync(join(fixtureDir, "node_modules/firebase-functions/package.json"), "utf8"),
    );
    if (found.version !== FIREBASE_FUNCTIONS_VERSION)
      problems.push(`firebase-functions is ${found.version}, not ${FIREBASE_FUNCTIONS_VERSION}`);
  } catch {
    problems.push("firebase-functions cannot be resolved from the fixture");
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
 * Copies the tracked files of `conformance/scheduled-delivery-004` at `commit` into `target` (git archive, so
 * nothing untracked comes along) and the installed dependency tree `depsDir` next to the fixture:
 * firebase-tools resolves firebase-functions from the source directory before it creates anything.
 */
export function prepareSource({ repoRoot, commit, target, depsDir }) {
  if (!/^[0-9a-f]{40}$/.test(commit)) throw new Error("the source commit must be a full SHA");
  mkdirSync(target, { recursive: true, mode: 0o700 });
  const archive = execFileSync(
    "git",
    ["-C", repoRoot, "archive", commit, "conformance/scheduled-delivery-004"],
    {
      maxBuffer: 64 * 1024 * 1024,
    },
  );
  execFileSync("tar", ["-x", "-C", target], { input: archive });
  const fixtureDir = join(target, "conformance/scheduled-delivery-004/fixture");
  if (depsDir)
    cpSync(realpathSync(depsDir), join(fixtureDir, "node_modules"), {
      recursive: true,
      verbatimSymlinks: true,
    });
  return {
    configPath: join(target, "conformance/scheduled-delivery-004/firebase.json"),
    fixtureDir,
  };
}

/**
 * Writes the round number into the source copy (`const ROUND = <n>;` in the fixture's index.js) so that the source of a
 * redeploy differs from the last one: the CLI skips a function whose source is unchanged, and so would leave its
 * Scheduler job alone whatever it has become. Rounds are 2 and 3 (round 1 is the copy as archived).
 */
export function setRound(fixtureDir, round) {
  if (![2, 3].includes(round)) throw new Error("the round must be 2 or 3");
  const file = join(fixtureDir, "index.js");
  const text = readFileSync(file, "utf8");
  const marker = /^const ROUND = (\d+);$/gm;
  if ((text.match(marker) ?? []).length !== 1)
    throw new Error("the fixture must hold exactly one `const ROUND = <n>;` line");
  writeFileSync(file, text.replace(marker, `const ROUND = ${round};`));
}

/** The SDK's own discovery of the fixture, offline, in the deploy's environment: the manifest's endpoints. */
export function discoverManifest({ fixtureDir, node, directory }) {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const manifest = join(directory, "functions-manifest.json");
  execFileSync(
    node,
    [join(fixtureDir, "node_modules/firebase-functions/lib/bin/firebase-functions.js"), fixtureDir],
    {
      env: {
        PATH: dirname(node),
        HOME: directory,
        FUNCTIONS_MANIFEST_OUTPUT_PATH: manifest,
        GCLOUD_PROJECT: PROJECT,
        FIREBASE_CONFIG: JSON.stringify({ projectId: PROJECT }),
      },
      cwd: fixtureDir,
      timeout: 60_000,
      stdio: ["ignore", "ignore", "pipe"],
    },
  );
  return JSON.parse(readFileSync(manifest, "utf8")).endpoints ?? {};
}

// Where firebase-tools 15.28.2 puts an endpoint whose manifest names no region (prepare.js
// resolveDefaultRegionsForBuild): Gen1 in us-central1, Gen2 by its trigger's service default. Every one of
// the five pins us-central1, so a missing or different region is a refusal.
const PINNED_REGION = JSON.stringify([REGION]);
export function regionProblems(endpoints) {
  const problems = [];
  for (const [name, endpoint] of Object.entries(endpoints)) {
    if (endpoint.region === undefined || endpoint.region === null)
      problems.push(`${name}: no region is set; pin region "${REGION}"`);
    else if (JSON.stringify(endpoint.region) !== PINNED_REGION)
      problems.push(`${name}: the region is ${JSON.stringify(endpoint.region)}, not ["${REGION}"]`);
  }
  return problems;
}

const canonical = (value) =>
  JSON.stringify(value, (key, v) =>
    v && typeof v === "object" && !Array.isArray(v)
      ? Object.fromEntries(Object.entries(v).toSorted(([a], [b]) => (a < b ? -1 : 1)))
      : v,
  );

/** What the discovered endpoints must declare: the names, the platform, the schedule, the time zone, the retry. */
export function declarationProblems(endpoints) {
  const problems = [];
  const found = Object.keys(endpoints).toSorted();
  const wanted = [...ALL_FUNCTIONS].toSorted();
  if (JSON.stringify(found) !== JSON.stringify(wanted))
    return [`the fixture exports ${found.join(", ")}; expected ${wanted.join(", ")}`];
  for (const [name, want] of Object.entries(DECLARED)) {
    const e = endpoints[name];
    const trigger = e.scheduleTrigger ?? {};
    if (e.platform !== want.platform) problems.push(`${name}: platform ${e.platform}`);
    if (trigger.schedule !== want.schedule) problems.push(`${name}: schedule ${trigger.schedule}`);
    if ("timeZone" in want ? (trigger.timeZone ?? undefined) !== want.timeZone : false)
      problems.push(`${name}: time zone ${trigger.timeZone}`);
    if (want.retryConfig && canonical(trigger.retryConfig) !== canonical(want.retryConfig))
      problems.push(`${name}: retry ${JSON.stringify(trigger.retryConfig)}`);
    if (want.timeoutSeconds !== undefined && e.timeoutSeconds !== want.timeoutSeconds)
      problems.push(`${name}: timeout ${e.timeoutSeconds}`);
  }
  return problems;
}

/** Everything about the source copy that can be checked offline. */
export function sourceProblems({ fixtureDir, node, directory }) {
  const problems = dependencyProblems(fixtureDir);
  if (problems.length) return problems;
  let endpoints;
  try {
    endpoints = discoverManifest({ fixtureDir, node, directory });
  } catch (error) {
    return [
      `the SDK discovery of the fixture failed: ${String(error.stderr ?? error.message).slice(0, 300)}`,
    ];
  }
  return [...regionProblems(endpoints), ...declarationProblems(endpoints)];
}

// ---- the CLI ----------------------------------------------------------------------------------

const requireAbsolute = (options, keys) => {
  for (const key of keys)
    if (typeof options?.[key] !== "string" || !isAbsolute(options[key]))
      throw new Error(`the CLI plan needs an absolute ${key}`);
  if (typeof options.path !== "string" || !options.path)
    throw new Error("the CLI plan needs an explicit PATH");
};

/**
 * The CLI invocation (args, cwd, env) of one action. `dry-run` is the exact deploy argv with `--dry-run` appended
 * last; the deploy carries `--force` (a function that retries is refused non-interactively without it). The
 * environment is explicit: nothing from the caller's own environment but what is listed.
 */
export function cliPlan(action, options) {
  if (!["deploy", "dry-run", "delete"].includes(action)) throw new Error("unknown CLI action");
  requireAbsolute(options, ["configHome", "configPath", "workDir", "home"]);
  // A round redeploys a subset of the functions. The delete is always of every function: a partial delete is not part
  // of this packet.
  const names = options.names ?? ALL_FUNCTIONS;
  if (
    !Array.isArray(names) ||
    names.length === 0 ||
    new Set(names).size !== names.length ||
    !names.every((name) => ALL_FUNCTIONS.includes(name))
  )
    throw new Error("the CLI plan's names must be distinct functions of the packet");
  if (action === "delete" && options.names !== undefined)
    throw new Error("a partial delete is not part of this packet");
  const only = names.map((name) => `functions:${CODEBASE}:${name}`).join(",");
  const args =
    action === "delete"
      ? [
          "functions:delete",
          ...ALL_FUNCTIONS,
          "--config",
          options.configPath,
          "--region",
          REGION,
          "--project",
          PROJECT,
          "--non-interactive",
          "--force",
          "--debug",
        ]
      : [
          "deploy",
          "--config",
          options.configPath,
          "--project",
          PROJECT,
          "--only",
          only,
          "--non-interactive",
          "--force",
          "--debug",
          ...(action === "dry-run" ? ["--dry-run"] : []),
        ];
  return {
    args,
    cwd: options.workDir,
    env: {
      HOME: options.home,
      PATH: options.path,
      XDG_CONFIG_HOME: options.configHome,
      GOOGLE_CLOUD_QUOTA_PROJECT: PROJECT,
      GCLOUD_PROJECT: PROJECT,
      FIREBASE_CONFIG: JSON.stringify({ projectId: PROJECT }),
    },
  };
}

/**
 * How many functions the CLI says errored: the line `N Functions Errored` its summary prints (with or without a
 * timestamp from `--debug`). `null` when there is no such line. An earlier recording's CLI delete printed
 * `1 Functions Errored` and still exited 0, so the exit code alone judges nothing.
 */
export function erroredFunctions(text) {
  const matches = [...String(text).matchAll(/^(?:\[[^\]]*\] )?(\d+) Functions? Errored[ \t]*$/gm)];
  return matches.length === 0 ? null : Number(matches.at(-1)[1]);
}

/**
 * The writes to Cloud Functions, Cloud Scheduler or Pub/Sub that the CLI's `--debug` output shows answered with a
 * status that does not say whether the write happened: a 5xx, a 3xx or a status below 200 (the line
 * `<<< [apiv2][status] POST <url> 500`, with or without a prefix). firebase-tools retries only some statuses, so a
 * create answered 500 is reported as an errored function and the CLI exits non-zero: a clean failure that may still
 * have created the name. A write that got no answer at all prints no such line and is not seen here.
 */
export function unknownWrites(text) {
  const found = [];
  for (const m of String(text).matchAll(
    /<<< \[apiv2\]\[status\] (POST|PUT|PATCH) https:\/\/(cloudfunctions|cloudscheduler|pubsub)\.googleapis\.com\/\S* (\d{3})[ \t]*$/gm,
  )) {
    const status = Number(m[3]);
    if (status < 200 || (status >= 300 && status < 400) || status >= 500)
      found.push({ method: m[1], host: m[2], status });
  }
  return found;
}

/** Whether a CLI result is a failure: a non-zero exit, a timeout, an error, or any function errored. */
export const cliFailed = (result) =>
  result?.exitCode !== 0 ||
  Boolean(result?.timedOut) ||
  Boolean(result?.error) ||
  (Number.isInteger(result?.errored) && result.errored > 0);

/**
 * Runs the pinned firebase-tools once. stdout and stderr go to private files in `directory`. Never retried; a
 * timeout stops the process group. Returns what happened, judging nothing; `cliFailed` judges.
 */
export function runCli({
  action,
  label = action,
  plan,
  firebaseJs,
  node,
  directory,
  spawnFn = spawn,
  timeoutMs,
  killGraceMs = 60_000,
}) {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const out = openSync(join(directory, `cli-${label}-stdout.txt`), "wx", 0o600);
  const err = openSync(join(directory, `cli-${label}-stderr.txt`), "wx", 0o600);
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
      let errored = null;
      let unknown = [];
      try {
        const text = readFileSync(join(directory, `cli-${label}-stdout.txt`), "utf8");
        errored = erroredFunctions(text.slice(-65_536));
        unknown = unknownWrites(text);
      } catch {
        // the output cannot be read: no count
      }
      resolve({
        action,
        exitCode,
        signal,
        timedOut,
        error: error?.message ?? null,
        errored,
        unknownWrites: unknown,
        durationMs: Date.now() - startedAt,
      });
    };
    const timer = setTimeout(() => {
      timedOut = true;
      try {
        process.kill(-child.pid, "SIGTERM");
      } catch {}
      killTimer = setTimeout(() => {
        try {
          process.kill(-child.pid, "SIGKILL");
        } catch {}
        setTimeout(
          () => finish(null, "SIGKILL", new Error("the CLI had to be killed")),
          killGraceMs,
        );
      }, killGraceMs);
    }, timeoutMs ?? CLI_TIMEOUT_MS[action]);
    child.on("error", (error) => finish(null, null, error));
    child.on("exit", (code, signal) => finish(code, signal));
  });
}

// ---- readiness: from lists, no per-function reads ----------------------------------------------------

/**
 * What the four lists say about the five functions: v1 and v2 function lists (`status` / `state`), Cloud Run
 * services (lower-case ids), and the Scheduler jobs. Names are compared case-exact for functions and
 * lower-case for Run services only. Returns, per function, whether it is `present` and `active`.
 */
export function summarize({ v1, v2, run }) {
  const names = (list, key) => new Map((list?.[key] ?? []).map((item) => [item.name, item]));
  const f1 = names(v1, "functions");
  const f2 = names(v2, "functions");
  const services = new Set((run?.services ?? []).map((s) => String(s.name).split("/").at(-1)));
  const out = {};
  for (const fn of ALL_FUNCTIONS) {
    const name = functionName(fn);
    // A function of this id in another region is not ours to delete: it is reported so that the run stops
    // (preflight) or is left for recovery (cleanup).
    const stray = [...f1.keys(), ...f2.keys()].some(
      (n) => n !== name && n.split("/").at(-1) === fn,
    );
    if (FUNCTIONS.v1.includes(fn)) {
      const item = f1.get(name);
      out[fn] = { present: item !== undefined, active: item?.status === "ACTIVE", stray };
    } else {
      const item = f2.get(name);
      const service = services.has(runServiceId(fn));
      out[fn] = {
        present: item !== undefined,
        active: item?.state === "ACTIVE" && service,
        runService: service,
        stray,
      };
    }
  }
  return out;
}
export const allActive = (summary) => ALL_FUNCTIONS.every((fn) => summary[fn]?.active === true);
export const nonePresent = (summary) =>
  ALL_FUNCTIONS.every(
    (fn) =>
      summary[fn]?.present === false &&
      summary[fn]?.runService !== true &&
      summary[fn]?.stray !== true,
  );
