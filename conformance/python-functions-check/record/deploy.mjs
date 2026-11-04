// The one `firebase deploy` of the thirteen Python functions: the source copy taken from the pinned commit, the offline
// discovery by the SDK itself, the CLI plan (dry run, deploy, delete), and the readiness reads. The CLI run itself
// (`runCli`, its judgement `cliFailed`, its output parsers) is the scheduled-delivery recorder's, unchanged: it runs
// the pinned firebase-tools once per action and never retries.
import { execFileSync } from "node:child_process";
import { lstatSync, mkdirSync, readFileSync, realpathSync, symlinkSync } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import {
  ALL_FUNCTIONS,
  CODEBASE,
  FAMILIES,
  FIREBASE_FUNCTIONS_PY_VERSION,
  PROJECT,
  REGION,
  functionName,
} from "./plan.mjs";

export {
  cliFailed,
  erroredFunctions,
  escapingLinks,
  runCli,
  unknownWrites,
} from "../../scheduled-delivery/record/deploy.mjs";

export const READY_POLL_SECONDS = 30;
export const READY_MAX_POLLS = 40;

const DIRECTORY = "conformance/python-functions-check";

/**
 * Copies the tracked files of `conformance/python-functions-check` at `commit` into `target` (git archive, so nothing
 * untracked comes along) and links the Python virtual environment `venvDir` as `fixture/venv`: firebase-tools
 * imports the SDK from `<source>/venv` before it creates anything, and does not upload that directory.
 */
export function prepareSource({ repoRoot, commit, target, venvDir }) {
  if (!/^[0-9a-f]{40}$/.test(commit)) throw new Error("the source commit must be a full SHA");
  mkdirSync(target, { recursive: true, mode: 0o700 });
  const archive = execFileSync("git", ["-C", repoRoot, "archive", commit, DIRECTORY], {
    maxBuffer: 64 * 1024 * 1024,
  });
  execFileSync("tar", ["-x", "-C", target], { input: archive });
  const fixtureDir = join(target, DIRECTORY, "fixture");
  if (venvDir) symlinkSync(realpathSync(venvDir), join(fixtureDir, "venv"));
  return { configPath: join(target, DIRECTORY, "firebase.json"), fixtureDir };
}

const DISCOVERY = `
import json, sys
from firebase_functions.private import serving
out = {}
for name, fn in serving.get_functions().items():
    e = fn.__firebase_endpoint__
    trigger = e.eventTrigger or {}
    out[name] = {
        "entryPoint": e.entryPoint,
        "platform": e.platform,
        "region": e.region,
        "eventType": trigger.get("eventType"),
        "filters": trigger.get("eventFilters"),
        "channel": trigger.get("channel"),
        "schedule": (e.scheduleTrigger or {}).get("schedule"),
        "timeZone": (e.scheduleTrigger or {}).get("timeZone"),
        "taskQueue": e.taskQueueTrigger is not None,
        "maxAttempts": ((e.taskQueueTrigger or {}).get("retryConfig") or {}).get("maxAttempts"),
    }
print(json.dumps(out, sort_keys=True))
`;

/** The SDK's own discovery of the fixture, offline, in the deploy's environment: the declared endpoints. */
export function discover({ fixtureDir, directory }) {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const text = execFileSync(join(fixtureDir, "venv/bin/python"), ["-I", "-c", DISCOVERY], {
    env: {
      PATH: "/usr/bin:/bin",
      HOME: directory,
      PYTHONPATH: fixtureDir,
      GCLOUD_PROJECT: PROJECT,
      FIREBASE_CONFIG: JSON.stringify({
        projectId: PROJECT,
        storageBucket: PROJECT + ".firebasestorage.app",
      }),
    },
    cwd: fixtureDir,
    timeout: 60_000,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  return JSON.parse(text);
}

const EVENT_TYPES = Object.freeze({
  pcfsc: "google.cloud.firestore.document.v1.created",
  pcfscraw: "google.cloud.firestore.document.v1.created",
  pcfsu: "google.cloud.firestore.document.v1.updated",
  pcps: "google.cloud.pubsub.topic.v1.messagePublished",
  pcpsraw: "google.cloud.pubsub.topic.v1.messagePublished",
  pcst: "google.cloud.storage.object.v1.finalized",
  pcstraw: "google.cloud.storage.object.v1.finalized",
  pcea: "pycheck.thing.v1.happened",
  pcearaw: "pycheck.thing.v1.happened",
});

/** What the discovered endpoints must declare: the names, the region, the trigger kinds and their pins. */
export function declarationProblems(endpoints) {
  const problems = [];
  const found = Object.keys(endpoints).toSorted();
  const wanted = [...ALL_FUNCTIONS].toSorted();
  if (JSON.stringify(found) !== JSON.stringify(wanted))
    return [`the fixture exports ${found.join(", ")}; expected ${wanted.join(", ")}`];
  for (const name of wanted) {
    const e = endpoints[name];
    if (e.entryPoint !== name) problems.push(`${name}: entry point ${e.entryPoint}`);
    if (e.platform !== "gcfv2") problems.push(`${name}: platform ${e.platform}`);
    if (JSON.stringify(e.region) !== JSON.stringify([REGION]))
      problems.push(`${name}: region ${JSON.stringify(e.region)}, not ["${REGION}"]`);
    if (name in EVENT_TYPES && e.eventType !== EVENT_TYPES[name])
      problems.push(`${name}: event type ${e.eventType}`);
  }
  for (const fn of [FAMILIES.scheduler.sdk, FAMILIES.scheduler.raw]) {
    if (endpoints[fn].schedule !== "0 0 1 1 *")
      problems.push(`${fn}: schedule ${endpoints[fn].schedule}`);
    if (endpoints[fn].timeZone !== "UTC")
      problems.push(`${fn}: time zone ${endpoints[fn].timeZone}`);
  }
  for (const fn of [FAMILIES.tasks.sdk, FAMILIES.tasks.raw]) {
    if (endpoints[fn].taskQueue !== true) problems.push(`${fn}: not a task queue function`);
    if (endpoints[fn].maxAttempts !== 1)
      problems.push(`${fn}: max attempts ${endpoints[fn].maxAttempts}`);
  }
  for (const fn of [FAMILIES.pubsub.sdk, FAMILIES.pubsub.raw])
    if (endpoints[fn].filters?.topic !== "pycheck-orders")
      problems.push(`${fn}: topic ${endpoints[fn].filters?.topic}`);
  return problems;
}

/** Everything about the source copy that can be checked offline. */
export function sourceProblems({ fixtureDir, directory, discoverFn = discover }) {
  let endpoints;
  try {
    endpoints = discoverFn({ fixtureDir, directory });
  } catch (error) {
    return [
      `the SDK discovery of the fixture failed: ${String(error.stderr ?? error.message).slice(0, 300)}`,
    ];
  }
  return declarationProblems(endpoints);
}

/** The pinned SDK is the one in the virtual environment the deploy imports it from. */
export function sdkVersionProblems(venvDir, run = execFileSync) {
  try {
    const version = run(
      join(venvDir, "bin/python"),
      ["-I", "-c", "import importlib.metadata as m; print(m.version('firebase-functions'))"],
      {
        encoding: "utf8",
        env: { PATH: "/usr/bin:/bin" },
      },
    ).trim();
    return version === FIREBASE_FUNCTIONS_PY_VERSION
      ? []
      : [`firebase-functions is ${version}, not ${FIREBASE_FUNCTIONS_PY_VERSION}`];
  } catch {
    return ["firebase-functions cannot be imported from the virtual environment"];
  }
}

export const isLink = (path) => lstatSync(path).isSymbolicLink();

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
 * last; the deploy carries `--force`. The environment is explicit: nothing from the caller's own environment but what
 * is listed (`SHELL` is for the `venv/bin/activate` step firebase-tools runs through a shell).
 */
export function cliPlan(action, options) {
  if (!["deploy", "dry-run", "delete"].includes(action)) throw new Error("unknown CLI action");
  requireAbsolute(options, ["configHome", "configPath", "workDir", "home"]);
  const only = `functions:${CODEBASE}`;
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
      SHELL: "/bin/bash",
      XDG_CONFIG_HOME: options.configHome,
      GOOGLE_CLOUD_QUOTA_PROJECT: PROJECT,
      GCLOUD_PROJECT: PROJECT,
      FIREBASE_CONFIG: JSON.stringify({ projectId: PROJECT }),
    },
  };
}

// ---- readiness: from lists, no per-function reads ----------------------------------------------------

/**
 * What the lists say about the run's functions: the v2 function list (`state`) and the Cloud Run services (lower-case
 * ids; every name here is lower-case already). A function of this id in another region is `stray`: not ours to delete,
 * so the run stops (preflight) or leaves it for recovery (cleanup).
 */
export function summarize({ v2, run }) {
  const items = new Map((v2?.functions ?? []).map((item) => [item.name, item]));
  const services = new Set((run?.services ?? []).map((s) => String(s.name).split("/").at(-1)));
  const out = {};
  for (const fn of ALL_FUNCTIONS) {
    const name = functionName(fn);
    const item = items.get(name);
    const stray = [...items.keys()].some((n) => n !== name && n.split("/").at(-1) === fn);
    out[fn] = {
      present: item !== undefined,
      active: item?.state === "ACTIVE" && services.has(fn),
      runService: services.has(fn),
      stray,
    };
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
export { dirname };

// ---- the upload receipt -----------------------------------------------------------------------------

// The only place the deploy tells which object it uploaded is the CLI's own `--debug` output (firebase-tools 15.28.2, recorded
// in production by the Gen2 upload probe): the `generateUploadUrl` answer names the bucket and the object, and the upload's
// PUT status line says whether the CLI's create was answered. Time, size and count never make an object ours.
const GENERATE_LINE =
  /<<< \[apiv2\]\[body\] POST \S+\/functions:generateUploadUrl(?:\?\S*)? (\{.*\})\s*$/u;
const PUT_STATUS_LINE =
  /<<< \[apiv2\]\[status\] PUT https:\/\/storage\.googleapis\.com\/([^/\s?]+)\/([^\s?]+) (\d{3})\s*$/u;

/** One CLI output line as an event (`receipt` or `put-status`), or null. The signed upload URL is never kept. */
export function uploadEventFromLine(line) {
  const put = PUT_STATUS_LINE.exec(line);
  if (put) return { type: "put-status", bucket: put[1], object: put[2], status: Number(put[3]) };
  const match = GENERATE_LINE.exec(line);
  if (!match) return null;
  let body;
  try {
    body = JSON.parse(match[1]);
  } catch {
    return null;
  }
  const source = body?.storageSource;
  return typeof source?.bucket === "string" && typeof source.object === "string"
    ? { type: "receipt", bucket: source.bucket, object: source.object }
    : null;
}

export const uploadEventsFromCliOutput = (text) =>
  String(text)
    .split(/\r?\n/u)
    .map(uploadEventFromLine)
    .filter((event) => event !== null);

/**
 * "confirmed": some status is a 2xx. "refused": there is at least one status and every one is a definite 4xx (not 408, 429
 * or 499), so nothing was made. Anything else is "unknown": no line, a 3xx or 5xx, or a retried PUT that met a retryable code
 * before a refusal.
 */
export function putClass(statuses) {
  if (statuses.some((status) => status >= 200 && status < 300)) return "confirmed";
  const definite = (status) => status >= 400 && status < 500 && ![408, 429, 499].includes(status);
  return statuses.length > 0 && statuses.every(definite) ? "refused" : "unknown";
}

/**
 * The CLI result with the upload events of its stdout file (the deploy only). A file that cannot be read gives `null`: the
 * run then cannot tell which object the deploy made and reports it.
 */
export function withUploadEvents(result, directory) {
  if (result?.action !== "deploy") return result;
  let uploadEvents = null;
  try {
    uploadEvents = uploadEventsFromCliOutput(
      readFileSync(join(directory, "cli-deploy-stdout.txt"), "utf8"),
    );
  } catch {
    // no events: reported by the run
  }
  return { ...result, uploadEvents };
}
