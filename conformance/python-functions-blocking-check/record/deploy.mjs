// The one `firebase deploy` of the blocking function: the source copy taken from the pinned commit, the offline discovery by
// the SDK itself, the CLI plan (dry run, deploy, delete), and the readiness summary. The CLI run itself (`runCli`, its
// judgement `cliFailed`) is the scheduled-delivery recorder's, unchanged: it runs the pinned firebase-tools once per action
// and never retries.
import { execFileSync } from "node:child_process";
import { mkdirSync, realpathSync, symlinkSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import {
  BLOCKING_EVENT_TYPE,
  CODEBASE,
  FIREBASE_FUNCTIONS_PY_VERSION,
  FUNCTION,
  PROJECT,
  REGION,
  functionName,
} from "./plan.mjs";

export {
  cliFailed,
  erroredFunctions,
  runCli,
  unknownWrites,
} from "../../scheduled-delivery/record/deploy.mjs";

export const READY_POLL_SECONDS = 30;
export const READY_MAX_POLLS = 40;

const DIRECTORY = "conformance/python-functions-blocking-check";

/**
 * Copies the tracked files of `conformance/python-functions-blocking-check` at `commit` into `target` (git archive, so
 * nothing untracked comes along) and links the Python virtual environment `venvDir` as `fixture/venv`: firebase-tools
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
import json
from firebase_functions.private import serving
out = {}
for name, fn in serving.get_functions().items():
    e = fn.__firebase_endpoint__
    trigger = e.blockingTrigger or {}
    out[name] = {
        "entryPoint": e.entryPoint,
        "platform": e.platform,
        "region": e.region,
        "eventType": trigger.get("eventType"),
        "options": trigger.get("options"),
        "eventTrigger": e.eventTrigger is not None,
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

/** What the discovered endpoints must declare: exactly the one function, in the region, with the beforeCreate trigger and no token forwarding. */
export function declarationProblems(endpoints) {
  const found = Object.keys(endpoints).toSorted();
  if (JSON.stringify(found) !== JSON.stringify([FUNCTION]))
    return [`the fixture exports ${found.join(", ")}; expected ${FUNCTION}`];
  const e = endpoints[FUNCTION];
  const problems = [];
  if (e.entryPoint !== FUNCTION) problems.push(`entry point ${e.entryPoint}`);
  if (e.platform !== "gcfv2") problems.push(`platform ${e.platform}`);
  if (JSON.stringify(e.region) !== JSON.stringify([REGION]))
    problems.push(`region ${JSON.stringify(e.region)}, not ["${REGION}"]`);
  if (e.eventType !== BLOCKING_EVENT_TYPE) problems.push(`blocking event type ${e.eventType}`);
  if (e.eventTrigger) problems.push("it also declares an event trigger");
  const options = e.options ?? {};
  for (const name of ["idToken", "accessToken", "refreshToken"])
    if (options[name] !== false) problems.push(`${name} forwarding is ${options[name]}`);
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

const requireAbsolute = (options, keys) => {
  for (const key of keys)
    if (typeof options?.[key] !== "string" || !isAbsolute(options[key]))
      throw new Error(`the CLI plan needs an absolute ${key}`);
  if (typeof options.path !== "string" || !options.path)
    throw new Error("the CLI plan needs an explicit PATH");
};

/**
 * The CLI invocation (args, cwd, env) of one action. `dry-run` is the deploy argv with `--dry-run` appended last. The deploy
 * carries no `--force`: the repository and its cleanup policy exist, so the CLI changes no policy and needs no confirmation
 * (the blocking recorder's convention). The delete carries it, because the CLI asks for a confirmation otherwise. The
 * environment is explicit: nothing from the caller's own environment but what is listed.
 */
export function cliPlan(action, options) {
  if (!["deploy", "dry-run", "delete"].includes(action)) throw new Error("unknown CLI action");
  requireAbsolute(options, ["configHome", "configPath", "workDir", "home"]);
  const args =
    action === "delete"
      ? [
          "functions:delete",
          FUNCTION,
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
          `functions:${CODEBASE}`,
          "--non-interactive",
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

/** What the lists say about the function: the v2 function list (`state`) and the Cloud Run services (lower-case ids). */
export function summarize({ v2, run }) {
  const name = functionName();
  const items = new Map((v2?.functions ?? []).map((item) => [item.name, item]));
  const services = new Set((run?.services ?? []).map((s) => String(s.name).split("/").at(-1)));
  const item = items.get(name);
  const stray = [...items.keys()].some((n) => n !== name && n.split("/").at(-1) === FUNCTION);
  return {
    present: item !== undefined,
    active: item?.state === "ACTIVE" && services.has(FUNCTION),
    runService: services.has(FUNCTION),
    stray,
  };
}
export const isActive = (summary) => summary?.active === true;
export const isGone = (summary) =>
  summary?.present === false && summary?.runService !== true && summary?.stray !== true;
