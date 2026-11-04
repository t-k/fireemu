// The one `firebase deploy` of the blocking function: the source copy taken from the pinned commit, the offline discovery by
// the SDK itself, the CLI plan (dry run, deploy, delete), and the readiness summary. The CLI run itself (`runCli`, its
// judgement `cliFailed`) is the scheduled-delivery recorder's, unchanged: it runs the pinned firebase-tools once per action
// and never retries.
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
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

// The mutating requests the CLI sent, from its own `--debug` output: one `>>> [apiv2][query] <METHOD> <url>` line per request
// and one `<<< [apiv2][status] <METHOD> <url> <code>` line per answer. Reads that use POST and the upload's PUT (settled
// by its receipt) are not mutations of the project.
const REQUEST_LINE = /\[apiv2\]\[query\] (POST|PUT|PATCH|DELETE) (https:\/\/\S+)/u;
const STATUS_LINE = /\[apiv2\]\[status\] (POST|PUT|PATCH|DELETE) (https:\/\/\S+) (\d{3})[ \t]*$/u;
const READ_ONLY_POST = /:(?:getIamPolicy|testIamPermissions|generateUploadUrl)$|\/entries:list$/u;

/**
 * Every mutating request in the CLI output with its answers: `{ method, url, requests, statuses, class }`. The class is
 * "ok" (every request answered 2xx), "unanswered" (fewer answers than requests), "non-2xx" (any other answer) or
 * "retried" (more than one request to the same method and URL, which only happens after a failed one). Anything but
 * "ok" is an unknown write for the run (coordinator ruling R1).
 */
export function cliWritesFromOutput(text) {
  const writes = new Map();
  for (const line of String(text).split(/\r?\n/u)) {
    const request = REQUEST_LINE.exec(line);
    const status = request ? null : STATUS_LINE.exec(line);
    const hit = request ?? status;
    if (!hit) continue;
    let url;
    try {
      const parsed = new URL(hit[2]);
      url = parsed.host + parsed.pathname;
    } catch {
      continue;
    }
    if (hit[1] === "POST" && READ_ONLY_POST.test(url)) continue;
    if (hit[1] === "PUT" && /\.cloudfunctions\.appspot\.com\//u.test(url)) continue;
    const key = hit[1] + " " + url;
    if (!writes.has(key))
      writes.set(key, { method: hit[1], url, requests: 0, statuses: [], class: "ok" });
    const entry = writes.get(key);
    if (request) entry.requests += 1;
    else entry.statuses.push(Number(status[3]));
  }
  for (const entry of writes.values()) {
    entry.class =
      entry.requests > 1 && !entry.statuses.every((code) => code >= 200 && code < 300)
        ? "retried"
        : entry.statuses.length < entry.requests
          ? "unanswered"
          : entry.statuses.every((code) => code >= 200 && code < 300)
            ? "ok"
            : "non-2xx";
  }
  return [...writes.values()];
}

/** The CLI output without the signed upload URLs and without any API key value the identity configuration carries. */
export function redactCliText(text) {
  return String(text)
    .replace(
      /https?:\/\/[^\s"'<>]*(?:X-Goog-|Signature=|GoogleAccessId=)[^\s"'<>]*/giu,
      "[REDACTED UPLOAD URL]",
    )
    .replace(/"apiKey"\s*:\s*"[^"]*"/gu, '"apiKey":"[REDACTED]"');
}

/**
 * The CLI result with what its output file shows: the upload events (the deploy only) and every mutating request. The
 * output files are then rewritten without signed URLs and API keys. A file that cannot be read gives `null` for both: the
 * run then cannot tell what the CLI wrote and reports it.
 */
export function withCliLog(result, directory) {
  if (!result?.action) return result;
  const read = (name) => {
    try {
      return readFileSync(join(directory, name), "utf8");
    } catch {
      return null;
    }
  };
  const stdout = read(`cli-${result.action}-stdout.txt`);
  const stderr = read(`cli-${result.action}-stderr.txt`);
  for (const [name, text] of [
    [`cli-${result.action}-stdout.txt`, stdout],
    [`cli-${result.action}-stderr.txt`, stderr],
  ])
    if (text !== null) {
      try {
        writeFileSync(join(directory, name), redactCliText(text), { mode: 0o600 });
      } catch {
        // the file stays as it was; the run directory is private
      }
    }
  return {
    ...result,
    ...(result.action === "deploy"
      ? { uploadEvents: stdout === null ? null : uploadEventsFromCliOutput(stdout) }
      : {}),
    cliWrites: stdout === null ? null : cliWritesFromOutput(stdout),
  };
}

// ---- the inventory the closure compares ---------------------------------------------------------------------

const OWN_SOURCE_COPY = new RegExp("^" + FUNCTION + "/function-source\\.zip$", "u");

/**
 * What differs between the preflight inventory and a later one, by identity and not by count. `before` and `after` carry
 * name lists for `channels`, `triggers`, `subscriptions`, `topics`, `packages` and `services`, and `sourceObjects` with
 * `uploads` and `sources` (the two Gen2 buckets). A list that is `null` (not read to its end) makes the comparison
 * incomplete, which blocks closure like a difference does. `enabled` is the services this run enabled on purpose.
 * The upload bucket must be as it was; the sources bucket may only have gained the build's copy of each function
 * (`<function>/function-source.zip`), which stays and is reported.
 */
export const INVENTORY_KINDS = Object.freeze([
  "channels",
  "triggers",
  "subscriptions",
  "topics",
  "packages",
]);

export function inventoryDifferences({ before, after, enabled = [], kinds = INVENTORY_KINDS }) {
  const differences = [];
  const missing = [];
  const compare = (kind, b, a, allowedAdded = () => false) => {
    if (!Array.isArray(b) || !Array.isArray(a)) return void missing.push(kind);
    const added = a.filter((name) => !b.includes(name));
    const removed = b.filter((name) => !a.includes(name));
    const unexpected = added.filter((name) => !allowedAdded(name));
    if (unexpected.length > 0 || removed.length > 0)
      differences.push({ kind, added: unexpected.toSorted(), removed: removed.toSorted() });
  };
  for (const kind of kinds) compare(kind, before?.[kind], after?.[kind]);
  compare("services", before?.services, after?.services, (name) => enabled.includes(name));
  compare("uploadObjects", before?.sourceObjects?.uploads, after?.sourceObjects?.uploads);
  compare("sourceObjects", before?.sourceObjects?.sources, after?.sourceObjects?.sources, (name) =>
    OWN_SOURCE_COPY.test(name),
  );
  return { complete: missing.length === 0, missing, differences };
}

/**
 * Project IAM changes that are not the CLI's service-agent bindings: a removed binding, or an added member that is not a
 * service account. `changes` is `iamChanges(before, after)` (`role|member` strings), or `null` for an unreadable policy.
 */
export function iamUnexpected(changes) {
  if (!changes) return { complete: false, unexpected: [] };
  return {
    complete: true,
    unexpected: [
      ...changes.removed.map((key) => "removed " + key),
      ...changes.added
        .filter((key) => !key.split("|")[1]?.startsWith("serviceAccount:"))
        .map((key) => "added " + key),
    ],
  };
}
