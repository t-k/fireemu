// The one `firebase deploy` of the eight task queue functions: the source copy taken from the pinned commit, the offline
// discovery by the SDK itself, the CLI plan (dry run, deploy, delete), and the readiness reads. The CLI run itself
// (`runCli`, its judgement `cliFailed`, its output parsers) is the scheduled-delivery recorder's, unchanged: it runs the
// pinned firebase-tools once per action and never retries. The upload receipt, the inventory and the IAM comparison are
// the Python Functions check's (work/python-functions-check 650824f6c, deploy.mjs), with the function list made a
// parameter because the ids of this fixture carry the run's suffix.
import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import {
  CODEBASE,
  FIREBASE_FUNCTIONS_VERSION,
  PROJECT,
  REGION,
  ROLES,
  ROLE_IDS,
  functionName,
  functionsOf,
  roleOf,
  suffixOf,
} from "../plan.mjs";

export {
  cliFailed,
  dependencyProblems,
  discoverManifest,
  erroredFunctions,
  escapingLinks,
  runCli,
  unknownWrites,
} from "../../../scheduled-delivery/record/deploy.mjs";
import {
  dependencyProblems,
  discoverManifest,
} from "../../../scheduled-delivery/record/deploy.mjs";

export const READY_POLL_SECONDS = 30;
export const READY_MAX_POLLS = 40;

const DIRECTORY = "conformance/task-queue-functions";
const FIXTURE = DIRECTORY + "/functions";

/**
 * Copies the tracked files of `conformance/task-queue-functions` at `commit` into `target` (git archive, so nothing
 * untracked comes along), writes the run's suffix into `suffix.json` of the copy (the only change to the committed
 * bytes; the function ids and so the queue ids come from it) and the installed dependency tree `depsDir` next to the
 * fixture: firebase-tools resolves firebase-functions from the source directory before it creates anything.
 */
export function prepareSource({ repoRoot, commit, target, depsDir, runId }) {
  if (!/^[0-9a-f]{40}$/.test(commit)) throw new Error("the source commit must be a full SHA");
  mkdirSync(target, { recursive: true, mode: 0o700 });
  const archive = execFileSync("git", ["-C", repoRoot, "archive", commit, DIRECTORY], {
    maxBuffer: 64 * 1024 * 1024,
  });
  execFileSync("tar", ["-x", "-C", target], { input: archive });
  const fixtureDir = join(target, FIXTURE);
  writeFileSync(
    join(fixtureDir, "suffix.json"),
    JSON.stringify({ suffix: suffixOf(runId) }) + "\n",
  );
  if (depsDir)
    cpSync(realpathSync(depsDir), join(fixtureDir, "node_modules"), {
      recursive: true,
      verbatimSymlinks: true,
    });
  return { configPath: join(target, DIRECTORY, "firebase.json"), fixtureDir };
}

/** What the discovered endpoints must declare: the names, the region, the task queue and its settings. */
export function declarationProblems(endpoints, runId) {
  const problems = [];
  const wanted = [...functionsOf(runId)].toSorted();
  const found = Object.keys(endpoints).toSorted();
  if (JSON.stringify(found) !== JSON.stringify(wanted))
    return [`the fixture exports ${found.join(", ")}; expected ${wanted.join(", ")}`];
  for (const name of wanted) {
    const e = endpoints[name];
    const options = ROLES[roleOf(name)];
    if (e.entryPoint !== name) problems.push(`${name}: entry point ${e.entryPoint}`);
    if (e.platform !== "gcfv2") problems.push(`${name}: platform ${e.platform}`);
    if (JSON.stringify(e.region) !== JSON.stringify([REGION]))
      problems.push(`${name}: region ${JSON.stringify(e.region)}, not ["${REGION}"]`);
    const trigger = e.taskQueueTrigger;
    if (trigger === undefined || trigger === null || typeof trigger !== "object")
      problems.push(`${name}: not a task queue function`);
    else {
      // firebase-tools grants a task queue service an invoker only when the manifest names one, so none may be declared.
      if (trigger.invoker !== undefined && trigger.invoker !== null)
        problems.push(`${name}: task queue invoker ${JSON.stringify(trigger.invoker)}`);
      // The SDK writes an option that was not given as null: null is "unset", and key order does not matter.
      const settled = (group) =>
        JSON.stringify(
          Object.fromEntries(
            Object.entries(group ?? {})
              .filter(([, value]) => value !== null && value !== undefined)
              .toSorted(([x], [y]) => x.localeCompare(y)),
          ),
        );
      for (const group of ["retryConfig", "rateLimits"])
        if (settled(trigger[group]) !== settled(options[group]))
          problems.push(
            `${name}: ${group} ${settled(trigger[group])}, not ${settled(options[group])}`,
          );
    }
  }
  return problems;
}

/** Everything about the source copy that can be checked offline. */
export function sourceProblems({
  fixtureDir,
  node,
  directory,
  runId,
  discoverFn = discoverManifest,
  checkDependencies = true,
}) {
  let endpoints;
  const dependencies = checkDependencies ? dependencyProblems(join(fixtureDir)) : [];
  try {
    endpoints = discoverFn({ fixtureDir, node, directory });
  } catch (error) {
    return [
      `the SDK discovery of the fixture failed: ${String(error.stderr ?? error.message).slice(0, 300)}`,
    ];
  }
  return [...dependencies, ...declarationProblems(endpoints, runId)];
}

/** The pinned SDK is the one in the dependency tree (a `node_modules` directory) the deploy resolves it from. */
export function sdkVersionProblems(depsDir) {
  try {
    const found = JSON.parse(
      readFileSync(join(depsDir, "firebase-functions/package.json"), "utf8"),
    ).version;
    return found === FIREBASE_FUNCTIONS_VERSION
      ? []
      : [`firebase-functions is ${found}, not ${FIREBASE_FUNCTIONS_VERSION}`];
  } catch {
    return ["firebase-functions cannot be read from the dependency tree"];
  }
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
 * last; the deploy carries `--force`. The environment is explicit: nothing from the caller's own environment but what
 * is listed.
 */
export function cliPlan(action, options) {
  if (!["deploy", "dry-run", "delete"].includes(action)) throw new Error("unknown CLI action");
  requireAbsolute(options, ["configHome", "configPath", "workDir", "home"]);
  const only = `functions:${CODEBASE}`;
  const args =
    action === "delete"
      ? [
          "functions:delete",
          ...functionsOf(options.runId),
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

// ---- readiness: from lists, no per-function reads ----------------------------------------------------

/**
 * What the lists say about the run's functions: the v2 function list (`state`) and the Cloud Run services (lower-case
 * ids; every name here is lower-case already). A function of this id in another region is `stray`: not ours to delete,
 * so the run stops (preflight) or leaves it for recovery (cleanup).
 */
export function summarize({ v2, run }, runId) {
  const items = new Map((v2?.functions ?? []).map((item) => [item.name, item]));
  const services = new Set((run?.services ?? []).map((s) => String(s.name).split("/").at(-1)));
  const out = {};
  for (const fn of functionsOf(runId)) {
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
export const allActive = (summary) =>
  Object.values(summary).every((entry) => entry?.active === true);
export const nonePresent = (summary) =>
  Object.values(summary).every(
    (entry) => entry?.present === false && entry?.runService !== true && entry?.stray !== true,
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

// The mutating requests the CLI sent, from its own `--debug` output: one `>>> [apiv2][query] <METHOD> <url>` line per request
// and one `<<< [apiv2][status] <METHOD> <url> <code>` line per answer. Reads that use POST and the upload's PUT (settled
// by its receipt) are not mutations of the project.
const REQUEST_LINE = /\[apiv2\]\[query\] (POST|PUT|PATCH|DELETE) (https:\/\/\S+)/u;
const STATUS_LINE = /\[apiv2\]\[status\] (POST|PUT|PATCH|DELETE) (https:\/\/\S+) (\d{3})[ \t]*$/u;
const READ_ONLY_POST = /:(?:getIamPolicy|testIamPermissions|generateUploadUrl)$|\/entries:list$/u;

/**
 * Every mutating request in the CLI output with its answers: `{ method, url, requests, statuses, class }`. The class is
 * "ok" (every request answered 2xx), "unanswered" (fewer answers than requests), "non-2xx" (any other answer) or
 * "retried" (more than one request to the same method and URL, whatever the answers). Anything but
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
      entry.requests > 1
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
    .replace(
      /(?:X-Goog-[A-Za-z-]+|Signature|GoogleAccessId)=[^&\s"'<>]+/giu,
      "[REDACTED SIGNATURE]",
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

const OWN_SOURCE_COPY = new RegExp(
  "^(?:" + ROLE_IDS.join("|") + ")[0-9a-f]{6}/function-source\\.zip$",
  "u",
);

export const INVENTORY_KINDS = Object.freeze([
  "channels",
  "triggers",
  "subscriptions",
  "topics",
  "packages",
  "notifications",
]);

/**
 * What differs between the preflight inventory and a later one, by identity and not by count. `before` and `after` carry
 * name lists for `channels`, `triggers`, `subscriptions`, `topics`, `packages`, `services` and `notifications` (the ids of
 * the default bucket's notification configs), and `sourceObjects` with
 * `uploads` and `sources` (the two Gen2 buckets). A list that is `null` (not read to its end) makes the comparison
 * incomplete, which blocks closure like a difference does. `enabled` is the services this run enabled on purpose.
 * The upload bucket must be as it was; the sources bucket may only have gained the build's copy of each function
 * (`<function>/function-source.zip`), which stays and is reported.
 */
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

const sortKeys = (value) =>
  Array.isArray(value)
    ? value.map(sortKeys)
    : value && typeof value === "object"
      ? Object.fromEntries(
          Object.keys(value)
            .toSorted()
            .map((key) => [key, sortKeys(value[key])]),
        )
      : value;
const stable = (value) => JSON.stringify(sortKeys(value));
const isPlainObject = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const POLICY_META = ["bindings", "etag", "version"];

/**
 * The bindings of a project IAM policy grouped by everything but their members (role, condition and any other field),
 * or `null` when the policy has a shape this does not know: bindings that are not a list of objects with a text role and
 * a list of text members.
 */
function bindingGroups(policy) {
  if (!isPlainObject(policy)) return null;
  const bindings = policy.bindings ?? [];
  if (!Array.isArray(bindings)) return null;
  const groups = new Map();
  for (const binding of bindings) {
    if (
      !isPlainObject(binding) ||
      typeof binding.role !== "string" ||
      !Array.isArray(binding.members) ||
      binding.members.some((m) => typeof m !== "string")
    )
      return null;
    const { members, ...rest } = binding;
    const key = stable(rest);
    const entry = groups.get(key) ?? {
      role: binding.role,
      plain: Object.keys(rest).length === 1,
      members: new Set(),
    };
    for (const member of members) entry.members.add(member);
    groups.set(key, entry);
  }
  return groups;
}

/** True when the policy has a shape `iamPolicyDifferences` can compare. */
export const supportedIamPolicy = (policy) => bindingGroups(policy) !== null;

/**
 * What differs between two project IAM policies (read without `etag` and `version`), judged as the packet's rule: the only
 * change allowed is a service-account member added to a binding (the CLI's service-agent step). A removed member or
 * binding, a changed condition or other binding field, any member that is not a service account, and any other policy
 * field changed (audit configuration among them) is a difference. A policy of a shape this does not know, or a missing
 * one, makes the comparison incomplete.
 */
export function iamPolicyDifferences(before, after) {
  const was = bindingGroups(before);
  const now = bindingGroups(after);
  if (!was || !now) return { complete: false, unexpected: [] };
  const unexpected = [];
  const fieldsOf = (policy) =>
    Object.fromEntries(Object.entries(policy).filter(([key]) => !POLICY_META.includes(key)));
  const fieldsBefore = fieldsOf(before);
  const fieldsAfter = fieldsOf(after);
  for (const key of [
    ...new Set([...Object.keys(fieldsBefore), ...Object.keys(fieldsAfter)]),
  ].toSorted())
    if (stable(fieldsBefore[key]) !== stable(fieldsAfter[key])) unexpected.push("changed " + key);
  for (const [key, group] of was)
    for (const member of [...group.members].toSorted())
      if (!now.get(key)?.members.has(member)) unexpected.push(`removed ${group.role}|${member}`);
  for (const [key, group] of now)
    for (const member of [...group.members].toSorted()) {
      if (was.get(key)?.members.has(member)) continue;
      if (!member.startsWith("serviceAccount:")) unexpected.push(`added ${group.role}|${member}`);
      else if (!was.has(key) && !group.plain)
        unexpected.push(
          `added ${group.role}|${member} in a binding with a condition or other fields`,
        );
    }
  return { complete: true, unexpected };
}

// ---- the shared image repository -----------------------------------------------------------------------------------

const same = (a, b) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null);

/** What differs between the repository policy read before and after. A policy that was not read makes the comparison incomplete. */
export function repositoryDifferences(before, after) {
  if (!before || !after) return { complete: false, differences: [] };
  return {
    complete: true,
    differences: same(before, after) ? [] : [{ kind: "repository", before, after }],
  };
}
