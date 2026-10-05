// The command line of the delivery recorder: `check` (local only: the environment, the pins, the source copy
// and its offline discovery) and `record` (the whole recording). The logic is in `main(argv, deps)` so that
// the send path can be tested with fakes in the same process; `bin.mjs` is the thin wrapper that exits.
//
//   node bin.mjs check  --run-dir <dir> --project-number <n> --source-commit <sha> --deps-dir <node_modules>
//                       --node <node 22> --firebase-js <firebase-tools bin>
//   node bin.mjs record <the same> --send --expect-digest <hex>
//   node bin.mjs readback --run-dir <dir> --project-number <n> --run-id <16 hex> --send --expect-digest <hex>
//
// `readback` is read-only (every mutation is refused by the allowlist): the separate read, at least ten minutes
// after the last request of a run, that an unknown answer needs before a close row.
//
// Exit codes: 0 only for a recording (or a read-back) that may be closed; 2 for bad arguments or a failed check; 3
// when the answers need review, a read-back or a recovery; 4 when the recorder stopped on an exception.
import { createHash, randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  closeSync,
  fsyncSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { FIREBASE_TOOLS_VERSION, NODE_VERSION, PROJECT, RUN_ID } from "./plan.mjs";
import { cliPlan, prepareSource, runCli as realRunCli, sourceProblems } from "./deploy.mjs";
import { MAX_REQUESTS, record } from "./run.mjs";
import { READBACK_MAX_REQUESTS, SETTLE_MS, readbackRun } from "./readback.mjs";
import { createTokenSource } from "./token.mjs";

const here = dirname(fileURLToPath(import.meta.url));
export const PACKET_FILES = [
  "record/plan.mjs",
  "record/guard.mjs",
  "record/logs.mjs",
  "record/deploy.mjs",
  "record/run.mjs",
  "record/token.mjs",
  "record/readback.mjs",
  "capture.mjs",
  "fixture/index.js",
  "fixture/package.json",
  "firebase.json",
];

/** The digest of the packet files, each by name and sha256 (the order is fixed). */
export function packetDigest(read = (name) => readFileSync(join(here, "..", name))) {
  return createHash("sha256")
    .update(
      PACKET_FILES.map(
        (name) => name + "\t" + createHash("sha256").update(read(name)).digest("hex") + "\n",
      ).join(""),
    )
    .digest("hex");
}

const FORBIDDEN_ENV = [
  /^GOOGLE_APPLICATION_CREDENTIALS$/,
  /^FIREBASE_TOKEN$/,
  /^CLOUDSDK_/,
  /^GCLOUD_PROJECT$/,
  /_EMULATOR_HOST$/,
  /^GOOGLE_CLOUD_PROJECT$/,
];
export const envProblems = (env) =>
  Object.keys(env)
    .filter((k) => FORBIDDEN_ENV.some((re) => re.test(k)))
    .map((k) => `${k} is set`);

export function parseArgs(argv) {
  const [command, ...rest] = argv;
  const values = {};
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i];
    if (!arg.startsWith("--")) return { error: "unexpected argument " + arg };
    const name = arg.slice(2);
    if (name === "send") values.send = true;
    else {
      const value = rest[++i];
      if (value === undefined || value.startsWith("--")) return { error: arg + " needs a value" };
      values[name] = value;
    }
  }
  return { command, values };
}

const REQUIRED = ["run-dir", "project-number", "source-commit", "deps-dir", "node", "firebase-js"];

/** The checks that need no network. Returns the problems (empty is good). */
export function localChecks({ values, env, deps }) {
  const problems = [...envProblems(env)];
  for (const key of REQUIRED) if (!values[key]) problems.push("--" + key + " is required");
  if (!env.HOME) problems.push("HOME is not set");
  if (problems.length) return problems;
  if (!/^\d{12,13}$/.test(values["project-number"]))
    problems.push("--project-number is 12 or 13 digits");
  if (!/^[0-9a-f]{40}$/.test(values["source-commit"]))
    problems.push("--source-commit is a full SHA");
  if (problems.length) return problems;
  const node = deps.nodeVersion(values.node);
  if (node !== NODE_VERSION) problems.push(`the CLI's Node is ${node}, not ${NODE_VERSION}`);
  const tools = deps.firebaseToolsVersion(values["firebase-js"]);
  if (tools !== FIREBASE_TOOLS_VERSION)
    problems.push(`firebase-tools is ${tools}, not ${FIREBASE_TOOLS_VERSION}`);
  const head = deps.gitHead();
  if (head !== values["source-commit"]) problems.push("HEAD is not the source commit");
  if (deps.gitDirty()) problems.push("the working tree is not clean");
  // Existence only, never read: the CLI authenticates with the owner's application-default credential, which it
  // finds under the real HOME (gcloud's well-known file).
  if (!deps.adcExists(env.HOME))
    problems.push("the application-default credential file is missing under HOME");
  return problems;
}

export const realDeps = {
  nodeVersion: (node) =>
    execFileSync(node, ["--version"], { encoding: "utf8" }).trim().replace(/^v/, ""),
  firebaseToolsVersion: (js) =>
    JSON.parse(readFileSync(join(dirname(js), "../../package.json"), "utf8")).version,
  gitHead: () => execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8", cwd: here }).trim(),
  gitDirty: () =>
    execFileSync("git", ["status", "--porcelain", "--ignored=no"], {
      encoding: "utf8",
      cwd: here,
    }).trim() !== "",
  adcExists: (home) =>
    existsSync(join(home, ".config/gcloud/application_default_credentials.json")),
  signals: (handler) => {
    for (const name of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(name, () => handler(name));
  },
  token: () =>
    execFileSync("gcloud", ["auth", "application-default", "print-access-token"], {
      encoding: "utf8",
      env: { PATH: process.env.PATH, HOME: process.env.HOME },
    }).trim(),
  send: (request) => fetch(request.url, request),
  runCli: realRunCli,
  prepareSource,
  sourceProblems,
  record,
  readback: readbackRun,
  repoRoot: () =>
    execFileSync("git", ["rev-parse", "--show-toplevel"], { encoding: "utf8", cwd: here }).trim(),
};

/** The latest time a run's journal records (a request dispatched or answered), or `null` for no journal. */
export function lastActivity(path) {
  let text;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return null;
  }
  let last = null;
  for (const line of text.split("\n")) {
    if (!line) continue;
    let row;
    try {
      row = JSON.parse(line);
    } catch {
      continue;
    }
    for (const stamp of [row.dispatchAt, row.responseAt]) {
      const at = Date.parse(stamp ?? "");
      if (Number.isFinite(at) && (last === null || at > last)) last = at;
    }
  }
  return last;
}

/** The read-only read-back of a run, at least ten minutes after its last request. */
async function readbackCommand({ values, env, deps, out, err, digest }) {
  const problems = envProblems(env);
  for (const key of ["run-dir", "project-number", "run-id"])
    if (!values[key]) problems.push("--" + key + " is required");
  if (!env.HOME) problems.push("HOME is not set");
  if (values["project-number"] && !/^\d{12,13}$/.test(values["project-number"]))
    problems.push("--project-number is 12 or 13 digits");
  if (values["run-id"] && !RUN_ID.test(values["run-id"]))
    problems.push("--run-id is 16 hexadecimal digits");
  if (problems.length) {
    err("check failed:\n" + problems.map((p) => "- " + p).join("\n"));
    return 2;
  }
  if (!values.send || values["expect-digest"] !== digest) {
    err(
      "readback needs --send and the approved --expect-digest; this packet's digest is " + digest,
    );
    return 2;
  }
  const runDir = values["run-dir"];
  const runId = values["run-id"];
  const last = lastActivity(join(runDir, "journal-" + runId + ".jsonl"));
  if (last === null) {
    err("there is no journal of run " + runId + " in the run directory");
    return 2;
  }
  const waited = (deps.now ?? Date.now)() - last;
  if (waited < SETTLE_MS) {
    err(
      "the last request of run " +
        runId +
        " was " +
        Math.floor(waited / 1000) +
        " seconds ago; wait until ten minutes have passed",
    );
    return 2;
  }
  const stamp = String((deps.now ?? Date.now)());
  const journal = openSync(join(runDir, "readback-" + runId + "-" + stamp + ".jsonl"), "wx", 0o600);
  try {
    const result = await deps.readback({
      runId,
      projectNumber: values["project-number"],
      accessToken: deps.token(),
      save: async (row) => {
        writeSync(journal, JSON.stringify(row) + "\n");
        fsyncSync(journal);
      },
      send: deps.send,
    });
    writeFileSync(
      join(runDir, "readback-result-" + runId + "-" + stamp + ".json"),
      JSON.stringify(result, null, 2) + "\n",
      { mode: 0o600 },
    );
    out(
      JSON.stringify(
        {
          runId,
          allAbsent: result.allAbsent,
          attempted: result.attempted,
          unknown: result.unknown,
        },
        null,
        2,
      ),
    );
    return result.allAbsent ? 0 : 3;
  } catch (error) {
    err("the read-back stopped: " + String(error?.message));
    return 4;
  } finally {
    closeSync(journal);
  }
}

export async function main(
  argv,
  {
    env = process.env,
    deps = realDeps,
    out = console.log,
    err = console.error,
    digest = packetDigest(),
  } = {},
) {
  const parsed = parseArgs(argv);
  if (parsed.error || !["check", "record", "readback"].includes(parsed.command)) {
    err(parsed.error ?? "the command is check, record or readback");
    return 2;
  }
  const { command, values } = parsed;
  if (command === "readback") {
    out(
      JSON.stringify(
        { project: PROJECT, command, maxRequests: READBACK_MAX_REQUESTS, packetDigest: digest },
        null,
        2,
      ),
    );
    return readbackCommand({ values, env, deps, out, err, digest });
  }
  out(
    JSON.stringify(
      { project: PROJECT, command, maxRequests: MAX_REQUESTS, packetDigest: digest },
      null,
      2,
    ),
  );
  const problems = localChecks({ values, env, deps });
  if (problems.length) {
    err("check failed:\n" + problems.map((p) => "- " + p).join("\n"));
    return 2;
  }
  const runDir = values["run-dir"];
  mkdirSync(runDir, { recursive: true, mode: 0o700 });
  const sourceDir = join(runDir, "source");
  const prepared = deps.prepareSource({
    repoRoot: deps.repoRoot(),
    commit: values["source-commit"],
    target: sourceDir,
    depsDir: values["deps-dir"],
  });
  const source = deps.sourceProblems({
    fixtureDir: prepared.fixtureDir,
    node: values.node,
    directory: join(runDir, "discovery"),
  });
  if (source.length) {
    err("the source copy failed its offline checks:\n" + source.map((p) => "- " + p).join("\n"));
    return 2;
  }
  if (command === "check") {
    out("check passed: nothing was sent");
    return 0;
  }
  if (!values.send || values["expect-digest"] !== digest) {
    err("record needs --send and the approved --expect-digest; this packet's digest is " + digest);
    return 2;
  }
  const runId = randomBytes(8).toString("hex");
  const journal = openSync(join(runDir, "journal-" + runId + ".jsonl"), "a", 0o600);
  // The token is asked for again when it is about 40 minutes old (at most twice): a run can outlast one token.
  const tokenSource = createTokenSource({ printToken: deps.token, now: deps.now });
  const accessToken = await tokenSource();
  const send = async (request) => {
    const current = await tokenSource();
    const response = await deps.send({
      ...request,
      headers: { ...request.headers, authorization: "Bearer " + current },
    });
    if (current === accessToken) return response;
    // The capture checks answers against the first token only: a refreshed one is checked here.
    const bytes = Buffer.from(await response.arrayBuffer());
    if (bytes.toString("utf8").includes(current))
      throw new Error("response reflected a credential; capture stopped");
    return { status: response.status, headers: response.headers, arrayBuffer: async () => bytes };
  };
  const signal = { aborted: false };
  deps.signals?.((name) => {
    if (signal.aborted) err(name + ": a stop is already under way; wait for the cleanup");
    else {
      signal.aborted = true;
      err(name + ": stopping at the next request; the cleanup runs, do not kill the recorder");
    }
  });
  const configHome = join(runDir, "cli-config");
  mkdirSync(configHome, { recursive: true, mode: 0o700 });
  const runCli = ({ action }) =>
    deps.runCli({
      action,
      plan: cliPlan(action, {
        configHome,
        configPath: prepared.configPath,
        workDir: dirname(prepared.configPath),
        home: env.HOME,
        path: dirname(values.node) + ":" + (env.PATH ?? ""),
      }),
      firebaseJs: values["firebase-js"],
      node: values.node,
      directory: join(runDir, "cli"),
    });
  let result;
  try {
    result = await deps.record({
      runId,
      projectNumber: values["project-number"],
      accessToken,
      save: async (row) => {
        writeSync(journal, JSON.stringify(row) + "\n");
        fsyncSync(journal);
      },
      send,
      runCli,
      signal,
    });
  } catch (error) {
    closeSync(journal);
    writeFileSync(
      join(runDir, "result-" + runId + ".json"),
      JSON.stringify(
        { outcome: "calendar-delivery-recorder-threw", message: String(error?.message) },
        null,
        2,
      ) + "\n",
      { mode: 0o600 },
    );
    err("the recorder stopped: " + String(error?.message));
    return 4;
  }
  closeSync(journal);
  writeFileSync(join(runDir, "result-" + runId + ".json"), JSON.stringify(result, null, 2) + "\n", {
    mode: 0o600,
  });
  out(
    JSON.stringify(
      {
        runId,
        outcome: result.outcome,
        closureReady: result.closureReady,
        readBackRequired: result.readBackRequired,
        attempted: result.attempted,
      },
      null,
      2,
    ),
  );
  return result.closureReady ? 0 : 3;
}
