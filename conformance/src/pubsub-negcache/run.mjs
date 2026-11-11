import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { performance } from "node:perf_hooks";
import { pathToFileURL } from "node:url";
import { CELLS, requestCount } from "./program.mjs";
import { CAPS, createRecorder } from "./runner.mjs";
import { createWorld, virtualClock } from "./world.mjs";
import { judgeRun } from "./judge.mjs";
import { settleA2, A2_MIN_AGE_MS } from "./a2.mjs";
import { listRequest, kindOfName } from "./requests.mjs";
import { isOwned } from "./names.mjs";
import { createJournal, writeExclusive } from "./journal.mjs";
import { createTransport } from "./transport.mjs";
import {
  assertCredentialsAllowed,
  productionSendApproved,
  SEND_FLAG,
  SEND_FLAG_VALUE,
} from "./guard.mjs";
import { createCredentials } from "../pubsub-observation/credentials.mjs";

/** The gcloud helper is a production client: it is reachable only with the flag, at the moment it is asked. */
function guardedCredentials() {
  assertCredentialsAllowed();
  return createCredentials();
}

const realClock = {
  now: () => performance.now(),
  sleepUntil: (at) =>
    new Promise((resolve) => setTimeout(resolve, Math.max(0, at - performance.now()))),
};
const resolvePath = (root, value) => path.resolve(root, value);

export { SEND_FLAG, SEND_FLAG_VALUE };

export function preflight(env, args, deps = {}) {
  const io = deps.fs ?? fs,
    root = deps.root ?? process.cwd();
  if (
    Object.keys(env).some(
      (k) =>
        (k === "GOOGLE_APPLICATION_CREDENTIALS" ||
          k === "FIREBASE_TOKEN" ||
          k.startsWith("CLOUDSDK_")) &&
        env[k] !== undefined,
    )
  )
    throw new Error("forbidden credential environment variable");
  if (!/^[a-f0-9]{12}$/.test(args.runId ?? ""))
    throw new Error("run id must be 12 lowercase hex characters");
  if (!args.out || io.existsSync(resolvePath(root, args.out)))
    throw new Error("output directory must be new");
  let lock;
  try {
    lock = JSON.parse(io.readFileSync(resolvePath(root, args.lock), "utf8"));
  } catch {
    throw new Error("lock file must exist and contain JSON");
  }
  if (lock.pid !== (deps.pid ?? process.pid) || lock.packetId !== "PUBSUB-NEGCACHE")
    throw new Error("lock ownership or packet mismatch");
  if (
    args.packet &&
    (!io.existsSync(resolvePath(root, args.packet)) ||
      !io.statSync(resolvePath(root, args.packet)).isFile())
  )
    throw new Error("packet file must exist");
  if (args.mode === "record" && !args.packet) throw new Error("packet file required");
}

function parse(args) {
  const [mode, ...rest] = args;
  const allowed = {
    plan: [],
    local: ["run-id", "world-params"],
    record: ["run-id", "out", "lock", "packet"],
    a2: ["run-id", "from", "out", "lock"],
    prelist: ["run-id", "out", "lock"],
  }[mode];
  if (!allowed) throw new Error("unknown mode");
  const options = { mode };
  for (let i = 0; i < rest.length; i += 2) {
    const key = rest[i]?.startsWith("--") ? rest[i].slice(2) : "";
    if (!allowed.includes(key) || rest[i + 1] === undefined || rest[i + 1].startsWith("--"))
      throw new Error("unknown or incomplete option");
    const name = key.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    if (name in options) throw new Error("duplicate option");
    options[name] = rest[i + 1];
  }
  for (const key of allowed.filter((k) => k !== "world-params"))
    if (!(key.replace(/-([a-z])/g, (_, c) => c.toUpperCase()) in options))
      throw new Error(`missing --${key}`);
  if (mode !== "plan" && !/^[a-f0-9]{12}$/.test(options.runId))
    throw new Error("run id must be 12 lowercase hex characters");
  return options;
}

/** One complete, paged LIST per kind (five pages at most). `keep` selects the names worth keeping; the others are counted. */
async function completeLists(transport, keep) {
  const lists = {};
  for (const kind of ["snapshot", "subscription", "topic"]) {
    const names = [];
    let pageToken,
      complete = false;
    for (let page = 0; page < 5; page++) {
      const raw = await transport.send(listRequest(kind, pageToken), {
        conn: "a2",
        connPolicy: "pool",
        timeoutMs: 10000,
      });
      if (!(raw.status >= 200 && raw.status < 300)) break;
      let body;
      try {
        body = JSON.parse(raw.bodyText);
      } catch {
        break;
      }
      if (!body || typeof body !== "object" || Array.isArray(body)) break;
      const items = body[`${kind}s`] ?? [];
      if (
        !Array.isArray(items) ||
        items.some((item) => typeof item.name !== "string") ||
        (body.nextPageToken !== undefined && typeof body.nextPageToken !== "string")
      )
        break;
      names.push(...items.map((item) => item.name));
      pageToken = body.nextPageToken;
      if (!pageToken) {
        complete = true;
        break;
      }
    }
    const kept = names.filter(keep);
    lists[kind] = { complete, names: kept, foreign: names.length - kept.length };
  }
  return lists;
}

export async function main(args, deps = {}) {
  const options = parse(args),
    { mode, runId } = options;
  const print = deps.print ?? ((value) => console.log(JSON.stringify(value)));
  if (mode === "plan") {
    print({ cells: CELLS.length, scheduledRequests: requestCount(), caps: CAPS });
    return 0;
  }
  if (mode === "local") {
    const { faults = {}, ...params } = options.worldParams ? JSON.parse(options.worldParams) : {};
    const clock = virtualClock(),
      transport = createWorld({
        clock,
        params,
        faults: new Map(Object.entries(faults).map(([index, kind]) => [Number(index), kind])),
      });
    const result = await createRecorder({ runId, clock, transport, journal: { write() {} } }).run();
    const { answers, invalid } = judgeRun(result.records);
    print({
      stopped: result.stopped,
      sent: result.sent,
      closureReady: result.closureReady,
      open: result.open,
      answers,
      invalid,
    });
    return result.stopped === null && result.closureReady ? 0 : 2;
  }
  const io = deps.fs ?? fs,
    root = deps.root ?? process.cwd();
  const env = deps.env ?? process.env;
  preflight(env, options, deps);
  // The flag comes from the process environment only; the injected environment is for preflight.
  const approved = productionSendApproved();
  // The real clients (credentials through gcloud, the HTTPS and gRPC transport) exist only with the flag.
  if (!approved && (!deps.transport || (!deps.token && !deps.createCredentials)))
    throw new Error(
      `the production send flag ${SEND_FLAG} is not set; only the launch script sets it`,
    );
  let summary, ageMs;
  if (mode === "a2") {
    const from = resolvePath(root, options.from);
    summary = JSON.parse(io.readFileSync(path.join(from, `summary-${runId}.json`), "utf8"));
    if (summary.runId !== runId) throw new Error("summary run id mismatch");
    const rows = io
      .readFileSync(path.join(from, `capture-${runId}.jsonl`), "utf8")
      .trim()
      .split("\n")
      .map(JSON.parse);
    const last = rows.filter((row) => row.event === "request").at(-1);
    ageMs = (deps.now ?? Date.now)() - Date.parse(last?.at);
    if (!(ageMs >= A2_MIN_AGE_MS))
      throw new Error("A2 needs at least ten minutes after the last request");
  }
  const newToken = () => (deps.createCredentials ?? guardedCredentials)()({ timeoutMs: 30000 });
  let token = deps.token ?? (await newToken());
  const clock = deps.clock ?? realClock;
  let issuedAt = clock.now();
  // A token older than the limit is replaced at a cell boundary (never inside a cell: no credential
  // subprocess between an arming request and its reads). An injected static token is never replaced.
  const refreshMs = deps.tokenRefreshMs ?? 30 * 60 * 1000;
  const beforeCell = async () => {
    if (deps.token !== undefined || clock.now() - issuedAt <= refreshMs) return;
    token = await newToken();
    issuedAt = clock.now();
  };
  const transport = deps.transport ?? createTransport({ getToken: () => token, clock });
  try {
    const out = resolvePath(root, options.out);
    if (mode === "a2") {
      const lists = await completeLists(transport, (name) => isOwned(name, runId));
      const result = settleA2({ open: summary.open, lists, kindOf: kindOfName, ageMs });
      io.mkdirSync(out, { mode: 0o700 });
      writeExclusive(
        path.join(out, `a2-${runId}.json`),
        JSON.stringify({ runId, ageMs, lists, ...result }, null, 2) + "\n",
      );
      print(result);
      return result.stillPresent.length ||
        result.unconfirmed.length ||
        result.presentUnconfirmed.length ||
        result.unreadable.length
        ? 2
        : 0;
    }
    if (mode === "prelist") {
      // Read-only provider-state check before a launch: no resource of any observation run may exist.
      const lists = await completeLists(transport, (name) => name.includes("/fireemu-observe-"));
      io.mkdirSync(out, { mode: 0o700 });
      writeExclusive(
        path.join(out, `prelist-${runId}.json`),
        JSON.stringify({ runId, lists }, null, 2) + "\n",
      );
      const clean = Object.values(lists).every((l) => l.complete === true && l.names.length === 0);
      print({ clean, lists });
      return clean ? 0 : 2;
    }
    const packetSha256 = createHash("sha256")
      .update(io.readFileSync(resolvePath(root, options.packet)))
      .digest("hex");
    const sourceHead =
      deps.sourceHead ??
      execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
    const startedAt = new Date((deps.now ?? Date.now)()).toISOString();
    const journal = createJournal(out, runId);
    const recorder = createRecorder({ runId, transport, clock, journal, beforeCell });
    let signaled = false;
    const onSignal = () => {
      if (!signaled) {
        signaled = true;
        recorder.requestStop("signal");
      }
    };
    process.on("SIGINT", onSignal);
    process.on("SIGTERM", onSignal);
    try {
      const result = await recorder.run();
      const judged = judgeRun(result.records);
      const output = {
        runId,
        packetSha256,
        sourceHead,
        startedAt,
        stopped: result.stopped,
        sent: result.sent,
        closureReady: result.closureReady,
        open: result.open,
        report: result.report,
        records: result.records,
        ledger: result.ledger.snapshot(),
        answers: judged.answers,
        invalid: judged.invalid,
      };
      writeExclusive(
        path.join(out, `summary-${runId}.json`),
        JSON.stringify(output, null, 2) + "\n",
      );
      print(output);
      return result.stopped === null && result.closureReady ? 0 : 2;
    } finally {
      process.off("SIGINT", onSignal);
      process.off("SIGTERM", onSignal);
      journal.close();
    }
  } finally {
    transport.close?.();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (error) => {
      console.error(error.message);
      process.exitCode = 2;
    },
  );
}
