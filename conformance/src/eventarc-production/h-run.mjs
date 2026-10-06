// Coordinator entry: node h-run.mjs --config <private reviewed input.json> [--a2].
import {
  readFileSync,
  mkdirSync,
  writeFileSync,
  appendFileSync,
  openSync,
  fsyncSync,
  closeSync,
  existsSync,
  lstatSync,
  unlinkSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import { execFile } from "node:child_process";
import { isDeepStrictEqual } from "node:util";
import { createBudget, createCapture, createFileJournal } from "../pubsub-production/capture.mjs";
import { createTokenProvider } from "../pubsub-production/token.mjs";
import { withProjectLocks } from "../storage-rules/project-locks.mjs";
import { prepareHSource, discoverH, hCliPlan, runHCli } from "./h-deploy.mjs";
import { recordH, hA2, createHRest } from "./h-record.mjs";
import { hManifest, H_LIMITS } from "./h-script.mjs";
import { ledgerFilesOf, directoryOf } from "./ledger-files.mjs";
import { hProductionEvidence } from "./h-production.mjs";

export const H_A2_RULING =
  "- 2026-10-06 | EVENTARC-H A2 list settlement | decision=APPROVE; for EVENTARC packet H recordings on fireemu-oracle-events, a separate coordinator A2 may use a fresh complete 2xx list (every page, nextPageToken exhausted, page cap not reached, envelope judged against the recorded shape) that omits an exact name, read at least 600 seconds after the recording's latest request, as the absence read in place of a 404, only in five collections: Cloud Functions v2 functions in us-central1, Cloud Run v2 services in us-central1, Eventarc triggers in us-central1, Pub/Sub topics (global) and Pub/Sub subscriptions (global); it closes only a create the run confirmed by its own complete positive list or its own done operation, or that name's own unknown or not-done DELETE; an unknown or operation-pending CREATE is never closed by absence; a managed Run service, trigger, topic or subscription closes only after its function closed; A2 may send one DELETE each for the exact run-owned confirmed retry marker and baseline-absent confirmed firebase channel, only after functions and cascades close, with a complete judged trigger list showing no channel dependents and exact-name read-backs; never resend a prior DELETE; the firebase channel and the retry marker keep their exact-name recorded GET and 404 routes | Claude（委任。オーナーの裁量の委任 2026-09-28） | docs.local/reviews/2026-10-06-eventarc-packet-h-v1-presend-review.md";

/** Replay checkpoints and unanswered intents; never infer ownership from absence or CLI exit. */
export function readHJournal(path) {
  let recording;
  let lastRequestAt = -Infinity;
  let openCli;
  const runId = /issued-([a-f0-9]{12})\.jsonl$/.exec(path)?.[1];
  if (!runId) throw new Error("H requires the original issued journal path");
  for (const file of ledgerFilesOf(directoryOf(path), runId)) {
    const text = readFileSync(file, "utf8");
    const complete = text.endsWith("\n") ? text : text.slice(0, text.lastIndexOf("\n") + 1);
    for (const line of complete.split("\n").filter(Boolean)) {
      const row = JSON.parse(line);
      if (row.kind === "h-state") {
        recording = row.value;
        openCli = null;
      }
      if (row.kind === "cli-issued") openCli = row.value.name;
      if (
        row.kind === "cli-native-issued" &&
        row.value.host === "eventarc.googleapis.com" &&
        row.value.method === "POST" &&
        row.value.path.endsWith("/channels") &&
        recording?.baseline?.status === 404 &&
        !recording.writes.some((w) => w.name === recording.manifest.channel)
      )
        recording.writes.push({
          name: recording.manifest.channel,
          host: "eventarc",
          kind: "channel",
          action: "create",
          state: "unknown",
        });
      if (
        row.kind === "request" ||
        row.kind === "answer" ||
        row.kind === "cli-issued" ||
        row.kind === "cli-answer" ||
        row.kind === "cli-native-issued" ||
        row.kind === "cli-native-answer"
      )
        lastRequestAt = Math.max(lastRequestAt, row.at);
    }
  }
  if (!recording || !Number.isFinite(lastRequestAt))
    throw new Error("H journal has no issued recording");
  if (openCli) recording.cleanup.unconfirmed.push(`cli:${openCli}:interrupted-inventory`);
  recording.lastRequestAt = lastRequestAt;
  return recording;
}

export async function main(argv, env = process.env, io = process, deps = {}) {
  const now = deps.now ?? Date.now;
  let config;
  const a2 = argv.length === 3 && argv[2] === "--a2";
  try {
    if (argv[0] !== "--config" || !argv[1] || !(argv.length === 2 || a2))
      throw new Error("usage: --config <reviewed input.json> [--a2]");
    config = JSON.parse(readFileSync(argv[1], "utf8"));
    if (
      config.project !== "fireemu-oracle-events" ||
      !/^[a-f0-9]{40}$/.test(config.sourceCommit ?? "")
    )
      throw new Error("H requires the reviewed events project and source commit");
    hManifest(config);
    for (const key of [
      "out",
      "sandboxLedger",
      "lockDir",
      "ownerLedger",
      "frozenManifest",
      "adcFile",
      "depsDir",
      "firebaseJs",
    ])
      if (typeof config[key] !== "string" || !config[key]) throw new Error(`H requires ${key}`);
    if (!readFileSync(config.ownerLedger, "utf8").split("\n").includes(H_A2_RULING))
      throw new Error("H requires the exact A2 RULING line before H1 or A2");
  } catch (error) {
    io.stderr.write(`${error.message}\n`);
    return 2;
  }
  const m = hManifest(config);
  const issuedPath = join(config.out, `issued-${m.runId}.jsonl`);
  let recording;
  let exitCode = 1;
  try {
    if (a2) {
      recording = readHJournal(issuedPath);
      if (
        !isDeepStrictEqual(recording.manifest, {
          ...m,
          projectNumber: recording.manifest.projectNumber,
        }) ||
        now() - recording.lastRequestAt < 600_000
      )
        throw new Error("H A2 manifest mismatch or less than ten minutes since latest request");
    }
    mkdirSync(config.out, { recursive: true, mode: 0o700 });
    if (a2) {
      const path = join(config.lockDir, `${m.project}.lock`);
      if (existsSync(path)) {
        const stat = lstatSync(path);
        const raw = readFileSync(path, "utf8");
        const lock = JSON.parse(raw);
        if (
          !stat.isFile() ||
          lock.taskId !== "PUBSUB-EVENTARC" ||
          lock.packetId !== `EVENTARC-H-${m.runId}` ||
          lock.sourceCommit !== config.sourceCommit ||
          !Number.isSafeInteger(lock.pid) ||
          lock.pid <= 0
        )
          throw new Error("H A2 refuses a foreign recovery lock");
        try {
          (deps.checkPid ?? ((pid) => process.kill(pid, 0)))(lock.pid);
          throw new Error("H A2 recorder process is still alive");
        } catch (error) {
          if (error.code !== "ESRCH") throw error;
        }
        const current = lstatSync(path);
        if (
          current.ino !== stat.ino ||
          current.dev !== stat.dev ||
          readFileSync(path, "utf8") !== raw
        )
          throw new Error("H A2 recovery lock changed");
        unlinkSync(path);
      }
    }
    return await withProjectLocks(
      {
        projects: [m.project],
        taskId: "PUBSUB-EVENTARC",
        packetId: `EVENTARC-H-${m.runId}`,
        sourceCommit: config.sourceCommit,
        pid: process.pid,
        acquiredAt: new Date(now()).toISOString(),
        lockDir: config.lockDir,
        legacyLockPath: `${config.sandboxLedger}.lock`,
      },
      async (lease) => {
        const suffix = a2
          ? `-a2-${new Date(now()).toISOString().replace(/[-:]/g, "").replace(/\.\d+/, "")}`
          : "";
        const issued = createFileJournal(join(config.out, `issued-${m.runId}${suffix}.jsonl`));
        const journal = createFileJournal(join(config.out, `capture-${m.runId}${suffix}.jsonl`));
        const capture = createCapture({ journal, now: () => new Date(now()) });
        const controller = new AbortController();
        const stop = () => controller.abort();
        const signals = deps.signals ?? process;
        for (const signal of ["SIGINT", "SIGTERM"]) signals.on(signal, stop);
        let live = recording;
        const note = (kind, value) => {
          if (kind === "h-state") live = value;
          if (live && ["request", "cli-issued", "h-write-issued"].includes(kind))
            issued.write({ at: now(), kind: "h-state", value: live });
          issued.write({ at: now(), kind, value });
        };
        const ledgerFd = openSync(config.sandboxLedger, "a", 0o600);
        const row = (event, extra = {}) => {
          appendFileSync(
            ledgerFd,
            `${JSON.stringify({ ts: new Date(now()).toISOString(), taskId: "PUBSUB-EVENTARC", project: m.project, packetId: `EVENTARC-H-${m.runId}`, runId: m.runId, mode: a2 ? "a2" : "h1", event, ...extra })}\n`,
          );
          fsyncSync(ledgerFd);
        };
        let credentialCalls = 0;
        const token = createTokenProvider({
          now,
          execFile: async (...args) => {
            if (++credentialCalls > 4) throw new Error("H token invocation ceiling");
            if (deps.execToken) return deps.execToken(...args);
            return new Promise((resolve, reject) =>
              execFile(...args, (error, stdout) => (error ? reject(error) : resolve(stdout))),
            );
          },
        });
        const getToken = () => token.get();
        const hosts = {
          usage: "serviceusage",
          firestore: "firestore",
          functions: "cloudfunctions",
          run: "run",
          eventarc: "eventarc",
          pubsub: "pubsub",
          logging: "logging",
          artifact: "artifactregistry",
          publishing: "eventarcpublishing",
        };
        const budget = createBudget(
          a2 ? H_LIMITS.a2 : Object.values(H_LIMITS).reduce((a, b) => a + b, 0) - H_LIMITS.a2,
        );
        const transports = Object.fromEntries(
          Object.entries(hosts).map(([host, service]) => {
            const rest = createHRest({
              base: `https://${service}.googleapis.com`,
              capture,
              budget,
              getToken,
              quotaProject: m.project,
              fetchImpl: deps.fetchImpl,
            });
            return [
              host,
              {
                request: async (spec) => {
                  await lease.verifyHeld();
                  note("request", { host, ...spec });
                  const answer = await lease.dispatch(() => rest.request(spec));
                  note("answer", { host, spec, answer });
                  return answer;
                },
              },
            ];
          }),
        );
        let result;
        try {
          row("started", { reserveUsd: a2 ? 0 : 2 });
          const evidence = { ...(deps.evidence ?? hProductionEvidence), a2ListRuling: true };
          const sleep = deps.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
          if (a2) result = await hA2({ recording, transports, evidence, now, note, sleep });
          else {
            const prepared = (deps.prepare ?? prepareHSource)({
              manifest: m,
              source: fileURLToPath(new URL("../../eventarc-functions/", import.meta.url)),
              target: join(config.out, "source"),
              depsDir: config.depsDir,
            });
            const endpoints = (deps.discover ?? discoverH)({
              manifest: m,
              ...prepared,
              node: process.execPath,
              directory: join(config.out, "discovery"),
            });
            if (
              !isDeepStrictEqual(
                endpoints,
                JSON.parse(readFileSync(config.frozenManifest, "utf8")).endpoints,
              ) ||
              !isDeepStrictEqual(
                JSON.parse(
                  readFileSync(join(config.out, "discovery/functions-manifest.json"), "utf8"),
                ),
                JSON.parse(readFileSync(config.frozenManifest, "utf8")),
              )
            )
              throw new Error("H discovery differs from frozen functions manifest");
            result = await recordH({
              manifest: m,
              transports,
              evidence,
              now,
              sleep,
              note,
              getToken,
              shouldStop: () => controller.signal.aborted,
              makeSdk: deps.makeSdk,
              saveFrame: (frame) => note("h-frame", frame),
              cli: async (name) => {
                // Reserve the entire declared CLI write set before spawn; native debug bytes are fsynced as received.
                note("cli-issued", {
                  name,
                  channel: m.channel,
                  allowance:
                    "FE upload/build/image/managed resources/approved IAM/service identities",
                });
                const paths = Object.fromEntries(
                  ["stdout", "stderr"].map((s) => [s, join(config.out, `${name}-${s}.txt`)]),
                );
                const fds = Object.fromEntries(
                  Object.entries(paths).map(([s, path]) => [s, openSync(path, "wx", 0o600)]),
                );
                try {
                  const home = join(config.out, "cli-home");
                  mkdirSync(home, { recursive: true, mode: 0o700 });
                  const plan = hCliPlan({
                    manifest: m,
                    name,
                    ...prepared,
                    env: {
                      ...env,
                      HOME: home,
                      XDG_CONFIG_HOME: join(home, ".config"),
                      FIREBASE_TOKEN: undefined,
                      GOOGLE_APPLICATION_CREDENTIALS: config.adcFile,
                    },
                  });
                  const answer = await (deps.runCli ?? runHCli)({
                    node: process.execPath,
                    firebaseJs: config.firebaseJs,
                    plan,
                    signal: controller.signal,
                    issuedPath: join(config.out, `issued-${m.runId}${suffix}.jsonl`),
                    save: (stream, chunk) => {
                      appendFileSync(fds[stream], chunk);
                      fsyncSync(fds[stream]);
                    },
                  });
                  note("cli-answer", { name, exitCode: answer.exitCode });
                  return answer;
                } finally {
                  for (const fd of Object.values(fds)) closeSync(fd);
                }
              },
            });
          }
          writeFileSync(
            join(config.out, `summary${suffix}.json`),
            `${JSON.stringify(result, null, 2)}\n`,
            { mode: 0o600 },
          );
          row("finished", {
            outcome: result.closureReady ? "recorded" : "needs-recovery",
            sandboxAtBaseline: result.cleanupReady ?? result.closureReady,
            requests: capture.count(),
          });
          if (result.cleanupReady ?? result.closureReady) lease.confirmClosed();
          io.stdout.write(
            `${JSON.stringify({ closureReady: result.closureReady, stopped: result.stopped ?? null })}\n`,
          );
          exitCode = result.closureReady ? 0 : controller.signal.aborted ? 3 : 1;
          return exitCode;
        } catch (error) {
          row("finished", { outcome: "needs-recovery", sandboxAtBaseline: false });
          io.stderr.write(`${error.message}\n`);
          return 1;
        } finally {
          for (const signal of ["SIGINT", "SIGTERM"]) signals.removeListener(signal, stop);
          issued.close();
          journal.close();
          closeSync(ledgerFd);
        }
      },
    );
  } catch (error) {
    io.stderr.write(`${error.message}\n`);
    return exitCode;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  process.exitCode = await main(process.argv.slice(2));
