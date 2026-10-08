// Coordinator entry: node w-run.mjs --config <reviewed input.json> [--a2].
import {
  readFileSync,
  appendFileSync,
  mkdirSync,
  writeFileSync,
  openSync,
  fsyncSync,
  closeSync,
  existsSync,
  lstatSync,
  unlinkSync,
  realpathSync,
} from "node:fs";
import { dirname, join, delimiter, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { createHash } from "node:crypto";
import { execFile, execFileSync } from "node:child_process";
import { isDeepStrictEqual } from "node:util";
import {
  createBudget,
  createCapture,
  createFileJournal,
  sanitize,
} from "../pubsub-production/capture.mjs";
import { createTokenProvider } from "../pubsub-production/token.mjs";
import { withProjectLocks } from "../storage-rules/project-locks.mjs";
import { createHRest } from "./h-record.mjs";
import { ledgerFilesOf, directoryOf } from "./ledger-files.mjs";
import { recordW, wManifest, wAdmission, W_A2_RULING } from "./w.mjs";

export function readWJournal(path) {
  const runId = /issued-([a-f0-9]{12})\.jsonl$/.exec(path)?.[1];
  if (!runId) throw new Error("W requires the original issued journal");
  let recording,
    lastRequestAt = -Infinity;
  for (const file of ledgerFilesOf(directoryOf(path), runId)) {
    const text = readFileSync(file, "utf8");
    const complete = text.endsWith("\n") ? text : text.slice(0, text.lastIndexOf("\n") + 1);
    for (const line of complete.split("\n").filter(Boolean)) {
      const row = JSON.parse(line);
      if (row.kind === "w-state") recording = row.value;
      if (["request", "answer"].includes(row.kind)) lastRequestAt = Math.max(lastRequestAt, row.at);
    }
  }
  if (!recording || !Number.isFinite(lastRequestAt))
    throw new Error("W journal has no issued recording");
  recording.lastRequestAt = lastRequestAt;
  return recording;
}

export async function main(argv, env = process.env, io = process, deps = {}) {
  const now = deps.now ?? Date.now;
  const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
  const a2 = argv.length === 3 && argv[2] === "--a2";
  let config, m, recording, ledger;
  try {
    if (argv[0] !== "--config" || !argv[1] || !(argv.length === 2 || a2))
      throw new Error("usage: --config <reviewed input.json> [--a2]");
    if (
      process.version !== "v24.14.0" ||
      env.PATH?.split(delimiter)[0] !== dirname(realpathSync(process.execPath)) ||
      !env.PATH.split(delimiter).includes("/etc/profiles/per-user/tk/bin")
    )
      throw new Error("W requires real Node 24.14.0 first on PATH and the gcloud bin directory");
    config = JSON.parse(readFileSync(argv[1], "utf8"));
    m = wManifest(config);
    if (a2 && ["w-shape", "w-upper-counter"].includes(m.stage))
      throw new Error("W shape A2 requires a separate ruling");
    if (
      !/^[a-f0-9]{40}$/.test(config.sourceCommit ?? "") ||
      config.reserveUsd !== 0.05 ||
      config.packetReserveUsd !== 0.15 ||
      config.parentBudgetUsd !== 14
    )
      throw new Error("W requires source pins and ledger 972 budget");
    for (const key of ["out", "sandboxLedger", "lockDir", "ownerLedger", "packetDir"])
      if (typeof config[key] !== "string" || !config[key]) throw new Error(`W requires ${key}`);
    const descriptor = JSON.parse(
      readFileSync(join(config.packetDir, "w-descriptor.json"), "utf8"),
    );
    if (
      descriptor.sourceCommit !== config.sourceCommit ||
      descriptor.status !== "frozen" ||
      !descriptor.executions.some((e) => e.runId === m.runId && e.stage === m.stage)
    )
      throw new Error("W packet is not coordinator-frozen for this source and execution");
    if (
      (
        deps.head ?? (() => execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim())
      )() !== config.sourceCommit
    )
      throw new Error("W checkout HEAD mismatch");
    for (const [path, digest] of Object.entries(descriptor.sourceHashes))
      if (hash(readFileSync(path)) !== digest) throw new Error("W recorder source changed");
    for (const [path, digest] of Object.entries(descriptor.artifactHashes))
      if (hash(readFileSync(join(config.packetDir, path))) !== digest)
        throw new Error("W packet artifact changed");
    ledger = readFileSync(config.ownerLedger, "utf8").split("\n");
    if (!ledger.includes(W_A2_RULING)) throw new Error("W requires the exact A2 ruling");
    const envelopeId = `EVENTARC-W-${m.runId}`;
    const eBody = descriptor.envelopeBodies[m.stage];
    const vBody = `decision=APPROVE; envelopeId=${envelopeId}; packetSha256=${descriptor.artifactHashes["eventarc-packet-w.md"]}; checklistSha256=${descriptor.artifactHashes["w-checklist.md"]}; mutationSha256=${descriptor.artifactHashes["w-mutation-report.md"]}; descriptorSha256=${hash(readFileSync(join(config.packetDir, "w-descriptor.json")))}; sourceCommit=${config.sourceCommit}`;
    for (const [topic, body] of [
      ["EVENTARC-PACKET-W envelope", eBody],
      ["EVENTARC-PACKET-W", vBody],
    ]) {
      const matches = ledger.filter((line) => {
        const c = line.split(" | ");
        return (
          c.length === 5 &&
          /^- \d{4}-\d{2}-\d{2}$/.test(c[0]) &&
          c[1] === topic &&
          c[2] === body &&
          c[3] &&
          c[4]
        );
      });
      if (typeof body !== "string" || matches.length !== 1)
        throw new Error("W exact E/V admission absent or duplicate");
    }
    if (
      ledger.some(
        (line) =>
          line.includes("REVOKED") &&
          (line.includes(envelopeId) ||
            line.includes(descriptor.artifactHashes["eventarc-packet-w.md"])),
      )
    )
      throw new Error("W approval revoked");
    if (["w1", "w2"].includes(m.stage)) {
      const bytes = readFileSync(config.checkpoint);
      const prior = JSON.parse(bytes);
      if (
        hash(bytes) !== config.checkpointSha256 ||
        prior.manifest.stage !== (m.stage === "w1" ? "w0" : "w1") ||
        prior.manifest.project !== m.project ||
        prior.manifest.runId === m.runId ||
        prior.stopped ||
        !prior.cleanupReady ||
        !prior.evidenceComplete ||
        !isDeepStrictEqual(m.prerequisite, {
          ...prior.boundary,
          ...(m.stage === "w2" ? { layer: prior.layer } : {}),
        })
      )
        throw new Error("W prerequisite checkpoint changed or incomplete");
      const expected = wAdmission({
        ...m,
        sourceCommit: config.sourceCommit,
        checkpointSha256: config.checkpointSha256,
        date: "2026-10-07",
      }).split(" | ");
      if (
        !ledger.some((line) => {
          const c = line.split(" | ");
          return (
            c.length === 5 &&
            /^- \d{4}-\d{2}-\d{2}$/.test(c[0]) &&
            c[1] === expected[1] &&
            c[2] === expected[2] &&
            c[3] &&
            c[4]
          );
        })
      )
        throw new Error("W checkpoint-bound stage admission absent");
    }
    if (a2) {
      recording = readWJournal(join(config.out, `issued-${m.runId}.jsonl`));
      if (
        !isDeepStrictEqual(recording.manifest, m) ||
        recording.sourceCommit !== config.sourceCommit ||
        now() - recording.lastRequestAt < 600_000 ||
        (recording.a2Requests ?? 0) >= 38
      )
        throw new Error("W A2 identity, spacing, request or wall cap mismatch");
    }
  } catch (error) {
    io.stderr.write(`${error.message}\n`);
    return 2;
  }
  try {
    mkdirSync(config.out, { recursive: true, mode: 0o700 });
    if (a2) {
      const path = join(config.lockDir, `${m.project}.lock`);
      if (existsSync(path)) {
        const stat = lstatSync(path),
          raw = readFileSync(path, "utf8"),
          lock = JSON.parse(raw);
        if (
          !stat.isFile() ||
          lock.taskId !== "PUBSUB-EVENTARC" ||
          lock.packetId !== `EVENTARC-W-${m.runId}` ||
          lock.sourceCommit !== config.sourceCommit ||
          !Number.isSafeInteger(lock.pid) ||
          lock.pid <= 0
        )
          throw new Error("W A2 refuses a foreign lock");
        try {
          (deps.checkPid ?? ((pid) => process.kill(pid, 0)))(lock.pid);
          throw new Error("W recorder process is alive");
        } catch (error) {
          if (error.code !== "ESRCH") throw error;
        }
        const current = lstatSync(path);
        if (
          current.ino !== stat.ino ||
          current.dev !== stat.dev ||
          readFileSync(path, "utf8") !== raw
        )
          throw new Error("W recovery lock changed");
        unlinkSync(path);
      }
    }
    return await withProjectLocks(
      {
        projects: [m.project],
        taskId: "PUBSUB-EVENTARC",
        packetId: `EVENTARC-W-${m.runId}`,
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
        const controller = new AbortController(),
          signals = deps.signals ?? process;
        const stop = () => controller.abort();
        for (const signal of ["SIGINT", "SIGTERM"]) signals.on(signal, stop);
        const deadline = now() + (a2 ? 45 * 60_000 : m.wallMs);
        const ledgerFd = openSync(config.sandboxLedger, "a", 0o600);
        const row = (event, extra = {}) => {
          appendFileSync(
            ledgerFd,
            `${JSON.stringify({ ts: new Date(now()).toISOString(), taskId: "PUBSUB-EVENTARC", project: m.project, packetId: `EVENTARC-W-${m.runId}`, envelopeId: `EVENTARC-W-${m.runId}`, estimatedUsd: a2 ? 0 : m.reserveUsd, lockRetained: true, runId: m.runId, mode: a2 ? "a2" : m.stage, event, ...extra })}\n`,
          );
          fsyncSync(ledgerFd);
        };
        let live = recording,
          credentialCalls = 0;
        const note = (kind, value) => {
          if (kind === "w-state") {
            value.sourceCommit = config.sourceCommit;
            live = value;
          }
          issued.write({ at: now(), kind, value: sanitize(value) });
        };
        const token = createTokenProvider({
          now,
          execFile: (...args) => {
            if (++credentialCalls > 4) throw new Error("W credential invocation ceiling");
            if (deps.execToken) return deps.execToken(...args);
            return new Promise((accept, reject) =>
              execFile(...args, (error, stdout) => (error ? reject(error) : accept(stdout))),
            );
          },
        });
        const budget = createBudget(a2 ? 38 - (recording.a2Requests ?? 0) : 86);
        const transports = Object.fromEntries(
          Object.entries({
            usage: "serviceusage",
            eventarc: "eventarc",
            publishing: "eventarcpublishing",
            pubsub: "pubsub",
          }).map(([host, service]) => {
            let emitted, timeoutMs;
            const rest = createHRest({
              base: `https://${service}.googleapis.com`,
              getToken: () => token.get(),
              quotaProject: m.project,
              budget,
              capture: {
                ...capture,
                record: (entry) =>
                  capture.record({
                    ...entry,
                    ...(emitted
                      ? { requestBytes: Buffer.byteLength(emitted), requestSha256: hash(emitted) }
                      : {}),
                  }),
              },
              fetchImpl: (address, options) => {
                if (now() + timeoutMs > deadline) throw new Error("W outbound wall cap");
                return (deps.fetchImpl ?? fetch)(address, {
                  ...options,
                  redirect: "manual",
                  ...(emitted === undefined ? {} : { body: emitted }),
                });
              },
            });
            return [
              host,
              {
                request: async (spec) => {
                  await lease.verifyHeld();
                  emitted = spec.rawBody;
                  timeoutMs = spec.timeoutMs;
                  // The recipe and exact hash reconstruct the emitted bytes without recording credentials or huge strings.
                  note("request", {
                    host,
                    method: spec.method,
                    path: spec.path,
                    ...(spec.recipe ? { recipe: spec.recipe } : { body: spec.body }),
                  });
                  const answer = await lease.dispatch(() => rest.request(spec));
                  note("answer", { host, method: spec.method, path: spec.path, answer });
                  return answer;
                },
              },
            ];
          }),
        );
        try {
          row("started", { reserveUsd: a2 ? 0 : m.reserveUsd });
          const result = await recordW({
            manifest: m,
            transports,
            now,
            sleep: deps.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms))),
            note,
            shouldStop: () => controller.signal.aborted,
            recording,
          });
          const output = join(config.out, `summary${suffix}.json`),
            fd = openSync(output, "wx", 0o600);
          try {
            writeFileSync(fd, `${JSON.stringify(result, null, 2)}\n`);
            fsyncSync(fd);
          } finally {
            closeSync(fd);
          }
          row("finished", {
            outcome: result.closureReady
              ? "recorded"
              : result.cleanupReady
                ? "stopped-for-review"
                : "needs-recovery",
            sandboxAtBaseline: result.cleanupReady,
            requests: budget.used(),
            estimatedUsd: a2 || budget.used() === 0 ? 0 : m.reserveUsd,
            lockRetained: !result.cleanupReady,
          });
          if (result.cleanupReady && budget.used() > 0) lease.confirmClosed();
          io.stdout.write(
            `${JSON.stringify({ stage: m.stage, runId: m.runId, requests: budget.used(), stopped: result.stopped, cleanupReady: result.cleanupReady, evidenceComplete: result.evidenceComplete, lockRetained: !result.cleanupReady })}\n`,
          );
          return result.cleanupReady && !result.stopped ? 0 : 3;
        } catch (error) {
          row("finished", {
            outcome: !a2 && budget.used() === 0 ? "stopped-clean" : "needs-recovery",
            sandboxAtBaseline: !a2 && budget.used() === 0,
            requests: budget.used(),
            estimatedUsd: a2 || budget.used() === 0 ? 0 : m.reserveUsd,
            lockRetained: a2 || budget.used() > 0,
          });
          throw error;
        } finally {
          closeSync(ledgerFd);
          if (live) note("w-state", live);
          for (const signal of ["SIGINT", "SIGTERM"]) signals.off(signal, stop);
          issued.close();
          journal.close();
        }
      },
    );
  } catch (error) {
    io.stderr.write(`${error.message}\n`);
    return 3;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  process.exitCode = await main(process.argv.slice(2));
