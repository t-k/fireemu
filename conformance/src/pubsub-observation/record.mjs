import { readFileSync, openSync, closeSync, fsyncSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256, claimSourceRun } from "../pubsub-production/admission.mjs";
import { createLedger, readLedger } from "../pubsub-production/ledger.mjs";
import { describeSource, admit } from "./admission.mjs";
import { makePlan, PROJECT, SUITE } from "./plan.mjs";
import { createMeter } from "./meter.mjs";
import { createWire } from "./wire.mjs";
import { createCredentials } from "./credentials.mjs";
import { createJournal, writeExclusive } from "./journal.mjs";
import { runCell, recoverA2 } from "./scenarios.mjs";

export function parseArgs(args) {
  const result = { mode: "prepare" };
  const valued = new Set(["authority", "descriptor", "packet", "E", "V", "lock", "run-id", "out"]);
  for (let i = 0; i < args.length; i++) {
    const key = args[i].replace(/^--/, "");
    if (["prepare", "record", "a2"].includes(key)) {
      if (result.mode !== "prepare" || result.explicitMode) throw new Error("one mode required");
      result.mode = key;
      result.explicitMode = true;
    } else if (valued.has(key) && args[i].startsWith("--")) {
      if (!args[i + 1] || args[i + 1].startsWith("--") || result[key] !== undefined)
        throw new Error("argument value required once");
      result[key] = args[++i];
    } else throw new Error("unknown recorder option");
  }
  if (result.mode !== "prepare") {
    for (const key of valued) if (!result[key]) throw new Error(`${key} required`);
  } else if (Object.keys(result).some((key) => !["mode", "explicitMode"].includes(key))) {
    throw new Error("prepare takes no authority options");
  }
  return { ...result, runId: result["run-id"], a2: result.mode === "a2" };
}
function recoveryInput(admission, runId) {
  const { scope, descriptor } = admission;
  const original = scope.runOutputs[runId];
  const capturePath = resolve(original, `capture-${runId}.jsonl`),
    ledgerPath = resolve(original, `issued-${runId}.jsonl`);
  const summaryPath = resolve(original, `summary-${runId}.json`);
  const binding = scope.recoveryBindings?.[runId];
  if (
    !binding ||
    ["captureSha256", "issuedSha256", "summarySha256"].some(
      (key) => !/^[a-f0-9]{64}$/.test(binding[key] ?? ""),
    )
  )
    throw new Error("A2 original input pins required");
  const capture = readFileSync(capturePath),
    issued = readFileSync(ledgerPath),
    summaryBytes = readFileSync(summaryPath);
  if (
    capture.length > 83886080 ||
    issued.length > 83886080 ||
    summaryBytes.length > 4194304 ||
    sha256(capture) !== binding.captureSha256 ||
    sha256(issued) !== binding.issuedSha256 ||
    sha256(summaryBytes) !== binding.summarySha256
  )
    throw new Error("A2 original input pin mismatch");
  const summary = JSON.parse(summaryBytes);
  if (
    summary.runId !== runId ||
    summary.sourceHead !== descriptor.head ||
    summary.envelopeId !== scope.envelopeId ||
    summary.project !== PROJECT ||
    summary.suite !== SUITE ||
    summary.packetSha256 !== scope.packetSha256
  )
    throw new Error("A2 original scope mismatch");
  const rows = capture.toString("utf8").trim().split("\n");
  if (rows.length > 20000) throw new Error("A2 capture row cap");
  let last = 0;
  for (const line of rows) {
    const row = JSON.parse(line);
    for (const value of [row.at, row.requestDeadlineAt])
      if (value !== undefined) {
        const at = Date.parse(value);
        if (!Number.isFinite(at)) throw new Error("invalid original timestamp");
        last = Math.max(last, at);
      }
  }
  const elapsedMs = Date.now() - last;
  if (elapsedMs < 600000) throw new Error("A2 minimum age required");
  return { ledgerPath, elapsedMs };
}
export async function main(args = process.argv.slice(2), deps = {}) {
  const options = parseArgs(args);
  if (options.mode === "prepare") {
    const descriptor = (deps.describe ?? describeSource)();
    (deps.print ?? ((value) => process.stdout.write(`${JSON.stringify(value, null, 2)}\n`)))(
      descriptor,
    );
    return descriptor;
  }
  const admission = (deps.admit ?? admit)(options);
  const input = options.a2 ? recoveryInput(admission, options.runId) : null;
  // The default source path has no contingency activation switch and never silently retries a cell.
  claimSourceRun({ out: options.out, runId: options.runId });
  const journal = createJournal(options.out, options.runId);
  const ledgerFd = openSync(resolve(options.out, `issued-${options.runId}.jsonl`), "wx", 0o600);
  const issuedJournal = {
    write: (row) => {
      writeFileSync(ledgerFd, `${JSON.stringify(row)}\n`);
      fsyncSync(ledgerFd);
    },
  };
  const ledger = input
    ? readLedger(input.ledgerPath).withJournal(issuedJournal)
    : createLedger({ journal: issuedJournal });
  const meter = createMeter({ a2: options.a2 });
  const token = (deps.createCredentials ?? createCredentials)();
  const guardedToken = (value) => {
    admission.check();
    return token(value);
  };
  const wire = (deps.createWire ?? createWire)({ meter, journal, getToken: guardedToken });
  let signalled = false;
  let activeStream;
  const interrupted = new AbortController();
  const signals = deps.signals ?? process;
  const originalCall = wire.call,
    originalOpen = wire.open;
  wire.call = (value) => {
    if (signalled && !value.category.startsWith("cleanup")) throw new Error("source signal stop");
    admission.check();
    return originalCall(value);
  };
  wire.open = async (value) => {
    if (signalled) throw new Error("source signal stop");
    admission.check();
    activeStream = await originalOpen(value);
    if (signalled) activeStream.cancel("source-signal");
    return activeStream;
  };
  const stop = () => {
    signalled = true;
    interrupted.abort();
    wire.abortSource?.();
    activeStream?.cancel("source-signal");
    journal.write({ event: "signal-stop" });
  };
  signals.on("SIGINT", stop);
  signals.on("SIGTERM", stop);
  const sleep = (ms) =>
    new Promise((resolve, reject) => {
      if (interrupted.signal.aborted) {
        reject(new Error("source wait stopped"));
        return;
      }
      const abort = () => {
        clearTimeout(timer);
        reject(new Error("source wait stopped"));
      };
      const timer = setTimeout(() => {
        interrupted.signal.removeEventListener("abort", abort);
        resolve();
      }, ms);
      interrupted.signal.addEventListener("abort", abort, { once: true });
    });
  const results = [];
  let resourcesClosed = false,
    recordingComplete = false,
    error = null;
  try {
    journal.write({
      event: "run-start",
      runId: options.runId,
      suite: SUITE,
      project: PROJECT,
      sourceHead: admission.descriptor.head,
      envelopeId: admission.scope.envelopeId,
      packetSha256: admission.scope.packetSha256,
      descriptorSha256: admission.descriptorSha256,
    });
    if (options.a2) {
      meter.enter({ id: "A2", group: "G7", transport: "rest" });
      const recovery = await recoverA2({
        wire,
        ledger,
        runId: options.runId,
        elapsedMs: input.elapsedMs,
      });
      resourcesClosed = recovery.closed;
      results.push(recovery);
    } else {
      for (const cell of makePlan().cells.filter((item) => !item.reserve)) {
        if (signalled) break;
        meter.enter(cell);
        const result = await runCell({
          cell,
          meter,
          wire,
          ledger,
          runId: options.runId,
          journal,
          sleep,
        });
        results.push(result);
        if (!result.complete || !result.cleanupClosed) break;
      }
      resourcesClosed = results.length > 0 && results.every((item) => item.cleanupClosed);
      recordingComplete = results.length === 32 && results.every((item) => item.complete);
    }
  } catch (failure) {
    error = failure.message;
    journal.write({ event: "run-incomplete", error });
  } finally {
    signals.removeListener("SIGINT", stop);
    signals.removeListener("SIGTERM", stop);
    wire.close();
    journal.close();
    closeSync(ledgerFd);
  }
  const summary = {
    schema: 1,
    suite: SUITE,
    project: PROJECT,
    runId: options.runId,
    sourceHead: admission.descriptor.head,
    envelopeId: admission.scope.envelopeId,
    packetSha256: admission.scope.packetSha256,
    resourcesClosed: resourcesClosed && error === null,
    recordingComplete: recordingComplete && !signalled && error === null,
    closureReady: false,
    a2: options.a2,
    signalled,
    error,
    results,
    meter: meter.snapshot(),
    captureSha256: sha256(readFileSync(resolve(options.out, `capture-${options.runId}.jsonl`))),
    issuedSha256: sha256(readFileSync(resolve(options.out, `issued-${options.runId}.jsonl`))),
  };
  writeExclusive(resolve(options.out, `summary-${options.runId}.json`), summary);
  if (!summary.resourcesClosed || (!options.a2 && !summary.recordingComplete))
    (
      deps.setExitCode ??
      ((code) => {
        process.exitCode = code;
      })
    )(2);
  return summary;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  main().catch(() => {
    process.stderr.write("observation recorder refused or incomplete\n");
    process.exitCode = 2;
  });
