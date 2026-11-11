// Runs the setup, the cells and the cleanup of one recording against an injected transport and clock.
// One request is in flight at a time. Every request is journaled with its measured start and latency.
// Nothing here touches the network or the file system: the transport, the clock and the journal are
// parameters, so the whole run is tested on virtual time against a fake production.

import { classify } from "./answer.mjs";
import { CELLS, MIN_GAP_MS, planned } from "./program.mjs";
import { createLedger } from "./ledger.mjs";
import { buildRequest, setupRequests, Refusal } from "./requests.mjs";
import { isOwned } from "./names.mjs";
import { cleanup } from "./cleanup.mjs";

export const CAPS = Object.freeze({
  requests: 260,
  cleanupRequests: 50, // kept free for the cleanup: the cells stop 50 requests before the hard cap
  wallMs: 45 * 60 * 1000,
  cleanupReserveMs: 5 * 60 * 1000,
  lateMs: 250,
  cellOverrunMs: 60000,
});

// Recorded successful maxima plus the margin the observation recorder already used (lane guide
// section 5: a timeout is the recorded latency plus margin, never shorter).
export const timeoutMs = (request) =>
  request.method === "PUT"
    ? 19000
    : request.method === "DELETE"
      ? 13000
      : request.path.includes(":pull")
        ? 25000
        : 10000;

export class StopRun extends Error {}

/** A LIST answer keeps only the names this run owns (and a count of the others); other bodies are kept when small. */
export function journaledBody(request, body, runId) {
  if (body === null || typeof body !== "object") return null;
  if (request.list) {
    const out = {};
    for (const [key, items] of Object.entries(body)) {
      if (!Array.isArray(items)) continue;
      out[key] = items.filter((item) => isOwned(item?.name, runId));
      out.foreign = (out.foreign ?? 0) + items.length - out[key].length;
    }
    return out;
  }
  return JSON.stringify(body).length <= 4096 ? body : null;
}

const resultOf = (answer) =>
  answer.kind === "ok"
    ? "ok"
    : answer.kind === "unknown"
      ? "unknown"
      : answer.status === 404
        ? "notfound"
        : answer.status === 409
          ? "conflict"
          : "error";

export function createRecorder({ runId, transport, clock, journal, cells = CELLS, caps = CAPS }) {
  const ledger = createLedger();
  const begun = clock.now();
  let sent = 0;
  let lastActivityAt = begun;
  const records = [];
  let stopped = null;

  /** Sends one request with ledger bookkeeping; returns the classified answer and timing. */
  async function exec(request, meta, { maintenance = false } = {}) {
    if (stopped && !maintenance) throw new StopRun(stopped);
    if (sent >= (maintenance ? caps.requests : caps.requests - caps.cleanupRequests))
      throw new StopRun("request cap");
    const wallLeft = begun + caps.wallMs - (maintenance ? 0 : caps.cleanupReserveMs) - clock.now();
    if (wallLeft <= 0) throw new StopRun("wall clock cap");
    for (const name of request.targets)
      if (!isOwned(name, runId)) throw new Refusal(`foreign name ${name}`);
    const kindOf = (name) =>
      name.includes("/topics/")
        ? "topic"
        : name.includes("/snapshots/")
          ? "snapshot"
          : "subscription";
    let intent = null;
    if (request.create || request.delete) {
      const name = request.targets[0];
      if (request.delete && ledger.deleting(name))
        throw new Refusal("an unknown delete is never re-sent");
      intent = ledger.intent({
        name,
        action: request.create ? "create" : "delete",
        kind: kindOf(name),
      });
    }
    sent += 1;
    const limit = Math.min(timeoutMs(request), Math.max(1, wallLeft));
    // A dedicated cell keeps one keep-alive connection; a fresh cell opens a new one for every request.
    const conn =
      meta.connPolicy === "fresh" ? `fresh:${sent}` : `${meta.connPolicy ?? "pool"}:${meta.cell}`;
    const raw = await transport.send(request, {
      conn,
      connPolicy: meta.connPolicy ?? "pool",
      timeoutMs: limit,
    });
    lastActivityAt = Math.max(lastActivityAt, raw.completedAt ?? clock.now());
    const answer = classify({ ...raw, headersMs: raw.headersAt - raw.startedAt });
    if (intent !== null) ledger.answer(intent, resultOf(answer));
    // Own reads feed the ledger. A fast 404 can be a cached answer and proves nothing about absence.
    if (request.method === "GET" && !request.list && !request.grpc && !request.path.includes(":")) {
      const name = request.path.replace(/^\/v1\//, "").replace(/\?.*$/, "");
      if (answer.kind === "ok") ledger.read(name, "present");
      else if (answer.kind === "error" && answer.status === 404 && answer.latency === "slow")
        ledger.read(name, "absent");
    }
    const row = {
      ...meta,
      method: request.method,
      path: request.path,
      startedAt: raw.startedAt,
      headersMs: raw.headersAt === undefined ? null : raw.headersAt - raw.startedAt,
      completedMs: raw.completedAt === undefined ? null : raw.completedAt - raw.startedAt,
      status: answer.status,
      kind: answer.kind,
      code: answer.code,
      latency: answer.latency,
      failure: raw.failure ?? null,
      body: journaledBody(request, answer.body, runId),
    };
    journal.write({ event: "request", ...row });
    if (intent !== null && request.create && answer.kind === "unknown") {
      stopped = "unknown create";
    }
    return { answer, raw, row };
  }

  async function runCell(cell) {
    const cellStart = clock.now();
    const actual = [];
    const deadline = cellStart + Math.max(...planned(cell)) + 120000 + caps.cellOverrunMs;
    const done = [];
    const out = { id: cell.id, conn: cell.conn, arm: cell.arm, steps: [], aborted: null };
    records.push(out);
    for (let i = 0; i < cell.steps.length; i += 1) {
      const step = cell.steps[i];
      let target = i === 0 ? cellStart : done[i - 1] + MIN_GAP_MS;
      if (step.at !== undefined) target = Math.max(target, cellStart + step.at);
      if (step.after !== undefined) target = Math.max(target, done[i - 1] + step.after);
      if (step.since !== undefined)
        target = Math.max(target, actual[step.since[0]] + step.since[1]);
      if (clock.now() > deadline) {
        out.aborted = "cell time";
        break;
      }
      await clock.sleepUntil(target);
      let request;
      try {
        request = buildRequest(step, { runId, cellId: cell.id });
      } catch (error) {
        out.aborted = `refused: ${error.message}`;
        stopped = out.aborted;
        journal.write({ event: "refusal", cell: cell.id, step: i, reason: error.message });
        break;
      }
      let result;
      try {
        result = await exec(
          request,
          { cell: cell.id, step: i, op: step.op, connPolicy: cell.conn },
          {},
        );
      } catch (error) {
        if (error instanceof StopRun || error instanceof Refusal) {
          out.aborted = error.message;
          stopped = error instanceof Refusal ? `refused: ${error.message}` : error.message;
          break;
        }
        throw error;
      }
      const startedAt = result.raw.startedAt;
      actual.push(startedAt);
      done.push(result.raw.completedAt ?? clock.now());
      out.steps.push({
        i,
        op: step.op,
        planned: target - cellStart,
        startedMs: startedAt - cellStart,
        late: startedAt - target > caps.lateMs,
        ageMs: actual[cell.arm] === undefined ? null : startedAt - actual[cell.arm],
        status: result.row.status,
        kind: result.row.kind,
        latency: result.row.latency,
        body: result.row.body,
      });
      if (stopped) {
        out.aborted = stopped;
        break;
      }
    }
    return out;
  }

  async function run() {
    for (const request of setupRequests({ runId })) {
      try {
        const { answer } = await exec(
          request,
          { cell: "setup", step: request.id, op: request.id },
          {},
        );
        if (answer.kind !== "ok") {
          stopped = `setup ${request.id} answered ${answer.kind} ${answer.status}`;
          break;
        }
      } catch (error) {
        if (!(error instanceof StopRun)) throw error;
        stopped = error.message;
        break;
      }
    }
    if (!stopped) {
      for (const cell of cells) {
        try {
          await runCell(cell);
        } catch (error) {
          if (!(error instanceof StopRun)) throw error;
          stopped = error.message;
        }
        if (stopped) break;
      }
    }
    // Cleanup always runs, with the reserve the cells did not use.
    let report;
    try {
      report = await cleanup({
        ledger,
        exec,
        clock,
        runId,
        lastActivityAt: () => lastActivityAt,
        journal,
      });
    } catch (error) {
      if (!(error instanceof StopRun)) throw error;
      report = { stopped: error.message };
    }
    return {
      stopped,
      records,
      report,
      ledger,
      sent,
      closureReady: ledger.closureReady(),
      open: ledger.open(),
    };
  }

  /** Asks the recording to stop after the request in flight; the cleanup still runs. */
  const requestStop = (reason) => {
    stopped ??= reason;
  };
  return { run, exec, ledger, records, sentCount: () => sent, requestStop };
}
