import { isDeepStrictEqual } from "node:util";
import { makePlan, SUITE } from "./plan.mjs";
import { normalizeOutcome } from "../pubsub-production/outcome.mjs";
import {
  canonicalStatus,
  createBindings,
  judgeRow,
} from "../pubsub-production/stream-dlq-compare-core.mjs";

const decision = (verdict, reason) => ({ verdict, reason });
const aggregate = (rows, debts) =>
  rows.some((r) => r.verdict === "DIVERGES")
    ? "DIVERGES"
    : debts.length || !rows.length || rows.some((r) => r.verdict !== "MATCH")
      ? "NOT_COMPARABLE"
      : "MATCH";
const contains = (value, key) =>
  value &&
  typeof value === "object" &&
  (Object.hasOwn(value, key) ||
    Object.entries(value).some(
      ([k, v]) => !["labels", "attributes", "tags"].includes(k) && contains(v, key),
    ));
const successful = (row) =>
  row.transport === "grpc"
    ? canonicalStatus(row.response.code) === "OK"
    : row.response.status >= 200 && row.response.status < 300;

export function prepareObservation(input) {
  const {
    rows,
    packet,
    descriptor,
    summary,
    packetSha256,
    descriptorSha256,
    evidenceKind,
    verifiedFrames = new Set(),
  } = input;
  if (!Array.isArray(rows) || !rows.length || rows.length > 20000)
    throw new Error("capture row bound");
  const starts = rows.filter((r) => r.event === "run-start");
  const start = starts[0];
  if (
    starts.length !== 1 ||
    start !== rows[0] ||
    packet.suite !== SUITE ||
    !isDeepStrictEqual(packet.plan, makePlan()) ||
    descriptor.head !== packet.sourceHead ||
    packet.descriptorSha256 !== descriptorSha256 ||
    !packet.runIds.includes(start.runId) ||
    !/^[0-9a-f]{12}$/.test(start.runId)
  )
    throw new Error("run/packet binding");
  for (const key of ["suite", "sourceHead", "packetSha256", "descriptorSha256"]) {
    const expected =
      key === "packetSha256"
        ? packetSha256
        : key === "descriptorSha256"
          ? descriptorSha256
          : packet[key];
    if (start[key] !== expected) throw new Error(`start binding ${key}`);
  }
  for (const key of ["suite", "runId", "sourceHead", "packetSha256", "envelopeId"])
    if (summary[key] !== start[key]) throw new Error(`summary binding ${key}`);
  if (
    summary.a2 !== false ||
    !Array.isArray(summary.results) ||
    !["fixture", "production", "local"].includes(evidenceKind)
  )
    throw new Error("summary/evidence binding");
  const cells = packet.plan.cells
    .filter((c) => !c.reserve)
    .map((c) => ({ ...c, exchanges: [], frames: [], events: [], result: null, debts: [] }));
  const byCell = new Map(cells.map((c) => [c.id, c]));
  const dispatches = new Map();
  const answered = new Set();
  let previousAt = -Infinity;
  for (const [i, row] of rows.entries()) {
    const at = Date.parse(row.at);
    if (row.n !== i + 1 || !Number.isFinite(at) || at < previousAt)
      throw new Error("capture sequence/chronology");
    previousAt = at;
    const cell = byCell.get(row.cellId);
    if (row.cellId !== undefined && !cell) throw new Error("undeclared or unused reserve cell");
    if (row.event === "request-dispatch") {
      if (
        !cell ||
        !Number.isSafeInteger(row.requestId) ||
        row.requestId < 1 ||
        dispatches.has(row.requestId) ||
        !["rest", "grpc"].includes(row.transport) ||
        typeof row.method !== "string" ||
        !row.request ||
        typeof row.request !== "object"
      )
        throw new Error("invalid dispatch pair");
      dispatches.set(row.requestId, row);
    } else if (row.event === "response") {
      const dispatch = dispatches.get(row.requestId);
      if (
        !dispatch ||
        answered.has(row.requestId) ||
        ["cellId", "method", "transport"].some((k) => dispatch[k] !== row[k])
      )
        throw new Error("invalid response pair");
      if (!Number.isFinite(row.durationMs) || row.durationMs < 0)
        throw new Error("invalid duration");
      answered.add(row.requestId);
      const response = normalizeOutcome(row.reply);
      if (
        row.method === "UpdateSubscription" &&
        response.ok === true &&
        (typeof dispatch.request.subscription?.name !== "string" ||
          response.body?.name !== dispatch.request.subscription.name)
      )
        response.unknown = true;
      cell.exchanges.push({
        n: row.n,
        dispatchN: dispatch.n,
        at: dispatch.at,
        durationMs: row.durationMs,
        case: `${cell.id}/${row.transport}`,
        transport: row.transport,
        op: row.method[0].toLowerCase() + row.method.slice(1),
        method: row.method,
        category: dispatch.category,
        request: {
          body: dispatch.request,
          ...(dispatch.routeName ? { routeName: dispatch.routeName } : {}),
        },
        response,
      });
    } else if (row.event === "case-result") {
      if (!cell || cell.result) throw new Error("duplicate case result");
      cell.result = row;
    } else if (row.event === "case-budget-overrun") {
      if (!cell?.result || row.complete !== false || row.budgetOverrun !== true)
        throw new Error("invalid post-persistence case result");
      cell.result = row;
    } else if (row.event === "stream-frame") {
      if (!cell || !["in", "out"].includes(row.direction)) throw new Error("invalid stream frame");
      cell.frames.push({ ...row, verified: verifiedFrames.has(row.n) });
    }
    if (cell && row.event.startsWith("stream-")) cell.events.push(row);
  }
  for (const [id, dispatch] of dispatches)
    if (!answered.has(id))
      byCell.get(dispatch.cellId).debts.push(`missing response for dispatch n${dispatch.n}`);
  const summaryCells = new Map();
  for (const result of summary.results) {
    const cell = byCell.get(result.cellId);
    if (!cell || summaryCells.has(result.cellId)) throw new Error("invalid summary result");
    summaryCells.set(result.cellId, result);
    const captured =
      cell.result &&
      Object.fromEntries(
        Object.entries(cell.result).filter(([k]) => !["n", "at", "event"].includes(k)),
      );
    if (!isDeepStrictEqual(captured, result)) throw new Error("captured/summary result mismatch");
  }
  for (const cell of cells) {
    if (
      !cell.result ||
      !summaryCells.has(cell.id) ||
      cell.result.complete !== true ||
      cell.result.budgetOverrun ||
      cell.result.cleanupClosed !== true
    )
      cell.debts.push("cell completion/cleanup witness missing or incomplete");
    if (cell.group === "G4")
      cell.debts.push(
        "native stream timing and causal witness requires dedicated replay; frame equality alone is insufficient",
      );
    if (cell.frames.some((f) => !f.verified)) cell.debts.push("native frame blob proof missing");
  }
  return {
    schema: 1,
    evidenceKind,
    runId: start.runId,
    sourceHead: start.sourceHead,
    packetSha256,
    descriptorSha256,
    cells,
    reservations: packet.plan.cells
      .filter((c) => c.reserve)
      .map((c) => ({ ...c, semanticWitnessExists: false })),
    parentClosureReady: false,
    replayExecuted: false,
  };
}

export function compareObservation(source, local) {
  if (
    source.runId !== local.runId ||
    source.packetSha256 !== local.packetSha256 ||
    source.descriptorSha256 !== local.descriptorSha256
  )
    throw new Error("local source binding mismatch");
  const bindings = createBindings();
  const cells = source.cells.map((cell) => {
    const peer = local.cells.find((c) => c.id === cell.id);
    const debts = [...cell.debts, ...(peer?.debts ?? ["local cell missing"])];
    const rows = [];
    if (cell.exchanges.length !== peer?.exchanges.length)
      debts.push("different exchange cardinality");
    for (const [i, expected] of cell.exchanges.entries()) {
      const actual = peer?.exchanges[i];
      let judgment;
      if (!actual) judgment = decision("NOT_COMPARABLE", "local exchange missing");
      else if (contains(expected.request, "omitted"))
        judgment = decision(
          "NOT_COMPARABLE",
          "omitted request payload requires exact reconstruction proof",
        );
      else if (contains(expected.response.body, "ackId") || contains(actual.response.body, "ackId"))
        judgment = decision(
          "NOT_COMPARABLE",
          "ACK selector unresolved; no shape selection inferred",
        );
      else {
        try {
          const rewritten = bindings.request(expected);
          if (
            ["method", "transport", "category"].some((k) => expected[k] !== actual[k]) ||
            !isDeepStrictEqual(rewritten, actual.request)
          )
            judgment = decision("NOT_COMPARABLE", "request/route/causal binding mismatch");
          else {
            if (
              expected.op === "publish" &&
              successful(expected) &&
              successful(actual) &&
              !expected.response.unknown &&
              !actual.response.unknown
            )
              bindings.linkPublish(
                expected.request.body,
                expected.response.body,
                actual.response.body,
              );
            judgment = judgeRow(expected, actual);
          }
        } catch (error) {
          judgment = decision("NOT_COMPARABLE", error.message);
        }
      }
      rows.push({
        sourceN: expected.n,
        sourceDispatchN: expected.dispatchN,
        localN: actual?.n ?? null,
        method: expected.method,
        transport: expected.transport,
        ...judgment,
      });
    }
    return {
      id: cell.id,
      group: cell.group,
      coordinate: cell.coordinate ?? null,
      supplement: cell.supplement ?? false,
      verdict: aggregate(rows, debts),
      rows,
      debts,
    };
  });
  return {
    schema: 1,
    kind: "pubsub-observation-a-comparison-preparation",
    evidenceKind:
      source.evidenceKind === "fixture" || local.evidenceKind === "fixture"
        ? "fixture"
        : "production-vs-supplied-local",
    sourceRunId: source.runId,
    cells,
    counts: Object.fromEntries(
      ["MATCH", "DIVERGES", "NOT_COMPARABLE"].map((v) => [
        v,
        cells.filter((c) => c.verdict === v).length,
      ]),
    ),
    replayExecuted: false,
    localRuntimeVerified: false,
    parentClosureReady: false,
  };
}
