import { isDeepStrictEqual } from "node:util";
import { createHash } from "node:crypto";
import { protos } from "@google-cloud/pubsub";
import { sanitize } from "../pubsub-production/capture.mjs";
import { makePlan, PROJECT, SUITE } from "./plan.mjs";
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

export function observationOutcome(reply, method, request) {
  const response = normalizeOutcome(reply);
  if (
    method === "UpdateSubscription" &&
    response.ok === true &&
    (typeof request.subscription?.name !== "string" ||
      response.body?.name !== request.subscription.name)
  )
    response.unknown = true;
  return response;
}

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
    !isDeepStrictEqual(packet.plan, makePlan(packet.plan.selection ?? "full")) ||
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
      const response = observationOutcome(row.reply, row.method, dispatch.request);
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

function zeroShape(cell, runId) {
  const frame = cell?.frames[0],
    body = frame?.body;
  return (
    cell?.id === "S10" &&
    cell.coordinate === "/conditions/13/cases/9" &&
    cell.variant === "invalid-opening-frame" &&
    cell.group === "G4" &&
    cell.frames.length === 1 &&
    frame.direction === "out" &&
    frame.verified === true &&
    /^[a-f0-9]{64}$/.test(frame.blob?.sha256 ?? "") &&
    frame.blob.bytes > 0 &&
    isDeepStrictEqual(body, {
      subscription: `projects/${PROJECT}/subscriptions/fe${runId}-s10-sub`,
      streamAckDeadlineSeconds: 0,
      maxOutstandingMessages: "1",
      maxOutstandingBytes: "1024",
    })
  );
}
function naturalZero(cell, state) {
  const events = cell?.events ?? [];
  const one = (event) => events.filter((e) => e.event === event);
  const error = one("stream-error"),
    status = one("stream-status"),
    end = one("stream-inbound-end");
  return (
    state?.terminal?.code === 13 &&
    state.inboundEnded === true &&
    state.received === 0 &&
    state.windowExpired === false &&
    state.windowMs === 90000 &&
    one("stream-dispatch").length === 1 &&
    one("stream-open-local").length === 1 &&
    one("stream-open-local")[0].windowMs === 90000 &&
    error.length === 1 &&
    status.length === 1 &&
    end.length === 1 &&
    error[0].code === 13 &&
    status[0].code === 13 &&
    [error[0], status[0], end[0]].every(
      (e) => Number.isFinite(e.elapsedMs) && e.elapsedMs >= 0 && e.elapsedMs < 90000,
    ) &&
    one("stream-dispatch")[0].n < one("stream-open-local")[0].n &&
    one("stream-open-local")[0].n < error[0].n &&
    error[0].n < status[0].n &&
    status[0].n < end[0].n &&
    !events.some((e) =>
      [
        "stream-cancel",
        "stream-observation-window-end",
        "stream-frame-refused",
        "stream-write-end",
      ].includes(e.event),
    ) &&
    cell.result?.cleanupClosed === true &&
    cell.result.budgetOverrun === false &&
    Array.isArray(cell.result.outstanding) &&
    cell.result.outstanding.length === 0
  );
}
function zeroCleanup(cell, runId, observationN) {
  if (!Number.isSafeInteger(observationN) || observationN < 1) return false;
  return ["Subscription", "Topic"].every((suffix) => {
    const name = `projects/${PROJECT}/${suffix === "Topic" ? "topics" : "subscriptions"}/fe${runId}-s10-${suffix === "Topic" ? "topic" : "sub"}`;
    const rows = cell?.exchanges ?? [];
    const deletes = rows.filter(
      (e) =>
        e.method === `Delete${suffix}` &&
        e.category === "cleanupDelete" &&
        e.request.body.name === name,
    );
    const gets = rows.filter(
      (e) =>
        e.method === `Get${suffix}` && e.category === "cleanupGet" && e.request.body.name === name,
    );
    return (
      deletes.length === 1 &&
      gets.length === 1 &&
      deletes[0].dispatchN > observationN &&
      deletes[0].response.ok === true &&
      deletes[0].response.unknown !== true &&
      gets[0].response.unknown !== true &&
      gets[0].response.ok === false &&
      gets[0].response.status === 404 &&
      deletes[0].n < gets[0].dispatchN
    );
  });
}
function nativeDetails(cell) {
  const rows =
    cell?.events.filter((e) => ["stream-error", "stream-status"].includes(e.event)) ?? [];
  return {
    available: rows.length === 2 && rows.every((e) => typeof e.details === "string"),
    error: rows.find((e) => e.event === "stream-error")?.details ?? null,
    status: rows.find((e) => e.event === "stream-status")?.details ?? null,
  };
}
function compareZeroOutcome(source, local, original, actual, proof) {
  const observations = original.events.filter((e) => e.event === "stream-case-observation"),
    observation = observations[0],
    localObservations = actual?.events.filter((e) => e.event === "stream-case-observation") ?? [],
    localObservation = localObservations[0],
    localDetails = nativeDetails(actual),
    sourceDetails = nativeDetails(original);
  const details = {
    source: sourceDetails,
    local: localDetails,
    verdict:
      !sourceDetails.available || !localDetails.available
        ? "NOT_COMPARABLE"
        : isDeepStrictEqual(sourceDetails, localDetails)
          ? "MATCH"
          : "DIVERGES",
  };
  const exact =
    source.evidenceKind === "production" &&
    local.evidenceKind === "local" &&
    zeroShape(original, source.runId) &&
    zeroShape(actual, source.runId) &&
    observations.length === 1 &&
    naturalZero(original, observation?.state) &&
    naturalZero(actual, proof?.zeroOutcome?.state) &&
    zeroCleanup(original, source.runId, observation.n) &&
    localObservations.length === 1 &&
    localObservation.n === proof.zeroOutcome.observationN &&
    localObservation.elapsedMs === proof.zeroOutcome.observedElapsedMs &&
    isDeepStrictEqual(localObservation.state, proof.zeroOutcome.state) &&
    zeroCleanup(actual, source.runId, localObservation.n) &&
    original.frames[0].blob.sha256 === actual.frames[0].blob.sha256 &&
    original.frames[0].blob.bytes === actual.frames[0].blob.bytes &&
    original.events.find((e) => e.event === "stream-inbound-end")?.n < observation?.n &&
    isDeepStrictEqual(
      proof?.sourceFrames,
      original.frames.map((f) => f.n),
    ) &&
    isDeepStrictEqual(
      proof?.actions?.map((a) => [a.sourceN, a.event]),
      [[observation?.n, "stream-case-observation"]],
    ) &&
    proof.actions.every((a) => Number.isFinite(a.elapsedMs) && a.elapsedMs >= 0) &&
    Number.isFinite(proof?.zeroOutcome?.observedElapsedMs) &&
    proof.zeroOutcome.observedElapsedMs >= 0 &&
    actual.events.find((e) => e.event === "stream-inbound-end").n < localObservation.n &&
    actual.events.find((e) => e.event === "stream-inbound-end").elapsedMs <=
      proof.zeroOutcome.observedElapsedMs;
  return {
    verdict: exact ? "MATCH" : "NOT_COMPARABLE",
    details,
    sourceRunId: source.runId,
    sourceHead: source.sourceHead,
    scope:
      "explicit-zero natural native13 without delivery; whole cell completion remains separate",
  };
}

// Preserve field order and all non-ACK widths, including opaque timestamp widths.
function ackWireProjection(raw, kind) {
  let offset = 0, containsAck = false;
  const fields = [], seen = new Set(), acks = new Set();
  const varint = () => {
    const start = offset;
    let value = 0n;
    for (let i = 0; i < 10 && offset < raw.length; i++) {
      const byte = raw[offset++];
      value |= BigInt(byte & 127) << BigInt(i * 7);
      if (byte < 128) {
        if ((i > 0 && byte === 0) || (i === 9 && byte > 1))
          throw new Error("noncanonical native varint");
        return { value, bytes: raw.subarray(start, offset) };
      }
    }
    throw new Error("truncated native varint");
  };
  while (offset < raw.length) {
    const tag = varint(), number = Number(tag.value >> 3n), wire = Number(tag.value & 7n);
    if (number < 1 || number > 536870911) throw new Error("invalid native tag");
    const ack = (kind === "received" && number === 1) ||
      (kind === "request" && [2, 4].includes(number));
    const childKind = kind === "response" && number === 1 ? "received" :
      kind === "received" && number === 2 ? "message" :
      kind === "message" && number === 4 ? "timestamp" : null;
    const singular = kind === "received" && [1, 2, 3].includes(number) ||
      kind === "message" && [1, 3, 4, 5].includes(number) ||
      kind === "timestamp" && [1, 2].includes(number) ||
      kind === "response" && number === 4 ||
      kind === "request" && [1, 5, 6, 7, 8, 10].includes(number);
    if (singular && seen.has(number)) throw new Error("duplicate native field");
    seen.add(number);
    if ((ack || childKind) && wire !== 2) throw new Error("native field wire type");
    let payload, prefix;
    if (wire === 2) {
      prefix = varint();
      if (prefix.value > BigInt(raw.length - offset)) throw new Error("truncated native field");
      const length = Number(prefix.value);
      payload = raw.subarray(offset, offset + length); offset += length;
    } else if (wire === 0) payload = varint().bytes;
    else if ([1, 5].includes(wire)) {
      const length = wire === 1 ? 8 : 4;
      if (offset + length > raw.length) throw new Error("truncated native field");
      payload = raw.subarray(offset, offset + length); offset += length;
    } else throw new Error("unsupported native wire type");
    const field = { number, wire, tag: tag.bytes.toString("hex") };
    if (ack) {
      const text = payload.toString("utf8");
      if (!text || !Buffer.from(text).equals(payload) || acks.has(text))
        throw new Error("empty, invalid or duplicate native ACK");
      acks.add(text); field.ack = true; containsAck = true;
    } else if (childKind) {
      const child = ackWireProjection(payload, childKind);
      field.fields = child.fields;
      if (!child.containsAck) field.prefix = prefix.bytes.toString("hex");
      containsAck ||= child.containsAck;
    } else {
      field.bytes = payload.length;
      if (prefix) field.prefix = prefix.bytes.toString("hex");
      const opaque = kind === "message" && number === 3 ||
        kind === "timestamp" && [1, 2].includes(number) && wire === 0;
      if (!opaque) field.value = payload.toString("hex");
    }
    fields.push(field);
  }
  if (kind === "received" && !seen.has(1)) throw new Error("native ACK absent");
  return { fields, containsAck };
}

function approvedBinding(source, local, disposition) {
  try {
    const authority = disposition.authority;
    if (!Buffer.isBuffer(authority.bytes) || authority.bytes.length > 65536 ||
      !/^[a-f0-9]{64}$/.test(authority.sha256) ||
      createHash("sha256").update(authority.bytes).digest("hex") !== authority.sha256 ||
      !/^[a-f0-9]{64}$/.test(JSON.parse(authority.bytes).proposalSha256) ||
      !isDeepStrictEqual(disposition.source, {
        runId: source.runId, packetSha256: source.packetSha256,
        descriptorSha256: source.descriptorSha256,
      }) || !Array.isArray(disposition.rawFrames)) return false;
    const expected = source.cells.flatMap((cell) => cell.frames.map((f, i) =>
      [f.n, local.cells.find((c) => c.id === cell.id)?.frames[i]?.n]));
    return local.cells.reduce((n, cell) => n + cell.frames.length, 0) === expected.length &&
      isDeepStrictEqual(disposition.rawFrames.map((f) => [f.sourceN, f.localN]), expected) &&
      new Set(expected.map(([n]) => n)).size === expected.length &&
      new Set(expected.map(([, n]) => n)).size === expected.length;
  } catch { return false; }
}

function approvedNativeComparison(original, actual, proof, disposition, binding) {
  const terminal = (cell) => cell.events.filter((e) =>
    ["stream-error", "stream-status"].includes(e.event));
  const sourceTerminal = terminal(original), localTerminal = terminal(actual);
  const invalidTerminal = (events) => events.some((e) =>
    typeof e.details !== "string" || canonicalStatus(e.code) === "UNKNOWN") ||
    new Set(events.map((e) => e.event)).size !== events.length;
  const terminalVerdict = sourceTerminal.length !== localTerminal.length ? "NOT_COMPARABLE" :
    invalidTerminal(sourceTerminal) || invalidTerminal(localTerminal) ?
      "NOT_COMPARABLE" : isDeepStrictEqual(
        sourceTerminal.map((e) => [e.event, e.code, e.details]),
        localTerminal.map((e) => [e.event, e.code, e.details]),
      ) ? "MATCH" : "DIVERGES";
  const frames = [];
  const complete = [original, actual].every((cell) => cell.result?.complete === true &&
    cell.result.cleanupClosed === true && cell.result.budgetOverrun === false);
  let verdict = !binding || !complete || proof.semanticsVerified !== true ? "NOT_COMPARABLE" : "MATCH";
  if (verdict === "MATCH") {
    try {
      for (const [i, sourceFrame] of original.frames.entries()) {
        const localFrame = actual.frames[i];
        const raw = disposition.rawFrames.find((f) => f.sourceN === sourceFrame.n);
        const projections = [[sourceFrame, raw.sourceBytes], [localFrame, raw.localBytes]].map(([frame, bytes]) => {
          if (!Buffer.isBuffer(bytes) || bytes.length > 65536 || bytes.length !== frame.blob.bytes ||
            createHash("sha256").update(bytes).digest("hex") !== frame.blob.sha256)
            throw new Error("native raw pin mismatch");
          const Type = protos.google.pubsub.v1[frame.direction === "out" ? "StreamingPullRequest" : "StreamingPullResponse"];
          const decoded = Type.toObject(Type.decode(bytes), { longs: String, enums: String, bytes: String, defaults: false });
          if (!isDeepStrictEqual(sanitize(decoded), frame.body)) throw new Error("native decoded body mismatch");
          return ackWireProjection(bytes, frame.direction === "out" ? "request" : "response").fields;
        });
        const matches = sourceFrame.direction === localFrame.direction &&
          isDeepStrictEqual(projections[0], projections[1]);
        frames.push({ sourceN: sourceFrame.n, localN: localFrame.n,
          sourceSha256: sourceFrame.blob.sha256, localSha256: localFrame.blob.sha256,
          verdict: matches ? "MATCH" : "DIVERGES" });
        if (!matches) verdict = "DIVERGES";
      }
    } catch { verdict = "NOT_COMPARABLE"; }
  }
  if (terminalVerdict === "DIVERGES") verdict = "DIVERGES";
  else if (terminalVerdict !== "MATCH" && verdict === "MATCH") verdict = "NOT_COMPARABLE";
  return { verdict, authoritySha256: disposition?.authority?.sha256 ?? null,
    terminalVerdict, frames, scope: "explicit offline ACK-only wire disposition; literal physical result retained" };
}

export function compareExecutedObservation(source, local, nativeWitnesses, approvedDisposition) {
  const report = compareObservation(source, local);
  const approved = approvedDisposition !== undefined;
  const approvedBound = approved && approvedBinding(source, local, approvedDisposition);
  const nativeDebt =
    "native stream timing and causal witness requires dedicated replay; frame equality alone is insufficient";
  for (const cell of report.cells.filter((c) => c.group === "G4")) {
    const original = source.cells.find((c) => c.id === cell.id),
      actual = local.cells.find((c) => c.id === cell.id),
      proof = nativeWitnesses[cell.id];
    const actions = original.events.filter((e) =>
      ["stream-write-end", "stream-cancel", "stream-case-observation"].includes(e.event),
    );
    const observation = actions.find((e) => e.event === "stream-case-observation");
    if (cell.id === "S10") {
      cell.nativeOutcome = compareZeroOutcome(source, local, original, actual, proof);
      if (cell.nativeOutcome.details.verdict !== "MATCH")
        cell.debts.push(
          `native error details ${cell.nativeOutcome.details.verdict}: availability and exact recorded values retained`,
        );
    }
    const exact =
      proof?.completed === true &&
      Array.isArray(proof.actions) &&
      proof.actions.every((a) => Number.isFinite(a.elapsedMs) && a.elapsedMs >= 0) &&
      original.frames.length > 0 &&
      original.frames.every((f) => f.verified) &&
      actual?.frames.every((f) => f.verified) &&
      isDeepStrictEqual(
        proof.sourceFrames,
        original.frames.map((f) => f.n),
      ) &&
      isDeepStrictEqual(
        proof.actions.map((a) => [a.sourceN, a.event]),
        actions.map((a) => [a.n, a.event]),
      ) &&
      observation?.state?.incomplete === false &&
      (observation.invalidAckObservedMs == null ||
        (observation.invalidAckObservedMs >= 30000 && proof.silenceMs >= 30000));
    if (!exact) continue;
    cell.debts = cell.debts.filter((debt) => debt !== nativeDebt);
    const shapeMatches =
      original.frames.length === actual.frames.length &&
      original.frames.every((f, i) => f.direction === actual.frames[i].direction);
    const layoutMatches = shapeMatches &&
      original.frames.every((f, i) => f.blob?.bytes === actual.frames[i].blob?.bytes);
    cell.nativeSemantics = {
      verdict: proof.semanticsVerified !== true ? "NOT_COMPARABLE" : shapeMatches ? "MATCH" : "DIVERGES",
      scope: "executed identity-bound receive, ACK, presence and timing guards; physical layout remains separate",
    };
    cell.nativeLayout = {
      verdict: layoutMatches ? "MATCH" : "DIVERGES",
      frames: original.frames.map((f, i) => ({
        sourceN: f.n,
        localN: actual.frames[i]?.n ?? null,
        sourceDirection: f.direction,
        localDirection: actual.frames[i]?.direction ?? null,
        sourceBytes: f.blob?.bytes ?? null,
        localBytes: actual.frames[i]?.blob?.bytes ?? null,
        sourceSha256: f.blob?.sha256 ?? null,
        localSha256: actual.frames[i]?.blob?.sha256 ?? null,
      })),
    };
    if (approved) {
      cell.approvedComparison = approvedNativeComparison(original, actual, proof, approvedDisposition, approvedBound);
      cell.approvedComparison.physicalVerdict = cell.nativeLayout.verdict;
      cell.debts.push(...(approvedDisposition?.remainingDebts?.[cell.id] ?? []));
    }
    cell.rows.push({
      method: "StreamingPull",
      transport: "grpc",
      verdict: approved ? cell.approvedComparison.verdict : layoutMatches ? "MATCH" : "DIVERGES",
      ...(approved ? { physicalVerdict: cell.nativeLayout.verdict } : {}),
      reason: approved ? "explicit pinned ACK projection and recorded terminal details" : layoutMatches
        ? "actual causal actions, measured window and physical frame lengths match"
        : "native frame direction/cardinality/physical length gap",
    });
    cell.verdict = aggregate(cell.rows, cell.debts);
  }
  report.counts = Object.fromEntries(
    ["MATCH", "DIVERGES", "NOT_COMPARABLE"].map((v) => [
      v,
      report.cells.filter((c) => c.verdict === v).length,
    ]),
  );
  return report;
}
