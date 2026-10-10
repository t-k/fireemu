import { publicationTimeVerdict, publishTimeAuthorized } from "./replay-native.mjs";
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

// Preserve field order and non-ACK values and widths, except bound message identities.
// Generated timestamp scalar placeholders retain presence and derive each ancestor length exactly.
export function ackWireProjection(raw, kind, generatedTime = false) {
  let normalizedBytes = raw.length;
  const timestamp =
    generatedTime && kind === "timestamp"
      ? protos.google.protobuf.Timestamp.toObject(protos.google.protobuf.Timestamp.decode(raw), {
          longs: String,
          defaults: false,
        })
      : null;
  const encodeLength = (value) => {
    const bytes = [];
    do {
      bytes.push((value & 127) | (value > 127 ? 128 : 0));
      value = Math.floor(value / 128);
    } while (value);
    return Buffer.from(bytes);
  };
  let offset = 0,
    containsAck = false;
  const fields = [],
    seen = new Set(),
    acks = new Set();
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
    const tag = varint(),
      number = Number(tag.value >> 3n),
      wire = Number(tag.value & 7n);
    if (number < 1 || number > 536870911) throw new Error("invalid native tag");
    const ack =
      (kind === "received" && number === 1) || (kind === "request" && [2, 4].includes(number));
    const childKind =
      kind === "response" && number === 1
        ? "received"
        : kind === "received" && number === 2
          ? "message"
          : kind === "message" && number === 4
            ? "timestamp"
            : null;
    const singular =
      (kind === "received" && [1, 2, 3].includes(number)) ||
      (kind === "message" && [1, 3, 4, 5].includes(number)) ||
      (kind === "timestamp" && [1, 2].includes(number)) ||
      (kind === "response" && number === 4) ||
      (kind === "request" && [1, 5, 6, 7, 8, 10].includes(number));
    if (singular && seen.has(number)) throw new Error("duplicate native field");
    seen.add(number);
    if ((ack || childKind) && wire !== 2) throw new Error("native field wire type");
    let payload, prefix, scalar;
    if (wire === 2) {
      prefix = varint();
      if (prefix.value > BigInt(raw.length - offset)) throw new Error("truncated native field");
      const length = Number(prefix.value);
      payload = raw.subarray(offset, offset + length);
      offset += length;
    } else if (wire === 0) {
      scalar = varint();
      payload = scalar.bytes;
    } else if ([1, 5].includes(wire)) {
      const length = wire === 1 ? 8 : 4;
      if (offset + length > raw.length) throw new Error("truncated native field");
      payload = raw.subarray(offset, offset + length);
      offset += length;
    } else throw new Error("unsupported native wire type");
    const field = { number, wire, tag: tag.bytes.toString("hex") };
    if (generatedTime && kind === "timestamp") {
      if (![1, 2].includes(number) || wire !== 0)
        throw new Error("generated timestamp field layout invalid");
      const key = number === 1 ? "seconds" : "nanos";
      const value = number === 1 ? BigInt.asIntN(64, scalar.value) : scalar.value;
      if (
        !Object.hasOwn(timestamp, key) ||
        (number === 1
          ? value < -62135596800n || value > 253402300799n
          : value < 0n || value > 999999999n) ||
        value !== BigInt(timestamp[key])
      )
        throw new Error("generated timestamp raw scalar invalid");
      field.bytes = 1;
      field.value = "generated";
      normalizedBytes += 1 - payload.length;
      fields.push(field);
      continue;
    }
    if (ack) {
      const text = payload.toString("utf8");
      if (!text || !Buffer.from(text).equals(payload) || acks.has(text))
        throw new Error("empty, invalid or duplicate native ACK");
      acks.add(text);
      field.ack = true;
      containsAck = true;
    } else if (childKind) {
      const child = ackWireProjection(payload, childKind, generatedTime);
      field.fields = child.fields;
      const normalizedPrefix = encodeLength(child.normalizedBytes);
      normalizedBytes +=
        child.normalizedBytes - payload.length + normalizedPrefix.length - prefix.bytes.length;
      if (!child.containsAck)
        field.prefix = (generatedTime ? normalizedPrefix : prefix.bytes).toString("hex");
      containsAck ||= child.containsAck;
    } else {
      field.bytes = payload.length;
      if (prefix) field.prefix = prefix.bytes.toString("hex");
      const opaque = kind === "message" && number === 3;
      if (!opaque) field.value = payload.toString("hex");
    }
    fields.push(field);
  }
  if (kind === "received" && !seen.has(1)) throw new Error("native ACK absent");
  return { fields, containsAck, normalizedBytes };
}

function approvedBinding(source, local, disposition) {
  try {
    const authority = disposition.authority;
    if (
      !Buffer.isBuffer(authority.bytes) ||
      authority.bytes.length > 65536 ||
      !/^[a-f0-9]{64}$/.test(authority.sha256) ||
      createHash("sha256").update(authority.bytes).digest("hex") !== authority.sha256 ||
      !/^[a-f0-9]{64}$/.test(JSON.parse(authority.bytes).proposalSha256) ||
      !isDeepStrictEqual(disposition.source, {
        runId: source.runId,
        packetSha256: source.packetSha256,
        descriptorSha256: source.descriptorSha256,
      }) ||
      !Array.isArray(disposition.rawFrames)
    )
      return false;
    const expected = source.cells.flatMap((cell) =>
      cell.frames.map((f, i) => [f.n, local.cells.find((c) => c.id === cell.id)?.frames[i]?.n]),
    );
    return (
      local.cells.reduce((n, cell) => n + cell.frames.length, 0) === expected.length &&
      isDeepStrictEqual(
        disposition.rawFrames.map((f) => [f.sourceN, f.localN]),
        expected,
      ) &&
      new Set(expected.map(([n]) => n)).size === expected.length &&
      new Set(expected.map(([, n]) => n)).size === expected.length
    );
  } catch {
    return false;
  }
}

function nativeTerminalVerdict(original, actual) {
  const terminal = (cell) =>
    cell.events.filter((e) => ["stream-error", "stream-status"].includes(e.event));
  const sourceTerminal = terminal(original),
    localTerminal = terminal(actual);
  const invalidTerminal = (events) =>
    events.some((e) => typeof e.details !== "string" || canonicalStatus(e.code) === "UNKNOWN") ||
    new Set(events.map((e) => e.event)).size !== events.length;
  if (
    original.id === "S03" &&
    original.events.some((e) => e.event === "stream-cancel" && e.reason === "dispose") &&
    ![sourceTerminal, localTerminal].every((events) =>
      events.some((e) => e.event === "stream-status"),
    )
  )
    return "NOT_COMPARABLE";
  return sourceTerminal.length !== localTerminal.length
    ? "NOT_COMPARABLE"
    : invalidTerminal(sourceTerminal) || invalidTerminal(localTerminal)
      ? "NOT_COMPARABLE"
      : isDeepStrictEqual(
            sourceTerminal.map((e) => [e.event, e.code, e.details, e.phase, e.cancelReason]),
            localTerminal.map((e) => [e.event, e.code, e.details, e.phase, e.cancelReason]),
          )
        ? "MATCH"
        : "DIVERGES";
}

function declaredPhaseComparison(original, actual, proof, eligible) {
  const variants = new Map([
    ["S01", "opening-frame"],
    ["S02", "future-publications"],
    ["S04", "in-stream-nack"],
    ["S05", "in-stream-deadline-update"],
    ["S06", "flow-control"],
  ]);
  if (!variants.has(original.id)) return null;
  const declared = original.events.some(
    (event) =>
      event.event === "stream-cancel" ||
      (event.event === "stream-case-observation" &&
        ["windowMs", "windowExpired", "inboundEnded", "received"].some((field) =>
          Object.hasOwn(event.state ?? {}, field),
        )),
  );
  if (!declared) return null;
  const result = {
    verdict: "NOT_COMPARABLE",
    scope: "original bounded observation through own disposal boundary",
  };
  if (
    !eligible ||
    [original, actual].some(
      (cell) =>
        cell.variant !== variants.get(original.id) ||
        cell.coordinate !== `/conditions/13/cases/${Number(original.id.slice(1)) - 1}`,
    )
  )
    return result;
  const observations = original.events.filter((e) => e.event === "stream-case-observation");
  const sourceCancels = original.events.filter((e) => e.event === "stream-cancel");
  const localCancels = actual.events.filter((e) => e.event === "stream-cancel");
  if (observations.length !== 1 || sourceCancels.length !== 1 || localCancels.length !== 1)
    return result;
  const [observation] = observations,
    [sourceCancel] = sourceCancels,
    [localCancel] = localCancels;
  const state = observation.state;
  if (
    sourceCancel.reason !== "dispose" ||
    localCancel.reason !== "dispose" ||
    !(observation.n < sourceCancel.n) ||
    state?.terminal !== null ||
    state.inboundEnded !== false ||
    state.incomplete !== false ||
    state.windowExpired !== false ||
    state.windowMs !== 90000
  )
    return result;
  const observationAction = proof.actions.filter(
    (a) => a.sourceN === observation.n && a.event === observation.event,
  );
  const cancelAction = proof.actions.filter(
    (a) => a.sourceN === sourceCancel.n && a.event === sourceCancel.event,
  );
  if (
    observationAction.length !== 1 ||
    cancelAction.length !== 1 ||
    proof.actions.indexOf(observationAction[0]) >= proof.actions.indexOf(cancelAction[0]) ||
    !Number.isFinite(localCancel.elapsedMs) ||
    localCancel.elapsedMs < observationAction[0].elapsedMs ||
    cancelAction[0].elapsedMs < observationAction[0].elapsedMs
  )
    return result;
  const forbidden = new Set([
    "stream-error",
    "stream-status",
    "stream-inbound-end",
    "stream-close",
    "stream-observation-window-end",
    "stream-frame-refused",
  ]);
  for (const [cell, cancel] of [
    [original, sourceCancel],
    [actual, localCancel],
  ]) {
    if (
      cell.events.some(
        (event, i) =>
          !Number.isSafeInteger(event.n) || event.n < 1 || (i && cell.events[i - 1].n >= event.n),
      )
    )
      return result;
    if (cell.events.some((event) => event.n < cancel.n && forbidden.has(event.event)))
      return { ...result, verdict: "DIVERGES" };
    if (
      cell.frames.some(
        (frame) =>
          !(frame.n < cancel.n) ||
          !cell.events.some(
            (event) =>
              event.n === frame.n &&
              event.event === "stream-frame" &&
              isDeepStrictEqual(event.body, frame.body),
          ),
      )
    )
      return result;
    const received = cell.frames
      .filter((f) => f.direction === "in")
      .reduce((n, f) => n + (f.body.receivedMessages?.length ?? 0), 0);
    if (
      received !== state.received ||
      ["in", "out"].some(
        (direction) => cell.frames.filter((f) => f.direction === direction).length > 6,
      )
    )
      return result;
  }
  return {
    ...result,
    verdict: "MATCH",
    sourceObservationN: observation.n,
    sourceCancelN: sourceCancel.n,
    localCancelN: localCancel.n,
  };
}

function unorderedFramePairs(original, actual, proof, authority) {
  if (
    original.id !== "S06" ||
    original.variant !== "flow-control" ||
    original.coordinate !== "/conditions/13/cases/5" ||
    !authority
  )
    return null;
  let approval;
  try {
    if (
      !Buffer.isBuffer(authority.bytes) ||
      authority.bytes.length > 65536 ||
      createHash("sha256").update(authority.bytes).digest("hex") !== authority.sha256
    )
      throw new Error("unordered authority pin");
    approval = JSON.parse(authority.bytes);
  } catch {
    throw new Error("unordered authority invalid");
  }
  if (
    approval.ownerRow !== 1171 ||
    approval.proposalSha256 !==
      "cb37288c3197dace9acd60a2a2b0ba0694efd3077dde4f019e3b863e383dd700" ||
    approval.lineSha256 !== "846f39d9ac6179a62e177206d9e6a95f7e2765af305cf6771445a8c610e796f7"
  )
    throw new Error("unordered authority scope");
  const pairs = new Map(),
    mappings = [];
  for (const cell of [original, actual]) {
    const setup = (method) =>
      cell.exchanges.filter(
        (e) => e.method === method && e.response.ok === true && e.response.unknown !== true,
      );
    const creates = setup("CreateSubscription"),
      gets = setup("GetSubscription");
    if (creates.length !== 1 || gets.length !== 1) throw new Error("unordered setup missing");
    const values = [
      creates[0].request.body.enableMessageOrdering,
      creates[0].response.body.enableMessageOrdering,
      gets[0].response.body.enableMessageOrdering,
    ];
    if (values.some((v) => v !== undefined && typeof v !== "boolean"))
      throw new Error("unordered setup unknown");
    if (values.some((v) => v === true)) return null;
    const opener = cell.frames[0]?.body;
    if (
      creates[0].request.body.name !== opener?.subscription ||
      creates[0].response.body.name !== opener.subscription ||
      gets[0].request.body.name !== opener.subscription ||
      gets[0].response.body.name !== opener.subscription ||
      creates[0].request.body.topic !== creates[0].response.body.topic ||
      creates[0].request.body.topic !== gets[0].response.body.topic ||
      opener.maxOutstandingMessages !== "1" ||
      opener.maxOutstandingBytes !== "1024"
    )
      throw new Error("unordered setup contradictory");
    const published = setup("Publish");
    if (
      published.length !== 3 ||
      new Set(published.map((e) => e.response.body.messageIds?.[0])).size !== 3 ||
      published.some(
        (e) =>
          e.request.body.topic !== creates[0].request.body.topic ||
          e.request.body.messages?.length !== 1 ||
          e.response.body.messageIds?.length !== 1 ||
          e.request.body.messages[0].orderingKey,
      )
    )
      throw new Error("unordered publication cardinality or key");
    if (
      cell.frames.length !== 7 ||
      cell.frames.some(
        (f, i) => f.direction !== (i % 2 ? "in" : "out") || (i && cell.frames[i - 1].n >= f.n),
      )
    )
      throw new Error("unordered credit frame sequence");
    const ids = [];
    for (const i of [1, 3, 5]) {
      const received = cell.frames[i].body.receivedMessages,
        ack = cell.frames[i + 1].body.ackIds;
      if (
        received?.length !== 1 ||
        typeof received[0].ackId !== "string" ||
        !received[0].ackId ||
        ack?.length !== 1 ||
        ack[0] !== received[0].ackId ||
        received[0].message?.orderingKey
      )
        throw new Error("unordered receive or actual ACK association");
      ids.push(received[0].message.messageId);
    }
    if (
      new Set(ids).size !== 3 ||
      ids.some((id) => published.filter((e) => e.response.body.messageIds[0] === id).length !== 1)
    )
      throw new Error("unordered missing or duplicate own receive");
  }
  for (const publication of original.exchanges.filter((e) => e.method === "Publish")) {
    const candidates =
      proof.publishTime?.publications?.filter((p) => p.sourceDispatchN === publication.dispatchN) ??
      [];
    if (candidates.length !== 1) throw new Error("unordered publication binding missing");
    const p = candidates[0],
      sourceId = publication.response.body.messageIds[0],
      localId = p.localReply?.body?.messageIds?.[0];
    const localPublished = actual.exchanges.filter(
      (e) => e.method === "Publish" && e.response.body?.messageIds?.[0] === localId,
    );
    if (
      localPublished.length !== 1 ||
      !isDeepStrictEqual(p.sourceRequest, publication.request.body) ||
      !isDeepStrictEqual(p.sourceReply.body, publication.response.body) ||
      !isDeepStrictEqual(p.localRequest, localPublished[0].request.body) ||
      !isDeepStrictEqual(p.localReply.body, localPublished[0].response.body)
    )
      throw new Error("unordered publication transcript mismatch");
    const sourceIndex = original.frames.findIndex(
      (f) => f.direction === "in" && f.body.receivedMessages[0].message.messageId === sourceId,
    );
    const localIndex = actual.frames.findIndex(
      (f) => f.direction === "in" && f.body.receivedMessages[0].message.messageId === localId,
    );
    if (sourceIndex < 0 || localIndex < 0) throw new Error("unordered receive identity missing");
    pairs.set(original.frames[sourceIndex].n, actual.frames[localIndex]);
    pairs.set(original.frames[sourceIndex + 1].n, actual.frames[localIndex + 1]);
    mappings.push({
      sourcePublicationN: publication.dispatchN,
      sourceReceiveN: original.frames[sourceIndex].n,
      localReceiveN: actual.frames[localIndex].n,
      sourceAckN: original.frames[sourceIndex + 1].n,
      localAckN: actual.frames[localIndex + 1].n,
    });
  }
  pairs.set(original.frames[0].n, actual.frames[0]);
  if (pairs.size !== 7 || new Set([...pairs.values()].map((f) => f.n)).size !== 7)
    throw new Error("unordered frame binding ambiguous");
  return { pairs, mappings, authoritySha256: approval.lineSha256 };
}

function approvedNativeComparison(original, actual, proof, disposition, binding) {
  const terminalVerdict = nativeTerminalVerdict(original, actual);
  const frames = [];
  let ownPublicationAckBindings;
  const complete = [original, actual].every(
    (cell) =>
      cell.result?.complete === true &&
      cell.result.cleanupClosed === true &&
      cell.result.budgetOverrun === false,
  );
  let verdict =
    !binding || !complete || proof.semanticsVerified !== true ? "NOT_COMPARABLE" : "MATCH";
  if (verdict === "MATCH") {
    try {
      const needsGeneratedTime =
        disposition.publishTime &&
        [original, actual].some((cell) =>
          cell.frames.some(
            (frame) =>
              frame.direction === "in" &&
              frame.body.receivedMessages?.some((received) =>
                Object.hasOwn(received.message ?? {}, "publishTime"),
              ),
          ),
        );
      const generated = needsGeneratedTime ? proof.publishTime : null;
      if (
        needsGeneratedTime &&
        (!generated ||
          generated.cellId !== original.id ||
          generated.cellId !== actual.id ||
          !publishTimeAuthorized(generated) ||
          !isDeepStrictEqual(generated.source, disposition.source) ||
          !isDeepStrictEqual(generated.runtime, disposition.publishTime.runtime))
      )
        verdict = "NOT_COMPARABLE";
      const unordered = unorderedFramePairs(
        original,
        actual,
        proof,
        disposition.s06OrderingAuthority,
      );
      for (const [i, sourceFrame] of original.frames.entries()) {
        const localFrame = unordered?.pairs.get(sourceFrame.n) ?? actual.frames[i];
        const sourceRaw = disposition.rawFrames.find((f) => f.sourceN === sourceFrame.n);
        const localRaw = disposition.rawFrames.filter((f) => f.localN === localFrame?.n);
        if (localRaw.length !== 1) throw new Error("native local raw binding missing");
        const raw = { sourceBytes: sourceRaw.sourceBytes, localBytes: localRaw[0].localBytes };
        let timeVerdict = "MATCH";
        if (
          generated &&
          sourceFrame.direction === "in" &&
          sourceFrame.body.receivedMessages?.length
        ) {
          timeVerdict = publicationTimeVerdict(sourceFrame.body, localFrame.body, generated);
          if (timeVerdict !== "MATCH") verdict = timeVerdict;
        }
        const projections = [
          [sourceFrame, raw.sourceBytes],
          [localFrame, raw.localBytes],
        ].map(([frame, bytes]) => {
          if (
            !Buffer.isBuffer(bytes) ||
            bytes.length > 65536 ||
            bytes.length !== frame.blob.bytes ||
            createHash("sha256").update(bytes).digest("hex") !== frame.blob.sha256
          )
            throw new Error("native raw pin mismatch");
          const Type =
            protos.google.pubsub.v1[
              frame.direction === "out" ? "StreamingPullRequest" : "StreamingPullResponse"
            ];
          const decoded = Type.toObject(Type.decode(bytes), {
            longs: String,
            enums: String,
            bytes: String,
            defaults: false,
          });
          if (!isDeepStrictEqual(sanitize(decoded), frame.body))
            throw new Error("native decoded body mismatch");
          return ackWireProjection(
            bytes,
            frame.direction === "out" ? "request" : "response",
            Boolean(generated),
          ).fields;
        });
        const matches =
          sourceFrame.direction === localFrame.direction &&
          isDeepStrictEqual(projections[0], projections[1]);
        frames.push({
          sourceN: sourceFrame.n,
          localN: localFrame.n,
          sourceSha256: sourceFrame.blob.sha256,
          localSha256: localFrame.blob.sha256,
          verdict: matches ? timeVerdict : "DIVERGES",
        });
        if (!matches) verdict = "DIVERGES";
      }
      if (unordered) ownPublicationAckBindings = unordered.mappings;
    } catch {
      verdict = "NOT_COMPARABLE";
    }
  }
  const declaredPhase = declaredPhaseComparison(
    original,
    actual,
    proof,
    binding && complete && proof.completed === true && verdict === "MATCH",
  );
  if (declaredPhase) {
    if (declaredPhase.verdict !== "MATCH" && verdict === "MATCH") verdict = declaredPhase.verdict;
  } else if (terminalVerdict === "DIVERGES") verdict = "DIVERGES";
  else if (terminalVerdict !== "MATCH" && verdict === "MATCH") verdict = "NOT_COMPARABLE";
  return {
    verdict,
    authoritySha256: disposition?.authority?.sha256 ?? null,
    terminalVerdict,
    ...(declaredPhase ? { declaredPhase } : {}),
    frames,
    ...(ownPublicationAckBindings
      ? {
          ownPublicationAckBindings,
          orderingAuthoritySha256:
            "846f39d9ac6179a62e177206d9e6a95f7e2765af305cf6771445a8c610e796f7",
        }
      : {}),
    scope: disposition?.publishTime
      ? "explicit ACK and publication-bound generated publishTime disposition; literal physical result retained"
      : "explicit offline ACK-only wire disposition; literal physical result retained",
  };
}

// The original cancellation case observes a fresh ordinary Pull token without using it.
function ownPullComparison(original, actual, expected, observed, proof, disposition) {
  const missing = () =>
    decision("NOT_COMPARABLE", "own Pull selector or publication proof incomplete");
  const differs = () => decision("DIVERGES", "own Pull nonopaque response or timeline differs");
  const timestamp = (value) => {
    const match =
      typeof value === "string" &&
      /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.(\d{3}|\d{6}|\d{9})Z$/.exec(value);
    if (!match) return null;
    const ms = Date.parse(`${match[1]}Z`);
    if (!Number.isFinite(ms) || new Date(ms).toISOString().slice(0, 19) !== match[1]) return null;
    return { seconds: String(ms / 1000), nanos: Number(match[2].padEnd(9, "0")) };
  };
  const selectors =
    proof.ordinaryPulls?.filter((p) => p.sourceDispatchN === expected.dispatchN) ?? [];
  if (selectors.length !== 1 || !observed || !proof.publishTime || !disposition?.publishTime)
    return missing();
  const selector = selectors[0],
    generated = proof.publishTime;
  if (
    ![expected, observed].every(
      (e) =>
        e.method === "Pull" &&
        e.transport === "rest" &&
        e.response.ok === true &&
        e.response.unknown !== true &&
        successful(e),
    ) ||
    !isDeepStrictEqual(expected.request, observed.request) ||
    !isDeepStrictEqual(expected.request.body, {
      subscription: generated.subscription?.opener,
      maxMessages: 1,
      returnImmediately: true,
    }) ||
    selector.sourceResponseN !== expected.n ||
    selector.localDispatchN !== observed.dispatchN ||
    selector.localResponseN !== observed.n ||
    selector.tokenUse !== "notObserved" ||
    generated.cellId !== original.id ||
    generated.cellId !== actual.id ||
    !isDeepStrictEqual(generated.source, disposition.source) ||
    !isDeepStrictEqual(generated.runtime, disposition.publishTime.runtime)
  )
    return missing();
  const items = [
    expected.response.body?.receivedMessages,
    observed.response.body?.receivedMessages,
  ];
  if (!items.every((a) => Array.isArray(a) && a.length === 1)) return missing();
  const [sourceItem, localItem] = items.map((a) => a[0]);
  if (
    ![sourceItem, localItem].every((i) => typeof i.ackId === "string" && i.ackId.length > 0) ||
    selector.sourceAck !== sourceItem.ackId ||
    selector.localAck !== localItem.ackId
  )
    return missing();
  const times = [sourceItem, localItem].map((i) => timestamp(i.message?.publishTime));
  if (times.some((v) => v === null)) return missing();
  const sourceBody = {
    receivedMessages: [
      { ...sourceItem, message: { ...sourceItem.message, publishTime: times[0] } },
    ],
  };
  const localBody = {
    receivedMessages: [{ ...localItem, message: { ...localItem.message, publishTime: times[1] } }],
  };
  const publications =
    generated.publications?.filter(
      (p) =>
        p.sourceReply?.body?.messageIds?.includes(sourceItem.message?.messageId) &&
        p.localReply?.body?.messageIds?.includes(localItem.message?.messageId),
    ) ?? [];
  if (publications.length !== 1) return missing();
  const publicationProof = publications[0];
  for (const [cell, request, reply, id] of [
    [
      original,
      publicationProof.sourceRequest,
      publicationProof.sourceReply,
      sourceItem.message.messageId,
    ],
    [
      actual,
      publicationProof.localRequest,
      publicationProof.localReply,
      localItem.message.messageId,
    ],
  ]) {
    const published = cell.exchanges.filter(
      (e) => e.method === "Publish" && e.response.body?.messageIds?.includes(id),
    );
    if (
      published.length !== 1 ||
      !successful(published[0]) ||
      published[0].response.ok !== true ||
      published[0].response.unknown === true ||
      !isDeepStrictEqual(published[0].request.body, request) ||
      !isDeepStrictEqual(published[0].response.body, reply.body) ||
      !(published[0].dispatchN < (cell === original ? expected : observed).dispatchN) ||
      (cell === original && published[0].dispatchN !== publicationProof.sourceDispatchN)
    )
      return missing();
  }
  const publication = publicationTimeVerdict(sourceBody, localBody, generated);
  if (publication !== "MATCH") return decision(publication, "own Pull publication timestamp proof");
  const clock = selector.clock;
  try {
    const bytes = Buffer.from(clock.responseBytes, "base64");
    if (
      bytes.length > 65536 ||
      createHash("sha256").update(bytes).digest("hex") !== clock.responseSha256 ||
      !isDeepStrictEqual(JSON.parse(bytes), clock.body) ||
      clock.status !== 200 ||
      clock.session !== "default" ||
      clock.sourceDispatchN !== expected.dispatchN ||
      !isDeepStrictEqual(timestamp(clock.instant), timestamp(expected.at)) ||
      !isDeepStrictEqual(timestamp(clock.body.clock), timestamp(expected.at))
    )
      return missing();
  } catch {
    return missing();
  }
  for (const [cell, exchange, item, time] of [
    [original, expected, sourceItem, times[0]],
    [actual, observed, localItem, times[1]],
  ]) {
    const cancels = cell.events.filter(
      (e) => e.event === "stream-cancel" && e.reason === "unacked-owned-delivery",
    );
    if (cancels.length !== 1 || !(cancels[0].n < exchange.dispatchN)) return missing();
    const statuses = cell.events.filter(
      (e) => e.event === "stream-status" && e.n > cancels[0].n && e.n < exchange.dispatchN,
    );
    if (
      statuses.length !== 1 ||
      canonicalStatus(statuses[0].code) !== "CANCELLED" ||
      statuses[0].details !== "Cancelled on client"
    )
      return missing();
    const prior = cell.frames
      .filter((f) => f.direction === "in" && f.n < cancels[0].n)
      .flatMap((f) => f.body.receivedMessages ?? [])
      .filter((i) => i.message?.messageId === item.message.messageId);
    if (
      prior.length !== 1 ||
      prior[0].ackId === item.ackId ||
      !isDeepStrictEqual(prior[0].message.publishTime, time)
    )
      return differs();
    if (
      cell.exchanges.filter((e) => e.method === "Pull" && e.response.body?.receivedMessages?.length)
        .length !== 1 ||
      cell.exchanges.some(
        (e) => e.method === "Acknowledge" && e.request.body.ackIds?.includes(item.ackId),
      ) ||
      cell.frames.some((f) => f.direction === "out" && f.body.ackIds?.includes(item.ackId))
    )
      return missing();
  }
  if (
    ![expected.response.bodyBytes, observed.response.bodyBytes].every(
      (n) => Number.isSafeInteger(n) && n >= 0,
    )
  )
    return missing();
  if (
    expected.response.bodyBytes !== observed.response.bodyBytes ||
    sourceItem.message.publishTime.length !== localItem.message.publishTime.length
  )
    return differs();
  const project = (body) => ({
    ...body,
    receivedMessages: body.receivedMessages.map((i) => ({
      ...i,
      ackId: { type: "string", nonempty: true },
      message: {
        ...i.message,
        messageId: { publication: true },
        publishTime: { publication: true },
      },
    })),
  });
  if (!isDeepStrictEqual(project(expected.response.body), project(observed.response.body)))
    return differs();
  const hashes = [expected.response.bodySha256, observed.response.bodySha256];
  if (!hashes.every((value) => /^[a-f0-9]{64}$/.test(value ?? "")))
    return { ...missing(), physicalVerdict: "NOT_COMPARABLE" };
  return {
    ...decision("MATCH", "explicit own Pull redelivery, fresh ACK and publication proof"),
    tokenUse: "notObserved",
    physicalVerdict: hashes[0] === hashes[1] ? "MATCH" : "DIVERGES",
  };
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
    if (cell.id === "S07" && approvedBound && proof.semanticsVerified === true) {
      for (const row of cell.rows.filter(
        (r) =>
          r.method === "Pull" &&
          r.reason === "ACK selector unresolved; no shape selection inferred",
      )) {
        const expected = original.exchanges.find((e) => e.dispatchN === row.sourceDispatchN);
        const observed = actual.exchanges.find((e) => e.n === row.localN);
        Object.assign(
          row,
          ownPullComparison(original, actual, expected, observed, proof, approvedDisposition),
        );
      }
    }
    const shapeMatches =
      original.frames.length === actual.frames.length &&
      original.frames.every((f, i) => f.direction === actual.frames[i].direction);
    const layoutMatches =
      shapeMatches &&
      original.frames.every((f, i) => f.blob?.bytes === actual.frames[i].blob?.bytes);
    const terminalVerdict = cell.id === "S03" ? nativeTerminalVerdict(original, actual) : "MATCH";
    cell.nativeSemantics = {
      verdict:
        proof.semanticsVerified !== true
          ? "NOT_COMPARABLE"
          : terminalVerdict !== "MATCH"
            ? terminalVerdict
            : shapeMatches
              ? "MATCH"
              : "DIVERGES",
      scope:
        "executed identity-bound receive, ACK, presence and timing guards; physical layout remains separate",
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
      cell.approvedComparison = approvedNativeComparison(
        original,
        actual,
        proof,
        approvedDisposition,
        approvedBound,
      );
      cell.approvedComparison.physicalVerdict = cell.nativeLayout.verdict;
      cell.debts.push(...(approvedDisposition?.remainingDebts?.[cell.id] ?? []));
    }
    cell.rows.push({
      method: "StreamingPull",
      transport: "grpc",
      verdict: approved
        ? cell.approvedComparison.verdict
        : terminalVerdict !== "MATCH"
          ? terminalVerdict
          : layoutMatches
            ? "MATCH"
            : "DIVERGES",
      ...(approved ? { physicalVerdict: cell.nativeLayout.verdict } : {}),
      reason: approved
        ? "explicit pinned ACK projection and recorded terminal details"
        : layoutMatches
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
