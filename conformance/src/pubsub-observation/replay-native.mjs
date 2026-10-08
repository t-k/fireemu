import grpc from "@grpc/grpc-js";
import { isDeepStrictEqual } from "node:util";
import { CAPS } from "./plan.mjs";

export function rewriteNativeFrame(frame, bindings, invalidAck, ackSlots = null) {
  const result = structuredClone(frame);
  for (const field of ["ackIds", "modifyDeadlineAckIds"])
    if (result[field])
      result[field] = result[field].map((value) =>
        field === "ackIds" && value === invalidAck
          ? value
          : field === "ackIds" && ackSlots
            ? liveAckSlot(ackSlots, value)
            : bindings.get("ack", value),
      );
  return result;
}
function liveAckSlot(slots, sourceToken) {
  if (!slots.has(sourceToken)) throw new Error("native ACK slot requires an actual live receive");
  return slots.get(sourceToken);
}
function unorderedFlow(cell, sourceCell, opener) {
  if (cell.id !== "S06" || cell.variant !== "flow-control") return null;
  const exchanges = sourceCell?.exchanges ?? [];
  const setup = (method) =>
    exchanges.filter(
      (e) =>
        e.method === method &&
        e.request.body.name === opener.subscription &&
        e.response.ok === true &&
        e.response.unknown !== true &&
        e.response.body.name === opener.subscription,
    );
  const creates = setup("CreateSubscription"),
    gets = setup("GetSubscription");
  if (creates.length !== 1 || gets.length !== 1)
    throw new Error("native unordered ordering witness missing");
  const flag = (value) => {
    if (value === undefined || value === false) return false;
    if (value === true) return true;
    throw new Error("native unordered ordering witness invalid");
  };
  const ordering = flag(creates[0].request.body.enableMessageOrdering);
  if (
    flag(creates[0].response.body.enableMessageOrdering) !== ordering ||
    flag(gets[0].response.body.enableMessageOrdering) !== ordering
  )
    throw new Error("native unordered ordering witness contradictory");
  if (ordering) return null;
  const publications = new Map();
  for (const exchange of exchanges.filter((e) => e.method === "Publish")) {
    const messages = exchange.request.body.messages,
      ids = exchange.response.body?.messageIds;
    if (
      exchange.request.body.topic !== creates[0].request.body.topic ||
      exchange.response.ok !== true ||
      exchange.response.unknown === true ||
      messages?.length !== 1 ||
      ids?.length !== 1 ||
      publications.has(ids[0])
    )
      throw new Error("native unordered owned publication witness invalid");
    if (messages[0].orderingKey) return null;
    publications.set(ids[0], messages[0]);
  }
  const pending = new Map();
  for (const frame of sourceCell.frames.filter((f) => f.direction === "in")) {
    if (!frame.verified || frame.body.receivedMessages?.length !== 1)
      throw new Error("native unordered source cardinality witness invalid");
    const item = frame.body.receivedMessages[0],
      publication = publications.get(item.message?.messageId);
    if (
      !publication ||
      pending.has(item.message.messageId) ||
      !["data", "attributes", "orderingKey"].every((field) =>
        isDeepStrictEqual(publication[field], item.message[field]),
      )
    )
      throw new Error("native unordered owned receive witness invalid");
    pending.set(item.message.messageId, item);
  }
  if (pending.size !== 3 || publications.size !== 3)
    throw new Error("native unordered owned multiset witness incomplete");
  return { pending, sourceIds: [...pending.keys()], ackSlots: new Map() };
}
function legalTimestamp(value) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).some((key) => !["seconds", "nanos"].includes(key))
  )
    return false;
  const seconds = Object.hasOwn(value, "seconds") ? value.seconds : "0";
  const nanos = Object.hasOwn(value, "nanos") ? value.nanos : 0;
  if (
    !(typeof seconds === "string" && /^-?(0|[1-9]\d{0,11})$/.test(seconds)) &&
    !(typeof seconds === "number" && Number.isSafeInteger(seconds))
  )
    return false;
  const epoch = BigInt(seconds);
  return (
    epoch >= -62135596800n &&
    epoch <= 253402300799n &&
    Number.isInteger(nanos) &&
    nanos >= 0 &&
    nanos <= 999999999
  );
}

export function matchNativeReceive(source, actual, bindings) {
  if (
    !Array.isArray(source.receivedMessages) ||
    !Array.isArray(actual.receivedMessages) ||
    source.receivedMessages.length !== actual.receivedMessages.length
  )
    throw new Error("native receive cardinality mismatch");
  for (const [index, item] of source.receivedMessages.entries()) {
    const peer = actual.receivedMessages[index];
    const present = Object.hasOwn(item.message ?? {}, "publishTime");
    if (
      present !== Object.hasOwn(peer.message ?? {}, "publishTime") ||
      (present &&
        (!legalTimestamp(item.message.publishTime) || !legalTimestamp(peer.message.publishTime)))
    )
      throw new Error("native receive timestamp presence or structure mismatch");
  }
  bindings.linkReceive(source, actual);
  const rewrite = (body) => ({
    ...body,
    receivedMessages: body.receivedMessages.map((item) => ({
      ...item,
      ackId: undefined,
      message: { ...item.message, messageId: undefined, publishTime: undefined },
    })),
  });
  if (!isDeepStrictEqual(rewrite(source), rewrite(actual)))
    throw new Error("native receive semantic mismatch");
}
export function createActionClock({
  advance,
  now = () => performance.now(),
  wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
}) {
  let last = -Infinity;
  const opened = new Map(),
    requests = [];
  async function dispatch(row) {
    const instant = Date.parse(row.at);
    if (!Number.isFinite(instant) || instant < last) throw new Error("logical clock regressed");
    last = instant;
    const receipt = { n: row.n ?? null, instant: new Date(instant).toISOString() };
    await advance(receipt);
    requests.push(receipt);
  }
  return {
    dispatch,
    open(cellId) {
      if (opened.has(cellId)) throw new Error("stream already open");
      opened.set(cellId, now());
    },
    async native(row, sourceEvents = []) {
      if (!opened.has(row.cellId)) throw new Error("native clock requires open stream");
      const ends = sourceEvents.filter(
        (event) => event.cellId === row.cellId && event.event === "stream-observation-window-end",
      );
      const end = ends[0];
      const postWindowCancel =
        row.event === "stream-cancel" &&
        row.reason === "window-end" &&
        sourceEvents.some((event) => isDeepStrictEqual(event, row)) &&
        ends.length === 1 &&
        Number.isSafeInteger(end.n) &&
        Number.isSafeInteger(row.n) &&
        end.n < row.n &&
        Number.isFinite(end.elapsedMs) &&
        end.elapsedMs >= 0 &&
        end.elapsedMs <= row.elapsedMs &&
        Date.parse(end.at) <= Date.parse(row.at);
      const ceiling = postWindowCancel ? 90000 + CAPS.cleanupReserveMs : 90000;
      if (!Number.isFinite(row.elapsedMs) || row.elapsedMs < 0 || row.elapsedMs > ceiling)
        throw new Error("native elapsed bound");
      const remaining = row.elapsedMs - (now() - opened.get(row.cellId));
      if (remaining > 0) await wait(remaining);
      await dispatch(row);
    },
    elapsed: (cellId) => now() - opened.get(cellId),
    requests,
  };
}

// A finite action connector; all token substitutions come from an actual owned receive.
export function createNativeReplay({
  wire,
  bindings,
  clock,
  cells,
  sourceCells = [],
  journal = null,
}) {
  let active = null;
  const witnesses = new Map();
  const receivedAt = new WeakMap();
  function checkActualReceives() {
    if (active?.receiptViolation) throw new Error("native actual receive violated quiet interval");
  }
  async function quietProbe(nextRow) {
    const probe = active?.probe;
    if (!probe || nextRow.elapsedMs < probe.elapsedMs + 1000) return;
    active.probe = null;
    await clock.native({
      ...probe.origin,
      elapsedMs: probe.elapsedMs,
      at: new Date(Date.parse(probe.origin.at) + probe.delayMs).toISOString(),
    });
    const endMs = probe.elapsedMs + 1000;
    while (clock.elapsed(active.cellId) < endMs) {
      const frame = await active.stream.next(endMs - clock.elapsed(active.cellId));
      if (frame?.receivedMessages?.length)
        throw new Error("native recorded quiet interval violated");
      if (!frame) {
        await clock.native({
          ...probe.origin,
          elapsedMs: endMs,
          at: new Date(Date.parse(probe.origin.at) + probe.delayMs + 1000).toISOString(),
        });
        break;
      }
    }
    checkActualReceives();
    witnesses.get(active.cellId).probes ??= [];
    witnesses.get(active.cellId).probes.push({
      sourceN: probe.origin.n,
      kind: probe.kind,
      elapsedMs: clock.elapsed(active.cellId),
      quietMs: 1000,
    });
  }
  return {
    recordFrame(frame) {
      if (!active || !Number.isFinite(frame.elapsedMs) || frame.elapsedMs < 0) return;
      active.clockOriginOffsetMs ??= clock.elapsed(active.cellId) - frame.elapsedMs;
      if (frame.direction === "out") {
        active.lastOutboundMs = frame.elapsedMs;
        active.lastOutboundBody = frame.body;
        if (frame.body.ackIds?.length) active.creditHeld = false;
      } else if (frame.direction === "in") {
        receivedAt.set(frame.body, frame.elapsedMs);
        active.receipts ??= [];
        active.receipts.push({ body: frame.body, elapsedMs: frame.elapsedMs });
        if (
          frame.body.receivedMessages?.length &&
          (active.creditHeld ||
            (active.deadlineUntilMs !== undefined && frame.elapsedMs < active.deadlineUntilMs))
        )
          active.receiptViolation = true;
      }
    },
    async frame(row) {
      const cell = cells.find((c) => c.id === row.cellId);
      if (!cell || cell.group !== "G4") throw new Error("native cell scope");
      if (!active) {
        if (row.direction !== "out" || row.elapsedMs < 0) throw new Error("native opener order");
        const unordered = unorderedFlow(
          cell,
          sourceCells.find((c) => c.id === cell.id),
          row.body,
        );
        await clock.dispatch(row);
        clock.open(cell.id);
        active = {
          unordered,
          cellId: cell.id,
          sourceOpenedAt: Date.parse(row.at),
        };
        active.stream = await wire.open({ cellId: cell.id, opener: row.body });
        witnesses.set(cell.id, {
          sourceFrames: [],
          actions: [],
          completed: false,
          semanticsVerified: false,
        });
      } else {
        if (active.cellId !== cell.id) throw new Error("concurrent native cell refused");
        await quietProbe(row);
        await clock.native(row);
        checkActualReceives();
        if (row.direction === "out") {
          const outbound = rewriteNativeFrame(
            row.body,
            bindings,
            cell.invalidAck,
            active.unordered?.ackSlots,
          );
          const expectedOutbound = structuredClone(outbound);
          active.lastOutboundMs = undefined;
          active.lastOutboundBody = undefined;
          active.stream.write(outbound);
          if (
            active.lastOutboundBody !== undefined &&
            !isDeepStrictEqual(active.lastOutboundBody, expectedOutbound)
          )
            throw new Error("native actual outbound semantic mismatch");
          if (active.unordered)
            for (const token of row.body.ackIds ?? []) active.unordered.ackSlots.delete(token);
          if (
            cell.variant === "in-stream-deadline-update" &&
            row.body.modifyDeadlineSeconds?.[0] === 20
          ) {
            if (!Number.isFinite(active.lastOutboundMs) || active.lastOutboundBody !== outbound)
              throw new Error("native outbound update receipt missing or mismatched");
            active.deadlineUntilMs = active.lastOutboundMs + 20000;
            active.probe = {
              origin: row,
              elapsedMs: row.elapsedMs + 10000,
              delayMs: 10000,
              kind: "deadline-before-expiry",
            };
          }
          if (cell.invalidAck && row.body.ackIds?.includes(cell.invalidAck))
            witnesses.get(cell.id).invalidAckStartedMs = clock.elapsed(cell.id);
        } else {
          const actual = await active.stream.next(10000);
          if (!actual) throw new Error("native expected receive missing");
          checkActualReceives();
          if (active.deadlineUntilMs !== undefined || active.creditHeld) {
            const instant = receivedAt.get(actual);
            if (!Number.isFinite(instant))
              throw new Error("native actual receive timestamp missing");
            if (active.creditHeld || instant < active.deadlineUntilMs)
              throw new Error("native actual receive violated quiet interval");
          }
          if (active.unordered) {
            if (row.body.receivedMessages?.length !== 1 || actual.receivedMessages?.length !== 1)
              throw new Error("native receive cardinality mismatch");
            const received = actual.receivedMessages[0];
            const matches = [...active.unordered.pending].filter(
              ([id]) => bindings.get("message", id) === received.message?.messageId,
            );
            if (matches.length !== 1)
              throw new Error("native unordered owned receive missing or duplicate");
            const [id, candidate] = matches[0];
            matchNativeReceive({ ...row.body, receivedMessages: [candidate] }, actual, bindings);
            const slot = row.body.receivedMessages[0].ackId;
            if (active.unordered.ackSlots.has(slot))
              throw new Error("native ACK slot already live");
            active.unordered.ackSlots.set(slot, received.ackId);
            active.unordered.pending.delete(id);
          } else matchNativeReceive(row.body, actual, bindings);
          if (cell.variant === "flow-control" && actual.receivedMessages?.length) {
            const instant = receivedAt.get(actual);
            if (!Number.isFinite(instant))
              throw new Error("native actual receive timestamp missing");
            if (
              active.receipts.some(
                (receipt) =>
                  receipt.body !== actual &&
                  receipt.body.receivedMessages?.length &&
                  receipt.elapsedMs >= instant,
              )
            )
              throw new Error("native actual receive violated quiet interval");
            active.creditHeld = true;
          }
          if (
            cell.variant === "flow-control" &&
            !witnesses
              .get(cell.id)
              .sourceFrames.some((n) => n !== witnesses.get(cell.id).sourceFrames[0])
          ) {
            active.creditHeld = true;
            active.probe = {
              origin: row,
              elapsedMs: row.elapsedMs + 5000,
              delayMs: 5000,
              kind: "held-credit",
            };
          }
        }
      }
      witnesses.get(cell.id).sourceFrames.push(row.n);
    },
    async action(row) {
      if (!active || row.cellId !== active.cellId)
        throw new Error("native action requires active stream");
      const proof = witnesses.get(row.cellId);
      const timed = {
        ...row,
        elapsedMs: row.elapsedMs ?? Math.min(90000, Date.parse(row.at) - active.sourceOpenedAt),
      };
      await quietProbe(timed);
      await clock.native(timed, sourceCells.find((cell) => cell.id === row.cellId)?.events);
      checkActualReceives();
      if (row.event === "stream-write-end") active.stream.end();
      else if (row.event === "stream-cancel") active.stream.cancel(row.reason);
      else if (row.event === "stream-case-observation") {
        const state = active.stream.state();
        if (
          Boolean(row.state?.terminal) !== Boolean(state.terminal) ||
          (row.state?.terminal && row.state.terminal.code !== state.terminal?.code)
        )
          throw new Error("native terminal witness mismatch");
        if (row.state?.inboundEnded && !state.inboundEnded)
          throw new Error("native half-close witness missing");
        if (row.invalidAckObservedMs !== null && row.invalidAckObservedMs !== undefined) {
          const measured = clock.elapsed(row.cellId) - proof.invalidAckStartedMs;
          if (
            !Number.isFinite(measured) ||
            row.invalidAckObservedMs < 30000 ||
            measured < 30000 ||
            state.terminal ||
            state.received
          )
            throw new Error("native silence window incomplete");
          proof.silenceMs = measured;
        }
        if (active.deadlineUntilMs !== undefined) {
          const observedUntilMs = clock.elapsed(row.cellId) - active.clockOriginOffsetMs;
          if (!Number.isFinite(observedUntilMs) || observedUntilMs < active.deadlineUntilMs)
            throw new Error("native actual receive observation ended before expiry");
          proof.observedUntilMs = observedUntilMs;
          proof.deadlineUntilMs = active.deadlineUntilMs;
        }
        if (active.cellId === "S10") {
          const observedElapsedMs = clock.elapsed(row.cellId);
          const observation = journal?.write({
            event: "stream-case-observation",
            cellId: active.cellId,
            state: structuredClone(state),
            elapsedMs: observedElapsedMs,
          });
          proof.zeroOutcome = {
            state: structuredClone(state),
            observedElapsedMs,
            observationN: observation?.n ?? null,
          };
        }
        if (active.unordered) {
          const expectedIds = active.unordered.sourceIds
            .map((id) => bindings.get("message", id))
            .toSorted();
          const actualIds = (active.receipts ?? [])
            .flatMap((receipt) =>
              (receipt.body.receivedMessages ?? []).map((item) => item.message?.messageId),
            )
            .toSorted();
          if (
            active.unordered.pending.size ||
            active.unordered.ackSlots.size ||
            !isDeepStrictEqual(expectedIds, actualIds)
          )
            throw new Error("native unordered owned multiset or live ACK slots incomplete");
        }
        proof.completed = !state.incomplete;
        proof.semanticsVerified = proof.completed;
      } else throw new Error("unlisted native action");
      proof.actions.push({
        sourceN: row.n,
        event: row.event,
        elapsedMs: clock.elapsed(row.cellId),
      });
    },
    closeCell(cellId) {
      if (active && active.cellId !== cellId) throw new Error("native close cell mismatch");
      active?.stream.dispose();
      active = null;
    },
    close() {
      active?.stream.dispose();
      active = null;
    },
    witnesses,
  };
}

// Only the declared credential-free loopback development transport is used by A replay.
export function anonymousLocalMetadata(original) {
  const metadata = original.clone();
  metadata.remove("authorization");
  return metadata;
}
export function createReplayClient(target, { onTerminalDetails = () => {} } = {}) {
  if (!/^127\.0\.0\.1:[1-9]\d{0,4}$/.test(target) || Number(target.split(":")[1]) > 65535)
    throw new Error("replay loopback target required");
  class ReplayClient extends grpc.Client {
    makeUnaryRequest(...args) {
      args[4] = anonymousLocalMetadata(args[4]);
      return super.makeUnaryRequest(...args);
    }
    makeBidiStreamRequest(...args) {
      args[3] = anonymousLocalMetadata(args[3]);
      const rpc = super.makeBidiStreamRequest(...args);
      for (const name of ["error", "status"])
        rpc.on(name, (value) => onTerminalDetails(`stream-${name}`, value.details));
      return rpc;
    }
  }
  return new ReplayClient(target, grpc.credentials.createInsecure(), {
    "grpc.enable_retries": 0,
    "grpc.max_receive_message_length": 65536,
  });
}
