import { isDeepStrictEqual } from "node:util";
import { PROJECT, SUITE, validatePlan } from "./plan.mjs";

const same = isDeepStrictEqual;
const verdict = (values) =>
  values.includes("DIVERGES")
    ? "DIVERGES"
    : values.includes("NOT_COMPARABLE")
      ? "NOT_COMPARABLE"
      : "MATCH";
const owned = (name, runId, cellId) =>
  typeof name === "string" &&
  new RegExp(
    `^projects/${PROJECT}/(topics|subscriptions|snapshots)/fe${runId}-${cellId.toLowerCase()}-[a-z0-9-]+$`,
  ).test(name);
function resources(request, runId, cellId) {
  for (const key of ["name", "topic", "subscription", "snapshot"])
    if (request[key] !== undefined && !owned(request[key], runId, cellId))
      throw new Error("foreign C resource refused");
}
export function importRecording(input) {
  const { packet, descriptor, summary, rows, issued, packetSha256, descriptorSha256 } = input;
  validatePlan(packet.plan);
  if (packet.plan.selection || packet.plan.cells.filter((c) => !c.reserve).length !== 26)
    throw new Error("original C26 plan required");
  if (!Array.isArray(rows) || rows.length < 1 || rows.length > 10000 || !Array.isArray(issued))
    throw new Error("bounded C journals required");
  const metadata = rows[0];
  if (
    metadata.event !== "run-start" ||
    rows.filter((r) => r.event === "run-start").length !== 1 ||
    metadata.suite !== SUITE ||
    metadata.project !== PROJECT ||
    descriptor.suite !== SUITE ||
    descriptor.head !== packet.sourceHead ||
    metadata.sourceHead !== packet.sourceHead ||
    metadata.packetSha256 !== packetSha256 ||
    metadata.descriptorSha256 !== descriptorSha256 ||
    packet.descriptorSha256 !== descriptorSha256 ||
    !/^[a-f0-9]{12}$/.test(metadata.runId) ||
    !packet.runIds.includes(metadata.runId) ||
    !Number.isFinite(Date.parse(metadata.at))
  )
    throw new Error("C source/packet binding refused");
  for (const key of ["runId", "suite", "project", "sourceHead", "packetSha256", "envelopeId"])
    if (metadata[key] !== summary[key]) throw new Error("C summary binding refused");
  if (summary.recordingComplete !== true || summary.resourcesClosed !== true)
    throw new Error("closed C recording required");
  const cells = packet.plan.cells
    .filter((c) => !c.reserve)
    .map((c) => Object.assign({}, c, { exchanges: [], observations: [] }));
  const pending = new Map(),
    answered = new Set(),
    finished = new Set();
  let previous = 0,
    instant = -Infinity;
  for (const row of rows) {
    if (
      !Number.isSafeInteger(row.n) ||
      row.n <= previous ||
      !Number.isFinite(Date.parse(row.at)) ||
      Date.parse(row.at) < instant
    )
      throw new Error("C journal order refused");
    previous = row.n;
    instant = Date.parse(row.at);
    if (row === metadata) continue;
    const cell = cells.find((c) => c.id === row.cellId);
    if (!cell || finished.has(cell.id))
      throw new Error("inactive reserve or settled cell evidence refused");
    if (row.event === "request-dispatch") {
      if (
        !Number.isSafeInteger(row.requestId) ||
        pending.has(row.requestId) ||
        answered.has(row.requestId) ||
        row.transport !== cell.transport
      )
        throw new Error("unique C dispatch required");
      resources(row.request, metadata.runId, cell.id);
      pending.set(row.requestId, structuredClone(row));
    } else if (row.event === "response") {
      const dispatch = pending.get(row.requestId);
      if (
        !dispatch ||
        dispatch.cellId !== row.cellId ||
        dispatch.method !== row.method ||
        dispatch.transport !== row.transport ||
        !row.reply
      )
        throw new Error("C response dispatch binding refused");
      pending.delete(row.requestId);
      answered.add(row.requestId);
      cell.exchanges.push({ ...dispatch, reply: row.reply, responseN: row.n });
    } else if (row.event === "delivery-observation") cell.observations.push(row);
    else if (row.event === "client-cancel") {
      const dispatch = pending.get(row.requestId);
      if (
        !dispatch ||
        dispatch.cellId !== row.cellId ||
        dispatch.method !== "Pull" ||
        cell.variant !== "cancel-followup" ||
        row.cause !== "intentional-unary-cancel" ||
        row.pending !== true
      )
        throw new Error("C pending cancel binding refused");
      dispatch.cancellation = row;
    } else if (row.event === "case-result") {
      if (row.complete !== true || row.cleanupClosed !== true || pending.size)
        throw new Error("completed C cell required");
      const result = summary.results?.filter((r) => r.cellId === cell.id);
      if (
        result?.length !== 1 ||
        result[0].complete !== true ||
        result[0].cleanupClosed !== true ||
        !same(result[0].observations ?? [], row.observations ?? [])
      )
        throw new Error("C result binding refused");
      finished.add(cell.id);
    } else throw new Error("unlisted C journal event");
  }
  if (pending.size || finished.size !== 26 || summary.results?.length !== 26)
    throw new Error("original C26 completion required");
  for (const item of issued)
    if (!cells.some((c) => owned(item.name, metadata.runId, c.id)))
      throw new Error("foreign or reserve issued resource refused");
  return { ...input, metadata, cells };
}
const payload = (message) => ({
  data: message.data,
  attributes: message.attributes ?? {},
  orderingKey: message.orderingKey ?? "",
});
export async function replayRecording(
  input,
  execute,
  { enter = () => {}, observe = () => {} } = {},
) {
  const results = [];
  for (const cell of input.cells) {
    enter(cell);
    const messages = new Map(),
      publicationIds = new Map(),
      subscriptionTopics = new Map(),
      tokens = new Map(),
      acked = new Set(),
      exchanges = [];
    let stopped = false;
    for (const source of cell.exchanges) {
      if (stopped && !source.category.startsWith("cleanup")) continue;
      const call = {
        cellId: cell.id,
        category: source.category,
        transport: source.transport,
        service: /Topic|Publish/.test(source.method) ? "Publisher" : "Subscriber",
        method: source.method,
        request: structuredClone(source.request),
        at: source.at,
      };
      try {
        if (call.request.ackIds)
          call.request.ackIds = call.request.ackIds.map((id) => {
            const item = tokens.get(`${call.request.subscription}\0${id}`);
            if (!item) throw new Error("ACK selector unresolved");
            return item.ackId;
          });
        if (source.cancellation) {
          const c = source.cancellation;
          const outstanding = tokens.get(
              `${source.request.subscription}\0${c.lastObservedUnacked?.ackId}`,
            ),
            control = tokens.get(`${source.request.subscription}\0${c.acknowledgedControl?.ackId}`);
          if (
            !outstanding ||
            !control ||
            outstanding.sourceMessageId !== c.lastObservedUnacked.messageId ||
            control.sourceMessageId !== c.acknowledgedControl.messageId ||
            !acked.has(control.ackId) ||
            acked.has(outstanding.ackId)
          )
            throw new Error("actual cancel delivery/control binding unresolved");
          call.cancelObservation = true;
          call.cancelBinding = {
            outstandingMessageId: outstanding.messageId,
            outstandingAckId: outstanding.ackId,
            ackedControlMessageId: control.messageId,
            ackedControlAckId: control.ackId,
            deliveredAt: outstanding.deliveredAt,
          };
        }
        const actual = await execute(call, source);
        if (!actual || (actual.unknown === true && !source.cancellation))
          throw new Error("unknown local response");
        let expected = structuredClone(source.reply.body),
          semantic = "MATCH";
        if (source.method === "Publish" && source.reply.ok && actual.ok) {
          const ids = source.reply.body?.messageIds,
            local = actual.body?.messageIds;
          if (
            !Array.isArray(ids) ||
            !Array.isArray(local) ||
            ids.length !== source.request.messages.length ||
            ids.length !== local.length ||
            new Set(local).size !== local.length
          )
            throw new Error("publication identity unresolved");
          ids.forEach((id, i) => {
            if (
              typeof id !== "string" ||
              !/^\d+$/.test(id) ||
              typeof local[i] !== "string" ||
              !/^\d+$/.test(local[i])
            )
              throw new Error("publication ID refused");
            const key = `${source.request.topic}\0${id}`,
              reverseKey = `${source.request.topic}\0${local[i]}`,
              prior = messages.get(key),
              sourceId = publicationIds.get(reverseKey);
            if (
              (sourceId !== undefined && sourceId !== id) ||
              (prior &&
                (prior.messageId !== local[i] ||
                  !same(prior.payload, payload(source.request.messages[i]))))
            )
              throw new Error("same-topic publication identity collapsed or drifted");
            publicationIds.set(reverseKey, id);
            messages.set(key, {
              sourceMessageId: id,
              messageId: local[i],
              topic: source.request.topic,
              payload: payload(source.request.messages[i]),
            });
          });
          expected.messageIds = local;
        }
        if (
          ["CreateSubscription", "GetSubscription"].includes(source.method) &&
          source.reply.ok &&
          actual.ok &&
          typeof source.reply.body?.topic === "string" &&
          source.reply.body.topic === actual.body?.topic
        )
          subscriptionTopics.set(
            source.request.name ?? source.request.subscription,
            source.reply.body.topic,
          );
        if (source.method === "Pull" && source.reply.ok && actual.ok) {
          const received = expected?.receivedMessages ?? [],
            local = actual.body?.receivedMessages ?? [];
          if (!Array.isArray(received) || !Array.isArray(local))
            throw new Error("delivery envelope unresolved");
          const simultaneous = [];
          for (const item of received) {
            const candidates = [...messages.values()].filter(
              (p) =>
                p.sourceMessageId === item.message?.messageId &&
                same(payload(item.message), p.payload) &&
                (!subscriptionTopics.has(source.request.subscription) ||
                  p.topic === subscriptionTopics.get(source.request.subscription)),
            );
            const publication = candidates.length === 1 ? candidates[0] : null;
            const matching = local.filter(
              (l) =>
                publication &&
                l.message?.messageId === publication.messageId &&
                same(payload(l.message), publication.payload),
            );
            if (
              !publication ||
              !same(payload(item.message), publication.payload) ||
              matching.length !== 1 ||
              !matching[0].ackId
            )
              throw new Error("actual same-cell publication/delivery binding unresolved");
            const [delivered] = matching;
            if (
              simultaneous.some(
                (prior) =>
                  (prior.sourceAckId === item.ackId) !== (prior.localAckId === delivered.ackId),
              )
            )
              throw new Error("simultaneous ACK identity equality classes collapsed or drifted");
            simultaneous.push({ sourceAckId: item.ackId, localAckId: delivered.ackId });
            const binding = {
              sourceMessageId: item.message.messageId,
              messageId: publication.messageId,
              ackId: delivered.ackId,
              deliveredAt: Date.parse(source.at) - Date.parse(input.metadata.at),
            };
            const prior = tokens.get(`${source.request.subscription}\0${item.ackId}`);
            if (prior && (prior.ackId !== binding.ackId || prior.messageId !== binding.messageId))
              throw new Error("same-delivery identity drift");
            tokens.set(`${source.request.subscription}\0${item.ackId}`, binding);
            item.ackId = delivered.ackId;
            item.message.messageId = delivered.message.messageId;
          }
          expected = {
            ...expected,
            ...(received.length || Object.hasOwn(expected, "receivedMessages")
              ? { receivedMessages: received }
              : {}),
          };
        }
        if (source.cancellation) {
          const c = actual.clientCancellation;
          if (
            !c ||
            c.pending !== true ||
            c.cause !== "intentional-unary-cancel" ||
            c.cellId !== cell.id ||
            c.subscription !== call.request.subscription ||
            c.transport !== call.transport ||
            c.lastObservedUnacked?.messageId !== call.cancelBinding.outstandingMessageId ||
            c.acknowledgedControl?.messageId !== call.cancelBinding.ackedControlMessageId
          )
            throw new Error("actual pending cancellation missing");
        }
        if (
          source.reply.ok !== actual.ok ||
          source.reply.code !== actual.code ||
          source.reply.status !== actual.status ||
          !same(expected, actual.body)
        )
          semantic = "DIVERGES";
        if (source.method === "Acknowledge" && actual.ok)
          call.request.ackIds.forEach((id) => acked.add(id));
        const physical =
          source.reply.bodyBytes == null || actual.bodyBytes == null
            ? "NOT_COMPARABLE"
            : source.reply.bodyBytes === actual.bodyBytes &&
                source.reply.bodySha256 === actual.bodySha256
              ? "MATCH"
              : "DIVERGES";
        const entry = {
          cellId: cell.id,
          requestId: source.requestId,
          sourceN: source.n,
          method: source.method,
          semanticVerdict: semantic,
          physicalVerdict: physical,
          actual,
        };
        exchanges.push(entry);
        observe(entry);
      } catch (error) {
        const entry = {
          cellId: cell.id,
          requestId: source.requestId,
          sourceN: source.n,
          method: source.method,
          semanticVerdict: "NOT_COMPARABLE",
          physicalVerdict: "NOT_COMPARABLE",
          reason: error.message,
        };
        exchanges.push(entry);
        observe(entry);
        stopped = true;
      }
    }
    results.push({
      id: cell.id,
      coordinates: cell.coordinates,
      semanticVerdict: exchanges.length
        ? verdict(exchanges.map((e) => e.semanticVerdict))
        : "NOT_COMPARABLE",
      physicalVerdict: exchanges.length
        ? verdict(exchanges.map((e) => e.physicalVerdict))
        : "NOT_COMPARABLE",
      exchanges,
    });
  }
  return {
    schema: 1,
    kind: "pubsub-observation-c-executed-replay",
    sourceRunId: input.metadata.runId,
    cells: results,
    counts: Object.fromEntries(
      ["MATCH", "DIVERGES", "NOT_COMPARABLE"].map((v) => [
        v,
        results.filter((c) => c.semanticVerdict === v).length,
      ]),
    ),
    parentClosureReady: false,
  };
}
