import { isDeepStrictEqual } from "node:util";
import { PROJECT, SUITE, validatePlan } from "./plan.mjs";
import { createSchedulingDisposition } from "./scheduling-disposition.mjs";
import { compareEmptyAttributeValueDisposition } from "./empty-attribute-value-disposition.mjs";

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
  const witness = packet.plan.selection === "snapshot-origin-witness";
  const expectedCells = witness ? 2 : 26;
  if (
    (!witness && packet.plan.selection) ||
    packet.plan.cells.filter((c) => !c.reserve).length !== expectedCells
  )
    throw new Error("original C26 or approved snapshot witness plan required");
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
  if (pending.size || finished.size !== expectedCells || summary.results?.length !== expectedCells)
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
const publicationProposal = "8238575c8202949f721b59bb9c97ee36b3f0ae701efd552f4169c70fcf0c1c53";
const snapshotProposal = "c11c23ae6486c496c9f8f5469dd8bed3ac2630f0274b0f44b270196df4c35a78";
const week = 604800000000000n,
  hour = 3600000000000n;
function timestamp(value) {
  if (typeof value !== "string") return null;
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{3}|\d{6}|\d{9}))?Z$/.exec(value);
  if (!match || Number(match[1].slice(0, 4)) < 1) return null;
  const ms = Date.parse(`${match[1]}Z`);
  if (!Number.isFinite(ms) || new Date(ms).toISOString().slice(0, 19) !== match[1]) return null;
  return {
    instant: BigInt(ms) * 1000000n + BigInt((match[2] ?? "").padEnd(9, "0")),
    precision: match[2]?.length ?? 0,
  };
}
function authorityBound(disposition, input, cell, owner, proposal) {
  const runtime = input.runtimeInputs;
  return (
    disposition?.[`owner${owner}`]?.proposalSha256 === proposal &&
    ["runId", "sourceHead", "packetSha256", "descriptorSha256"].every(
      (key) => disposition.source?.[key] === input.metadata[key],
    ) &&
    Array.isArray(disposition.cellIds) &&
    disposition.cellIds.includes(cell.id) &&
    runtime &&
    ["binarySha256", "inputsSha256"].every(
      (key) =>
        /^[a-f0-9]{64}$/.test(runtime[key] ?? "") &&
        disposition.runtimeInputs?.[key] === runtime[key],
    )
  );
}
function publicationClock(source, receipt) {
  const requested = timestamp(receipt?.requestedInstant),
    readback = timestamp(receipt?.body?.clock),
    dispatch = timestamp(source.at);
  return receipt?.sourceRequestId === source.requestId &&
    receipt.sourceN === source.n &&
    receipt.status === 200 &&
    requested &&
    readback &&
    dispatch &&
    requested.instant === dispatch.instant &&
    readback.instant === requested.instant
    ? readback
    : null;
}
function publicationTime(publication, sourceValue, localValue, bound, topic) {
  const source = timestamp(sourceValue),
    local = timestamp(localValue);
  const result = {
    owner: 1135,
    proposalSha256: publicationProposal,
    publicationSourceRequestId: publication.source.requestId,
    publicationSourceN: publication.source.n,
    verdict: "NOT_COMPARABLE",
  };
  if (
    !source ||
    !local ||
    source.precision !== local.precision ||
    (publication.sourceTime !== undefined && publication.sourceTime !== sourceValue) ||
    (publication.localTime !== undefined && publication.localTime !== localValue)
  )
    result.verdict = "DIVERGES";
  else if (bound && topic === publication.topic && publication.clock)
    result.verdict = local.instant === publication.clock.instant ? "MATCH" : "DIVERGES";
  publication.sourceTime ??= sourceValue;
  publication.localTime ??= localValue;
  // Only independently validated saved messages can witness Snapshot backlog lifetime.
  publication.timestampVerdict = verdict([publication.timestampVerdict ?? "MATCH", result.verdict]);
  return result;
}
const snapshotFields = (body) => {
  if (!body || typeof body !== "object" || Array.isArray(body)) return null;
  const { expireTime: _generated, ...fields } = body;
  return fields;
};
function snapshotTime(source, actual, receipt, state, messages, topics, bound) {
  const result = { owner: 1146, proposalSha256: snapshotProposal, verdict: "NOT_COMPARABLE" },
    original = timestamp(source.reply.body?.expireTime),
    local = timestamp(actual.body?.expireTime),
    name = source.request.name,
    subscription = state.get(source.request.subscription);
  if (
    !original ||
    !local ||
    original.precision !== local.precision ||
    source.reply.body.name !== name ||
    actual.body.name !== name ||
    !same(snapshotFields(source.reply.body), snapshotFields(actual.body))
  ) {
    result.verdict = "DIVERGES";
    return result;
  }
  result.scope = "bounded-source-correlation-and-local-lifetime";
  result.sourceInternalLifetimeVerdict = "NOT_COMPARABLE";
  result.sourceCreationBoundsVerdict = "NOT_COMPARABLE";
  result.automaticExpiryVerdict = "NOT_COMPARABLE";
  if (
    !subscription ||
    subscription.tainted ||
    !topics.has(subscription.topic) ||
    subscription.topic !== source.reply.body.topic
  ) {
    result.gap = "fresh unchanged subscription/topic backlog unavailable";
    return result;
  }
  const publications = [...messages.values()].filter(
    (p) =>
      p.topic === subscription.topic && p.source.n > subscription.createdN && p.source.n < source.n,
  );
  const backlog = publications.filter(
    (p) => !subscription.localAcknowledged.has(p.sourceMessageId),
  );
  if (subscription.localAckGap) {
    result.gap = subscription.localAckGap;
    return result;
  }
  if (!publications.length || publications.some((p) => p.timestampVerdict !== "MATCH")) {
    result.gap = "saved publication witness unavailable";
    return result;
  }
  const clock = publicationClock(source, receipt);
  if (!clock) {
    result.gap = "actual local Snapshot creation clock unavailable";
    return result;
  }
  const oldest = (items, key) =>
    items.reduce((min, p) => {
      const value = timestamp(p[key]).instant;
      return min === null || value < min ? value : min;
    }, null);
  const expectedLocalExpiry = backlog.length
    ? oldest(backlog, "localTime") + week
    : clock.instant + week;
  result.localLifetimeVerdict =
    local.instant === expectedLocalExpiry &&
    local.instant <= clock.instant + week &&
    local.instant >= clock.instant + hour
      ? "MATCH"
      : "DIVERGES";
  result.subscription = source.request.subscription;
  result.publicationSourceNs = backlog.map((p) => p.source.n);
  if (result.localLifetimeVerdict === "DIVERGES") {
    result.verdict = "DIVERGES";
    return result;
  }
  const sourceBacklog = publications.filter(
    (p) => !subscription.sourceAcknowledged.has(p.sourceMessageId),
  );
  // Public saved timestamps do not expose Google's internal backlog-age clock.
  result.sourcePublicExpiryRelationVerdict =
    sourceBacklog.length && original.instant === oldest(sourceBacklog, "sourceTime") + week
      ? "MATCH"
      : "NOT_COMPARABLE";
  if (!bound || source.reply.unknown || subscription.sourceAckGap) {
    result.gap =
      subscription.sourceAckGap ??
      (source.reply.unknown
        ? "successful source Snapshot creation unavailable"
        : "approved source/runtime disposition unavailable");
    return result;
  }
  result.sourceCorrelationVerdict = "MATCH";
  result.verdict = "MATCH";
  return result;
}
function createNackDisposition(input, cell, authority) {
  if (
    !authority ||
    !["R8", "N8"].includes(cell.id) ||
    !["567e1cd860a1", "45298b949da0"].includes(input.metadata.runId) ||
    input.metadata.sourceHead !== "3235e54940ff1ece6004d3e78e70548ca6eba85c" ||
    input.metadata.packetSha256 !==
      "285a6220ed6c7e7efdafbe8618a52e3f87aac1be57a0ea7a684ae80b75126c80" ||
    input.metadata.descriptorSha256 !==
      "3b455b9613b20aa89d2ea277962652f110f45847c9b80668a66605517aba5707" ||
    authority.proposalSha256 !==
      "aab063ec406aa8ad4395b8f21eb251e0157d6a933576ff66ecdd906f89e0961b" ||
    authority.owner1213LineSha256 !==
      "b05cb78d655502359c268032d1893991bb6c4e19a2370cf05f6133c02675f775" ||
    !["runId", "sourceHead", "packetSha256", "descriptorSha256"].every(
      (k) => authority.source?.[k] === input.metadata[k],
    ) ||
    !["binarySha256", "inputsSha256"].every(
      (k) =>
        /^[a-f0-9]{64}$/.test(input.runtimeInputs?.[k] ?? "") &&
        authority.runtimeInputs?.[k] === input.runtimeInputs[k],
    ) ||
    !Array.isArray(authority.cellIds) ||
    !authority.cellIds.includes(cell.id)
  )
    return null;
  const stages = ["before-predecessor-ACK", "after-predecessor-ACK"];
  const role = (e) => {
    const next = cell.exchanges.find((x) => x.n > e.n)?.n ?? Infinity;
    const obs = cell.observations.filter(
      (o) =>
        o.n > e.responseN &&
        o.n < next &&
        o.subscription === e.request.subscription &&
        stages.includes(o.stage),
    );
    return obs.length === 1 ? obs[0].stage : null;
  };
  const windows = new Map(),
    checks = [];
  let nacked = false,
    predecessor = null,
    subscriptionName = null;
  const current = () =>
    windows.get("after-predecessor-ACK") ?? windows.get("before-predecessor-ACK");
  return {
    owner: 1213,
    nack(source, call, actual, subscriptions, tokens) {
      if (source.method !== "ModifyAckDeadline" || source.request.ackDeadlineSeconds !== 0) return;
      const prior = cell.exchanges.findLast(
        (e) =>
          e.n < source.n &&
          e.method === "Pull" &&
          e.request.subscription === source.request.subscription &&
          e.reply.ok,
      );
      const initial = prior?.reply.body?.receivedMessages;
      const binding =
        initial?.length === 1
          ? tokens.get(`${source.request.subscription}\0${initial[0].ackId}`)
          : null;
      const sub = subscriptions.get(source.request.subscription);
      const valid =
        binding &&
        sub?.enableMessageOrdering === true &&
        source.request.ackIds?.length === 1 &&
        source.request.ackIds[0] === initial[0].ackId &&
        call.request.ackIds[0] === binding.ackId;
      if (!valid) {
        checks.push("NOT_COMPARABLE");
        return;
      }
      predecessor = binding.sourceMessageId;
      subscriptionName = source.request.subscription;
      nacked =
        source.reply.ok &&
        actual.ok &&
        source.reply.code === actual.code &&
        source.reply.status === actual.status &&
        same(source.reply.body, actual.body);
      checks.push(nacked ? "MATCH" : "DIVERGES");
    },
    pull(source, actual, publications, subscription) {
      const stage = role(source);
      if (!stage || !nacked) return null;
      if (
        source.request.subscription !== subscriptionName ||
        subscription?.enableMessageOrdering !== true
      ) {
        checks.push("NOT_COMPARABLE");
        return null;
      }
      let w = windows.get(stage);
      if (!w) {
        const sources = cell.exchanges.filter(
          (e) =>
            e.method === "Pull" && role(e) === stage && e.request.subscription === subscriptionName,
        );
        const sourceItems = sources.flatMap((e) => e.reply.body?.receivedMessages ?? []);
        w = {
          stage,
          sources,
          sourceItems,
          required: new Set(sourceItems.map((i) => i.message?.messageId)),
          seen: new Map(),
          pending: new Map(),
          acked: new Set(),
          verdicts: [],
        };
        windows.set(stage, w);
      }
      const pre = windows.get(stages[0]);
      if (stage === stages[1] && (!pre?.acked.has(predecessor) || pre.pending.size)) {
        w.verdicts.push("DIVERGES");
      }
      const items = actual.body?.receivedMessages ?? [];
      if (
        !Array.isArray(items) ||
        !Number.isSafeInteger(source.request.maxMessages) ||
        items.length > source.request.maxMessages
      ) {
        w.verdicts.push("DIVERGES");
        return { kind: "nack", bindings: [] };
      }
      const envelope = { ...actual.body },
        expected = { ...source.reply.body };
      delete envelope.receivedMessages;
      delete expected.receivedMessages;
      if (!same(envelope, expected)) w.verdicts.push("DIVERGES");
      for (const item of items) {
        const matches = [...publications.values()].filter(
          (p) =>
            p.topic === subscription.topic &&
            p.messageId === item.message?.messageId &&
            same(p.payload, payload(item.message)),
        );
        const p = matches.length === 1 ? matches[0] : null;
        if (
          !p ||
          !w.required.has(p.sourceMessageId) ||
          w.seen.has(p.sourceMessageId) ||
          typeof item.ackId !== "string" ||
          !item.ackId ||
          [...w.pending.values()].some(
            (b) =>
              b.delivered.ackId === item.ackId ||
              b.publication.payload.orderingKey === p.payload.orderingKey,
          )
        ) {
          w.verdicts.push("DIVERGES");
          continue;
        }
        const deadline = timestamp(source.at)?.instant;
        if (
          deadline === undefined ||
          !Number.isSafeInteger(subscription.ackDeadlineSeconds) ||
          subscription.ackDeadlineSeconds <= 0
        ) {
          w.verdicts.push("NOT_COMPARABLE");
          continue;
        }
        const binding = {
          publication: p,
          delivered: item,
          witnesses: w.sourceItems.filter((i) => i.message?.messageId === p.sourceMessageId),
          deadline: deadline + BigInt(subscription.ackDeadlineSeconds) * 1000000000n,
        };
        w.seen.set(p.sourceMessageId, binding);
        w.pending.set(p.sourceMessageId, binding);
      }
      return { kind: "nack", bindings: [...w.pending.values()] };
    },
    owns(subscription) {
      return nacked && subscription === subscriptionName;
    },
    ackIds(subscription, source) {
      const w = current();
      if (subscription !== subscriptionName || !w)
        throw new Error("NACK window current ACK unavailable");
      const ids = (source.request.ackIds ?? []).map((id) => {
        const items = w.sourceItems.filter((i) => i.ackId === id);
        if (items.length !== 1) throw new Error("NACK source ACK identity unavailable");
        return items[0].message?.messageId;
      });
      if (
        ids.length !== w.pending.size ||
        new Set(ids).size !== ids.length ||
        ids.some((id) => !w.pending.has(id))
      )
        throw new Error("NACK delivered batch incomplete before ACK");
      const now = timestamp(source.at)?.instant;
      if (now === undefined || ids.some((id) => now >= w.pending.get(id).deadline))
        throw new Error("NACK current ACK expired");
      return ids.map((id) => w.pending.get(id).delivered.ackId);
    },
    ack(subscription, ids, actual, at) {
      const w = current();
      if (subscription !== subscriptionName || !w) return;
      const now = timestamp(at)?.instant;
      if (
        !actual.ok ||
        now === undefined ||
        ids.length !== w.pending.size ||
        [...w.pending.values()].some((b) => !ids.includes(b.delivered.ackId) || now >= b.deadline)
      ) {
        w.verdicts.push("DIVERGES");
        return;
      }
      for (const id of w.pending.keys()) w.acked.add(id);
      w.pending.clear();
    },
    finish() {
      const proof = [...windows.values()].map((w) => ({
        stage: w.stage,
        required: [...w.required],
        received: [...w.seen.keys()],
        acknowledged: [...w.acked],
        verdict: verdict([
          ...w.verdicts,
          w.required.size > 0 &&
          w.seen.size === w.required.size &&
          w.acked.size === w.required.size &&
          !w.pending.size
            ? "MATCH"
            : "NOT_COMPARABLE",
        ]),
      }));
      return {
        owner: 1213,
        proposalSha256: authority.proposalSha256,
        owner1213LineSha256: authority.owner1213LineSha256,
        source: authority.source,
        runtimeInputs: authority.runtimeInputs,
        windows: proof,
        verdict: verdict([
          ...checks,
          ...proof.map((w) => w.verdict),
          proof.length === 2 && proof[0].required.includes(predecessor)
            ? "MATCH"
            : "NOT_COMPARABLE",
        ]),
      };
    },
  };
}

export async function replayRecording(
  input,
  execute,
  {
    enter = () => {},
    observe = () => {},
    timestampDisposition,
    schedulingDisposition,
    nackDisposition,
    emptyAttributeValueDisposition,
    emptyAttributeValueComparator,
    emptyAttributeValueRawBodyFor = () => undefined,
    clockReceiptFor = () => undefined,
  } = {},
) {
  const results = [];
  const wireComparator = emptyAttributeValueDisposition
    ? (emptyAttributeValueComparator ?? compareEmptyAttributeValueDisposition)
    : null;
  for (const cell of input.cells) {
    enter(cell);
    const messages = new Map(),
      publicationIds = new Map(),
      subscriptionTopics = new Map(),
      subscriptions = new Map(),
      freshTopics = new Set(),
      snapshots = new Map(),
      tokens = new Map(),
      acked = new Set(),
      exchanges = [];
    const scheduling =
      createSchedulingDisposition(input, cell, schedulingDisposition) ??
      createNackDisposition(input, cell, nackDisposition);
    const schedulingInvariants = [];
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
      let schedulingAck = false,
        schedulingPull = null;
      try {
        if (call.method === "Acknowledge" && scheduling?.owns(call.request.subscription)) {
          schedulingAck = true;
          call.request.ackIds = scheduling.ackIds(call.request.subscription, source);
        }
        if (call.request.ackIds && !schedulingAck)
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
        const clockReceipt = clockReceiptFor(source);
        if (!actual || (actual.unknown === true && !source.cancellation))
          throw new Error("unknown local response");
        let expected = structuredClone(source.reply.body),
          semantic = "MATCH";
        const timestampProofs = [];
        let heldSnapshot = null,
          pairedSnapshot = null;
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
              source,
              clock: publicationClock(source, clockReceipt),
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
        if (
          source.method === "CreateTopic" &&
          source.reply.ok &&
          actual.ok &&
          same(source.reply.body, actual.body) &&
          source.reply.body?.name === source.request.name
        )
          freshTopics.add(source.request.name);
        if (
          source.method === "CreateSubscription" &&
          source.reply.ok &&
          actual.ok &&
          same(source.reply.body, actual.body) &&
          source.reply.body?.name === source.request.name &&
          source.reply.body.topic === source.request.topic
        )
          subscriptions.set(source.request.name, {
            topic: source.request.topic,
            createdN: source.n,
            tainted: Boolean(source.request.filter || source.reply.body.filter),
            filter: source.reply.body.filter ?? source.request.filter ?? "",
            enableMessageOrdering: source.reply.body.enableMessageOrdering === true,
            ackDeadlineSeconds: source.reply.body.ackDeadlineSeconds,
            currentDeliveries: new Map(),
            localAcknowledged: new Set(),
            sourceAcknowledged: new Set(),
          });
        if (
          ["Seek", "ModifyAckDeadline", "UpdateSubscription", "DeleteSubscription"].includes(
            source.method,
          )
        ) {
          const state = subscriptions.get(source.request.subscription ?? source.request.name);
          if (state) state.tainted = true;
        }
        scheduling?.nack?.(source, call, actual, subscriptions, tokens);
        if (source.method === "ModifyAckDeadline" && scheduling?.owner === 1213)
          schedulingInvariants.push(
            publicationClock(source, clockReceipt) ? "MATCH" : "NOT_COMPARABLE",
          );
        if (source.method === "Pull" && source.reply.ok && actual.ok && scheduling) {
          schedulingPull = scheduling.pull(
            source,
            actual,
            messages,
            subscriptions.get(source.request.subscription),
          );
          if (schedulingPull) {
            schedulingInvariants.push(
              publicationClock(source, clockReceipt) ? "MATCH" : "NOT_COMPARABLE",
            );
            const received = expected?.receivedMessages ?? [],
              local = actual.body?.receivedMessages ?? [];
            for (const item of received) {
              const publication = [...messages.values()].find(
                (p) =>
                  p.sourceMessageId === item.message?.messageId &&
                  p.topic === subscriptionTopics.get(source.request.subscription),
              );
              const delivered = schedulingPull.bindings.find(
                (b) => b.publication === publication,
              )?.delivered;
              if (!publication || !delivered) {
                semantic = "NOT_COMPARABLE";
                continue;
              }
              tokens.set(`${source.request.subscription}\0${item.ackId}`, {
                sourceMessageId: publication.sourceMessageId,
                messageId: publication.messageId,
                ackId: delivered.ackId,
                deliveredAt: Date.parse(source.at) - Date.parse(input.metadata.at),
              });
              item.ackId = delivered.ackId;
              item.message.messageId = publication.messageId;
              if (timestampDisposition) item.message.publishTime = delivered.message.publishTime;
            }
            for (const { publication, delivered, witnesses } of schedulingPull.bindings) {
              const savedWitnesses =
                witnesses.length || schedulingPull.kind !== "seek"
                  ? witnesses
                  : cell.exchanges
                      .filter(
                        (e) =>
                          e.method === "Pull" &&
                          e.reply.ok &&
                          !e.reply.unknown &&
                          e.request.subscription === source.request.subscription &&
                          e.n > publication.source.n &&
                          e.n < schedulingPull.seek.n &&
                          exchanges.some(
                            (entry) => entry.sourceN === e.n && entry.semanticVerdict === "MATCH",
                          ),
                      )
                      .flatMap((e) => e.reply.body?.receivedMessages ?? [])
                      .filter((item) => item.message?.messageId === publication.sourceMessageId);
              const normalized = savedWitnesses.map((item) => {
                const value = structuredClone(item);
                value.ackId = delivered.ackId;
                value.message.messageId = delivered.message.messageId;
                if (timestampDisposition) value.message.publishTime = delivered.message.publishTime;
                return value;
              });
              schedulingInvariants.push(
                !savedWitnesses.length
                  ? "NOT_COMPARABLE"
                  : normalized.some((item) => same(item, delivered))
                    ? "MATCH"
                    : "DIVERGES",
              );
              if (timestampDisposition) {
                const witness = cell.exchanges
                  .flatMap((e) => e.reply.body?.receivedMessages ?? [])
                  .find((i) => i.message?.messageId === publication.sourceMessageId);
                timestampProofs.push(
                  publicationTime(
                    publication,
                    witness?.message.publishTime,
                    delivered.message.publishTime,
                    authorityBound(timestampDisposition, input, cell, 1135, publicationProposal),
                    subscriptionTopics.get(source.request.subscription),
                  ),
                );
              }
            }
            if (!Array.isArray(local)) throw new Error("delivery envelope unresolved");
          }
        }
        if (source.method === "Pull" && source.reply.ok && actual.ok && !schedulingPull) {
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
            const subscription = subscriptions.get(source.request.subscription);
            if (subscription) {
              const deliveredClock = publicationClock(source, clockReceipt);
              subscription.currentDeliveries.set(publication.sourceMessageId, {
                sourceAckId: item.ackId,
                binding,
                deadline:
                  deliveredClock &&
                  Number.isSafeInteger(subscription.ackDeadlineSeconds) &&
                  subscription.ackDeadlineSeconds > 0
                    ? deliveredClock.instant + BigInt(subscription.ackDeadlineSeconds) * 1000000000n
                    : null,
              });
            }
            if (timestampDisposition) {
              const proof = publicationTime(
                publication,
                item.message.publishTime,
                delivered.message.publishTime,
                authorityBound(timestampDisposition, input, cell, 1135, publicationProposal),
                subscriptionTopics.get(source.request.subscription),
              );
              timestampProofs.push(proof);
              item.message.publishTime = delivered.message.publishTime;
            }
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
        if (
          timestampDisposition &&
          source.reply.ok &&
          actual.ok &&
          source.method === "CreateSnapshot"
        ) {
          const proof = snapshotTime(
            source,
            actual,
            clockReceipt,
            subscriptions,
            messages,
            freshTopics,
            authorityBound(timestampDisposition, input, cell, 1146, snapshotProposal),
          );
          timestampProofs.push(proof);
          if (expected && actual.body) expected.expireTime = actual.body.expireTime;
          heldSnapshot = {
            sourceBody: structuredClone(source.reply.body),
            localBody: structuredClone(actual.body),
            proof,
          };
          snapshots.set(source.request.name, heldSnapshot);
        }
        if (
          timestampDisposition &&
          source.reply.ok &&
          actual.ok &&
          source.method === "GetSnapshot"
        ) {
          const pending = snapshots.get(source.request.name);
          const proof = {
            owner: 1146,
            proposalSha256: snapshotProposal,
            verdict: "NOT_COMPARABLE",
          };
          const a = timestamp(expected?.expireTime),
            b = timestamp(actual.body?.expireTime);
          if (!a || !b || a.precision !== b.precision) proof.verdict = "DIVERGES";
          else if (pending)
            proof.verdict =
              same(source.reply.body, pending.sourceBody) && same(actual.body, pending.localBody)
                ? pending.proof.verdict
                : "DIVERGES";
          if (source.reply.unknown && proof.verdict !== "DIVERGES")
            proof.verdict = "NOT_COMPARABLE";
          timestampProofs.push(proof);
          if (expected && actual.body) expected.expireTime = actual.body.expireTime;
          pairedSnapshot = pending;
          if (!authorityBound(timestampDisposition, input, cell, 1146, snapshotProposal))
            proof.verdict = verdict([
              proof.verdict === "DIVERGES" ? "DIVERGES" : "MATCH",
              "NOT_COMPARABLE",
            ]);
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
          semantic = semantic === "NOT_COMPARABLE" ? "NOT_COMPARABLE" : "DIVERGES";
        semantic = verdict([semantic, ...timestampProofs.map((p) => p.verdict)]);
        if (pairedSnapshot?.entry) {
          pairedSnapshot.entry.semanticVerdict = verdict([pairedSnapshot.baseVerdict, semantic]);
          observe(pairedSnapshot.entry);
          pairedSnapshot.entry = null;
        }
        if (source.method === "Acknowledge" && schedulingAck) {
          scheduling.ack(source.request.subscription, call.request.ackIds, actual, source.at);
          schedulingInvariants.push(
            publicationClock(source, clockReceipt) ? "MATCH" : "NOT_COMPARABLE",
          );
          schedulingInvariants.push(
            source.reply.ok === actual.ok &&
              source.reply.code === actual.code &&
              source.reply.status === actual.status &&
              same(source.reply.body, actual.body)
              ? "MATCH"
              : "DIVERGES",
          );
          if (
            semantic === "MATCH" &&
            source.request.ackIds.some((id) => !tokens.has(`${source.request.subscription}\0${id}`))
          )
            semantic = "NOT_COMPARABLE";
        }
        if (source.method === "Acknowledge" && !schedulingAck) {
          const subscription = subscriptions.get(source.request.subscription);
          const ackClock = publicationClock(source, clockReceipt);
          for (const [index, sourceAckId] of source.request.ackIds.entries()) {
            const binding = tokens.get(`${source.request.subscription}\0${sourceAckId}`);
            const current = subscription?.currentDeliveries.get(binding?.sourceMessageId);
            if (subscription) {
              if (
                !current ||
                !ackClock ||
                current.deadline === null ||
                !actual.ok ||
                actual.unknown ||
                actual.code !== "OK" ||
                !same(actual.body, {}) ||
                (actual.status !== 200 &&
                  !(source.transport === "grpc" && actual.status === undefined))
              ) {
                subscription.localAckGap = "ACK current local lease/effect unavailable";
                subscription.sourceAckGap = "ACK source effect unavailable";
              } else if (ackClock.instant >= current.deadline) {
                // An expired local lease cannot remove this message; source effect stays unproved.
                subscription.sourceAckGap = "ACK source effect unavailable for expired local lease";
              } else if (current.binding.ackId !== call.request.ackIds[index]) {
                subscription.localAckGap = "ACK local token is not the current delivery";
                subscription.sourceAckGap = "ACK source token is not the current delivery";
              } else {
                subscription.localAcknowledged.add(binding.sourceMessageId);
                if (
                  current.sourceAckId === sourceAckId &&
                  source.reply.ok &&
                  !source.reply.unknown &&
                  semantic === "MATCH"
                )
                  subscription.sourceAcknowledged.add(binding.sourceMessageId);
                else subscription.sourceAckGap = "ACK source current token/effect unavailable";
              }
            }
            if (actual.ok) acked.add(call.request.ackIds[index]);
          }
        }
        const physical =
          source.reply.bodyBytes == null || actual.bodyBytes == null
            ? "NOT_COMPARABLE"
            : source.reply.bodyBytes === actual.bodyBytes &&
                source.reply.bodySha256 === actual.bodySha256
              ? "MATCH"
              : "DIVERGES";
        let wireDisposition;
        if (wireComparator) {
          try {
            wireDisposition = wireComparator({
              input,
              cell,
              source,
              actual,
              sourceBody: input.emptyAttributeValueSourceBodies?.get(
                `${source.n}:${source.requestId}:${source.transport}`,
              ),
              localBody: emptyAttributeValueRawBodyFor(source),
              disposition: emptyAttributeValueDisposition,
            });
          } catch {
            wireDisposition = {
              verdict: "NOT_COMPARABLE",
              reason: "wire disposition evaluation unavailable",
            };
          }
        }
        const entry = {
          ...(wireDisposition ? { wireDisposition } : {}),
          cellId: cell.id,
          requestId: source.requestId,
          sourceN: source.n,
          method: source.method,
          semanticVerdict: semantic,
          physicalVerdict: physical,
          ...(schedulingPull || schedulingAck
            ? {
                schedulingCandidate: true,
                exactSemanticVerdict: semantic,
                localRequest: structuredClone(call.request),
              }
            : {}),
          actual,
          ...(timestampProofs.length
            ? {
                timestampProofs: timestampProofs.map((proof) =>
                  Object.assign(proof, {
                    cellId: cell.id,
                    sourceBinding: Object.fromEntries(
                      ["runId", "sourceHead", "packetSha256", "descriptorSha256"].map((key) => [
                        key,
                        input.metadata[key],
                      ]),
                    ),
                    runtimeInputs: structuredClone(input.runtimeInputs),
                  }),
                ),
                ...(source.transport === "grpc" ? { wireVerdict: "NOT_COMPARABLE" } : {}),
              }
            : {}),
        };
        exchanges.push(entry);
        if (heldSnapshot) {
          heldSnapshot.entry = entry;
          heldSnapshot.baseVerdict = semantic;
          entry.semanticVerdict = verdict([semantic, "NOT_COMPARABLE"]);
        } else observe(entry);
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
    for (const pending of snapshots.values()) if (pending.entry) observe(pending.entry);
    const schedulingProof = scheduling?.finish();
    const retainedVerdicts = exchanges
      .filter((e) => !e.schedulingCandidate)
      .map((e) => e.semanticVerdict);
    results.push({
      ...(schedulingProof?.windows.length
        ? {
            ...(schedulingProof.owner === 1213
              ? { nackDisposition: schedulingProof }
              : { schedulingDisposition: schedulingProof }),
            dispositionVerdict: verdict([
              ...retainedVerdicts,
              ...schedulingInvariants,
              schedulingProof.verdict,
              ...exchanges.flatMap((e) => (e.timestampProofs ?? []).map((p) => p.verdict)),
            ]),
          }
        : {}),
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
    dispositionCounts: Object.fromEntries(
      ["MATCH", "DIVERGES", "NOT_COMPARABLE"].map((v) => [
        v,
        results.filter((c) => (c.dispositionVerdict ?? c.semanticVerdict) === v).length,
      ]),
    ),
    parentClosureReady: false,
  };
}
