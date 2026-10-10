import { isDeepStrictEqual as same } from "node:util";
import { createHash } from "node:crypto";
import { protos } from "@google-cloud/pubsub";
import { requestToWire, responseFromWire } from "../pubsub-production/grpc.mjs";
import { ackWireProjection } from "../pubsub-observation/compare-core.mjs";
import { PROJECT, SUITE, validatePlan, categoryCaps, iamCategory, CAPS } from "./plan.mjs";
import { createLedger, kindOf } from "../pubsub-observation/ledger.mjs";
import { createIamOwnership, readPolicy } from "../pubsub-production/iam.mjs";

const refuse = (condition, message) => {
  if (!condition) throw new Error(`D ${message}`);
};
const instant = (value) => Date.parse(value);
const aggregate = (values) =>
  values.includes("DIVERGES")
    ? "DIVERGES"
    : values.includes("NOT_COMPARABLE")
      ? "NOT_COMPARABLE"
      : "MATCH";
const graph = (run, cell) => {
  const prefix = `projects/${PROJECT}`,
    suffix = `fe${run}-${cell.toLowerCase()}`;
  return {
    topic: `${prefix}/topics/${suffix}-t`,
    deadTopic: `${prefix}/topics/${suffix}-d`,
    subscription: `${prefix}/subscriptions/${suffix}-s`,
    sink: `${prefix}/subscriptions/${suffix}-k`,
  };
};
const good = (reply) =>
  reply?.ok === true &&
  reply.unknown !== true &&
  (reply.status === 200 || (!Object.hasOwn(reply, "status") && reply.code === "OK"));
const bodyBound = (reply) =>
  Number.isSafeInteger(reply?.bodyBytes) &&
  reply.bodyBytes >= 0 &&
  reply.bodyBytes <= CAPS.metadataBytesEachDirection &&
  /^[a-f0-9]{64}$/.test(reply.bodySha256 ?? "");
const forwardedProposal = "3b30ea2ff65d1ddd8d905fa26defa997793b9311ca595c67642ef1f41861420b";
const originTimeKey = "CloudPubSubDeadLetterSourceTopicPublishTime";
function sourceTime(value) {
  const m =
    typeof value === "string" &&
    /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{3}|\d{6}|\d{9}))?Z$/.exec(value);
  const ms = m && Date.parse(`${m[1]}Z`);
  return m &&
    Number(m[1].slice(0, 4)) > 0 &&
    Number.isFinite(ms) &&
    new Date(ms).toISOString().slice(0, 19) === m[1]
    ? {
        instant: BigInt(ms) * 1000000n + BigInt((m[2] ?? "").padEnd(9, "0")),
        precision: m[2]?.length ?? 0,
        origin: `${m[1]}${(m[2] ?? "").replace(/0+$/, "") ? "." + m[2].replace(/0+$/, "") : ""}+00:00`,
      }
    : null;
}
function attributeTime(value) {
  const m =
    typeof value === "string" &&
    /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(?:Z|\+00:00)$/.exec(value);
  return m
    ? sourceTime(
        `${m[1]}${m[2] ? "." + m[2].padEnd(m[2].length <= 3 ? 3 : m[2].length <= 6 ? 6 : 9, "0") : ""}Z`,
      )
    : null;
}
function forwardedProofs(
  cell,
  source,
  actual,
  publications,
  exchanges,
  clockReceiptFor,
  disposition,
) {
  const a = source.reply.body?.receivedMessages?.[0],
    b = actual.body?.receivedMessages?.[0];
  const base = {
    sourceBodySha256: source.reply.bodySha256,
    localBodySha256: actual.bodySha256,
    requiresOwnAck: true,
    verdict: "NOT_COMPARABLE",
  };
  const sink = {
    ...base,
    selector: "body.receivedMessages[0].message.publishTime",
    sourceValue: a?.message?.publishTime,
    localValue: b?.message?.publishTime,
  };
  const origin = {
    ...base,
    selector: `body.receivedMessages[0].message.attributes.${originTimeKey}`,
    sourceValue: a?.message?.attributes?.[originTimeKey],
    localValue: b?.message?.attributes?.[originTimeKey],
  };
  if (!["R2", "R4", "R6", "N2", "N4", "N6"].includes(cell.id) || !a || !b) return [sink, origin];
  const deliveries = exchanges.filter(
    (e) => e.category === "sourcePull" && e.sourceReply?.body?.receivedMessages?.length,
  );
  const candidates = [...publications.entries()].filter(
    ([id, p]) =>
      deliveries.some((e) =>
        e.sourceReply.body.receivedMessages.some((item) => item.message?.messageId === id),
      ) && p.payload.data === a.message.data,
  );
  if (candidates.length !== 1) return [sink, origin];
  const [id, p] = candidates[0],
    last = deliveries.at(-1);
  const sourceSubscription =
    last && cell.exchanges.find((e) => e.n === last.sourceN)?.request.subscription;
  const firstSink = cell.exchanges.find(
    (e) =>
      e.category === "sinkPull" &&
      e.request.subscription === source.request.subscription &&
      e.reply.body?.receivedMessages?.some(
        (item) => item.message?.messageId === a.message.messageId,
      ),
  );
  const triggerCandidates = exchanges.filter((e) => {
    const original = cell.exchanges.find((call) => call.n === e.sourceN);
    return (
      e.category === "sourcePull" &&
      e.sourceN > last.sourceN &&
      e.sourceN < firstSink?.n &&
      original?.request.subscription === sourceSubscription &&
      good(e.sourceReply) &&
      good(e.localReply) &&
      !e.sourceReply.body?.receivedMessages?.length &&
      !e.localReply.body?.receivedMessages?.length
    );
  });
  const trigger = triggerCandidates.length === 1 ? triggerCandidates[0] : undefined;
  sink.forwardCandidateSourceNs = origin.forwardCandidateSourceNs = triggerCandidates.map(
    (e) => e.sourceN,
  );
  const triggerSource = trigger && cell.exchanges.find((e) => e.n === trigger.sourceN),
    clock = triggerSource && clockReceiptFor(triggerSource);
  const times = [sourceTime(a.message.publishTime), sourceTime(b.message.publishTime)],
    saved = sourceTime(clock?.body?.clock),
    requested = sourceTime(clock?.requestedInstant),
    dispatch = sourceTime(triggerSource?.at);
  const sourceStored = sourceTime(p.sourceTime),
    localStored = sourceTime(p.localTime);
  const correlated =
    trigger &&
    last &&
    trigger.sourceN > last.sourceN &&
    exchanges.some((e) => iamCategory(e.category) && e.semanticVerdict === "MATCH") &&
    deliveries.every((e) =>
      e.timestampProofs?.every((proof) => (proof.publicationVerdict ?? proof.verdict) === "MATCH"),
    ) &&
    bodyBound(source.reply) &&
    bodyBound(actual) &&
    bodyBound(clock) &&
    clock.sourceN === triggerSource.n &&
    clock.sourceRequestId === triggerSource.requestId &&
    clock.status === 200 &&
    requested &&
    dispatch &&
    saved;
  const payload = (message) => ({
    data: message.data,
    attributes: Object.fromEntries(
      Object.entries(message.attributes ?? {}).filter(
        ([key]) =>
          ![
            originTimeKey,
            "CloudPubSubDeadLetterSourceSubscription",
            "CloudPubSubDeadLetterSourceSubscriptionProject",
            "CloudPubSubDeadLetterSourceDeliveryCount",
          ].includes(key),
      ),
    ),
    orderingKey: message.orderingKey ?? "",
  });
  const original = {
    data: p.payload.data,
    attributes: p.payload.attributes ?? {},
    orderingKey: p.payload.orderingKey ?? "",
  };
  const relation =
    same(payload(a.message), original) &&
    same(payload(b.message), original) &&
    [a, b].every(
      (item) =>
        item.message.attributes?.CloudPubSubDeadLetterSourceSubscription ===
          sourceSubscription?.split("/").at(-1) &&
        item.message.attributes?.CloudPubSubDeadLetterSourceSubscriptionProject === PROJECT &&
        /^\d+$/.test(item.message.attributes?.CloudPubSubDeadLetterSourceDeliveryCount ?? ""),
    ) &&
    a.message.messageId !== id &&
    b.message.messageId !== p.localId;
  for (const proof of [sink, origin]) {
    proof.publicationSourceN = p.source.n;
    proof.forwardSourceN = trigger?.sourceN;
    proof.sourcePublicationId = id;
    proof.localPublicationId = p.localId;
  }
  if (
    !relation ||
    times.some((t) => !t) ||
    (times[0] && times[1] && times[0].precision !== times[1].precision)
  )
    sink.verdict = "DIVERGES";
  else if (correlated) {
    if (
      requested.instant !== dispatch.instant ||
      saved.instant !== requested.instant ||
      times[1].instant !== saved.instant
    )
      sink.verdict = "DIVERGES";
    else if (disposition?.owner1193?.proposalSha256 === forwardedProposal) sink.verdict = "MATCH";
  }
  if (sourceStored && localStored) {
    const sourceAttribute = attributeTime(origin.sourceValue),
      localAttribute = attributeTime(origin.localValue);
    origin.derivedInstantVerdict =
      sourceAttribute?.instant === sourceStored.instant &&
      localAttribute?.instant === localStored.instant
        ? "MATCH"
        : "DIVERGES";
    origin.sourceExpected = sourceStored.origin;
    origin.localExpected = localStored.origin;
    origin.representationVerdict =
      origin.sourceValue === origin.sourceExpected && origin.localValue === origin.localExpected
        ? "MATCH"
        : "DIVERGES";
    if (
      !relation ||
      origin.derivedInstantVerdict === "DIVERGES" ||
      origin.representationVerdict === "DIVERGES"
    )
      origin.verdict = "DIVERGES";
    else if (correlated && disposition?.owner1194?.proposalSha256 === forwardedProposal)
      origin.verdict = "MATCH";
  }
  const prior = exchanges
    .filter((e) => e.category === "sinkPull")
    .flatMap(
      (e) =>
        e.sourceReply?.body?.receivedMessages?.map((item, index) => ({
          source: item,
          local: e.localReply?.body?.receivedMessages?.[index],
        })) ?? [],
    )
    .find((item) => item.source.message?.messageId === a.message.messageId);
  if (
    prior &&
    (prior.source.message.publishTime !== a.message.publishTime ||
      prior.local?.message?.publishTime !== b.message.publishTime ||
      prior.local?.message?.messageId !== b.message.messageId)
  )
    sink.verdict = "DIVERGES";
  sink.publicationVerdict = sink.verdict;
  if (source.transport === "grpc") {
    sink.nativeWire = nativePullWire(source.reply, actual, origin.verdict === "MATCH");
    sink.verdict = aggregate([sink.verdict, sink.nativeWire.verdict]);
  }
  return [sink, origin];
}
function recoverNativePull(reply) {
  if (!good(reply) || !bodyBound(reply)) return null;
  const Type = protos.google.pubsub.v1.PullResponse;
  try {
    const wire = requestToWire(structuredClone(reply.body));
    for (const candidate of [1, 2]) {
      if (candidate === 2)
        for (const item of wire.receivedMessages ?? []) {
          const timestamp = item.message?.publishTime;
          if (timestamp?.seconds === "0" || timestamp?.seconds === 0) delete timestamp.seconds;
          if (timestamp?.nanos === 0) delete timestamp.nanos;
        }
      const bytes = Buffer.from(Type.encode(Type.fromObject(wire)).finish());
      if (
        bytes.length === reply.bodyBytes &&
        createHash("sha256").update(bytes).digest("hex") === reply.bodySha256 &&
        same(
          responseFromWire(
            Type.toObject(Type.decode(bytes), {
              longs: String,
              enums: String,
              bytes: String,
              defaults: false,
            }),
          ),
          reply.body,
        )
      )
        return { bytes, candidate, wire: structuredClone(wire) };
    }
  } catch {
    /* Missing exact captured-wire evidence remains not comparable. */
  }
  return null;
}
function nativePullWire(
  sourceReply,
  localReply,
  originDisposition = false,
  restartAttempt = false,
) {
  const source = recoverNativePull(sourceReply),
    local = recoverNativePull(localReply);
  const proof = {
    sourceRecovered: Boolean(source),
    localRecovered: Boolean(local),
    sourceCandidate: source?.candidate,
    localCandidate: local?.candidate,
    sourceBytes: sourceReply.bodyBytes,
    localBytes: localReply.bodyBytes,
    sourceSha256: sourceReply.bodySha256,
    localSha256: localReply.bodySha256,
    verdict: "NOT_COMPARABLE",
  };
  if (!source || !local) return proof;
  proof.originAttributeDisposition = originDisposition;
  proof.sourceBodyBase64 = source.bytes.toString("base64");
  proof.localBodyBase64 = local.bytes.toString("base64");
  proof.physicalVerdict = source.bytes.equals(local.bytes) ? "MATCH" : "DIVERGES";
  try {
    const originalSource = ackWireProjection(source.bytes, "response", true).fields;
    const originalLocal = ackWireProjection(local.bytes, "response", true).fields;
    proof.originalProjectionVerdict = same(originalSource, originalLocal) ? "MATCH" : "DIVERGES";
    const normalized = [];
    proof.attributesOrder = [];
    for (const [side, recovered] of [
      ["source", source],
      ["local", local],
    ]) {
      const wire = structuredClone(recovered.wire);
      if (restartAttempt)
        for (const item of wire.receivedMessages ?? []) delete item.deliveryAttempt;
      if (originDisposition && side === "source")
        for (const [index, item] of (wire.receivedMessages ?? []).entries())
          if (item.message?.attributes)
            item.message.attributes[originTimeKey] =
              local.wire.receivedMessages[index]?.message?.attributes?.[originTimeKey];
      for (const [index, item] of (wire.receivedMessages ?? []).entries()) {
        if (!item.message?.attributes) continue;
        const entries = Object.entries(item.message.attributes);
        proof.attributesOrder.push({ side, index, keys: entries.map(([key]) => key) });
        item.message.attributes = Object.fromEntries(
          entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
        );
      }
      const bytes = Buffer.from(
        protos.google.pubsub.v1.PullResponse.encode(
          protos.google.pubsub.v1.PullResponse.fromObject(wire),
        ).finish(),
      );
      proof[`${side}MapOrderComparisonSha256`] = createHash("sha256").update(bytes).digest("hex");
      proof[`${side}MapOrderComparisonBytes`] = bytes.length;
      normalized.push(ackWireProjection(bytes, "response", true).fields);
    }
    proof.verdict = same(normalized[0], normalized[1]) ? "MATCH" : "DIVERGES";
  } catch {
    proof.verdict = "DIVERGES";
  }
  return proof;
}
const nativeAbsence = (reply, transport, method) =>
  transport === "grpc" &&
  ["GetTopic", "GetSubscription"].includes(method) &&
  reply?.ok === false &&
  reply.unknown === false &&
  reply.code === "NOT_FOUND" &&
  !Object.hasOwn(reply, "status") &&
  reply.bodyBytes === null &&
  !Object.hasOwn(reply, "bodySha256") &&
  reply.layoutVerdict === "NOT_COMPARABLE_NATIVE_ERROR_BODY_NOT_CAPTURED" &&
  reply.body &&
  !Array.isArray(reply.body) &&
  same(Object.keys(reply.body), ["error"]) &&
  reply.body.error &&
  !Array.isArray(reply.body.error) &&
  same(Object.keys(reply.body.error).sort(), ["message", "status"]) &&
  reply.body.error.status === "NOT_FOUND" &&
  typeof reply.body.error.message === "string" &&
  Number.isSafeInteger(reply.metadataBytesIn) &&
  reply.metadataBytesIn >= 0 &&
  Buffer.byteLength(reply.body.error.message) + reply.metadataBytesIn <=
    CAPS.metadataBytesEachDirection;
export function importRecording(input) {
  refuse(input?.packet?.plan, "fixed recording plan required");
  const {
    packet,
    descriptor,
    summary,
    rows,
    issued,
    iam,
    recovery,
    packetSha256,
    descriptorSha256,
  } = input;
  validatePlan(packet.plan);
  refuse(
    Array.isArray(rows) &&
      rows.length > 0 &&
      rows.length <= 10000 &&
      Array.isArray(issued) &&
      Array.isArray(iam) &&
      iam.length <= 4000 &&
      Array.isArray(recovery),
    "bounded journals required",
  );
  const metadata = rows[0];
  refuse(
    metadata.event === "run-start" &&
      rows.filter((r) => r.event === "run-start").length === 1 &&
      metadata.suite === SUITE &&
      metadata.project === PROJECT &&
      descriptor.suite === SUITE &&
      descriptor.head === packet.sourceHead &&
      metadata.sourceHead === packet.sourceHead &&
      metadata.packetSha256 === packetSha256 &&
      metadata.descriptorSha256 === descriptorSha256 &&
      packet.descriptorSha256 === descriptorSha256 &&
      /^[a-f0-9]{12}$/.test(metadata.runId) &&
      packet.runIds.includes(metadata.runId) &&
      Number.isFinite(instant(metadata.at)),
    "source/packet binding refused",
  );
  for (const key of ["runId", "suite", "project", "sourceHead", "packetSha256", "envelopeId"])
    refuse(metadata[key] === summary[key], "summary binding refused");
  refuse(
    summary.recordingComplete === true &&
      summary.resourcesClosed === true &&
      summary.a2 === false &&
      summary.signalled === false &&
      summary.error === null,
    "closed recording required",
  );
  const cells = packet.plan.cells
    .filter((c) => !c.reserve)
    .map((c) => ({ ...c, exchanges: [], observations: [] }));
  const pending = new Map(),
    answered = new Set(),
    finished = new Set();
  let previous = 0,
    time = -Infinity;
  for (const row of rows) {
    refuse(
      Number.isSafeInteger(row.n) &&
        row.n > previous &&
        Number.isFinite(instant(row.at)) &&
        instant(row.at) >= time,
      "journal order refused",
    );
    previous = row.n;
    time = instant(row.at);
    if (row === metadata) continue;
    const cell = cells.find((c) => c.id === row.cellId);
    refuse(cell && !finished.has(cell.id), "inactive reserve or settled cell refused");
    if (row.event === "request-dispatch") {
      refuse(
        Number.isSafeInteger(row.requestId) &&
          !pending.has(row.requestId) &&
          !answered.has(row.requestId) &&
          row.transport === (iamCategory(row.category) ? "rest" : cell.transport),
        "dispatch binding refused",
      );
      for (const key of ["name", "topic", "subscription", "resource"])
        if (row.request[key] !== undefined)
          refuse(
            Object.values(graph(metadata.runId, cell.id)).includes(row.request[key]),
            "foreign resource refused",
          );
      refuse(
        Number.isSafeInteger(row.requestBodyBytes) &&
          row.requestBodyBytes >= 0 &&
          row.requestBodyBytes <= CAPS.metadataBytesEachDirection &&
          Number.isSafeInteger(row.metadataBytesOut) &&
          row.metadataBytesOut >= 0 &&
          row.metadataBytesOut + row.requestBodyBytes <= CAPS.metadataBytesEachDirection,
        "request byte cap refused",
      );
      pending.set(row.requestId, structuredClone(row));
    } else if (row.event === "response") {
      const dispatch = pending.get(row.requestId);
      refuse(
        dispatch &&
          dispatch.cellId === row.cellId &&
          dispatch.method === row.method &&
          dispatch.transport === row.transport &&
          row.reply &&
          !row.reply.unknown &&
          (bodyBound(row.reply) || nativeAbsence(row.reply, row.transport, row.method)) &&
          Number.isSafeInteger(row.reply.metadataBytesIn) &&
          row.reply.metadataBytesIn >= 0 &&
          row.reply.bodyBytes + row.reply.metadataBytesIn <= CAPS.metadataBytesEachDirection,
        "response binding or physical evidence refused",
      );
      pending.delete(row.requestId);
      answered.add(row.requestId);
      cell.exchanges.push({ ...dispatch, reply: row.reply, responseN: row.n, responseAt: row.at });
    } else if (row.event === "dlq-observation") cell.observations.push(row);
    else if (row.event === "iam-evidence") cell.observations.push(row);
    else if (row.event === "case-result") {
      refuse(
        row.complete === true &&
          row.cleanupClosed === true &&
          pending.size === 0 &&
          row.budgetOverrun === false &&
          row.outstanding?.length === 0 &&
          row.iam?.unsettled?.length === 0,
        "complete cell required",
      );
      const result = summary.results?.filter((r) => r.cellId === cell.id);
      const { event: _event, n: _n, at: _at, ...value } = row;
      refuse(result?.length === 1 && same(result[0], value), "result binding refused");
      cell.result = value;
      cell.finishedAt = row.at;
      finished.add(cell.id);
    } else throw new Error("D unlisted journal event");
  }
  refuse(
    pending.size === 0 && finished.size === 12 && summary.results?.length === 12,
    "original D12 completion required",
  );
  for (const item of issued)
    refuse(
      cells.some((c) => Object.values(graph(metadata.runId, c.id)).includes(item.name)),
      "foreign issued resource refused",
    );
  const ledger = createLedger();
  for (const item of issued) {
    if (item.phase === "sent") ledger.sent(item);
    else if (item.phase === "answered") ledger.answered(item);
    else if (item.phase === "resolved") ledger.replayResolution(item);
    else throw new Error("D unlisted issued phase");
  }
  refuse(ledger.outstanding().length === 0, "issued terminal proof refused");
  for (const cell of cells) validateCell(cell, metadata, iam, issued, recovery);
  refuse(
    instant(rows.at(-1).at) - instant(metadata.at) <= CAPS.sourceWallMs,
    "source wall cap refused",
  );
  const counts = { requests: 0, rest: 0, grpc: 0 };
  for (const cell of cells)
    for (const exchange of cell.exchanges) {
      counts.requests++;
      counts[exchange.transport]++;
    }
  for (const key of Object.keys(counts))
    refuse(counts[key] <= CAPS.G5[key], "source request cap refused");
  const last = recovery.at(-1);
  refuse(
    recovery.length > 1 &&
      recovery.every(
        (r, i) =>
          r.runId === metadata.runId &&
          Number.isSafeInteger(r.sequence) &&
          (i === 0 || r.sequence > recovery[i - 1].sequence),
      ) &&
      last.obligations?.length === 0 &&
      last.iam?.length === 0,
    "recovery closure refused",
  );
  const binding = recovery.find((r) => r.event === "recovery-binding");
  refuse(
    binding &&
      ["runId", "suite", "sourceHead", "packetSha256", "descriptorSha256"].every(
        (k) => binding[k] === metadata[k],
      ),
    "recovery binding refused",
  );
  return { ...input, metadata, cells };
}
function validateCell(cell, metadata, iam, issued, recovery) {
  const names = graph(metadata.runId, cell.id),
    caps = categoryCaps(cell),
    counts = {};
  const observations = cell.observations.filter((r) => r.event === "dlq-observation");
  refuse(
    cell.exchanges.length > 0 &&
      instant(cell.finishedAt) - instant(cell.exchanges[0].at) <= cell.cellMs,
    "cell ceiling refused",
  );
  for (const exchange of cell.exchanges) {
    counts[exchange.category] = (counts[exchange.category] ?? 0) + 1;
    refuse(counts[exchange.category] <= (caps[exchange.category] ?? -1), "category cap refused");
  }
  const calls = (category) => cell.exchanges.filter((e) => e.category === category);
  for (const name of Object.values(names)) {
    const create = calls("create").filter((e) => e.request.name === name),
      remove = calls("cleanupDelete").filter((e) => e.request.name === name),
      read = calls("cleanupGet").filter((e) => e.request.name === name);
    refuse(
      create.length === 1 &&
        good(create[0].reply) &&
        remove.length === 1 &&
        remove[0].reply.ok === true &&
        read.length === 1 &&
        (read[0].reply.status === 404 ||
          nativeAbsence(read[0].reply, read[0].transport, read[0].method)) &&
        remove[0].n > create[0].n &&
        read[0].n > remove[0].n,
      "known create/delete/absence proof refused",
    );
    refuse(
      issued.some(
        (r) =>
          r.name === name &&
          r.phase === "sent" &&
          r.action === "create" &&
          r.transport === create[0].transport &&
          r.requestId === `${name}#1`,
      ) &&
        issued.some(
          (r) =>
            r.name === name &&
            r.phase === "answered" &&
            r.requestId === `${name}#1` &&
            r.kind === kindOf(create[0].reply),
        ) &&
        issued.some(
          (r) =>
            r.name === name &&
            r.phase === "answered" &&
            r.requestId === `${name}#2` &&
            r.kind === kindOf(remove[0].reply),
        ) &&
        issued.some(
          (r) =>
            r.name === name &&
            r.phase === "resolved" &&
            r.resolution === "gone" &&
            r.proof?.kind === "own-delete-404",
        ),
      "issued closure refused",
    );
  }
  refuse(
    same([...cell.result.names].sort(), Object.values(names).sort()),
    "owned graph result refused",
  );
  const stages = new Set([
    "baseline-permission",
    "iam-window",
    "publication-binding",
    "source-delivery",
    "sink-delivery",
    "inactivity-start",
    "inactivity-completed",
    "bounded-window-end",
  ]);
  refuse(
    observations.every((r) => stages.has(r.stage) && Number.isFinite(r.clockMs)),
    "unlisted observation refused",
  );
  refuse(
    same(
      observations.map(({ n: _n, at: _at, ...value }) => value),
      cell.result.observations,
    ),
    "observation result correlation refused",
  );
  for (const observation of cell.observations.filter((r) => r.event === "iam-evidence")) {
    const exchange = cell.exchanges.filter((e) => e.responseN < observation.n).at(-1);
    refuse(
      exchange &&
        iamCategory(exchange.category) &&
        observation.category === exchange.category &&
        same(observation.response, exchange.reply),
      "IAM evidence response correlation refused",
    );
  }
  const publication = calls("publish");
  refuse(
    publication.length === 1 &&
      good(publication[0].reply) &&
      publication[0].reply.body?.messageIds?.length === 1 &&
      publication[0].request.messages?.length === 1 &&
      Buffer.byteLength(publication[0].request.messages[0].data) <= CAPS.smallEncodedPayloadBytes,
    "publication binding refused",
  );
  const binding = observations.filter((r) => r.stage === "publication-binding");
  refuse(
    binding.length === 1 &&
      same(binding[0].messageIds, publication[0].reply.body.messageIds) &&
      same(binding[0].messages, publication[0].request.messages),
    "publication observation correlation refused",
  );
  const expected = publication[0].request.messages[0],
    messageId = publication[0].reply.body.messageIds[0],
    tokens = new Map();
  for (const e of cell.exchanges) {
    if (e.method === "Pull") {
      const items = e.reply.body?.receivedMessages ?? [];
      refuse(
        good(e.reply) && Array.isArray(items) && items.length <= 1,
        "delivery envelope refused",
      );
      for (const item of items) {
        const message = item.message,
          attributes = message?.attributes;
        refuse(
          typeof item.ackId === "string" &&
            item.ackId.length > 0 &&
            item.ackId.length <= 4096 &&
            message?.data === expected.data,
          "foreign message/ACK refused",
        );
        if (e.category === "sourcePull")
          refuse(
            message.messageId === messageId && same(attributes ?? {}, expected.attributes ?? {}),
            "source delivery binding refused",
          );
        else
          refuse(
            e.category === "sinkPull" &&
              typeof message.messageId === "string" &&
              message.messageId.length > 0 &&
              attributes?.CloudPubSubDeadLetterSourceSubscription ===
                names.subscription.split("/").at(-1) &&
              attributes.CloudPubSubDeadLetterSourceSubscriptionProject === PROJECT &&
              /^\d+$/.test(attributes.CloudPubSubDeadLetterSourceDeliveryCount ?? "") &&
              Number.isFinite(instant(attributes.CloudPubSubDeadLetterSourceTopicPublishTime)) &&
              Object.entries(expected.attributes ?? {}).every(([k, v]) => attributes[k] === v),
            "forwarding identity refused",
          );
        tokens.set(`${e.request.subscription}\0${item.ackId}`, item);
      }
      const observation = observations.filter(
        (r) =>
          r.stage === (e.category === "sourcePull" ? "source-delivery" : "sink-delivery") &&
          r.n > e.responseN &&
          r.n < (cell.exchanges.find((next) => next.n > e.responseN)?.n ?? Infinity),
      );
      refuse(
        observation.length === 1 && same(observation[0].items, items),
        "delivery observation binding refused",
      );
    }
    if (e.request.ackIds)
      refuse(
        e.request.ackIds.every((id) => tokens.has(`${e.request.subscription}\0${id}`)),
        "unobserved own ACK refused",
      );
  }
  const managed = cell.arm === "managed-grant-readback-wait",
    localIam = iam.filter((r) => r.cellId === cell.id);
  const iamNames = [names.subscription, names.deadTopic];
  if (managed) {
    refuse(
      localIam.length === 8 && localIam.every((r) => iamNames.includes(r.resource)),
      "managed IAM journal required",
    );
    const ownership = createIamOwnership({
      replay: localIam,
      assertOwned: (name) => refuse(iamNames.includes(name), "foreign IAM resource refused"),
    });
    refuse(ownership.outstanding().length === 0, "IAM restoration refused");
    for (const row of localIam) {
      const category = {
        "grant-intent": "iamSetupWrite",
        "grant-confirmed": "iamSetupReadback",
        "restore-intent": "cleanupIamRestoreWrite",
        "restore-confirmed": "cleanupIamRestoreReadback",
      }[row.phase];
      const matches = calls(category).filter((e) => e.request.resource === row.resource);
      refuse(matches.length === 1, "IAM dispatch correlation refused");
      if (row.before) {
        const preimage = calls(
          row.phase === "grant-intent" ? "baselineIamGet" : "cleanupIamConflictGet",
        ).filter((e) => e.request.resource === row.resource);
        refuse(
          preimage.length === 1 &&
            good(preimage[0].reply) &&
            same(preimage[0].reply.body, row.before) &&
            preimage[0].responseN < matches[0].n,
          "IAM preimage correlation refused",
        );
      }
      if (row.requested)
        refuse(
          same(matches[0].request.policy, row.requested),
          "IAM requested policy correlation refused",
        );
      if (row.readback)
        refuse(same(matches[0].reply, row.readback), "IAM readback correlation refused");
      if (row.setAnswer) {
        const writes = calls(
          row.phase === "grant-confirmed" ? "iamSetupWrite" : "cleanupIamRestoreWrite",
        ).filter((e) => e.request.resource === row.resource);
        refuse(
          writes.length === 1 && same(writes[0].reply, row.setAnswer),
          "IAM write answer correlation refused",
        );
      }
    }
    const window = observations.filter((r) => r.stage === "iam-window");
    const lastGrant = Math.max(...calls("iamSetupWrite").map((e) => instant(e.responseAt)));
    const firstActivity = Math.min(
      ...cell.exchanges
        .filter((e) => ["publish", "sourcePull", "sinkPull"].includes(e.category))
        .map((e) => instant(e.at)),
    );
    refuse(
      window.length === 1 &&
        window[0].waitAfterLastGrantMs === 900000 &&
        window[0].iamConvergenceClaim === false &&
        firstActivity - lastGrant >= 900000,
      "managed IAM wait refused",
    );
    refuse(
      recovery.some((r) => r.cellId === cell.id && r.iam?.length > 0),
      "IAM recovery correspondence required",
    );
  } else {
    refuse(
      localIam.length === 0 && calls("baselineIamGet").length === 2,
      "baseline IAM evidence refused",
    );
    calls("baselineIamGet").forEach((e) => {
      refuse(good(e.reply), "baseline IAM read refused");
      readPolicy(e.reply.body);
    });
    const baseline = observations.filter((r) => r.stage === "baseline-permission");
    refuse(
      baseline.length === 1 &&
        baseline[0].status === "UNAUDITED" &&
        baseline[0].newGrant === false &&
        baseline[0].effectivePermissionClaim === false,
      "UNAUDITED baseline required",
    );
  }
  if (cell.mode === "720-second-source-inactivity") {
    const start = observations.filter((r) => r.stage === "inactivity-start"),
      end = observations.filter((r) => r.stage === "inactivity-completed");
    refuse(
      start.length === 1 &&
        end.length === 1 &&
        start[0].sourceAttempts === 9 &&
        Number.isFinite(start[0].resumeAt) &&
        start[0].resumeAt - 720000 <= start[0].clockMs &&
        start[0].clockMs < start[0].resumeAt &&
        end[0].clockMs >= start[0].resumeAt &&
        end[0].elapsedMs >= 720000 &&
        end[0].elapsedMs >= end[0].clockMs - start[0].clockMs &&
        end[0].elapsedMs <= end[0].clockMs - (start[0].resumeAt - 720000) &&
        end[0].noSourcePullDuringWindow === true &&
        end[0].resetInferred === false,
      "inactivity window refused",
    );
    const before = calls("sourcePull").filter((e) => e.n < start[0].n),
      during = calls("sourcePull").filter((e) => e.n > start[0].n && e.n < end[0].n),
      after = calls("sourcePull").filter((e) => e.n > end[0].n);
    refuse(
      before.length === 9 &&
        during.length === 0 &&
        after.length > 0 &&
        instant(after[0].at) - instant(start[0].at) >= 720000 &&
        calls("sinkPull").some((e) => e.n > start[0].n && e.n < end[0].n),
      "ninth/resumed source and sink activity refused",
    );
  }
}

// Owner1199 evaluates a separate relation: pre(i)=i+1 for i<9, base in {1,10}, post(j)=base+j.
// It preserves every original verdict and supplies no forwarding settlement.
function restartAttemptRelation(input, cell, exchanges, evidence, disposition) {
  const result = {
    owner: 1199,
    verdict: "NOT_COMPARABLE",
    selector: "body.receivedMessages[0].deliveryAttempt",
    forwardingSettled: false,
  };
  const finish = (verdict, reason) => ({ ...result, verdict, reason });
  if (
    !["R5", "N5"].includes(cell.id) ||
    cell.mode !== "720-second-source-inactivity" ||
    cell.arm !== "no-new-grant"
  )
    return finish("NOT_COMPARABLE", "Outside the approved restart variant");
  const bindings = disposition.cells?.filter((b) => b.cellId === cell.id),
    binding = bindings?.length === 1 && bindings[0];
  if (
    disposition.owner1199?.proposalSha256 !==
      "e2e8865fb9569def971cd9acc7bfdee4a8e2e75e5749c5921c7a757d46ba1c38" ||
    disposition.owner1199?.rowSha256WithLf !==
      "17c64221706deef2f6ba3dce37a4c4d326568ed81821dc3a3d94de73b9ff49ad" ||
    !["runId", "sourceHead", "packetSha256", "descriptorSha256"].every(
      (k) => input.metadata[k] !== undefined && disposition.source?.[k] === input.metadata[k],
    ) ||
    !["binarySha256", "inputsSha256"].every(
      (k) =>
        /^[a-f0-9]{64}$/.test(input.runtimeInputs?.[k] ?? "") &&
        disposition.runtimeInputs?.[k] === input.runtimeInputs[k],
    ) ||
    !binding
  )
    return finish("NOT_COMPARABLE", "Owner, recording, runtime or selector binding unavailable");
  result.binding = structuredClone(binding);
  const starts = cell.observations?.filter((r) => r.stage === "inactivity-start"),
    ends = cell.observations?.filter((r) => r.stage === "inactivity-completed");
  const start = starts?.length === 1 && starts[0],
    end = ends?.length === 1 && ends[0];
  if (
    !start ||
    !end ||
    start.n !== binding.inactivityStartSourceN ||
    end.n !== binding.inactivityCompletedSourceN ||
    start.n >= end.n ||
    start.sourceAttempts !== 9 ||
    !Number.isFinite(start.resumeAt) ||
    start.resumeAt - 720000 > start.clockMs ||
    start.clockMs >= start.resumeAt ||
    end.clockMs < start.resumeAt ||
    end.elapsedMs < 720000 ||
    end.elapsedMs < end.clockMs - start.clockMs ||
    end.elapsedMs > end.clockMs - (start.resumeAt - 720000) ||
    end.noSourcePullDuringWindow !== true ||
    end.resetInferred !== false
  )
    return finish("NOT_COMPARABLE", "Exact recorded source inactivity boundary unavailable");
  const pulls = cell.exchanges.filter((r) => r.category === "sourcePull" && r.method === "Pull"),
    before = pulls.filter((r) => r.n < start.n),
    after = pulls.filter((r) => r.n > end.n);
  if (
    before.length !== 9 ||
    pulls.some((r) => r.n >= start.n && r.n <= end.n) ||
    !after.length ||
    before.at(-1).n !== binding.beforeSourceN ||
    after[0].n !== binding.resumedSourceN ||
    instant(after[0].at) - instant(start.at) < 720000
  )
    return finish("NOT_COMPARABLE", "Pre-rest and resumed delivery correspondence unavailable");
  const policy = cell.exchanges.find(
    (r) =>
      r.method === "CreateSubscription" &&
      r.request.name === before[0].request.subscription &&
      r.request.deadLetterPolicy?.maxDeliveryAttempts > 0,
  );
  const localPolicy = policy && exchanges.find((r) => r.sourceN === policy.n);
  if (
    !policy ||
    !good(policy.reply) ||
    localPolicy?.semanticVerdict !== "MATCH" ||
    !good(localPolicy.localReply)
  )
    return finish("NOT_COMPARABLE", "Observed policy-bearing subscription unavailable");
  const paired = [...before, ...after].map((source) => ({
    source,
    local: exchanges.find((r) => r.sourceN === source.n),
    proof: evidence.get(source.n),
  }));
  if (
    paired.some(
      ({ local, proof }) =>
        !proof?.known ||
        !proof.cardinality ||
        local?.physicalVerdict === "NOT_COMPARABLE" ||
        proof.otherVerdict === "NOT_COMPARABLE" ||
        !Number.isSafeInteger(proof.sourceAttempt) ||
        !Number.isSafeInteger(proof.localAttempt) ||
        proof.sourceAttempt < 1 ||
        proof.localAttempt < 1,
    )
  )
    return finish(
      "NOT_COMPARABLE",
      "Complete known paired delivery and clock evidence unavailable",
    );
  const first = paired[0].proof;
  if (
    paired.some(
      ({ proof }) =>
        proof.identityVerdict !== "MATCH" ||
        proof.otherVerdict !== "MATCH" ||
        proof.sourceId !== first.sourceId ||
        proof.localId !== first.localId,
    )
  )
    return finish(
      "DIVERGES",
      "Publication identity, payload or retained non-attempt evidence differs",
    );
  for (const [index, { source, proof }] of paired.entries()) {
    const next = paired[index + 1]?.source.n ?? Infinity;
    const nack = cell.exchanges.find(
      (r) =>
        r.n > source.n &&
        r.n < next &&
        r.category === "nack" &&
        r.method === "ModifyAckDeadline" &&
        r.request.subscription === source.request.subscription &&
        same(r.request.ackIds, [proof.sourceAck]) &&
        r.request.ackDeadlineSeconds === 0,
    );
    const localNack = nack && exchanges.find((r) => r.sourceN === nack.n);
    if (
      !nack ||
      !good(nack.reply) ||
      !good(localNack?.localReply) ||
      localNack.semanticVerdict !== "MATCH" ||
      localNack.physicalVerdict === "NOT_COMPARABLE"
    )
      return finish("NOT_COMPARABLE", "Own ACK/deadline path correspondence unavailable");
  }
  result.deliveries = paired.map(({ source, proof }, i) => ({
    sourceN: source.n,
    phase: i < 9 ? "before" : "resumed",
    ordinal: i < 9 ? i : i - 9,
    sourceAttempt: proof.sourceAttempt,
    localAttempt: proof.localAttempt,
  }));
  if (
    paired
      .slice(0, 9)
      .some(({ proof }, i) => proof.sourceAttempt !== i + 1 || proof.localAttempt !== i + 1)
  )
    return finish("DIVERGES", "Original nine pre-rest attempts differ");
  const sourceBase = paired[9].proof.sourceAttempt,
    localBase = paired[9].proof.localAttempt;
  result.sourceBase = sourceBase;
  result.localBase = localBase;
  result.postDeliveries = after.length;
  if (![1, 10].includes(sourceBase) || ![1, 10].includes(localBase))
    return finish("DIVERGES", "Resumed base is neither reset nor continuation");
  if (
    paired
      .slice(9)
      .some(
        ({ proof }, j) =>
          proof.sourceAttempt !== sourceBase + j || proof.localAttempt !== localBase + j,
      )
  )
    return finish("DIVERGES", "Resumed attempts reset, skip or leave their own delivery ordinal");
  return finish(
    "MATCH",
    "Owner-approved bounded reset-or-continuation relation holds independently",
  );
}

export async function replayRecording(
  input,
  execute,
  {
    enter = () => {},
    observe = () => {},
    clockReceiptFor = () => undefined,
    timestampDisposition,
    restartAttemptDisposition,
  } = {},
) {
  const results = [];
  for (const cell of input.cells) {
    enter(cell);
    const publications = new Map(),
      publicationEvidence = new Map(),
      subscriptionTopics = new Map(),
      tokens = new Map(),
      exchanges = [],
      localOwnership = new Map(),
      localPolicies = new Map(),
      restartEvidence = new Map();
    let stopped = false;
    for (const source of cell.exchanges) {
      const call = {
        cellId: cell.id,
        category: source.category,
        transport: source.transport,
        service: /Topic|Publish/.test(source.method) ? "Publisher" : "Subscriber",
        method: source.method,
        request: structuredClone(source.request),
        at: source.at,
      };
      const resource =
        call.request.resource ??
        call.request.name ??
        call.request.topic ??
        call.request.subscription;
      const creation = ["CreateTopic", "CreateSubscription"].includes(call.method);
      const maintenance = source.category.startsWith("cleanup") && !iamCategory(source.category);
      let entry;
      if (maintenance && localOwnership.get(resource)?.confirmedCreate !== true) {
        if (!localOwnership.has(resource))
          localOwnership.set(resource, {
            confirmedCreate: false,
            deleteConfirmed: false,
            absenceConfirmed: false,
            reason: "Local create was not executed; ownership unconfirmed",
          });
        entry = {
          sourceRequestId: source.requestId,
          sourceN: source.n,
          cellId: cell.id,
          method: source.method,
          category: source.category,
          physicalVerdict: "NOT_COMPARABLE",
          semanticVerdict: "NOT_COMPARABLE",
          resource,
          debt: "Local ownership is unconfirmed; cleanup dispatch refused",
        };
      } else if (stopped && !source.category.startsWith("cleanup")) {
        entry = {
          sourceRequestId: source.requestId,
          sourceN: source.n,
          cellId: cell.id,
          method: source.method,
          category: source.category,
          physicalVerdict: "NOT_COMPARABLE",
          semanticVerdict: "NOT_COMPARABLE",
          debt: "Ordinary dispatch stopped after an incomplete local call",
        };
      } else if (
        iamCategory(source.category) &&
        localOwnership.get(resource)?.confirmedCreate !== true
      ) {
        entry = {
          sourceRequestId: source.requestId,
          sourceN: source.n,
          cellId: cell.id,
          method: source.method,
          category: source.category,
          physicalVerdict: "NOT_COMPARABLE",
          semanticVerdict: "NOT_COMPARABLE",
          resource,
          debt: "Local IAM ownership is unconfirmed; policy dispatch refused",
        };
      } else {
        try {
          if (creation)
            localOwnership.set(resource, {
              confirmedCreate: false,
              deleteConfirmed: false,
              absenceConfirmed: false,
              reason: "Local create outcome is unconfirmed",
            });
          if (call.request.ackIds)
            call.request.ackIds = call.request.ackIds.map((id) => {
              const local = tokens.get(`${call.request.subscription}\0${id}`);
              if (!local) throw new Error("D own ACK selector unresolved");
              return local;
            });
          if (call.method === "SetIamPolicy") {
            const previous = localPolicies.get(resource);
            refuse(
              previous &&
                previous.sourceEtag === call.request.policy?.etag &&
                same(previous.sourceBindings, previous.localBindings),
              "D local IAM CAS or policy conflict unresolved",
            );
            call.request.policy.etag = previous.localEtag;
          }
          const actual = await execute(call, source),
            clock = clockReceiptFor(source);
          if (
            creation &&
            good(actual) &&
            actual.unknown === false &&
            actual.code === "OK" &&
            bodyBound(actual) &&
            Number.isSafeInteger(actual.metadataBytesIn) &&
            actual.metadataBytesIn >= 0 &&
            actual.metadataBytesIn + actual.bodyBytes <= CAPS.metadataBytesEachDirection &&
            actual.body?.name === resource
          ) {
            localOwnership.set(resource, {
              confirmedCreate: true,
              deleteConfirmed: false,
              absenceConfirmed: false,
              reason: "Local cleanup has not been confirmed",
            });
          }
          if (maintenance && localOwnership.get(resource)?.confirmedCreate) {
            const ownership = localOwnership.get(resource);
            if (call.method.startsWith("Delete") && good(actual)) ownership.deleteConfirmed = true;
            if (
              call.method.startsWith("Get") &&
              ownership.deleteConfirmed &&
              (actual?.status === 404 || nativeAbsence(actual, call.transport, call.method))
            )
              ownership.absenceConfirmed = true;
          }
          if (creation && !localOwnership.get(resource)?.confirmedCreate) stopped = true;
          if (
            !actual ||
            actual.unknown === true ||
            (source.reply.ok === true && actual.ok !== true)
          )
            stopped = true;
          let semantic =
            source.reply.ok === actual?.ok &&
            source.reply.code === actual?.code &&
            source.reply.status === actual?.status
              ? "MATCH"
              : "DIVERGES";
          let expected = structuredClone(source.reply.body),
            local = structuredClone(actual?.body);
          const debts = [],
            timestampProofs = [];
          if (
            ["CreateSubscription", "GetSubscription"].includes(source.method) &&
            good(source.reply) &&
            good(actual) &&
            same(expected, local) &&
            expected?.name === (source.request.name ?? source.request.subscription) &&
            typeof expected?.topic === "string"
          )
            subscriptionTopics.set(expected.name, expected.topic);
          if (iamCategory(source.category) && source.reply.ok && good(actual)) {
            if (
              typeof expected?.etag !== "string" ||
              typeof local?.etag !== "string" ||
              !local.etag
            ) {
              semantic = "DIVERGES";
            } else {
              localPolicies.set(resource, {
                sourceEtag: expected.etag,
                localEtag: local.etag,
                sourceBindings: structuredClone(expected.bindings ?? []),
                localBindings: structuredClone(local.bindings ?? []),
              });
              expected.etag = local.etag;
            }
          } else if (source.method === "Publish" && source.reply.ok && actual?.ok) {
            const sourceIds = expected?.messageIds,
              localIds = local?.messageIds;
            if (
              !Array.isArray(sourceIds) ||
              !Array.isArray(localIds) ||
              localIds.length !== sourceIds.length ||
              !sourceIds.every((id) => typeof id === "string" && id.length > 0) ||
              !localIds.every((id) => typeof id === "string" && id.length > 0)
            )
              semantic = "DIVERGES";
            else {
              sourceIds.forEach((id, i) => {
                publications.set(id, localIds[i]);
                if (
                  source.request.messages?.length === sourceIds.length &&
                  new Set(sourceIds).size === sourceIds.length &&
                  new Set(localIds).size === localIds.length &&
                  !publicationEvidence.has(id) &&
                  good(source.reply) &&
                  good(actual)
                )
                  publicationEvidence.set(id, {
                    source,
                    call,
                    actual,
                    clock,
                    localId: localIds[i],
                    payload: source.request.messages[i],
                  });
              });
              expected.messageIds = [...localIds];
            }
          } else if (source.method === "Pull" && source.reply.ok && actual?.ok) {
            const sourceItems = expected?.receivedMessages ?? [],
              localItems = local?.receivedMessages ?? [];
            const forwardedSingle = sourceItems.length === 1 && localItems.length === 1;
            if (
              source.category === "sinkPull" &&
              (timestampDisposition?.owner1193 || timestampDisposition?.owner1194) &&
              !forwardedSingle &&
              (sourceItems.length > 0 || localItems.length > 0)
            )
              debts.push(
                "Forwarded timestamp disposition requires exactly one source/local sink message",
              );
            if (!Array.isArray(localItems) || sourceItems.length !== localItems.length)
              semantic = "DIVERGES";
            else
              for (let i = 0; i < sourceItems.length; i++) {
                const a = sourceItems[i],
                  b = localItems[i];
                if (typeof b?.ackId !== "string" || !b.ackId || !b.message) {
                  semantic = "DIVERGES";
                  continue;
                }
                tokens.set(`${call.request.subscription}\0${a.ackId}`, b.ackId);
                a.ackId = b.ackId;
                if (source.category === "sourcePull") {
                  if (publications.get(a.message.messageId) !== b.message.messageId)
                    semantic =
                      timestampDisposition && !publications.has(a.message.messageId)
                        ? "NOT_COMPARABLE"
                        : "DIVERGES";
                  const publication = publicationEvidence.get(a.message.messageId);
                  if (timestampDisposition && ["rest", "grpc"].includes(source.transport)) {
                    const proof = {
                      publicationSourceN: publication?.source.n,
                      sourceValue: a.message.publishTime,
                      localValue: b.message.publishTime,
                      selector: `body.receivedMessages[${i}].message.publishTime`,
                      sourceBodySha256: source.reply.bodySha256,
                      localBodySha256: actual.bodySha256,
                      verdict: "NOT_COMPARABLE",
                    };
                    const time = (value) => {
                      const m =
                        typeof value === "string" &&
                        /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{3}|\d{6}|\d{9}))?Z$/.exec(
                          value,
                        );
                      const ms = m && Date.parse(`${m[1]}Z`);
                      return m &&
                        Number(m[1].slice(0, 4)) > 0 &&
                        Number.isFinite(ms) &&
                        new Date(ms).toISOString().slice(0, 19) === m[1]
                        ? {
                            instant: BigInt(ms) * 1000000n + BigInt((m[2] ?? "").padEnd(9, "0")),
                            precision: m[2]?.length ?? 0,
                          }
                        : null;
                    };
                    const sourceTime = time(proof.sourceValue),
                      localTime = time(proof.localValue);
                    const payload = (message) => ({
                      data: message?.data,
                      attributes: message?.attributes ?? {},
                      orderingKey: message?.orderingKey ?? "",
                    });
                    const bound =
                      timestampDisposition.owner1135?.proposalSha256 ===
                        "8238575c8202949f721b59bb9c97ee36b3f0ae701efd552f4169c70fcf0c1c53" &&
                      ["runId", "sourceHead", "packetSha256", "descriptorSha256"].every(
                        (k) =>
                          input.metadata[k] !== undefined &&
                          timestampDisposition.source?.[k] === input.metadata[k],
                      ) &&
                      Array.isArray(timestampDisposition.cellIds) &&
                      timestampDisposition.cellIds.includes(cell.id) &&
                      ["binarySha256", "inputsSha256"].every(
                        (k) =>
                          /^[a-f0-9]{64}$/.test(input.runtimeInputs?.[k] ?? "") &&
                          timestampDisposition.runtimeInputs?.[k] === input.runtimeInputs[k],
                      );
                    if (!sourceTime || !localTime || sourceTime.precision !== localTime.precision)
                      proof.verdict = "DIVERGES";
                    else if (publication) {
                      const p = publication,
                        c = p.clock,
                        requested = time(c?.requestedInstant),
                        savedClock = time(c?.body?.clock),
                        dispatch = time(p.source.at);
                      if (
                        !same(payload(a.message), payload(p.payload)) ||
                        !same(payload(b.message), payload(p.payload)) ||
                        p.localId !== b.message.messageId ||
                        (p.sourceTime !== undefined && p.sourceTime !== proof.sourceValue) ||
                        (p.localTime !== undefined && p.localTime !== proof.localValue)
                      )
                        proof.verdict = "DIVERGES";
                      else if (
                        c?.sourceRequestId === p.source.requestId &&
                        c.sourceN === p.source.n &&
                        c.status === 200 &&
                        requested &&
                        savedClock &&
                        dispatch
                      ) {
                        if (
                          requested.instant !== dispatch.instant ||
                          savedClock.instant !== requested.instant ||
                          localTime.instant !== savedClock.instant
                        )
                          proof.verdict = "DIVERGES";
                        else if (
                          bound &&
                          bodyBound(c) &&
                          bodyBound(p.source.reply) &&
                          bodyBound(p.actual) &&
                          bodyBound(source.reply) &&
                          bodyBound(actual) &&
                          ["rest", "grpc"].includes(source.transport) &&
                          subscriptionTopics.get(call.request.subscription) ===
                            p.source.request.topic
                        )
                          proof.verdict = "MATCH";
                      }
                      p.sourceTime ??= proof.sourceValue;
                      p.localTime ??= proof.localValue;
                    }
                    proof.gap =
                      proof.verdict === "NOT_COMPARABLE"
                        ? `sourceN=${source.n}: successful Publish/clock/subscription/authority binding unavailable`
                        : undefined;
                    if (source.transport === "grpc") {
                      proof.publicationVerdict = proof.verdict;
                      proof.nativeWire = nativePullWire(source.reply, actual);
                      proof.verdict = aggregate([proof.verdict, proof.nativeWire.verdict]);
                      if (proof.nativeWire.verdict === "NOT_COMPARABLE")
                        proof.gap = `sourceN=${source.n}: exact native Pull response raw recovery unavailable`;
                    }
                    timestampProofs.push(proof);
                    semantic = aggregate([semantic, proof.verdict]);
                  }
                  a.message.messageId = b.message.messageId;
                } else {
                  if (typeof b.message.messageId !== "string" || !b.message.messageId)
                    semantic = "DIVERGES";
                  a.message.messageId = b.message.messageId;
                }
                if (
                  source.category === "sinkPull" &&
                  forwardedSingle &&
                  (timestampDisposition?.owner1193 || timestampDisposition?.owner1194)
                ) {
                  const proofs = forwardedProofs(
                    cell,
                    source,
                    actual,
                    publicationEvidence,
                    exchanges,
                    clockReceiptFor,
                    timestampDisposition,
                  );
                  timestampProofs.push(...proofs);
                  semantic = aggregate([semantic, ...proofs.map((p) => p.verdict)]);
                }
                // Publication instants are retained separately; a source response timestamp is not a local clock receipt.
                if (
                  a.message.publishTime !== b.message.publishTime &&
                  !(
                    (source.category === "sourcePull" ||
                      (source.category === "sinkPull" && timestampProofs.length)) &&
                    ["rest", "grpc"].includes(source.transport) &&
                    timestampDisposition
                  )
                )
                  debts.push("Observed publication timestamp requires source/local clock evidence");
                delete a.message.publishTime;
                delete b.message.publishTime;
                const key = "CloudPubSubDeadLetterSourceTopicPublishTime";
                if (
                  source.category === "sinkPull" &&
                  !Number.isFinite(instant(b.message.attributes?.[key]))
                )
                  semantic = "DIVERGES";
                else if (
                  a.message.attributes?.[key] !== b.message.attributes?.[key] &&
                  !timestampProofs.some((p) => p.selector.endsWith(key))
                )
                  debts.push(
                    "Forwarded publication timestamp requires source/local clock evidence",
                  );
                if (a.message.attributes) delete a.message.attributes[key];
                if (b.message.attributes) delete b.message.attributes[key];
              }
          }
          if (restartAttemptDisposition && source.category === "sourcePull") {
            const sourceItem = source.reply.body?.receivedMessages?.[0],
              localItem = actual?.body?.receivedMessages?.[0];
            const withoutAttempt = (body) => {
              const value = structuredClone(body);
              for (const item of value?.receivedMessages ?? []) delete item.deliveryAttempt;
              return value;
            };
            const native =
              source.transport === "grpc"
                ? nativePullWire(source.reply, actual, false, true)
                : undefined;
            restartEvidence.set(source.n, {
              sourceAttempt: sourceItem?.deliveryAttempt,
              localAttempt: localItem?.deliveryAttempt,
              sourceId: sourceItem?.message?.messageId,
              localId: localItem?.message?.messageId,
              sourceAck: sourceItem?.ackId,
              cardinality:
                source.reply.body?.receivedMessages?.length === 1 &&
                actual?.body?.receivedMessages?.length === 1,
              known:
                good(source.reply) &&
                good(actual) &&
                bodyBound(source.reply) &&
                bodyBound(actual) &&
                (!native || native.verdict !== "NOT_COMPARABLE"),
              identityVerdict: publications.has(sourceItem?.message?.messageId)
                ? publications.get(sourceItem.message.messageId) ===
                    localItem?.message?.messageId &&
                  same(withoutAttempt(expected), withoutAttempt(local))
                  ? "MATCH"
                  : "DIVERGES"
                : "NOT_COMPARABLE",
              otherVerdict:
                debts.length ||
                timestampProofs.some(
                  (p) => (p.publicationVerdict ?? p.verdict) === "NOT_COMPARABLE",
                )
                  ? "NOT_COMPARABLE"
                  : timestampProofs.some(
                        (p) => (p.publicationVerdict ?? p.verdict) === "DIVERGES",
                      ) || native?.verdict === "DIVERGES"
                    ? "DIVERGES"
                    : "MATCH",
            });
          }
          if (!same(expected, local)) semantic = "DIVERGES";
          const clockBound =
            clock?.sourceRequestId === source.requestId &&
            clock.sourceN === source.n &&
            clock.status === 200 &&
            Number.isFinite(instant(clock.requestedInstant)) &&
            instant(clock.requestedInstant) === instant(source.at) &&
            instant(clock.body?.clock) === instant(source.at);
          const physical =
            actual &&
            bodyBound(actual) &&
            Number.isSafeInteger(actual.metadataBytesIn) &&
            actual.metadataBytesIn >= 0 &&
            actual.metadataBytesIn + (actual.bodyBytes ?? 0) <= CAPS.metadataBytesEachDirection &&
            clockBound
              ? "MATCH"
              : "NOT_COMPARABLE";
          entry = {
            sourceRequestId: source.requestId,
            sourceN: source.n,
            cellId: cell.id,
            method: source.method,
            category: source.category,
            sourceReply: source.reply,
            localReply: actual,
            physicalVerdict:
              physical === "MATCH" &&
              timestampProofs.some(
                (p) =>
                  p.sourceValue !== p.localValue || p.nativeWire?.physicalVerdict === "DIVERGES",
              )
                ? "DIVERGES"
                : physical,
            timestampProofs,
            semanticVerdict:
              semantic === "DIVERGES" ? semantic : debts.length ? "NOT_COMPARABLE" : semantic,
            debts,
          };
        } catch (error) {
          stopped = true;
          entry = {
            sourceRequestId: source.requestId,
            sourceN: source.n,
            cellId: cell.id,
            method: source.method,
            category: source.category,
            physicalVerdict: "NOT_COMPARABLE",
            semanticVerdict: "NOT_COMPARABLE",
            debt: error.message,
          };
        }
      }
      if (resource && localOwnership.has(resource))
        entry.localOwnership = { resource, ...localOwnership.get(resource) };
      if (entry.timestampProofs?.some((p) => p.requiresOwnAck)) {
        entry.pendingOwnAckVerdict = entry.semanticVerdict;
        if (entry.semanticVerdict === "MATCH") entry.semanticVerdict = "NOT_COMPARABLE";
      }
      exchanges.push(entry);
      observe(entry);
    }
    for (const entry of exchanges.filter((e) => e.timestampProofs?.some((p) => p.requiresOwnAck))) {
      const original = cell.exchanges.find((e) => e.n === entry.sourceN),
        token = original.reply.body.receivedMessages[0].ackId;
      const ack = cell.exchanges.find(
        (e) =>
          e.n > original.n &&
          e.method === "Acknowledge" &&
          e.request.subscription === original.request.subscription &&
          e.request.ackIds?.includes(token),
      );
      const localAck = ack && exchanges.find((e) => e.sourceN === ack.n);
      const acknowledged =
        ack &&
        good(ack.reply) &&
        good(localAck?.localReply) &&
        localAck.semanticVerdict === "MATCH";
      for (const proof of entry.timestampProofs.filter((p) => p.requiresOwnAck)) {
        proof.ownAckSourceN = acknowledged ? ack?.n : undefined;
        if (!acknowledged && proof.verdict === "MATCH") proof.verdict = "NOT_COMPARABLE";
        if (!acknowledged && proof.publicationVerdict === "MATCH")
          proof.publicationVerdict = "NOT_COMPARABLE";
      }
      entry.semanticVerdict = aggregate([
        entry.pendingOwnAckVerdict,
        ...entry.timestampProofs.map((p) => p.verdict),
      ]);
      delete entry.pendingOwnAckVerdict;
      entry.ownAckFinalized = true;
    }
    const physicalVerdict = aggregate(exchanges.map((e) => e.physicalVerdict)),
      semanticVerdict = aggregate(exchanges.map((e) => e.semanticVerdict));
    const ownershipDebts = [...localOwnership]
      .filter(([, state]) => !state.confirmedCreate || !state.absenceConfirmed)
      .map(([resource, state]) => ({ resource, ...state }));
    results.push({
      cellId: cell.id,
      exchanges,
      ...(restartAttemptDisposition
        ? {
            restartAttemptRelation: restartAttemptRelation(
              input,
              cell,
              exchanges,
              restartEvidence,
              restartAttemptDisposition,
            ),
          }
        : {}),
      ownershipDebts,
      physicalVerdict,
      semanticVerdict,
      verdict: aggregate([physicalVerdict, semanticVerdict]),
    });
  }
  return {
    suite: SUITE,
    runId: input.metadata.runId,
    results,
    verdict: aggregate(results.map((r) => r.verdict)),
    parityEstablished: false,
    parentClosureReady: false,
  };
}

export function bindTerminal(terminal, input, summarySha256) {
  refuse(
    terminal &&
      terminal.runId === input.metadata.runId &&
      terminal.sourceCommit === input.metadata.sourceHead &&
      terminal.packetSha256 === input.metadata.packetSha256 &&
      terminal.summarySha256 === summarySha256 &&
      terminal.recordingComplete === true &&
      terminal.resourcesClosed === true &&
      terminal.sandboxAtBaseline === true,
    "retained source terminal binding refused",
  );
  return structuredClone(terminal);
}
