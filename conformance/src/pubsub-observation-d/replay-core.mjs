import { isDeepStrictEqual as same } from "node:util";
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

export async function replayRecording(
  input,
  execute,
  { enter = () => {}, observe = () => {}, clockReceiptFor = () => undefined } = {},
) {
  const results = [];
  for (const cell of input.cells) {
    enter(cell);
    const publications = new Map(),
      tokens = new Map(),
      exchanges = [],
      localOwnership = new Map(),
      localPolicies = new Map();
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
          const debts = [];
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
              sourceIds.forEach((id, i) => publications.set(id, localIds[i]));
              expected.messageIds = [...localIds];
            }
          } else if (source.method === "Pull" && source.reply.ok && actual?.ok) {
            const sourceItems = expected?.receivedMessages ?? [],
              localItems = local?.receivedMessages ?? [];
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
                    semantic = "DIVERGES";
                  a.message.messageId = b.message.messageId;
                } else {
                  if (typeof b.message.messageId !== "string" || !b.message.messageId)
                    semantic = "DIVERGES";
                  a.message.messageId = b.message.messageId;
                }
                // Publication instants are retained separately; a source response timestamp is not a local clock receipt.
                if (a.message.publishTime !== b.message.publishTime)
                  debts.push("Observed publication timestamp requires source/local clock evidence");
                delete a.message.publishTime;
                delete b.message.publishTime;
                const key = "CloudPubSubDeadLetterSourceTopicPublishTime";
                if (
                  source.category === "sinkPull" &&
                  !Number.isFinite(instant(b.message.attributes?.[key]))
                )
                  semantic = "DIVERGES";
                else if (a.message.attributes?.[key] !== b.message.attributes?.[key])
                  debts.push(
                    "Forwarded publication timestamp requires source/local clock evidence",
                  );
                if (a.message.attributes) delete a.message.attributes[key];
                if (b.message.attributes) delete b.message.attributes[key];
              }
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
            physicalVerdict: physical,
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
      exchanges.push(entry);
      observe(entry);
    }
    const physicalVerdict = aggregate(exchanges.map((e) => e.physicalVerdict)),
      semanticVerdict = aggregate(exchanges.map((e) => e.semanticVerdict));
    const ownershipDebts = [...localOwnership]
      .filter(([, state]) => !state.confirmedCreate || !state.absenceConfirmed)
      .map(([resource, state]) => ({ resource, ...state }));
    results.push({
      cellId: cell.id,
      exchanges,
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
