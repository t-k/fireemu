import { protectCell, checkpoint, obligations } from "../pubsub-observation/safety.mjs";
import { normalizeOutcome } from "../pubsub-production/outcome.mjs";
import { isDeepStrictEqual } from "node:util";
import { kindOf } from "../pubsub-observation/ledger.mjs";
import { PROJECT, makePlan, minimumCallMs } from "./plan.mjs";
const kinds = { topics: "Topic", subscriptions: "Subscription", snapshots: "Snapshot" };
const resourceRank = (name) =>
  name.includes("/snapshots/") ? 2 : name.includes("/subscriptions/") ? 1 : 0;
const resourceMethod = (name, action) => `${action}${kinds[name.split("/")[2]]}`;
const serviceOf = (method) => (/Topic|Publish/.test(method) ? "Publisher" : "Subscriber");
const settled = (ledger, name) =>
  (ledger.state().get(name)?.requests ?? []).every((r) =>
    ["rejected", "gone", "gone-a2"].includes(r.resolution),
  );
const filters = {
  "filter-inequality": 'attributes.env != "prod"',
  "filter-conjunction": 'attributes.env = "test" AND attributes.region = "west"',
  "filter-disjunction": 'attributes.env = "test" OR attributes.region = "west"',
  "attribute-exists": "attributes:env",
};
export function graph(cell, runId) {
  if (!/^[a-f0-9]{12}$/.test(runId) || !makePlan().cells.some((c) => isDeepStrictEqual(c, cell)))
    throw new Error("declared graph required");
  const suffix = `fe${runId}-${cell.id.toLowerCase()}`,
    root = `projects/${PROJECT}`;
  const topic = `${root}/topics/${suffix}-t`,
    subscription = `${root}/subscriptions/${suffix}-s`,
    control = `${root}/subscriptions/${suffix}-c`,
    otherTopic = `${root}/topics/${suffix}-u`,
    origin = `${root}/subscriptions/${suffix}-o`,
    snapshot = `${root}/snapshots/${suffix}-snap`;
  const resources = [{ name: topic, method: "CreateTopic", request: { name: topic } }];
  const sub = (name, target, extra = {}) =>
    resources.push({
      name,
      method: "CreateSubscription",
      request: { name, topic: target, ackDeadlineSeconds: 60, ...extra },
    });
  sub(subscription, topic, {
    ...(filters[cell.variant] ? { filter: filters[cell.variant] } : {}),
    ...(["nack-blocked-key", "ordered-first-cross-key"].includes(cell.variant)
      ? { enableMessageOrdering: true }
      : {}),
    ...(["unacked-backlog-seek", "reverse-seek-members"].includes(cell.variant)
      ? { retainAckedMessages: true }
      : cell.variant === "retain-false-seek"
        ? { retainAckedMessages: false }
        : {}),
  });
  if (
    filters[cell.variant] ||
    ["multiple-subscriptions", "ordered-first-cross-key", "retain-false-seek"].includes(
      cell.variant,
    )
  )
    sub(control, topic, cell.variant === "retain-false-seek" ? { retainAckedMessages: true } : {});
  if (cell.variant === "wrong-topic-snapshot") {
    resources.push({ name: otherTopic, method: "CreateTopic", request: { name: otherTopic } });
    sub(origin, otherTopic);
  }
  if (
    ["wrong-topic-snapshot", "unacked-backlog-seek", "reverse-seek-members"].includes(cell.variant)
  )
    resources.push({
      name: snapshot,
      method: "CreateSnapshot",
      request: {
        name: snapshot,
        subscription: cell.variant === "wrong-topic-snapshot" ? origin : subscription,
      },
      late: true,
      expectedTopic: cell.variant === "wrong-topic-snapshot" ? otherTopic : topic,
    });
  return { resources, topic, subscription, control, otherTopic, origin, snapshot };
}
export const owned = (name, runId) =>
  /^[a-f0-9]{12}$/.test(runId) &&
  makePlan().cells.some((c) => graph(c, runId).resources.some((r) => r.name === name));
export function parseDelivery(body, published) {
  const items = body?.receivedMessages ?? [];
  if (
    !body ||
    typeof body !== "object" ||
    Array.isArray(body) ||
    !Array.isArray(items) ||
    items.length > 3
  )
    throw new Error("unreadable delivery envelope");
  for (const item of items) {
    const expected = published.get(item?.message?.messageId);
    if (
      !expected ||
      typeof item.ackId !== "string" ||
      !item.ackId.length ||
      item.ackId.length > 4096 ||
      item.message.data !== expected.data ||
      !isDeepStrictEqual(item.message.attributes ?? {}, expected.attributes ?? {}) ||
      (item.message.orderingKey ?? "") !== (expected.orderingKey ?? "")
    )
      throw new Error("foreign or unbound delivery refused");
  }
  return items;
}

export async function runCell({
  cell,
  meter,
  wire,
  ledger,
  runId,
  journal,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
}) {
  const manifest = graph(cell, runId),
    allowed = new Set(manifest.resources.map((r) => r.name));
  const tracked = new Set(),
    absentSeen = new Set(),
    observations = [];
  let complete = false,
    reason = null,
    budgetOverrun = false;
  const send = async (category, method, request, cancelBinding = null) => {
    const maintenance = category.startsWith("cleanup");
    if (meter.remaining(maintenance) < minimumCallMs(method))
      throw new Error("recorded latency margin unavailable");
    const list = method.startsWith("List"),
      name = request.name ?? request.topic ?? request.subscription;
    if (list ? request.project !== `projects/${PROJECT}` : !allowed.has(name))
      throw new Error("foreign resource refused");
    for (const field of ["topic", "subscription", "snapshot"])
      if (request[field] !== undefined && !allowed.has(request[field]))
        throw new Error("foreign prerequisite refused");
    const action = method.startsWith("Create")
      ? "create"
      : method.startsWith("Delete")
        ? "delete"
        : null;
    if (action === "delete" && (ledger.deleting(name) || ledger.unconfirmed(name)))
      throw new Error("unknown delete cannot retry");
    if (action) {
      tracked.add(name);
      checkpoint(journal, ledger, tracked, cell.id, [{ name, action, transport: cell.transport }]);
    }
    const intent = action
      ? {
          name,
          action,
          transport: cell.transport,
          requestId: ledger.sent({ name, action, transport: cell.transport }),
        }
      : null;
    if (action) tracked.add(name);
    let reply;
    try {
      reply = await wire.call({
        category,
        transport: cell.transport,
        service: serviceOf(method),
        method,
        request,
        cellId: cell.id,
        ...(cancelBinding ? { cancelObservation: true, cancelBinding } : {}),
      });
    } catch (error) {
      if (intent) ledger.answered({ ...intent, kind: "unknown" });
      throw error;
    }
    reply = normalizeOutcome(reply);
    let kind = kindOf(reply);
    if (
      (action === "create" || method.startsWith("Get")) &&
      kind === "ok" &&
      (reply.body?.name !== name || "done" in reply.body)
    )
      kind = "unknown";
    if (intent) ledger.answered({ ...intent, kind });
    if (method.startsWith("Get")) {
      ledger.observeRead(name, reply);
      if (kind === "error" && reply.code === "NOT_FOUND" && !settled(ledger, name))
        absentSeen.add(name);
    }
    const intentionalCancel =
      cancelBinding &&
      method === "Pull" &&
      category === "pull" &&
      cell.variant === "cancel-followup" &&
      reply.unknown === true &&
      reply.clientCancellation?.cellId === cell.id &&
      reply.clientCancellation?.transport === cell.transport &&
      reply.clientCancellation?.subscription === request.subscription &&
      reply.clientCancellation?.method === "Pull" &&
      reply.clientCancellation?.cause === "intentional-unary-cancel" &&
      reply.clientCancellation?.pending === true &&
      Number.isSafeInteger(reply.clientCancellation?.requestId);
    if ((kind === "unknown" || kind === "pending") && !intentionalCancel)
      throw new Error("unknown answer stops the cell");
    if (reply.budgetOverrun) budgetOverrun = true;
    try {
      meter.remaining(maintenance);
    } catch {
      budgetOverrun = true;
    }
    return reply;
  };
  const published = new Map();
  let serial = 0;
  const observe = (stage, value) => {
    const row = {
      event: "delivery-observation",
      cellId: cell.id,
      stage,
      clockMs: meter.clock(),
      ...value,
    };
    observations.push(row);
    journal.write(row);
  };
  const wait = async (ms) => {
    if (ms >= meter.remaining()) throw new Error("wait exceeds cell time");
    await sleep(ms);
    meter.remaining();
  };
  const create = async (resource, read = true) => {
    const reply = await send("create", resource.method, resource.request);
    if (!reply.ok) throw new Error("required setup refused");
    if (
      read &&
      !(await send("get", resourceMethod(resource.name, "Get"), { name: resource.name })).ok
    )
      throw new Error("setup read missing");
  };
  const publish = async (messages, topic = manifest.topic) => {
    if (!Array.isArray(messages) || !messages.length || messages.length > 3)
      throw new Error("publication envelope");
    const values = messages.map((value) => ({
      data: Buffer.from(`${runId}:${cell.id}:${serial++}`).toString("base64"),
      ...value,
    }));
    const reply = await send("publish", "Publish", { topic, messages: values });
    const ids = reply.body?.messageIds;
    if (
      !reply.ok ||
      !Array.isArray(ids) ||
      ids.length !== values.length ||
      new Set(ids).size !== ids.length ||
      ids.some((id) => typeof id !== "string" || !id || published.has(id))
    )
      throw new Error("publication is not bound");
    ids.forEach((id, index) => published.set(id, values[index]));
    observe("publication-binding", { topic, messageIds: ids, messages: values });
    return ids;
  };
  const pull = async (
    subscription,
    stage,
    { attempts = 1, maxMessages = 3, immediate = false, required = false } = {},
  ) => {
    const received = [],
      seen = new Set();
    for (let attempt = 0; attempt < attempts; attempt++) {
      const reply = await send("pull", "Pull", {
        subscription,
        maxMessages,
        returnImmediately: immediate,
      });
      if (!reply.ok) throw new Error("required pull refused");
      const items = parseDelivery(reply.body, published);
      observe(stage, {
        subscription,
        attempt,
        items,
        returnImmediately: immediate,
        ackSelector: "NOT_COMPARABLE-until-observed",
      });
      for (const item of items)
        if (!seen.has(item.message.messageId)) {
          seen.add(item.message.messageId);
          received.push(item);
        }
      if (items.length || attempt === attempts - 1) break;
      await wait(1000);
    }
    if (required && !received.length)
      throw new Error("own delivery absent within bounded attempts; NOT_COMPARABLE");
    return received;
  };
  const ack = async (subscription, items) => {
    if (!items.length) return;
    const reply = await send("ackControl", "Acknowledge", {
      subscription,
      ackIds: items.map((i) => i.ackId),
    });
    observe("ack-boundary", {
      subscription,
      messageIds: items.map((i) => i.message.messageId),
      ackIds: items.map((i) => i.ackId),
      reply,
    });
    if (!reply.ok) throw new Error("own ACK refused");
  };
  const nack = async (subscription, item) => {
    const reply = await send("ackControl", "ModifyAckDeadline", {
      subscription,
      ackIds: [item.ackId],
      ackDeadlineSeconds: 0,
    });
    observe("nack-boundary", {
      subscription,
      messageId: item.message.messageId,
      ackId: item.ackId,
      reply,
    });
    if (!reply.ok) throw new Error("own NACK refused");
    await wait(1000);
  };
  const seekTime = (item) => {
    const raw = item?.message?.publishTime,
      value = Date.parse(raw);
    if (typeof raw !== "string" || !Number.isFinite(value))
      throw new Error("publishTime witness required for Seek");
    return new Date(value - 1).toISOString();
  };
  const seek = async (subscription, target, stage) => {
    const reply = await send("other", "Seek", { subscription, ...target });
    observe(stage, {
      subscription,
      target,
      reply,
      verdict: reply.ok ? "accepted-observation" : "known-refusal",
    });
    return reply;
  };
  const makeSnapshot = async () =>
    create(manifest.resources.find((r) => r.name === manifest.snapshot));
  let cleanupClosed = true;
  const failures = await protectCell({
    body: async () => {
      for (const resource of manifest.resources.filter((r) => !r.late))
        await create(
          resource,
          !(cell.variant === "wrong-topic-snapshot" && resource.name === manifest.subscription),
        );
      const s = manifest.subscription,
        c = manifest.control;
      if (cell.variant === "multiple-subscriptions") {
        await publish([{}]);
        const first = await pull(s, "first-subscription", { attempts: 2, required: true });
        await ack(s, first);
        const second = await pull(c, "independent-subscription", { attempts: 2, required: true });
        await ack(c, second);
        await wait(1000);
        await pull(s, "post-ack-bounded-window", { attempts: 2, immediate: true });
      } else if (cell.variant === "stale-ack") {
        const [id] = await publish([{}]);
        const [original] = await pull(s, "initial-token", { attempts: 2, required: true });
        await nack(s, original);
        const redelivery = await pull(s, "redelivery-token", { attempts: 3, required: true });
        const current = redelivery.find((i) => i.message.messageId === id);
        if (!current || current.ackId === original.ackId)
          throw new Error("distinct stale/current token witness missing; NOT_COMPARABLE");
        await ack(s, [original]);
        await ack(s, [current]);
        await wait(1000);
        await pull(s, "post-current-ack", { attempts: 2, immediate: true });
      } else if (cell.variant === "cancel-followup") {
        observe("prior-cancel-causal-debt", {
          verdict: "NOT_COMPARABLE",
          reason:
            "Prior G4 resources must already be closed; no transferable outstanding subscription or correlated unary follow-up is supplied. No new stream is authorized by G2.",
        });
        const [outstandingId, controlId] = await publish([
          { attributes: { role: "outstanding" } },
          { attributes: { role: "acked-control" } },
        ]);
        const items = await pull(s, "cancel-original-delivery", { attempts: 2, required: true });
        const outstanding = items.find((item) => item.message.messageId === outstandingId),
          control = items.find((item) => item.message.messageId === controlId);
        if (!outstanding || !control)
          throw new Error("cancel control delivery missing; NOT_COMPARABLE");
        const deliveredAt = meter.clock();
        await ack(s, [control]);
        observe("outstanding-before-client-cancel", {
          subscription: s,
          messageId: outstandingId,
          ackId: outstanding.ackId,
          deliveredAt,
          ackDeadlineSeconds: 60,
          ackedControlId: controlId,
        });
        const cancelled = await send(
          "pull",
          "Pull",
          { subscription: s, maxMessages: 1, returnImmediately: false },
          {
            outstandingMessageId: outstandingId,
            outstandingAckId: outstanding.ackId,
            ackedControlMessageId: controlId,
            ackedControlAckId: control.ackId,
            deliveredAt,
          },
        );
        if (!cancelled.unknown || !cancelled.clientCancellation)
          throw new Error("second Pull completed without pending cancel witness; NOT_COMPARABLE");
        observe("intentional-client-cancel", {
          subscription: s,
          clientCancellation: cancelled.clientCancellation,
          reply: cancelled,
          serverOutcome: "UNKNOWN",
          possibleServerLeaseEffect: "UNKNOWN",
          redeliveryCause: "ordinary-ACK-deadline",
        });
        const deadlineAt = deliveredAt + 61000,
          delay = deadlineAt - meter.clock();
        if (delay > 0) await wait(delay);
        if (meter.clock() < deadlineAt)
          throw new Error("cancel follow-up before deadline; NOT_COMPARABLE");
        observe("ordinary-ACK-deadline-elapsed", {
          subscription: s,
          deliveredAt,
          deadlineAt,
          messageId: outstandingId,
          cause: "ordinary-ACK-deadline",
          cancellationDoesNotProveCause: true,
        });
        const replay = await pull(s, "post-deadline-cancel-followup", {
          attempts: 3,
          required: true,
        });
        if (
          replay.some((item) => item.message.messageId === controlId) ||
          !replay.some((item) => item.message.messageId === outstandingId)
        )
          throw new Error("cancel follow-up identity or ACKed control differs; NOT_COMPARABLE");
        await ack(s, replay);
      } else if (filters[cell.variant]) {
        const attrs =
          cell.variant === "filter-inequality"
            ? [{ env: "prod" }, { env: "test" }, {}]
            : cell.variant === "attribute-exists"
              ? [{ env: "test" }, { env: "" }, {}]
              : [
                  { env: "test", region: "west" },
                  { env: "test", region: "east" },
                  { env: "prod", region: "west" },
                  { env: "prod", region: "east" },
                  {},
                ];
        for (let i = 0; i < attrs.length; i += 3)
          await publish(attrs.slice(i, i + 3).map((attributes) => ({ attributes })));
        const positive = new Set();
        for (let i = 0; i < 2 && positive.size < published.size; i++) {
          const items = await pull(c, "unfiltered-positive-control", {
            attempts: 2,
            required: true,
          });
          items.forEach((item) => positive.add(item.message.messageId));
          await ack(c, items);
        }
        if (positive.size !== published.size)
          throw new Error("unfiltered positive control incomplete; NOT_COMPARABLE");
        for (let i = 0; i < 2; i++) {
          const items = await pull(s, "filtered-selection-window", {
            attempts: 2,
            immediate: true,
          });
          await ack(s, items);
          await wait(1000);
        }
        observe("filter-window-censored", {
          verdict: "bounded-observation",
          permanentAutomaticAckProved: false,
        });
      } else if (["nack-blocked-key", "ordered-first-cross-key"].includes(cell.variant)) {
        if (cell.variant === "nack-blocked-key") {
          const [firstId] = await publish([{ orderingKey: "key-A", attributes: { seq: "0" } }]);
          const [first] = await pull(s, "outstanding-predecessor", {
            attempts: 2,
            maxMessages: 1,
            required: true,
          });
          await publish([
            { orderingKey: "key-A", attributes: { seq: "1" } },
            { orderingKey: "key-B", attributes: { seq: "0" } },
          ]);
          await nack(s, first);
          const before = await pull(s, "before-predecessor-ACK", { attempts: 3, required: true });
          if (!before.some((i) => i.message.messageId === firstId))
            throw new Error("correlated predecessor redelivery missing; NOT_COMPARABLE");
          await ack(s, before);
          const after = await pull(s, "after-predecessor-ACK", { attempts: 3, required: true });
          await ack(s, after);
        } else {
          await publish([
            { orderingKey: "key-A", attributes: { seq: "0" } },
            { orderingKey: "key-A", attributes: { seq: "1" } },
          ]);
          await publish([{ orderingKey: "key-B", attributes: { seq: "0" } }]);
          for (const subscription of [s, c]) {
            const seen = new Set();
            for (let i = 0; i < 2 && seen.size < published.size; i++) {
              const items = await pull(
                subscription,
                i === 0 ? "first-Pull-exact-order" : "subsequent-Pull-exact-order",
                { attempts: 2, required: true },
              );
              items.forEach((item) => seen.add(item.message.messageId));
              await ack(subscription, items);
            }
            if (seen.size !== published.size)
              throw new Error("ordered/unordered delivery control incomplete; NOT_COMPARABLE");
          }
        }
      } else if (cell.variant === "retain-false-seek") {
        await publish([{}]);
        const first = await pull(s, "retain-false-original", { attempts: 2, required: true });
        const target = seekTime(first[0]);
        await ack(s, first);
        const other = await pull(c, "retain-true-original", { attempts: 2, required: true });
        await ack(c, other);
        await publish([{}]);
        for (const subscription of [s, c]) {
          await seek(subscription, { time: target }, "retention-Seek");
          const items = await pull(subscription, "post-retention-Seek", {
            attempts: 2,
            required: true,
          });
          await ack(subscription, items);
        }
      } else if (cell.variant === "wrong-topic-snapshot") {
        await publish([{}], manifest.otherTopic);
        await makeSnapshot();
        await publish([{}, {}]);
        const before = await pull(s, "target-before-wrong-Seek", { attempts: 3, required: true });
        if (before.length < 2)
          throw new Error("two target messages required before wrong-topic Seek");
        await ack(s, [before[0]]);
        await seek(s, { snapshot: manifest.snapshot }, "wrong-topic-Seek");
        const config = await send("get", "GetSubscription", { name: s });
        observe("target-config-after-wrong-Seek", { reply: config });
        await nack(s, before[1]);
        const after = await pull(s, "target-after-wrong-Seek", { attempts: 3, required: true });
        await ack(s, after);
      } else if (cell.variant === "unacked-backlog-seek") {
        await publish([{}, {}]);
        const before = await pull(s, "pre-snapshot-ACK-split", { attempts: 3, required: true });
        if (before.length < 2)
          throw new Error("ACKed/unACKed snapshot boundary requires two messages");
        await ack(s, [before[0]]);
        await makeSnapshot();
        await ack(s, [before[1]]);
        await publish([{}]);
        const after = await pull(s, "post-snapshot-publication", { attempts: 2, required: true });
        await ack(s, after);
        await seek(s, { snapshot: manifest.snapshot }, "snapshot-Seek");
        const replay = await pull(s, "snapshot-replay", { attempts: 3, required: true });
        await ack(s, replay);
      } else if (cell.variant === "reverse-seek-members") {
        await publish([{}]);
        const before = await pull(s, "before-snapshot", { attempts: 2, required: true });
        const time = seekTime(before[0]);
        await ack(s, before);
        await makeSnapshot();
        await publish([{}]);
        const after = await pull(s, "after-snapshot", { attempts: 2, required: true });
        await ack(s, after);
        for (const target of [
          { snapshot: manifest.snapshot, time },
          { time, snapshot: manifest.snapshot },
        ]) {
          await seek(s, target, "both-target-Seek-member-order");
          const items = await pull(s, "both-target-Seek-followup", {
            attempts: 2,
            immediate: true,
          });
          await ack(s, items);
        }
        observe("native-member-order-scope", {
          jsonOrderAnalogue: cell.transport === "rest",
          nativeRawBytesCaptured: cell.transport === "grpc",
          inferredOneofSelection: false,
        });
      } else throw new Error("undeclared recipe");
      complete = true;
    },
    report: (error) => {
      reason = error.message;
      journal.write({
        event: "case-incomplete",
        cellId: cell.id,
        reason,
        verdict: "NOT_COMPARABLE",
      });
    },
    finalize: async () => {
      for (const name of ledger.state().keys()) if (allowed.has(name)) tracked.add(name);
      for (const name of [...tracked].sort((a, b) => resourceRank(b) - resourceRank(a))) {
        if (settled(ledger, name)) continue;
        try {
          if (ledger.unconfirmed(name)) {
            const reply = await send("cleanupGet", resourceMethod(name, "Get"), { name });
            ledger.observeRead(name, reply);
            if (ledger.unconfirmed(name)) {
              cleanupClosed = false;
              continue;
            }
          }
          if (!ledger.deleting(name) && !absentSeen.has(name))
            await send("cleanupDelete", resourceMethod(name, "Delete"), { name });
          const reply = await send("cleanupGet", resourceMethod(name, "Get"), { name });
          if (!ledger.settleAbsent(name, reply)) cleanupClosed = false;
        } catch {
          cleanupClosed = false;
        }
        if (!settled(ledger, name)) cleanupClosed = false;
      }
    },
    persist: () => checkpoint(journal, ledger, tracked, cell.id, [], []),
  });
  if (failures.length) {
    complete = false;
    reason ??= failures[0].message;
  }
  if (
    failures.finalizationFailed ||
    failures.persistenceFailed ||
    obligations(ledger, tracked).length
  )
    cleanupClosed = false;
  try {
    meter.remaining(true);
  } catch {
    budgetOverrun = true;
  }
  const result = {
    cellId: cell.id,
    complete: complete && !budgetOverrun,
    reason,
    cleanupClosed,
    names: [...tracked],
    observations,
    parityEstablished: false,
    outstanding: ledger.outstanding().filter((item) => tracked.has(item.name)),
    budgetOverrun,
  };
  journal.write({ event: "case-result", ...result });
  try {
    meter.remaining(true);
  } catch {
    result.complete = false;
    result.budgetOverrun = true;
    result.reason = "cell or source budget exceeded during persistence";
    journal.write({ event: "case-budget-overrun", ...result });
  }
  return result;
}

export async function recoverA2({ wire, ledger, runId, elapsedMs, meter }) {
  if (!Number.isFinite(elapsedMs) || elapsedMs < 600000) throw new Error("A2 minimum age required");
  const originalIds = new Set(
    [...ledger.state().values()].flatMap((item) => item.requests.map((request) => request.id)),
  );
  let resourceReads = 0,
    unknownDeleteReads = 0;
  for (const [name] of ledger.state()) {
    if (!owned(name, runId)) throw new Error("foreign recovery resource refused");
    if (settled(ledger, name)) continue;
    const category = ledger.deleting(name) ? "unknownDeleteRead" : "resourceRead";
    if (category === "resourceRead" ? resourceReads >= 6 : unknownDeleteReads >= 6) break;
    if (category === "resourceRead") resourceReads++;
    else unknownDeleteReads++;
    const reply = await wire.call({
      category,
      transport: "rest",
      service: serviceOf(resourceMethod(name, "Get")),
      method: resourceMethod(name, "Get"),
      request: { name },
      cellId: "A2",
    });
    ledger.observeRead(name, reply);
    ledger.settleAbsent(name, reply, { a2ElapsedMs: elapsedMs, a2EligibleRequestIds: originalIds });
    meter?.remaining(true);
  }
  return {
    closed: [...ledger.state().keys()].every((name) => settled(ledger, name)),
    reads: resourceReads + unknownDeleteReads,
    resourceReads,
    unknownDeleteReads,
    iamReads: 0,
    outstanding: ledger.outstanding(),
  };
}
