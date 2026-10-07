import { kindOf } from "../pubsub-production/ledger.mjs";
import { PROJECT } from "./plan.mjs";
import { boundaryPayload } from "./payload.mjs";

export const owned = (name, runId) =>
  typeof name === "string" &&
  /^[a-f0-9]{12}$/.test(runId) &&
  new RegExp(`^projects/${PROJECT}/(topics|subscriptions)/fe${runId}-[a-z0-9-]+$`).test(name);
export const selectOwn = (frame, published) =>
  (frame?.receivedMessages ?? []).filter(
    (item) =>
      typeof item.ackId === "string" &&
      item.ackId.length > 0 &&
      typeof item.message?.messageId === "string" &&
      published.has(item.message.messageId) &&
      published.get(item.message.messageId) === item.message.data,
  );
const settled = (ledger, name) =>
  (ledger.state().get(name)?.requests ?? []).every((request) =>
    ["rejected", "gone", "gone-a2"].includes(request.resolution),
  );
const resourceMethod = (name, action) =>
  `${action}${name.includes("/topics/") ? "Topic" : "Subscription"}`;
const serviceOf = (method) => (/Topic|Publish/.test(method) ? "Publisher" : "Subscriber");
const sleepDefault = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export async function runCell({ cell, meter, wire, ledger, runId, journal, sleep = sleepDefault }) {
  const prefix = `projects/${PROJECT}/`,
    suffix = `fe${runId}-${cell.id.toLowerCase()}`;
  const topic = `${prefix}topics/${suffix}-topic`,
    subscription = `${prefix}subscriptions/${suffix}-sub`;
  const tracked = new Set(),
    absentSeen = new Set();
  let complete = false,
    reason = null,
    stream;
  const send = async (category, method, request, { routeName, candidates } = {}) => {
    const name =
      request.name ?? request.topic ?? request.subscription?.name ?? request.subscription;
    if (
      !owned(name, runId) ||
      (routeName && !owned(routeName, runId)) ||
      (method === "CreateSubscription" && !owned(request.topic, runId))
    )
      throw new Error("foreign resource refused");
    const action = method.startsWith("Create")
      ? "create"
      : method.startsWith("Delete")
        ? "delete"
        : null;
    const names = candidates ?? [name];
    if (names.some((candidate) => !owned(candidate, runId)))
      throw new Error("foreign candidate refused");
    if (action === "delete" && ledger.deleting(name))
      throw new Error("unknown delete cannot retry");
    const intents = action
      ? names.map((candidate) => {
          tracked.add(candidate);
          return {
            name: candidate,
            action,
            transport: cell.transport,
            requestId: ledger.sent({ name: candidate, action, transport: cell.transport }),
          };
        })
      : [];
    let reply;
    try {
      reply = await wire.call({
        category,
        transport: cell.transport,
        service: serviceOf(method),
        method,
        request,
        cellId: cell.id,
        ...(routeName ? { routeName } : {}),
      });
    } catch (error) {
      for (const intent of intents) ledger.answered({ ...intent, kind: "unknown" });
      throw error;
    }
    let kind = kindOf(reply);
    if (
      action === "create" &&
      kind === "ok" &&
      (!names.includes(reply.body?.name) || "done" in reply.body)
    )
      kind = "unknown";
    if (method.startsWith("Get") && kind === "ok" && reply.body?.name !== name) kind = "unknown";
    for (const intent of intents)
      ledger.answered({
        ...intent,
        kind:
          action === "create" && kind === "ok" && intent.name !== reply.body.name ? "error" : kind,
      });
    if (method.startsWith("Get")) {
      ledger.observeRead(name, reply);
      if (reply.code === "NOT_FOUND" && !settled(ledger, name)) absentSeen.add(name);
    }
    if (kind === "unknown" || kind === "pending") throw new Error("unknown answer stops the cell");
    return reply;
  };
  const setup = async (twoTopics = false) => {
    const a = await send("create", "CreateTopic", { name: topic });
    if (!a.ok) throw new Error("topic setup refused");
    const second = twoTopics ? `${topic}-second` : subscription;
    const b = await send(
      "create",
      twoTopics ? "CreateTopic" : "CreateSubscription",
      twoTopics
        ? { name: second }
        : { name: subscription, topic, ackDeadlineSeconds: 10, labels: { env: "test", ttl: "7" } },
    );
    if (!b.ok) throw new Error("second setup refused");
    for (const name of [topic, second])
      if (!(await send("get", resourceMethod(name, "Get"), { name })).ok)
        throw new Error("setup read missing");
  };
  const wait = async (ms) => {
    if (ms >= meter.remaining()) throw new Error("wait exceeds cell time");
    await sleep(ms);
    meter.remaining();
  };
  try {
    if (cell.variant.includes("path-body")) {
      const isSub = cell.variant.startsWith("subscription");
      const routeName = isSub ? subscription : topic,
        bodyName = `${routeName}-body`;
      if (isSub && !(await send("create", "CreateTopic", { name: topic })).ok)
        throw new Error("anchor refused");
      for (const name of [routeName, bodyName]) {
        const reply = await send("get", resourceMethod(name, "Get"), { name });
        if (reply.code !== "NOT_FOUND") throw new Error("mismatch candidate not known absent");
      }
      journal.write({
        event: "path-body-candidates",
        cellId: cell.id,
        candidates: [routeName, bodyName],
        actualNativeAnalogue: false,
      });
      await send(
        "target",
        isSub ? "CreateSubscription" : "CreateTopic",
        { name: bodyName, ...(isSub ? { topic } : {}) },
        { routeName, candidates: [routeName, bodyName] },
      );
      for (const name of [routeName, bodyName])
        await send("target", resourceMethod(name, "Get"), { name });
      complete = true;
    } else if (cell.group === "G1") {
      const boundary = cell.variant.startsWith("request-") || cell.variant.startsWith("message-");
      await setup(boundary);
      if (boundary) {
        const kind = cell.variant.startsWith("message-") ? "message" : "request";
        const lower = Number(cell.variant.split("-")[1]);
        for (const target of [lower, lower + 1]) {
          const payload = boundaryPayload({ topic, transport: cell.transport, target, kind });
          journal.write({
            event: "boundary-input",
            cellId: cell.id,
            ...payload.sizes,
            kind,
            target,
            isolatedMessageLimit:
              kind === "message" ? "NOT_COMPARABLE-if-outer-request-preempts" : null,
          });
          await send("target", "Publish", { topic, messages: payload.messages });
        }
      } else if (cell.variant === "delete-recreate") {
        await send("target", "DeleteTopic", { name: topic });
        await send("target", "GetSubscription", { name: subscription });
        await send("target", "CreateTopic", { name: topic });
        await send("target", "GetSubscription", { name: subscription });
      } else {
        const pairs =
          cell.variant === "unicode-layout"
            ? [
                { env: "\u00e9", ttl: "7" },
                { env: "e\u0301", ttl: "7" },
              ]
            : cell.variant === "label-key-63-64"
              ? [{ ["k".repeat(63)]: "v" }, { ["k".repeat(64)]: "v" }]
              : cell.variant === "label-value-63-64"
                ? [{ key: "v".repeat(63) }, { key: "v".repeat(64) }]
                : [{ atomic: "probe" }, { env: "restored", ttl: "7" }];
        for (const [index, labels] of pairs.entries()) {
          await send("target", "UpdateSubscription", {
            subscription: { name: subscription, labels },
            updateMask:
              cell.variant === "atomic-mask" && index === 0
                ? "labels,fieldThatDoesNotExist"
                : "labels",
          });
          await send("target", "GetSubscription", { name: subscription });
        }
      }
      complete = true;
    } else {
      await setup();
      const published = new Map();
      const publish = async (index) => {
        const data = Buffer.from(`${runId}:${cell.id}:marker${index}`).toString("base64");
        const reply = await send("publish", "Publish", { topic, messages: [{ data }] });
        if (
          !reply.ok ||
          reply.body?.messageIds?.length !== 1 ||
          typeof reply.body.messageIds[0] !== "string"
        )
          throw new Error("publication is not bound");
        published.set(reply.body.messageIds[0], data);
        journal.write({
          event: "publication-binding",
          cellId: cell.id,
          messageId: reply.body.messageIds[0],
          data,
        });
      };
      const noMessage = [
        "invalid-ack-silence",
        "missing-opening-subscription",
        "opening-deadline-601",
        "missing-subscription",
      ].includes(cell.variant);
      if (!noMessage && cell.variant !== "future-publications") {
        for (let i = 0; i < (cell.variant === "flow-control" ? 3 : 1); i++) await publish(i);
      }
      const opener = {
        subscription,
        streamAckDeadlineSeconds: 10,
        maxOutstandingMessages: "1",
        maxOutstandingBytes: "1024",
      };
      if (cell.variant === "missing-opening-subscription") delete opener.subscription;
      if (cell.variant === "opening-deadline-601") opener.streamAckDeadlineSeconds = 601;
      if (cell.variant === "invalid-opening-frame") opener.streamAckDeadlineSeconds = 0;
      if (cell.variant === "missing-subscription") {
        const missing = `${subscription}-missing`;
        const reply = await send("target", "GetSubscription", { name: missing });
        if (reply.code !== "NOT_FOUND") throw new Error("missing subscription not known absent");
        opener.subscription = missing;
      }
      stream = await wire.open({ opener, cellId: cell.id });
      if (cell.variant === "future-publications") await publish(0);
      if (cell.variant === "invalid-ack-silence") stream.write({ ackIds: [cell.invalidAck] });
      const nextOwned = async () => {
        for (let frame = 0; frame < 6; frame++) {
          const body = await stream.next();
          if (!body) return [];
          const items = selectOwn(body, published);
          if (items.length) return items;
        }
        return [];
      };
      const first = (await nextOwned())[0];
      journal.write({ event: "first-owned-delivery", cellId: cell.id, bound: Boolean(first) });
      if (cell.variant === "half-close") {
        if (!first) throw new Error("half-close has no pending owned delivery");
        stream.end();
      }
      if (["in-stream-ack", "future-publications"].includes(cell.variant)) {
        if (!first) throw new Error("missing owned token");
        stream.write({ ackIds: [first.ackId] });
        await stream.next(1000);
      } else if (
        [
          "in-stream-nack",
          "in-stream-deadline-update",
          "invalid-update-frame",
          "update-array-length",
          "update-deadline-601",
        ].includes(cell.variant)
      ) {
        if (!first) throw new Error("missing owned update token");
        const seconds =
          cell.variant === "in-stream-nack"
            ? [0]
            : cell.variant === "invalid-update-frame"
              ? [-1]
              : cell.variant === "update-array-length"
                ? []
                : cell.variant === "update-deadline-601"
                  ? [601]
                  : [20];
        stream.write({ modifyDeadlineAckIds: [first.ackId], modifyDeadlineSeconds: seconds });
        if (cell.variant === "in-stream-nack") {
          const repeated = (await nextOwned()).find(
            (item) => item.message.messageId === first.message.messageId,
          );
          if (!repeated) throw new Error("redelivery not observed");
          stream.write({ ackIds: [repeated.ackId] });
        } else if (cell.variant === "in-stream-deadline-update") {
          journal.write({ event: "deadline-update-before", cellId: cell.id, seconds: 20 });
          await wait(10000);
          await stream.next(1000);
          await wait(11000);
          await stream.next(1000);
          journal.write({ event: "deadline-update-after", cellId: cell.id, seconds: 20 });
        } else await stream.next();
      } else if (cell.variant === "flow-control") {
        if (!first) throw new Error("first flow token missing");
        await wait(5000);
        const held = selectOwn(await stream.next(1000), published);
        journal.write({
          event: "flow-before-ack",
          cellId: cell.id,
          messages: held.length,
          heldMs: 5000,
        });
        stream.write({ ackIds: [first.ackId] });
        const seen = new Set([first.message.messageId]);
        for (let attempt = 0; attempt < 2; attempt++)
          for (const item of await nextOwned()) {
            if (!seen.has(item.message.messageId)) {
              seen.add(item.message.messageId);
              stream.write({ ackIds: [item.ackId] });
            }
          }
        if (seen.size < 3) throw new Error("credit resumption not fully observed");
      } else if (cell.variant === "client-cancel") {
        if (!first) throw new Error("cancel has no outstanding owned message");
        stream.cancel("unacked-owned-delivery");
        let repeated = false;
        for (let attempt = 0; attempt < 6 && !repeated; attempt++) {
          if (attempt > 0) await wait(3000);
          const reply = await send("target", "Pull", {
            subscription,
            maxMessages: 1,
            returnImmediately: true,
          });
          repeated = selectOwn(reply.body, published).some(
            (item) => item.message.messageId === first.message.messageId,
          );
        }
        if (!repeated) throw new Error("cancel redelivery not observed");
      }
      if (cell.variant === "half-close") {
        for (let frame = 0; frame < 6; frame++) if (!(await stream.next())) break;
      }
      const state = stream.state();
      journal.write({
        event: "stream-case-observation",
        cellId: cell.id,
        state,
        ackSelector: "NOT_COMPARABLE-until-observed",
        silenceBeyond30sGeneralized: false,
      });
      complete =
        !state.incomplete &&
        (Boolean(first) ||
          ((noMessage || cell.variant === "invalid-opening-frame") &&
            (Boolean(state.terminal) || cell.variant === "invalid-ack-silence")));
      if (!complete) reason = "bounded witness incomplete or clipped";
    }
  } catch (error) {
    reason = error.message;
    journal.write({ event: "case-incomplete", cellId: cell.id, reason });
  } finally {
    stream?.dispose();
  }
  let cleanupClosed = true;
  for (const name of [...tracked].sort(
    (a, b) => Number(b.includes("/subscriptions/")) - Number(a.includes("/subscriptions/")),
  )) {
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
  const result = {
    cellId: cell.id,
    complete,
    reason,
    cleanupClosed,
    names: [...tracked],
    outstanding: ledger.outstanding().filter((item) => tracked.has(item.name)),
  };
  journal.write({ event: "case-result", ...result });
  return result;
}

export async function recoverA2({ wire, ledger, runId, elapsedMs }) {
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
