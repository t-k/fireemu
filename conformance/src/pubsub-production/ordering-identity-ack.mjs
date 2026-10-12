import { isDeepStrictEqual } from "node:util";

// Strict replay mode for the two original ordering cells (owner ledger 1392 and 1395).
//
// When production and LOCAL pick a different ordering key for a later Pull, the source ackIds are bound
// to messages LOCAL has not delivered at that point, so the plain ack rewrite refuses them and LOCAL never
// acknowledges its own deliveries: the ordered keys stay blocked and later LOCAL Pulls come back empty.
// In this mode an Acknowledge row acknowledges every outstanding LOCAL delivery whose message the source
// has acknowledged by then (at this row or earlier). A message is the same when the LOCAL delivery carries
// the publication bound to the source message and equal data, attributes and ordering key. Other cells
// keep the existing replay unchanged.

export const ORDERING_IDENTITY_CASES = new Set(["ordering/rest", "ordering/grpc"]);

const REST_SUBSCRIPTION = /^\/v1\/(projects\/[^/]+\/subscriptions\/[^/:]+):(pull|acknowledge)$/;

export function subscriptionOf(request) {
  if (typeof request?.path === "string") {
    const match = REST_SUBSCRIPTION.exec(request.path);
    if (match) return match[1];
  } else if (typeof request?.body?.subscription === "string" && request.body.subscription) {
    return request.body.subscription;
  }
  throw new Error("ordering identity subscription required");
}

// Name of a subscription created with message ordering enabled, else null.
export function orderedSubscriptionOf(request) {
  if (request?.body?.enableMessageOrdering !== true) return null;
  if (typeof request.path === "string") {
    const match = /^\/v1\/(projects\/[^/]+\/subscriptions\/[^/:]+)$/.exec(request.path);
    return match ? match[1] : null;
  }
  return typeof request.body.name === "string" && request.body.name ? request.body.name : null;
}

const identity = (message) => ({
  data: message?.data ?? "",
  attributes: message?.attributes ?? {},
  orderingKey: message?.orderingKey ?? "",
});

export function createOrderingIdentityAck(bindings) {
  const subscriptions = new Map();
  const state = (subscription) => {
    if (!subscriptions.has(subscription))
      subscriptions.set(subscription, {
        sourceAcks: new Map(), // source ackId -> source messageId
        sourceMessages: new Map(), // source messageId -> message
        sourceAcked: [], // source messageIds acknowledged so far, in order
        outstanding: new Map(), // LOCAL messageId -> latest delivery
      });
    return subscriptions.get(subscription);
  };
  function observePull(subscription, sourceBody, localBody) {
    const s = state(subscription);
    for (const body of [sourceBody, localBody]) {
      const ids = (body?.receivedMessages ?? []).map((d) => d.message?.messageId);
      if (new Set(ids).size !== ids.length) throw new Error("duplicate delivery in one Pull");
    }
    for (const d of sourceBody?.receivedMessages ?? []) {
      s.sourceAcks.set(d.ackId, d.message.messageId);
      s.sourceMessages.set(d.message.messageId, d.message);
    }
    for (const d of localBody?.receivedMessages ?? []) s.outstanding.set(d.message.messageId, d);
  }
  function acknowledge(subscription, sourceAckIds) {
    if (
      !Array.isArray(sourceAckIds) ||
      sourceAckIds.length === 0 ||
      new Set(sourceAckIds).size !== sourceAckIds.length
    )
      throw new Error("source acknowledgement ids required");
    const s = subscriptions.get(subscription);
    for (const ack of sourceAckIds) {
      const id = s?.sourceAcks.get(ack);
      if (id === undefined) throw new Error("source acknowledgement without a source delivery");
      if (!s.sourceAcked.includes(id)) s.sourceAcked.push(id);
    }
    const due = [];
    for (const sourceMessageId of s.sourceAcked) {
      let localMessageId;
      try {
        localMessageId = bindings.get("message", sourceMessageId);
      } catch {
        continue;
      }
      const local = s.outstanding.get(localMessageId);
      if (
        !local ||
        !isDeepStrictEqual(identity(local.message), identity(s.sourceMessages.get(sourceMessageId)))
      )
        continue;
      due.push({ sourceMessageId, localMessageId, ackId: local.ackId });
    }
    if (due.length === 0) return null;
    for (const d of due) s.outstanding.delete(d.localMessageId);
    return {
      ackIds: due.map((d) => d.ackId),
      due: due.map(({ sourceMessageId, localMessageId }) => ({ sourceMessageId, localMessageId })),
    };
  }
  return { observePull, acknowledge };
}

// Owner 1392 judge for the ordered subscription of an original ordering cell. Input: the source and LOCAL
// Pull bodies on that subscription, in order. Messages are compared by identity (ordering key, data and
// attributes); a redelivery repeats a message and is judged on its first delivery.
export function judgeOrderingCell(sourcePulls, localPulls) {
  const key = (d) => JSON.stringify(identity(d.message));
  const firstDeliveries = (pulls) => {
    const seen = new Set(),
      order = [];
    for (const p of pulls)
      for (const d of p?.receivedMessages ?? []) {
        const k = key(d);
        if (!seen.has(k)) {
          seen.add(k);
          order.push(d);
        }
      }
    return order;
  };
  const mixed = (pulls) =>
    pulls.some((p) => {
      const kinds = new Set(
        (p?.receivedMessages ?? []).map((d) => Boolean(d.message?.orderingKey)),
      );
      return kinds.size > 1;
    });
  if (mixed(localPulls))
    return {
      verdict: "DIVERGES",
      reason: "owner 1392: keyed and unkeyed messages mixed in one Pull",
    };
  const source = firstDeliveries(sourcePulls),
    local = firstDeliveries(localPulls);
  if (!isDeepStrictEqual(source.map(key).toSorted(), local.map(key).toSorted()))
    return { verdict: "DIVERGES", reason: "owner 1392: delivered message set differs" };
  const perKey = (deliveries) => {
    const map = new Map();
    for (const d of deliveries) {
      const k = d.message?.orderingKey ?? "";
      if (!k) continue;
      if (!map.has(k)) map.set(k, []);
      map.get(k).push(key(d));
    }
    return map;
  };
  const a = perKey(source),
    b = perKey(local);
  for (const [k, order] of a)
    if (!isDeepStrictEqual(order, b.get(k)))
      return { verdict: "DIVERGES", reason: `owner 1392: per-key order differs (${k})` };
  return {
    verdict: "MATCH",
    reason: "owner 1392: per-key order, no keyed/unkeyed mixing and delivered set equal",
  };
}

// Owner 1392 cell results for every ordering cell present in the source exchanges. `success` is the
// replay's own success predicate; only successful Pulls on the ordered subscription are judged.
export function orderingCellResults(sourceExchanges, localExchanges, success) {
  const results = {};
  for (const cell of ORDERING_IDENTITY_CASES) {
    const original = sourceExchanges.filter((e) => e.case === cell);
    if (original.length === 0) continue;
    const created = original
      .filter((e) => e.op === "createSubscription")
      .map((e) => orderedSubscriptionOf(e.request))
      .filter(Boolean);
    if (created.length !== 1)
      throw new Error("ordering cell needs exactly one ordered subscription");
    const [orderedSubscription] = created;
    const pulls = (exchanges) =>
      exchanges
        .filter(
          (e) =>
            e.case === cell &&
            e.op === "pull" &&
            success(e) &&
            subscriptionOf(e.request) === orderedSubscription,
        )
        .map((e) => e.response.body);
    const sourcePulls = pulls(original),
      localPulls = pulls(localExchanges);
    const delivered = (bodies) =>
      new Set(
        bodies.flatMap((b) =>
          (b?.receivedMessages ?? []).map((d) => JSON.stringify(identity(d.message))),
        ),
      ).size;
    results[cell] = {
      orderedSubscription,
      sourcePulls: sourcePulls.length,
      localPulls: localPulls.length,
      sourceDelivered: delivered(sourcePulls),
      localDelivered: delivered(localPulls),
      ...judgeOrderingCell(sourcePulls, localPulls),
    };
  }
  return results;
}
