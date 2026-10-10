import { isDeepStrictEqual as same } from "node:util";

export const SCHEDULING_APPROVAL = Object.freeze({
  proposalSha256: "5dd0032ef9581d029ac500dc6e81d50ac5f0524988edde1b9af02800b2e94a7d",
  correctionSha256: "8937528243dfe0858cc5ce27090f155f51d50514e1692a6432f6877b3db7ccca",
  independentReviewSha256: "1e4ea85afe7bdb6786e7cee9d19893a8cd4de4403b0e804efe9ec07db1965be9",
  owner1203LineSha256: "df6b5272565599403342ba572b913f2934e971de2bae449d5d0ea91b2fae8b5f",
  owner1204LineSha256: "b6842d3c55c29550f40f495529a020e1e5d2427c32c1ae8f4be7af47d1001ae7",
});
const payload = (m) => ({
  data: m?.data,
  attributes: m?.attributes ?? {},
  orderingKey: m?.orderingKey ?? "",
});
const combine = (values) =>
  values.includes("DIVERGES")
    ? "DIVERGES"
    : values.includes("NOT_COMPARABLE")
      ? "NOT_COMPARABLE"
      : "MATCH";

function instant(value) {
  const match =
    typeof value === "string" &&
    /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{3}|\d{6}|\d{9}))?Z$/.exec(value);
  if (!match) return null;
  const ms = Date.parse(`${match[1]}Z`);
  if (!Number.isFinite(ms) || new Date(ms).toISOString().slice(0, 19) !== match[1]) return null;
  return BigInt(ms) * 1000000n + BigInt((match[2] ?? "").padEnd(9, "0"));
}

export function createSchedulingDisposition(input, cell, authority) {
  if (
    !authority ||
    !Object.entries(SCHEDULING_APPROVAL).every(([k, v]) => authority[k] === v) ||
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
  const windows = new Map();
  function observation(source) {
    const next = cell.exchanges.find((e) => e.n > source.n)?.n ?? Infinity;
    const rows = cell.observations.filter(
      (o) =>
        o.n > source.responseN &&
        o.n < next &&
        o.subscription === source.request.subscription &&
        Array.isArray(o.items),
    );
    return rows.length === 1 ? rows[0] : null;
  }
  function role(source, subscription) {
    const o = observation(source);
    if (!o || subscription?.filter) return null;
    if (
      ["R5", "N5", "R6", "N6"].includes(cell.id) &&
      o.stage === "unfiltered-positive-control" &&
      subscription?.enableMessageOrdering !== true
    )
      return { kind: "control", key: source.request.subscription };
    if (cell.id === "N9") {
      const approved = authority.owner1215;
      if (
        approved?.proposalSha256 !==
          "10462775738fa3a1de9fae803e285bb385fd379ff6cf0ddadb856b5c93457b05" ||
        approved.rowSha256WithLf !==
          "60d325e05acea467d78513e2ebcc474f62e8f9bde8971e8118d644bb33225606" ||
        input.metadata.runId !== "45298b949da0" ||
        input.metadata.sourceHead !== "3235e54940ff1ece6004d3e78e70548ca6eba85c" ||
        input.metadata.packetSha256 !==
          "285a6220ed6c7e7efdafbe8618a52e3f87aac1be57a0ea7a684ae80b75126c80" ||
        input.metadata.descriptorSha256 !==
          "3b455b9613b20aa89d2ea277962652f110f45847c9b80668a66605517aba5707" ||
        source.n !== 1065 ||
        source.requestId !== 423 ||
        source.request.maxMessages !== 3 ||
        o.stage !== "first-Pull-exact-order" ||
        subscription?.enableMessageOrdering !== true
      )
        return null;
      return { kind: "cross-key", key: source.request.subscription };
    }
    if (
      cell.id === "R9" &&
      ["first-Pull-exact-order", "subsequent-Pull-exact-order"].includes(o.stage)
    )
      return {
        kind: subscription?.enableMessageOrdering === true ? "cross-key" : "control",
        key: source.request.subscription,
      };
    if (
      ["R12", "N12", "N13"].includes(cell.id) &&
      ["snapshot-replay", "both-target-Seek-followup"].includes(o.stage)
    ) {
      const seek = cell.exchanges.findLast(
        (e) =>
          e.n < source.n &&
          e.method === "Seek" &&
          e.request.subscription === source.request.subscription,
      );
      if (!seek?.reply.ok || seek.reply.unknown) return null;
      return { kind: "seek", key: `${source.request.subscription}\0${seek.n}`, seek };
    }
    return null;
  }
  return {
    pull(source, actual, publications, subscription) {
      const r = role(source, subscription);
      if (!r) return null;
      let w = windows.get(r.key);
      if (!w) {
        const eligible = [...publications.values()].filter((p) => p.topic === subscription.topic);
        const required =
          r.kind === "seek"
            ? new Set(
                cell.exchanges
                  .filter((e) => e.method === "Pull" && role(e, subscription)?.key === r.key)
                  .flatMap((e) =>
                    (e.reply.body?.receivedMessages ?? []).map((i) => i.message?.messageId),
                  ),
              )
            : new Set(eligible.map((p) => p.sourceMessageId));
        const forbidden = new Set();
        if (
          r.kind === "seek" &&
          r.seek.request.snapshot &&
          !Object.hasOwn(r.seek.request, "time")
        ) {
          const snapshot = cell.exchanges.find(
            (e) =>
              e.method === "CreateSnapshot" &&
              e.request.name === r.seek.request.snapshot &&
              e.n < r.seek.n,
          );
          if (snapshot) {
            const tokens = new Map();
            for (const e of cell.exchanges.filter(
              (prior) =>
                prior.n < snapshot.n && prior.request.subscription === source.request.subscription,
            )) {
              if (e.method === "Pull")
                for (const item of e.reply.body?.receivedMessages ?? [])
                  tokens.set(item.ackId, item.message?.messageId);
              if (e.method === "Acknowledge" && e.reply.ok && !e.reply.unknown)
                for (const id of e.request.ackIds ?? [])
                  if (tokens.has(id)) forbidden.add(tokens.get(id));
            }
          }
        }
        w = {
          kind: r.kind,
          subscription: source.request.subscription,
          required,
          forbidden,
          seen: new Set(),
          acked: new Set(),
          pending: new Map(),
          order: new Map(),
          verdicts: [],
          requests: [],
          deliveries: [],
        };
        windows.set(r.key, w);
      }
      w.requests.push(source.requestId);
      if (
        !actual?.ok ||
        actual.unknown ||
        actual.code !== source.reply.code ||
        actual.status !== source.reply.status
      ) {
        w.verdicts.push(actual?.unknown ? "NOT_COMPARABLE" : "DIVERGES");
        return { ...r, bindings: [] };
      }
      const items = actual.body?.receivedMessages ?? [];
      if (
        !Array.isArray(items) ||
        !Number.isSafeInteger(source.request.maxMessages) ||
        items.length > source.request.maxMessages
      ) {
        w.verdicts.push("DIVERGES");
        return { ...r, bindings: [] };
      }
      const envelope = { ...actual.body };
      delete envelope.receivedMessages;
      const expectedEnvelope = { ...source.reply.body };
      delete expectedEnvelope.receivedMessages;
      if (!same(envelope, expectedEnvelope)) w.verdicts.push("DIVERGES");
      const bindings = [],
        batchKeys = new Set();
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
          typeof item.ackId !== "string" ||
          !item.ackId ||
          w.forbidden.has(p.sourceMessageId) ||
          w.seen.has(p.sourceMessageId) ||
          [...w.pending.values()].some((b) => b.ackId === item.ackId)
        ) {
          w.verdicts.push("DIVERGES");
          continue;
        }
        const key = p.payload.orderingKey;
        if (w.kind === "cross-key" && key) {
          const sequence = [...publications.values()].filter(
            (v) => v.topic === subscription.topic && v.payload.orderingKey === key,
          );
          const next = w.order.get(key) ?? 0;
          if (
            sequence[next]?.sourceMessageId !== p.sourceMessageId ||
            (!batchKeys.has(key) && [...w.pending.values()].some((b) => b.orderingKey === key))
          )
            w.verdicts.push("DIVERGES");
          w.order.set(key, next + 1);
          batchKeys.add(key);
        }
        const binding = {
          sourceMessageId: p.sourceMessageId,
          messageId: p.messageId,
          ackId: item.ackId,
          orderingKey: key,
          deliveredAt: Date.parse(source.at),
          deadline:
            instant(source.at) !== null &&
            Number.isSafeInteger(subscription.ackDeadlineSeconds) &&
            subscription.ackDeadlineSeconds > 0
              ? instant(source.at) + BigInt(subscription.ackDeadlineSeconds) * 1000000000n
              : null,
        };
        w.seen.add(p.sourceMessageId);
        w.pending.set(p.sourceMessageId, binding);
        w.deliveries.push(structuredClone(item));
        bindings.push({
          publication: p,
          delivered: item,
          binding,
          witnesses: cell.exchanges
            .filter((e) => e.method === "Pull" && role(e, subscription)?.key === r.key)
            .flatMap((e) => e.reply.body?.receivedMessages ?? [])
            .filter((i) => i.message?.messageId === p.sourceMessageId),
        });
      }
      return { ...r, bindings };
    },
    owns(subscription) {
      return [...windows.values()].some((w) => w.subscription === subscription);
    },
    seek(subscription, actual) {
      if (
        !actual?.ok ||
        actual.unknown ||
        actual.code !== "OK" ||
        !same(actual.body, {}) ||
        (actual.status !== 200 && actual.status !== undefined)
      )
        return;
      for (const w of windows.values()) {
        if (w.subscription !== subscription) continue;
        for (const binding of w.pending.values()) binding.invalidated = true;
      }
    },
    ackIds(subscription, source) {
      const pending = [...windows.values()]
        .filter((w) => w.subscription === subscription)
        .flatMap((w) => Array.from(w.pending.values()))
        .filter((binding) => !binding.invalidated);
      if (source) {
        const selected = (source.request.ackIds ?? []).map((id) => {
          const publication = cell.exchanges
            .filter(
              (e) =>
                e.n < source.n && e.method === "Pull" && e.request.subscription === subscription,
            )
            .flatMap((e) => e.reply.body?.receivedMessages ?? [])
            .findLast((item) => item.ackId === id)?.message?.messageId;
          return pending.find((binding) => binding.sourceMessageId === publication)?.ackId;
        });
        if (
          selected.length === pending.length &&
          selected.every((id) => typeof id === "string") &&
          new Set(selected).size === pending.length
        )
          return selected;
      }
      return pending.map((binding) => binding.ackId);
    },
    ack(subscription, ids, actual, at) {
      const affected = [...windows.values()].filter((w) => w.subscription === subscription);
      if (
        !actual?.ok ||
        actual.unknown ||
        actual.code !== "OK" ||
        !same(actual.body, {}) ||
        (actual.status !== 200 && actual.status !== undefined)
      ) {
        for (const w of affected) w.verdicts.push(actual?.unknown ? "NOT_COMPARABLE" : "DIVERGES");
        return;
      }
      for (const id of ids) {
        const w =
          [...windows.values()].find(
            (window) =>
              window.subscription === subscription &&
              [...window.pending.values()].some(
                (binding) => binding.ackId === id && !binding.invalidated,
              ),
          ) ?? [...windows.values()].findLast((window) => window.subscription === subscription);
        const b = w && [...w.pending.values()].find((binding) => binding.ackId === id);
        if (!b || b.invalidated) {
          w?.verdicts.push("DIVERGES");
          continue;
        }
        if (instant(at) === null || b.deadline === null || instant(at) >= b.deadline) {
          w.verdicts.push("NOT_COMPARABLE");
          continue;
        }
        w.acked.add(b.sourceMessageId);
        w.pending.delete(b.sourceMessageId);
      }
    },
    finish() {
      const proof = [...windows.values()].map((w) => ({
        kind: w.kind,
        subscription: w.subscription,
        sourceRequestIds: w.requests,
        required: [...w.required],
        received: [...w.seen],
        acknowledged: [...w.acked],
        invalidated: [...w.pending.values()]
          .filter((b) => b.invalidated)
          .map((b) => b.sourceMessageId),
        rawDeliveries: w.deliveries,
        verdict: combine([
          ...w.verdicts,
          !w.required.size ||
          [...w.required].some((id) => !w.seen.has(id) || !w.acked.has(id)) ||
          w.pending.size
            ? "NOT_COMPARABLE"
            : "MATCH",
        ]),
      }));
      return {
        approval: {
          ...structuredClone(SCHEDULING_APPROVAL),
          ...(cell.id === "N9" ? { owner1215: structuredClone(authority.owner1215) } : {}),
        },
        source: structuredClone(input.metadata),
        runtimeInputs: structuredClone(input.runtimeInputs),
        cellId: cell.id,
        windows: proof,
        verdict: proof.length ? combine(proof.map((p) => p.verdict)) : "NOT_COMPARABLE",
      };
    },
  };
}
