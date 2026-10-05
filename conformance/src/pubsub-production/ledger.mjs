// An append-only, per-request ledger preserves raw answers separately from settlement proofs.
// Absence cannot confirm an unknown creation. Unknown deletions remain sticky until an aged A2 read.
import { readFileSync } from "node:fs";

export const MIN_ABSENCE_WAIT_MS = 10 * 60 * 1000;
const object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const operationName = (value) =>
  typeof value === "string" && /(?:^|\/)operations\/[^/]+$/.test(value);
const operationBody = (body) => object(body) && ("done" in body || operationName(body.name));
const unknownReply = (reply) =>
  reply.unknown === true ||
  reply.code === "CANCELLED" ||
  (typeof reply.status === "number" &&
    (reply.status < 200 ||
      (reply.status >= 300 && reply.status < 400) ||
      reply.status >= 500 ||
      reply.status === 499));
const complete = (reply) => reply.ok === true && !unknownReply(reply) && object(reply.body);

/** Classify only this answer; a later conflict never confirms an earlier request. */
export function kindOf(reply) {
  if (unknownReply(reply)) return "unknown";
  if (reply.ok) {
    if (operationBody(reply.body)) {
      if (
        !operationName(reply.body.name) ||
        typeof reply.body.done !== "boolean" ||
        "error" in reply.body
      )
        return "unknown";
      if (!reply.body.done) return "pending";
      if (!object(reply.body.response)) return "unknown";
    }
    return "ok";
  }
  return reply.code === "ALREADY_EXISTS" ? "conflict" : "error";
}

/** State and durable proofs for each creation or deletion, including unanswered legacy requests. */
export function createLedger({
  journal = { write() {} },
  now = () => new Date(),
  names = new Map(),
} = {}) {
  const entry = (name) => {
    if (!names.has(name)) names.set(name, { creates: [], deletes: [], open: [], requests: [] });
    return names.get(name);
  };
  const write = (row) => journal.write({ at: now().toISOString(), ...row });
  const resolve = (name, request, resolution, proof, persist = true) => {
    request.resolution = resolution;
    request.proof = proof;
    if (persist) write({ phase: "resolved", name, requestId: request.id, resolution, proof });
  };
  const ledger = {
    withJournal: (other) => createLedger({ journal: other, now, names }),
    sent({ name, action, transport, requestId }) {
      const item = entry(name);
      const id = requestId ?? `${name}#${item.requests.length + 1}`;
      item.requests.push({
        id,
        action,
        transport,
        kind: "unknown",
        answered: false,
        resolution: "unresolved",
      });
      item.open.push(action);
      write({ phase: "sent", name, action, transport, requestId: id });
      return id;
    },
    answered({ name, action, transport, requestId, kind, operation }) {
      const item = entry(name);
      const request = item.requests.find((r) =>
        requestId
          ? r.id === requestId
          : r.action === action && r.transport === transport && !r.answered,
      );
      if (
        !request ||
        request.answered ||
        request.action !== action ||
        request.transport !== transport
      )
        throw new Error("an answer has no matching issued request");
      request.kind = kind;
      request.answered = true;
      if (operationName(operation)) request.operation = operation;
      request.resolution =
        kind === "ok"
          ? "confirmed"
          : kind === "unknown" || kind === "pending"
            ? "unresolved"
            : "rejected";
      const at = item.open.indexOf(action);
      if (at >= 0) item.open.splice(at, 1);
      (action === "create" ? item.creates : item.deletes).push(kind);
      write({
        phase: "answered",
        name,
        action,
        transport,
        requestId: request.id,
        kind,
        ...(request.operation ? { operation: request.operation } : {}),
      });
    },
    /** Only the requested resource's complete positive read confirms unresolved creations. */
    observeRead(name, reply) {
      if (!complete(reply) || reply.body.name !== name || operationBody(reply.body)) return false;
      const item = names.get(name);
      for (const request of item?.requests ?? [])
        if (request.action === "create" && request.resolution === "unresolved")
          resolve(name, request, "confirmed", { kind: "own-positive-read", name });
      return true;
    },
    /** Native Pub/Sub has no LRO route; callers must supply a complete read of this exact own operation. */
    observeOperation(operation, reply) {
      if (
        !complete(reply) ||
        !operationName(operation) ||
        reply.body.name !== operation ||
        reply.body.done !== true ||
        "error" in reply.body ||
        !object(reply.body.response)
      )
        return false;
      let changed = false;
      for (const [name, item] of names)
        for (const request of item.requests)
          if (
            request.operation === operation &&
            request.resolution === "unresolved" &&
            (request.action === "delete" || reply.body.response.name === name)
          ) {
            resolve(name, request, "confirmed", { kind: "own-operation-done", operation });
            changed = true;
          }
      return changed;
    },
    unconfirmed(name) {
      return (names.get(name)?.requests ?? []).some(
        (r) => r.action === "create" && r.resolution === "unresolved",
      );
    },
    deleting(name) {
      return (names.get(name)?.requests ?? []).some(
        (r) => r.action === "delete" && r.resolution === "unresolved",
      );
    },
    /** A clean 404 settles only confirmed creations or sticky deletions with the permitted proof. */
    settleAbsent(name, reply, { a2ElapsedMs, a2EligibleRequestIds } = {}) {
      if (
        reply.unknown === true ||
        reply.code !== "NOT_FOUND" ||
        (reply.status !== undefined &&
          (reply.status !== 404 || reply.body?.error?.status !== "NOT_FOUND"))
      )
        return false;
      const item = names.get(name);
      if (ledger.unconfirmed(name)) return false;
      const requests = item?.requests ?? [];
      const aged = Number.isFinite(a2ElapsedMs) && a2ElapsedMs >= MIN_ABSENCE_WAIT_MS;
      if (
        ledger.deleting(name) &&
        (!aged ||
          (a2EligibleRequestIds &&
            requests.some(
              (r) =>
                r.action === "delete" &&
                r.resolution === "unresolved" &&
                !a2EligibleRequestIds.has(r.id),
            )))
      )
        return false;
      const lastCreate = requests.findLastIndex(
        (r) => r.action === "create" && r.resolution !== "rejected",
      );
      const confirmedDelete = requests.some(
        (r, index) => index > lastCreate && r.action === "delete" && r.resolution === "confirmed",
      );
      const confirmedCreate = requests.some(
        (r) => r.action === "create" && r.resolution === "confirmed",
      );
      if (!confirmedDelete && confirmedCreate && !aged) return false;
      if (!confirmedDelete && !confirmedCreate && !ledger.deleting(name)) return false;
      for (const request of requests)
        if (request.resolution !== "rejected")
          resolve(name, request, aged ? "gone-a2" : "gone", {
            kind: aged ? "aged-a2-404" : "own-delete-404",
            ...(aged ? { elapsedMs: a2ElapsedMs } : {}),
          });
      return true;
    },
    outstanding: () =>
      [...names].flatMap(([name, item]) =>
        item.requests
          .filter((r) => r.resolution === "unresolved")
          .map((r) => ({ name, requestId: r.id, action: r.action, kind: r.kind })),
      ),
    replayResolution(row) {
      const request = names.get(row.name)?.requests.find((r) => r.id === row.requestId);
      if (!request) throw new Error("a settlement has no matching issued request");
      if (
        request.resolution === row.resolution &&
        JSON.stringify(request.proof) === JSON.stringify(row.proof)
      )
        return;
      // Re-evaluate every proof rather than trusting a hand-edited resolution label.
      if (
        row.proof?.kind === "own-positive-read" &&
        row.resolution === "confirmed" &&
        row.proof.name === row.name &&
        request.action === "create"
      )
        resolve(row.name, request, row.resolution, row.proof, false);
      else if (
        row.proof?.kind === "own-operation-done" &&
        row.resolution === "confirmed" &&
        row.proof.operation === request.operation
      )
        resolve(row.name, request, row.resolution, row.proof, false);
      else if (
        (row.resolution === "gone-a2" &&
          row.proof?.kind === "aged-a2-404" &&
          row.proof.elapsedMs >= MIN_ABSENCE_WAIT_MS) ||
        (row.resolution === "gone" && row.proof?.kind === "own-delete-404")
      ) {
        if (
          !ledger.settleAbsent(
            row.name,
            {
              code: "NOT_FOUND",
              status: 404,
              unknown: false,
              body: { error: { status: "NOT_FOUND" } },
            },
            { a2ElapsedMs: row.proof.elapsedMs },
          )
        )
          throw new Error("a settlement proof contradicts the request state");
      } else throw new Error("unreadable settlement proof");
    },
    state: () => names,
  };
  return Object.freeze(ledger);
}

/** Reconstruct exact requests; an interrupted send remains unresolved and is never resubmitted. */
export function readLedger(path, options = {}) {
  const ledger = createLedger(options);
  for (const line of readFileSync(path, "utf8").split("\n")) {
    if (!line.trim()) continue;
    const item = JSON.parse(line);
    if (item.phase === "sent") ledger.sent(item);
    else if (item.phase === "answered") ledger.answered(item);
    else if (item.phase === "resolved") ledger.replayResolution(item);
    else throw new Error("unreadable issued ledger phase");
  }
  for (const item of ledger.state().values()) {
    for (const request of item.requests)
      if (!request.answered)
        (request.action === "create" ? item.creates : item.deletes).push("unknown");
    item.open.length = 0;
  }
  return ledger;
}

export const maybeCreated = (item) =>
  item.creates.some((kind) => ["ok", "unknown", "pending"].includes(kind)) ||
  item.open.includes("create");
export const maybeDeleting = (item) =>
  item.requests.some((r) => r.action === "delete" && r.resolution === "unresolved");
