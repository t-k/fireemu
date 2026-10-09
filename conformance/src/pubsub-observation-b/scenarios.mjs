import { protectCell, checkpoint, obligations } from "../pubsub-observation/safety.mjs";
import { normalizeOutcome } from "../pubsub-production/outcome.mjs";
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
export function graph(cell, runId) {
  if (
    !/^[a-f0-9]{12}$/.test(runId) ||
    !makePlan().cells.some((c) => JSON.stringify(c) === JSON.stringify(cell))
  )
    throw new Error("declared graph required");
  const root = `projects/${PROJECT}`,
    suffix = `fe${runId}-${cell.id.toLowerCase()}`;
  const topic = `${root}/topics/${suffix}-prereq`,
    subscription = `${root}/subscriptions/${suffix}-prereq`;
  const members = [
    ...["a", "b", "c"].map((letter) => `${root}/${cell.kind}/${suffix}-${letter}`),
    `${root}/${cell.kind}/sentinel-${runId}-${cell.id.toLowerCase()}-x`,
  ];
  const order = { lexical: [0, 1, 2], reverse: [2, 1, 0], rotated: [1, 2, 0] }[cell.permutation];
  const resources = [];
  if (cell.kind !== "topics")
    resources.push({ name: topic, method: "CreateTopic", request: { name: topic } });
  if (cell.kind === "snapshots")
    resources.push({
      name: subscription,
      method: "CreateSubscription",
      request: { name: subscription, topic, ackDeadlineSeconds: 10 },
    });
  for (const index of [...order, 3]) {
    const name = members[index];
    resources.push({
      name,
      method: `Create${kinds[cell.kind]}`,
      request: {
        name,
        ...(cell.kind === "subscriptions"
          ? { topic, ackDeadlineSeconds: 10 }
          : cell.kind === "snapshots"
            ? { subscription }
            : {}),
      },
    });
  }
  return { members, resources, topic, subscription };
}
export const owned = (name, runId) =>
  /^[a-f0-9]{12}$/.test(runId) &&
  makePlan().cells.some((c) => graph(c, runId).resources.some((r) => r.name === name));

export function parsePage(body, { kind, allowed, pageSize }) {
  if (
    !body ||
    typeof body !== "object" ||
    Array.isArray(body) ||
    !Object.hasOwn(kinds, kind) ||
    !Array.isArray(allowed) ||
    !Number.isSafeInteger(pageSize) ||
    pageSize < 0
  )
    throw new Error("invalid page parser inputs");
  const members = body[kind] ?? [];
  if (
    !Array.isArray(members) ||
    members.some((r) => typeof r?.name !== "string" || !allowed.includes(r.name))
  )
    throw new Error("foreign or unreadable list member");
  const names = members.map((r) => r.name);
  if (new Set(names).size !== names.length || names.length > pageSize)
    throw new Error("page cardinality invalid");
  const nextPageToken = body.nextPageToken ?? null;
  if (
    nextPageToken !== null &&
    (typeof nextPageToken !== "string" || !nextPageToken.length || nextPageToken.length > 4096)
  )
    throw new Error("unrecordable token shape");
  return { names, nextPageToken };
}

export async function runCell({ cell, meter, wire, ledger, runId, journal }) {
  const manifest = graph(cell, runId),
    allowed = new Set(manifest.resources.map((r) => r.name));
  const tracked = new Set(),
    absentSeen = new Set(),
    observations = [];
  let complete = false,
    reason = null,
    budgetOverrun = false,
    deletedCursor = null;
  const send = async (category, method, request) => {
    const maintenance = category.startsWith("cleanup");
    if (meter.remaining(maintenance) < minimumCallMs(method))
      throw new Error("recorded latency margin unavailable");
    const list = method.startsWith("List"),
      name = request.name ?? request.topic;
    if (list ? request.project !== `projects/${PROJECT}` : !allowed.has(name))
      throw new Error("foreign resource refused");
    for (const field of ["topic", "subscription"])
      if (request[field] !== undefined && !allowed.has(request[field]))
        throw new Error("foreign prerequisite refused");
    const action = method.startsWith("Create")
      ? "create"
      : method.startsWith("Delete")
        ? "delete"
        : null;
    if (action === "delete" && ledger.deleting(name))
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
    if (kind === "unknown" || kind === "pending") throw new Error("unknown answer stops the cell");
    if (reply.budgetOverrun) budgetOverrun = true;
    try {
      meter.remaining(maintenance);
    } catch {
      budgetOverrun = true;
    }
    return reply;
  };
  const list = async (stage, page, required = true) => {
    const reply = await send("list", `List${cell.kind[0].toUpperCase() + cell.kind.slice(1)}`, {
      project: `projects/${PROJECT}`,
      ...page,
    });
    if (!reply.ok) {
      const observation = {
        event: "page-observation",
        cellId: cell.id,
        stage,
        requestToken: page.pageToken ?? null,
        names: [],
        nextPageToken: null,
        projection: [],
        reply,
        verdict: "known-refusal",
      };
      observations.push(observation);
      journal.write(observation);
      if (required) throw new Error("required page refused");
      return observation;
    }
    const { names, nextPageToken } = parsePage(reply.body, {
      kind: cell.kind,
      allowed: manifest.members,
      pageSize: page.pageSize,
    });
    const observation = {
      event: "page-observation",
      cellId: cell.id,
      stage,
      requestToken: page.pageToken ?? null,
      names,
      nextPageToken,
      projection: names.filter((n) => n.split("/").at(-1).startsWith(`fe${runId}-`)),
      reply,
    };
    observations.push(observation);
    journal.write(observation);
    meter.remaining();
    return observation;
  };
  let cleanupClosed = true;
  const failures = await protectCell({
    body: async () => {
      journal.write({
        event: "cell-manifest",
        cellId: cell.id,
        manifest,
        creationOrder: manifest.resources.map((r) => r.name),
        canonicalCoordinates: cell.coordinates,
      });
      for (const r of manifest.resources) {
        if (
          cell.kind === "snapshots" &&
          r.method === "CreateSnapshot" &&
          !tracked.has(manifest.members[0]) &&
          !tracked.has(manifest.members[1]) &&
          !tracked.has(manifest.members[2])
        ) {
          const reply = await send("publish", "Publish", {
            topic: manifest.topic,
            messages: [{ data: Buffer.from("snapshot prerequisite").toString("base64") }],
          });
          if (!reply.ok) throw new Error("snapshot prerequisite publication refused");
        }
        if (!(await send("create", r.method, r.request)).ok)
          throw new Error("resource setup refused");
        if (!(await send("get", resourceMethod(r.name, "Get"), { name: r.name })).ok)
          throw new Error("setup read missing");
      }
      const baseline = await list("baseline", { pageSize: 1000 });
      if (
        baseline.nextPageToken ||
        baseline.names.length !== 4 ||
        manifest.members.some((n) => !baseline.names.includes(n))
      )
        throw new Error("baseline member coverage incomplete");
      const first = await list("first", { pageSize: 1 });
      if (first.names.length !== 1 || !first.nextPageToken)
        throw new Error("issued cursor witness missing");
      deletedCursor = first.names[0];
      if (
        !(
          await send("cursorDelete", resourceMethod(deletedCursor, "Delete"), {
            name: deletedCursor,
          })
        ).ok
      )
        throw new Error("cursor deletion refused");
      const absent = await send("cursorGet", resourceMethod(deletedCursor, "Get"), {
        name: deletedCursor,
      });
      if (!ledger.settleAbsent(deletedCursor, absent))
        throw new Error("cursor delete readback incomplete");
      let page = await list("after-delete", { pageSize: 1, pageToken: first.nextPageToken }, false);
      const traversed = new Set(page.names);
      let exhausted = page.verdict !== "known-refusal" && !page.nextPageToken;
      for (let i = 0; i < 2 && page.nextPageToken; i++) {
        const next = await list(
          `continuation-${i + 1}`,
          { pageSize: 1, pageToken: page.nextPageToken },
          false,
        );
        if (next.names.some((n) => traversed.has(n)))
          throw new Error("page traversal repeated a member");
        for (const name of next.names) traversed.add(name);
        page = next;
        exhausted = page.verdict !== "known-refusal" && !page.nextPageToken;
      }
      const original = first.nextPageToken;
      const changed = (original[0] === "A" ? "B" : "A") + original.slice(1);
      await list("altered-token", { pageSize: 1, pageToken: changed }, false);
      const control = await list("ownership-control", { pageSize: 1000 });
      const remaining = manifest.members.filter((n) => n !== deletedCursor);
      if (
        control.nextPageToken ||
        control.names.length !== 3 ||
        remaining.some((n) => !control.names.includes(n))
      )
        throw new Error("post-delete member coverage incomplete");
      complete = exhausted && traversed.size === 3 && remaining.every((n) => traversed.has(n));
      if (!complete)
        reason = "bounded traversal insufficient; no invented continuation or hidden polling";
    },
    report: (error) => {
      reason = error.message;
      journal.write({ event: "case-incomplete", cellId: cell.id, reason });
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
    deletedCursor,
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
