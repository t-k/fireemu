import { protectCell, checkpoint, obligations } from "../pubsub-observation/safety.mjs";
import { normalizeOutcome } from "../pubsub-production/outcome.mjs";
import { isDeepStrictEqual } from "node:util";
import { kindOf } from "../pubsub-observation/ledger.mjs";
import { createIamOwnership, readPolicy, waitAfterLastGrant } from "../pubsub-production/iam.mjs";
import { PROJECT, makePlan, minimumCallMs } from "./plan.mjs";
const settled = (ledger, name) =>
  (ledger.state().get(name)?.requests ?? []).every((r) =>
    ["rejected", "gone", "gone-a2"].includes(r.resolution),
  );
const methodFor = (name, action) =>
  `${action}${name.includes("/topics/") ? "Topic" : "Subscription"}`;
const serviceFor = (method) => (/Topic|Publish/.test(method) ? "Publisher" : "Subscriber");
export function graph(cell, runId) {
  if (!/^[a-f0-9]{12}$/.test(runId) || !makePlan().cells.some((c) => isDeepStrictEqual(c, cell)))
    throw new Error("declared graph required");
  const prefix = `projects/${PROJECT}`,
    suffix = `fe${runId}-${cell.id.toLowerCase()}`;
  const topic = `${prefix}/topics/${suffix}-t`,
    deadTopic = `${prefix}/topics/${suffix}-d`,
    subscription = `${prefix}/subscriptions/${suffix}-s`,
    sink = `${prefix}/subscriptions/${suffix}-k`;
  const resources = [
    { name: topic, method: "CreateTopic", request: { name: topic } },
    { name: deadTopic, method: "CreateTopic", request: { name: deadTopic } },
    {
      name: sink,
      method: "CreateSubscription",
      request: {
        name: sink,
        topic: deadTopic,
        ackDeadlineSeconds: 10,
        messageRetentionDuration: "3600s",
      },
    },
    {
      name: subscription,
      method: "CreateSubscription",
      request: {
        name: subscription,
        topic,
        ackDeadlineSeconds: 10,
        messageRetentionDuration: "3600s",
        deadLetterPolicy: { deadLetterTopic: deadTopic, maxDeliveryAttempts: 5 },
      },
    },
  ];
  return { resources, topic, deadTopic, subscription, sink };
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
    items.length > 1
  )
    throw new Error("unreadable delivery envelope");
  for (const item of items) {
    const value = published.get(item?.message?.messageId);
    if (
      !value ||
      typeof item.ackId !== "string" ||
      !item.ackId ||
      item.ackId.length > 4096 ||
      item.message.data !== value.data ||
      !isDeepStrictEqual(item.message.attributes ?? {}, value.attributes ?? {})
    )
      throw new Error("foreign or unbound delivery refused");
  }
  return items;
}
export function parseForwarded(body, expected, source) {
  const items = body?.receivedMessages ?? [];
  if (
    !body ||
    typeof body !== "object" ||
    Array.isArray(body) ||
    !Array.isArray(items) ||
    items.length > 1
  )
    throw new Error("unreadable forwarding envelope");
  for (const item of items) {
    const m = item?.message,
      a = m?.attributes;
    if (
      typeof item.ackId !== "string" ||
      !item.ackId ||
      item.ackId.length > 4096 ||
      typeof m?.messageId !== "string" ||
      !m.messageId ||
      m.data !== expected.data ||
      !a ||
      a.CloudPubSubDeadLetterSourceSubscription !== source.split("/").at(-1) ||
      a.CloudPubSubDeadLetterSourceSubscriptionProject !== PROJECT ||
      !/^\d+$/.test(a.CloudPubSubDeadLetterSourceDeliveryCount ?? "") ||
      typeof a.CloudPubSubDeadLetterSourceTopicPublishTime !== "string" ||
      !Number.isFinite(Date.parse(a.CloudPubSubDeadLetterSourceTopicPublishTime)) ||
      Object.entries(expected.attributes).some(([k, v]) => a[k] !== v)
    )
      throw new Error("foreign forwarding identity refused");
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
  iamJournal = journal,
  serviceAgent,
  createIamManager = createIamOwnership,
  sleep = (ms) => new Promise((r) => setTimeout(r, ms)),
}) {
  const g = graph(cell, runId),
    allowed = new Set(g.resources.map((r) => r.name)),
    tracked = new Set(),
    absentSeen = new Set(),
    observations = [];
  let complete = false,
    reason = null,
    budgetOverrun = false,
    manager = null,
    iam = { restored: [], unsettled: [] };
  const observe = (stage, value = {}) => {
    const row = {
      event: "dlq-observation",
      cellId: cell.id,
      stage,
      clockMs: meter.clock(),
      ...value,
    };
    observations.push(row);
    journal.write(row);
  };
  const send = async (category, method, request, transport = cell.transport) => {
    const maintenance = category.startsWith("cleanup"),
      name = request.name ?? request.topic ?? request.subscription ?? request.resource;
    if (
      !allowed.has(name) ||
      ["topic", "subscription"].some((k) => request[k] !== undefined && !allowed.has(request[k]))
    )
      throw new Error("foreign resource refused");
    if (meter.remaining(maintenance) < minimumCallMs(method))
      throw new Error("recorded latency margin unavailable");
    const action = method.startsWith("Create")
      ? "create"
      : method.startsWith("Delete")
        ? "delete"
        : null;
    if (action === "delete" && (ledger.deleting(name) || ledger.unconfirmed(name)))
      throw new Error("unknown delete cannot retry");
    if (action) {
      tracked.add(name);
      checkpoint(journal, ledger, tracked, cell.id, [{ name, action, transport: transport }]);
    }
    const intent = action
      ? { name, action, transport, requestId: ledger.sent({ name, action, transport }) }
      : null;
    if (intent) tracked.add(name);
    let reply;
    try {
      reply = await wire.call({
        category,
        method,
        request,
        transport,
        service: serviceFor(method),
        cellId: cell.id,
      });
    } catch (error) {
      if (intent) ledger.answered({ ...intent, kind: "unknown" });
      throw error;
    }
    reply = normalizeOutcome(reply);
    let kind = kindOf(reply);
    if (
      (action === "create" || (method.startsWith("Get") && !method.includes("Iam"))) &&
      kind === "ok" &&
      (reply.body?.name !== name || "done" in reply.body)
    )
      kind = "unknown";
    if (intent) ledger.answered({ ...intent, kind });
    if (method.startsWith("Get") && !method.includes("Iam")) {
      ledger.observeRead(name, reply);
      if (kind === "error" && reply.code === "NOT_FOUND" && !settled(ledger, name))
        absentSeen.add(name);
    }
    if (method.includes("Iam"))
      journal.write({
        event: "iam-evidence",
        cellId: cell.id,
        category,
        assessment: { status: "needs-review", evidence: [] },
        response: reply,
      });
    if (kind === "unknown" || kind === "pending") throw new Error("unknown answer stops the cell");
    if (reply.budgetOverrun) budgetOverrun = true;
    meter.remaining(maintenance);
    return reply;
  };
  const wait = async (ms) => {
    if (ms >= meter.remaining()) throw new Error("wait exceeds phase");
    await sleep(ms);
    meter.remaining();
  };
  const iamAllowed = new Set([g.subscription, g.deadTopic]);
  const assertIam = (name) => {
    if (!iamAllowed.has(name) || !tracked.has(name) || ledger.unconfirmed(name))
      throw new Error("IAM requires own confirmed resource");
  };
  const iamClient = (phase) => {
    const gets = new Map();
    return {
      async getIamPolicy(resource) {
        assertIam(resource);
        const count = gets.get(resource) ?? 0;
        gets.set(resource, count + 1);
        const category =
          phase === "grant"
            ? count === 0
              ? "baselineIamGet"
              : "iamSetupReadback"
            : count === 0
              ? "cleanupIamConflictGet"
              : "cleanupIamRestoreReadback";
        return send(category, "GetIamPolicy", { resource, requestedPolicyVersion: 3 }, "rest");
      },
      async setIamPolicy(resource, policy) {
        assertIam(resource);
        return send(
          phase === "grant" ? "iamSetupWrite" : "cleanupIamRestoreWrite",
          "SetIamPolicy",
          { resource, policy },
          "rest",
        );
      },
    };
  };
  let cleanupClosed = true;
  const failures = await protectCell({
    body: async () => {
      for (const resource of g.resources) {
        if (!(await send("create", resource.method, resource.request)).ok)
          throw new Error("required setup refused");
        if (
          !(await send("resourceGet", methodFor(resource.name, "Get"), { name: resource.name })).ok
        )
          throw new Error("setup read missing");
      }
      if (cell.arm === "managed-grant-readback-wait") {
        if (
          !/^serviceAccount:service-\d{1,20}@gcp-sa-pubsub\.iam\.gserviceaccount\.com$/.test(
            serviceAgent ?? "",
          )
        )
          throw new Error("scoped service agent required");
        manager = createIamManager({
          journal: {
            write: (row) => {
              checkpoint(
                journal,
                ledger,
                tracked,
                cell.id,
                [],
                [{ resource: row.resource, role: row.role, member: row.member, state: row.phase }],
              );
              iamJournal.write({ cellId: cell.id, ...row });
            },
          },
          assertOwned: assertIam,
          now: meter.clock,
        });
        const client = iamClient("grant");
        await manager.grant(client, g.subscription, "roles/pubsub.subscriber", serviceAgent);
        const last = await manager.grant(
          client,
          g.deadTopic,
          "roles/pubsub.publisher",
          serviceAgent,
        );
        observe("iam-window", {
          waitAfterLastGrantMs: 900000,
          grantedAt: last.grantedAt,
          phaseMs: cell.cellMs,
          iamConvergenceClaim: false,
          requestsDuringWait: 0,
        });
        await waitAfterLastGrant({ grantedAt: last.grantedAt, now: meter.clock, sleep: wait });
      } else {
        for (const resource of iamAllowed) {
          const r = await send(
            "baselineIamGet",
            "GetIamPolicy",
            { resource, requestedPolicyVersion: 3 },
            "rest",
          );
          if (!r.ok || r.status !== 200) throw new Error("unreadable baseline IAM");
          readPolicy(r.body);
        }
        observe("baseline-permission", {
          status: "UNAUDITED",
          newGrant: false,
          effectivePermissionClaim: false,
        });
      }
      const expected = {
          data: Buffer.from(`dlq-${runId}-${cell.id}`).toString("base64"),
          attributes: { recorderRun: runId, recorderCell: cell.id },
        },
        published = new Map();
      const publication = await send("publish", "Publish", {
        topic: g.topic,
        messages: [expected],
      });
      if (
        !publication.ok ||
        !Array.isArray(publication.body?.messageIds) ||
        publication.body.messageIds.length !== 1 ||
        typeof publication.body.messageIds[0] !== "string" ||
        !publication.body.messageIds[0]
      )
        throw new Error("publication is not bound");
      published.set(publication.body.messageIds[0], expected);
      observe("publication-binding", {
        messageIds: publication.body.messageIds,
        messages: [expected],
      });
      const windowStart = meter.clock(),
        end = Math.min(windowStart + 900000, windowStart + meter.remaining());
      let sourceAttempts = 0,
        sinkAttempts = 0,
        forwarded = false;
      const enough = () => meter.clock() + minimumCallMs("Pull") < end;
      const pullSource = async (nack) => {
        const r = await send("sourcePull", "Pull", {
          subscription: g.subscription,
          maxMessages: 1,
          returnImmediately: false,
        });
        sourceAttempts++;
        if (!r.ok) throw new Error("source pull refused");
        const items = parseDelivery(r.body, published);
        observe("source-delivery", {
          attempt: sourceAttempts,
          items,
          selectorVerdict: "NOT_COMPARABLE",
        });
        if (nack)
          for (const item of items) {
            if (
              !(
                await send("nack", "ModifyAckDeadline", {
                  subscription: g.subscription,
                  ackIds: [item.ackId],
                  ackDeadlineSeconds: 0,
                })
              ).ok
            )
              throw new Error("source nack refused");
          }
      };
      const pullSink = async () => {
        if (sinkAttempts >= 60 || !enough()) return;
        const r = await send("sinkPull", "Pull", {
          subscription: g.sink,
          maxMessages: 1,
          returnImmediately: true,
        });
        sinkAttempts++;
        if (!r.ok) throw new Error("sink pull refused");
        const items = parseForwarded(r.body, expected, g.subscription);
        observe("sink-delivery", {
          attempt: sinkAttempts,
          items,
          deliveryWitness: items.length > 0,
        });
        if (items.length && !forwarded) {
          if (
            !(
              await send("ownAck", "Acknowledge", {
                subscription: g.sink,
                ackIds: items.map((i) => i.ackId),
              })
            ).ok
          )
            throw new Error("sink ack refused");
          forwarded = true;
        }
      };
      if (cell.mode === "720-second-source-inactivity") {
        for (let i = 0; i < 9 && enough(); i++) {
          await pullSource(true);
          await pullSink();
          if (i < 8 && enough()) await wait(1000);
        }
        const paused = meter.clock();
        const resumeAt = paused + 720000;
        observe("inactivity-start", { sourceAttempts, resumeAt });
        while (meter.clock() < resumeAt && enough()) {
          if (meter.clock() + minimumCallMs("Pull") + minimumCallMs("Pull") >= end) break;
          await pullSink();
          const left = Math.min(
            30000,
            resumeAt - meter.clock(),
            end - meter.clock() - minimumCallMs("Pull"),
          );
          if (left > 0) await wait(left);
          else break;
        }
        if (sourceAttempts !== 9 || meter.clock() < resumeAt || !enough()) {
          observe("inactivity-not-completed", {
            elapsedMs: meter.clock() - paused,
            requiredMs: 720000,
          });
          throw new Error("source inactivity window clipped by phase");
        }
        observe("inactivity-completed", {
          elapsedMs: meter.clock() - paused,
          noSourcePullDuringWindow: true,
          resetInferred: false,
        });
      }
      while (sourceAttempts < 60 && enough()) {
        await pullSource(cell.mode !== "passive-deadline");
        await pullSink();
        const delay = cell.mode === "passive-deadline" ? 11000 : 1000;
        if (meter.clock() + delay + minimumCallMs("Pull") >= end) break;
        await wait(delay);
      }
      observe("bounded-window-end", {
        sourceAttempts,
        sinkAttempts,
        forwarded,
        observedWindowMs: meter.clock() - windowStart,
        emptyWindowVerdict: forwarded ? "WITNESS_RECORDED" : "NOT_COMPARABLE",
        iamConvergenceClaim: false,
      });
      complete = true;
    },
    report: (error) => {
      reason = error.message;
      observe("case-incomplete", { reason, verdict: "NOT_COMPARABLE" });
    },
    finalize: async () => {
      for (const name of ledger.state().keys()) if (allowed.has(name)) tracked.add(name);
      if (manager) {
        try {
          iam = await manager.restore(iamClient("restore"));
        } catch {
          iam = { restored: [], unsettled: [{ state: "restoration-unestablished" }] };
        }
        iam.unsettled = [...iam.unsettled, ...manager.outstanding()];
        if (iam.unsettled.length) {
          complete = false;
          reason = "IAM restoration unresolved; retain lock and stop later cells";
        }
      }
      cleanupClosed = iam.unsettled.length === 0;
      if (cleanupClosed)
        for (const name of [...tracked].sort(
          (a, b) => Number(b.includes("/subscriptions/")) - Number(a.includes("/subscriptions/")),
        )) {
          if (settled(ledger, name)) continue;
          try {
            if (ledger.unconfirmed(name)) {
              const r = await send("cleanupGet", methodFor(name, "Get"), { name });
              ledger.observeRead(name, r);
              if (ledger.unconfirmed(name)) {
                cleanupClosed = false;
                continue;
              }
            }
            if (!ledger.deleting(name) && !absentSeen.has(name))
              await send("cleanupDelete", methodFor(name, "Delete"), { name });
            if (
              !ledger.settleAbsent(name, await send("cleanupGet", methodFor(name, "Get"), { name }))
            )
              cleanupClosed = false;
          } catch {
            cleanupClosed = false;
          }
          if (!settled(ledger, name)) cleanupClosed = false;
        }
    },
    persist: () =>
      checkpoint(
        journal,
        ledger,
        tracked,
        cell.id,
        [],
        iam.unsettled.map(({ resource, role, member, state }) => ({
          resource,
          role,
          member,
          state,
        })),
      ),
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
    iam,
    parityEstablished: false,
    outstanding: ledger.outstanding().filter((r) => tracked.has(r.name)),
    budgetOverrun,
  };
  journal.write({ event: "case-result", ...result });
  try {
    meter.remaining(true);
  } catch {
    result.complete = false;
    result.budgetOverrun = true;
  }
  return result;
}

export async function recoverA2({ wire, ledger, runId, elapsedMs, meter, iamReplay = [] }) {
  if (!Number.isFinite(elapsedMs) || elapsedMs < 600000) throw new Error("A2 minimum age required");
  const replay = createIamOwnership({
    replay: iamReplay,
    journal: {
      write() {
        throw new Error("read-only A2 cannot write IAM");
      },
    },
    assertOwned: (name) => {
      if (!owned(name, runId)) throw new Error("foreign recovery IAM");
    },
  });
  const originalIds = new Set(
    [...ledger.state().values()].flatMap((i) => i.requests.map((r) => r.id)),
  );
  let resourceReads = 0,
    unknownDeleteReads = 0,
    iamReads = 0;
  const iamObservations = [];
  for (const entry of replay.outstanding()) {
    if (iamReads >= 2) break;
    const reply = await wire.call({
      category: "iamRead",
      transport: "rest",
      service: "Publisher",
      method: "GetIamPolicy",
      request: { resource: entry.resource, requestedPolicyVersion: 3 },
      cellId: "A2",
    });
    iamReads++;
    iamObservations.push({
      resource: entry.resource,
      reply,
      assessment: "needs-review",
      settles: false,
    });
    meter?.remaining(true);
  }
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
      service: serviceFor(methodFor(name, "Get")),
      method: methodFor(name, "Get"),
      request: { name },
      cellId: "A2",
    });
    ledger.observeRead(name, reply);
    ledger.settleAbsent(name, reply, { a2ElapsedMs: elapsedMs, a2EligibleRequestIds: originalIds });
    meter?.remaining(true);
  }
  return {
    closed:
      replay.outstanding().length === 0 &&
      [...ledger.state().keys()].every((name) => settled(ledger, name)),
    reads: resourceReads + unknownDeleteReads + iamReads,
    resourceReads,
    unknownDeleteReads,
    iamReads,
    iamObservations,
    iamUnsettled: replay.outstanding(),
    outstanding: ledger.outstanding(),
  };
}
