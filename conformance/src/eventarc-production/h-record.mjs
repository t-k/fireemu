import { createHash } from "node:crypto";
import { createClient } from "./client.mjs";
import { createOwnership } from "./names.mjs";
import { createRawRest } from "./rest.mjs";
import { createSdk } from "./sdk.mjs";
import { hManifest, hPublishes, H_LIMITS } from "./h-script.mjs";
import { hCapture, judgeH } from "./h-capture.mjs";
import { hUnknown, hDisposition, hCliFailed, hReadList, hReady } from "./h-deploy.mjs";

/** Reuse stage C byte capture, but all H 5xx answers are unknown, including 501. */
export function createHRest(options) {
  const capture = {
    ...options.capture,
    record: (entry) => {
      if (entry.response?.status >= 500) {
        entry.response.unknown = true;
        entry.unknown = true;
      }
      return options.capture.record(entry);
    },
  };
  const rest = createRawRest({ ...options, capture });
  return {
    ...rest,
    request: async (spec) => {
      const reply = await rest.request(spec);
      return { ...reply, unknown: hUnknown(reply) };
    },
  };
}

const APIS = [
  "artifactregistry.googleapis.com",
  "cloudbuild.googleapis.com",
  "cloudfunctions.googleapis.com",
  "cloudresourcemanager.googleapis.com",
  "eventarc.googleapis.com",
  "eventarcpublishing.googleapis.com",
  "firestore.googleapis.com",
  "logging.googleapis.com",
  "pubsub.googleapis.com",
  "run.googleapis.com",
  "storage.googleapis.com",
];

/**
 * Fixed H orchestration, using stage C transports and SDK forwarding and FE CLI/source preparation.
 * The coordinator supplies the frozen same-route evidence judges, including native byte layout;
 * missing evidence stops before any write. CLI evidence is per-resource, never exit-code settlement.
 */
export async function recordH({
  manifest: input,
  transports,
  cli,
  sleep,
  now,
  note,
  saveFrame,
  evidence,
  getToken,
  shouldStop = () => false,
  makeSdk = createSdk,
}) {
  const m = hManifest(input);
  const counts = Object.fromEntries(Object.keys(H_LIMITS).map((k) => [k, 0]));
  const result = {
    runId: m.runId,
    manifest: m,
    stopped: null,
    counts,
    publishes: [],
    writes: [],
    identities: [],
    cleanup: { unconfirmed: [], unsettled: [], retained: [] },
    closureReady: false,
  };
  const required = [
    "preflight",
    "readiness",
    "operation",
    "notFound",
    "cliWrites",
    "retention",
    "logging",
  ];
  if (!evidence || required.some((key) => typeof evidence[key] !== "function"))
    return { ...result, stopped: "needs-review: frozen production shape evidence is required" };
  const meter = (phase) => {
    if (++counts[phase] > H_LIMITS[phase]) throw new Error(`H ${phase} ceiling`);
  };
  const request = async (host, spec, phase, judge) => {
    meter(phase);
    const reply = await transports[host].request({ ...spec, label: { case: `h-${phase}` } });
    if (hUnknown(reply) || !judge(reply, { ...spec, host }))
      throw new Error(`needs-review: H ${phase} answer`);
    return reply;
  };
  const get = (host, path, phase, judge) =>
    request(host, { method: "GET", path, op: "h.read" }, phase, judge);
  const parent = `projects/${m.project}/locations/us-central1`;
  let baseline;
  let capture;
  let sdk;
  const attempted = [];
  let publishNumber = 0;
  let lastPollAt = 0;
  const origins = [];
  const ownership = createOwnership(m);
  ownership.allowPublish(m.channel);
  const client = createClient({
    transports,
    ownership,
    caseId: "h-publish",
    usageProject: m.project,
  });
  const settle = async (write, phase) => {
    if (!write.operation || !["pending", "unknown"].includes(write.state)) return;
    for (let poll = 0; poll < 10; poll++) {
      const reply = await get(
        write.host,
        `/${write.host === "eventarc" ? "v1" : "v2"}/${write.operation}`,
        phase,
        evidence.operation,
      );
      if (reply.body.metadata?.target !== write.name)
        throw new Error("H operation target mismatch");
      if (reply.body.done === true) {
        write.state = reply.body.error ? "failed" : "confirmed";
        note("h-operation", { ...write });
        return;
      }
      await sleep(2000);
    }
  };
  const lists = async (names) => {
    const read = async (host, version, collection) => {
      const transport = {
        request: async (spec) => {
          const reply = await transports[host].request(spec);
          if (!evidence.readiness(reply, { ...spec, host }))
            throw new Error("needs-review: H list shape");
          return reply;
        },
      };
      return hReadList(
        transport,
        { path: `/${version}/${parent}/${collection}`, key: collection, phase: "readiness" },
        () => meter("readiness"),
      );
    };
    const functions = await read("functions", "v2", "functions");
    const services = await read("run", "v2", "services");
    const triggers = await read("eventarc", "v1", "triggers");
    const channel = await get("eventarc", `/v1/${m.channel}`, "readiness", evidence.readiness);
    return hReady({ manifest: m, functions, services, triggers, channel: channel.body, names });
  };
  const pause = async (ms) => {
    const end = now() + ms;
    while (now() < end) {
      if (shouldStop()) throw new Error("H signal");
      await sleep(Math.min(60_000, end - now()));
      if (capture && now() - lastPollAt >= 120_000) {
        await capture.poll();
        lastPollAt = now();
      }
    }
  };
  try {
    // No implicit API enabling, Firestore creation, Auth or Rules setup.
    for (const api of APIS) {
      const reply = await get(
        "usage",
        `/v1/projects/${m.project}/services/${api}`,
        "preflight",
        evidence.preflight,
      );
      if (reply.body.state !== "ENABLED" || reply.body.config?.name !== api)
        throw new Error(`H prerequisite disabled: ${api}`);
    }
    const database = await get(
      "firestore",
      `/v1/projects/${m.project}/databases/(default)`,
      "preflight",
      evidence.preflight,
    );
    if (database.body.type !== "FIRESTORE_NATIVE" || database.body.locationId !== "us-central1")
      throw new Error("H undeclared Firestore placement");
    baseline = await get(
      "eventarc",
      `/v1/${m.channel}`,
      "preflight",
      (r, spec) => evidence.preflight(r, spec) || evidence.notFound(r, spec),
    );
    if (
      baseline.status !== 404 &&
      (baseline.status !== 200 ||
        baseline.body.name !== m.channel ||
        baseline.body.state !== "ACTIVE")
    )
      throw new Error("H ambiguous firebase baseline");
    if (baseline.status === 200 && evidence.preexistingChannelPermission !== true)
      throw new Error("H preexisting firebase channel needs explicit permission");
    const baselineTriggers = await hReadList(
      {
        request: async (spec) => {
          const reply = await transports.eventarc.request(spec);
          if (!evidence.preflight(reply, { ...spec, host: "eventarc" }))
            throw new Error("needs-review: H baseline trigger shape");
          return reply;
        },
      },
      { path: `/v1/${parent}/triggers`, key: "triggers", phase: "preflight" },
      () => meter("preflight"),
    );
    result.baseline = baseline;
    note("h-baseline", {
      channel: baseline.body,
      triggers: baselineTriggers,
      database: database.body,
    });
    for (const name of [m.observe, m.filtered]) {
      const reply = await get(
        "functions",
        `/v2/${parent}/functions/${name}`,
        "preflight",
        evidence.notFound,
      );
      if (reply.status !== 404) throw new Error("H export already exists");
    }
    const retrySubject = hPublishes(m).find((p) => p.retry).body.events[0];
    const markerId = createHash("sha256")
      .update(JSON.stringify([retrySubject.source, retrySubject.id]))
      .digest("hex");
    result.marker = `projects/${m.project}/databases/(default)/documents/${m.markerCollection}/${markerId}`;
    await get("firestore", `/v1/${result.marker}`, "preflight", evidence.notFound);
    // Reserve each possibly created function before launching its official CLI request.
    for (const name of [m.observe, m.filtered]) {
      if (shouldStop()) throw new Error("H signal");
      attempted.push(name);
      const write = {
        kind: "function",
        action: "create",
        name: `${parent}/functions/${name}`,
        host: "functions",
        state: "unknown",
      };
      result.writes.push(write);
      note("h-write-issued", write);
      const deployed = await cli(name);
      let writes;
      try {
        writes = evidence.cliWrites(deployed, m);
      } catch {
        result.cleanup.unconfirmed.push(`cli:${name}:unreadable-writes`);
        throw new Error("needs-review: H CLI output");
      }
      // The native CLI requests/operations account for every build/upload/IAM/managed write.
      result.writes.push(...(writes?.resources ?? []));
      if (!writes || !writes.complete) {
        result.cleanup.unconfirmed.push(`cli:${name}:write-inventory`);
        throw new Error("needs-review: H CLI write inventory");
      }
      Object.assign(write, writes.function);
      note("h-cli-answer", { name, exitCode: deployed.exitCode, timedOut: deployed.timedOut });
      if (hCliFailed(deployed)) throw new Error("H deploy failed; no redeploy");
      await settle(write, "readiness");
      let readiness;
      for (let poll = 0; poll < 40; poll++) {
        readiness = await lists(attempted);
        if (readiness.ready) break;
        await sleep(30_000);
      }
      if (!readiness?.ready) throw new Error("H readiness incomplete");
      result.identities = readiness.identities;
      for (const identity of readiness.identities) {
        const own = result.writes.find(
          (w) => w.name === identity.function && w.action === "create",
        );
        // Complete positive readbacks, not the CLI summary, confirm creation.
        if (own) own.state = "confirmed";
      }
    }
    for (const identity of result.identities)
      origins.push({
        handler: identity.handler,
        service: identity.service.split("/").at(-1),
        location: m.location,
      });
    capture = hCapture({
      manifest: m,
      origins,
      now,
      startedAt: now(),
      saveFrame,
      transport: {
        request: async (spec) => {
          const reply = await transports.logging.request(spec);
          if (!evidence.logging(reply, { ...spec, host: "logging" }))
            throw new Error("needs-review: H Logging shape");
          return reply;
        },
      },
    });
    await capture.poll();
    lastPollAt = now();
    await pause(m.propagationMs);
    const meteredPublishing = {
      ...transports.publishing,
      request: async (spec) => {
        meter("publish");
        const events = spec.body?.events;
        if (events)
          note("h-sdk-emitted", { sequence: publishNumber, path: spec.path, body: spec.body });
        const reply = await transports.publishing.request(spec);
        if (result.publishes.at(-1)?.sdk) {
          Object.assign(result.publishes.at(-1), {
            body: spec.body,
            known: !hUnknown(reply),
            status: reply.status,
            candidates: (events ?? []).map((e) => ({ id: e.id, source: e.source, type: e.type })),
          });
        }
        return reply;
      },
    };
    sdk = await makeSdk({
      project: m.project,
      runId: m.runId,
      caseId: "h-publish",
      getToken,
      transport: meteredPublishing,
      ownership,
      publishPrefix: "/v1",
      note,
    });
    const plan = hPublishes(m);
    for (const p of plan) {
      if (shouldStop()) throw new Error("H signal");
      publishNumber = p.sequence;
      if (p.retry) {
        const write = {
          name: result.marker,
          host: "firestore",
          kind: "marker",
          action: "create",
          state: "unknown",
        };
        result.writes.push(write);
        note("h-write-issued", write);
      }
      const observation = {
        ...p,
        sentAt: now(),
        known: false,
        candidates: (p.body?.events ?? []).map((e) => ({
          id: e.id,
          source: e.source,
          type: e.type,
        })),
        ...(p.retry ? { retryHandler: m.observe } : {}),
      };
      result.publishes.push(observation);
      if (p.sdk) {
        observation.sdkResult = await sdk.publish(p);
      } else {
        meter("publish");
        const reply = await client.publishEvents(m.channel, p.body);
        Object.assign(observation, { status: reply.status, known: !hUnknown(reply) });
      }
      if (!p.refused && !p.negativeHandlers?.length) {
        observation.expectedRecipients = (observation.body?.events ?? []).flatMap((e) => {
          const handlers =
            e.type === m.type
              ? [
                  m.observe,
                  ...(e.source === m.source && e.attributes?.tenant?.ceString === m.tenant
                    ? [m.filtered]
                    : []),
                ]
              : [];
          return handlers.map((handler) => ({ handler, id: e.id, source: e.source }));
        });
      }
      note("h-publish-answer", observation);
      if (!observation.known) throw new Error("H unknown publish; never replay");
      if (p.control && !(observation.status >= 200 && observation.status < 300))
        throw new Error("H control refused");
      await pause(p.windowMs ?? (p.control ? 120_000 : 0));
      observation.endedAt = now();
      const both = [m.observe, m.filtered];
      const receivedBoth = (o) =>
        both.every((handler) =>
          o.candidates.some((e) =>
            capture
              .result()
              .frames.some(
                (f) =>
                  f.frame.handler === handler &&
                  f.frame.event.id === e.id &&
                  f.frame.event.source === e.source,
              ),
          ),
        );
      if (p.control && !receivedBoth(observation)) throw new Error("H control missing");
      if (p.windowMs)
        observation.before =
          result.publishes.at(-2)?.control === true && receivedBoth(result.publishes.at(-2));
      const previous = result.publishes.at(-2);
      if (p.control && previous?.windowMs) previous.after = receivedBoth(observation);
    }
    await pause(120_000);
    await capture.finish();
    result.capture = capture.result();
    result.evidence = judgeH({
      manifest: m,
      observations: result.publishes,
      capture: result.capture,
    });
  } catch (error) {
    result.stopped = error.message;
    if (capture) {
      try {
        await capture.finish();
      } catch {}
      result.capture = capture.result();
    }
  }
  {
    try {
      await sdk?.close();
    } catch {
      result.cleanup.unsettled.push("sdk-forwarder");
    }
    // Partial deployments are inventoried too. Never issue a second unknown DELETE.
    for (const name of attempted.toReversed()) {
      const full = `${parent}/functions/${name}`;
      const creation = result.writes.find((w) => w.name === full && w.action === "create");
      try {
        const current = await get(
          "functions",
          `/v2/${full}`,
          "cleanup",
          (r, spec) => evidence.readiness(r, spec) || evidence.notFound(r, spec),
        );
        const read =
          current.status === 200 && current.body.name === full
            ? "present"
            : current.status === 404
              ? "absent"
              : "unknown";
        const disposition = hDisposition({ create: creation.state, read });
        if (disposition.confirmed) creation.state = "confirmed";
        if (!disposition.canDelete) {
          if (!disposition.closed)
            result.cleanup[disposition.unconfirmed ? "unconfirmed" : "unsettled"].push(full);
          continue;
        }
        const deletion = {
          name: full,
          host: "functions",
          kind: "function",
          action: "delete",
          state: "unknown",
        };
        result.writes.push(deletion);
        note("h-write-issued", deletion);
        meter("cleanup");
        const reply = await transports.functions.request({
          method: "DELETE",
          path: `/v2/${full}`,
          op: "h.function.delete",
          label: { case: "h-cleanup" },
        });
        if (
          !hUnknown(reply) &&
          evidence.operation(reply, { host: "functions", method: "DELETE", path: `/v2/${full}` }) &&
          reply.status >= 200 &&
          reply.status < 300 &&
          reply.body.metadata?.target === full
        ) {
          deletion.operation = reply.body.name;
          deletion.state =
            reply.body.done === true ? (reply.body.error ? "failed" : "confirmed") : "pending";
          await settle(deletion, "cleanup");
        }
        const absent = await get("functions", `/v2/${full}`, "cleanup", evidence.notFound);
        if (
          !hDisposition({
            create: creation.state,
            deletion: deletion.state,
            read: absent.status === 404 ? "absent" : "unknown",
          }).closed
        )
          result.cleanup.unsettled.push(full);
        if (deletion.state === "confirmed")
          for (const identity of result.identities.filter((i) => i.function === full)) {
            for (const [host, version, resource] of [
              ["run", "v2", identity.service],
              ["eventarc", "v1", identity.trigger],
              ["pubsub", "v1", identity.topic],
              ["pubsub", "v1", identity.subscription],
            ]) {
              const reply = await get(
                host,
                `/${version}/${resource}`,
                "cleanup",
                evidence.notFound,
              );
              if (reply.status !== 404) result.cleanup.unsettled.push(resource);
            }
          }
      } catch {
        result.cleanup.unsettled.push(full);
      }
    }
    // Stop retry execution before the exact marker can be removed.
    if (
      result.marker &&
      result.cleanup.unsettled.length === 0 &&
      result.cleanup.unconfirmed.length === 0 &&
      attempted.length === 2
    ) {
      try {
        const marker = await get(
          "firestore",
          `/v1/${result.marker}`,
          "cleanup",
          (r, spec) => evidence.readiness(r, spec) || evidence.notFound(r, spec),
        );
        if (marker.status === 200) {
          const creation = result.writes.find(
            (w) => w.name === result.marker && w.action === "create",
          );
          if (creation) creation.state = "confirmed";
          const write = {
            action: "delete",
            kind: "marker",
            host: "firestore",
            name: result.marker,
            state: "unknown",
          };
          result.writes.push(write);
          note("h-write-issued", write);
          const reply = await request(
            "firestore",
            { method: "DELETE", path: `/v1/${result.marker}`, op: "h.marker.delete" },
            "cleanup",
            evidence.readiness,
          );
          write.state = reply.status >= 200 && reply.status < 300 ? "confirmed" : "unknown";
          await get("firestore", `/v1/${result.marker}`, "cleanup", evidence.notFound);
        } else if (result.publishes.some((p) => p.retry))
          result.cleanup.unconfirmed.push(result.marker);
      } catch {
        result.cleanup.unsettled.push(result.marker);
      }
    }
    // Shared/default channel and retained build/upload/AR/IAM/API resources require baseline-aware evidence.
    if (baseline?.status === 404 && attempted.length) {
      const creation = result.writes.find((w) => w.name === m.channel && w.action === "create");
      try {
        if (!creation) throw new Error("H default channel has no own CREATE evidence");
        const current = await get(
          "eventarc",
          `/v1/${m.channel}`,
          "cleanup",
          (r, spec) => evidence.readiness(r, spec) || evidence.notFound(r, spec),
        );
        const read =
          current.status === 200 && current.body.name === m.channel
            ? "present"
            : current.status === 404
              ? "absent"
              : "unknown";
        const facts = hDisposition({ create: creation.state, read });
        if (facts.confirmed) creation.state = "confirmed";
        if (!facts.canDelete) throw new Error("H default channel creation remains unsettled");
        const remaining = await hReadList(
          {
            request: async (spec) => {
              const answer = await transports.eventarc.request(spec);
              if (!evidence.readiness(answer, { ...spec, host: "eventarc" }))
                throw new Error("H trigger cleanup shape");
              return answer;
            },
          },
          { path: `/v1/${parent}/triggers`, key: "triggers", phase: "cleanup" },
          () => meter("cleanup"),
        );
        if (
          remaining.some((t) => t.channel === m.channel) ||
          result.cleanup.unconfirmed.length ||
          result.cleanup.unsettled.length
        )
          throw new Error("H channel still has possible dependents");
        const deletion = {
          name: m.channel,
          host: "eventarc",
          kind: "channel",
          action: "delete",
          state: "unknown",
        };
        result.writes.push(deletion);
        note("h-write-issued", deletion);
        meter("cleanup");
        const answer = await transports.eventarc.request({
          method: "DELETE",
          path: `/v1/${m.channel}`,
          op: "h.channel.delete",
          label: { case: "h-cleanup" },
        });
        if (
          !hUnknown(answer) &&
          evidence.operation(answer, {
            host: "eventarc",
            method: "DELETE",
            path: `/v1/${m.channel}`,
          }) &&
          answer.status >= 200 &&
          answer.status < 300
        ) {
          deletion.operation = answer.body.name;
          deletion.state =
            answer.body.done === true ? (answer.body.error ? "failed" : "confirmed") : "pending";
          await settle(deletion, "cleanup");
        }
        const absent = await get("eventarc", `/v1/${m.channel}`, "cleanup", evidence.notFound);
        if (
          !hDisposition({
            create: creation.state,
            deletion: deletion.state,
            read: absent.status === 404 ? "absent" : "unknown",
          }).closed
        )
          result.cleanup.unsettled.push(m.channel);
      } catch {
        result.cleanup.unconfirmed.push(m.channel);
      }
    }
    if (baseline && attempted.length) {
      try {
        const retained = await evidence.retention({
          manifest: m,
          baseline,
          result,
          get: (host, path, judge) => get(host, path, "cleanup", judge),
        });
        result.cleanup.retained = retained?.resources ?? [];
        result.retentionVerified = retained?.complete === true && retained?.atBaseline === true;
        if (!retained?.complete || !retained?.atBaseline) result.cleanup.unsettled.push(m.channel);
      } catch {
        result.cleanup.unsettled.push(m.channel);
      }
    }
  }
  result.lastRequestAt = now();
  counts.capture = result.capture?.requests ?? 0;
  result.closureReady =
    result.stopped === null &&
    result.evidence?.complete === true &&
    result.cleanup.unsettled.length === 0 &&
    result.cleanup.unconfirmed.length === 0 &&
    result.writes.every((w) => w.state === "confirmed" || w.state === "failed");
  note("h-run-end", result);
  return result;
}

/** Separate coordinator A2: exact-name reads only, at least ten minutes after the latest request. */
export async function hA2({ recording, transports, evidence, now, note }) {
  if (!Number.isFinite(recording.lastRequestAt) || now() - recording.lastRequestAt < 600_000)
    throw new Error("H A2 must wait ten minutes after the latest request");
  const names = new Map();
  for (const write of recording.writes) {
    if (write.name && write.host)
      names.set(write.name, {
        host: write.host,
        version:
          write.host === "eventarc" || write.host === "firestore" || write.host === "pubsub"
            ? "v1"
            : "v2",
      });
  }
  for (const identity of recording.identities)
    for (const [host, name] of [
      ["functions", identity.function],
      ["run", identity.service],
      ["eventarc", identity.trigger],
      ["pubsub", identity.topic],
      ["pubsub", identity.subscription],
    ])
      names.set(name, { host, version: ["functions", "run"].includes(host) ? "v2" : "v1" });
  if (recording.marker) names.set(recording.marker, { host: "firestore", version: "v1" });
  const facts = [];
  let requests = 0;
  for (const [name, { host, version }] of names) {
    if (++requests > H_LIMITS.a2) throw new Error("H A2 ceiling");
    const reply = await transports[host].request({
      method: "GET",
      path: `/${version}/${name}`,
      op: "h.a2.read",
      label: { case: "h-a2" },
    });
    const read =
      !hUnknown(reply) &&
      evidence.notFound(reply, { host, method: "GET", path: `/${version}/${name}` }) &&
      reply.status === 404
        ? "absent"
        : !hUnknown(reply) &&
            evidence.readiness(reply, { host, method: "GET", path: `/${version}/${name}` }) &&
            reply.status === 200 &&
            reply.body.name === name
          ? "present"
          : "unknown";
    const creation = recording.writes.find((w) => w.name === name && w.action === "create");
    const deletion = recording.writes.find((w) => w.name === name && w.action === "delete");
    // Managed children whose function DELETE completed use that cascade's own disposition.
    const owner = recording.identities.find((i) =>
      [i.service, i.trigger, i.topic, i.subscription].includes(name),
    );
    const ownerDeletion =
      owner && recording.writes.find((w) => w.name === owner.function && w.action === "delete");
    const disposition = hDisposition({
      create: creation?.state ?? (owner ? "confirmed" : "unknown"),
      deletion: deletion?.state ?? ownerDeletion?.state,
      read,
      mode: "a2",
      ageMs: now() - recording.lastRequestAt,
    });
    facts.push({ name, read, ...disposition });
    note("h-a2-read", facts.at(-1));
  }
  const unresolvedInventory = [
    ...(recording.cleanup.unconfirmed ?? []),
    ...(recording.cleanup.unsettled ?? []),
  ].filter((name) => !facts.some((f) => f.name === name && f.closed));
  const restorationPending = recording.writes.some(
    (w) => !["create", "delete"].includes(w.action) && w.state !== "confirmed",
  );
  let retentionVerified = false;
  if (typeof evidence.retention === "function") {
    const retained = await evidence.retention({
      recording,
      manifest: recording.manifest,
      baseline: recording.baseline,
      get: async (host, path, judge) => {
        if (++requests > H_LIMITS.a2) throw new Error("H A2 ceiling");
        const reply = await transports[host].request({
          method: "GET",
          path,
          op: "h.a2.retention",
          label: { case: "h-a2" },
        });
        if (hUnknown(reply) || !judge(reply, { host, method: "GET", path }))
          throw new Error("needs-review: H A2 retention answer");
        return reply;
      },
    });
    retentionVerified = retained?.complete === true && retained?.atBaseline === true;
  }
  const cleanupReady =
    facts.every((f) => f.closed) &&
    unresolvedInventory.length === 0 &&
    !restorationPending &&
    retentionVerified;
  return {
    requests,
    lastRequestAt: now(),
    cleanupReady,
    closureReady:
      cleanupReady && recording.evidence?.complete === true && recording.stopped === null,
    unresolvedInventory,
    facts,
  };
}
