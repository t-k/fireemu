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
  return {
    ...createRawRest(options),
    request: async (spec) => {
      let response;
      const rest = createRawRest({
        ...options,
        capture: {
          ...options.capture,
          record: (entry) => {
            response = entry.response;
            if (entry.response?.status >= 500) {
              entry.response.unknown = true;
              entry.unknown = true;
            }
            return options.capture.record(entry);
          },
        },
      });
      const reply = await rest.request(spec);
      return { ...response, ...reply, unknown: hUnknown(reply) };
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
  const limits = m.limits ?? H_LIMITS;
  const counts = Object.fromEntries(Object.keys(limits).map((k) => [k, 0]));
  const result = {
    ...(m.functions ? { startedAt: now(), channelTopics: {}, segments: [] } : {}),
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
  note("h-state", result);
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
    if (
      m.functions &&
      now() + 30_000 >
        result.startedAt + m.wallMs - (["cleanup", "a2"].includes(phase) ? 0 : m.cleanupReserveMs)
    )
      throw new Error(`H2 ${phase} wall cap; cleanup reserved`);
    if (counts[phase] >= limits[phase]) throw new Error(`H ${phase} ceiling`);
    counts[phase]++;
  };
  const request = async (host, spec, phase, judge) => {
    meter(phase);
    note("h-state", result);
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
  if (m.namedChannel) ownership.allowPublish(m.namedChannel);
  const client = createClient({
    transports,
    ownership,
    caseId: "h-publish",
    usageProject: m.project,
  });
  const settle = async (write, phase) => {
    if (!write.operation || !["pending", "unknown"].includes(write.state)) return;
    const deleting = write.action === "delete";
    const pollStarted = now();
    for (let poll = 0; poll < (deleting ? 25 : 10); poll++) {
      if (m.functions && deleting) {
        if (now() > pollStarted + 120_000) return;
        await sleep(Math.max(0, pollStarted + poll * 5000 - now()));
      } else if (poll > 0) await sleep(deleting ? 5000 : 2000);
      const reply = await get(
        write.host,
        `/${write.host === "eventarc" ? "v1" : "v2"}/${write.operation}`,
        phase,
        evidence.operation,
      );
      if (reply.body.name !== write.operation || reply.body.metadata?.target !== write.name) {
        note("h-operation-mismatch", { ...write });
        throw new Error("H operation target mismatch");
      }
      if (reply.body.done === true) {
        write.state = reply.body.error ? "failed" : "confirmed";
        note("h-operation", { ...write });
        return;
      }
    }
  };
  const readList = async (phase, host, version, collection) => {
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
      {
        path: `/${version}/${host === "pubsub" ? `projects/${m.project}` : parent}/${collection}${host === "pubsub" ? "?pageSize=100" : ""}`,
        key: collection,
        phase,
      },
      () => meter(phase),
    );
  };
  const lists = async (phase) => {
    const read = (...args) => readList(phase, ...args);
    return {
      functions: await read("functions", "v2", "functions"),
      services: await read("run", "v2", "services"),
      triggers: await read("eventarc", "v1", "triggers"),
      topics: await read("pubsub", "v1", "topics"),
      subscriptions: await read("pubsub", "v1", "subscriptions"),
    };
  };
  const pause = async (ms) => {
    const end = now() + ms;
    while (now() < end) {
      if (shouldStop()) throw new Error("H signal");
      if (m.functions && end > result.startedAt + m.wallMs - m.cleanupReserveMs)
        throw new Error("H2 observation wall cap; cleanup reserved");
      await sleep(Math.min(60_000, end - now()));
      if (capture && now() - lastPollAt >= 120_000) {
        await capture.poll();
        lastPollAt = now();
      }
    }
  };
  try {
    // This envelope enables publishing once and never disables it.
    const servicesPath = `/v1/projects/${m.project}/services?filter=state:ENABLED&pageSize=200`;
    let enabled = await hReadList(
      { request: (spec) => request("usage", spec, "preflight", evidence.preflight) },
      { path: servicesPath, key: "services", phase: "preflight" },
      () => {},
    );
    note("h-enabled-services-before", enabled);
    m.projectNumber = enabled[0]?.name?.split("/")[1];
    if (
      !/^[0-9]{12}$/.test(m.projectNumber ?? "") ||
      enabled.some((s) => s.name?.split("/")[1] !== m.projectNumber)
    )
      throw new Error("H enabled-services project mismatch");
    for (const api of APIS.filter((api) => api !== "eventarcpublishing.googleapis.com"))
      if (!enabled.some((s) => s.state === "ENABLED" && s.config?.name === api))
        throw new Error(`H prerequisite disabled: ${api}`);
    if (
      !enabled.some(
        (s) => s.state === "ENABLED" && s.config?.name === "eventarcpublishing.googleapis.com",
      )
    ) {
      const write = {
        name: "eventarcpublishing.googleapis.com",
        host: "usage",
        action: "enable",
        state: "unknown",
      };
      result.writes.push(write);
      note("h-write-issued", write);
      const answer = await request(
        "usage",
        {
          method: "POST",
          path: `/v1/projects/${m.project}/services/${write.name}:enable`,
          body: {},
          op: "h.service.enable",
        },
        "preflight",
        evidence.preflight,
      );
      if (answer.status !== 200 || typeof answer.body.name !== "string")
        throw new Error("H enable unknown");
      write.operation = answer.body.name;
      for (let poll = 0; poll < 10; poll++) {
        const operation = await get(
          "usage",
          `/v1/${write.operation}`,
          "preflight",
          evidence.preflight,
        );
        if (operation.body.name !== write.operation) {
          note("h-enable-mismatch", { ...write });
          throw new Error("H enable operation mismatch");
        }
        if (operation.body.done === true) {
          if (operation.body.error) throw new Error("H enable failed");
          write.state = "confirmed";
          note("h-operation", { ...write });
          break;
        }
        await sleep(2000);
      }
      if (write.state !== "confirmed") {
        note("h-enable-pending", { ...write });
        throw new Error("H enable pending; never resend");
      }
    }
    enabled = await hReadList(
      { request: (spec) => request("usage", spec, "preflight", evidence.preflight) },
      { path: servicesPath, key: "services", phase: "preflight" },
      () => {},
    );
    note("h-enabled-services-after", enabled);
    if (!APIS.every((api) => enabled.some((s) => s.state === "ENABLED" && s.config?.name === api)))
      throw new Error("H prerequisites incomplete after enable");
    const database = await get(
      "firestore",
      `/v1/projects/${m.project}/databases/(default)`,
      "preflight",
      evidence.preflight,
    );
    if (database.body.type !== "FIRESTORE_NATIVE" || database.body.locationId !== "us-central1")
      throw new Error("H undeclared Firestore placement");
    const repository = `/v1/projects/${m.project}/locations/us-central1/repositories/gcf-artifacts`;
    const policy = await get("artifact", repository, "preflight", evidence.preflight);
    const packages = await get(
      "artifact",
      `${repository}/packages?pageSize=100`,
      "preflight",
      evidence.preflight,
    );
    if (!Object.keys(policy.body.cleanupPolicies ?? {}).length || Object.keys(packages.body).length)
      throw new Error("H Artifact Registry baseline or cleanup policy mismatch");
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
    const initial = await lists("preflight");
    result.baselineLists = initial;
    note("h-preflight-lists", initial);
    for (const name of m.functions?.map((f) => f.name) ?? [m.observe, m.filtered])
      if (initial.functions.some((f) => f.name === `${parent}/functions/${name}`))
        throw new Error("H export already exists");
    if (m.functions) {
      result.namedBaseline = await get(
        "eventarc",
        `/v1/${m.namedChannel}`,
        "preflight",
        (r, spec) => evidence.preflight(r, spec) || evidence.notFound(r, spec),
      );
      if (result.namedBaseline.status !== 404)
        throw new Error("H2 named channel already exists; never adopt");
      const write = {
        name: m.namedChannel,
        host: "eventarc",
        kind: "channel",
        action: "create",
        state: "unknown",
      };
      result.writes.push(write);
      note("h-write-issued", write);
      const spec = {
        method: "POST",
        path: `/v1/${parent}/channels?channelId=${m.namedChannelId}`,
        body: { name: m.namedChannel },
        op: "h.channel.create",
      };
      const answer = await request("eventarc", spec, "preflight", evidence.operation);
      if (
        answer.status < 200 ||
        answer.status >= 300 ||
        answer.body.metadata?.target !== write.name
      )
        throw new Error("H2 named channel CREATE unknown");
      write.operation = answer.body.name;
      write.state = answer.body.done ? (answer.body.error ? "failed" : "confirmed") : "pending";
      await settle(write, "preflight");
      if (write.state !== "confirmed") throw new Error("H2 named channel CREATE not done");
      const ready = await get("eventarc", `/v1/${m.namedChannel}`, "preflight", evidence.readiness);
      if (
        ready.status !== 200 ||
        ready.body.name !== m.namedChannel ||
        ready.body.state !== "ACTIVE" ||
        !ready.body.pubsubTopic?.startsWith(`projects/${m.project}/topics/`)
      )
        throw new Error("H2 named channel not ACTIVE or topic unknown");
      result.channelTopics[m.namedChannel] = ready.body.pubsubTopic;
    }
    const retrySubject = hPublishes(m).find((p) => p.retry).body.events[0];
    const markerId = createHash("sha256")
      .update(JSON.stringify([retrySubject.source, retrySubject.id]))
      .digest("hex");
    result.marker = `projects/${m.project}/databases/(default)/documents/${m.markerCollection}/${markerId}`;
    await get("firestore", `/v1/${result.marker}`, "preflight", evidence.notFound);
    note("h-state", result);
    segments: for (const segment of m.functions
      ? ["core", "extension", "multi", ...(m.recording === "h2-a" ? ["source"] : [])]
      : ["core"]) {
      if (m.functions) {
        if (capture) {
          counts.capture = capture.result().requests;
          result.capture = capture.result();
        }
        note("h-state", result);
        note("h-segment-gate", { segment, runId: m.runId, counts });
        if (
          segment !== "core" &&
          (typeof evidence.admitSegment !== "function" ||
            (await evidence.admitSegment({
              segment,
              result,
              settlement:
                result.segments.at(-1)?.status === "native-refusal"
                  ? result.segments.at(-1).segment
                  : null,
            })) !== true)
        )
          throw new Error(`H2 ${segment} needs coordinator admission`);
        result.segments.push({ segment, status: "started" });
      }
      // Reserve each possibly created function before launching its official CLI request.
      for (const name of m.functions?.filter((f) => f.segment === segment).map((f) => f.name) ?? [
        m.observe,
        m.filtered,
      ]) {
        if (shouldStop()) throw new Error("H signal");
        if (m.functions && now() + 21 * 60_000 > result.startedAt + m.wallMs - m.cleanupReserveMs)
          throw new Error("H2 CLI wall cap; cleanup reserved");
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
        note("h-state", result);
        const deployed = await cli(name);
        let writes;
        try {
          writes = evidence.cliWrites(deployed, m, name);
        } catch {
          result.cleanup.unconfirmed.push(`cli:${name}:unreadable-writes`);
          throw new Error("needs-review: H CLI output");
        }
        // The native CLI requests/operations account for every build/upload/IAM/managed write.
        result.writes.push(...(writes?.resources ?? []));
        note("h-state", result);
        if (!writes || !writes.complete) {
          result.cleanup.unconfirmed.push(`cli:${name}:write-inventory`);
          throw new Error("needs-review: H CLI write inventory");
        }
        Object.assign(write, writes.function);
        note("h-cli-answer", { name, exitCode: deployed.exitCode, timedOut: deployed.timedOut });
        if (m.functions) {
          result.segments.at(-1).native = writes.native;
          note("h-capability-native", {
            segment,
            name,
            native: writes.native,
            refusal: writes.refusal === true,
          });
          if (writes.refusal === true) {
            result.segments.at(-1).status = "native-refusal";
            const partial = await lists("readiness");
            note("h-partial-deploy-lists", partial);
            note("h-state", result);
            // No delivery table for a refused capability. The next iteration requires a checkpoint-bound settlement/admission.
            continue segments;
          }
        }
        if (hCliFailed(deployed)) throw new Error("H deploy failed; no redeploy");
        await settle(write, "readiness");
        let readiness;
        for (let poll = 0; poll < 40; poll++) {
          const inventory = await lists("readiness");
          note("h-readiness-lists", inventory);
          readiness = hReady({
            manifest: m,
            ...inventory,
            names: attempted.filter(
              (name) =>
                !m.functions ||
                !result.segments.some(
                  (segment) =>
                    segment.status === "native-refusal" &&
                    m.functions.some((f) => f.name === name && f.segment === segment.segment),
                ),
            ),
          });
          if (readiness.ready) break;
          if (!m.functions || poll < 39) await sleep(30_000);
        }
        if (!readiness?.ready) throw new Error("H readiness incomplete");
        result.identities = readiness.identities;
        // H1 exact-name GETs are raw observations, including errors; they settle nothing.
        for (const identity of readiness.identities)
          for (const [host, version, resource] of [
            ["functions", "v2", identity.function],
            ["run", "v2", identity.service],
            ["eventarc", "v1", identity.trigger],
            ["pubsub", "v1", identity.topic],
            ["pubsub", "v1", identity.subscription],
          ]) {
            meter("readiness");
            try {
              const reply = await transports[host].request({
                method: "GET",
                path: `/${version}/${resource}`,
                op: "h.observeOnly",
                label: { case: "h-observeOnly" },
              });
              note("h-observeOnly", { host, resource, reply });
            } catch {
              note("h-observeOnly", { host, resource, unknown: true });
            }
          }
        for (const identity of readiness.identities) {
          const own = result.writes.find(
            (w) => w.name === identity.function && w.action === "create",
          );
          // Complete positive readbacks, not the CLI summary, confirm creation.
          if (own) own.state = "confirmed";
        }
      }
      if (m.functions && segment === "core") {
        const channel = await get("eventarc", `/v1/${m.channel}`, "readiness", evidence.readiness);
        if (
          channel.status !== 200 ||
          channel.body.name !== m.channel ||
          !channel.body.pubsubTopic?.startsWith(`projects/${m.project}/topics/`)
        )
          throw new Error("H2 default channel topic unknown");
        result.channelTopics[m.channel] = channel.body.pubsubTopic;
        const creation = result.writes.find((w) => w.name === m.channel && w.action === "create");
        if (creation) creation.state = "confirmed";
      }
      if (m.functions && segment === "source") {
        result.segments.at(-1).status = "unexpected-acceptance";
        throw new Error("H2 source unexpectedly accepted; review without source publications");
      }
      for (const identity of result.identities)
        if (!origins.some((o) => o.handler === identity.handler))
          origins.push({
            handler: identity.handler,
            service: identity.service.split("/").at(-1),
            location: m.location,
          });
      capture ??= hCapture({
        manifest: m,
        origins,
        now,
        startedAt: now(),
        saveFrame,
        transport: {
          request: async (spec) => {
            if (m.functions && now() + 30_000 > result.startedAt + m.wallMs - m.cleanupReserveMs)
              throw new Error("H2 capture wall cap; cleanup reserved");
            const reply = await transports.logging.request(spec);
            if (!evidence.logging(reply, { ...spec, host: "logging" }))
              throw new Error("needs-review: H Logging shape");
            return reply;
          },
        },
      });
      await capture.poll();
      lastPollAt = now();
      if (segment === "core") await pause(m.propagationMs);
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
              ...(m.functions
                ? { channel: spec.path.replace(/^\/v1\//, "").replace(/:publishEvents$/, "") }
                : {}),
              known:
                !hUnknown(reply) &&
                (!m.functions ||
                  evidence.publish?.(reply, { ...spec, host: "publishing" }) === true),
              status: reply.status,
              candidates: (events ?? []).map((e) => ({ id: e.id, source: e.source, type: e.type })),
            });
          }
          return reply;
        },
      };
      sdk ??= await makeSdk({
        project: m.project,
        runId: m.runId,
        caseId: "h-publish",
        getToken,
        transport: meteredPublishing,
        ownership,
        publishPrefix: "/v1",
        note,
      });
      const plan = hPublishes(m).filter((p) => !m.functions || p.segment === segment);
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
          const channel = p.channel ?? m.channel;
          const reply = await client.publishEvents(channel, p.body);
          Object.assign(observation, {
            status: reply.status,
            known:
              !hUnknown(reply) &&
              (!m.functions ||
                evidence.publish?.(reply, {
                  host: "publishing",
                  method: "POST",
                  path: `/v1/${channel}:publishEvents`,
                  body: p.body,
                }) === true),
          });
        }
        if (!m.functions && !p.refused && !p.negativeHandlers?.length) {
          observation.expectedRecipients = (observation.body?.events ?? []).flatMap((e) => {
            const handlers =
              e.type === m.type ? [m.observe] : e.type === m.filteredType ? [m.filtered] : [];
            return handlers.map((handler) => ({ handler, id: e.id, source: e.source }));
          });
        }
        note("h-publish-answer", observation);
        if (!observation.known) throw new Error("H unknown publish; never replay");
        if (p.control && !(observation.status >= 200 && observation.status < 300))
          throw new Error("H control refused");
        if (m.functions && p.sdk)
          observation.expectedRecipients = (observation.body?.events ?? []).flatMap((e) =>
            [m.observe, m.fanout].map((handler) => ({ handler, id: e.id, source: e.source })),
          );
        await pause(p.windowMs ?? (p.control ? (p.controlWaitMs ?? 120_000) : 0));
        observation.endedAt = now();
        if (m.functions) {
          const controlComplete = (o) =>
            o.expectedRecipients?.length &&
            o.expectedRecipients.every((r) =>
              capture
                .result()
                .frames.some(
                  ({ frame }) =>
                    frame.handler === r.handler &&
                    frame.event.id === r.id &&
                    frame.event.source === r.source,
                ),
            );
          if (p.control && p.controlWaitMs !== 0) {
            const group = p.bracket
              ? result.publishes.filter(
                  (o) => o.control && o.bracket === p.bracket && o.position === p.position,
                )
              : [observation];
            if (!group.every(controlComplete)) throw new Error("H2 control missing");
            if (p.position === "after") {
              const subject = result.publishes.find((o) => !o.control && o.bracket === p.bracket);
              if (subject) subject.after = true;
            }
          }
          if (p.windowMs && !p.retry)
            observation.before = result.publishes
              .filter((o) => o.control && o.bracket === p.bracket && o.position === "before")
              .every(controlComplete);
          continue;
        }
        const both = [m.observe, m.filtered];
        const receivedBoth = (o) =>
          both.every((handler) =>
            o.candidates.some(
              (e) =>
                e.type === (handler === m.observe ? m.type : m.filteredType) &&
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
      if (m.functions) result.segments.at(-1).status = "observed";
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
      result.evidence = judgeH({
        manifest: m,
        observations: result.publishes,
        capture: result.capture,
      });
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
        const functions = await readList("cleanup", "functions", "v2", "functions");
        const current = functions.find((f) => f.name === full);
        const read = current ? "present" : "absent";
        const disposition = hDisposition({ create: creation.state, read });
        if (disposition.confirmed) creation.state = "confirmed";
        if (!disposition.canDelete) {
          if (!disposition.closed)
            result.cleanup[disposition.unconfirmed ? "unconfirmed" : "unsettled"].push(full);
          continue;
        }
        // Child admission cannot prevent deletion of a confirmed function.
        let inventory;
        if (!result.identities.some((i) => i.function === full))
          try {
            inventory = await lists("cleanup");
          } catch {}
        if (inventory && current && !result.identities.some((i) => i.function === full)) {
          const service = inventory.services.find((s) => s.name === current.serviceConfig?.service);
          const trigger = inventory.triggers.find((t) => t.name === current.eventTrigger?.trigger);
          const identity = {
            function: full,
            handler: name,
            service: service?.name,
            trigger: trigger?.name,
            topic: trigger?.transport?.pubsub?.topic,
            subscription: trigger?.transport?.pubsub?.subscription,
          };
          if (
            identity.service &&
            identity.trigger &&
            inventory.topics.some((t) => t.name === identity.topic) &&
            inventory.subscriptions.some((s) => s.name === identity.subscription)
          )
            result.identities.push(identity);
          else result.cleanup.unconfirmed.push(`cli:${name}:managed-inventory`);
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
        const after = await lists("cleanup");
        note("h-cleanup-lists-after-delete", after);
        const closed =
          deletion.state === "confirmed" && !after.functions.some((f) => f.name === full);
        if (!closed) result.cleanup.unsettled.push(full);
        for (const identity of result.identities.filter((i) => i.function === full)) {
          for (const [key, resource] of [
            ["services", identity.service],
            ["triggers", identity.trigger],
            ["topics", identity.topic],
            ["subscriptions", identity.subscription],
          ]) {
            // R2: only confirmed children, and only after R1 settles their function.
            if (!closed || after[key].some((item) => item.name === resource))
              result.cleanup.unsettled.push(resource);
          }
        }
      } catch {
        result.cleanup.unsettled.push(full);
      }
    }
    if (attempted.length && result.baselineLists) {
      try {
        const remaining = await lists("cleanup");
        note("h-final-lists", remaining);
        for (const key of ["functions", "services", "triggers", "topics", "subscriptions"])
          for (const item of remaining[key])
            if (
              !result.baselineLists[key].some((before) => before.name === item.name) &&
              !(m.functions && Object.values(result.channelTopics).includes(item.name)) &&
              !result.cleanup.unsettled.includes(item.name) &&
              !result.cleanup.unconfirmed.includes(item.name)
            )
              result.cleanup.unsettled.push(item.name);
      } catch {
        result.cleanup.unsettled.push("incomplete-final-lists");
      }
    }
    // Stop retry execution before the exact marker can be removed.
    if (
      result.marker &&
      result.cleanup.unsettled.length === 0 &&
      result.cleanup.unconfirmed.length === 0 &&
      attempted.length === (m.functions ? attempted.length : 2) &&
      result.writes.filter(
        (w) => w.kind === "function" && w.action === "create" && w.state === "confirmed",
      ).length === (m.functions ? attempted.length : 2)
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
          if (
            m.functions &&
            (!creation ||
              marker.body.name !== result.marker ||
              marker.body.fields?.run?.stringValue !== m.runId ||
              marker.body.fields?.source?.stringValue !== m.source ||
              marker.body.fields?.eventId?.stringValue !==
                hPublishes(m).find((p) => p.retry).body.events[0].id)
          )
            throw new Error("H2 marker ownership mismatch");
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
    for (const channel of m.functions ? [m.namedChannel, m.channel] : [m.channel]) {
      const channelBaseline = channel === m.channel ? baseline : result.namedBaseline;
      if (
        channelBaseline?.status === 404 &&
        (attempted.length || (m.functions && result.writes.some((w) => w.name === channel)))
      ) {
        const creation = result.writes.find((w) => w.name === channel && w.action === "create");
        try {
          if (!creation) throw new Error("H default channel has no own CREATE evidence");
          const current = await get(
            "eventarc",
            `/v1/${channel}`,
            "cleanup",
            (r, spec) => evidence.readiness(r, spec) || evidence.notFound(r, spec),
          );
          if (
            m.functions &&
            current.status === 200 &&
            current.body.pubsubTopic?.startsWith(`projects/${m.project}/topics/`)
          )
            result.channelTopics[channel] = current.body.pubsubTopic;
          const read =
            current.status === 200 && current.body.name === channel
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
            remaining.some((t) => t.channel === channel) ||
            result.cleanup.unconfirmed.length ||
            result.cleanup.unsettled.length
          )
            throw new Error("H channel still has possible dependents");
          const deletion = {
            name: channel,
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
            path: `/v1/${channel}`,
            op: "h.channel.delete",
            label: { case: "h-cleanup" },
          });
          if (
            !hUnknown(answer) &&
            evidence.operation(answer, {
              host: "eventarc",
              method: "DELETE",
              path: `/v1/${channel}`,
            }) &&
            answer.status >= 200 &&
            answer.status < 300 &&
            (!m.functions || answer.body.metadata?.target === channel)
          ) {
            deletion.operation = answer.body.name;
            deletion.state =
              answer.body.done === true ? (answer.body.error ? "failed" : "confirmed") : "pending";
            await settle(deletion, "cleanup");
          }
          const absent = await get("eventarc", `/v1/${channel}`, "cleanup", evidence.notFound);
          if (
            !hDisposition({
              create: creation.state,
              deletion: deletion.state,
              read: absent.status === 404 ? "absent" : "unknown",
            }).closed
          )
            result.cleanup.unsettled.push(channel);
          if (m.functions) {
            const topics = await readList("cleanup", "pubsub", "v1", "topics");
            const topic = result.channelTopics[channel];
            if (!topic || deletion.state !== "confirmed" || topics.some((t) => t.name === topic))
              result.cleanup.unsettled.push(topic ?? `${channel}:topic-unknown`);
          }
        } catch {
          result.cleanup.unconfirmed.push(channel);
        }
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
  if (m.functions)
    result.cleanupReady =
      result.retentionVerified === true &&
      result.cleanup.unsettled.length === 0 &&
      result.cleanup.unconfirmed.length === 0 &&
      result.writes.every((w) => w.state === "confirmed" || w.state === "failed");
  result.closureReady =
    result.stopped === null &&
    result.evidence?.complete === true &&
    result.cleanup.unsettled.length === 0 &&
    result.cleanup.unconfirmed.length === 0 &&
    result.writes.every((w) => w.state === "confirmed" || w.state === "failed");
  note("h-state", result);
  note("h-run-end", result);
  return result;
}

/** Separate coordinator A2: ruled complete lists, at least ten minutes after the latest request. */
export async function hA2({
  recording,
  transports,
  evidence,
  now,
  note,
  sleep = (ms) => new Promise((r) => setTimeout(r, ms)),
}) {
  if (!Number.isFinite(recording.lastRequestAt) || now() - recording.lastRequestAt < 600_000)
    throw new Error("H A2 must wait ten minutes after the latest request");
  const m = recording.manifest ?? {};
  const limits = m.limits ?? H_LIMITS;
  if (
    m.functions &&
    (evidence.a2ChannelRuling !== true ||
      !Number.isFinite(recording.startedAt) ||
      now() + 30_000 > recording.startedAt + m.wallMs)
  )
    return {
      requests: 0,
      lastRequestAt: recording.lastRequestAt,
      cleanupReady: false,
      closureReady: false,
      unresolvedInventory: ["H2 A2 ruling or wall cap"],
      facts: [],
    };
  const names = new Map();
  for (const write of recording.writes) {
    if (write.name && write.host && ["create", "delete"].includes(write.action))
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
      if (name)
        names.set(name, { host, version: ["functions", "run"].includes(host) ? "v2" : "v1" });
  for (const topic of Object.values(recording.channelTopics ?? {}))
    names.set(topic, { host: "pubsub", version: "v1" });
  const channels = m.functions ? [m.namedChannel, m.channel] : [m.channel];
  const facts = [];
  const inventoryUnknown = [];
  let channelTopic;
  let requests = 0;
  const collections = new Map();
  if (m.functions) {
    for (const [host, version, key] of [
      ["functions", "v2", "functions"],
      ["run", "v2", "services"],
      ["eventarc", "v1", "triggers"],
      ["pubsub", "v1", "topics"],
      ["pubsub", "v1", "subscriptions"],
    ]) {
      const path = `/${version}/projects/${m.project}${host === "pubsub" ? "" : `/locations/${m.location}`}/${key}${host === "pubsub" ? "?pageSize=100" : ""}`;
      try {
        const items = await hReadList(
          {
            request: async (spec) => {
              const reply = await transports[host].request(spec);
              if (!evidence.readiness(reply, { ...spec, host }))
                throw new Error("H2 A2 inventory shape");
              return reply;
            },
          },
          { path, key, phase: "a2" },
          () => {
            if (requests >= limits.a2 || now() + 30_000 > recording.startedAt + m.wallMs)
              throw new Error("H2 A2 ceiling");
            requests++;
          },
        );
        collections.set(path, items);
        for (const item of items)
          if (
            !names.has(item.name) &&
            !recording.baselineLists?.[key]?.some((before) => before.name === item.name)
          )
            inventoryUnknown.push(item.name);
      } catch {
        inventoryUnknown.push(`incomplete-${key}`);
        collections.set(path, null);
      }
    }
  }
  const order = (name) =>
    name.includes("/functions/")
      ? 0
      : channels.includes(name)
        ? 2
        : name === recording.marker
          ? 3
          : 1;
  for (const [name, { host, version }] of [...names].sort(([a], [b]) => order(a) - order(b))) {
    channelTopic = recording.channelTopics?.[name];
    let read = "unknown";
    const collection = name.match(
      /^(projects\/[^/]+(?:\/locations\/[^/]+)?\/(functions|services|triggers|topics|subscriptions))\/[^/]+$/,
    );
    if (collection && evidence.a2ListRuling === true) {
      const path = `/${version}/${collection[1]}${host === "pubsub" ? "?pageSize=100" : ""}`;
      if (!collections.has(path)) {
        try {
          const items = await hReadList(
            {
              request: async (spec) => {
                const reply = await transports[host].request(spec);
                if (!evidence.readiness(reply, { ...spec, host }))
                  throw new Error("H A2 list shape");
                return reply;
              },
            },
            { path, key: collection[2], phase: "a2" },
            () => {
              if (
                requests >= limits.a2 ||
                (m.functions && now() + 30_000 > recording.startedAt + m.wallMs)
              )
                throw new Error("H A2 ceiling");
              requests++;
            },
          );
          collections.set(path, items);
          note("h-a2-list", { path, items });
        } catch {
          collections.set(path, null);
        }
      }
      const items = collections.get(path);
      if (items) read = items.some((item) => item.name === name) ? "present" : "absent";
    } else if (!collection) {
      if (requests >= limits.a2 || (m.functions && now() + 30_000 > recording.startedAt + m.wallMs))
        throw new Error("H A2 ceiling");
      requests++;
      const path = `/${version}/${name}`;
      const reply = await transports[host].request({
        method: "GET",
        path,
        op: "h.a2.read",
        label: { case: "h-a2" },
      });
      read =
        !hUnknown(reply) &&
        evidence.notFound(reply, { host, method: "GET", path }) &&
        reply.status === 404
          ? "absent"
          : !hUnknown(reply) &&
              evidence.readiness(reply, { host, method: "GET", path }) &&
              reply.status === 200 &&
              reply.body.name === name
            ? "present"
            : "unknown";
      if (m.functions && name === recording.marker && read === "present") {
        const retryId = recording.publishes?.find((p) => p.retry)?.body?.events?.[0]?.id;
        if (
          !retryId ||
          reply.body.fields?.run?.stringValue !== m.runId ||
          reply.body.fields?.source?.stringValue !== m.source ||
          reply.body.fields?.eventId?.stringValue !== retryId
        )
          read = "unknown";
      }
      if (
        channels.includes(name) &&
        host === "eventarc" &&
        read === "present" &&
        typeof reply.body.pubsubTopic === "string" &&
        reply.body.pubsubTopic.startsWith(`projects/${recording.manifest.project}/topics/`)
      ) {
        channelTopic = reply.body.pubsubTopic;
        if (m.functions) recording.channelTopics[name] = channelTopic;
      }
    }
    const creation = recording.writes.find((w) => w.name === name && w.action === "create");
    const deletion = recording.writes.find((w) => w.name === name && w.action === "delete");
    const channelOwner = Object.entries(recording.channelTopics ?? {}).find(
      ([, topic]) => topic === name,
    )?.[0];
    const channelCreation =
      channelOwner &&
      recording.writes.find((w) => w.name === channelOwner && w.action === "create");
    // Managed children whose function DELETE completed use that cascade's own disposition.
    const owner = recording.identities.find((i) =>
      [i.service, i.trigger, i.topic, i.subscription].includes(name),
    );
    const ownerDeletion =
      owner && recording.writes.find((w) => w.name === owner.function && w.action === "delete");
    if (
      !collection &&
      read === "present" &&
      creation &&
      ["pending", "unknown"].includes(creation.state)
    ) {
      creation.state = "confirmed";
      note("h-state", recording);
    }
    if (
      !collection &&
      read === "present" &&
      !deletion &&
      facts.every(
        (f) =>
          f.closed ||
          (channels.includes(name) && f.name === channelTopic && f.confirmed) ||
          (m.functions &&
            (channels.includes(f.name) ||
              Object.entries(recording.channelTopics).some(
                ([channel, topic]) =>
                  topic === f.name &&
                  recording.writes.some(
                    (w) => w.name === channel && w.action === "create" && w.state === "confirmed",
                  ),
              ))),
      ) &&
      [...(recording.cleanup.unconfirmed ?? []), ...(recording.cleanup.unsettled ?? [])].every(
        (n) =>
          n === recording.marker ||
          channels.includes(n) ||
          facts.some(
            (f) =>
              f.name === n &&
              (f.closed || (channels.includes(name) && n === channelTopic && f.confirmed)),
          ),
      ) &&
      ((host === "firestore" && name === recording.marker && creation?.state === "confirmed") ||
        (host === "eventarc" &&
          channels.includes(name) &&
          (name === m.channel ? recording.baseline : recording.namedBaseline)?.status === 404 &&
          creation?.state === "confirmed"))
    ) {
      let dependents = inventoryUnknown.length > 0;
      if (host === "eventarc") {
        const items = await hReadList(
          {
            request: async (spec) => {
              const reply = await transports.eventarc.request(spec);
              if (!evidence.readiness(reply, { ...spec, host }))
                throw new Error("H A2 trigger shape");
              return reply;
            },
          },
          {
            path: `/v1/projects/${recording.manifest.project}/locations/us-central1/triggers`,
            key: "triggers",
            phase: "a2",
          },
          () => {
            if (
              requests >= limits.a2 ||
              (m.functions && now() + 30_000 > recording.startedAt + m.wallMs)
            )
              throw new Error("H A2 ceiling");
            requests++;
          },
        );
        dependents ||= items.some((t) => t.channel === name);
      }
      if (!dependents) {
        const write = { name, host, action: "delete", state: "unknown" };
        recording.writes.push(write);
        note("h-state", recording);
        note("h-write-issued", write);
        if (
          requests >= limits.a2 ||
          (m.functions && now() + 30_000 > recording.startedAt + m.wallMs)
        )
          throw new Error("H A2 ceiling");
        requests++;
        const path = `/${version}/${name}`;
        const answer = await transports[host].request({
          method: "DELETE",
          path,
          op: "h.a2.delete",
          label: { case: "h-a2" },
        });
        if (
          !hUnknown(answer) &&
          evidence.readiness(answer, { host, method: "DELETE", path }) &&
          answer.status >= 200 &&
          answer.status < 300
        ) {
          if (host === "firestore") write.state = "confirmed";
          else if (answer.body?.name && answer.body.metadata?.target === name) {
            write.operation = answer.body.name;
            if (answer.body.done === true) write.state = answer.body.error ? "failed" : "confirmed";
            const pollStarted = now();
            for (let poll = 0; answer.body.done !== true && poll < 25; poll++) {
              if (m.functions) {
                if (now() > pollStarted + 120_000) break;
                await sleep(Math.max(0, pollStarted + poll * 5000 - now()));
              } else if (poll) await sleep(5000);
              if (
                requests >= limits.a2 ||
                (m.functions && now() + 30_000 > recording.startedAt + m.wallMs)
              )
                throw new Error("H A2 ceiling");
              requests++;
              const spec = { host, method: "GET", path: `/v1/${write.operation}` };
              const operation = await transports[host].request(spec);
              if (
                hUnknown(operation) ||
                !evidence.operation(operation, spec) ||
                operation.body.name !== write.operation ||
                operation.body.metadata?.target !== name
              )
                break;
              if (operation.body.done) {
                write.state = operation.body.error ? "failed" : "confirmed";
                break;
              }
            }
          }
        }
        note("h-state", recording);
        if (
          requests >= limits.a2 ||
          (m.functions && now() + 30_000 > recording.startedAt + m.wallMs)
        )
          throw new Error("H A2 ceiling");
        requests++;
        const absent = await transports[host].request({
          method: "GET",
          path,
          op: "h.a2.read",
          label: { case: "h-a2" },
        });
        read =
          !hUnknown(absent) && evidence.notFound(absent, { host, method: "GET", path })
            ? "absent"
            : "unknown";
        // The exact topic reported by the channel survives until its owner's DELETE.
        const topicFact = facts.find((f) => f.name === channelTopic);
        if (host === "eventarc" && topicFact) {
          let topicRead = "unknown";
          try {
            const items = await hReadList(
              {
                request: async (spec) => {
                  const reply = await transports.pubsub.request(spec);
                  if (!evidence.readiness(reply, { ...spec, host: "pubsub" }))
                    throw new Error("H A2 channel topic shape");
                  return reply;
                },
              },
              {
                path: `/v1/projects/${recording.manifest.project}/topics?pageSize=100`,
                key: "topics",
                phase: "a2",
              },
              () => {
                if (
                  requests >= limits.a2 ||
                  (m.functions && now() + 30_000 > recording.startedAt + m.wallMs)
                )
                  throw new Error("H A2 ceiling");
                requests++;
              },
            );
            topicRead = items.some((t) => t.name === channelTopic) ? "present" : "absent";
          } catch {}
          Object.assign(
            topicFact,
            { read: topicRead },
            hDisposition({
              create: topicFact.confirmed ? "confirmed" : "unknown",
              deletion: write.state,
              read: topicRead,
              mode: "run",
            }),
          );
          if (read !== "absent" || write.state !== "confirmed") topicFact.closed = false;
          note("h-a2-read", topicFact);
        }
      }
    }
    const latestDeletion = recording.writes.findLast(
      (w) => w.name === name && w.action === "delete",
    );
    const disposition = hDisposition({
      create: creation?.state ?? (owner ? "confirmed" : (channelCreation?.state ?? "unknown")),
      deletion: latestDeletion?.state ?? ownerDeletion?.state,
      read,
      mode: latestDeletion && latestDeletion !== deletion ? "run" : "a2",
      ageMs: now() - recording.lastRequestAt,
    });
    if (
      (owner && !facts.some((fact) => fact.name === owner.function && fact.closed)) ||
      (channelOwner && !facts.some((fact) => fact.name === channelOwner && fact.closed))
    )
      disposition.closed = false;
    if (m.functions && channels.includes(name) && latestDeletion?.state !== "confirmed")
      disposition.closed = false;
    facts.push({ name, read, ...disposition });
    note("h-a2-read", facts.at(-1));
  }
  if (m.functions)
    for (const [channel, topic] of Object.entries(recording.channelTopics)) {
      const topicFact = facts.find((f) => f.name === topic);
      const channelFact = facts.find((f) => f.name === channel);
      const deletion = recording.writes.find((w) => w.name === channel && w.action === "delete");
      if (topicFact?.read === "absent" && channelFact?.closed && deletion?.state === "confirmed")
        topicFact.closed = true;
    }
  const unresolvedInventory = [
    ...inventoryUnknown,
    ...(recording.cleanup.unconfirmed ?? []),
    ...(recording.cleanup.unsettled ?? []),
  ].filter((name) => !facts.some((f) => f.name === name && f.closed));
  const restorationPending = recording.writes.some(
    (w) => !["create", "delete"].includes(w.action) && w.state !== "confirmed",
  );
  let retentionVerified = false;
  if (typeof evidence.retention === "function") {
    try {
      const retained = await evidence.retention({
        recording,
        manifest: recording.manifest,
        baseline: recording.baseline,
        get: async (host, path, judge) => {
          if (
            requests >= limits.a2 ||
            (m.functions && now() + 30_000 > recording.startedAt + m.wallMs)
          )
            throw new Error("H A2 ceiling");
          requests++;
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
    } catch {
      retentionVerified = false;
    }
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
