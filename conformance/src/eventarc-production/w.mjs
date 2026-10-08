import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { cloudEventSize, publishRequestSize } from "./compare.mjs";
import { bisect, bracket } from "./bisect.mjs";
import { hProductionAnswer, hProductionEvidence } from "./h-production.mjs";
import { hUnknown, hReadList } from "./h-deploy.mjs";

export const W_A2_RULING =
  "- 2026-10-07 | EVENTARC-W A2 channel settlement | decision=APPROVE; for EVENTARC packet W recordings W0, W1 and W2 on fireemu-oracle-events, separate coordinator A2 starts at least 600 seconds after the latest preceding request; at most 38 cumulative requests with each A2 invocation bounded by its own 45-minute wall cap; it may confirm only the exact baseline-absent run channel by its own judged positive GET or own CREATE operation done; unknown or pending CREATE never closes by absence; it may send one exact channel DELETE only for that confirmed create after a fresh complete judged trigger list has no channel dependents; never resend an unknown or pending DELETE; it may read the own operation of a prior channel DELETE; the exact pubsubTopic positively named by the channel is its own topic and may remain when admitting channel DELETE; close channel and topic only after that DELETE's own matching-target operation is done without error, the exact channel GET is a judged 404, and a fresh complete judged topics list omits its exact topic; no topic DELETE, deployment, API enable or publication | Claude（委任。オーナーの裁量の委任 2026-09-28） | docs.local/runs/eventarc-lane/2026-10-07-h2-w-design.md";

export function wManifest({ project, runId, stage, prerequisite }) {
  if (
    project !== "fireemu-oracle-events" ||
    !/^[a-f0-9]{12}$/.test(runId ?? "") ||
    !["w0", "w1", "w2", "w-shape"].includes(stage)
  )
    throw new Error("W requires the owned project, fresh fixed-width run and stage");
  const ceiling = 40 * 1024 * 1024;
  if (stage === "w-shape" && prerequisite !== undefined)
    throw new Error("W shape is an independent fixed observation");
  if (["w1", "w2"].includes(stage)) {
    if (
      !prerequisite ||
      !Number.isSafeInteger(prerequisite.accepted) ||
      !Number.isSafeInteger(prerequisite.refused) ||
      prerequisite.accepted < 1024 * 1024 ||
      prerequisite.refused > ceiling - 2 ||
      prerequisite.accepted >= prerequisite.refused
    )
      throw new Error("W requires a reviewed prerequisite boundary");
    if (stage === "w1" && prerequisite.refused - prerequisite.accepted > 4096)
      throw new Error("W1 interval exceeds twelve bisections");
    if (stage === "w2" && prerequisite.refused !== prerequisite.accepted + 1)
      throw new Error("W2 requires adjacent bounds");
  }
  const parent = `projects/${project}/locations/us-central1`;
  return {
    project,
    runId,
    stage,
    parent,
    channel: `${parent}/channels/fe${runId}-w`,
    type: `fireemu.w.${runId}`,
    source: `//fireemu/w/${runId}`,
    ceiling,
    ladder: [1, 2, 4, 8, 16, 32].map((n) => n * 1024 * 1024).concat(ceiling - 2),
    ...(["w1", "w2"].includes(stage) ? { prerequisite } : {}),
    limits: { preflight: 16, setup: 12, publish: stage === "w-shape" ? 5 : 20, cleanup: 38 },
    wallMs: 150 * 60_000,
    reserveUsd: 0.05,
  };
}

/** Three fixed counterexamples to the inferred Pub/Sub request-size transformation. */
export function wShapeBody(m, sequence, shape, topic) {
  if (
    m.stage !== "w-shape" ||
    sequence !== { N99: 2, T0: 3, I0: 4 }[shape] ||
    !["N99", "T0", "I0"].includes(shape) ||
    !new RegExp(`^projects/${m.project}/topics/[A-Za-z][A-Za-z0-9._~-]*$`).test(topic ?? "")
  )
    throw new Error("W shape recipe or managed topic mismatch");
  const { body } = wBody(m, sequence, 65536);
  if (shape === "N99") body.events.pop();
  for (const event of body.events) {
    event.textData = '""';
    if (shape === "T0") event.attributes.time.ceTimestamp = "1970-01-01T00:00:00Z";
    if (shape === "I0") event.attributes.probe = { ceInteger: 0 };
  }
  const varint = (n) => {
    let count = 1;
    for (; n >= 128; n = Math.floor(n / 128)) count++;
    return count;
  };
  const field = (n) => 1 + varint(n) + n;
  const length = (text) => Buffer.byteLength(text, "utf8");
  const sizes = () =>
    body.events.map((event) => {
      // compare.mjs covers string/timestamp attributes; only this fixed integer-zero entry is added.
      const { probe, ...attributes } = event.attributes;
      const inner =
        cloudEventSize({ ...event, attributes }) +
        (probe === undefined ? 0 : field(field(length("probe")) + field(2)));
      return field(length(event["@type"])) + field(inner);
    });
  const requestSize = () =>
    field(length(m.channel)) + sizes().reduce((sum, n) => sum + field(n), 0);
  let padding = 0;
  // A bounded local fixed point accounts for protobuf length-prefix width changes, with no dispatch.
  for (let step = 0; step < 3; step++) {
    padding += 10081812 - requestSize();
    for (let i = 0; i < body.events.length; i++)
      body.events[i].textData = JSON.stringify(
        "x".repeat(
          Math.floor(padding / body.events.length) + (i < padding % body.events.length ? 1 : 0),
        ),
      );
  }
  const raw = JSON.stringify(body),
    httpBytes = length(raw),
    anyBytes = sizes();
  if (requestSize() !== 10081812 || httpBytes > m.ceiling || anyBytes.some((n) => n >= 450000))
    throw new Error("W shape fixed wire size, ceiling or individual Any violated");
  const messages = body.events.map((event) => {
    const attributes = {
      "ce-id": event.id,
      "ce-source": event.source,
      "ce-specversion": event.specVersion,
      "ce-type": event.type,
      "ce-datacontenttype": event.attributes.datacontenttype.ceString,
      "ce-time": event.attributes.time.ceTimestamp,
      ...(shape === "I0" ? { "ce-probe": "0" } : {}),
    };
    return (
      field(length(event.textData)) +
      Object.entries(attributes).reduce(
        (sum, [key, value]) => sum + field(field(length(key)) + field(length(value))),
        0,
      )
    );
  });
  return {
    body,
    raw,
    httpBytes,
    requestBytes: requestSize(),
    anyBytes,
    whitespace: 0,
    shape,
    predictedRequestSize: field(length(topic)) + messages.reduce((sum, n) => sum + field(n), 0),
    sha256: createHash("sha256").update(raw).digest("hex"),
  };
}

/** An exact uncompressed ASCII JSON family, with per-publication fresh fixed-width IDs. */
export function wBody(m, sequence, size, whitespace = 0) {
  if (
    !Number.isInteger(sequence) ||
    sequence < 1 ||
    sequence > 20 ||
    !Number.isSafeInteger(size) ||
    ![0, 1, 2].includes(whitespace) ||
    size + whitespace > m.ceiling
  )
    throw new Error("W body ceiling or recipe violated");
  const body = {
    events: Array.from({ length: 100 }, (_, i) => ({
      "@type": "type.googleapis.com/io.cloudevents.v1.CloudEvent",
      id: `${m.runId}-${String(sequence).padStart(2, "0")}-${String(i).padStart(3, "0")}`,
      source: m.source,
      specVersion: "1.0",
      type: m.type,
      attributes: {
        datacontenttype: { ceString: "application/json" },
        time: { ceTimestamp: "2026-10-07T00:00:00Z" },
      },
      textData: '""',
    })),
  };
  const padding = size - Buffer.byteLength(JSON.stringify(body));
  if (padding < 0) throw new Error("W body is below the metadata floor");
  for (let i = 0; i < 100; i++)
    body.events[i].textData = JSON.stringify(
      "x".repeat(Math.floor(padding / 100) + (i < padding % 100 ? 1 : 0)),
    );
  const raw = JSON.stringify(body) + " ".repeat(whitespace);
  const varint = (n) => {
    let count = 1;
    for (; n >= 128; n = Math.floor(n / 128)) count++;
    return count;
  };
  const field = (n) => 1 + varint(n) + n;
  const anyBytes = body.events.map(
    (event) => field(Buffer.byteLength(event["@type"])) + field(cloudEventSize(event)),
  );
  if (Buffer.byteLength(raw) !== size + whitespace || anyBytes.some((n) => n >= 450000))
    throw new Error("W individual Any invariant violated");
  return {
    body,
    raw,
    httpBytes: size + whitespace,
    requestBytes: publishRequestSize(m.channel, body.events),
    anyBytes,
    whitespace,
    sha256: createHash("sha256").update(raw).digest("hex"),
  };
}

const publishRows = ["stage-c-replay", "h-readiness"].flatMap((file) =>
  JSON.parse(readFileSync(new URL(`./fixtures/h-fe/${file}.json`, import.meta.url))),
);

/** A new request-size reason is an observation; its native envelope/layout comes from recorded publish refusals. */
export function wAcceptance(reply, spec) {
  if (
    hUnknown(reply) ||
    spec?.host !== "publishing" ||
    spec.method !== "POST" ||
    !/^\/v1\/projects\/fireemu-oracle-events\/locations\/us-central1\/channels\/fe[a-f0-9]{12}-w:publishEvents$/.test(
      spec.path,
    )
  )
    return null;
  if (
    hProductionEvidence.publish(reply, spec) &&
    reply.status === 200 &&
    JSON.stringify(reply.body) === "{}"
  )
    return true;
  const bytes = Buffer.from(reply.bodyBase64 ?? reply.bodyBase64Parts?.join("") ?? "", "base64");
  if (
    bytes.length !== reply.bodyBytes ||
    !bytes.equals(Buffer.from(`${JSON.stringify(reply.body, null, 2)}\n`)) ||
    (reply.headers?.["content-length"] !== undefined &&
      reply.headers["content-length"] !== String(bytes.length)) ||
    (reply.bodySha256 !== undefined &&
      reply.bodySha256 !== createHash("sha256").update(bytes).digest("hex"))
  )
    return null;
  const error = reply.body?.error;
  const requestSize =
    typeof error?.message === "string"
      ? /^The value for request_size is too large\. You passed ([1-9][0-9]{7}) in the request, but the maximum value is 10000000\.(?![\s\S])/.exec(
          error.message,
        )
      : null;
  if (
    reply.status === 400 &&
    JSON.stringify(Object.keys(reply.body)) === '["error"]' &&
    JSON.stringify(Object.keys(error ?? {})) === '["code","message","status"]' &&
    error.code === 400 &&
    error.status === "INVALID_ARGUMENT" &&
    (error.message === "Request payload size exceeds the limit: 10485760 bytes." ||
      (requestSize !== null && Number(requestSize[1]) > 10000000))
  )
    return false;
  if (
    ![400, 413].includes(reply.status) ||
    error?.code !== reply.status ||
    typeof error.message !== "string" ||
    typeof error.status !== "string" ||
    !Array.isArray(error.details) ||
    error.details.length !== 1 ||
    error.details[0]["@type"] !== "type.googleapis.com/google.rpc.BadRequest" ||
    error.details[0].fieldViolations?.length !== 1 ||
    !["request", "events"].includes(error.details[0].fieldViolations[0].field)
  )
    return null;
  const layout = (value) =>
    Array.isArray(value)
      ? value.map(layout)
      : value && typeof value === "object"
        ? Object.entries(value).map(([key, item]) => [key, layout(item)])
        : typeof value;
  return publishRows.some(
    (row) =>
      row.status === 400 &&
      ["No events provided.", "Too many events."].includes(row.body?.error?.message) &&
      row.bodyBytes === Buffer.byteLength(`${JSON.stringify(row.body, null, 2)}\n`) &&
      JSON.stringify(layout(row.body)) === JSON.stringify(layout(reply.body)),
  )
    ? false
    : null;
}

export function wAdmission({ stage, runId, sourceCommit, checkpointSha256, date }) {
  if (
    !/^w[12]$/.test(stage) ||
    !/^[a-f0-9]{12}$/.test(runId) ||
    !/^[a-f0-9]{40}$/.test(sourceCommit) ||
    !/^[a-f0-9]{64}$/.test(checkpointSha256) ||
    !/^\d{4}-\d{2}-\d{2}$/.test(date)
  )
    throw new Error("W admission pins invalid");
  return `- ${date} | EVENTARC-W stage admission | run=${runId}; source=${sourceCommit}; stage=${stage}; checkpoint=${checkpointSha256}; decision=APPROVE | Claude（委任。オーナーの裁量の委任 2026-09-28） | docs.local/runs/eventarc-lane/2026-10-07-h2-w-design.md`;
}

/** A failed CREATE requires the complete recorded native refusal, never just a 4xx status. */
export function wCreateRefusal(reply, spec) {
  if (
    spec?.host !== "eventarc" ||
    spec.method !== "POST" ||
    !spec.path.split("?")[0].endsWith("/channels") ||
    reply?.status < 400 ||
    reply?.status >= 500 ||
    !hProductionAnswer(reply, spec)
  )
    return false;
  const error = reply.body.error;
  return (
    JSON.stringify(Object.keys(reply.body)) === '["error"]' &&
    JSON.stringify(Object.keys(error ?? {})) === '["code","message","status","details"]' &&
    error.code === reply.status &&
    typeof error.message === "string" &&
    error.message.length > 0 &&
    Array.isArray(error.details) &&
    error.details.length === 4 &&
    error.details.every((detail, i) =>
      i % 2 === 0
        ? JSON.stringify(detail) ===
          '{"@type":"type.googleapis.com/google.rpc.BadRequest","fieldViolations":[{"field":"channel.name"}]}'
        : JSON.stringify(Object.keys(detail ?? {})) === '["@type","requestId"]' &&
          detail["@type"] === "type.googleapis.com/google.rpc.RequestInfo" &&
          typeof detail.requestId === "string" &&
          /^[a-f0-9]{16}$/.test(detail.requestId) &&
          detail.requestId === error.details[1].requestId,
    )
  );
}

/** W uses H's native judges and complete lists, with no deploy, API enable or write resend. */
export async function recordW({
  manifest: m,
  transports,
  now,
  sleep,
  note,
  shouldStop = () => false,
  recording,
}) {
  const a2 = recording !== undefined;
  if (a2 && now() - recording.lastRequestAt < 600_000)
    throw new Error("W A2 requires ten minutes since latest request");
  const result = a2
    ? structuredClone(recording)
    : {
        manifest: m,
        startedAt: now(),
        lastRequestAt: now(),
        writes: [],
        publishes: [],
        boundary: null,
        layer: null,
        stopped: null,
        cleanupReady: false,
        evidenceComplete: false,
      };
  const deadline = a2 ? now() + 45 * 60_000 : result.startedAt + m.wallMs;
  const counts = { preflight: 0, setup: 0, publish: 0, cleanup: 0 };
  if (a2) result.mainCounts ??= result.counts;
  result.a2Requests ??= 0;
  result.counts = counts;
  const checkpoint = () => note("w-state", result);
  checkpoint();
  const request = async (host, spec, phase, judge) => {
    const timeoutMs = 30_000 + Math.ceil(((spec.recipe?.httpBytes ?? 0) * 8 * 1000) / 2_000_000);
    if (
      (a2 && result.a2Requests >= 38) ||
      counts[phase] >= m.limits[phase] ||
      now() + 30_000 + timeoutMs > deadline - (phase === "cleanup" ? 0 : 5 * 60_000) ||
      (phase !== "cleanup" && shouldStop())
    )
      throw new Error(`W ${phase} ceiling, wall or signal`);
    counts[phase]++;
    if (a2) result.a2Requests++;
    result.lastRequestAt = now();
    checkpoint();
    const reply = await transports[host].request({
      ...spec,
      timeoutMs,
      label: { case: `w-${phase}` },
    });
    result.lastRequestAt = now();
    checkpoint();
    if (hUnknown(reply) || !judge(reply, { ...spec, host }))
      throw new Error(`needs-review: W ${phase} answer`);
    return reply;
  };
  const get = (host, path, phase, judge = hProductionEvidence.readiness) =>
    request(host, { method: "GET", path }, phase, judge);
  const list = (host, path, key, phase) =>
    hReadList(
      { request: (spec) => request(host, spec, phase, hProductionEvidence.readiness) },
      { path, key, phase },
      () => {},
    );
  const triggers = (phase) => list("eventarc", `/v1/${m.parent}/triggers`, "triggers", phase);
  const topics = (phase) =>
    list("pubsub", `/v1/projects/${m.project}/topics?pageSize=100`, "topics", phase);
  const settle = async (write, phase) => {
    if (!write.operation) return;
    const start = now(),
      deleting = write.action === "delete";
    for (let i = 0; i < (deleting ? 25 : 10); i++) {
      await sleep(Math.max(0, start + i * (deleting ? 5000 : 2000) - now()));
      if (deleting && now() > start + 120_000) return;
      const reply = await get(
        "eventarc",
        `/v1/${write.operation}`,
        phase,
        hProductionEvidence.operation,
      );
      if (reply.body.name !== write.operation || reply.body.metadata.target !== m.channel)
        throw new Error("W operation target mismatch");
      if (reply.body.done) {
        write.state = reply.body.error ? "failed" : "confirmed";
        checkpoint();
        return;
      }
    }
  };
  const write = async (action, phase) => {
    const intent = { name: m.channel, action, state: "unknown" };
    result.writes.push(intent);
    checkpoint();
    const spec =
      action === "create"
        ? {
            method: "POST",
            path: `/v1/${m.parent}/channels?channelId=${m.channel.split("/").at(-1)}`,
            body: { name: m.channel },
          }
        : { method: "DELETE", path: `/v1/${m.channel}` };
    const answer = await request(
      "eventarc",
      spec,
      phase,
      (reply, judged) =>
        hProductionEvidence.operation(reply, judged) ||
        (action === "create" && wCreateRefusal(reply, judged)),
    );
    if (action === "create" && answer.status >= 400 && answer.status < 500) {
      intent.state = "failed";
      checkpoint();
      return intent;
    }
    if (
      answer.status !== 200 ||
      !answer.body.name.startsWith(`${m.parent}/operations/`) ||
      answer.body.metadata.target !== m.channel
    )
      throw new Error("W write operation mismatch");
    intent.operation = answer.body.name;
    intent.state = "pending";
    checkpoint();
    await settle(intent, phase);
    return intent;
  };
  const captureChannel = (answer) => {
    if (
      answer.body.name !== m.channel ||
      answer.body.state !== "ACTIVE" ||
      answer.body.provider !== undefined ||
      !new RegExp(`^projects/${m.project}/topics/[A-Za-z][A-Za-z0-9._~-]*$`).test(
        answer.body.pubsubTopic ?? "",
      )
    )
      throw new Error("W channel identity or provider mismatch");
    if (result.topic && result.topic !== answer.body.pubsubTopic)
      throw new Error("W managed topic changed");
    if (result.baselineTopics.some((t) => t.name === answer.body.pubsubTopic))
      throw new Error("W managed topic was preexisting");
    result.topic = answer.body.pubsubTopic;
  };
  if (!a2) {
    try {
      // Validate the maximum candidate before any request; balanced padding makes all smaller candidates safe.
      if (m.stage === "w-shape")
        for (const [index, shape] of ["N99", "T0", "I0"].entries())
          wShapeBody(m, index + 2, shape, `projects/${m.project}/topics/w-validation`);
      else wBody(m, 20, m.ceiling - 2, 2);
      const services = await list(
        "usage",
        `/v1/projects/${m.project}/services?filter=state:ENABLED&pageSize=200`,
        "services",
        "preflight",
      );
      for (const api of [
        "eventarc.googleapis.com",
        "eventarcpublishing.googleapis.com",
        "pubsub.googleapis.com",
      ])
        if (!services.some((s) => s.state === "ENABLED" && s.config?.name === api))
          throw new Error(`W prerequisite disabled: ${api}`);
      await get("eventarc", `/v1/${m.channel}`, "preflight", hProductionEvidence.notFound);
      result.baselineAbsent = true;
      result.baselineTopics = await topics("preflight");
      result.baselineTriggers = await triggers("preflight");
      if (result.baselineTriggers.some((t) => t.channel === m.channel))
        throw new Error("W baseline has channel dependents");
      const created = await write("create", "setup");
      if (created.state !== "confirmed") throw new Error("W CREATE unconfirmed");
      captureChannel(await get("eventarc", `/v1/${m.channel}`, "setup"));
      checkpoint();
      let acceptedSequence;
      const publishBody = async (built, sequence, purpose) => {
        const { httpBytes: size, whitespace } = built;
        const { raw, body, ...recipe } = built;
        const spec = {
          method: "POST",
          path: `/v1/${m.channel}:publishEvents`,
          body,
          rawBody: raw,
          recipe: { ...recipe, sequence, ordinal: result.publishes.length + 1, purpose },
        };
        const entry = { ...spec.recipe, accepted: null };
        result.publishes.push(entry);
        checkpoint();
        let answer;
        await request("publishing", spec, "publish", (reply, judged) => {
          entry.answer = reply;
          answer = wAcceptance(reply, judged);
          entry.accepted = answer;
          if (answer === false) entry.observation = reply.body.error.message;
          if (built.shape && answer !== null) {
            const measured =
              /^The value for request_size is too large\. You passed ([1-9][0-9]{7}) in the request, but the maximum value is 10000000\.(?![\s\S])/.exec(
                entry.observation ?? "",
              );
            if (answer !== false || measured === null) return false;
            entry.observedRequestSize = Number(measured[1]);
            entry.predictionMatches = entry.observedRequestSize === built.predictedRequestSize;
          }
          return answer !== null;
        });
        const earlier = result.publishes
          .slice(0, -1)
          .filter((p) => p.whitespace === 0 && p.accepted !== null);
        if (
          m.stage !== "w-shape" &&
          !whitespace &&
          earlier.some(
            (p) =>
              (answer && !p.accepted && p.httpBytes <= size) ||
              (!answer && p.accepted && p.httpBytes >= size),
          )
        )
          throw new Error("W nonmonotonic answer");
        return answer;
      };
      const publish = (size, whitespace = 0, purpose = "search") => {
        const sequence = whitespace ? acceptedSequence : result.publishes.length + 1;
        return publishBody(wBody(m, sequence, size, whitespace), sequence, purpose);
      };
      if ((await publish(65536, 0, "before-control")) !== true)
        throw new Error("W before control refused");
      if (m.stage === "w-shape") {
        for (const shape of ["N99", "T0", "I0"]) {
          const sequence = result.publishes.length + 1;
          await publishBody(wShapeBody(m, sequence, shape, result.topic), sequence, shape);
        }
        if ((await publish(65536, 0, "after-control")) !== true)
          throw new Error("W after control refused");
      } else if (m.stage === "w0") {
        const found = await bracket({ start: 65536, values: m.ladder, accepts: publish });
        if (found.high === null)
          result.observation =
            "no distinct boundary observed through 40 MiB minus 2 bytes for this family";
        else {
          if (found.low < m.ladder[0])
            throw new Error("W first ladder point refused without valid lower bound");
          const boundary = await bisect({
            low: found.low,
            high: found.high,
            accepts: publish,
            maxSteps: 12,
          });
          result.boundary = { accepted: boundary.accepted, refused: boundary.refused };
        }
      } else {
        const boundary =
          m.stage === "w1"
            ? await bisect({
                low: m.prerequisite.accepted,
                high: m.prerequisite.refused,
                accepts: publish,
                maxSteps: 12,
              })
            : m.prerequisite;
        if (boundary.refused !== boundary.accepted + 1)
          throw new Error("W boundary is not adjacent");
        if ((await publish(boundary.accepted, 0, "accepted-confirmation")) !== true)
          throw new Error("W boundary changed");
        acceptedSequence = result.publishes.length;
        if ((await publish(boundary.refused, 0, "refused-confirmation")) !== false)
          throw new Error("W boundary changed");
        const one = await publish(boundary.accepted, 1, "whitespace-one"),
          two = await publish(boundary.accepted, 2, "whitespace-two");
        if (one !== two) throw new Error("W ambiguous whitespace layer");
        result.boundary = { accepted: boundary.accepted, refused: boundary.refused };
        result.layer = one ? "logical-request-dependent" : "http-body-dependent";
        if (m.stage === "w2" && m.prerequisite.layer && result.layer !== m.prerequisite.layer)
          throw new Error("W2 layer changed");
        if ((await publish(65536, 0, "after-control")) !== true)
          throw new Error("W after control refused");
      }
      result.evidenceComplete = true;
    } catch (error) {
      result.stopped = error.message;
    }
  }
  try {
    const create = result.writes.find((w) => w.action === "create");
    if (!create) {
      result.cleanupReady = true;
      checkpoint();
      return result;
    }
    const answer = await get("eventarc", `/v1/${m.channel}`, "cleanup");
    if (answer.status === 200) {
      captureChannel(answer);
      if (!result.baselineAbsent) throw new Error("W baseline ownership absent");
      if (["unknown", "pending"].includes(create.state)) create.state = "confirmed";
      checkpoint();
    } else if (
      answer.status !== 404 ||
      !hProductionEvidence.notFound(answer, {
        host: "eventarc",
        method: "GET",
        path: `/v1/${m.channel}`,
      })
    )
      throw new Error("W channel absence unjudged");
    if (create.state === "failed" && !create.operation && !result.topic && answer.status === 404) {
      if (!result.baselineAbsent) throw new Error("W baseline ownership absent");
      const remaining = await triggers("cleanup");
      if (
        remaining.some((t) => t.channel === m.channel) ||
        remaining.some((t) => !result.baselineTriggers.some((b) => b.name === t.name)) ||
        (await topics("cleanup")).some((t) => !result.baselineTopics.some((b) => b.name === t.name))
      )
        throw new Error("W failed CREATE has dependents or foreign residue");
      result.cleanupReady = true;
      delete result.cleanupError;
      result.closureReady = false;
      checkpoint();
      return result;
    }
    if (create.state !== "confirmed" || !result.topic)
      throw new Error("W unknown CREATE stays open");
    const remaining = await triggers("cleanup");
    if (
      remaining.some((t) => t.channel === m.channel) ||
      remaining.some((t) => !result.baselineTriggers.some((b) => b.name === t.name))
    )
      throw new Error("W possible dependents or foreign trigger");
    let deletion = result.writes.find((w) => w.action === "delete");
    if (!deletion) {
      if (answer.status !== 200) throw new Error("W no own DELETE proves absence");
      deletion = await write("delete", "cleanup");
    } else if (a2 && deletion.state !== "confirmed") await settle(deletion, "cleanup");
    if (deletion.state !== "confirmed") throw new Error("W DELETE unresolved; never resend");
    await get("eventarc", `/v1/${m.channel}`, "cleanup", hProductionEvidence.notFound);
    const remainingTopics = await topics("cleanup");
    if (
      remainingTopics.some(
        (t) => t.name === result.topic || !result.baselineTopics.some((b) => b.name === t.name),
      )
    )
      throw new Error("W managed topic or foreign topic remains");
    result.cleanupReady = true;
  } catch (error) {
    result.cleanupReady = false;
    result.cleanupError = error.message;
  }
  result.closureReady = !result.stopped && result.evidenceComplete && result.cleanupReady;
  checkpoint();
  return result;
}
