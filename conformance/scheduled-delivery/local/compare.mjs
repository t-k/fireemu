// The comparison of a local run with the second SCHEDULED-FUNCTIONS delivery recording (run 156715222b86ea44,
// 2026-10-05). Every row names one thing the recording showed, what production did, what fireemu did under each
// profile, and a verdict: MATCH, DIVERGES, or NOT_COMPARABLE (a thing production does that fireemu has no
// counterpart for, or the other way round). A row never loosens: a form is compared as a form, a timing within a
// stated tolerance, and what the recording cannot determine says so.
//
// `production` is the digest `production-run2.json`; `local` is `{ natural: Timeline, probe: Timeline }` for one
// profile (see `local-run.mjs`).
import { readFileSync } from "node:fs";

export const FORM = (value) => String(value).replace(/\.\d+/, "").replace(/\d/g, "d");
const unique = (values) =>
  [...new Set(values.map((v) => JSON.stringify(v ?? null)))].toSorted().map((v) => JSON.parse(v));
const handlerLines = (timeline, handler) =>
  timeline.lines.filter((l) => l.kind === "SCHED_DELIVERY_FRAME" && l.value.handler === handler);
const v2Local = (timeline) =>
  timeline.lines
    .filter((l) => l.kind === "SCHED_DELIVERY_FRAME" && l.value.generation === 2)
    .map((l) => l.value);
const v1Local = (timeline) =>
  timeline.lines
    .filter((l) => l.kind === "SCHED_DELIVERY_FRAME" && l.value.generation === 1)
    .map((l) => l.value);
const v2Prod = (digest) => digest.frames.filter((f) => f.generation === 2);
const v1Prod = (digest) => digest.frames.filter((f) => f.generation === 1);
const secondsOf = (instant) =>
  Date.parse(instant.replace(/(\.\d{3})\d+/, "$1")) / 1000 +
  Number(/\.(\d+)/.exec(instant)?.[1]?.padEnd(9, "0").slice(3, 9) ?? 0) / 1e6;

/** The recorded retry chains: the attempt offsets (seconds from the first attempt) of each job's first chain. */
export function productionChains(digest) {
  const groups = new Map();
  for (const f of digest.frames) {
    if (f.handler !== "schedRetryV2") continue;
    const key =
      f.headers["x-cloudscheduler-jobname"] + "|" + f.headers["x-cloudscheduler-scheduletime"];
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(f.at / 1000);
  }
  const chains = {};
  for (const [key, times] of groups) {
    const job = key.split("|")[0].replace(/^fe-sd-[0-9a-f]{16}-/, "");
    const sorted = times.toSorted((a, b) => a - b);
    const offsets = sorted.map((t) => Math.round((t - sorted[0]) * 100) / 100);
    const name = {
      "firebase-schedule-schedRetryV2-us-central1": "retryFour",
      zero: "retryZero",
      duration: "retryDuration",
      retry5: "retryFive",
    }[job];
    // A job's longest chain: a retried failure is the recording of its retry rule (a lone attempt is not one).
    if (name && (chains[name]?.length ?? 0) < offsets.length) chains[name] = offsets;
  }
  return chains;
}

/** The local retry chains from a probe timeline: each handler's first occurrence, as offsets in seconds from its first attempt. */
export function localChains(timeline) {
  const occurrences = new Map();
  for (const line of timeline.lines.filter((x) => x.kind === "PROBE")) {
    const key = line.value.handler + "|" + (line.value.scheduleTime ?? "");
    if (!occurrences.has(key)) occurrences.set(key, { handler: line.value.handler, times: [] });
    occurrences.get(key).times.push(Date.parse(line.at) / 1000);
  }
  const chains = {};
  for (const { handler, times } of occurrences.values()) {
    const sorted = [...times].toSorted((a, b) => a - b);
    // the earliest occurrence of a handler is its first chain
    if (!chains[handler] || sorted[0] < chains[handler].start)
      chains[handler] = { start: sorted[0], offsets: sorted.map((t) => t - sorted[0]) };
  }
  return Object.fromEntries(Object.entries(chains).map(([name, { offsets }]) => [name, offsets]));
}

const verdict = (match) => (match ? "MATCH" : "DIVERGES");

/** The rows for one profile. */
export function rows(production, local) {
  const out = [];
  const add = (id, area, condition, p, l, match, note = "") =>
    out.push({
      id,
      area,
      condition,
      production: p,
      local: l,
      verdict: match === null ? "NOT_COMPARABLE" : verdict(match),
      note,
    });
  const pv2 = v2Prod(production);
  const lv2 = v2Local(local.natural);
  const lv2Requests = lv2.map((f) => f.request).filter(Boolean);

  // ---- Gen2: the request ----
  const pMethod = unique(pv2.map((f) => f.method));
  const lMethod = unique(lv2.map((f) => f.request?.method ?? null));
  add(
    "v2.request.method",
    "v2-http-delivery",
    "request-method",
    pMethod,
    lMethod,
    JSON.stringify(pMethod) === JSON.stringify(lMethod),
  );
  const pUrl = unique(pv2.map((f) => f.url));
  const lUrl = unique(lv2.map((f) => f.request?.url ?? null));
  add(
    "v2.request.url",
    "v2-http-delivery",
    "request-method",
    pUrl,
    lUrl,
    JSON.stringify(pUrl) === JSON.stringify(lUrl),
  );
  const kept = [
    "x-cloudscheduler",
    "user-agent",
    "content-length",
    "x-cloudscheduler-jobname",
    "x-cloudscheduler-scheduletime",
  ];
  const formOf = (headers) =>
    Object.fromEntries(
      kept.map((k) => [
        k,
        k.includes("jobname")
          ? headers?.[k] === undefined
            ? undefined
            : headers[k].includes("/")
              ? "<resource name>"
              : "<job id>"
          : headers?.[k] === undefined
            ? undefined
            : k.includes("scheduletime")
              ? FORM(headers[k])
              : headers[k],
      ]),
    );
  const pForm = unique(pv2.map((f) => formOf(f.headers)));
  const lForm = unique(lv2Requests.map((r) => formOf(r.headers)));
  // The production scheduleTime form varies with the fraction (digits dropped by FORM); compare the set of forms.
  add(
    "v2.request.headers",
    "v2-http-delivery",
    "jobName-header",
    pForm,
    lForm,
    JSON.stringify(pForm) === JSON.stringify(lForm),
    "the five headers a handler can depend on",
  );
  const pNames = unique(pv2.map((f) => f.headerNames))[0] ?? [];
  const lNames = unique(lv2Requests.map((r) => Object.keys(r.headers).toSorted()))[0] ?? [];
  const missing = pNames.filter((n) => !lNames.includes(n));
  add(
    "v2.request.header-names",
    "v2-http-delivery",
    "scheduleTime-header",
    pNames,
    lNames,
    missing.length === 0,
    missing.length
      ? `not reproduced: ${missing.join(", ")} (the OIDC credential, trace and forwarding headers; nothing here can sign for Google)`
      : "",
  );
  const pBody = unique(pv2.map((f) => [f.rawBodyLength, f.event ? "event" : null]));
  const lBody = unique(lv2Requests.map((r) => [r.rawBodyLength, "event"]));
  add(
    "v2.request.body",
    "v2-http-delivery",
    "body",
    unique(pv2.map((f) => f.rawBodyLength)),
    unique(lv2Requests.map((r) => r.rawBodyLength)),
    JSON.stringify(unique(pv2.map((f) => f.rawBodyLength))) ===
      JSON.stringify(unique(lv2Requests.map((r) => r.rawBodyLength))) &&
      pBody.length > 0 &&
      lBody.length > 0,
    "an empty body (no content)",
  );

  // ---- Gen2: the SDK event ----
  const pKeys = unique(pv2.map((f) => f.eventKeys));
  const lKeys = unique(lv2.map((f) => f.eventKeys));
  add(
    "v2.event.keys",
    "v2-http-delivery",
    "SDK-ScheduledEvent",
    pKeys,
    lKeys,
    JSON.stringify(pKeys) === JSON.stringify(lKeys),
  );
  const jobForm = (name) => (String(name).includes("/") ? "<resource name>" : "<job id>");
  const pJob = unique(pv2.map((f) => jobForm(f.event.jobName)));
  const lJob = unique(lv2.map((f) => jobForm(f.event.jobName)));
  add(
    "v2.event.jobName",
    "v2-http-delivery",
    "jobName-header",
    pJob,
    lJob,
    JSON.stringify(pJob) === JSON.stringify(lJob),
    "production hands the job's id, not its resource name",
  );
  const pTime = unique(pv2.map((f) => FORM(f.event.scheduleTime)));
  const lTime = unique(lv2.map((f) => FORM(f.event.scheduleTime)));
  add(
    "v2.event.scheduleTime-form",
    "v2-http-delivery",
    "scheduleTime-header",
    pTime,
    lTime,
    JSON.stringify(pTime) === JSON.stringify(lTime),
    "production writes it in America/Los_Angeles with its offset, whatever the job's zone",
  );
  const ctx = (f) => ({
    property: f.contextProperty,
    eventIdIsJobId: f.context?.eventId === f.event.jobName,
    topic:
      typeof f.context?.resource?.name === "string" &&
      f.context.resource.name.endsWith("/topics/" + f.event.jobName),
    type: f.context?.eventType,
  });
  const pCtx = unique(pv2.map((f) => ctx(f)));
  const lCtx = unique(lv2.map((f) => ctx(f)));
  add(
    "v2.event.context",
    "v2-http-delivery",
    "SDK-context-getter",
    pCtx,
    lCtx,
    JSON.stringify(pCtx) === JSON.stringify(lCtx),
    "the non-enumerable `context` getter the SDK defines",
  );
  add(
    "v2.event.context-values",
    "v2-http-delivery",
    "SDK-event-enumerability",
    unique(pv2.map((f) => f.context?.params)),
    unique(lv2.map((f) => f.context?.params)),
    JSON.stringify(unique(pv2.map((f) => f.context?.params))) ===
      JSON.stringify(unique(lv2.map((f) => f.context?.params))),
  );

  // ---- Gen1: the Pub/Sub context ----
  const pv1 = v1Prod(production);
  const lv1 = v1Local(local.natural);
  add(
    "v1.argumentCount",
    "v1-pubsub-delivery",
    "context-only-handler",
    unique(pv1.map((f) => f.argumentCount)),
    unique(lv1.map((f) => f.argumentCount)),
    JSON.stringify(unique(pv1.map((f) => f.argumentCount))) ===
      JSON.stringify(unique(lv1.map((f) => f.argumentCount))),
  );
  const idForm = (f) => (/^\d{17}$/.test(String(f.context.eventId)) ? "<17 digits>" : "<other>");
  add(
    "v1.context.eventId",
    "v1-pubsub-delivery",
    "message-id-presence",
    unique(pv1.map(idForm)),
    unique(lv1.map(idForm)),
    JSON.stringify(unique(pv1.map(idForm))) === JSON.stringify(unique(lv1.map(idForm))),
    "a Pub/Sub message id",
  );
  const resForm = (f) => ({
    keys: Object.keys(f.context.resource).toSorted(),
    service: f.context.resource.service,
    type: f.context.resource.type,
    name: String(f.context.resource.name)
      .replace(/^projects\/[^/]+\//, "projects/<project>/")
      .replace(/[^/]+$/, "<id>")
      .replace(/\/(jobs|topics)\//, "/$1/"),
  });
  add(
    "v1.context.resource",
    "v1-pubsub-delivery",
    "context-resource-topic-versus-job",
    unique(pv1.map(resForm)),
    unique(lv1.map(resForm)),
    JSON.stringify(unique(pv1.map(resForm))) === JSON.stringify(unique(lv1.map(resForm))),
    "the topic, not the job, with the PubsubMessage type",
  );
  const tsForm = (f) => {
    const t = String(f.context.timestamp);
    return /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,3})?Z$/.test(t) && !/\.\d*0Z$/.test(t)
      ? "<ms at most, no trailing zero>"
      : "<other>";
  };
  add(
    "v1.context.timestamp",
    "v1-pubsub-delivery",
    "publishTime",
    unique(pv1.map(tsForm)),
    unique(lv1.map(tsForm)),
    JSON.stringify(unique(pv1.map(tsForm))) === JSON.stringify(unique(lv1.map(tsForm))),
  );
  add(
    "v1.context.keys",
    "v1-pubsub-delivery",
    "v1-handler-context",
    unique(pv1.map((f) => Object.keys(f.context).toSorted())),
    unique(lv1.map((f) => Object.keys(f.context).toSorted())),
    JSON.stringify(unique(pv1.map((f) => Object.keys(f.context).toSorted()))) ===
      JSON.stringify(unique(lv1.map((f) => Object.keys(f.context).toSorted()))),
  );

  // ---- failure handling ----
  const perOccurrence = (frames, key) => {
    const counts = new Map();
    for (const f of frames) counts.set(key(f), (counts.get(key(f)) ?? 0) + 1);
    return unique([...counts.values()]);
  };
  const pFail = perOccurrence(
    pv1.filter((f) => f.handler === "schedFailV1"),
    (f) => f.at,
  );
  const lFail = perOccurrence(handlerLines(local.natural, "schedFailV1"), (line) => line.at);
  add(
    "v1.failure-no-retry",
    "v1-two-stage-retry",
    "handler-no-retry",
    pFail,
    lFail,
    JSON.stringify(pFail) === JSON.stringify(lFail),
    "a Gen1 handler that throws is attempted once per occurrence",
  );

  // ---- cadence ----
  const natural = (frames, handler, timeOf) =>
    unique(frames.filter((f) => f.handler === handler).map(timeOf))
      .map(secondsOf)
      .toSorted((a, b) => a - b);
  const pOk = natural(pv2, "schedOkV2", (f) => f.event.scheduleTime);
  const lOk = natural(lv2, "schedOkV2", (f) => f.event.scheduleTime);
  const mode = (list) =>
    [...list].toSorted(
      (a, b) => list.filter((x) => x === b).length - list.filter((x) => x === a).length,
    )[0];
  const pSpacing = mode(pOk.slice(1).map((t, i) => Math.round(t - pOk[i])));
  const lSpacing = mode(lOk.slice(1).map((t, i) => Math.round(t - lOk[i])));
  add(
    "cadence.every-1-minutes.spacing",
    "natural-scheduled-run",
    "success-next-occurrence",
    pSpacing,
    lSpacing,
    pSpacing === lSpacing,
    "consecutive occurrences of `every 1 minutes`",
  );
  const phase = (times) =>
    unique(
      times.map((t) =>
        Math.round((t % 60) * 1e6) / 1e6 > 0 && Math.abs(t % 60) > 0.0005
          ? "fractional second"
          : "whole minute",
      ),
    );
  const pPhase = phase(pOk.slice(1));
  const lPhase = phase(lOk);
  add(
    "cadence.every-1-minutes.phase",
    "natural-scheduled-run",
    "interval-phase-versus-creation-anchor",
    pPhase,
    lPhase,
    JSON.stringify(pPhase) === JSON.stringify(lPhase),
    "production anchors an interval to the job's creation instant, with sub-second drift; fireemu runs it on the minute",
  );
  const pFive = unique(
    pv2
      .filter(
        (f) =>
          f.handler === "schedRetryV2" &&
          f.headers["x-cloudscheduler-jobname"].startsWith("firebase-schedule-"),
      )
      .map((f) => f.event.scheduleTime),
  )
    .map(secondsOf)
    .toSorted((a, b) => a - b);
  const lFive = natural(lv2, "schedRetryV2", (f) => f.event.scheduleTime);
  const alignedFive = (times) =>
    unique(times.map((t) => (t % 300 === 0 ? "five-minute boundary" : "off the boundary")));
  add(
    "cadence.every-5-minutes.alignment",
    "natural-scheduled-run",
    "synchronized-window",
    alignedFive(pFive.slice(1)),
    alignedFive(lFive),
    JSON.stringify(alignedFive(pFive.slice(1))) === JSON.stringify(alignedFive(lFive)),
    "production's `every 5 minutes` job ran off the five-minute boundary after forced runs, and the 08:53 occurrence is missing: not determined by the recording",
  );
  add(
    "forced-run",
    "forced-and-natural-invocation",
    "Cloud-Scheduler-run-now",
    "scheduleTime is the job's next scheduled time",
    "manual control (`functions/{name}:run`) carries the current logical time",
    null,
    "fireemu's manual run is Fireemu-only control, distinct from Cloud Scheduler's run-now (condition 8)",
  );

  // ---- retry chains ----
  const pChains = productionChains(production);
  const lChains = localChains(local.probe);
  for (const [name, label, expected] of [
    ["retryFour", "retryCount 4, min 4s, max 50s, 2 doublings", "finite-retry-count"],
    ["retryFive", "retryCount 5, defaults", "retryCount-boundary"],
    ["retryZero", "retryCount 0", "zero-no-retry"],
    ["retryDuration", "maxRetryDuration 30s, min 4s, max 10s, no count", "duration-only"],
  ]) {
    const p = pChains[name];
    const l = lChains[name] ?? [];
    const sameCount = p && l.length === p.length;
    // Production's offsets carry dispatch latency (about half a second per attempt) that a logical clock does not:
    // an offset matches when production's is within [-0.5, 1.2 * attempt index + 1] seconds above the local one.
    const within =
      sameCount && p.every((offset, i) => offset - l[i] >= -0.5 && offset - l[i] <= 1.2 * i + 1);
    add(
      `retry.${name}`,
      "v2-backoff",
      expected,
      p,
      l,
      Boolean(within),
      `${label}; offsets in seconds from the first attempt`,
    );
  }
  return out;
}

/** The two profiles' rows side by side (a row's verdict per profile). */
export function compareProfiles(production, strict, emulator) {
  const s = rows(production, strict);
  const e = rows(production, emulator);
  return s.map((row, i) => ({
    id: row.id,
    area: row.area,
    condition: row.condition,
    production: row.production,
    strict: { local: row.local, verdict: row.verdict },
    emulator: { local: e[i].local, verdict: e[i].verdict },
    note: row.note,
  }));
}

export const loadDigest = (path) => JSON.parse(readFileSync(path, "utf8"));
