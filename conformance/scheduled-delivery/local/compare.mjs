// The comparison of a local run with the second SCHEDULED-FUNCTIONS delivery recording (run 156715222b86ea44,
// 2026-10-05). Every row names one thing the recording showed, what production did, what fireemu did under each
// profile, and a verdict: MATCH, DIVERGES, or NOT_COMPARABLE (a thing production does that fireemu has no
// counterpart for, or the other way round). A row never loosens: a form is compared as a form, a timing within a
// stated tolerance, and what the recording cannot determine says so.
//
// `production` is the digest `production-run2.json`; `local` is `{ natural: Timeline, probe: Timeline }` for one
// profile (see `local-run.mjs`).
import { readFileSync } from "node:fs";

/**
 * The shape of an instant: every digit is `d`, the fraction is kept (its length shows, and a trailing zero is `z`), so
 * that precision and presence are compared and only the values are masked.
 */
export const FORM = (value) =>
  String(value)
    .replace(
      /\.(\d+)/,
      (_, digits) => "." + "d".repeat(digits.length - 1) + (digits.endsWith("0") ? "z" : "d"),
    )
    .replace(/\d/g, "d");
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
// The jobs the fixture deploys (the REST probe jobs `fe-sd-<runId>-*` carry the same handler but not the same ids).
const DEPLOYED = /^firebase-schedule-/;
const deployedJob = (frame) => DEPLOYED.test(frame.headers?.["x-cloudscheduler-jobname"] ?? "");
/** A function host `<region>-<project>.cloudfunctions.net` with its project masked (the region is kept: it is recorded). */
const maskHostProject = (host) =>
  String(host).replace(/^([a-z]+-[a-z]+\d+)-.+(\.cloudfunctions\.net)$/, "$1-<project>$2");
/** A job id or resource name with its project masked and nothing else: the id itself is compared by value. */
const maskProject = (name) => String(name).replace(/^projects\/[^/]+\//, "projects/<project>/");
const v1Prod = (digest) => digest.frames.filter((f) => f.generation === 1);
/** An RFC 3339 instant (with an offset, and a fraction of up to nine digits) as seconds since the epoch. */
export const secondsOf = (instant) => {
  const fraction = /\.(\d+)/.exec(instant)?.[1] ?? "";
  return Date.parse(instant.replace(/\.\d+/, "")) / 1000 + (fraction ? Number("0." + fraction) : 0);
};

/** Seconds a forced run's first frame may trail (or, by a clock step, lead) the request that forced it. */
const FORCED_FRAME_WINDOW = [-1, 5];

/**
 * The seconds the lag of a natural start against its own schedule time may vary by. Production's varied by 0.8 s in run
 * `156715222b86ea44` and by up to about 12.6 s in run `f123d4fa2d61c5f5` (the slow job's revision started cold); a queue
 * starts each occurrence after the run it waited for, so with a 100 s handler on a 60 s cadence its lag grows by 40 s or
 * more from one start to the next. 20 s separates the two: it is above what production did and below what a queue does.
 */
const ON_TIME_SPREAD = 20;

/**
 * What a job whose handler outlasts its cadence did about overlap, from its `start` and `end` frames (`at` in
 * seconds on one timeline, `scheduled` the schedule time of the occurrence in seconds) and the instants its forced runs
 * were requested. A forced run is the first unclaimed start that follows a request within the window; every other start
 * is a natural occurrence. A run is in flight from its start to its end (a run never ended stays in flight), and the
 * oldest open start is the one an end closes.
 *
 * - `naturalStartsInFlight`: natural starts that began while another run of the job was in flight (production: none);
 * - `occurrencesSkipped`: whether two consecutive natural starts are more than one and a half cadences apart, so that
 *   an occurrence in between never started;
 * - `forcedStartsInFlight`: whether a forced run began while another run was in flight (production: yes);
 * - `startsOnTime`: whether every natural start came when its own occurrence was due, to within `ON_TIME_SPREAD` seconds
 *   of the others' lag. A queue also leaves two starts a cadence or more apart and none inside a run, but it starts each
 *   occurrence late, after the run it waited for; a skip never delays one (production: no start more than 12.6 s off
 *   the others' lag). A start with no schedule time is not on time.
 */
export function inFlightFacts(frames, forcedAt, cadenceSeconds) {
  const sorted = (phase) => frames.filter((f) => f.phase === phase).toSorted((a, b) => a.at - b.at);
  const ends = sorted("end").map((f) => f.at);
  const runs = sorted("start").map((f, i) => ({
    start: f.at,
    scheduled: f.scheduled,
    end: ends[i] ?? Number.POSITIVE_INFINITY,
    forced: false,
  }));
  for (const requested of forcedAt.toSorted((a, b) => a - b)) {
    const run = runs.find(
      (r) =>
        !r.forced &&
        r.start >= requested + FORCED_FRAME_WINDOW[0] &&
        r.start <= requested + FORCED_FRAME_WINDOW[1],
    );
    if (run) run.forced = true;
  }
  const inFlight = (run) =>
    runs.some((other) => other !== run && other.start < run.start && run.start < other.end);
  const natural = runs.filter((r) => !r.forced);
  const lags = natural.map((r) => r.start - r.scheduled);
  return {
    naturalStartsInFlight: natural.filter(inFlight).length,
    occurrencesSkipped: natural
      .slice(1)
      .some((r, i) => r.start - natural[i].start > cadenceSeconds * 1.5),
    forcedStartsInFlight: runs.some((r) => r.forced && inFlight(r)),
    startsOnTime:
      lags.every(Number.isFinite) && Math.max(...lags) - Math.min(...lags) <= ON_TIME_SPREAD,
  };
}

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
      count: "retryCountWindow",
      zerobackoff: "retryZeroBackoff",
      double0: "retryDouble0",
      double1: "retryDouble1",
      double3: "retryDouble3",
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

/** The chains only some recordings hold (the extra REST jobs of later runs): no recording of them, no row. */
const OPTIONAL_CHAINS = new Set([
  "retryCountWindow",
  "retryZeroBackoff",
  "retryDouble0",
  "retryDouble1",
  "retryDouble3",
]);

/**
 * The rows for one profile. `alsoRecorded` lists other recordings whose optional retry chains (the extra REST jobs of a
 * later run) are compared as well, when `production` has none of its own: run `ecef353d18975246` ran a different fixture,
 * so only its chains join the comparison, not its cadence or frames.
 */
export function rows(production, local, alsoRecorded = []) {
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
  // A recording with no Gen2 or no Gen1 frame would let every row match vacuously.
  if (pv2.length === 0 || v1Prod(production).length === 0)
    throw new Error("the recording holds no frames of one generation: nothing to compare");
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
    // sent in every recorded frame: the front end's encodings and protocol, and the function's public host
    "accept-encoding",
    "x-forwarded-proto",
    "host",
  ];
  const formOf = (headers) =>
    Object.fromEntries(
      kept.map((k) => [
        k,
        headers?.[k] === undefined
          ? undefined
          : k.includes("jobname")
            ? maskProject(headers[k])
            : k.includes("scheduletime")
              ? FORM(headers[k])
              : k === "host"
                ? maskHostProject(headers[k])
                : headers[k],
      ]),
    );
  // The recorded forms: production wrote the schedule time with a six-digit fraction on every occurrence after the
  // first of a job (its phase, compared by `cadence.every-1-minutes.phase`) and without one on the first. A local form
  // must be one of those exactly (a nine-digit fraction, a trailing zero, a missing header all are not), and the forms
  // with their fraction set aside must be the same set.
  const pForm = unique(pv2.filter(deployedJob).map((f) => formOf(f.headers)));
  const lForm = unique(lv2Requests.map((r) => formOf(r.headers)));
  const sameForms = (recorded, produced, strip) =>
    produced.length > 0 &&
    produced.every((form) => recorded.some((r) => JSON.stringify(r) === JSON.stringify(form))) &&
    JSON.stringify(unique(recorded.map(strip))) === JSON.stringify(unique(produced.map(strip)));
  const withoutFraction = (form) => ({
    ...form,
    "x-cloudscheduler-scheduletime": form["x-cloudscheduler-scheduletime"]?.replace(/\.[dz]+/, ""),
  });
  add(
    "v2.request.headers",
    "v2-http-delivery",
    "jobName-header",
    pForm,
    lForm,
    sameForms(pForm, lForm, withoutFraction),
    "the headers a handler can depend on, and the three production always sent (accept-encoding, x-forwarded-proto, the host with its project masked); the job id is compared by value",
  );
  // Every name production sent, against every name fireemu sends, in both directions: only the headers nothing here
  // can reproduce (the OIDC credential, the trace headers, `forwarded` and `x-forwarded-for`) are expected to be missing.
  const UNREPRODUCIBLE = [
    "authorization",
    "forwarded",
    "traceparent",
    "x-cloud-trace-context",
    "x-forwarded-for",
  ];
  const nameSet = (lists) => [...new Set(lists.flat())].toSorted();
  const pNames = nameSet(unique(pv2.map((f) => f.headerNames)));
  const lNames = nameSet(unique(lv2Requests.map((r) => Object.keys(r.headers).toSorted())));
  const missing = pNames.filter((n) => !lNames.includes(n));
  const extra = lNames.filter((n) => !pNames.includes(n));
  const same = missing.length === 0 && extra.length === 0 && lNames.length > 0;
  // Only a local request that sent something, and only the unreproducible headers missing, is the declared difference.
  const declared =
    !same &&
    lNames.length > 0 &&
    extra.length === 0 &&
    missing.every((n) => UNREPRODUCIBLE.includes(n));
  add(
    "v2.request.header-names",
    "v2-http-delivery",
    "scheduleTime-header",
    pNames,
    lNames,
    same,
    same
      ? ""
      : declared
        ? `declared: not reproduced ${missing.join(", ")} (the OIDC credential, trace headers, forwarded and x-forwarded-for; nothing here can sign for Google)`
        : `UNEXPECTED: missing ${missing.join(", ") || "none"}; extra ${extra.join(", ") || "none"}`,
  );
  const pLengths = unique(pv2.map((f) => f.rawBodyLength));
  const lLengths = unique(lv2Requests.map((r) => r.rawBodyLength));
  add(
    "v2.request.body",
    "v2-http-delivery",
    "body",
    pLengths,
    lLengths,
    JSON.stringify(pLengths) === JSON.stringify(lLengths),
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
  const pJob = unique(pv2.filter(deployedJob).map((f) => maskProject(f.event.jobName)));
  const lJob = unique(lv2.map((f) => maskProject(f.event.jobName)));
  add(
    "v2.event.jobName",
    "v2-http-delivery",
    "jobName-header",
    pJob,
    lJob,
    JSON.stringify(pJob) === JSON.stringify(lJob),
    "production hands the job's id (`firebase-schedule-<name>-<region>`), not its resource name; compared by value",
  );
  const pTime = unique(pv2.map((f) => FORM(f.event.scheduleTime)));
  const lTime = unique(lv2.map((f) => FORM(f.event.scheduleTime)));
  const timeWithoutFraction = (form) => form.replace(/\.[dz]+/, "");
  add(
    "v2.event.scheduleTime-form",
    "v2-http-delivery",
    "scheduleTime-header",
    pTime,
    lTime,
    lTime.every((form) => pTime.includes(form)) &&
      JSON.stringify(unique(pTime.map(timeWithoutFraction))) ===
        JSON.stringify(unique(lTime.map(timeWithoutFraction))),
    "production writes it in America/Los_Angeles with its offset, whatever the job's zone, and with a six-digit fraction after the first occurrence of an interval job (its phase)",
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

  // ---- Gen1: the message published to the job's topic ----
  // Cloud Scheduler publishes one message to the job's topic for each occurrence (and each forced run); the handler's
  // context names that message. The recording holds what pull subscriptions on the topics held (`published`), the local
  // run what the same kind of subscription held on the broker (`natural.pulled`). A recording without any (run 2) has
  // no such rows.
  const published = production.published ?? [];
  if (published.length > 0) {
    const TOPIC = /^firebase-schedule-(.+)-us-central1$/;
    const asMessage = (fn, m) => ({
      fn,
      id: String(m.messageId),
      time: String(m.publishTime),
      hasData: Boolean(m.data ?? m.hasData),
      attributes: m.attributes ?? {},
    });
    const pMsgs = published.map((m) => asMessage(m.function, m));
    // only a topic of the job's own id (the official emulator's has no region) that answered and held messages counts
    const lMsgs = (local.natural.pulled ?? []).flatMap((t) => {
      const fn = TOPIC.exec(String(t.topic))?.[1];
      return t.status === 200 && fn ? (t.messages ?? []).map((m) => asMessage(fn, m)) : [];
    });
    // what the recording holds is never empty here (`published` is), so an empty local list never equals it
    const same = (p, l) => JSON.stringify(p) === JSON.stringify(l);
    const pTopics = unique(pMsgs.map((m) => m.fn));
    const lTopics = unique(lMsgs.map((m) => m.fn));
    add(
      "v1.published.topic",
      "v1-pubsub-delivery",
      "context-resource-topic-versus-job",
      pTopics,
      lTopics,
      same(pTopics, lTopics),
      "each first-generation function's topic has the job's id (`firebase-schedule-<name>-<region>`) and holds its messages",
    );
    const pData = unique(pMsgs.map((m) => m.hasData));
    const lData = unique(lMsgs.map((m) => m.hasData));
    add(
      "v1.published.data",
      "v1-pubsub-delivery",
      "published-data",
      pData,
      lData,
      same(pData, lData),
      "the published message has no data",
    );
    const attributesOf = (m) => Object.fromEntries(Object.entries(m.attributes).toSorted());
    const pAttributes = unique(pMsgs.map(attributesOf));
    const lAttributes = unique(lMsgs.map(attributesOf));
    add(
      "v1.published.attributes",
      "v1-pubsub-delivery",
      "published-attributes",
      pAttributes,
      lAttributes,
      same(pAttributes, lAttributes),
      'the published message\'s only attribute is `scheduled: "true"`',
    );
    // the handler frame that reports a message: the one of the same function whose context event id is the message id
    const frameOf = (frames) => (m) =>
      frames.find((f) => f.handler === m.fn && f.context?.eventId === m.id);
    const pFrame = frameOf(pv1);
    const lFrame = frameOf(lv1);
    const idFacts = (frame) => (m) => ({
      form: /^\d{17}$/.test(m.id) ? "<17 digits>" : "<other>",
      namedByAHandler: frame(m) !== undefined,
    });
    const pIds = unique(pMsgs.map(idFacts(pFrame)));
    const lIds = unique(lMsgs.map(idFacts(lFrame)));
    add(
      "v1.published.messageId",
      "v1-pubsub-delivery",
      "message-id-presence",
      pIds,
      lIds,
      same(pIds, lIds),
      "the message id is a Pub/Sub message id and is the event id of the handler's context",
    );
    // an instant to the nanosecond, written however many digits: the whole second and the fraction without trailing zeros
    const exact = (instant) => {
      const m = /^(.*?)(?:\.(\d+))?Z$/.exec(String(instant));
      return m ? `${Date.parse(m[1] + "Z")}.${(m[2] ?? "").replace(/0+$/, "")}` : null;
    };
    const timeFacts = (frame) => (m) => {
      const f = frame(m);
      return f ? exact(f.context.timestamp) === exact(m.time) : "no handler reports it";
    };
    const pTimes = unique(pMsgs.map(timeFacts(pFrame)));
    const lTimes = unique(lMsgs.map(timeFacts(lFrame)));
    add(
      "v1.published.publishTime",
      "v1-pubsub-delivery",
      "publishTime",
      pTimes,
      lTimes,
      same(pTimes, lTimes),
      "the handler's context time is the publish time of its message",
    );
  }

  // ---- failure handling ----
  // An occurrence is told by its message id, which a redelivery keeps: a retry some seconds later is the same one.
  const perOccurrence = (frames, key) => {
    const counts = new Map();
    for (const f of frames) counts.set(key(f), (counts.get(key(f)) ?? 0) + 1);
    return unique([...counts.values()]);
  };
  const pFail = perOccurrence(
    pv1.filter((f) => f.handler === "schedFailV1"),
    (f) => f.context.eventId,
  );
  const lFail = perOccurrence(
    handlerLines(local.natural, "schedFailV1"),
    (line) => line.value.context.eventId,
  );
  add(
    "v1.failure-no-retry",
    "v1-two-stage-retry",
    "handler-no-retry",
    pFail,
    lFail,
    JSON.stringify(pFail) === JSON.stringify(lFail),
    "a Gen1 handler that throws is attempted once per occurrence",
  );

  if (pv1.some((f) => f.handler === "schedRetryV1")) {
    const pRetry = perOccurrence(
      pv1.filter((f) => f.handler === "schedRetryV1"),
      (f) => f.context.eventId,
    );
    const lRetry = perOccurrence(
      handlerLines(local.natural, "schedRetryV1"),
      (line) => line.value.context.eventId,
    );
    add(
      "v1.retry-declaration-no-retry",
      "v1-two-stage-retry",
      "handler-retry-declaration",
      pRetry,
      lRetry,
      JSON.stringify(pRetry) === JSON.stringify(lRetry),
      "a Gen1 function declared with `retryCount` 1 whose handler throws is attempted once per occurrence: its job's retry covers the publish, never the handler",
    );
  }

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
    unique(times.map((t) => (Math.abs(t % 60) > 0.0005 ? "fractional second" : "whole minute")));
  const pPhase = phase(pOk.slice(1));
  const lPhase = phase(lOk);
  add(
    "cadence.every-1-minutes.phase",
    "natural-scheduled-run",
    "interval-phase-versus-creation-anchor",
    pPhase,
    lPhase,
    JSON.stringify(pPhase) === JSON.stringify(lPhase),
    "production's first occurrence was on the minute and every later one kept one fraction of a second per job (.416739 across 15 occurrences); the anchor is not determined by the recording and does not follow the job's creation instant; fireemu runs the interval on the minute",
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
  // ---- a handler outlasting its cadence ----
  const SLOW = "schedSlowV2";
  const slowFrames = (frames, atOf) =>
    frames
      .filter((f) => f.handler === SLOW && f.phase !== undefined)
      .map((f) => ({ phase: f.phase, at: atOf(f), scheduled: secondsOf(f.event.scheduleTime) }));
  const pInFlight = inFlightFacts(
    slowFrames(pv2, (f) => f.at / 1000),
    (production.forced ?? [])
      .filter((f) => f.job.startsWith(`firebase-schedule-${SLOW}-`))
      .map((f) => f.atMs / 1000),
    60,
  );
  const inflight = local.inflight ?? { lines: [], manual: [] };
  const lInFlight = inFlightFacts(
    inflight.lines
      .filter((l) => l.kind === "SCHED_DELIVERY_FRAME" && l.value.handler === SLOW)
      .map((l) => ({
        phase: l.value.phase,
        at: Date.parse(l.at) / 1000,
        scheduled: secondsOf(l.value.event.scheduleTime),
      })),
    (inflight.manual ?? []).filter((m) => m.name === SLOW).map((m) => Date.parse(m.at) / 1000),
    60,
  );
  add(
    "cadence.in-flight-skip",
    "natural-scheduled-run",
    "deadline-and-overlap",
    pInFlight,
    lInFlight,
    JSON.stringify(pInFlight) === JSON.stringify(lInFlight),
    "`every 1 minutes` with a 100 s handler: production never started a natural occurrence while a run of the job was in flight (it ran every 2 to 3 minutes) and a forced run did start inside one; the recording does not say whether in flight ends at the 504 or at the handler's end",
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
  for (const other of alsoRecorded)
    for (const [name, offsets] of Object.entries(productionChains(other)))
      if (OPTIONAL_CHAINS.has(name) && pChains[name] === undefined) pChains[name] = offsets;
  const lChains = localChains(local.probe);
  for (const [name, label, expected] of [
    ["retryFour", "retryCount 4, min 4s, max 50s, 2 doublings", "finite-retry-count"],
    ["retryFive", "retryCount 5, defaults", "retryCount-boundary"],
    ["retryZero", "retryCount 0", "zero-no-retry"],
    ["retryDuration", "maxRetryDuration 30s, min 4s, max 10s, no count", "duration-only"],
    // run f123d4fa2d61c5f5 only: a recording without these chains has no such rows
    [
      "retryCountWindow",
      "retryCount 3 and maxRetryDuration 20s, min 4s, max 10s: four attempts, the fourth past the window",
      "count-and-duration-interaction",
    ],
    [
      "retryZeroBackoff",
      "min 0s and max 0s with maxRetryDuration 10s: stored as 5s and 3600s, two attempts",
      "zero-min-backoff",
    ],
    // run ecef353d18975246 only: the gap grows by 2 s after the doublings, and `maxDoublings 0` is stored as 5
    [
      "retryDouble0",
      "retryCount 5, min 3s, max 100s, maxDoublings 0 (stored as 5): every gap doubles",
      "exponential-doubling",
    ],
    [
      "retryDouble1",
      "retryCount 5, min 4s, max 100s, 1 doubling: 4, 8, then 2 s more each time",
      "linear-after-doublings",
    ],
    [
      "retryDouble3",
      "retryCount 5, min 2s, max 100s, 3 doublings: 2, 4, 8, 16, then 18",
      "linear-after-doublings",
    ],
  ]) {
    const p = pChains[name];
    if (p === undefined && OPTIONAL_CHAINS.has(name)) continue;
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
export function compareProfiles(production, strict, emulator, alsoRecorded = []) {
  const s = rows(production, strict, alsoRecorded);
  const e = rows(production, emulator, alsoRecorded);
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
