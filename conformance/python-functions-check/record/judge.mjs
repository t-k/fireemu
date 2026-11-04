// The judge of the check: a pure function of the frames the fixture printed, the ERROR log entries, and which source
// operations were sent. It decides, case by case, whether production (or, in the dry run, fireemu) delivered what the
// Python runner assumes, and records what it observed either way. It never throws on a shape it does not know: a frame
// that is missing or unreadable is `not-delivered` (or `unreadable`), and a value that is not one the judge has a rule
// for is `differs`, with the value kept. Importing it sends and reads nothing.
//
// Statuses: `as-expected` (every rule held), `differs` (a delivery arrived and a rule did not hold), `observed` (a value
// was recorded that has no expectation to hold it to), `not-delivered` (an operation was sent and no frame arrived),
// `not-sent` (the operation was not sent, so there is nothing to judge).
import {
  FAMILIES,
  FIREBASE_FUNCTIONS_PY_VERSION,
  PROJECT,
  REGION,
  jobId,
  runMarker,
} from "./plan.mjs";

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const own = (frame, key) => (isObject(frame) && Object.hasOwn(frame, key) ? frame[key] : undefined);
const sorted = (list) => [...list].toSorted();

/** The frames of one function that belong to this run (a frame without a run marker belongs to no run). */
export function framesOf(frames, fn, run, { anyRun = false } = {}) {
  return frames
    .map((entry) => entry?.frame ?? entry)
    .filter((f) => isObject(f) && f.function === fn && (anyRun || f.run === run));
}

const result = (status, observed, expected, notes = []) => ({ status, observed, expected, notes });

/** `as-expected` when every check passed, else `differs` listing the checks that did not. */
function verdict(checks, observed, expected) {
  const failed = Object.entries(checks)
    .filter(([, ok]) => ok !== true)
    .map(([name]) => name);
  return result(failed.length === 0 ? "as-expected" : "differs", observed, expected, failed);
}

const contentTypeOf = (raw) =>
  own(own(own(raw, "request"), "headers"), "content-type") ??
  own(own(raw, "attributes"), "datacontenttype") ??
  null;
const attributeNames = (raw) =>
  sorted(Object.keys(isObject(raw?.attributes) ? raw.attributes : {}));
const messageOf = (raw) => raw?.data?.value?.message;
const fractionDigits = (time) => {
  const m = /\.(\d+)(?:Z|[+-]\d\d:\d\d)$/.exec(String(time ?? ""));
  return m ? m[1].length : 0;
};

const FIRESTORE_ATTRIBUTES = [
  "database",
  "document",
  "id",
  "location",
  "namespace",
  "project",
  "source",
  "specversion",
  "subject",
  "time",
  "type",
];
const STORAGE_DATA_KEYS = [
  "bucket",
  "generation",
  "id",
  "metageneration",
  "name",
  "size",
  "storageClass",
];
const SCHEDULE_TIME = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?-0[78]:00$/;

/** The one raw event frame of an operation, or why there is none. */
function onlyFrame(frames, label) {
  if (frames.length === 0) return { missing: true };
  const chosen = label ? frames.filter((f) => labelOf(f) === label) : frames;
  if (chosen.length === 0) return { missing: true };
  return { frame: chosen[0], count: chosen.length };
}
/** The label an operation put in its payload: a Pub/Sub message attribute, or the Eventarc event's data. */
const labelOf = (frame) =>
  frame?.data?.value?.message?.attributes?.label ?? frame?.data?.value?.label ?? null;

export function judge({ runId, frames, errors = [], sent = {}, mode = "production" }) {
  const run = runMarker(runId);
  const cases = {};
  const sentOk = (...keys) => keys.every((k) => sent[k] !== undefined);
  const needSent = (id, keys, body) => {
    cases[id] = sentOk(...keys)
      ? body()
      : result(
          "not-sent",
          null,
          null,
          keys.filter((k) => sent[k] === undefined),
        );
  };
  const raw = (family, label) =>
    onlyFrame(
      framesOf(frames, FAMILIES[family].raw, run).filter((f) => f.kind === "raw-event"),
      label,
    );
  const sdk = (family) => framesOf(frames, FAMILIES[family].sdk, run);
  const needRequest = (frame, checks) => {
    if (mode === "production") checks["request-context"] = isObject(frame.request);
  };

  needSent("firestore-protobuf", ["fs-create"], () => {
    const r = raw("firestoreCreated");
    if (r.missing) return result("not-delivered", null, null, ["no raw frame"]);
    const f = r.frame;
    const contentType = contentTypeOf(f);
    const fields = f.data?.protobuf?.value?.fields ?? null;
    const checks = {
      "data-is-bytes": f.data?.kind === "bytes",
      "content-type-protobuf": String(contentType).startsWith("application/protobuf"),
      "protobuf-decodes": isObject(fields),
      "run-in-document": fields?.run?.stringValue === run,
    };
    needRequest(f, checks);
    return verdict(
      checks,
      { dataKind: f.data?.kind ?? null, contentType, decodes: isObject(fields) },
      { dataKind: "bytes", contentType: "application/protobuf" },
    );
  });

  needSent("firestore-attributes", ["fs-create"], () => {
    const r = raw("firestoreCreated");
    if (r.missing) return result("not-delivered", null, null, ["no raw frame"]);
    const names = attributeNames(r.frame);
    const missing = FIRESTORE_ATTRIBUTES.filter((n) => !names.includes(n));
    const allStrings = Object.values(r.frame.attributes ?? {}).every((v) => typeof v === "string");
    return verdict(
      { "required-attributes": missing.length === 0, "all-strings": allStrings },
      {
        names,
        missing,
        extra: names.filter((n) => ![...FIRESTORE_ATTRIBUTES, "datacontenttype"].includes(n)),
      },
      { names: FIRESTORE_ATTRIBUTES },
    );
  });

  needSent("firestore-sdk", ["fs-create", "fs-update"], () => {
    const created = sdk("firestoreCreated");
    const updated = framesOf(frames, FAMILIES.firestoreUpdated.sdk, run);
    if (created.length === 0 || updated.length === 0)
      return result("not-delivered", { created: created.length, updated: updated.length }, null, [
        "an SDK frame is missing",
      ]);
    const before = updated[0].before?.data;
    const after = updated[0].after?.data;
    return verdict(
      {
        "created-n": created[0].snapshot?.data?.n === 1,
        "updated-before": before?.n === 1,
        "updated-after": after?.n === 2,
        "created-params": isObject(created[0].params) && typeof created[0].params.id === "string",
      },
      { created: created[0].snapshot?.data ?? null, before: before ?? null, after: after ?? null },
      { created: { n: 1 }, before: { n: 1 }, after: { n: 2 } },
    );
  });

  for (const [label, key] of [
    ["plain", "ps-plain"],
    ["ordered", "ps-ordered"],
  ]) {
    needSent("pubsub-keys-" + label, [key], () => {
      const r = raw("pubsub", label);
      if (r.missing) return result("not-delivered", null, null, ["no raw frame"]);
      const m = messageOf(r.frame);
      const keys = sorted(Object.keys(isObject(m) ? m : {}));
      const checks = {
        "message-id": typeof m?.messageId === "string",
        "publish-time": typeof m?.publishTime === "string",
        "snake-message-id": typeof m?.message_id === "string",
        "snake-publish-time": typeof m?.publish_time === "string",
        "no-snake-ordering-key": !Object.hasOwn(isObject(m) ? m : {}, "ordering_key"),
        ...(label === "ordered"
          ? { "ordering-key": m?.orderingKey === "pycheck-key" }
          : { "no-ordering-key": !Object.hasOwn(isObject(m) ? m : {}, "orderingKey") }),
      };
      return verdict(
        checks,
        {
          messageKeys: keys,
          contentType: contentTypeOf(r.frame),
          attributeNames: attributeNames(r.frame),
        },
        { snakeCase: ["message_id", "publish_time"] },
      );
    });
    needSent("pubsub-sdk-" + label, [key], () => {
      const frames_ = sdk("pubsub").filter((f) => f.attributes?.label === label);
      if (frames_.length === 0)
        return result("not-delivered", null, null, ["no SDK frame (see errors)"]);
      const f = frames_[0];
      return verdict(
        {
          "publish-time": typeof f.publish_time === "string",
          "message-id": typeof f.message_id === "string",
          "ordering-key":
            label === "ordered" ? f.ordering_key === "pycheck-key" : f.ordering_key === null,
        },
        { publish_time: f.publish_time ?? null, ordering_key: f.ordering_key ?? null },
        {},
      );
    });
  }

  needSent("storage-time", ["st-upload"], () => {
    const r = raw("storage");
    if (r.missing) return result("not-delivered", null, null, ["no raw frame"]);
    const time = r.frame.attributes?.time ?? null;
    const s = sdk("storage");
    return verdict(
      { "time-has-fraction": fractionDigits(time) > 0, "sdk-ran": s.length > 0 },
      { time, fractionDigits: fractionDigits(time), sdkFrames: s.length },
      { fractionDigits: ">0" },
    );
  });

  needSent("storage-shape", ["st-upload"], () => {
    const r = raw("storage");
    if (r.missing) return result("not-delivered", null, null, ["no raw frame"]);
    const data = r.frame.data?.value;
    const keys = sorted(Object.keys(isObject(data) ? data : {}));
    const missing = STORAGE_DATA_KEYS.filter((k) => !keys.includes(k));
    return verdict(
      { "sdk-required-keys": missing.length === 0, "data-is-json": r.frame.data?.kind === "json" },
      {
        attributeNames: attributeNames(r.frame),
        dataKeys: keys,
        missing,
        contentType: contentTypeOf(r.frame),
      },
      { dataKeys: STORAGE_DATA_KEYS },
    );
  });

  for (const [label, key, sent_] of [
    ["fraction", "ea-fraction", "2026-01-01T00:00:02.500Z"],
    ["whole", "ea-whole", "2026-01-01T00:00:02Z"],
  ]) {
    needSent("eventarc-time-" + label, [key], () => {
      const r = raw("eventarc", label);
      if (r.missing) return result("not-delivered", null, null, ["no raw frame"]);
      const time = r.frame.attributes?.time ?? null;
      const s = sdk("eventarc").filter((f) => f.data?.label === label);
      const observed = {
        time,
        fractionDigits: fractionDigits(time),
        sdkRan: s.length > 0,
        contentType: contentTypeOf(r.frame),
        attributeNames: attributeNames(r.frame),
      };
      // The fraction event must come through unchanged. What Eventarc does to a whole-second time has no expectation to
      // hold it to: it is the observation (the runner's lenient padding is for the emulator profile only).
      if (label === "whole")
        return result(
          "observed",
          observed,
          { sentTime: sent_ },
          time === sent_ ? ["preserved"] : ["changed"],
        );
      return verdict({ "time-preserved": time === sent_, "sdk-ran": s.length > 0 }, observed, {
        time: sent_,
      });
    });
  }

  needSent("eventarc-data", ["ea-fraction"], () => {
    const r = raw("eventarc", "fraction");
    if (r.missing) return result("not-delivered", null, null, ["no raw frame"]);
    return verdict(
      {
        "data-is-json": r.frame.data?.kind === "json",
        "run-in-data": r.frame.data?.value?.run === run,
        type: r.frame.attributes?.type === "pycheck.thing.v1.happened",
      },
      { dataKind: r.frame.data?.kind ?? null, attributeNames: attributeNames(r.frame) },
      { dataKind: "json" },
    );
  });

  needSent("scheduler-request", ["sched-pcschraw"], () => {
    const fn = FAMILIES.scheduler.raw;
    const frames_ = framesOf(frames, fn, null, { anyRun: true }).filter(
      (f) =>
        f.kind === "raw-request" && own(f.request, "headers")?.["x-cloudscheduler"] !== undefined,
    );
    if (frames_.length === 0) return result("not-delivered", null, null, ["no raw frame"]);
    const h = frames_[0].request.headers ?? {};
    const checks = {
      "x-cloudscheduler": h["x-cloudscheduler"] === "true",
      "job-id": h["x-cloudscheduler-jobname"] === jobId(fn),
      "schedule-time-los-angeles": SCHEDULE_TIME.test(h["x-cloudscheduler-scheduletime"] ?? ""),
      "user-agent": h["user-agent"] === "Google-Cloud-Scheduler",
      "content-length": h["content-length"] === "0",
      "x-forwarded-proto": h["x-forwarded-proto"] === "https",
      "accept-encoding": h["accept-encoding"] === "gzip, deflate, br",
      host: h.host === `${REGION}-${PROJECT}.cloudfunctions.net`,
      method: frames_[0].request.method === "POST",
    };
    const s = framesOf(frames, FAMILIES.scheduler.sdk, null, { anyRun: true });
    return verdict(
      checks,
      {
        headers: h,
        headerNames: frames_[0].request.header_names ?? null,
        sdkFrames: s.length,
        sdkJob: s[0]?.job_name ?? null,
        sdkTime: s[0]?.schedule_time ?? null,
      },
      { host: `${REGION}-${PROJECT}.cloudfunctions.net` },
    );
  });

  needSent("tasks-request", ["task-pctaskraw"], () => {
    const fn = FAMILIES.tasks.raw;
    const f = framesOf(frames, fn, run).find((x) => x.kind === "raw-request");
    if (!f) return result("not-delivered", null, null, ["no raw frame"]);
    const h = f.request?.headers ?? {};
    const names = f.request?.header_names ?? [];
    let body = null;
    try {
      body = JSON.parse(f.request?.body_text ?? "null");
    } catch {
      body = null;
    }
    const checks = {
      "content-type-json": String(h["content-type"] ?? "").startsWith("application/json"),
      "queue-name-header": h["x-cloudtasks-queuename"] === fn,
      "task-name-header": names.includes("x-cloudtasks-taskname"),
      "retry-count-header": names.includes("x-cloudtasks-taskretrycount"),
      "execution-count-header": names.includes("x-cloudtasks-taskexecutioncount"),
      "eta-header": names.includes("x-cloudtasks-tasketa"),
      "bearer-token":
        f.request?.authorization?.scheme === "Bearer" && f.request?.authorization?.segments === 3,
      "body-callable-format": isObject(body) && isObject(body.data) && body.data.run === run,
      method: f.request?.method === "POST",
    };
    const s = framesOf(frames, FAMILIES.tasks.sdk, run);
    return verdict(
      checks,
      {
        headers: h,
        headerNames: names,
        authorization: f.request?.authorization ?? null,
        body,
        sdkFrames: s.length,
      },
      {},
    );
  });

  const versions = {};
  for (const entry of frames) {
    const f = entry?.frame ?? entry;
    if (isObject(f?.versions)) versions[f.function] = f.versions;
  }
  const functionsVersions = new Set(Object.values(versions).map((v) => v["firebase-functions"]));
  cases["sdk-versions"] =
    Object.keys(versions).length === 0
      ? result("not-delivered", null, null, ["no frame carries versions"])
      : verdict(
          {
            "pinned-sdk":
              functionsVersions.size === 1 && functionsVersions.has(FIREBASE_FUNCTIONS_PY_VERSION),
          },
          { versions: Object.values(versions)[0], sdkVersionsSeen: [...functionsVersions] },
          { "firebase-functions": FIREBASE_FUNCTIONS_PY_VERSION },
        );

  const counts = { "as-expected": 0, differs: 0, observed: 0, "not-delivered": 0, "not-sent": 0 };
  for (const c of Object.values(cases)) counts[c.status] = (counts[c.status] ?? 0) + 1;
  return {
    run,
    mode,
    cases,
    counts,
    errors: errors.map((e) => ({
      function: e.function,
      timestamp: e.timestamp ?? null,
      text: e.text,
    })),
    complete: counts["not-delivered"] === 0 && counts["not-sent"] === 0,
  };
}
