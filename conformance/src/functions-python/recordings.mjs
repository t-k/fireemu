/** Offline, allowlisted projection of the two event recordings. No network or token inspection. */
import { compare } from "./compare.mjs";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const check = (ok, message) => {
  if (!ok) throw new Error(message);
};
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const functionFamilies = {
  pcfsc: "firestore-events",
  pcfscraw: "firestore-events",
  pcfsu: "firestore-events",
  pcps: "pubsub-events",
  pcpsraw: "pubsub-events",
  pcst: "storage-events",
  pcstraw: "storage-events",
  pcea: "eventarc-custom-events",
  pcearaw: "eventarc-custom-events",
  pcsch: "scheduler-events",
  pcschraw: "scheduler-events",
  pctask: "tasks-events",
  pctaskraw: "tasks-events",
};
const families = [...new Set(Object.values(functionFamilies))];
// The separate Tasks pass deployed the same handlers under queue names never used before
// (Cloud Tasks refuses to recreate a deleted queue name for days); queue = function id.
const tasksPassFunctions = { pc3task: "tasks-events", pc3taskraw: "tasks-events" };
const rawTaskFunctions = new Set(["pctaskraw", "pc3taskraw"]);
const sdkTaskFunctions = new Set(["pctask", "pc3task"]);
const profiles = {
  "pass-1": { name: "events", functions: functionFamilies, families },
  "pass-2": { name: "events", functions: functionFamilies, families },
  "tasks-pass-2": { name: "tasks", functions: tasksPassFunctions, families: ["tasks-events"] },
};
const headerNames = new Set(
  "accept accept-encoding authorization content-length content-type forwarded from function-execution-id host traceparent user-agent x-cloud-trace-context x-forwarded-for x-forwarded-proto ce-database ce-dataschema ce-document ce-id ce-location ce-namespace ce-project ce-source ce-specversion ce-subject ce-time ce-type ce-bucket x-cloudtasks-queuename x-cloudtasks-tasketa x-cloudtasks-taskexecutioncount x-cloudtasks-taskname x-cloudtasks-taskretrycount x-cloudscheduler x-cloudscheduler-jobname x-cloudscheduler-scheduletime".split(
    " ",
  ),
);
const headerValues = {
  "content-type": ["application/json", "application/protobuf"],
  "user-agent": [
    "APIs-Google; (+https://developers.google.com/webmasters/APIs-Google.html)",
    "Google-Cloud-Tasks",
    "Google-Cloud-Scheduler",
  ],
  "accept-encoding": ["gzip, deflate, br"],
  "x-forwarded-proto": ["https"],
  "x-cloudscheduler": ["true"],
};
const schema =
  "https://github.com/googleapis/google-cloudevents/blob/main/proto/google/events/cloud/firestore/v1/data.proto";
const eventTypes = new Set([
  "google.cloud.firestore.document.v1.created",
  "google.cloud.firestore.document.v1.updated",
  "google.cloud.pubsub.topic.v1.messagePublished",
  "google.cloud.storage.object.v1.finalized",
  "pycheck.thing.v1.happened",
]);

export function accountRecording(rows, result) {
  const recorderRequests = rows.filter((r) => r.state === "before-send").length;
  const persisted = rows.filter((r) => r.state === "response-persisted").length;
  check(
    result.attempted === recorderRequests &&
      result.completed === persisted &&
      persisted === recorderRequests,
    "recorder counters disagree with journal",
  );
  const cli = rows.filter((r) => r.state === "cli-write");
  check(
    cli.every((r) => Number.isSafeInteger(r.requests) && r.requests > 0),
    "invalid CLI attempt counter",
  );
  const cliWriteAttempts = cli.reduce((sum, r) => sum + r.requests, 0);
  return {
    recorderRequests,
    cliWriteRows: cli.length,
    cliWriteAttempts,
    accountedRequests: recorderRequests + cliWriteAttempts,
  };
}

function timeAlias(value) {
  check(typeof value === "string", "timestamp must be text");
  const m = value.match(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:\d\d)$/);
  check(m, "unrecorded timestamp format");
  return "2026-01-01T00:00:02" + (m[1] ? "." + "5".repeat(m[1].length - 1) : "") + m[2];
}
function numericAlias(value) {
  check(typeof value === "string" && /^\d+$/.test(value), "numeric identifier format");
  return "1".repeat(value.length);
}
function payload(value) {
  check(value && typeof value === "object" && !Array.isArray(value), "payload object required");
  check(
    Object.keys(value).every((key) => ["n", "run", "label"].includes(key)),
    "unrecorded payload field",
  );
  return Object.fromEntries(
    Object.entries(value).map(([key, v]) => {
      check(key === "n" ? Number.isSafeInteger(v) : typeof v === "string", "payload field type");
      return [key, key === "n" ? v : `fixture-${key}`];
    }),
  );
}
function baseEvent(type, time) {
  check(eventTypes.has(type), "unrecorded event type");
  return {
    specversion: "1.0",
    id: "fixture-event",
    source: "//example.invalid/fixture",
    type,
    time: timeAlias(time),
    datacontenttype: "application/json",
  };
}
function rawProjection(frame) {
  check(["sdk-event", "raw-event", "raw-request"].includes(frame.kind), "unrecorded frame kind");
  const out = { kind: frame.kind };
  if (frame.request) {
    const req = frame.request;
    check(req.method === "POST" && req.path === "/", "unrecorded request route");
    check(
      Array.isArray(req.header_names) && req.header_names.every((h) => headerNames.has(h)),
      "unrecorded header name",
    );
    const headers = {};
    for (const [key, allowed] of Object.entries(headerValues)) {
      if (Object.hasOwn(req.headers, key)) {
        check(allowed.includes(req.headers[key]), "unrecorded fixed header value");
        headers[key] = req.headers[key];
      }
    }
    out.request = { method: req.method, path: req.path, headerNames: req.header_names, headers };
  }
  if (frame.kind === "raw-event") {
    const a = frame.attributes;
    check(a.specversion === "1.0" && eventTypes.has(a.type), "unrecorded event attributes");
    check(
      ["application/json", "application/protobuf"].includes(a.datacontenttype),
      "unrecorded content type",
    );
    out.attributes = {
      type: a.type,
      specversion: a.specversion,
      datacontenttype: a.datacontenttype,
    };
    if (Object.hasOwn(a, "dataschema")) {
      check(a.dataschema === schema, "unrecorded schema");
      out.attributes.dataschema = a.dataschema;
    }
    out.fractionalTime = timeAlias(a.time).includes(".");
  }
  if (rawTaskFunctions.has(frame.function)) {
    const body = frame.request.body_text;
    check(
      typeof body === "string" && Buffer.byteLength(body) === frame.request.body_length,
      "recorded task byte length",
    );
    const value = JSON.parse(body);
    check(
      Object.keys(value).length === 1 &&
        value.data &&
        Object.keys(value.data).sort().join() === "label,run",
      "unrecorded task body",
    );
    payload(value.data);
    // JSON.parse above already rejects literal control characters inside string values.
    const lexical = body.match(
      /^(\s*\{\s*"data"\s*:\s*\{\s*"(run|label)"\s*:\s*)("[^"\\]*")(\s*,\s*"(run|label)"\s*:\s*)("[^"\\]*")(\s*\}\s*\}\s*)$/,
    );
    check(lexical && lexical[2] !== lexical[5], "unsupported task body lexical shape");
    out.bodyText =
      lexical[1] +
      JSON.stringify(`fixture-${lexical[2]}`) +
      lexical[4] +
      JSON.stringify(`fixture-${lexical[5]}`) +
      lexical[7];
    check(
      compare({ data: payload(value.data) }, JSON.parse(out.bodyText), "strict").length === 0,
      "masked task payload mismatch",
    );
    out.originalBodyBytes = frame.request.body_length;
    // Lengths of the masked string tokens (without quotes): a mask hides values, not lengths.
    out.originalValueBytes = {
      [lexical[2]]: Buffer.byteLength(lexical[3]) - 2,
      [lexical[5]]: Buffer.byteLength(lexical[6]) - 2,
    };
    out.layoutVerifiedAgainstRecordedLength = true;
  }
  if (sdkTaskFunctions.has(frame.function)) {
    check(
      typeof frame.has_app === "boolean" && typeof frame.has_auth === "boolean",
      "task context types",
    );
    out.hasApp = frame.has_app;
    out.hasAuth = frame.has_auth;
  }
  return out;
}
function sdkProjection(f, family) {
  const c = { origin: "observed-sdk-projection", inputIdentity: "synthetic", expected: {} };
  if (family === "firestore-events") {
    const updated = Object.hasOwn(f, "before"),
      event = baseEvent(f.type, f.time);
    Object.assign(event, {
      source: "//firestore.googleapis.com/projects/fixture-project/databases/(default)",
      subject: "documents/items/fixture-document",
      project: "fixture-project",
      location: "us-central1",
      database: "(default)",
      namespace: "(default)",
      document: "items/fixture-document",
    });
    const snapshots = Object.fromEntries(
      (updated ? ["before", "after"] : ["snapshot"]).map((key) => [key, payload(f[key].data)]),
    );
    const doc = (v) => ({
      name: "projects/fixture-project/databases/(default)/documents/items/fixture-document",
      fields: Object.fromEntries(
        Object.entries(v).map(([k, x]) => [
          k,
          typeof x === "number" ? { integerValue: String(x) } : { stringValue: x },
        ]),
      ),
    });
    event.data = { value: doc(updated ? snapshots.after : snapshots.snapshot) };
    if (updated) event.data.oldValue = doc(snapshots.before);
    Object.assign(c, {
      trigger: "firestore",
      variant: updated ? "updated" : "created",
      event,
      expected: snapshots,
    });
  } else if (family === "pubsub-events") {
    const event = baseEvent(f.type, f.time);
    check(f.ordering_key === null || typeof f.ordering_key === "string", "ordering key type");
    const expected = {
      attributes: payload(f.attributes),
      ordering_key: f.ordering_key ? "fixture-order" : f.ordering_key,
      message_id: numericAlias(f.message_id),
      publish_time: timeAlias(f.publish_time),
      subscription:
        "projects/fixture-project/subscriptions/eventarc-us-central1-fixture-111111-sub-111",
    };
    const message = {
      data: Buffer.from("fixture-message").toString("base64"),
      messageId: expected.message_id,
      publishTime: expected.publish_time,
      attributes: expected.attributes,
    };
    if (expected.ordering_key) message.orderingKey = expected.ordering_key;
    event.data = { message, subscription: expected.subscription };
    Object.assign(c, { trigger: "pubsub", event, expected });
  } else if (family === "storage-events") {
    const event = baseEvent(f.type, f.time);
    check(
      typeof f.size === "string" && /^\d+$/.test(f.size) && f.content_type === "application/json",
      "unrecorded object fields",
    );
    const expected = {
      bucket: "fixture-bucket.firebasestorage.app",
      name: "fixture-object",
      generation: numericAlias(f.generation),
      size: f.size,
      content_type: f.content_type,
    };
    event.data = {
      bucket: expected.bucket,
      name: expected.name,
      generation: expected.generation,
      size: expected.size,
      contentType: expected.content_type,
      id: `fixture-object/${expected.generation}`,
      metageneration: "1",
      storageClass: "STANDARD",
    };
    Object.assign(c, { trigger: "storage", event, expected });
  } else if (family === "eventarc-custom-events") {
    const event = baseEvent(f.type, f.time);
    event.data = payload(f.data);
    Object.assign(c, {
      trigger: "eventarc",
      event,
      expected: { data: payload(f.data), time: timeAlias(f.time) },
    });
  } else if (family === "tasks-events") {
    check(f.has_app === false && f.has_auth === false, "unrecorded task context");
    Object.assign(c, {
      trigger: "tasks",
      body: JSON.stringify({ data: payload(f.data) }),
      expected: { data: payload(f.data), has_app: f.has_app, has_auth: f.has_auth },
    });
  } else if (family === "scheduler-events") {
    const instant = timeAlias(f.schedule_time),
      utc = new Date(instant).toISOString().replace(".000Z", "Z");
    Object.assign(c, {
      trigger: "schedule",
      event: {
        data: {
          jobName: "projects/fixture-project/locations/us-central1/jobs/fixture-job",
          scheduleTime: utc,
        },
      },
      expected: { job_name: "fixture-job", schedule_time: instant },
    });
  } else throw new Error("unrecorded SDK family");
  return c;
}

/** Receipts remain private: callers must never include privateCustody in a public fixture. */
export function extractRecording(journalText, resultText, alias) {
  check(Object.hasOwn(profiles, alias), "recording alias");
  const profile = profiles[alias];
  const rows = journalText
      .trim()
      .split(/\r?\n/)
      .map((line) => JSON.parse(line)),
    result = JSON.parse(resultText);
  const accounting = accountRecording(rows, result),
    entries = new Map();
  for (const row of rows) {
    if (
      row.state !== "response-persisted" ||
      !/^logs-(observe-\d+|final)-frames$/.test(row.id) ||
      !row.bodyBase64
    )
      continue;
    const response = JSON.parse(Buffer.from(row.bodyBase64, "base64"));
    for (const entry of response.entries ?? []) {
      if (typeof entry.textPayload !== "string" || !entry.textPayload.startsWith("PYCHECK_FRAME "))
        continue;
      check(
        typeof entry.insertId === "string" && entry.insertId.length > 0,
        "log entry identity missing",
      );
      const previous = entries.get(entry.insertId);
      check(
        previous === undefined || previous === entry.textPayload,
        "contradictory duplicate log entry",
      );
      entries.set(entry.insertId, entry.textPayload);
    }
  }
  const frames = [...entries.values()].map((text) =>
    JSON.parse(text.slice("PYCHECK_FRAME ".length)),
  );
  check(frames.length > 0, "no recorded frames");
  const counts = {};
  for (const f of frames) {
    check(Object.hasOwn(profile.functions, f.function), "unrecorded function");
    counts[f.function] = (counts[f.function] ?? 0) + 1;
  }
  check(
    Object.keys(result.frames).length === Object.keys(counts).length &&
      Object.entries(counts).every(([k, v]) => result.frames[k] === v),
    "result/frame count disagreement",
  );
  const observations = profile.families.map((family) => {
    const selected = frames.filter((f) => profile.functions[f.function] === family);
    const row = {
      condition: family,
      origin: "masked-production-projection",
      observedPasses: selected.length ? 1 : 0,
      coverage: selected.length ? "RECORDED" : "UNOBSERVED",
      frames: selected.map(rawProjection),
      sdkCases: selected.filter((f) => f.kind === "sdk-event").map((f) => sdkProjection(f, family)),
    };
    if (!selected.length)
      row.reason =
        "No frame was recorded for this family; this is not evidence of successful delivery or correct no-delivery behavior.";
    if (family === "eventarc-custom-events") {
      const raw = row.frames.filter((f) => f.kind === "raw-event");
      check(
        raw.length === 2 &&
          raw.some((f) => f.fractionalTime) &&
          raw.some((f) => !f.fractionalTime) &&
          row.sdkCases.length === 1,
        "Eventarc absence coverage incomplete",
      );
      row.wholeSecondSdkFrames = 0;
      row.wholeSecondInput = { ...row.sdkCases[0].event, time: "2026-01-01T00:00:02Z" };
    }
    return row;
  });
  for (const row of observations) {
    const index = families.indexOf(row.condition),
      expectedFrames = [3, 4, 2, 3, 2, 2][index],
      expectedSdk = [2, 2, 1, 1, 1, 1][index];
    check(
      (row.frames.length === expectedFrames && row.sdkCases.length === expectedSdk) ||
        (profile.name === "events" &&
          row.condition === "tasks-events" &&
          row.frames.length === 0 &&
          row.sdkCases.length === 0),
      "incomplete recorded family",
    );
  }
  return {
    fixture: {
      schemaVersion: 1,
      recording: {
        alias,
        ...(profile.name === "events" ? {} : { profile: profile.name }),
        accounting,
        eventFrames: frames.length,
        functionFrameCategories: Object.keys(counts).length,
      },
      versions: {
        "firebase-functions": "0.6.0",
        "firebase-tools": "15.28.2",
        runtime: "python312",
      },
      observations,
    },
    privateCustody: {
      journalSha256: sha(journalText),
      resultSha256: sha(resultText),
      selectedLogEntries: entries.size,
      entryIdentityHashes: [...entries.keys()].map((id) => sha(id)).sort(),
      entryIdentitySha256: sha(JSON.stringify([...entries.keys()].sort())),
    },
  };
}

export function extractPair(first, second) {
  check(
    first.privateCustody.journalSha256 !== second.privateCustody.journalSha256 &&
      first.privateCustody.entryIdentitySha256 !== second.privateCustody.entryIdentitySha256,
    "same original recording cannot count twice",
  );
  const firstEntries = new Set(first.privateCustody.entryIdentityHashes);
  check(
    second.privateCustody.entryIdentityHashes.every((id) => !firstEntries.has(id)),
    "overlapping original recordings cannot count twice",
  );
  check(
    first.fixture.recording.alias === "pass-1" && second.fixture.recording.alias === "pass-2",
    "ordered independent aliases required",
  );
  return [first.fixture, second.fixture];
}

/** The Tasks-only pass counts as independent only if no original log entry is shared with pass 1. */
export function extractTasksPass(first, tasks) {
  check(
    first.fixture.recording.alias === "pass-1" && tasks.fixture.recording.alias === "tasks-pass-2",
    "ordered independent aliases required",
  );
  check(
    first.privateCustody.journalSha256 !== tasks.privateCustody.journalSha256,
    "same original recording cannot count twice",
  );
  const firstEntries = new Set(first.privateCustody.entryIdentityHashes);
  check(
    tasks.privateCustody.entryIdentityHashes.every((id) => !firstEntries.has(id)),
    "overlapping original recordings cannot count twice",
  );
  return tasks.fixture;
}

/** CLI: two explicit journal/result pairs; only the safe pair is written to stdout. */
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (process.argv[2] === "--compare") {
      check(
        process.argv.length === 5,
        "usage: recordings.mjs --compare FIRST_FIXTURE SECOND_FIXTURE",
      );
      const a = JSON.parse(readFileSync(process.argv[3], "utf8")),
        b = JSON.parse(readFileSync(process.argv[4], "utf8"));
      process.stdout.write(JSON.stringify(compareRecordings(a, b), null, 2) + "\n");
    } else if (process.argv[2] === "--tasks") {
      check(
        process.argv.length === 8,
        "usage: recordings.mjs --tasks FIRST_JOURNAL FIRST_RESULT TASKS_JOURNAL TASKS_RESULT PRIVATE_CUSTODY",
      );
      const args = process.argv.slice(3),
        custody = resolve(args[4]);
      check(
        custody.split(/[\\/]/).includes("docs.local"),
        "custody output must be inside docs.local",
      );
      const a = extractRecording(
        readFileSync(args[0], "utf8"),
        readFileSync(args[1], "utf8"),
        "pass-1",
      );
      const t = extractRecording(
        readFileSync(args[2], "utf8"),
        readFileSync(args[3], "utf8"),
        "tasks-pass-2",
      );
      const fixture = extractTasksPass(a, t);
      writeFileSync(custody, JSON.stringify([a.privateCustody, t.privateCustody], null, 2) + "\n", {
        flag: "wx",
      });
      process.stdout.write(JSON.stringify(fixture, null, 2) + "\n");
    } else {
      check(
        process.argv.length === 7,
        "usage: recordings.mjs FIRST_JOURNAL FIRST_RESULT SECOND_JOURNAL SECOND_RESULT PRIVATE_CUSTODY",
      );
      const args = process.argv.slice(2),
        custody = resolve(args[4]);
      check(
        custody.split(/[\\/]/).includes("docs.local"),
        "custody output must be inside docs.local",
      );
      const a = extractRecording(
        readFileSync(args[0], "utf8"),
        readFileSync(args[1], "utf8"),
        "pass-1",
      );
      const b = extractRecording(
        readFileSync(args[2], "utf8"),
        readFileSync(args[3], "utf8"),
        "pass-2",
      );
      const pair = extractPair(a, b);
      writeFileSync(custody, JSON.stringify([a.privateCustody, b.privateCustody], null, 2) + "\n", {
        flag: "wx",
      });
      process.stdout.write(JSON.stringify(pair, null, 2) + "\n");
    }
  } catch (error) {
    process.stderr.write(
      `recording extraction failed: ${error instanceof SyntaxError ? "invalid JSON" : error.message}\n`,
    );
    process.exitCode = 1;
  }
}

/**
 * True when every difference is a masked task value length and the remaining body bytes
 * (keys, punctuation, whitespace, quotes) are equal in both recordings.
 */
function valueLengthsOnly(a, b, differences) {
  const pattern = /^frames\.(\d+)\.(originalBodyBytes|originalValueBytes\.(run|label))$/;
  if (!differences.every((d) => pattern.test(d.path))) return false;
  const indexes = new Set(differences.map((d) => Number(d.path.match(pattern)[1])));
  const layout = (f) =>
    f.originalBodyBytes - Object.values(f.originalValueBytes).reduce((sum, n) => sum + n, 0);
  return [...indexes].every((i) => {
    const x = a.frames[i],
      y = b.frames[i];
    return (
      x.bodyText === y.bodyText &&
      Object.keys(x.originalValueBytes).toSorted().join() === "label,run" &&
      Object.keys(y.originalValueBytes).toSorted().join() === "label,run" &&
      layout(x) === layout(y)
    );
  });
}

export function compareRecordings(first, second) {
  check(first.recording.alias !== second.recording.alias, "distinct aliases required");
  check(
    second.recording.profile === undefined || second.recording.profile === "tasks",
    "known recording profile required",
  );
  const tasksOnly = second.recording.profile === "tasks";
  first = {
    ...first,
    observations: first.observations.filter(
      (r) =>
        !["auth-blocking", "deployment"].includes(r.condition) &&
        (!tasksOnly || r.condition === "tasks-events"),
    ),
  };
  second = {
    ...second,
    observations: second.observations.filter(
      (r) => !["auth-blocking", "deployment"].includes(r.condition),
    ),
  };
  for (const r of [...first.observations, ...second.observations]) {
    check(families.includes(r.condition), "known events family required");
    check(["RECORDED", "UNOBSERVED"].includes(r.coverage), "known coverage required");
    check(
      r.coverage !== "UNOBSERVED" || (r.frames.length === 0 && r.sdkCases.length === 0),
      "unobserved family cannot contain frames",
    );
  }
  check(
    JSON.stringify(first.observations.map((r) => r.condition)) ===
      JSON.stringify(second.observations.map((r) => r.condition)),
    "same family inventory required",
  );
  const canonical = (value, path = []) => {
    if (Array.isArray(value)) {
      const items = value.map((v, i) => canonical(v, [...path, i]));
      const unordered =
        (path.length === 1 && ["frames", "sdkCases"].includes(path[0])) ||
        (path.length === 4 &&
          path[0] === "frames" &&
          path[2] === "request" &&
          path[3] === "headerNames");
      return unordered
        ? items.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)))
        : items;
    }
    if (value && typeof value === "object")
      return Object.fromEntries(
        Object.keys(value)
          .sort()
          .map((k) => [k, canonical(value[k], [...path, k])]),
      );
    return value;
  };
  return first.observations.map((a, i) => {
    const b = second.observations[i],
      observedPasses = [a, b].filter((r) => r.coverage === "RECORDED").length;
    const projection = (r) =>
      canonical({
        frames: r.frames,
        sdkCases: r.sdkCases,
        ...(r.condition === "eventarc-custom-events"
          ? { wholeSecondSdkFrames: r.wholeSecondSdkFrames, wholeSecondInput: r.wholeSecondInput }
          : {}),
      });
    const pa = projection(a),
      pb = projection(b);
    const differences = observedPasses === 2 ? compare(pa, pb, "strict") : [];
    return {
      condition: a.condition,
      status:
        observedPasses < 2
          ? "UNOBSERVED"
          : !differences.length
            ? "MATCH"
            : valueLengthsOnly(pa, pb, differences)
              ? "MATCH_LAYOUT"
              : "DIFF",
      observedPasses,
      differences,
    };
  });
}
