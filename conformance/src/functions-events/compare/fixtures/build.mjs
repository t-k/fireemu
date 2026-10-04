// Test builders for comparator inputs in the record-schema.md shapes. Test-only; no I/O.

export const PRODUCTION_PROJECT = "fireemu-oracle-events";
export const LOCAL_PROJECT = "demo-conformance";
export const T0 = Date.UTC(2026, 9, 4, 0, 0, 0);
export const iso = (ms) => new Date(ms).toISOString();
/** An ISO time with six fraction digits, the precision of v2 event times. */
export const isoMicros = (ms) => iso(Math.floor(ms)).replace("Z", `${String(Math.round((ms % 1) * 1000)).padStart(3, "0")}Z`);

export function op({
  scenarioId,
  role = "subject",
  sourceResult = "typed-success",
  start,
  end = start + 1000,
  matchKey,
  readback = { exists: true },
  windowSeconds = 120,
}) {
  return { scenarioId, role, sourceResult, startedAt: iso(start), endedAt: iso(end), matchKey, readback, windowSeconds };
}

let insertCounter = 0;
export function frameEntry(frame, logMs, insertId = `insert-${(insertCounter += 1)}`) {
  return {
    insertId,
    logTimestamp: isoMicros(logMs),
    readAt: iso(logMs + 30_000),
    handler: frame.handler,
    generation: frame.generation,
    source: frame.source,
    frame,
  };
}

export function productionRun(pass1, pass2, frames, overrides = {}) {
  return {
    schemaVersion: 1,
    kind: "functions-events-production-run",
    project: PRODUCTION_PROJECT,
    corpusDigest: "0".repeat(64),
    recordedAt: iso(T0),
    passes: [
      { pass: 1, startedAt: iso(T0), endedAt: iso(T0 + 3_600_000), operations: pass1 },
      { pass: 2, startedAt: iso(T0 + 3_600_000), endedAt: iso(T0 + 7_200_000), operations: pass2 },
    ],
    frames,
    cleanup: {},
    deploy: {},
    ...overrides,
  };
}

export function localOp({ scenarioId, role = "subject", matchKey, sourceResult = "typed-success", readback = { exists: true }, status = "LOCAL_OBSERVATION", v1 = [], v2 = [] }) {
  let sequence = 0;
  const entries = (frames) =>
    frames.map((frame) => ({ sequence: (sequence += 1), receivedAt: iso(T0), rawJson: JSON.stringify(frame) }));
  return { scenarioId, role, status, sourceResult, readback, cleanup: { checked: true }, matchKey, cursor: 0, windowMs: 5000, framesByGeneration: { v1: entries(v1), v2: entries(v2) }, error: null };
}

/** The identity run.mjs writes into a session: the binary it ran, the harness commit and whether the tree was dirty. */
export const LOCAL_BINARY = Object.freeze({ binarySha256: "b".repeat(64), sourceCommit: "c".repeat(40), dirty: false });

export function localSession(programs, fireemu = LOCAL_BINARY) {
  return {
    schemaVersion: 1,
    ...(fireemu === null ? {} : { fireemu }),
    parent: "FUNCTIONS-EVENTS",
    status: "LOCAL_OBSERVATION",
    authority: "LOCAL_ONLY",
    productionEvidence: null,
    programs: programs.map(({ recipeId, operations }) => ({ recipeId, status: "LOCAL_OBSERVATION", operations, cases: [] })),
  };
}

const snapshot = (path, data, seconds) => ({
  exists: data !== null,
  id: path.split("/").at(-1),
  path,
  data,
  createTime: data === null ? null : { _seconds: seconds, _nanoseconds: 120_000_000 },
  updateTime: data === null ? null : { _seconds: seconds, _nanoseconds: 120_000_000 },
});

/** A Firestore frame in the fixture's print form (report.js), v1 or v2. */
export function firestoreFrame({ handler, generation, project, path, eventId, timeMs, data = { value: "created", count: 1 }, before, fixtureAttempt }) {
  const seconds = Math.floor(timeMs / 1000);
  const after = snapshot(path, data, seconds);
  const payload = before === undefined ? after : { before: snapshot(path, before, seconds - 5), after };
  if (fixtureAttempt) payload.fixtureAttempt = fixtureAttempt;
  const documentId = path.split("/").at(-1);
  if (generation === 1) {
    return {
      handler,
      generation,
      source: "firestore",
      event: {
        context: {
          eventId,
          timestamp: isoMicros(timeMs),
          eventType: "google.firestore.document.create",
          resource: { name: `projects/${project}/databases/(default)/documents/${path}`, service: "firestore.googleapis.com" },
          params: { documentId },
          authType: null,
          authId: null,
        },
        data: payload,
      },
    };
  }
  return {
    handler,
    generation,
    source: "firestore",
    event: {
      id: eventId,
      time: isoMicros(timeMs),
      type: "google.cloud.firestore.document.v1.created",
      source: `//firestore.googleapis.com/projects/${project}/databases/(default)`,
      subject: `documents/${path}`,
      specversion: "1.0",
      datacontenttype: null,
      params: { documentId },
      authType: null,
      authId: null,
      data: payload,
    },
  };
}

/** Replace every occurrence of each [from, to] pair in a JSON value (string level). */
export function rekey(value, pairs) {
  let text = JSON.stringify(value);
  for (const [from, to] of pairs) text = text.split(from).join(to);
  return JSON.parse(text);
}
