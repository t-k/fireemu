// Adapters from the two record formats of record-schema.md to comparator observations. The run
// record's top-level shape is the contract: anything else is refused. Inside a valid record, a
// malformed operation or frame is kept with an issue, so the rows that need it report INCOMPLETE
// with a reason instead of being dropped.
import { resourceMatches } from "../session.mjs";

const SOURCE_RESULTS = new Set(["typed-success", "typed-refusal", "typed-absent"]);
const KEY_KINDS = new Set(["firestore", "storage", "auth", "pubsub"]);
const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const isText = (value) => typeof value === "string" && value.length > 0;

const timePattern =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(?:Z|([+-])(\d{2}):(\d{2}))$/;

/** Milliseconds since the epoch (fractional, nanosecond digits kept) of an ISO-8601 time, or null. */
export function parseTimeMs(text) {
  if (typeof text !== "string") return null;
  const match = timePattern.exec(text);
  if (!match) return null;
  const [, y, mo, d, h, mi, s, fraction, sign, oh, om] = match;
  const whole = Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s));
  const check = new Date(whole);
  if (
    check.getUTCFullYear() !== Number(y) ||
    check.getUTCMonth() !== Number(mo) - 1 ||
    check.getUTCDate() !== Number(d) ||
    check.getUTCHours() !== Number(h) ||
    check.getUTCMinutes() !== Number(mi) ||
    check.getUTCSeconds() !== Number(s)
  ) {
    return null;
  }
  const nanos = fraction ? Number(fraction.padEnd(9, "0")) : 0;
  const offset = sign ? (sign === "-" ? -1 : 1) * (Number(oh) * 60 + Number(om)) * 60_000 : 0;
  return whole + nanos / 1e6 - offset;
}

/** The event's own time (v1 context.timestamp, v2 time), chosen by the frame's generation. */
export function eventTimeMs(frame) {
  if (!isObject(frame)) return null;
  if (frame.generation === 1) return parseTimeMs(frame.event?.context?.timestamp);
  if (frame.generation === 2) return parseTimeMs(frame.event?.time);
  return null;
}

/** True when a matchKey has one of the contract's role shapes. */
export function validMatchKey(key) {
  if (!isObject(key) || !KEY_KINDS.has(key.kind)) return false;
  if (key.bucket !== undefined && !isText(key.bucket)) return false;
  if (key.values !== undefined) {
    return (
      key.kind === "auth" &&
      Array.isArray(key.values) &&
      key.values.length > 0 &&
      key.values.every(isText)
    );
  }
  return isText(key.value);
}

function operationIssues(op) {
  const issues = [];
  if (typeof op.scenarioId !== "string") issues.push("operation scenarioId is not a string");
  if (typeof op.role !== "string") issues.push("operation role is not a string");
  if (!SOURCE_RESULTS.has(op.sourceResult)) issues.push("operation sourceResult is not a typed result");
  const startMs = parseTimeMs(op.startedAt);
  const endMs = parseTimeMs(op.endedAt);
  if (startMs === null) issues.push("operation startedAt is not an ISO time");
  if (endMs === null) issues.push("operation endedAt is not an ISO time");
  if (startMs !== null && endMs !== null && endMs < startMs) {
    issues.push("operation endedAt is before startedAt");
  }
  if (!validMatchKey(op.matchKey)) issues.push("operation matchKey is not a valid role key");
  if (!(typeof op.windowSeconds === "number" && op.windowSeconds > 0)) {
    issues.push("operation windowSeconds is not a positive number");
  }
  return { startMs, endMs, issues };
}

function frameIssues(entry) {
  const issues = [];
  if (!isText(entry.insertId)) issues.push("frame insertId is missing");
  const logMs = parseTimeMs(entry.logTimestamp);
  if (logMs === null) issues.push("frame logTimestamp is not an ISO time");
  if (!isText(entry.handler)) issues.push("frame handler is missing");
  if (entry.generation !== 1 && entry.generation !== 2) issues.push("frame generation is not 1 or 2");
  if (!isObject(entry.frame)) {
    issues.push("frame is not a JSON object");
  } else {
    if (entry.frame.handler !== entry.handler) {
      issues.push("frame handler disagrees with the record handler");
    }
    if (entry.frame.generation !== entry.generation) {
      issues.push("frame generation disagrees with the record generation");
    }
  }
  const eventMs = eventTimeMs(entry.frame);
  if (eventMs === null) issues.push("frame has no event time for its generation");
  return { logMs, eventMs, issues };
}

const frameContent = (entry) =>
  JSON.stringify([entry.logTimestamp, entry.handler, entry.generation, entry.source, entry.frame]);

/** Read a production run record (record-schema.md) into passes, operations and frames. */
export function fromProductionRun(record) {
  if (!isObject(record)) throw new TypeError("production run must be a JSON object");
  if (record.schemaVersion !== 1) throw new TypeError("production run schemaVersion must be 1");
  if (record.kind !== "functions-events-production-run") {
    throw new TypeError("production run kind must be functions-events-production-run");
  }
  if (!isText(record.project)) throw new TypeError("production run project is required");
  if (!/^[0-9a-f]{64}$/.test(record.corpusDigest ?? "")) {
    throw new TypeError("production run corpusDigest must be a sha256 hex digest");
  }
  if (!Array.isArray(record.passes) || record.passes.length !== 2) {
    throw new TypeError("production run must have exactly two passes");
  }
  if (record.passes[0]?.pass !== 1 || record.passes[1]?.pass !== 2) {
    throw new TypeError("production run passes must be pass 1 and pass 2 in order");
  }
  if (!Array.isArray(record.frames)) throw new TypeError("production run frames must be an array");

  const passes = record.passes.map((pass) => {
    if (!Array.isArray(pass.operations)) {
      throw new TypeError(`production pass ${pass.pass} operations must be an array`);
    }
    return {
      pass: pass.pass,
      operations: pass.operations.map((op, index) => ({
        ...op,
        pass: pass.pass,
        index,
        ...operationIssues(isObject(op) ? op : {}),
      })),
    };
  });

  const seen = new Map();
  const frames = [];
  let duplicateFrames = 0;
  for (const entry of record.frames) {
    const raw = isObject(entry) ? entry : {};
    const frame = { ...raw, ...frameIssues(raw) };
    if (isText(raw.insertId) && seen.has(raw.insertId)) {
      const first = seen.get(raw.insertId);
      if (frameContent(first.raw) === frameContent(raw)) {
        duplicateFrames += 1;
        continue;
      }
      const issue = "insertId read with different content";
      for (const other of [first.frame, frame]) {
        if (!other.issues.includes(issue)) other.issues.push(issue);
      }
    } else if (isText(raw.insertId)) {
      seen.set(raw.insertId, { raw, frame });
    }
    frames.push(frame);
  }
  return { project: record.project, corpusDigest: record.corpusDigest, passes, frames, duplicateFrames };
}

function localFrames(op, issues) {
  const frames = { 1: [], 2: [] };
  for (const generation of [1, 2]) {
    const list = op.framesByGeneration?.[`v${generation}`] ?? [];
    for (const entry of Array.isArray(list) ? list : []) {
      const label = `local v${generation} frame ${entry?.sequence}`;
      if (typeof entry?.rawJson !== "string") {
        issues.push(`${label} has no rawJson`);
        continue;
      }
      let frame;
      try {
        frame = JSON.parse(entry.rawJson);
      } catch {
        frame = undefined;
      }
      if (!isObject(frame)) {
        issues.push(`${label} rawJson is not a JSON object`);
      } else if (frame.generation !== generation) {
        issues.push(`${label} generation disagrees with its list`);
      } else if (!validMatchKey(op.matchKey) || !resourceMatches(frame, op.matchKey)) {
        issues.push(`${label} does not match the operation matchKey`);
      } else {
        frames[generation].push({ sequence: entry.sequence, frame });
      }
    }
  }
  return frames;
}

/** Read a local driver session.json (one profile) into programs keyed by recipeId. */
export function fromLocalSession(session) {
  if (!isObject(session)) throw new TypeError("local session must be a JSON object");
  if (session.schemaVersion !== 1) throw new TypeError("local session schemaVersion must be 1");
  if (session.authority !== "LOCAL_ONLY") throw new TypeError("local session must be LOCAL_ONLY");
  if (!Array.isArray(session.programs)) throw new TypeError("local session programs must be an array");
  const programs = new Map();
  for (const program of session.programs) {
    if (!isObject(program) || !isText(program.recipeId)) {
      throw new TypeError("local session program needs a recipeId");
    }
    if (programs.has(program.recipeId)) {
      throw new TypeError(`local session lists ${program.recipeId} twice`);
    }
    if (!Array.isArray(program.operations)) {
      throw new TypeError(`local session ${program.recipeId} operations must be an array`);
    }
    programs.set(program.recipeId, {
      recipeId: program.recipeId,
      operations: program.operations.map((op, index) => {
        const raw = isObject(op) ? op : {};
        const issues = [];
        if (typeof raw.scenarioId !== "string") issues.push("local operation scenarioId is not a string");
        if (typeof raw.role !== "string") issues.push("local operation role is not a string");
        if (!validMatchKey(raw.matchKey)) issues.push("local operation matchKey is not a valid role key");
        const frames = localFrames(raw, issues);
        return {
          index,
          scenarioId: raw.scenarioId,
          role: raw.role,
          status: raw.status,
          sourceResult: raw.sourceResult,
          readback: raw.readback,
          matchKey: raw.matchKey,
          frames,
          issues,
        };
      }),
    });
  }
  return { programs };
}
