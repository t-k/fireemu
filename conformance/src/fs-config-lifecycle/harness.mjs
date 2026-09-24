// Pure building blocks of the FS-CONFIG-LIFECYCLE sandbox harness: identifiers a run
// allocates, request construction, the request guard, response normalization and the
// comparison rules. Nothing here performs I/O.
//
// Production is only ever the disposable query sandbox (`SANDBOX_PROJECT`), and within it only
// the named databases a program creates (ids `cfg<run>-<letter>`), a Cloud Storage bucket the
// run creates, and read-only `GET` of `(default)` (scope decision C6). The local side is fireemu
// on a loopback port started with the same project id. Recorded values never contain the
// sandbox project id, its number, a token, a run-window time or an opaque server id.

import { isDeepStrictEqual } from "node:util";

export const SANDBOX_PROJECT = "fireemu-oracle-query";
export const RECORDED_PROJECT = "demo-fs-config";
export const PRODUCTION_ORIGIN = "https://firestore.googleapis.com";
export const STORAGE_ORIGIN = "https://storage.googleapis.com";
export const PRODUCTION_GRPC = { host: "firestore.googleapis.com", port: 443 };
/**
 * The FS-DATA-WRITE bisection project, used only for the (default) lifecycle program at its
 * cleanup (scope decision C9). It is the one place a program may delete or create (default).
 */
export const BISECT_PROJECT = "fireemu-fs-bisect-0924a";
/** A project id no one owns; production refuses it before it reaches any resource. */
export const FOREIGN_PROJECT = "fireemu-no-such-project-0924";
export const REQUEST_CAP = 2000;
/** The gRPC methods a step may call (scope decision C7); grpc.mjs maps them to services. */
export const GRPC_RPCS = new Set([
  "CreateDatabase",
  "GetDatabase",
  "ListDatabases",
  "DeleteDatabase",
  "CreateIndex",
  "GetIndex",
  "ExportDocuments",
  "ImportDocuments",
  "GetOperation",
]);
const LOOPBACK = new Set(["127.0.0.1", "localhost", "[::1]"]);

/**
 * Database ids production refuses as invalid, which the corpus names to observe that refusal.
 * They can never exist, so the guard admits reads of them and a create that names them;
 * nothing else. A missing but valid database is a program's own never-created letter `z`.
 */
export const UNCREATED_DATABASES = new Set(["Bad_Id", "ab", "a".repeat(64), "-leading-dash"]);

/**
 * Binds a run id and one target. The run id is the recording's start in whole seconds, which
 * keeps every allocated database id the same length on both sides.
 */
export function createContext({ run, target, startedMs = Date.now(), project = SANDBOX_PROJECT }) {
  if (!/^\d{10}$/.test(String(run))) throw new Error("run id must be ten digits");
  if (![SANDBOX_PROJECT, BISECT_PROJECT].includes(project))
    throw new Error(`project ${project} is not a sandbox`);
  if (target.kind === "production") {
    if (!target.token) throw new Error("production needs an access token");
    if (target.quotaProject !== project) throw new Error("quota project must be the run's project");
    if (!/^[a-z0-9-]{3,63}$/.test(String(target.bucket ?? "")))
      throw new Error("production needs the run bucket");
  } else if (target.kind === "local") {
    const url = new URL(target.origin);
    if (url.protocol !== "http:" || !LOOPBACK.has(url.hostname))
      throw new Error("local target must be a loopback http origin");
    if (!LOOPBACK.has(new URL(target.storageOrigin ?? target.origin).hostname))
      throw new Error("local Storage target must be a loopback origin");
    if (!LOOPBACK.has(String(target.grpcHost)) || !Number.isInteger(target.grpcPort))
      throw new Error("local gRPC target must be a loopback host and port");
  } else {
    throw new Error(`unknown target kind ${target.kind}`);
  }
  return {
    run: String(run),
    startedMs,
    project,
    target,
    bucket: target.bucket ?? `${project}-cfg-${run}`,
    window: { from: startedMs - 2 * 3_600_000, to: startedMs + 12 * 3_600_000 },
  };
}

/** The database id a program's symbolic database `letter` gets in this run. */
export const databaseId = (ctx, program, letter) =>
  `cfg${ctx.run}-${program.ordinal.toString(36).padStart(2, "0")}${letter}`;

export const projectName = (ctx, project = ctx.project) => `projects/${project}`;

function substitute(text, ctx, program) {
  return String(text)
    .replaceAll(/\{db:([a-z])\}/g, (_, letter) => databaseId(ctx, program, letter))
    .replaceAll("{foreign}", `projects/${FOREIGN_PROJECT}`)
    .replaceAll("{project}", projectName(ctx))
    .replaceAll("{bucket}", ctx.bucket)
    .replaceAll("{prefix}", `gs://${ctx.bucket}/${program.slug}`)
    .replaceAll("{objects}", `${program.slug}`);
}

function lookup(value, path) {
  let current = value;
  for (const segment of String(path).split(".")) {
    if (current === null || current === undefined) return undefined;
    current = current[segment];
  }
  return current;
}

/** A `$from` reference to an earlier step's raw answer. */
function chained(reference, raw) {
  const source = raw.get(reference.$from);
  const found = lookup(source, reference.path);
  if (found === undefined || found === "")
    throw new Error(`step ${reference.$from} recorded nothing at ${reference.path}`);
  return found;
}

/** Resolves placeholders and `$from` references in a request value. */
export function resolveValue(value, ctx, program, raw) {
  if (Array.isArray(value)) return value.map((v) => resolveValue(v, ctx, program, raw));
  if (value && typeof value === "object") {
    if (typeof value.$from === "string") return chained(value, raw);
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, resolveValue(v, ctx, program, raw)]),
    );
  }
  if (typeof value === "string") return substitute(value, ctx, program);
  return value;
}

/** The resolved path of a REST step: a template, or a resource name another step returned. */
export function stepPath(step, ctx, program, raw) {
  if (step.pathFrom) return `v1/${chained(step.pathFrom, raw)}${step.suffix ?? ""}`;
  return substitute(step.path, ctx, program);
}

/** The URL and fetch init for one REST step against the context's target. */
export function buildRestRequest(step, ctx, program, raw) {
  const service = step.service ?? "firestore";
  let origin;
  if (ctx.target.kind === "production")
    origin = service === "storage" ? STORAGE_ORIGIN : PRODUCTION_ORIGIN;
  else origin = service === "storage" ? ctx.target.storageOrigin : ctx.target.origin;
  const path = stepPath(step, ctx, program, raw);
  const query = step.query
    ? `?${new URLSearchParams(
        Object.entries(resolveValue(step.query, ctx, program, raw)).map(([k, v]) => [k, String(v)]),
      )}`
    : "";
  const headers = {
    authorization: `Bearer ${ctx.target.kind === "production" ? ctx.target.token : "owner"}`,
  };
  if (ctx.target.kind === "production") headers["x-goog-user-project"] = ctx.project;
  const init = { method: step.method ?? "GET", headers };
  if (step.body !== undefined) {
    headers["content-type"] = "application/json";
    init.body = JSON.stringify(resolveValue(step.body, ctx, program, raw));
  }
  return { url: `${origin}/${path}${query}`, init };
}

/** Which database ids a program may address, and how. */
export function programDatabases(ctx, program) {
  return new Set((program.databases ?? []).map((letter) => databaseId(ctx, program, letter)));
}

/**
 * The last check before a request leaves the process. A Firestore request must name the
 * sandbox project (or, when the step says so, the foreign project), and a database this
 * program created, `(default)` for a read of the database resource itself, or an id from
 * `UNCREATED_DATABASES`. A Storage request must address the run bucket. A request body may
 * only name the sandbox project's own program databases and the run bucket.
 */
export function guardRestRequest({ url, init }, ctx, program, { harness = false } = {}) {
  if ((program.project ?? SANDBOX_PROJECT) !== ctx.project)
    throw new Error(`${program.id} runs only against ${program.project ?? SANDBOX_PROJECT}`);
  const parsed = new URL(url);
  const raw = url.slice(parsed.origin.length).split("?")[0];
  // What is checked must be what fetch sends: a backslash or dot segment that URL parsing
  // rewrites would otherwise slip past the raw-path checks below.
  if (parsed.pathname !== raw) throw new Error(`request path is not canonical: ${raw}`);
  const own = programDatabases(ctx, program);
  const firestoreOrigin =
    ctx.target.kind === "production" ? PRODUCTION_ORIGIN : new URL(ctx.target.origin).origin;
  const storageOrigin =
    ctx.target.kind === "production" ? STORAGE_ORIGIN : new URL(ctx.target.storageOrigin).origin;
  if (parsed.origin === storageOrigin && /^\/(upload\/|download\/)?storage\//.test(raw)) {
    // Checked on the raw path: an object name is one percent-encoded segment (its slashes are
    // %2F), while the bucket segment must be a plain bucket name.
    const bucketPath =
      /^\/(?:upload\/|download\/)?storage\/v1\/b(?:\/([a-z0-9._-]+))?(?:\/o(?:\/([^/]+))?)?$/.exec(
        raw,
      );
    if (!bucketPath) throw new Error(`storage request outside the JSON API: ${raw}`);
    const object = bucketPath[2] === undefined ? undefined : decodeURIComponent(bucketPath[2]);
    if (object !== undefined && object.split("/").some((s) => s === "" || s === "." || s === ".."))
      throw new Error(`object name is not canonical: ${object}`);
    if (bucketPath[1] === undefined) {
      // Only the harness creates the run bucket, and only under the run's project.
      if (!harness || init.method !== "POST" || parsed.searchParams.get("project") !== ctx.project)
        throw new Error("only the harness may create a bucket");
    } else if (bucketPath[1] !== ctx.bucket) {
      throw new Error(`storage request outside the run bucket: ${bucketPath[1]}`);
    }
    return;
  }
  if (/%2e|%2f|\/\.\.?(\/|$)/i.test(raw)) throw new Error(`request path is not canonical: ${raw}`);
  const path = decodeURIComponent(parsed.pathname);
  if (parsed.origin !== firestoreOrigin)
    throw new Error(`request left the target: ${parsed.origin}`);
  const match = /^\/v1\/projects\/([^/]+)(\/.*)?$/.exec(path);
  if (!match) throw new Error(`request is not a project resource: ${path}`);
  const [, project, rest = ""] = match;
  if (project === FOREIGN_PROJECT) {
    if (init.method !== "GET") throw new Error("the foreign project is only read");
    return;
  }
  if (project !== ctx.project) throw new Error(`request names another project: ${project}`);
  const database = /^\/databases\/([^/:]+)/.exec(rest)?.[1];
  if (database !== undefined) {
    if (database === "(default)") {
      // C9: the (default) lifecycle program owns (default) in the bisection project only.
      const ownsDefault = program.defaultDatabase === true && ctx.project === BISECT_PROJECT;
      if (!ownsDefault && !(init.method === "GET" && rest === "/databases/(default)"))
        throw new Error("(default) may only be read as a database resource");
    } else if (UNCREATED_DATABASES.has(database)) {
      if (init.method !== "GET")
        throw new Error(`an invalid database id is only read: ${database}`);
    } else if (!own.has(database)) {
      throw new Error(`request names a database this program does not own: ${database}`);
    }
  } else if (rest === "/databases" && init.method === "POST") {
    const created = parsed.searchParams.get("databaseId");
    const ownsDefault = program.defaultDatabase === true && ctx.project === BISECT_PROJECT;
    if (created === "(default)" && ownsDefault) return;
    if (created !== null && !own.has(created) && !UNCREATED_DATABASES.has(created))
      throw new Error(`create names a database this program does not own: ${created}`);
  } else if (
    !["", "/databases", "/databases:restore", "/databases:clone"].includes(rest) &&
    !rest.startsWith("/locations")
  ) {
    throw new Error(`unexpected project resource ${rest}`);
  }
  if (rest === "/databases:restore" || rest === "/databases:clone")
    throw new Error("restore and clone are out of scope (C1)");
  if (/\/backupSchedules|\/backups/.test(rest)) throw new Error("backups are out of scope (C1)");
  // C1: point-in-time recovery is never enabled or configured.
  const mask = parsed.searchParams.get("updateMask") ?? "";
  if (
    /pointInTimeRecovery|versionRetentionPeriod/i.test(mask) ||
    /pointInTimeRecovery|versionRetentionPeriod/i.test(String(init.body ?? ""))
  )
    throw new Error("point-in-time recovery is out of scope (C1)");
  if (typeof init.body === "string") assertBodyScope(JSON.parse(init.body), ctx, own);
}

function walkStrings(value, visit) {
  if (typeof value === "string") visit(value);
  else if (Array.isArray(value)) for (const v of value) walkStrings(v, visit);
  else if (value && typeof value === "object")
    for (const v of Object.values(value)) walkStrings(v, visit);
}

/** A request body may name only the sandbox project, its program databases and the run bucket. */
function assertBodyScope(body, ctx, own) {
  walkStrings(body, (text) => {
    for (const [, project] of text.matchAll(/projects\/([^/\s"]+)/g)) {
      if (project !== ctx.project)
        throw new Error(`request body names another project: ${project}`);
    }
    for (const [, database] of text.matchAll(/databases\/([^/\s"]+)/g)) {
      if (!own.has(database)) throw new Error(`request body names a foreign database: ${database}`);
    }
    for (const [, bucket] of text.matchAll(/gs:\/\/([^/\s"]+)/g)) {
      if (bucket !== ctx.bucket && !bucket.startsWith("fireemu-no-such-bucket"))
        throw new Error(`request body names another bucket: ${bucket}`);
    }
  });
}

const TRANSIENT_STATUS = /^(RESOURCE_EXHAUSTED|UNAVAILABLE|DEADLINE_EXCEEDED)$/;

/**
 * A recorded answer that says nothing about behavior: a transport failure, a rate limit, or a
 * 5xx other than the one production answers deterministically (the caller decides that by
 * comparing both recordings).
 */
export function isTransient(recorded) {
  if (!recorded) return false;
  if (recorded.trace) return recorded.trace.some(isTransient) || isTransient(recorded.settled);
  if (recorded.status === -1) return recorded.dependencyTransient === true;
  if (recorded.transport === "grpc") return [4, 8, 14].includes(recorded.code);
  if (recorded.status === 0 || recorded.status === 429 || recorded.status === 503) return true;
  return TRANSIENT_STATUS.test(String(recorded.body?.error?.status ?? ""));
}

// Poll predicates, by name, evaluated on the raw answer (see session.mjs). They are part of
// the harness digest: a changed predicate makes every saved poll row stale.
export const UNTIL = {
  done: (json) => json?.done === true,
  ready: (json) => json?.state === "READY",
  notFound: (_json, status) => status === 404,
  httpError: (_json, status) => status >= 400,
  httpOk: (_json, status) => status === 200,
  // An applied exemption reads back as an index configuration that no longer inherits and
  // lists no index: production keeps naming the ancestor field, and proto3 JSON leaves out the
  // false usesAncestorConfig and the empty index list.
  exempt: (json) =>
    json?.indexConfig !== undefined &&
    json.indexConfig.usesAncestorConfig !== true &&
    (json.indexConfig.indexes ?? []).length === 0,
  inherits: (json) => json?.indexConfig?.usesAncestorConfig === true,
  ttlActive: (json) => json?.ttlConfig?.state === "ACTIVE",
  ttlGone: (json) => json?.ttlConfig === undefined,
  never: () => false,
};

/**
 * A quota refusal that says nothing about the resource: production's per-minute rate limits
 * (ErrorInfo reason RATE_LIMIT_EXCEEDED). Any other 429 (a TTL policy limit, a customer-managed
 * key quota) is behavior and is recorded.
 */
export function isRateLimited(status, json) {
  if (status !== 429) return false;
  const details =
    json?.error?.details ?? (Array.isArray(json) ? json[0]?.error?.details : undefined);
  return (details ?? []).some((d) => d?.reason === "RATE_LIMIT_EXCEEDED");
}

/**
 * Whether a request is a database operation production counts against its per-minute
 * database operation quota: any request on a database resource itself (create, get, list,
 * patch, delete), as opposed to one below it.
 */
export function isDatabaseOperation(url) {
  return /\/v1\/projects\/[^/]+\/databases(\/[^/:?]+)?(\?|$)/.test(url);
}

const INSTANT = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/;
const EMBEDDED_INSTANT = /\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z/g;
const UUID = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g;
const OPERATION = /(\/operations\/)([A-Za-z0-9_-]+)/g;
const INDEX = /(\/indexes\/|index ID = )([A-Za-z0-9_-]{6,})/g;
const INDEX_LINK = /(create_(?:composite|exemption))=([A-Za-z0-9_-]+)/g;
const RETRY = /Please retry in \d+ seconds/g;
/** Values that are opaque by key: always different, never compared. */
const OPAQUE_KEYS = new Map([
  ["etag", "<etag>"],
  ["nextPageToken", "<page-token>"],
]);

/**
 * The symbols of one program: database ids, uids, operation ids and index ids are numbered by
 * first appearance across the whole program (a later step that names the same resource shows
 * that it does); instants are numbered within each step.
 */
export function programSymbols(ctx, program) {
  const databases = new Map();
  for (const letter of program.databases ?? [])
    databases.set(databaseId(ctx, program, letter), `<db:${letter}>`);
  return { databases, uids: new Map(), operations: new Map(), indexes: new Map() };
}

function numbered(map, key, prefix) {
  if (!map.has(key)) map.set(key, `<${prefix}${map.size + 1}>`);
  return map.get(key);
}

function inRunWindow(text, ctx) {
  if (!INSTANT.test(text)) return false;
  const millis = Date.parse(text);
  return millis >= ctx.window.from && millis <= ctx.window.to;
}

function instantKey(text) {
  const match = /^(.*T\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z$/.exec(text);
  if (!match) return text;
  return `${Date.parse(`${match[1]}Z`) / 1000}.${(match[2] ?? "").padEnd(9, "0")}`;
}

function instantSymbol(text, local) {
  const key = instantKey(text);
  if (!local.has(key)) local.set(key, `<t${local.size + 1}>`);
  return local.get(key);
}

/**
 * The console link production puts in a missing-index message carries the index or field
 * name, and so the project and database ids, as base64url protobuf. The recorded form decodes
 * it and replaces those ids, so both sides stay comparable byte for byte.
 */
function normalizeIndexLink(text, ctx, symbols) {
  return text.replaceAll(INDEX_LINK, (_, kind, blob) => {
    let bytes = Buffer.from(blob, "base64url").toString("latin1");
    bytes = bytes.replaceAll(ctx.project, RECORDED_PROJECT);
    for (const [id, symbol] of symbols.databases) bytes = bytes.replaceAll(id, symbol);
    return `${kind}=${Buffer.from(bytes, "latin1").toString("base64url")}`;
  });
}

function normalizeString(text, ctx, symbols, local) {
  if (inRunWindow(text, ctx)) return instantSymbol(text, local);
  let out = normalizeIndexLink(text, ctx, symbols)
    .replaceAll(EMBEDDED_INSTANT, (i) => (inRunWindow(i, ctx) ? instantSymbol(i, local) : i))
    .replaceAll(UUID, (uid) => numbered(symbols.uids, uid, "uid"))
    .replaceAll(OPERATION, (_, head, id) => `${head}${numbered(symbols.operations, id, "op")}`)
    .replaceAll(INDEX, (_, head, id) => `${head}${numbered(symbols.indexes, id, "index")}`)
    .replaceAll(RETRY, "Please retry in <n> seconds")
    .replaceAll(ctx.bucket, "<bucket>")
    .replaceAll(ctx.project, RECORDED_PROJECT);
  for (const [id, symbol] of symbols.databases) out = out.replaceAll(id, symbol);
  if (ctx.target.projectNumber) out = out.replaceAll(ctx.target.projectNumber, "<project-number>");
  return out;
}

/**
 * Normalizes one decoded answer. Object keys are visited in sorted order, because production
 * map key order is not deterministic and symbols are numbered by first appearance.
 */
export function normalizeValue(value, key, ctx, symbols, local = new Map()) {
  if (OPAQUE_KEYS.has(key) && typeof value === "string" && value !== "")
    return OPAQUE_KEYS.get(key);
  if (typeof value === "string") return normalizeString(value, ctx, symbols, local);
  if (Array.isArray(value)) return value.map((v) => normalizeValue(v, key, ctx, symbols, local));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .toSorted()
        .map((k) => [k, normalizeValue(value[k], k, ctx, symbols, local)]),
    );
  }
  return value;
}

/**
 * The databases a list answer may show: `(default)` and this program's own (by id, or, once
 * deleted, by `previousId`). Other entries are other programs' or other lanes' and are counted
 * rather than recorded, so a concurrent run never changes a row.
 */
export function filterDatabaseList(body, ctx, program) {
  if (!Array.isArray(body?.databases)) return body;
  const own = programDatabases(ctx, program);
  const keep = (d) => {
    const id = String(d.name ?? "")
      .split("/")
      .at(-1);
    return id === "(default)" || own.has(id) || own.has(d.previousId);
  };
  const kept = body.databases.filter(keep);
  if (program.defaultDatabase)
    return {
      ...body,
      databases: kept.filter(
        (d) => String(d.name).endsWith("/(default)") || d.previousId === "(default)",
      ),
    };
  return { ...body, databases: kept };
}

/** A storage object listing, reduced to what the export layout contract is about. */
export function reduceObjectListing(body, program) {
  if (!Array.isArray(body?.items) && body?.kind !== "storage#objects") return body;
  return {
    names: (body.items ?? [])
      .map((item) => String(item.name).replace(`${program.slug}/`, ""))
      .toSorted(),
  };
}

/** The recorded form of one REST answer. */
export function normalizeRestResponse(status, text, ctx, program, symbols, step = {}) {
  let body;
  try {
    body = text === "" ? undefined : JSON.parse(text);
  } catch {
    return { status, nonJson: normalizeString(text.slice(0, 400), ctx, symbols, new Map()) };
  }
  if (step.filterDatabases) body = filterDatabaseList(body, ctx, program);
  if (step.objectListing) body = reduceObjectListing(body, program);
  return {
    status,
    ...(body === undefined ? {} : { body: normalizeValue(body, "", ctx, symbols) }),
  };
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.keys(value)
        .toSorted()
        .map((k) => [k, canonical(value[k])]),
    );
  return value;
}

export const sameRecording = (a, b) => isDeepStrictEqual(canonical(a), canonical(b));

/** The distinct consecutive states of a poll, with how many polls saw each dropped. */
export function collapseTrace(states) {
  const out = [];
  for (const state of states) if (!out.length || !sameRecording(out.at(-1), state)) out.push(state);
  return out;
}

/**
 * Whether `local`'s poll trace agrees with production's: the settled answers are equal, and
 * every state fireemu passed through is one production passed through, in production's order
 * (C10: fireemu may skip a transitional state, never invent one or reorder them).
 */
export function traceAgrees(production, local) {
  if (!production?.trace || !local?.trace) return false;
  if (!sameRecording(production.settled, local.settled)) return false;
  let at = 0;
  for (const state of local.trace) {
    while (at < production.trace.length && !sameRecording(production.trace[at], state)) at += 1;
    if (at === production.trace.length) return false;
  }
  return true;
}

/** Row keys (`program#step`) whose two production recordings differ. */
export function diffRecordings(first, second) {
  const rows = [];
  for (const [programId, program] of Object.entries(first)) {
    for (const [stepId, recorded] of Object.entries(program.steps)) {
      const other = second[programId]?.steps?.[stepId];
      const same = recorded?.trace
        ? traceAgrees(recorded, other) && traceAgrees(other, recorded)
        : sameRecording(recorded, other);
      if (!same) rows.push(`${programId}#${stepId}`);
    }
  }
  return rows;
}

/**
 * Refuses a corpus that is malformed or exceeds the request cap. Returns the number of
 * requests the corpus sends, counting every poll a poll step may make.
 */
export function validateCorpus(programs) {
  let requests = 0;
  const ids = new Set();
  const slugs = new Set();
  for (const program of programs) {
    if (ids.has(program.id)) throw new Error(`duplicate program ${program.id}`);
    ids.add(program.id);
    if (!/^fs-config\/[a-z0-9-]+(\/[a-z0-9-]+)+$/.test(program.id))
      throw new Error(`${program.id}: program id must be fs-config/<area>/<case>`);
    if (slugs.has(program.slug)) throw new Error(`${program.id}: duplicate slug`);
    slugs.add(program.slug);
    for (const letter of program.databases ?? [])
      if (!/^[a-z]$/.test(letter)) throw new Error(`${program.id}: database letters are a-z`);
    const stepIds = new Set();
    for (const step of program.steps) {
      if (stepIds.has(step.id)) throw new Error(`${program.id}: duplicate step ${step.id}`);
      stepIds.add(step.id);
      if (step.grpc && !GRPC_RPCS.has(step.grpc.rpc))
        throw new Error(`${program.id}#${step.id}: gRPC ${step.grpc.rpc} is not reviewed`);
      if (
        !step.path &&
        !step.pathFrom &&
        !step.grpc &&
        !step.capture &&
        !step.upload &&
        !step.reproduce
      )
        throw new Error(`${program.id}#${step.id}: a step needs a path, pathFrom or grpc`);
      if (
        step.path &&
        !/^(v1\/(\{project\}|\{foreign\})|storage\/v1\/b\/\{bucket\})/.test(step.path)
      )
        throw new Error(`${program.id}#${step.id}: path must start at a project or the bucket`);
      requests += step.poll ? step.poll.max : 1;
    }
  }
  if (requests > REQUEST_CAP) throw new Error(`corpus exceeds the request cap (${requests})`);
  return requests;
}
