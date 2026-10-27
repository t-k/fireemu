// The retirement of the kept database `entpipe1` (owner ledger 1792): the request plan, the guard
// that lets nothing else through, and the judges of what production answers. Pure functions; the
// CLI that sends the requests is retire-entpipe1.mjs. The shapes the judges accept are those of
// FS-CONFIG-LIFECYCLE's recorded `databases.delete` on named Standard databases (the delete
// answer is an operation named under the database, with DeleteDatabaseMetadata and the deleted
// database, the operation never reports done in the recording, and the database then reads 404),
// with the edition and the name of this database.

export const PROJECT = "fireemu-oracle-query";
export const DATABASE = "entpipe1";
export const ORIGIN = "https://firestore.googleapis.com/v1";
export const DB = `projects/${PROJECT}/databases/${DATABASE}`;

const OPERATION_NAME = new RegExp(
  `^${DB}/operations/[A-Za-z0-9_.-]{1,200}$`.replaceAll("/", "\\/"),
);
const DELETE_METADATA = "type.googleapis.com/google.firestore.admin.v1.DeleteDatabaseMetadata";
const DATABASE_TYPE = "type.googleapis.com/google.firestore.admin.v1.Database";

/** The fixed steps, by phase. The operation reads of S4 are built from the delete answer. */
export const PLAN = [
  { id: "s0-databases", phase: "S0", method: "GET", path: `projects/${PROJECT}/databases` },
  { id: "s0-describe", phase: "S0", method: "GET", path: DB },
  { id: "s0-indexes", phase: "S0", method: "GET", path: `${DB}/collectionGroups/-/indexes` },
  { id: "s0-operations", phase: "S0", method: "GET", path: `${DB}/operations` },
  {
    id: "s0-collection-ids",
    phase: "S0",
    method: "POST",
    path: `${DB}/documents:listCollectionIds`,
    body: {},
  },
  { id: "s4-delete", phase: "S4", method: "DELETE", path: DB },
  { id: "s4-describe-after", phase: "S4", method: "GET", path: DB },
  { id: "a2-databases", phase: "A2", method: "GET", path: `projects/${PROJECT}/databases` },
  { id: "a2-describe", phase: "A2", method: "GET", path: DB },
];
export const MAX_OPERATION_READS = 3;

/** The request of a step; an operation read names its operation. */
export function buildRequest(step, operationName) {
  const path = step.id.startsWith("s4-operation-") ? operationName : step.path;
  const request = { method: step.method, url: `${ORIGIN}/${path}` };
  if (step.body !== undefined) request.body = step.body;
  return guardRequest(request);
}

const ALLOWED = [
  ["GET", new RegExp(`^${ORIGIN}/projects/${PROJECT}/databases$`.replaceAll("/", "\\/"))],
  ["GET", new RegExp(`^${ORIGIN}/${DB}$`.replaceAll("/", "\\/"))],
  ["DELETE", new RegExp(`^${ORIGIN}/${DB}$`.replaceAll("/", "\\/"))],
  ["GET", new RegExp(`^${ORIGIN}/${DB}/collectionGroups/-/indexes$`.replaceAll("/", "\\/"))],
  ["GET", new RegExp(`^${ORIGIN}/${DB}/operations$`.replaceAll("/", "\\/"))],
  ["POST", new RegExp(`^${ORIGIN}/${DB}/documents:listCollectionIds$`.replaceAll("/", "\\/"))],
];

/** Throws unless the request is one of the planned ones, for exactly this database. */
export function guardRequest(request) {
  const exact = ALLOWED.some(
    ([method, pattern]) => method === request.method && pattern.test(request.url),
  );
  const operation =
    request.method === "GET" &&
    request.url.startsWith(`${ORIGIN}/`) &&
    OPERATION_NAME.test(request.url.slice(ORIGIN.length + 1));
  if (!exact && !operation)
    throw new Error(`not a planned request: ${request.method} ${request.url}`);
  if (request.method === "POST" && JSON.stringify(request.body) !== "{}")
    throw new Error("the only body is the empty one");
  if (request.method !== "POST" && request.body !== undefined) throw new Error("no body expected");
  return request;
}

/** An answer is definite when production settled it: a 2xx or a 4xx other than 408, 429 and 499. */
export const definite = (status) =>
  Number.isInteger(status) &&
  ((status >= 200 && status <= 299) ||
    (status >= 400 && status <= 499 && ![408, 429, 499].includes(status)));

const names = (answer) => (answer.body?.databases ?? []).map((d) => d.name);
const ok200 = (answer) =>
  answer?.status === 200 && answer.body !== null && typeof answer.body === "object";

/**
 * The read-only snapshot before the delete. `ok` is true only when every answer is a complete 200
 * and shows exactly the expected database: Enterprise, Firestore Native, delete protection
 * disabled, listed with the others, no index, no running operation, no document.
 */
export function judgeS0(answers) {
  const reasons = [];
  for (const id of [
    "s0-databases",
    "s0-describe",
    "s0-indexes",
    "s0-operations",
    "s0-collection-ids",
  ])
    if (!ok200(answers[id])) reasons.push(`${id}: not a complete 200 (${answers[id]?.status})`);
  if (reasons.length) return { ok: false, reasons };
  const described = answers["s0-describe"].body;
  const listed = names(answers["s0-databases"]);
  if (!listed.includes(DB)) reasons.push("the database is not in the list");
  if (described.name !== DB) reasons.push(`describe names ${described.name}`);
  if (described.type !== "FIRESTORE_NATIVE") reasons.push(`type ${described.type}`);
  if (described.databaseEdition !== "ENTERPRISE")
    reasons.push(`edition ${described.databaseEdition}`);
  if (described.deleteProtectionState !== "DELETE_PROTECTION_DISABLED")
    reasons.push(`delete protection ${described.deleteProtectionState}`);
  if (typeof described.uid !== "string" || described.uid === "") reasons.push("no uid");
  if ((answers["s0-indexes"].body.indexes ?? []).length > 0) reasons.push("an index is configured");
  if ((answers["s0-operations"].body.operations ?? []).some((o) => o.done !== true))
    reasons.push("an operation is not done");
  if ((answers["s0-collection-ids"].body.collectionIds ?? []).length > 0)
    reasons.push("a collection holds documents");
  return {
    ok: reasons.length === 0,
    reasons,
    snapshot: { uid: described.uid, others: listed.filter((n) => n !== DB).toSorted() },
  };
}

/**
 * The answer to the delete. "accepted": a 200 operation of this database whose metadata is
 * DeleteDatabaseMetadata and which carries the database with a deleteTime (the recorded shape).
 * A definite refusal is "refused"; anything else, including a 200 of another shape, is "unknown":
 * sticky, never re-sent, closed only by the read-back.
 */
export function judgeDelete(answer) {
  if (!definite(answer?.status)) return { verdict: "unknown", why: `status ${answer?.status}` };
  if (answer.status >= 400) return { verdict: "refused", why: `status ${answer.status}` };
  const body = answer.body;
  const named = typeof body?.name === "string" && OPERATION_NAME.test(body.name);
  const recorded =
    named &&
    body.metadata?.["@type"] === DELETE_METADATA &&
    body.response?.["@type"] === DATABASE_TYPE &&
    body.response.databaseEdition === "ENTERPRISE" &&
    body.response.previousId === DATABASE &&
    typeof body.response.deleteTime === "string" &&
    body.error === undefined;
  return recorded
    ? { verdict: "accepted", operation: body.name }
    : { verdict: "unknown", why: "a 200 of an unrecorded shape" };
}

/** A read of the operation: informational (the recording shows it never reports done). */
export function judgeOperation(answer, operation) {
  if (!ok200(answer) || answer.body.name !== operation) return { verdict: "unknown" };
  if (answer.body.error) return { verdict: "failed" };
  return { verdict: answer.body.done === true ? "done" : "pending" };
}

const NOT_FOUND = "Requested database was not found.";
const gone = (answer) =>
  answer?.status === 404 &&
  answer.body?.error?.status === "NOT_FOUND" &&
  answer.body.error.message === NOT_FOUND;

/**
 * The read-back, at least ten minutes after the delete: the list equals the S0 list without this
 * database, and the describe is the recorded 404. A 200 describe is "present"; anything else is
 * "unknown".
 */
export function judgeA2(answers, snapshot) {
  const list = answers["a2-databases"];
  const describe = answers["a2-describe"];
  if (ok200(list) && ok200(describe) && describe.body.name === DB) return { verdict: "present" };
  if (!ok200(list) || !gone(describe)) return { verdict: "unknown" };
  const listed = names(list).toSorted();
  return JSON.stringify(listed) === JSON.stringify(snapshot.others)
    ? { verdict: "deleted" }
    : { verdict: "unknown", why: "the list differs from the snapshot beyond this database" };
}
