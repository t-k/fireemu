// The judge of the FS-RULES differences recording: what a recorded production answer means for a
// row, and how it compares with what the official Firestore emulator is claimed to do.
//
// A saved row is classified only by a shape that production was recorded sending (RECORDED_SHAPES
// cites the fixture row of each). Anything else, including a 400 (for example a missing index), a
// 5xx, a transport failure, an unexpected extra key or a different message, is `unknown`: it is
// never read as an allow or a deny. The recorder stores a body compacted, so no byte layout is
// judged here; the classification is on the status and on exact key sets.

import { sameRecording } from "../fs-rules/harness.mjs";
import { DIFFS_PROGRAMS } from "./corpus.mjs";

/** The production answers the classifier accepts, with the fixture row each was recorded in. */
export const RECORDED_SHAPES = [
  {
    rpc: "get",
    kind: "allowed",
    source: "fs-rules-v1-observation.json fs-rules-v1/bad-path/core#ctl-missing-not-exists",
    row: "fs-rules-v1/bad-path/core",
    note: "404 NOT_FOUND: the rule allowed and the document is missing",
  },
  {
    rpc: "get",
    kind: "denied",
    source: "fs-rules-v1-observation.json fs-rules-v1/bad-path/core#ctl-real-not-exists",
    row: "fs-rules-v1/bad-path/core",
    note: "403 PERMISSION_DENIED",
  },
  {
    rpc: "runQuery",
    kind: "allowed",
    source: "fs-rules-production.json fs-rules/budgets/access-calls#list-10",
    row: "fs-rules/budgets/access-calls",
    note: "200 [{readTime}]: allowed, no document",
  },
  {
    rpc: "runQuery",
    kind: "allowed",
    source: "fs-rules-v1-observation.json fs-rules-v1/path-wildcard/v2#group-none",
    row: "fs-rules-v1/path-wildcard/v2",
    note: "200 [{document, readTime}, ...]: allowed with documents",
  },
  {
    rpc: "runQuery",
    kind: "denied",
    source: "fs-rules-v1-observation.json fs-rules-v1/path-wildcard/v2#kindless-parent-none",
    row: "fs-rules-v1/path-wildcard/v2",
    note: "403 [{error}]: PERMISSION_DENIED as a one-element array",
  },
];

const exactKeys = (value, keys) =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).toSorted().join() === keys.toSorted().join();

const DENIED = "Missing or insufficient permissions.";
const isDenied = (error) =>
  exactKeys(error, ["code", "message", "status"]) &&
  error.code === 403 &&
  error.message === DENIED &&
  error.status === "PERMISSION_DENIED";
const isNotFound = (error) =>
  exactKeys(error, ["code", "message", "status"]) &&
  error.code === 404 &&
  error.status === "NOT_FOUND" &&
  /^Document ".+" not found\.$/.test(error.message);

const isDocumentEntry = (entry) =>
  exactKeys(entry, ["document", "readTime"]) &&
  typeof entry.document?.name === "string" &&
  Object.keys(entry.document).every((key) =>
    ["name", "fields", "createTime", "updateTime"].includes(key),
  );

/**
 * What a recorded answer to `rpc` says: `allowed`, `denied`, `not-evaluated` (the row never ran)
 * or `unknown`. A `runQuery` allow also reports how many documents it returned.
 */
export function classifyAnswer(rpc, recorded) {
  if (recorded === undefined) return { kind: "unknown", detail: "no recording" };
  if (recorded.unresolved !== undefined)
    return { kind: "not-evaluated", detail: recorded.unresolved };
  const { status, body } = recorded;
  if (rpc === "get") {
    if (status === 404 && exactKeys(body, ["error"]) && isNotFound(body.error))
      return { kind: "allowed" };
    if (status === 403 && exactKeys(body, ["error"]) && isDenied(body.error))
      return { kind: "denied" };
  } else if (rpc === "runQuery" && Array.isArray(body)) {
    if (status === 200 && body.length === 1 && exactKeys(body[0], ["readTime"]))
      return { kind: "allowed", documents: 0 };
    if (status === 200 && body.length > 0 && body.every(isDocumentEntry))
      return { kind: "allowed", documents: body.length };
    if (
      status === 403 &&
      body.length === 1 &&
      exactKeys(body[0], ["error"]) &&
      isDenied(body[0].error)
    )
      return { kind: "denied" };
  }
  return { kind: "unknown", detail: `status ${status}, not a recorded shape` };
}

/**
 * What the official emulator (firebase-tools 15.28.2, Firestore emulator jar 1.22.0) answered to
 * each row, by `<program>#<row>`, measured by `FS3_CORPUS=diffs run.mjs official` on 2026-11-08.
 * The user's claims for the five cases all held there. Production is compared with these
 * answers: `agrees` means production does what the official emulator does.
 */
export const CLAIMS = {
  "queries#publishes": "compiled",
  "queries#owner-alone": "allowed",
  "queries#owner-and-name-missing": "denied",
  "queries#owner-and-name-foreign": "denied",
  "queries#owner-and-name-own": "allowed",
  "queries#name-missing-alone": "denied",
  "queries#name-foreign-alone": "denied",
  "queries#members-guarded-in": "allowed",
  "queries#members-guarded-in-viewer": "denied",
  "queries#members-unguarded-in": "allowed",
  "queries#members-bare-nofilter": "allowed",
  "queries#blocked-nofilter": "allowed",
  "queries#has-owner-nofilter": "denied",
  "queries#has-owner-filtered": "allowed",
  "string-index#publishes": "compiled",
  "string-index#ascii-ctl": "allowed",
  "string-index#idx0": "allowed",
  "string-index#idx1-fire": "denied",
  "string-index#idx2-x": "denied",
  "string-index#idx3-x": "allowed",
  "string-index#idx4-eq-x": "denied",
  "string-index#idx4-not-eq": "denied",
  "string-index#size-4": "allowed",
  "string-index#size-3": "denied",
  "string-escape#publishes": "compiled",
  "string-escape#esc-high": "allowed",
  "string-escape#esc-ctl": "allowed",
  "fn-top#publishes": "compiled",
  "fn-top#fn-top-true": "allowed",
  "fn-top#fn-top-false": "denied",
  "fn-inner#publishes": "compiled",
  "fn-inner#fn-inner-true": "allowed",
  "fn-inner#fn-inner-false": "denied",
};

function judgePublication(recorded) {
  if (recorded?.compiled === true) return { answer: "compiled" };
  if (recorded?.compiled === false) return { answer: "refused" };
  return { answer: "unknown", detail: "no publication answer" };
}

function verdictOf(answer, claim) {
  if (answer === "not-evaluated") return "not-evaluated";
  if (!["allowed", "denied", "compiled", "refused"].includes(answer)) return "unknown";
  if (claim === undefined) return "no-claim";
  return answer === claim ? "agrees" : "differs";
}

/** Every row of the corpus: the recorded answer, its meaning, the official claim and the verdict. */
export function diffsReport(fixture, claims = CLAIMS) {
  const rows = [];
  for (const program of DIFFS_PROGRAMS) {
    const name = program.id.split("/").at(-1);
    const saved = fixture.programs?.[program.id];
    for (const step of program.steps) {
      const row = `${name}#${step.id}`;
      const recorded = saved?.steps?.[step.id];
      const other = saved?.second?.[step.id];
      let judged;
      if (recorded === undefined) judged = { answer: "missing", detail: "not recorded" };
      else if (other !== undefined && !sameRecording(recorded, other))
        judged = { answer: "unknown", detail: "the two recordings differ" };
      else if (step.publish) judged = judgePublication(recorded);
      else {
        const { kind, detail, documents } = classifyAnswer(step.rpc, recorded);
        judged = {
          answer: kind,
          ...(detail ? { detail } : {}),
          ...(documents === undefined ? {} : { documents }),
        };
      }
      rows.push({
        row,
        claim: claims[row],
        ...judged,
        verdict: verdictOf(judged.answer, claims[row]),
      });
    }
  }
  return rows;
}
