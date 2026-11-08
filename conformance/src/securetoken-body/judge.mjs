// Decisions of the Secure Token body recording: how one recorded answer is read, how two
// recordings are merged, and how production is compared with fireemu.
//
// The judge reads only shapes production has already been recorded giving to a refresh request
// (the AUTH-CREDENTIAL refusals program, 2026-09-24, and the AUTH-TENANT-BLOCKING selection
// program). A body of any other shape, a status of any other kind, a transport failure or a
// disagreement between the two recordings is `unknown`; it is reported as such and never
// rounded to the nearest known answer. Recorded bodies are compared by their normalized keys and
// values (the recorders store a body as compact JSON, so byte layout is not judged here).

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";

import { CONFORMANCE_DIR } from "../config.mjs";
import { ROWS, corpusDigest } from "./corpus.mjs";

export const TASK_ID = "SECURETOKEN-BODY";
export const sha256 = (text) => createHash("sha256").update(text).digest("hex");

/** Where each accepted answer shape was recorded: fixture file, program, step. */
export const CITATIONS = Object.freeze({
  accepted: Object.freeze({
    project: "auth-credential-production.json#auth-credential/refresh/refusals#control-still-valid",
    tenant: "auth-tenant-blocking-production.json#atb/tenant/selection#refresh-a1",
  }),
  refused: Object.freeze({
    MISSING_REFRESH_TOKEN:
      "auth-credential-production.json#auth-credential/refresh/refusals#no-refresh-token",
    MISSING_GRANT_TYPE:
      "auth-credential-production.json#auth-credential/refresh/refusals#no-grant-type",
    INVALID_GRANT_TYPE:
      "auth-credential-production.json#auth-credential/refresh/refusals#password-grant-type",
    INVALID_REFRESH_TOKEN:
      "auth-credential-production.json#auth-credential/refresh/refusals#malformed-refresh-token",
  }),
});

const SUCCESS_KEYS = [
  "access_token",
  "expires_in",
  "id_token",
  "project_id",
  "refresh_token",
  "token_type",
  "user_id",
];
const RECORDED_PROJECT_ID = "demo-auth-account";

const unknown = (why) => ({ kind: "unknown", why });

/** The decoded JWT node of a normalized token field, when it has the recorded shape. */
function jwtClaims(node) {
  const inner = node?.["<jwt>"];
  if (!inner || typeof inner !== "object") return undefined;
  if (inner.header?.alg !== "RS256" || inner.header?.typ !== "JWT") return undefined;
  if (inner.signature !== "<present>" || inner.header?.kid !== "<present>") return undefined;
  return inner.claims;
}

/**
 * Reads one normalized answer of a refresh request.
 *
 * @returns {{kind: "accepted", user: string, tenant: boolean, cite: string}
 *   | {kind: "refused", message: string, cite: string}
 *   | {kind: "unknown", why: string}}
 */
export function classifyAnswer(recorded) {
  if (recorded === undefined || recorded === null) return unknown("no answer");
  const { status, body } = recorded;
  if (recorded.transport !== undefined || status === 0) return unknown("transport failure");
  if (recorded.nonJson) return unknown("non-JSON body");
  if (typeof status !== "number" || body === undefined) return unknown("no readable answer");
  if (status === 200) return classifyAccepted(body);
  if (status === 400) return classifyRefused(body);
  return unknown(`status ${status} is not a recorded refresh answer`);
}

function classifyAccepted(body) {
  if (body === null || typeof body !== "object" || Array.isArray(body))
    return unknown("200 without an object body");
  const keys = Object.keys(body).toSorted();
  if (!isDeepStrictEqual(keys, SUCCESS_KEYS)) return unknown(`200 with keys ${keys.join(",")}`);
  if (body.expires_in !== "3600" || body.token_type !== "Bearer")
    return unknown("200 with another lifetime or token type");
  if (body.refresh_token !== "<refresh_token>") return unknown("200 without a refresh token");
  if (body.project_id !== "<project-number>") return unknown("200 naming another project");
  const match = /^stb-<run>-([abt])$/.exec(String(body.user_id));
  if (!match) return unknown("200 for an account this run did not create");
  const user = match[1];
  const claims = [jwtClaims(body.id_token), jwtClaims(body.access_token)];
  if (claims.some((c) => c === undefined)) return unknown("200 with a token of another shape");
  for (const c of claims) {
    if (
      c.iss !== `https://securetoken.google.com/${RECORDED_PROJECT_ID}` ||
      c.aud !== RECORDED_PROJECT_ID ||
      c.user_id !== body.user_id ||
      c.sub !== body.user_id
    )
      return unknown("200 with a token that names another subject or project");
    const tenantClaim = c.firebase?.tenant;
    if (user === "t" ? tenantClaim !== "<tenant>" : tenantClaim !== undefined)
      return unknown("200 with a tenant claim that does not match the account");
  }
  return {
    kind: "accepted",
    user,
    tenant: user === "t",
    cite: user === "t" ? CITATIONS.accepted.tenant : CITATIONS.accepted.project,
  };
}

function classifyRefused(body) {
  const error = body?.error;
  if (
    error === null ||
    typeof error !== "object" ||
    !isDeepStrictEqual(Object.keys(body), ["error"]) ||
    !isDeepStrictEqual(Object.keys(error).toSorted(), ["code", "message", "status"]) ||
    error.code !== 400 ||
    error.status !== "INVALID_ARGUMENT"
  )
    return unknown("400 with a body of another shape");
  if (!Object.hasOwn(CITATIONS.refused, error.message))
    return unknown(`400 with a message no recording shows: ${String(error.message).slice(0, 80)}`);
  return { kind: "refused", message: error.message, cite: CITATIONS.refused[error.message] };
}

/** Whether two classifications state the same answer (the citation is not part of it). */
export function sameClassification(a, b) {
  if (a.kind !== b.kind || a.kind === "unknown") return false;
  return a.kind === "accepted"
    ? a.user === b.user && a.tenant === b.tenant
    : a.message === b.message;
}

/**
 * The answer of one row over the recordings made of it. Every recording must give the same
 * known answer; otherwise the row is unknown.
 */
export function mergeRecordings(answers) {
  const classes = answers.map(classifyAnswer);
  if (classes.length === 0) return unknown("not recorded");
  const [first, ...rest] = classes;
  if (first.kind === "unknown") return first;
  const odd = rest.find((c) => !sameClassification(first, c));
  if (odd) return unknown(`recordings differ (${describe(first)} / ${describe(odd)})`);
  return first;
}

/** A short statement of a classification, for a table. */
export function describe(c) {
  if (c.kind === "accepted") return `accepted as ${c.user}`;
  if (c.kind === "refused") return `refused ${c.message}`;
  return `unknown (${c.why})`;
}

const SPELLING = { snake: "snake_case", camel: "camelCase" };

/**
 * What a row answers, in words, from its merged classification. For the rows that offer two
 * accounts, the account that answered says which spelling won.
 */
export function readRow(spec, merged) {
  if (merged.kind === "unknown") return `unknown: ${merged.why}`;
  const tokenFields = spec.fields.filter(([name]) => /^refresh_?[tT]oken$/.test(name));
  const accounts = tokenFields.map(([name, value]) => ({
    spelling: name === "refresh_token" ? "snake" : "camel",
    account: value?.rt,
  }));
  const distinct = new Set(accounts.map((a) => a.account).filter(Boolean));
  if (merged.kind === "accepted" && distinct.size > 1) {
    const winner = accounts.find((a) => a.account === merged.user);
    return winner
      ? `accepted; the ${SPELLING[winner.spelling]} token was used`
      : "accepted for an account no field named";
  }
  return describe(merged);
}

/**
 * Production against fireemu for one row: `agrees` when both state the same known answer,
 * `differs` when both are known and not the same, `unknown` when either side is unknown,
 * `no-claim` when production was not recorded.
 */
export function compareRow(production, local) {
  if (production === undefined) return "no-claim";
  if (production.kind === "unknown" || local.kind === "unknown") return "unknown";
  return sameClassification(production, local) ? "agrees" : "differs";
}

/** The table rows of a report: one per corpus row, with the production and local readings. */
export function buildReport({ productionRecordings, localRecordings, rows = ROWS }) {
  return rows.map((spec) => {
    const production = productionRecordings?.length
      ? mergeRecordings(productionRecordings.map((r) => r.rows?.[spec.id]))
      : undefined;
    const local = localRecordings?.length
      ? mergeRecordings(localRecordings.map((r) => r.rows?.[spec.id]))
      : undefined;
    return {
      row: spec.id,
      question: spec.question,
      production: production && readRow(spec, production),
      fireemu: local && readRow(spec, local),
      status: local === undefined ? "no-claim" : compareRow(production, local),
      cite: production?.cite,
    };
  });
}

// ---- digests and the ledger ------------------------------------------------------------------

export const HARNESS_FILES = Object.freeze([
  "securetoken-body/corpus.mjs",
  "securetoken-body/harness.mjs",
  "securetoken-body/judge.mjs",
  "securetoken-body/session.mjs",
  "securetoken-body/record.mjs",
  "auth-account/harness.mjs",
  "auth-credential/tokens.mjs",
  "shared/ownership.mjs",
]);

export async function harnessDigest(
  read = (file) => readFile(join(CONFORMANCE_DIR, "src", file), "utf8"),
) {
  const sources = await Promise.all(HARNESS_FILES.map(read));
  return sha256(sources.join("\n"));
}

export { corpusDigest };

export const estimatedUsd = (requests) => Number((requests * 0.000002 + 0.01).toFixed(4));

function ledgerEntries(text) {
  return String(text)
    .split("\n")
    .filter(Boolean)
    .flatMap((line) => {
      try {
        return [JSON.parse(line)];
      } catch {
        return [];
      }
    });
}

/** The last end line of this task, when it is an abort or needs recovery within the hour. */
export function recentAbort(ledgerText, now = Date.now(), self = TASK_ID) {
  const last = ledgerEntries(ledgerText).findLast((e) => e.taskId === self && e.outcome);
  if (!last || !/^(aborted|needs-recovery)/.test(String(last.outcome))) return undefined;
  return now - Date.parse(last.ts) < 3_600_000 ? last : undefined;
}

/** Tasks that wrote `started` on the sandbox project and have not ended within six hours. */
export function openRuns(ledgerText, project, now = Date.now(), self = TASK_ID) {
  const open = new Map();
  for (const entry of ledgerEntries(ledgerText)) {
    if (entry.project !== project || entry.taskId === self || !entry.taskId) continue;
    if (entry.event === "started") open.set(entry.taskId, Date.parse(entry.ts));
    else open.delete(entry.taskId);
  }
  return [...open].filter(([, started]) => now - started < 6 * 3_600_000).map(([task]) => task);
}

/**
 * What the sandbox must look like before the first write: nothing this recording could be
 * confused with, and multi-tenancy in a state the session restores.
 */
export function preflightProblems(report) {
  return [
    ...report.failedReads.map((read) => `preflight read failed: ${read}`),
    ...(report.projectAccounts === 0
      ? []
      : [`${report.projectAccounts} project-level account(s) exist`]),
    ...(report.tenants === 0 ? [] : [`${report.tenants} tenant(s) exist`]),
    ...(report.passwordEnabled ? [] : ["email/password sign-in is not enabled"]),
    ...(report.openRuns.length ? [`runs still open: ${report.openRuns.join(", ")}`] : []),
  ];
}
