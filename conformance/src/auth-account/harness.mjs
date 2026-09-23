// Pure building blocks of the AUTH-ACCOUNT sandbox harness: request construction for client,
// Admin and Secure Token calls, the corpus guard, response normalization and the comparison of
// two production recordings. Nothing here performs I/O.
//
// Production is only ever the disposable Identity Platform sandbox (`SANDBOX_PROJECT`); the
// local side is fireemu on a loopback port. Recorded values never contain the sandbox project
// id, the API key, tokens, password hashes, salts or generated ids.

import { isDeepStrictEqual } from "node:util";

export const SANDBOX_PROJECT = "fireemu-oracle-idp";
export const RECORDED_PROJECT = "demo-auth-account";
/** The sandbox's configured test numbers (fixed code 123456); no SMS is ever sent to them. */
export const TEST_PHONES = [
  "+16505550101",
  "+16505550102",
  "+16505550103",
  "+16505550104",
  "+16505550105",
  "+16505550106",
];
export const TEST_PHONE_CODE = "123456";
export const REQUEST_CAP = 2000;

const PRODUCTION_ORIGINS = {
  itk: "https://identitytoolkit.googleapis.com",
  securetoken: "https://securetoken.googleapis.com",
};
const LOCAL_PREFIX = {
  itk: "identitytoolkit.googleapis.com",
  securetoken: "securetoken.googleapis.com",
};
const LOOPBACK = new Set(["127.0.0.1", "localhost", "[::1]"]);

/** Binds a run id, the project and one target (production sandbox or local fireemu). */
export function createContext({ run, project, target }) {
  if (!/^\d+$/.test(String(run))) throw new Error("run id must be numeric");
  if (target.kind === "production") {
    if (project !== SANDBOX_PROJECT) {
      throw new Error(`production target must be the sandbox project ${SANDBOX_PROJECT}`);
    }
    if (!target.apiKey || !target.adminToken)
      throw new Error("production needs an API key and an admin token");
    if (target.quotaProject !== SANDBOX_PROJECT)
      throw new Error("quota project must be the sandbox project");
  } else if (target.kind === "local") {
    const url = new URL(target.origin);
    if (url.protocol !== "http:" || !LOOPBACK.has(url.hostname)) {
      throw new Error("local target must be a loopback http origin");
    }
  } else {
    throw new Error(`unknown target kind ${target.kind}`);
  }
  return { run: String(run), project, target };
}

const email = (ctx, name) => `fireemu-aa-${ctx.run}-${name}@example.com`;
const mixedEmail = (ctx, name) => `FireEmu-AA-${ctx.run}-${name}@Example.COM`;
const uid = (ctx, name) => `aa-${ctx.run}-${name}`;

function lookup(value, path) {
  let current = value;
  for (const segment of String(path).split(".")) {
    if (current === null || current === undefined) return undefined;
    current = current[segment];
  }
  return current;
}

function substitute(text, ctx) {
  return text
    .replaceAll(/EMAILMIXED\(([a-z0-9-]+)\)/g, (_, n) => mixedEmail(ctx, n))
    .replaceAll(/EMAIL\(([a-z0-9-]+)\)/g, (_, n) => email(ctx, n))
    .replaceAll(/UID\(([a-z0-9-]+)\)/g, (_, n) => uid(ctx, n))
    .replaceAll(/PHONE\((\d)\)/g, (_, i) => {
      const phone = TEST_PHONES[Number(i)];
      if (!phone) throw new Error(`no test phone ${i}`);
      return phone;
    })
    .replaceAll("{project}", ctx.project);
}

/** Resolves placeholders, `$from` references and generated strings in a request value. */
export function resolveValue(value, ctx, raw) {
  if (Array.isArray(value)) return value.map((v) => resolveValue(v, ctx, raw));
  if (value && typeof value === "object") {
    if (typeof value.$from === "string") {
      const found = lookup(raw.get(value.$from), value.path);
      if (found === undefined)
        throw new Error(`step ${value.$from} recorded nothing at ${value.path}`);
      return found;
    }
    if (typeof value.$repeat === "string") return value.$repeat.repeat(value.count);
    if (Array.isArray(value.$concat))
      return value.$concat.map((v) => resolveValue(v, ctx, raw)).join("");
    if (value.$json !== undefined) return JSON.stringify(resolveValue(value.$json, ctx, raw));
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, resolveValue(v, ctx, raw)]),
    );
  }
  if (typeof value === "string") return substitute(value, ctx);
  return value;
}

/** The URL and fetch init for one step against the context's target. */
export function buildRequest(step, ctx, raw) {
  const api = step.api ?? "itk";
  const path = substitute(step.path, ctx);
  const origin =
    ctx.target.kind === "production"
      ? PRODUCTION_ORIGINS[api]
      : `${ctx.target.origin}/${LOCAL_PREFIX[api]}`;
  if (!origin) throw new Error(`unknown api ${api}`);
  const query = new URLSearchParams();
  for (const [k, v] of Object.entries(resolveValue(step.query ?? {}, ctx, raw)))
    query.set(k, String(v));
  const headers = {};
  if (step.auth === "key") {
    query.set("key", ctx.target.kind === "production" ? ctx.target.apiKey : "fake-api-key");
  } else if (step.auth === "admin") {
    headers.authorization = `Bearer ${ctx.target.kind === "production" ? ctx.target.adminToken : "owner"}`;
    if (ctx.target.kind === "production") headers["x-goog-user-project"] = ctx.target.quotaProject;
  } else if (step.auth !== "none") {
    throw new Error(`step ${step.id}: auth must be key, admin or none`);
  }
  const init = { method: step.method ?? "POST", headers };
  if (step.form) {
    headers["content-type"] = "application/x-www-form-urlencoded";
    init.body = new URLSearchParams(resolveValue(step.form, ctx, raw)).toString();
  } else if (step.rawBody !== undefined) {
    headers["content-type"] = "application/json";
    init.body = substitute(step.rawBody, ctx);
  } else if (step.body !== undefined) {
    headers["content-type"] = "application/json";
    init.body = JSON.stringify(resolveValue(step.body, ctx, raw));
  }
  const search = query.toString();
  return { url: `${origin}/${path}${search ? `?${search}` : ""}`, init };
}

function* walkStrings(value) {
  if (typeof value === "string") yield value;
  else if (Array.isArray(value)) for (const v of value) yield* walkStrings(v);
  else if (value && typeof value === "object")
    for (const v of Object.values(value)) yield* walkStrings(v);
}

/**
 * Refuses a corpus that could send mail to a real mailbox, SMS to a real number, address
 * anything but a relative Identity Toolkit / Secure Token path, or exceed the request cap.
 * Returns the number of recorded requests.
 */
export function validateCorpus(programs) {
  let requests = 0;
  const programIds = new Set();
  for (const program of programs) {
    if (programIds.has(program.id)) throw new Error(`duplicate program ${program.id}`);
    programIds.add(program.id);
    const stepIds = new Set();
    for (const step of program.steps) {
      requests += 1;
      if (stepIds.has(step.id)) throw new Error(`${program.id}: duplicate step ${step.id}`);
      stepIds.add(step.id);
      if (/^[a-z]+:|^\/\/|\.\./i.test(step.path))
        throw new Error(`${program.id}#${step.id}: path must be relative`);
      if (!["itk", "securetoken", undefined].includes(step.api))
        throw new Error(`${step.id}: unknown api`);
      const payload = {
        body: step.body,
        form: step.form,
        query: step.query,
        rawBody: step.rawBody,
      };
      if (step.path.endsWith("accounts:sendOobCode")) {
        const type = step.body?.requestType;
        if (type === "VERIFY_AND_CHANGE_EMAIL")
          throw new Error(`${step.id}: VERIFY_AND_CHANGE_EMAIL is never sent`);
        if (!/^EMAIL\(unknown[a-z0-9-]*\)$/.test(step.body?.email ?? "")) {
          throw new Error(`${step.id}: sendOobCode only for an unknown EMAIL(unknown-*) address`);
        }
      }
      if (
        step.path.endsWith("accounts:sendVerificationCode") &&
        !/^PHONE\(\d\)$/.test(step.body?.phoneNumber ?? "")
      ) {
        throw new Error(
          `${step.id}: sendVerificationCode only to a configured test phone PHONE(n)`,
        );
      }
      for (const text of walkStrings(payload)) {
        if (
          /@(?!example\.com\b|Example\.COM\b)[A-Za-z0-9.-]+\.[a-z]{2,}/.test(text) &&
          !step.allowForeignEmail
        ) {
          throw new Error(`${step.id}: email outside example.com`);
        }
      }
    }
  }
  if (requests > REQUEST_CAP)
    throw new Error(`corpus exceeds the request cap (${requests} > ${REQUEST_CAP})`);
  return requests;
}

const TOKEN_KEYS = new Set([
  "idToken",
  "refreshToken",
  "id_token",
  "refresh_token",
  "access_token",
  "oobCode",
  "sessionInfo",
  "pendingToken",
  "mfaPendingCredential",
  "temporaryProof",
]);
const TIME_KEYS = new Set([
  "createdAt",
  "lastLoginAt",
  "lastRefreshAt",
  "passwordUpdatedAt",
  "validSince",
  "phoneVerifiedAt",
]);
const BYTE_KEYS = new Set(["passwordHash", "salt"]);
const ID_KEYS = new Set(["localId", "user_id", "uid"]);
const INSTANT = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/;

function normalizeString(text, ctx) {
  let out = text.replaceAll(ctx.run, "<run>").replaceAll(ctx.project, RECORDED_PROJECT);
  if (ctx.target.kind === "production") {
    out = out.replaceAll(ctx.target.apiKey, "<api-key>");
    if (ctx.projectNumber) out = out.replaceAll(ctx.projectNumber, "<project-number>");
  }
  return out;
}

function normalizeValue(value, key, ctx) {
  if (TOKEN_KEYS.has(key) && typeof value === "string") return `<${key}>`;
  if (BYTE_KEYS.has(key) && typeof value === "string") return "<bytes>";
  if (TIME_KEYS.has(key) && (typeof value === "string" || typeof value === "number"))
    return "<time>";
  if ((key === "expiresIn" || key === "expires_in") && value !== null) return "<seconds>";
  if (typeof value === "string") {
    const text = normalizeString(value, ctx);
    if (ID_KEYS.has(key) && !text.includes("<run>")) return "<generated-localId>";
    if (INSTANT.test(text)) return "<instant>";
    return text;
  }
  if (Array.isArray(value)) return value.map((v) => normalizeValue(v, key, ctx));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, normalizeValue(v, k, ctx)]),
    );
  }
  return value;
}

/** The recorded form of one HTTP answer. */
export function normalizeResponse(status, text, ctx) {
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return { status, nonJson: true };
  }
  return { status, body: normalizeValue(body, "", ctx) };
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .toSorted()
        .map((k) => [k, canonical(value[k])]),
    );
  }
  return value;
}

export const sameRecording = (a, b) => isDeepStrictEqual(canonical(a), canonical(b));

/** Row keys (`program#step`) whose two production recordings differ. */
export function diffRecordings(first, second) {
  const rows = [];
  for (const [programId, program] of Object.entries(first)) {
    for (const [stepId, recorded] of Object.entries(program.steps)) {
      if (!sameRecording(recorded, second[programId]?.steps?.[stepId]))
        rows.push(`${programId}#${stepId}`);
    }
  }
  return rows;
}
