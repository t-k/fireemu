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

/**
 * Binds a run id, the run start time, the project and one target (production sandbox or local
 * fireemu). Times inside the run window are the only times normalization masks.
 */
export function createContext({ run, project, target, startedMs = Date.now() }) {
  if (!/^\d+$/.test(String(run))) throw new Error("run id must be numeric");
  if (!Number.isFinite(startedMs)) throw new Error("run start must be a time");
  if (target.projectNumber !== undefined && !/^[1-9]\d+$/.test(String(target.projectNumber))) {
    throw new Error("project number must be numeric");
  }
  if (target.kind === "production") {
    if (project !== SANDBOX_PROJECT) {
      throw new Error(`production target must be the sandbox project ${SANDBOX_PROJECT}`);
    }
    if (!target.apiKey || !target.adminToken || !target.projectNumber) {
      throw new Error("production needs an API key, an admin token and the project number");
    }
    if (target.quotaProject !== SANDBOX_PROJECT) {
      throw new Error("quota project must be the sandbox project");
    }
  } else if (target.kind === "local") {
    const url = new URL(target.origin);
    if (url.protocol !== "http:" || !LOOPBACK.has(url.hostname)) {
      throw new Error("local target must be a loopback http origin");
    }
  } else {
    throw new Error(`unknown target kind ${target.kind}`);
  }
  return {
    run: String(run),
    project,
    target,
    window: { from: startedMs - 10 * 60_000, to: startedMs + 12 * 3_600_000 },
  };
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
    for (const path of Object.keys(program.config ?? {})) {
      if (!CONFIG_PATHS.has(path))
        throw new Error(`${program.id}: config path ${path} is not allowed`);
    }
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
      for (const text of walkStrings(payload)) assertOnlyExampleEmail(text, step.id);
    }
  }
  if (requests > REQUEST_CAP)
    throw new Error(`corpus exceeds the request cap (${requests} > ${REQUEST_CAP})`);
  return requests;
}

/**
 * The Admin config paths a program may change. They only affect account operations and carry
 * no key material (unlike signIn.hashConfig or client.apiKey), so their values may be
 * recorded.
 */
export const CONFIG_PATHS = new Set([
  "signIn.allowDuplicateEmails",
  "emailPrivacyConfig.enableImprovedEmailPrivacy",
  "passwordPolicyConfig",
  "client.permissions.disabledUserSignup",
  "client.permissions.disabledUserDeletion",
]);

function assertOnlyExampleEmail(text, where) {
  for (const [, domain] of String(text).matchAll(/@([^\s@"'<>/?#&]+)/g)) {
    if (domain.toLowerCase() !== "example.com") {
      throw new Error(`${where}: email outside example.com (${domain})`);
    }
  }
}

function walkEntries(value, visit, key = "") {
  if (Array.isArray(value)) for (const v of value) walkEntries(v, visit, key);
  else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) walkEntries(v, visit, k);
  } else visit(key, value);
}

const PROJECT_KEYS = new Set(["targetProjectId", "projectId", "tenantProjectId", "project"]);

/**
 * The last check before a request leaves the process: the resolved URL must be a reviewed path
 * family of this project on the target's host, and the resolved body and query may only name
 * this project, example.com addresses and configured test phones. sendOobCode is only a
 * PASSWORD_RESET for an address that has no account. Only the harness itself (wipe and config
 * restore) may reach the project config.
 */
export function guardRequest({ url, init }, ctx, { harness = false } = {}) {
  const parsed = new URL(url);
  const raw = url.slice(parsed.origin.length).split("?")[0];
  if (/%2e|%2f|\/\.\.?(\/|$)/i.test(raw)) throw new Error(`request path is not canonical: ${raw}`);
  let api;
  let path;
  if (ctx.target.kind === "production") {
    api = Object.entries(PRODUCTION_ORIGINS).find(([, origin]) => origin === parsed.origin)?.[0];
    path = parsed.pathname;
  } else {
    if (parsed.origin !== new URL(ctx.target.origin).origin)
      throw new Error("request left the local target");
    api = Object.entries(LOCAL_PREFIX).find(([, prefix]) =>
      parsed.pathname.startsWith(`/${prefix}/`),
    )?.[0];
    path = api ? parsed.pathname.slice(LOCAL_PREFIX[api].length + 1) : parsed.pathname;
  }
  const project = ctx.project.replaceAll(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const families =
    api === "securetoken"
      ? [/^\/v1\/token$/]
      : [
          /^\/v1\/accounts:[A-Za-z]+$/,
          /^\/v2\/passwordPolicy$/,
          new RegExp(`^/v1/projects/${project}/accounts(:[A-Za-z]+)?$`),
          new RegExp(`^/v1/projects/${project}:queryAccounts$`),
          ...(harness ? [new RegExp(`^/admin/v2/projects/${project}/config$`)] : []),
        ];
  if (!api || !families.some((family) => family.test(path))) {
    throw new Error(`request path is not a reviewed family: ${path}`);
  }
  const inputs = [Object.fromEntries(parsed.searchParams)];
  if (typeof init.body === "string") {
    inputs.push(
      init.headers["content-type"] === "application/json"
        ? JSON.parse(init.body)
        : Object.fromEntries(new URLSearchParams(init.body)),
    );
  }
  for (const input of inputs) {
    walkEntries(input, (key, value) => {
      if (PROJECT_KEYS.has(key) && value !== ctx.project)
        throw new Error(`request names another project: ${value}`);
      if (typeof value !== "string") return;
      assertOnlyExampleEmail(value, key);
      for (const [phone] of value.matchAll(/\+\d{8,15}/g)) {
        if (!TEST_PHONES.includes(phone))
          throw new Error(`${phone} is not a configured test phone`);
      }
    });
  }
  if (path.endsWith(":sendOobCode")) {
    const body = inputs[1] ?? {};
    if (
      body.requestType !== "PASSWORD_RESET" ||
      !/-unknown[a-z0-9-]*@example\.com$/i.test(body.email ?? "")
    ) {
      throw new Error("sendOobCode is only a PASSWORD_RESET for an unknown address");
    }
  }
}

const TRANSIENT_CODES = /^(TOO_MANY_ATTEMPTS_TRY_LATER|QUOTA_EXCEEDED|RESOURCE_EXHAUSTED)\b/;

/** A recorded answer that says nothing about behaviour: transport failure, 5xx, rate limit. */
export function isTransient(recorded) {
  if (!recorded) return false;
  // -1: a step whose dependency returned nothing; transient only when that dependency was.
  if (recorded.status === -1) return recorded.dependencyTransient === true;
  if (recorded.status === 0 || recorded.status === 429 || recorded.status >= 500) return true;
  return TRANSIENT_CODES.test(String(recorded.body?.error?.message ?? ""));
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
const ID_KEYS = new Set(["localId", "user_id", "uid"]);
/** The fixed marker production returns instead of a hash to callers that may not see it. */
export const REDACTED_HASH = "UkVEQUNURUQ=";
const GENERATED_ID = /^[A-Za-z0-9]{28}$/;
const INSTANT = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/;

function normalizeString(text, ctx) {
  let out = text.replaceAll(ctx.run, "<run>").replaceAll(ctx.project, RECORDED_PROJECT);
  if (ctx.target.projectNumber) out = out.replaceAll(ctx.target.projectNumber, "<project-number>");
  if (ctx.target.kind === "production") out = out.replaceAll(ctx.target.apiKey, "<api-key>");
  return out;
}

/** `<run-time:type:unit>` for a time inside the run window; any other time is kept. */
function runTime(value, ctx) {
  let millis;
  let unit;
  if (typeof value === "string" && INSTANT.test(value)) {
    millis = Date.parse(value);
    unit = "instant";
  } else if (/^\d{10}$|^\d{13}$/.test(String(value))) {
    unit = String(value).length === 13 ? "ms" : "s";
    millis = Number(value) * (unit === "ms" ? 1 : 1000);
  } else {
    return undefined;
  }
  if (millis < ctx.window.from || millis > ctx.window.to) return undefined;
  return unit === "instant" ? "<run-time:instant>" : `<run-time:${typeof value}:${unit}>`;
}

function normalizeValue(value, key, ctx) {
  if (TOKEN_KEYS.has(key) && typeof value === "string") return `<${key}>`;
  if (key === "passwordHash" && typeof value === "string") {
    return value === REDACTED_HASH ? value : "<bytes>";
  }
  if (key === "salt" && typeof value === "string") return "<bytes>";
  if (TIME_KEYS.has(key) || typeof value === "string") {
    const masked = runTime(value, ctx);
    if (masked) return masked;
  }
  if (typeof value === "string") {
    const text = normalizeString(value, ctx);
    if (ID_KEYS.has(key) && GENERATED_ID.test(text)) return "<generated-localId>";
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

/** Config projections are recorded through the same normalization. */
export const normalizeConfig = (values, ctx) => normalizeValue(values, "", ctx);

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
