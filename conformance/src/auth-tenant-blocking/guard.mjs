// Request guard and corpus validation of the AUTH-TENANT-BLOCKING sandbox harness. Nothing here
// changes how a row is sent or recorded: the guard refuses a request before it leaves the
// process, and the validator refuses a corpus before a run starts. This module is therefore not
// part of the fixture's harness digest (run.mjs).
//
// Production is only ever the Auth side of the disposable Identity Platform sandbox (owner
// decisions TB1 and TB2, 2026-09-25). A request may address a tenant only when this program
// created it, or a reserved id no tenant carries (`atb-nosuch-*`), so a run never touches a
// tenant of another lane. Every phone number is one of the sandbox's test numbers (no SMS is
// sent, M3), every address is @example.com (null MX, so nothing is delivered, E1), and the
// project config changes only through the harness, only at the reviewed paths below; the
// session restores the pre-program values and reads them back.

import { REQUEST_CAP, TEST_PHONES } from "../auth-account/harness.mjs";
import { decodeJwt } from "../auth-credential/tokens.mjs";
import { MFA_CONFIGS } from "../auth-mfa/guard.mjs";

const PRODUCTION_ORIGINS = {
  itk: "https://identitytoolkit.googleapis.com",
  securetoken: "https://securetoken.googleapis.com",
};
const LOCAL_PREFIX = {
  itk: "identitytoolkit.googleapis.com",
  securetoken: "securetoken.googleapis.com",
};

/** A tenant id no tenant carries: production issues `<display name>-<5 of [a-z0-9]>`. */
export const UNKNOWN_TENANT = "atb-nosuch-tenant";
/** Every display name the harness gives a tenant starts with this. */
export const DISPLAY_NAME_PREFIX = "atb-";
/**
 * A display name the harness or a corpus step may give a tenant, the invalid forms the
 * management program offers included (`atb`, `atb_name`, `Atb-Upper`, `1atb-name`); the
 * validator requires it of every name the corpus sends, and the cleanup and restore-sandbox
 * recognise the harness's tenants by it (pre-send review MF-4).
 */
const HARNESS_DISPLAY_NAME = /^\d?atb/i;

export const isHarnessDisplayName = (name) =>
  typeof name === "string" && HARNESS_DISPLAY_NAME.test(name);

/** Every display name a program asks a tenant to carry, by the harness or a step. */
export function requestedDisplayNames(program) {
  const names = new Set();
  for (const spec of Object.values(program.tenants ?? {}))
    if (typeof spec.displayName === "string") names.add(spec.displayName);
  for (const step of program.steps)
    if (/\/tenants(\/[^/]+)?$/.test(step.path) && typeof step.body?.displayName === "string")
      names.add(step.body.displayName);
  return names;
}

/**
 * The project config paths the harness may switch for a program (owner decision TB2): the
 * multi-tenancy switch, and the project settings whose inheritance by tenants is compared (T7).
 */
export const TENANT_CONFIG_PATHS = new Set([
  "multiTenant.allowTenants",
  "emailPrivacyConfig.enableImprovedEmailPrivacy",
  "client.permissions.disabledUserSignup",
  "client.permissions.disabledUserDeletion",
  "signIn.allowDuplicateEmails",
  "mfa",
]);

const sameJson = (a, b) => JSON.stringify(a) === JSON.stringify(b);

function walkEntries(value, visit, key = "") {
  if (Array.isArray(value)) for (const v of value) walkEntries(v, visit, key);
  else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      visit("<key>", k);
      walkEntries(v, visit, k);
    }
  } else visit(key, value);
}

function assertOnlyExampleEmail(text, where) {
  for (const [, domain] of String(text).matchAll(/@([^\s@"'<>/?#&]+)/g)) {
    const lower = domain.toLowerCase();
    // Service-account addresses appear inside custom tokens; they are never mail recipients.
    if (lower !== "example.com" && !lower.endsWith(".iam.gserviceaccount.com")) {
      throw new Error(`${where}: email outside example.com (${domain})`);
    }
  }
}

const PROJECT_KEYS = new Set(["targetProjectId", "projectId", "tenantProjectId", "project"]);
const TENANT_KEYS = new Set(["tenantId", "tenant", "tenant_id"]);

/** Where a request goes: the api family and the path below the target's origin. */
function locate(parsed, ctx) {
  if (ctx.target.kind === "production") {
    const api = Object.entries(PRODUCTION_ORIGINS).find(
      ([, origin]) => origin === parsed.origin,
    )?.[0];
    return { api, path: parsed.pathname };
  }
  if (parsed.origin !== new URL(ctx.target.origin).origin)
    throw new Error("request left the local target");
  const api = Object.entries(LOCAL_PREFIX).find(([, prefix]) =>
    parsed.pathname.startsWith(`/${prefix}/`),
  )?.[0];
  return { api, path: api ? parsed.pathname.slice(LOCAL_PREFIX[api].length + 1) : parsed.pathname };
}

/** Whether a request may name this tenant id. */
function allowedTenant(id, tenants) {
  // An empty id names no tenant: production reads it as the project.
  return id === "" || tenants.has(id) || id === UNKNOWN_TENANT;
}

/**
 * The last check before a request leaves the process. `tenants` holds the ids this program
 * created (or saw created). Only the harness may list accounts for a wipe, write the project
 * config, or delete a tenant it did not create through a recorded step.
 */
export function guardTenantRequest(
  { url, init },
  ctx,
  { harness = false, tenants = new Set(), tenantPhones = new Map() } = {},
) {
  const parsed = new URL(url);
  const raw = url.slice(parsed.origin.length).split("?")[0];
  if (/%2e|%2f|\/\.\.?(\/|$)/i.test(raw)) throw new Error(`request path is not canonical: ${raw}`);
  const { api, path } = locate(parsed, ctx);
  const p = ctx.project.replaceAll(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const method = init.method ?? "GET";
  const families =
    api === "securetoken"
      ? [/^\/v1\/token$/]
      : [
          /^\/v1\/accounts:(signUp|signInWithPassword|signInWithPhoneNumber|signInWithEmailLink|signInWithCustomToken|sendVerificationCode|sendOobCode|resetPassword|createAuthUri|lookup|update|delete)$/,
          /^\/v2\/accounts\/mfaEnrollment:(start|finalize|withdraw)$/,
          /^\/v2\/accounts\/mfaSignIn:(start|finalize)$/,
          /^\/v2\/passwordPolicy$/,
          new RegExp(`^/v1/projects/${p}(/tenants/[^/:]+)?:createSessionCookie$`),
          new RegExp(
            `^/v1/projects/${p}(/tenants/[^/:]+)?/accounts(:(lookup|update|delete|query|batchCreate|batchGet|batchDelete|sendOobCode))?$`,
          ),
          new RegExp(`^/v2/projects/${p}/tenants(/[^/:]+)?$`),
          new RegExp(`^/v2/projects/${p}(/tenants/[^/:]+)?/oauthIdpConfigs(/[^/:]+)?$`),
          new RegExp(`^/admin/v2/projects/${p}/config$`),
        ];
  if (!api || !families.some((family) => family.test(path))) {
    throw new Error(`request path is not a reviewed family: ${path}`);
  }
  for (const [, id] of path.matchAll(/\/tenants\/([^/:]+)/g)) {
    if (!allowedTenant(id, tenants)) throw new Error(`request names a foreign tenant: ${id}`);
  }
  const inputs = [Object.fromEntries(parsed.searchParams)];
  if (typeof init.body === "string") {
    inputs.push(
      init.headers["content-type"] === "application/json"
        ? JSON.parse(init.body)
        : Object.fromEntries(new URLSearchParams(init.body)),
    );
  }
  const body = inputs[1] ?? {};
  // A recorded row may list or delete in bulk only inside a tenant this program created.
  if (new RegExp(`^/v1/projects/${p}/accounts:(batchGet|batchDelete)$`).test(path) && !harness)
    throw new Error("only the harness lists or deletes project accounts in bulk");
  if (path.endsWith("/config")) guardConfig(method, parsed, body, harness);
  if (new RegExp(`^/v2/projects/${p}/tenants$`).test(path) && method === "POST")
    guardTenantCreate(body);
  if (/oauthIdpConfigs/.test(path)) guardProvider(path, method, body, p);
  if (path.endsWith(":sendOobCode") && body.requestType === "VERIFY_AND_CHANGE_EMAIL")
    throw new Error("an email change is never requested");
  guardTenantPhone(path, body, tenantPhones);
  for (const input of inputs) {
    walkEntries(input, (key, value) => {
      if (PROJECT_KEYS.has(key) && value !== ctx.project)
        throw new Error(`request names another project: ${value}`);
      if (TENANT_KEYS.has(key) && typeof value === "string" && !allowedTenant(value, tenants))
        throw new Error(`request names a foreign tenant: ${value}`);
      if (typeof value !== "string") return;
      assertOnlyExampleEmail(value, key);
      for (const [phone] of value.replaceAll(/[\s().-]/g, "").matchAll(/\+\d{8,15}/g)) {
        if (!TEST_PHONES.includes(phone))
          throw new Error(`${phone} is not a configured test phone`);
      }
    });
  }
}

/**
 * A request that texts a code inside a tenant names one of that tenant's own test numbers: a
 * tenant does not answer the project's test numbers without an SMS unless shown to (pre-send
 * review MF-3). The tenant is the body's `tenantId`, or the tenant of the ID token it carries.
 */
function guardTenantPhone(path, body, tenantPhones) {
  let phone;
  if (path === "/v1/accounts:sendVerificationCode") phone = body.phoneNumber;
  else if (path === "/v2/accounts/mfaEnrollment:start")
    phone = body.phoneEnrollmentInfo?.phoneNumber;
  if (phone === undefined) return;
  const tenant =
    typeof body.tenantId === "string" && body.tenantId !== ""
      ? body.tenantId
      : decodeJwt(body.idToken)?.claims?.firebase?.tenant;
  if (tenant === undefined) return;
  if (!tenantPhones.get(tenant)?.has(phone))
    throw new Error(`${phone} is not a test number of tenant ${tenant}`);
}

/** A config read is free; only the harness writes, and only reviewed paths and values. */
function guardConfig(method, parsed, body, harness) {
  if (method === "GET") return;
  if (!harness) throw new Error("only the harness writes the project config");
  const mask = (parsed.searchParams.get("updateMask") ?? "").split(",").filter(Boolean);
  if (
    method !== "PATCH" ||
    mask.length === 0 ||
    !mask.every((path) => TENANT_CONFIG_PATHS.has(path))
  )
    throw new Error(`a config write names only reviewed paths: ${mask.join(",")}`);
  const keys = Object.keys(body).toSorted();
  const expected = [...new Set(mask.map((path) => path.split(".")[0]))].toSorted();
  if (!sameJson(keys, expected)) throw new Error("a config write body holds only its masked paths");
  if (
    mask.includes("mfa") &&
    !Object.values(MFA_CONFIGS).some((value) => sameJson(value, body.mfa))
  )
    throw new Error(`mfa value is not reviewed: ${JSON.stringify(body.mfa)}`);
}

/** A tenant the harness creates carries no key material and names only test phones. */
function guardTenantCreate(body) {
  if (body.hashConfig !== undefined) throw new Error("a tenant is created without hashConfig");
  if (
    body.displayName !== undefined &&
    (typeof body.displayName !== "string" || body.displayName.length > 64)
  )
    throw new Error("a tenant display name is a short string");
}

/**
 * A provider configuration exists only inside a tenant this program created, names Google's
 * issuer and a harness client id, and carries no client secret. Project-level provider
 * configurations are only listed.
 */
function guardProvider(path, method, body, p) {
  const projectLevel = new RegExp(`^/v2/projects/${p}/oauthIdpConfigs`).test(path);
  if (projectLevel && method !== "GET") throw new Error("project providers are only listed");
  if (method === "POST" || method === "PATCH") {
    if (body.clientSecret !== undefined) throw new Error("a provider carries no client secret");
    if (body.issuer !== undefined && body.issuer !== "https://accounts.google.com")
      throw new Error("a provider names Google's issuer");
    if (body.clientId !== undefined && !String(body.clientId).startsWith(DISPLAY_NAME_PREFIX))
      throw new Error("a provider client id is a harness name");
  }
}

function* walkStrings(value) {
  if (typeof value === "string") yield value;
  else if (Array.isArray(value)) for (const v of value) yield* walkStrings(v);
  else if (value && typeof value === "object")
    for (const [k, v] of Object.entries(value)) {
      yield k;
      yield* walkStrings(v);
    }
}

/**
 * Refuses a corpus that could text a real number or mail a real address, switch project config
 * outside the reviewed paths, create a tenant whose display name the cleanup would not
 * recognise, record a config answer beyond one member, address anything but a relative path,
 * or exceed the request cap. Returns the number of recorded requests.
 */
export function validateTenantCorpus(programs) {
  let requests = 0;
  const programIds = new Set();
  for (const program of programs) {
    if (programIds.has(program.id)) throw new Error(`duplicate program ${program.id}`);
    programIds.add(program.id);
    for (const [path, value] of Object.entries(program.config ?? {})) {
      if (!TENANT_CONFIG_PATHS.has(path) || path === "multiTenant.allowTenants")
        throw new Error(`${program.id}: config path ${path} is not a program switch`);
      if (path === "mfa" && !Object.values(MFA_CONFIGS).some((allowed) => sameJson(allowed, value)))
        throw new Error(`${program.id}: mfa value is not a reviewed program config`);
      if (path !== "mfa" && typeof value !== "boolean")
        throw new Error(`${program.id}: ${path} is a switch`);
    }
    for (const [label, spec] of Object.entries(program.tenants ?? {})) {
      if (!/^[a-z]$/.test(label))
        throw new Error(`${program.id}: tenant label ${label} is one letter`);
      if (!String(spec.displayName ?? "").startsWith(DISPLAY_NAME_PREFIX))
        throw new Error(
          `${program.id}: tenant ${label} display name starts with ${DISPLAY_NAME_PREFIX}`,
        );
      if (spec.hashConfig !== undefined) throw new Error(`${program.id}: no hashConfig`);
    }
    for (const [name, spec] of Object.entries(program.tokens ?? {})) {
      if ((spec.signer ?? "project") !== "project")
        throw new Error(`${program.id}: custom token ${name} is signed by the project only`);
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
      if (step.waitSeconds || step.age || step.waitUntil)
        throw new Error(`${program.id}#${step.id}: tenant programs do not wait`);
      if (step.path === "admin/v2/projects/{project}/config") {
        if (step.method !== "GET" || step.auth !== "admin" || typeof step.project !== "string")
          throw new Error(`${step.id}: a config row is an Admin read of one member`);
      } else if (step.project !== undefined) {
        throw new Error(`${step.id}: only a config answer is projected`);
      }
      if (/^v2\/projects\/\{project\}\/tenants(\/[^/]+)?$/.test(step.path)) {
        const name = step.body?.displayName;
        if (name !== undefined && !isHarnessDisplayName(name))
          throw new Error(`${step.id}: a tenant display name is a harness name (${name})`);
      }
      if (step.path.endsWith("sendOobCode") && step.body?.requestType === "VERIFY_AND_CHANGE_EMAIL")
        throw new Error(`${step.id}: an email change is never requested`);
      for (const text of walkStrings({ body: step.body, form: step.form, query: step.query })) {
        assertOnlyExampleEmail(text, step.id);
        if (/\+\d/.test(text))
          throw new Error(`${step.id}: a phone is named as PHONE(n), never by value`);
      }
    }
  }
  if (requests > REQUEST_CAP)
    throw new Error(`corpus exceeds the request cap (${requests} > ${REQUEST_CAP})`);
  return requests;
}
