// Request guard and corpus validation of the AUTH-CONFIG-SDK sandbox harness. Nothing here
// changes how a row is sent or recorded: the guard refuses a request before it leaves the
// process, and the validator refuses a corpus before a run starts. This module is therefore not
// part of the fixture's harness digest (run.mjs).
//
// Production is only ever the disposable Identity Platform sandbox. Every request passes the
// same guard, whether a corpus step, the harness itself (wipe, config snapshot and restore), the
// Web SDK (its fetch) or the Admin SDK (its https requests). The guard allows:
// - reviewed Identity Toolkit and Secure Token paths of this project;
// - for the Admin SDK only, Google's public token-verification keys and IAM signBlob of the
//   project's own Admin SDK service account (owner decision K6);
// - bodies and queries that name only this project, @example.com addresses (null MX), the
//   sandbox's test phone numbers and reviewed continue hosts;
// - action codes only through the Admin route with the link returned (nothing is mailed);
// - configuration writes only to reviewed paths, never reCAPTCHA ENFORCE (K2), never key
//   material or other lanes' members (K9, K10, K12).

import { REQUEST_CAP, SANDBOX_PROJECT, TEST_PHONES } from "../auth-account/harness.mjs";

const HOSTS = {
  itk: "identitytoolkit.googleapis.com",
  securetoken: "securetoken.googleapis.com",
};
/** Hosts only the Admin SDK reaches, and the paths it may reach there. */
const ADMIN_SDK_HOSTS = {
  "www.googleapis.com": [
    /^\/robot\/v1\/metadata\/x509\/securetoken@system\.gserviceaccount\.com$/,
    /^\/identitytoolkit\/v3\/relyingparty\/publicKeys$/,
  ],
  "iamcredentials.googleapis.com": [
    new RegExp(
      `^/v1/projects/-/serviceAccounts/firebase-adminsdk-fbsvc@${SANDBOX_PROJECT}\\.iam\\.gserviceaccount\\.com:signBlob$`,
    ),
  ],
};
/**
 * A fictional 555-01xx number the invalid-code probes add to the test-number map next to the
 * six sandbox numbers. It may appear only in a config write: nothing is ever sent to it.
 */
export const PROBE_PHONE = "+16505550107";
export const SIGNER_ACCOUNT = `firebase-adminsdk-fbsvc@${SANDBOX_PROJECT}.iam.gserviceaccount.com`;

/**
 * Config paths a program may write (as a recorded step) and the harness restores. Each is a
 * leaf or a whole member whose value the harness can snapshot and write back.
 */
export const CONFIG_WRITE_PATHS = new Set([
  "signIn.email.enabled",
  "signIn.email.passwordRequired",
  "signIn.anonymous.enabled",
  "signIn.phoneNumber.enabled",
  "signIn.phoneNumber.testPhoneNumbers",
  "signIn.allowDuplicateEmails",
  "emailPrivacyConfig.enableImprovedEmailPrivacy",
  "passwordPolicyConfig",
  "client.permissions.disabledUserSignup",
  "client.permissions.disabledUserDeletion",
  "recaptchaConfig",
  "quota.signUpQuotaConfig",
  "mobileLinksConfig.domain",
  "smsRegionConfig",
  "notification.defaultLocale",
  "notification.sendEmail.resetPasswordTemplate.subject",
  "autodeleteAnonymousUsers",
  "monitoring.requestLogging.enabled",
  "authorizedDomains",
]);

/**
 * Mask paths a recorded step may name besides the write paths: parents whose every writable
 * leaf the program also touches, read-only members that hold no key material, and names
 * production does not know. None of them can change key material or another lane's member.
 */
export const CONFIG_PROBE_PATHS = new Set([
  "emailPrivacyConfig",
  "client.permissions",
  "signIn.email",
  "signIn.anonymous",
  "name",
  "subtype",
  "defaultHostingSite",
  "signIn.unknownMember",
  "unknownMember",
]);

/** Where a written path's value must stay (config members that are never written). */
const NEVER_WRITTEN = [
  "signIn.hashConfig",
  "client.apiKey",
  "client.firebaseSubdomain",
  "mfa",
  "multiTenant",
  "blockingFunctions",
  "notification.sendEmail.method",
  "notification.sendEmail.smtp",
  "notification.sendEmail.callbackUri",
];

/** Continue URLs, link domains and authorized domains a request may name. */
export function allowedHosts(project) {
  return new Set([
    `${project}.firebaseapp.com`,
    `${project}.web.app`,
    "localhost",
    "unauthorized.example.com",
    "app.example.com",
  ]);
}

function walkEntries(value, visit, key = "", path = "") {
  if (Array.isArray(value)) for (const v of value) walkEntries(v, visit, key, path);
  else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) walkEntries(v, visit, k, path ? `${path}.${k}` : k);
  } else visit(key, value, path);
}

function assertOnlyExampleEmail(text, where) {
  for (const [, domain] of String(text).matchAll(/@([^\s@"'<>/?#&]+)/g)) {
    // A service-account name in a signBlob path is not an address; bodies never carry one.
    if (domain.toLowerCase() !== "example.com") {
      throw new Error(`${where}: email outside example.com (${domain})`);
    }
  }
}

const PROJECT_KEYS = new Set(["targetProjectId", "projectId", "tenantProjectId", "project"]);
const URL_KEYS = new Set(["continueUrl", "continueUri", "requestUri"]);
const DOMAIN_KEYS = new Set(["linkDomain", "dynamicLinkDomain"]);

function assertHost(value, ctx, key) {
  let host;
  try {
    host = new URL(value).hostname;
  } catch {
    // A value that is not an absolute URL names no host; it is sent to be validated.
    return;
  }
  if (!allowedHosts(ctx.project).has(host)) throw new Error(`${key} host ${host} is not reviewed`);
}

/** The API family and the path below the target's origin, or a refusal. */
function locate(parsed, ctx, role) {
  if (ctx.target.kind === "production") {
    if (parsed.protocol !== "https:") throw new Error("production requests use https");
    const api = Object.entries(HOSTS).find(([, host]) => host === parsed.host)?.[0];
    if (api) return { api, path: parsed.pathname };
    const extra = ADMIN_SDK_HOSTS[parsed.host];
    if (role === "sdk-admin" && extra?.some((family) => family.test(parsed.pathname)))
      return { api: "google", path: parsed.pathname };
    throw new Error(`request host ${parsed.host} is not reviewed`);
  }
  if (parsed.origin !== new URL(ctx.target.origin).origin)
    throw new Error("request left the local target");
  const api = Object.entries(HOSTS).find(([, host]) =>
    parsed.pathname.startsWith(`/${host}/`),
  )?.[0];
  return { api, path: api ? parsed.pathname.slice(HOSTS[api].length + 1) : parsed.pathname };
}

function families(project, role) {
  const p = project.replaceAll(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const clientMethods =
    "signUp|signInWithPassword|signInWithCustomToken|signInWithEmailLink|signInWithPhoneNumber|sendVerificationCode|sendOobCode|resetPassword|lookup|update|delete|createAuthUri";
  return [
    new RegExp(`^/v1/accounts:(${clientMethods})$`),
    /^\/v2\/(passwordPolicy|recaptchaConfig)$/,
    /^\/v1\/(projects|recaptchaParams)$/,
    new RegExp(`^/v1/projects/${p}/accounts(:(lookup|update|delete|sendOobCode|batchCreate))?$`),
    new RegExp(`^/v1/projects/${p}:createSessionCookie$`),
    new RegExp(`^/(admin/)?v2/projects/${p}/config$`),
    ...(role === "harness"
      ? [new RegExp(`^/v1/projects/${p}/accounts:(batchGet|batchDelete)$`)]
      : []),
  ];
}

/**
 * The last check before a request leaves the process. `role` is "step" (a recorded corpus
 * request), "harness" (wipe, config snapshot and restore), "sdk-web" or "sdk-admin".
 */
export function guardHttp(
  { url, method = "GET", headers = {}, body },
  ctx,
  { role, bodyPending = false },
) {
  if (!["step", "harness", "sdk-web", "sdk-admin"].includes(role)) throw new Error("unknown role");
  const parsed = new URL(url);
  const raw = url.slice(parsed.origin.length).split("?")[0];
  if (/%2e|%2f|\/\.\.?(\/|$)/i.test(raw)) throw new Error(`request path is not canonical: ${raw}`);
  const { api, path } = locate(parsed, ctx, role);
  if (api === "google") {
    // Key downloads carry nothing of ours; signBlob signs a custom token for this project.
    if (method === "POST" && !path.endsWith(":signBlob")) throw new Error("unexpected POST");
    if (ctx.target.kind === "production" && path.endsWith(":signBlob")) assertQuotaProject(headers);
    return;
  }
  const allowed =
    api === "securetoken" ? [/^\/v1\/token$/] : api === "itk" ? families(ctx.project, role) : [];
  if (!allowed.some((family) => family.test(path)))
    throw new Error(`request path is not a reviewed family: ${path}`);
  const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
  if (ctx.target.kind === "production" && String(lower.authorization ?? "").startsWith("Bearer "))
    assertQuotaProject(lower);
  // The Admin SDK transport is checked once before its body exists and again with it.
  if (bodyPending) return;
  const parsedBody = parseBody(body, lower["content-type"], role);
  const inputs = [Object.fromEntries(parsed.searchParams), parsedBody ?? {}];
  if (path.endsWith("/config")) guardConfigWrite(method, parsed, parsedBody ?? {}, role, ctx);
  if (path.endsWith(":sendOobCode")) guardOobRequest(path, lower, parsedBody ?? {}, ctx);
  for (const input of inputs) {
    walkEntries(input, (key, value) => {
      if (PROJECT_KEYS.has(key) && value !== ctx.project && value !== undefined)
        throw new Error(`request names another project: ${value}`);
      if (typeof value !== "string") return;
      if (URL_KEYS.has(key)) assertHost(value, ctx, key);
      if (
        DOMAIN_KEYS.has(key) &&
        value &&
        !allowedHosts(ctx.project).has(value) &&
        !value.endsWith(".page.link")
      )
        throw new Error(`${key} ${value} is not reviewed`);
      assertOnlyExampleEmail(value, key);
      for (const [phone] of value.replaceAll(/[\s().-]/g, "").matchAll(/\+\d{8,15}/g)) {
        if (phone === PROBE_PHONE && path.endsWith("/config")) continue;
        if (!TEST_PHONES.includes(phone))
          throw new Error(`${phone} is not a configured test phone`);
      }
    });
  }
}

function assertQuotaProject(headers) {
  const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
  if (lower["x-goog-user-project"] !== SANDBOX_PROJECT)
    throw new Error("an authorized production request must bill the sandbox project");
}

function parseBody(body, contentType = "", role = "step") {
  if (body !== undefined && typeof body !== "string") throw new Error("request body is not text");
  if (body === undefined || body === "") return undefined;
  if (/json/.test(contentType)) {
    try {
      return JSON.parse(body);
    } catch {
      // A deliberately malformed corpus body names nothing; it is sent to be refused. An SDK
      // never sends one, so an unreadable SDK body is refused rather than read as empty.
      if (role === "step") return undefined;
      throw new Error("an SDK request body that is not JSON");
    }
  }
  return Object.fromEntries(new URLSearchParams(body));
}

/** Every dotted leaf path of a JSON value (maps such as testPhoneNumbers count as leaves). */
export function leafPaths(value, prefix = "") {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    if (prefix.endsWith("testPhoneNumbers")) return [prefix];
    const entries = Object.entries(value);
    // An empty object is a value only at a write path (`smsRegionConfig: {allowByDefault: {}}`
    // sets one); elsewhere it is the parent a masked but absent value leaves behind.
    if (entries.length === 0)
      return prefix && [...CONFIG_WRITE_PATHS].some((w) => under(prefix, w)) ? [prefix] : [];
    return entries.flatMap(([k, v]) => leafPaths(v, prefix ? `${prefix}.${k}` : k));
  }
  return prefix ? [prefix] : [];
}

const under = (path, parent) => path === parent || path.startsWith(`${parent}.`);

/** The written path a body leaf or mask path falls under, if any. */
export const writePathOf = (path) => [...CONFIG_WRITE_PATHS].find((w) => under(path, w));

/**
 * Config writes: reviewed mask paths only, every body member under a write path, never key
 * material, another lane's member or reCAPTCHA ENFORCE. The harness restore writes only write
 * paths. A PATCH without a mask is refused (production's answer to it is unobserved).
 */
function guardConfigWrite(method, parsed, body, role, ctx) {
  if (method === "GET") return;
  if (method !== "PATCH") throw new Error(`config ${method} is not allowed`);
  // An omitted or empty mask is refused: production's reading of either is unobserved, and a
  // full replacement would reset members this harness may not write back (scope decision K13).
  const mask = (parsed.searchParams.get("updateMask") ?? "").split(",").filter(Boolean);
  if (mask.length === 0) throw new Error("a config write names a non-empty updateMask");
  // A program may write only what it restores; the harness restores only write paths.
  const touched = (path) => {
    const written = writePathOf(path);
    if (!written) return true;
    if (role === "harness" || ctx.touches === undefined) return true;
    return ctx.touches.some((t) => under(written, t) || under(t, written));
  };
  for (const path of mask) {
    const writable = writePathOf(path) !== undefined;
    if (role === "harness" ? !writable : !writable && !CONFIG_PROBE_PATHS.has(path))
      throw new Error(`config mask path ${path} is not reviewed`);
    if (!touched(path)) throw new Error(`config mask path ${path} is not touched by the program`);
  }
  for (const leaf of leafPaths(body)) {
    if (NEVER_WRITTEN.some((never) => under(leaf, never)))
      throw new Error(`config write names ${leaf}`);
    if (!writePathOf(leaf) && !(role === "step" && PROBE_BODY_MEMBERS.has(leaf)))
      throw new Error(`config body member ${leaf} is not reviewed`);
    if (!touched(leaf)) throw new Error(`config body member ${leaf} is not touched by the program`);
  }
  // Only OFF, AUDIT and unspecified (what a cleared config keeps), or the one unknown name the
  // validation probes send (`SOMETIMES`), which production refuses; never ENFORCE or a numeric
  // enum value (K2). Production also takes the proto names (`email_password_enforcement_state`),
  // so every member under recaptchaConfig named like a state is checked, whatever its spelling.
  const recaptcha = body.recaptchaConfig ?? body.recaptcha_config;
  const states = [];
  const collectStates = (value) => {
    if (Array.isArray(value)) value.forEach(collectStates);
    else if (value && typeof value === "object") {
      for (const [key, inner] of Object.entries(value)) {
        if (/enforcement_?state$/i.test(key)) states.push(inner);
        else collectStates(inner);
      }
    }
  };
  collectStates(recaptcha);
  if (
    states.some(
      (state) =>
        state !== undefined &&
        !["OFF", "AUDIT", "RECAPTCHA_PROVIDER_ENFORCEMENT_STATE_UNSPECIFIED", "SOMETIMES"].includes(
          state,
        ),
    )
  )
    throw new Error("reCAPTCHA is never enforced on the sandbox (K2)");
  for (const domain of body.authorizedDomains ?? []) {
    if (!allowedHosts(ctx.project).has(domain) && !INVALID_DOMAIN_PROBES.has(domain))
      throw new Error(`authorized domain ${domain} is not reviewed`);
  }
}

/**
 * Body members a recorded step may send besides write paths: read-only members (written back
 * with their current value) and one member production does not know.
 */
const PROBE_BODY_MEMBERS = new Set(["name", "subtype", "defaultHostingSite", "unknownMember"]);

/** Malformed authorized domains a validation step may send (production is expected to refuse). */
export const INVALID_DOMAIN_PROBES = new Set([
  "",
  "https://app.example.com",
  "app.example.com:8080",
  "*.example.com",
  "app example.com",
]);

/**
 * Action codes only through the Admin route with the link returned; the client route only asks
 * for a reset of an address that has no account (production answers without mailing).
 */
function guardOobRequest(path, headers, body, ctx) {
  const project = ctx.project.replaceAll(/[.*+?^${}()|[\]\\]/g, "\\$&");
  if (new RegExp(`^/v1/projects/${project}/accounts:sendOobCode$`).test(path)) {
    if (!String(headers.authorization ?? "").startsWith("Bearer "))
      throw new Error("the Admin sendOobCode needs the owner credential");
    if (body.returnOobLink !== true)
      throw new Error("the Admin sendOobCode must ask for the link back");
    return;
  }
  if (
    body.requestType !== "PASSWORD_RESET" ||
    body.idToken !== undefined ||
    !/-unknown[a-z0-9-]*@example\.com$/i.test(body.email ?? "")
  ) {
    throw new Error("the client sendOobCode is only a PASSWORD_RESET for an unknown address");
  }
}

function* walkStrings(value) {
  if (typeof value === "string") yield value;
  else if (Array.isArray(value)) for (const v of value) yield* walkStrings(v);
  else if (value && typeof value === "object")
    for (const v of Object.values(value)) yield* walkStrings(v);
}

const PROJECTIONS = new Set(["strict", "strict-unsigned-emulator", "emulator"]);

/**
 * Refuses a corpus that could mail a real mailbox or text a real number, write a config path it
 * does not restore, address anything but a relative path, or exceed the request cap. Returns
 * the number of recorded requests (an SDK call counts as one).
 */
export function validateConfigSdkCorpus(programs, { sdkOperations } = {}) {
  let requests = 0;
  const programIds = new Set();
  for (const program of programs) {
    const label = program.id;
    if (programIds.has(label)) throw new Error(`duplicate program ${label}`);
    programIds.add(label);
    if (!label.startsWith("auth-config-sdk/")) throw new Error(`${label}: id prefix`);
    if (!PROJECTIONS.has(program.projection)) throw new Error(`${label}: projection`);
    const touches = program.touches ?? [];
    for (const path of touches) {
      if (!CONFIG_WRITE_PATHS.has(path)) throw new Error(`${label}: touches ${path}`);
    }
    const stepIds = new Set();
    for (const step of program.steps) {
      requests += 1;
      if (stepIds.has(step.id)) throw new Error(`${label}: duplicate step ${step.id}`);
      stepIds.add(step.id);
      if (step.waitSeconds) throw new Error(`${label}#${step.id}: no waits in this corpus`);
      if (step.sdk) {
        if (sdkOperations && !sdkOperations.has(step.sdk))
          throw new Error(`${label}#${step.id}: unknown SDK operation ${step.sdk}`);
        if (!program.projection.startsWith("strict-unsigned") && program.projection !== "emulator")
          throw new Error(`${label}#${step.id}: SDK steps run under an SDK projection`);
        for (const text of walkStrings(step.args ?? [])) assertOnlyExampleEmail(text, step.id);
        continue;
      }
      if (/^[a-z]+:|^\/\/|\.\./i.test(step.path))
        throw new Error(`${label}#${step.id}: path must be relative`);
      for (const text of walkStrings({ b: step.body, q: step.query, r: step.rawBody }))
        assertOnlyExampleEmail(text, step.id);
      if (step.path.endsWith("config") && (step.method ?? "POST") === "PATCH") {
        const mask = String(step.query?.updateMask ?? "")
          .split(",")
          .filter(Boolean);
        const body = step.body ?? {};
        for (const leaf of [...mask, ...leafPaths(body)]) {
          const written = writePathOf(leaf);
          if (written && !touches.some((t) => under(written, t) || under(t, written)))
            throw new Error(`${label}#${step.id}: writes ${leaf} but does not touch it`);
          // A parent mask replaces every leaf under it; each of them must be restored.
          if (!written && CONFIG_PROBE_PATHS.has(leaf)) {
            const leaves = [...CONFIG_WRITE_PATHS].filter((w) => under(w, leaf));
            for (const w of leaves)
              if (!touches.includes(w)) throw new Error(`${label}#${step.id}: ${leaf} needs ${w}`);
          }
        }
      }
      if (step.path.endsWith("accounts:sendOobCode") && step.path.startsWith("v1/accounts")) {
        if (!/^EMAIL\(unknown[a-z0-9-]*\)$/.test(step.body?.email ?? ""))
          throw new Error(`${step.id}: the client sendOobCode only for an unknown address`);
      }
      if (
        step.path.endsWith("sendVerificationCode") &&
        !/^PHONE\(\d\)$/.test(step.body?.phoneNumber ?? "")
      )
        throw new Error(`${step.id}: sendVerificationCode only to a test phone PHONE(n)`);
    }
  }
  if (requests > REQUEST_CAP) throw new Error(`corpus exceeds the request cap (${requests})`);
  return requests;
}
