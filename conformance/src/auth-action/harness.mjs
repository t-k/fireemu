// Request guard, action-link normalization and corpus validation of the AUTH-ACTION sandbox
// harness. Request construction, the production/local context and transient classification come
// from the AUTH-ACCOUNT harness; token decoding comes from the AUTH-CREDENTIAL harness.
//
// Production is only ever the disposable Identity Platform sandbox. Action codes are obtained
// through the Admin `accounts:sendOobCode` with `returnOobLink: true`, which returns the code
// and mails nothing. The client `accounts:sendOobCode` is only ever a PASSWORD_RESET for an
// address that has no account, which production answers without sending anything. Applying an
// email change may send the old address a change notice; every address is @example.com, which
// publishes a null MX (RFC 7505), so nothing is delivered.

import { REQUEST_CAP, SANDBOX_PROJECT, TEST_PHONES } from "../auth-account/harness.mjs";
import { normalizeCredentialResponse } from "../auth-credential/tokens.mjs";

const PRODUCTION_ORIGINS = {
  itk: "https://identitytoolkit.googleapis.com",
  securetoken: "https://securetoken.googleapis.com",
};
const LOCAL_PREFIX = {
  itk: "identitytoolkit.googleapis.com",
  securetoken: "securetoken.googleapis.com",
};

/** The only project config paths a program may switch, and the value it may switch to. */
export const ACTION_CONFIG_PATHS = new Set(["signIn.email.passwordRequired"]);

/**
 * The continue-URL hosts a request may name: the sandbox's two authorized domains, `localhost`
 * (not authorized on the sandbox) and one example.com host that is never authorized.
 */
export function allowedContinueHosts(project) {
  return new Set([
    `${project}.firebaseapp.com`,
    `${project}.web.app`,
    "localhost",
    "unauthorized.example.com",
  ]);
}

function walkEntries(value, visit, key = "") {
  if (Array.isArray(value)) for (const v of value) walkEntries(v, visit, key);
  else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) walkEntries(v, visit, k);
  } else visit(key, value);
}

function assertOnlyExampleEmail(text, where) {
  for (const [, domain] of String(text).matchAll(/@([^\s@"'<>/?#&]+)/g)) {
    if (domain.toLowerCase() !== "example.com") {
      throw new Error(`${where}: email outside example.com (${domain})`);
    }
  }
}

const PROJECT_KEYS = new Set(["targetProjectId", "projectId", "tenantProjectId", "project"]);
const URL_KEYS = new Set(["continueUrl", "continueUri"]);

function assertContinueUrl(value, ctx) {
  let host;
  try {
    host = new URL(value).hostname;
  } catch {
    // A value that is not an absolute URL names no host; it is sent to be validated.
    return;
  }
  if (!allowedContinueHosts(ctx.project).has(host)) {
    throw new Error(`continueUrl host ${host} is not a reviewed host`);
  }
}

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

/**
 * The last check before a request leaves the process: a reviewed Identity Toolkit or Secure
 * Token path of this project on the target's host, whose body and query name only this
 * project, example.com addresses, configured test phones and reviewed continue hosts. Codes
 * come only from the Admin route with `returnOobLink: true`; the client route only asks for a
 * PASSWORD_RESET of an unknown address. Only the harness may wipe or switch the config.
 */
export function guardActionRequest({ url, init }, ctx, { harness = false } = {}) {
  const parsed = new URL(url);
  const raw = url.slice(parsed.origin.length).split("?")[0];
  if (/%2e|%2f|\/\.\.?(\/|$)/i.test(raw)) throw new Error(`request path is not canonical: ${raw}`);
  const { api, path } = locate(parsed, ctx);
  const project = ctx.project.replaceAll(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const families =
    api === "securetoken"
      ? [/^\/v1\/token$/]
      : [
          /^\/v1\/accounts:(signUp|signInWithPassword|signInWithEmailLink|signInWithPhoneNumber|sendVerificationCode|sendOobCode|resetPassword|lookup|update|delete)$/,
          new RegExp(`^/v1/projects/${project}:createSessionCookie$`),
          new RegExp(`^/v1/projects/${project}/accounts(:(lookup|update|delete|sendOobCode))?$`),
          ...(harness
            ? [
                new RegExp(`^/v1/projects/${project}/accounts:(batchGet|batchDelete)$`),
                new RegExp(`^/admin/v2/projects/${project}/config$`),
              ]
            : []),
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
  const body = inputs[1] ?? {};
  if (path.endsWith("/config")) guardConfigWrite(init, parsed, body);
  if (path.endsWith(":sendOobCode")) guardOobRequest(path, init, body, project);
  for (const input of inputs) {
    walkEntries(input, (key, value) => {
      if (PROJECT_KEYS.has(key) && value !== ctx.project)
        throw new Error(`request names another project: ${value}`);
      if (typeof value !== "string") return;
      if (URL_KEYS.has(key)) assertContinueUrl(value, ctx);
      assertOnlyExampleEmail(value, key);
      for (const [phone] of value.replaceAll(/[\s().-]/g, "").matchAll(/\+\d{8,15}/g)) {
        if (!TEST_PHONES.includes(phone))
          throw new Error(`${phone} is not a configured test phone`);
      }
    });
  }
}

/** The harness reads the config freely but writes only the email-link switch. */
function guardConfigWrite(init, parsed, body) {
  if (init.method === "GET") return;
  const mask = (parsed.searchParams.get("updateMask") ?? "").split(",").filter(Boolean);
  if (
    init.method !== "PATCH" ||
    mask.length === 0 ||
    !mask.every((p) => ACTION_CONFIG_PATHS.has(p))
  )
    throw new Error(`config write outside ${[...ACTION_CONFIG_PATHS].join(",")}`);
  const keys = JSON.stringify(Object.keys(body)) + JSON.stringify(Object.keys(body.signIn ?? {}));
  if (
    keys !== '["signIn"]["email"]' ||
    JSON.stringify(Object.keys(body.signIn.email)) !== '["passwordRequired"]'
  )
    throw new Error("config write body names more than signIn.email.passwordRequired");
}

/**
 * The runtime form of the corpus rule: the Admin route always asks for the link back (so nothing
 * is mailed), and the client route only asks for a reset of an address that has no account.
 */
function guardOobRequest(path, init, body, project) {
  const adminRoute = new RegExp(`^/v1/projects/${project}/accounts:sendOobCode$`).test(path);
  if (adminRoute) {
    if (!String(init.headers.authorization ?? "").startsWith("Bearer "))
      throw new Error("the Admin sendOobCode needs the owner credential");
    if (body.returnOobLink !== true)
      throw new Error("the Admin sendOobCode must ask for the link back");
    return;
  }
  if (
    body.requestType !== "PASSWORD_RESET" ||
    body.idToken !== undefined ||
    (body.returnOobLink !== undefined && body.returnOobLink !== true) ||
    !/-unknown[a-z0-9-]*@example\.com$/i.test(body.email ?? "")
  ) {
    throw new Error("the client sendOobCode is only a PASSWORD_RESET for an unknown address");
  }
}

/**
 * The recorded form of an action link. Where the handler lives (production's hosted action
 * page, fireemu's own `/emulator/action`) is not compared (scope decision E2); every query
 * parameter is, with the code recorded as whether it is the answer's own `oobCode` and the API
 * key by presence.
 */
export function describeLink(link, oobCode) {
  let url;
  try {
    url = new URL(link);
  } catch {
    return "<unparsable-link>";
  }
  const params = {};
  let code = "absent";
  for (const [name, value] of url.searchParams) {
    // Kept out of `params`: the normalization masks every `oobCode` member, which would hide
    // whether the link carries the answer's own code.
    if (name === "oobCode") code = value === oobCode ? "the-answer-oobCode" : "another-code";
    else if (name === "apiKey") params.apiKey = value ? "<present>" : "<empty>";
    else params[name] = value;
  }
  return { handler: "<action-handler>", code, params };
}

function describeLinks(value) {
  if (Array.isArray(value)) return value.map(describeLinks);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [
        k,
        k === "oobLink" && typeof v === "string"
          ? describeLink(v, value.oobCode)
          : describeLinks(v),
      ]),
    );
  }
  return value;
}

/**
 * The recorded form of one HTTP answer: action links described as above, then the
 * AUTH-CREDENTIAL normalization (tokens decoded; codes, ids, run-window times, the project,
 * its number and the API key as placeholders).
 */
export function normalizeActionResponse(status, text, ctx) {
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return { status, nonJson: true };
  }
  return normalizeCredentialResponse(status, JSON.stringify(describeLinks(body)), ctx);
}

function* walkStrings(value) {
  if (typeof value === "string") yield value;
  else if (Array.isArray(value)) for (const v of value) yield* walkStrings(v);
  else if (value && typeof value === "object")
    for (const v of Object.values(value)) yield* walkStrings(v);
}

/**
 * Refuses a corpus that could mail a real mailbox or text a real number, change a config path
 * other than the email-link switch, address anything but a relative path, wait anywhere but in
 * the last program, or exceed the request cap. Returns the number of recorded requests.
 */
export function validateActionCorpus(programs) {
  let requests = 0;
  const programIds = new Set();
  programs.forEach((program, index) => {
    if (programIds.has(program.id)) throw new Error(`duplicate program ${program.id}`);
    programIds.add(program.id);
    for (const path of Object.keys(program.config ?? {})) {
      if (!ACTION_CONFIG_PATHS.has(path))
        throw new Error(`${program.id}: config path ${path} is not allowed`);
      if (typeof program.config[path] !== "boolean")
        throw new Error(`${program.id}: ${path} is a switch`);
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
      if (step.waitSeconds && index !== programs.length - 1)
        throw new Error(`${program.id}#${step.id}: only the last program may wait`);
      if (step.noLinkExpected) {
        // Only an address that cannot receive anything may come back without a link.
        const email = String(step.body?.email ?? "");
        if (
          step.path !== "v1/projects/{project}/accounts:sendOobCode" ||
          (!/^EMAIL\(unknown[a-z0-9-]*\)$/.test(email) && /@|^EMAIL/.test(email))
        )
          throw new Error(`${step.id}: only an unknown address may expect no link`);
      }
      for (const key of ["email", "newEmail"]) {
        const creates =
          step.path === "v1/projects/{project}/accounts" ||
          step.path.endsWith("accounts:update") ||
          step.path.endsWith("accounts:signInWithEmailLink") ||
          (key === "newEmail" && step.path.endsWith("accounts:sendOobCode"));
        if (creates && String(step.body?.[key] ?? "").startsWith("EMAIL(unknown"))
          throw new Error(`${step.id}: an unknown-* address must never belong to an account`);
      }
      if (step.path === "v1/accounts:update" && step.body?.email !== undefined)
        throw new Error(`${step.id}: the client update never changes the address`);
      if (step.path === "v1/projects/{project}/accounts:sendOobCode") {
        if (step.auth !== "admin" || step.body?.returnOobLink !== true)
          throw new Error(`${step.id}: the Admin sendOobCode asks for the link back`);
      } else if (step.path.endsWith("accounts:sendOobCode")) {
        if (
          step.body?.requestType !== "PASSWORD_RESET" ||
          step.body?.idToken !== undefined ||
          !/^EMAIL\(unknown[a-z0-9-]*\)$/.test(step.body?.email ?? "")
        )
          throw new Error(`${step.id}: the client sendOobCode only resets an unknown address`);
      }
      if (
        step.path.endsWith("accounts:sendVerificationCode") &&
        !/^PHONE\(\d\)$/.test(step.body?.phoneNumber ?? "")
      ) {
        throw new Error(`${step.id}: sendVerificationCode only to a configured test phone`);
      }
      if (step.waitUntil) throw new Error(`${step.id}: waits are relative (waitSeconds)`);
      for (const text of walkStrings({ body: step.body, form: step.form, query: step.query }))
        assertOnlyExampleEmail(text, step.id);
    }
  });
  if (requests > REQUEST_CAP)
    throw new Error(`corpus exceeds the request cap (${requests} > ${REQUEST_CAP})`);
  return requests;
}

export { SANDBOX_PROJECT };
