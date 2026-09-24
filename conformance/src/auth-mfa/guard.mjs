// Request guard and corpus validation of the AUTH-MFA sandbox harness. Nothing here changes how
// a row is sent or recorded: the guard refuses a request before it leaves the process, and the
// validator refuses a corpus before a run starts. This module is therefore not part of the
// fixture's harness digest (run.mjs), unlike the normalization in harness.mjs.
//
// Production is only ever the Auth side of the disposable Identity Platform sandbox. Every
// phone number is one of the sandbox's configured test numbers (fixed code, no SMS is sent,
// owner decision M3), every address is @example.com (null MX), and nothing asks production to
// mail anything: the one action code (an email-link sign-in, owner decision M5) comes from the
// Admin sendOobCode with the link returned. The only project config a request may change is
// `mfa`, to one of the reviewed values below (owner decision M1), and the email-link switch
// (M5); the session restores the pre-run values.

import { REQUEST_CAP, TEST_PHONES } from "../auth-account/harness.mjs";

const PRODUCTION_ORIGINS = {
  itk: "https://identitytoolkit.googleapis.com",
  securetoken: "https://securetoken.googleapis.com",
};
const LOCAL_PREFIX = {
  itk: "identitytoolkit.googleapis.com",
  securetoken: "securetoken.googleapis.com",
};

const totp = (adjacentIntervals) => ({
  state: "ENABLED",
  totpProviderConfig: { adjacentIntervals },
});

/** The config paths a program may switch: `mfa` and the email-link switch (M5). */
export const MFA_CONFIG_PATHS = new Set(["mfa", "signIn.email.passwordRequired"]);

/** The project `mfa` values a program may run under. */
export const MFA_CONFIGS = {
  disabled: { state: "DISABLED" },
  enabled: { state: "ENABLED", enabledProviders: ["PHONE_SMS"], providerConfigs: [totp(5)] },
  totpOnly: { state: "ENABLED", providerConfigs: [totp(5)] },
  smsOnly: { state: "ENABLED", enabledProviders: ["PHONE_SMS"] },
};

/**
 * The `mfa` values a recorded config step may send: the reviewed values above and the invalid
 * or unusual values the config program offers. Production may accept one of the latter; the
 * session restores the whole `mfa` value after the program either way.
 */
export const MFA_CONFIG_PROBES = {
  adjacentTen: { state: "ENABLED", providerConfigs: [totp(10)] },
  adjacentZero: { state: "ENABLED", providerConfigs: [totp(0)] },
  adjacentEleven: { state: "ENABLED", providerConfigs: [totp(11)] },
  adjacentNegative: { state: "ENABLED", providerConfigs: [totp(-1)] },
  totpWithoutProviderConfig: { state: "ENABLED", providerConfigs: [{ state: "ENABLED" }] },
  totpDisabled: { state: "ENABLED", providerConfigs: [{ ...totp(5), state: "DISABLED" }] },
  enabledWithoutProviders: { state: "ENABLED" },
  disabledWithProviders: {
    state: "DISABLED",
    enabledProviders: ["PHONE_SMS"],
    providerConfigs: [totp(5)],
  },
  mandatory: { state: "MANDATORY", enabledProviders: ["PHONE_SMS"] },
  unknownProvider: { state: "ENABLED", enabledProviders: ["NOT_A_PROVIDER"] },
  unknownState: { state: "NOT_A_STATE" },
};

const ALLOWED_MFA_VALUES = [...Object.values(MFA_CONFIGS), ...Object.values(MFA_CONFIG_PROBES)];
const sameJson = (a, b) => JSON.stringify(a) === JSON.stringify(b);

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
 * project, example.com addresses and configured test phones. Only the harness may wipe; a
 * config write changes nothing but `mfa`, and only to a reviewed value.
 */
export function guardMfaRequest({ url, init }, ctx, { harness = false } = {}) {
  const parsed = new URL(url);
  const raw = url.slice(parsed.origin.length).split("?")[0];
  if (/%2e|%2f|\/\.\.?(\/|$)/i.test(raw)) throw new Error(`request path is not canonical: ${raw}`);
  const { api, path } = locate(parsed, ctx);
  const project = ctx.project.replaceAll(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const families =
    api === "securetoken"
      ? [/^\/v1\/token$/]
      : [
          /^\/v1\/accounts:(signUp|signInWithPassword|signInWithPhoneNumber|signInWithEmailLink|signInWithCustomToken|sendVerificationCode|lookup|update|delete)$/,
          /^\/v2\/accounts\/mfaEnrollment:(start|finalize|withdraw)$/,
          /^\/v2\/accounts\/mfaSignIn:(start|finalize)$/,
          new RegExp(`^/v1/projects/${project}:createSessionCookie$`),
          new RegExp(
            `^/v1/projects/${project}/accounts(:(lookup|update|delete|batchCreate|sendOobCode))?$`,
          ),
          new RegExp(`^/admin/v2/projects/${project}/config$`),
          ...(harness
            ? [new RegExp(`^/v1/projects/${project}/accounts:(batchGet|batchDelete)$`)]
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
  if (path.endsWith("/config")) guardConfig(init, parsed, inputs[1] ?? {});
  if (path.endsWith(":sendOobCode")) guardSignInLink(init, inputs[1] ?? {});
  for (const input of inputs) {
    walkEntries(input, (key, value) => {
      if (PROJECT_KEYS.has(key) && value !== ctx.project)
        throw new Error(`request names another project: ${value}`);
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
 * A config read is free; a write names `mfa` and the email-link switch at most, sends a
 * reviewed `mfa` value, and nothing else.
 */
function guardConfig(init, parsed, body) {
  if (init.method === "GET") {
    if (typeof init.body === "string") throw new Error("a config read has no body");
    return;
  }
  const mask = (parsed.searchParams.get("updateMask") ?? "").split(",").filter(Boolean);
  if (init.method !== "PATCH" || mask.length === 0 || !mask.every((p) => MFA_CONFIG_PATHS.has(p)))
    throw new Error("a config write names only mfa and the email-link switch");
  const keys = Object.keys(body).toSorted();
  const expected = [...new Set(mask.map((p) => p.split(".")[0]))].toSorted();
  if (JSON.stringify(keys) !== JSON.stringify(expected))
    throw new Error("a config write body holds only its masked paths");
  if (mask.includes("mfa") && !ALLOWED_MFA_VALUES.some((value) => sameJson(value, body.mfa)))
    throw new Error(`mfa value is not reviewed: ${JSON.stringify(body.mfa)}`);
  if (
    mask.includes("signIn.email.passwordRequired") &&
    JSON.stringify(body.signIn) !== JSON.stringify({ email: { passwordRequired: false } }) &&
    JSON.stringify(body.signIn) !== JSON.stringify({ email: { passwordRequired: true } })
  )
    throw new Error("config write body names more than signIn.email.passwordRequired");
}

/** The one action code the corpus asks for: an email-link sign-in, returned and never mailed. */
function guardSignInLink(init, body) {
  if (!String(init.headers.authorization ?? "").startsWith("Bearer "))
    throw new Error("sendOobCode only on the Admin route");
  if (body.requestType !== "EMAIL_SIGNIN" || body.returnOobLink !== true)
    throw new Error("sendOobCode only for an email-link sign-in with the link returned");
}

function* walkStrings(value) {
  if (typeof value === "string") yield value;
  else if (Array.isArray(value)) for (const v of value) yield* walkStrings(v);
  else if (value && typeof value === "object")
    for (const v of Object.values(value)) yield* walkStrings(v);
}

const CONFIG_PATH = "admin/v2/projects/{project}/config";

/**
 * Refuses a corpus that could text a real number or mail anyone, change project config other
 * than `mfa` or to an unreviewed value, record a config answer beyond its `mfa` member, address
 * anything but a relative path, wait anywhere but in the last program, or exceed the request
 * cap. Returns the number of recorded requests.
 */
export function validateMfaCorpus(programs) {
  let requests = 0;
  const programIds = new Set();
  programs.forEach((program, index) => {
    if (programIds.has(program.id)) throw new Error(`duplicate program ${program.id}`);
    programIds.add(program.id);
    for (const [path, value] of Object.entries(program.config ?? {})) {
      if (!MFA_CONFIG_PATHS.has(path))
        throw new Error(`${program.id}: config path ${path} is not allowed`);
      if (path === "mfa" && !Object.values(MFA_CONFIGS).some((allowed) => sameJson(allowed, value)))
        throw new Error(`${program.id}: mfa value is not a reviewed program config`);
      if (path !== "mfa" && typeof value !== "boolean")
        throw new Error(`${program.id}: ${path} is a switch`);
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
      if (step.waitSeconds && index !== programs.length - 1)
        throw new Error(`${program.id}#${step.id}: only the last program may wait`);
      if (step.waitUntil) throw new Error(`${step.id}: waits are relative (waitSeconds, age)`);
      if (step.age) {
        if (index !== programs.length - 1)
          throw new Error(`${program.id}#${step.id}: only the last program may wait`);
        if (!stepIds.has(step.age.from) || step.age.from === step.id)
          throw new Error(`${step.id}: an age counts from an earlier step`);
        if (!(step.age.seconds > 0 && step.age.seconds <= 1800))
          throw new Error(`${step.id}: an age is at most 1800 seconds (owner decision M4)`);
      }
      if (step.path.endsWith("sendOobCode")) {
        if (
          step.path !== "v1/projects/{project}/accounts:sendOobCode" ||
          step.auth !== "admin" ||
          step.body?.requestType !== "EMAIL_SIGNIN" ||
          step.body?.returnOobLink !== true
        )
          throw new Error(`${step.id}: nothing is mailed (Admin EMAIL_SIGNIN, link returned)`);
      }
      if (step.path === CONFIG_PATH) {
        if (!program.config?.mfa)
          throw new Error(
            `${step.id}: a program with a config step declares mfa, so it is restored`,
          );
        if (step.auth !== "admin" || step.project !== "mfa")
          throw new Error(`${step.id}: a config step is Admin and records only mfa`);
        if (step.method === "PATCH") {
          if (step.query?.updateMask !== "mfa")
            throw new Error(`${step.id}: a config write names only mfa`);
          if (!ALLOWED_MFA_VALUES.some((value) => sameJson(value, step.body?.mfa)))
            throw new Error(`${step.id}: mfa value is not reviewed`);
        } else if (step.method !== "GET") throw new Error(`${step.id}: config GET or PATCH`);
      } else if (step.project !== undefined) {
        throw new Error(`${step.id}: only a config answer is projected`);
      }
      for (const text of walkStrings({ body: step.body, form: step.form, query: step.query })) {
        assertOnlyExampleEmail(text, step.id);
        if (/\+\d/.test(text) && !/^\+\*+\d+$/.test(text))
          throw new Error(`${step.id}: a phone is named as PHONE(n), never by value`);
      }
    }
  });
  if (requests > REQUEST_CAP)
    throw new Error(`corpus exceeds the request cap (${requests} > ${REQUEST_CAP})`);
  return requests;
}
