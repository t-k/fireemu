// Request guard, harness-only requests and corpus validation of the AUTH-CREDENTIAL sandbox
// harness. Request construction, the production/local context and transient classification
// come from the AUTH-ACCOUNT harness unchanged.
//
// Production is only ever the disposable Identity Platform sandbox. Custom tokens are signed
// there by IAM `signJwt` for one of two named service accounts; no key file exists or is
// created. Against fireemu the same tokens are signed by run-local keys whose public halves
// fireemu is configured to trust.

import { REQUEST_CAP, SANDBOX_PROJECT, TEST_PHONES } from "../auth-account/harness.mjs";

/**
 * The service accounts a custom token may be issued by: the sandbox's own Admin SDK account,
 * and one account of another project (fireemu-35fe6), which production refuses as a credential
 * of the wrong project.
 */
export const SIGNER_ACCOUNTS = {
  project: `firebase-adminsdk-fbsvc@${SANDBOX_PROJECT}.iam.gserviceaccount.com`,
  other: "fireemu-oracle@fireemu-35fe6.iam.gserviceaccount.com",
};

const PRODUCTION_ORIGINS = {
  itk: "https://identitytoolkit.googleapis.com",
  securetoken: "https://securetoken.googleapis.com",
};
const LOCAL_PREFIX = {
  itk: "identitytoolkit.googleapis.com",
  securetoken: "securetoken.googleapis.com",
};

/** The same run-unique values the AUTH-ACCOUNT request builder substitutes. */
export function substituteText(text, ctx) {
  return String(text)
    .replaceAll(/EMAIL\(([a-z0-9-]+)\)/g, (_, n) => `fireemu-aa-${ctx.run}-${n}@example.com`)
    .replaceAll(/UID\(([a-z0-9-]+)\)/g, (_, n) => `aa-${ctx.run}-${n}`)
    .replaceAll("{project}", ctx.project);
}

function walkEntries(value, visit, key = "") {
  if (Array.isArray(value)) for (const v of value) walkEntries(v, visit, key);
  else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) walkEntries(v, visit, k);
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

/**
 * The last check before a request leaves the process: a reviewed Identity Toolkit or Secure
 * Token path of this project on the target's host, whose body and query name only this
 * project, example.com addresses and configured test phones. Only the harness may wipe.
 */
export function guardCredentialRequest({ url, init }, ctx, { harness = false } = {}) {
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
          /^\/v1\/accounts:(signUp|signInWithPassword|signInWithCustomToken|signInWithPhoneNumber|sendVerificationCode|sendOobCode|lookup|update|delete)$/,
          /^\/v2\/accounts\/mfaEnrollment:(start|withdraw)$/,
          new RegExp(`^/v1/projects/${project}:createSessionCookie$`),
          new RegExp(`^/v1/projects/${project}/accounts(:(lookup|update|delete))?$`),
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
  guardOobCode(path, inputs[1]);
  guardMfaEnrollment(path, inputs[1]);
  for (const input of inputs) {
    walkEntries(input, (key, value) => {
      if (PROJECT_KEYS.has(key) && value !== ctx.project)
        throw new Error(`request names another project: ${value}`);
      if (typeof value !== "string") return;
      assertOnlyExampleEmail(value, key);
      // Separators inside a number do not hide it.
      for (const [phone] of value.replaceAll(/[\s().-]/g, "").matchAll(/\+\d{8,15}/g)) {
        if (!TEST_PHONES.includes(phone))
          throw new Error(`${phone} is not a configured test phone`);
      }
    });
  }
}

/** The runtime form of the corpus rule: a verification mail only for a token's own account. */
function guardOobCode(path, input) {
  if (!path.endsWith(":sendOobCode")) return;
  if (input?.requestType !== "VERIFY_EMAIL" || !input?.idToken || input?.email !== undefined) {
    throw new Error("sendOobCode is only VERIFY_EMAIL for the account behind a token");
  }
}

/** MFA enrollment may only be started for TOTP with no settings: never a phone factor. */
function guardMfaEnrollment(path, input) {
  if (!path.endsWith("mfaEnrollment:start")) return;
  const keys = Object.keys(input ?? {}).toSorted();
  const totp = input?.totpEnrollmentInfo;
  const empty = totp !== null && typeof totp === "object" && Object.keys(totp).length === 0;
  if (keys.join(",") !== "idToken,totpEnrollmentInfo" || !empty) {
    throw new Error("mfaEnrollment:start only with an idToken and an empty totpEnrollmentInfo");
  }
}

/** Requests only the harness makes: token signing in production, the clock against fireemu. */
export const harnessRequest = {
  signJwt(ctx, serviceAccount, claims) {
    if (ctx.target.kind !== "production") throw new Error("signJwt is production-only");
    if (!Object.values(SIGNER_ACCOUNTS).includes(serviceAccount))
      throw new Error(`${serviceAccount} is not a reviewed signer`);
    return {
      url: `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${serviceAccount}:signJwt`,
      init: {
        method: "POST",
        headers: {
          authorization: `Bearer ${ctx.target.adminToken}`,
          "x-goog-user-project": ctx.target.quotaProject,
          "content-type": "application/json",
        },
        body: JSON.stringify({ payload: JSON.stringify(claims) }),
      },
    };
  },
  advanceClockTo(ctx, epochMillis) {
    if (ctx.target.kind !== "local") throw new Error("the clock is fireemu-only");
    const request = harnessRequest.advanceClock(ctx, 0);
    return {
      url: request.url.replace("clock:advance", "clock:advanceTo"),
      init: {
        ...request.init,
        body: JSON.stringify({ instant: new Date(epochMillis).toISOString() }),
      },
    };
  },
  advanceClock(ctx, seconds) {
    if (ctx.target.kind !== "local") throw new Error("the clock is fireemu-only");
    const control = new URL(ctx.target.control.url);
    if (!["127.0.0.1", "localhost", "[::1]"].includes(control.hostname))
      throw new Error("control API must be loopback");
    return {
      url: `${control.origin}/v1/sessions/default/clock:advance`,
      init: {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(ctx.target.control.token
            ? { authorization: `Bearer ${ctx.target.control.token}` }
            : {}),
        },
        body: JSON.stringify({ seconds }),
      },
    };
  },
};

function* walkStrings(value) {
  if (typeof value === "string") yield value;
  else if (Array.isArray(value)) for (const v of value) yield* walkStrings(v);
  else if (value && typeof value === "object")
    for (const v of Object.values(value)) yield* walkStrings(v);
}

/**
 * Refuses a corpus that could send SMS to a real number or mail to a real mailbox, address
 * anything but a relative path, wait anywhere but in the last program, or exceed the request
 * cap. Returns the number of recorded requests.
 */
export function validateCredentialCorpus(programs) {
  let requests = 0;
  const programIds = new Set();
  programs.forEach((program, index) => {
    if (programIds.has(program.id)) throw new Error(`duplicate program ${program.id}`);
    programIds.add(program.id);
    if (program.config) throw new Error(`${program.id}: credential programs change no config`);
    for (const [name, spec] of Object.entries(program.tokens ?? {})) {
      if (!Object.hasOwn(SIGNER_ACCOUNTS, spec.signer ?? "project"))
        throw new Error(`${program.id}: token ${name} has an unknown signer`);
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
      // fireemu's clock stays where a wait put it until wall time catches up, so only the
      // last program may wait; its later steps then need no further time to pass.
      if ((step.waitSeconds || step.waitUntil) && index !== programs.length - 1)
        throw new Error(`${program.id}#${step.id}: only the last program may wait`);
      if (
        step.path.endsWith("accounts:sendVerificationCode") &&
        !/^PHONE\(\d\)$/.test(step.body?.phoneNumber ?? "")
      ) {
        throw new Error(`${step.id}: sendVerificationCode only to a configured test phone`);
      }
      // A verification mail only for the account behind a token, never to a named address:
      // corpus accounts are example.com addresses, which accept no mail.
      if (
        step.path.endsWith("accounts:sendOobCode") &&
        (step.body?.requestType !== "VERIFY_EMAIL" || !step.body?.idToken || step.body?.email)
      )
        throw new Error(`${step.id}: sendOobCode only VERIFY_EMAIL for a token's own account`);
      if (step.path.endsWith("mfaEnrollment:start")) {
        const { idToken, totpEnrollmentInfo, ...rest } = step.body ?? {};
        if (!idToken || Object.keys(rest).length || JSON.stringify(totpEnrollmentInfo) !== "{}")
          throw new Error(`${step.id}: mfaEnrollment:start only as an empty TOTP enrollment`);
      }
      // A timed step names an earlier step or a minted token, so a typo fails here and not
      // after an hour of waiting.
      if (step.waitUntil) {
        const [kind, name, claim] = String(step.waitUntil.of).split(":");
        const known =
          kind === "token"
            ? Object.hasOwn(program.tokens ?? {}, name) && typeof claim === "string"
            : stepIds.has(kind) && typeof name === "string" && claim === undefined;
        if (!known || !Number.isInteger(step.waitUntil.plus))
          throw new Error(`${step.id}: waitUntil must name an earlier step or a minted token`);
      }
      for (const text of walkStrings({ body: step.body, form: step.form, query: step.query }))
        assertOnlyExampleEmail(text, step.id);
    }
  });
  if (requests > REQUEST_CAP)
    throw new Error(`corpus exceeds the request cap (${requests} > ${REQUEST_CAP})`);
  return requests;
}
