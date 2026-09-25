import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { SANDBOX_PROJECT, createContext } from "./auth-account/harness.mjs";
import { PROGRAMS } from "./auth-config-sdk/corpus.mjs";
import { guardHttp, validateConfigSdkCorpus } from "./auth-config-sdk/guard.mjs";
import { describeActionLink, normalizeHttp, normalizeSdk } from "./auth-config-sdk/harness.mjs";
import { SDK_OPERATIONS } from "./auth-config-sdk/sdk.mjs";
import {
  configCovers,
  configDrift,
  configEquals,
  createSession,
  driftForm,
  withTimes,
} from "./auth-config-sdk/session.mjs";
import {
  classify,
  linesAfter,
  otherLaneOnSandbox,
  recentAbort,
  restoreDue,
} from "./auth-config-sdk/run.mjs";
import { buildRequest } from "./auth-account/harness.mjs";
import { materialize } from "./auth-credential/session.mjs";

const production = () =>
  createContext({
    run: "1700000000000",
    project: SANDBOX_PROJECT,
    startedMs: 1700000000000,
    target: {
      kind: "production",
      apiKey: "AIzaTESTKEY",
      adminToken: "ya29.token",
      quotaProject: SANDBOX_PROJECT,
      projectNumber: "111222333444",
    },
  });
const local = () =>
  createContext({
    run: "1700000000000",
    project: SANDBOX_PROJECT,
    target: { kind: "local", origin: "http://127.0.0.1:32320", projectNumber: "123456789012" },
  });

const ITK = "https://identitytoolkit.googleapis.com";
const CONFIG = `${ITK}/admin/v2/projects/${SANDBOX_PROJECT}/config`;
const admin = {
  authorization: "Bearer t",
  "x-goog-user-project": SANDBOX_PROJECT,
  "content-type": "application/json",
};
const patch = (mask, body, headers = admin) => ({
  url: mask === undefined ? CONFIG : `${CONFIG}?updateMask=${encodeURIComponent(mask)}`,
  method: "PATCH",
  headers,
  body: JSON.stringify(body),
});

test("the guard lets only the sandbox's reviewed hosts and paths through", () => {
  const ctx = production();
  assert.doesNotThrow(() =>
    guardHttp({ url: `${ITK}/v1/accounts:signUp?key=k`, method: "POST" }, ctx, { role: "step" }),
  );
  assert.throws(
    () => guardHttp({ url: "https://example.com/v1/accounts:signUp" }, ctx, { role: "step" }),
    /host example.com is not reviewed/,
  );
  assert.throws(
    () =>
      guardHttp(
        { url: `${ITK}/v1/projects/other-project/accounts:lookup`, method: "POST", headers: admin },
        ctx,
        {
          role: "step",
        },
      ),
    /not a reviewed family/,
  );
  assert.throws(
    () =>
      guardHttp(
        {
          url: `${ITK}/v1/projects/${SANDBOX_PROJECT}/accounts:batchDelete`,
          method: "POST",
          headers: admin,
        },
        ctx,
        {
          role: "step",
        },
      ),
    /not a reviewed family/,
    "only the harness wipes",
  );
  assert.throws(
    () =>
      guardHttp({ url: `${ITK}/v1/accounts:signUp`, method: "POST" }, local(), { role: "step" }),
    /left the local target/,
  );
});

test("an authorized production request must bill the sandbox", () => {
  assert.throws(
    () =>
      guardHttp(
        {
          url: CONFIG,
          method: "GET",
          headers: { authorization: "Bearer t", "x-goog-user-project": "futaba-prod" },
        },
        production(),
        { role: "harness" },
      ),
    /bill the sandbox/,
  );
});

test("the Admin SDK reaches Google's keys and signBlob of the project's own account only", () => {
  const ctx = production();
  const sa = `firebase-adminsdk-fbsvc@${SANDBOX_PROJECT}.iam.gserviceaccount.com`;
  assert.doesNotThrow(() =>
    guardHttp(
      {
        url: "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com",
      },
      ctx,
      { role: "sdk-admin" },
    ),
  );
  assert.doesNotThrow(() =>
    guardHttp(
      {
        url: `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${sa}:signBlob`,
        method: "POST",
        headers: admin,
      },
      ctx,
      { role: "sdk-admin" },
    ),
  );
  assert.throws(
    () =>
      guardHttp(
        {
          url: "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/other@x.iam.gserviceaccount.com:signBlob",
          method: "POST",
          headers: admin,
        },
        ctx,
        { role: "sdk-admin" },
      ),
    /not reviewed/,
  );
  assert.throws(
    () =>
      guardHttp(
        {
          url: "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com",
        },
        ctx,
        {
          role: "sdk-web",
        },
      ),
    /not reviewed/,
    "the Web SDK has no business there",
  );
});

test("config writes stay on reviewed paths, never key material, other lanes or ENFORCE", () => {
  const ctx = production();
  const ok = (mask, body, role = "step") =>
    assert.doesNotThrow(() => guardHttp(patch(mask, body), ctx, { role }), mask);
  const refused = (mask, body, pattern, role = "step") =>
    assert.throws(() => guardHttp(patch(mask, body), ctx, { role }), pattern, mask);
  ok("emailPrivacyConfig.enableImprovedEmailPrivacy", {
    emailPrivacyConfig: { enableImprovedEmailPrivacy: false },
  });
  ok("passwordPolicyConfig", {
    passwordPolicyConfig: { passwordPolicyEnforcementState: "ENFORCE" },
  });
  ok("name", { name: `projects/${SANDBOX_PROJECT}/config` });
  refused("name", {}, /not reviewed/, "harness");
  refused("signIn.hashConfig", {}, /not reviewed/);
  refused(
    "signIn.allowDuplicateEmails",
    { signIn: { hashConfig: { rounds: 1 } } },
    /names signIn.hashConfig/,
  );
  refused("mfa", { mfa: { state: "ENABLED" } }, /not reviewed/);
  refused("client.apiKey", { client: { apiKey: "x" } }, /not reviewed/);
  refused("multiTenant.allowTenants", {}, /not reviewed/);
  refused(
    "recaptchaConfig",
    { recaptchaConfig: { emailPasswordEnforcementState: "ENFORCE" } },
    /never enforced/,
  );
  refused(
    "recaptchaConfig",
    { recaptchaConfig: { phoneEnforcementState: "ENFORCE" } },
    /never enforced/,
  );
  // Production also takes the proto names; any spelling of a state is checked (security
  // review 2026-09-25).
  for (const state of [
    { email_password_enforcement_state: "ENFORCE" },
    { phone_enforcement_state: "ENFORCE" },
    { emailPasswordEnforcementState: "enforce" },
    { phoneEnforcementState: 3 },
  ])
    refused("recaptchaConfig", { recaptchaConfig: state }, /never enforced/);
  refused(
    undefined,
    { emailPrivacyConfig: { enableImprovedEmailPrivacy: false } },
    /non-empty updateMask/,
  );
  refused("authorizedDomains", { authorizedDomains: ["evil.example.org"] }, /not reviewed/);
  ok("authorizedDomains", { authorizedDomains: [`${SANDBOX_PROJECT}.web.app`, "app.example.com"] });
});

test("action codes come only from the Admin route with the link returned", () => {
  const ctx = production();
  const oob = (path, body, headers) => ({
    url: `${ITK}${path}`,
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  const adminPath = `/v1/projects/${SANDBOX_PROJECT}/accounts:sendOobCode`;
  assert.throws(
    () =>
      guardHttp(
        oob(adminPath, { requestType: "PASSWORD_RESET", email: "a@example.com" }, admin),
        ctx,
        { role: "step" },
      ),
    /link back/,
  );
  assert.doesNotThrow(() =>
    guardHttp(
      oob(
        adminPath,
        { requestType: "PASSWORD_RESET", email: "a@example.com", returnOobLink: true },
        admin,
      ),
      ctx,
      { role: "sdk-admin" },
    ),
  );
  assert.throws(
    () =>
      guardHttp(
        oob("/v1/accounts:sendOobCode", { requestType: "VERIFY_EMAIL", idToken: "t" }),
        ctx,
        { role: "sdk-web" },
      ),
    /only a PASSWORD_RESET/,
  );
  assert.doesNotThrow(() =>
    guardHttp(
      oob("/v1/accounts:sendOobCode", {
        requestType: "PASSWORD_RESET",
        email: "fireemu-aa-1-unknown-x@example.com",
      }),
      ctx,
      { role: "step" },
    ),
  );
  assert.throws(
    () =>
      guardHttp(oob("/v1/accounts:signUp", { email: "someone@gmail.com", password: "x" }), ctx, {
        role: "sdk-web",
      }),
    /outside example.com/,
  );
  assert.throws(
    () =>
      guardHttp(oob("/v1/accounts:sendVerificationCode", { phoneNumber: "+15555550100" }), ctx, {
        role: "sdk-web",
      }),
    /not a configured test phone/,
  );
});

test("the Admin SDK transport is checked before its body exists and again with it", () => {
  const ctx = production();
  const url = `${ITK}/v1/projects/${SANDBOX_PROJECT}/accounts:sendOobCode`;
  assert.doesNotThrow(() =>
    guardHttp({ url, method: "POST", headers: admin }, ctx, {
      role: "sdk-admin",
      bodyPending: true,
    }),
  );
  assert.throws(
    () =>
      guardHttp(
        {
          url,
          method: "POST",
          headers: admin,
          body: JSON.stringify({ requestType: "PASSWORD_RESET", email: "a@example.com" }),
        },
        ctx,
        { role: "sdk-admin" },
      ),
    /link back/,
  );
});

test("the corpus is valid, bounded and restores everything it writes", () => {
  const requests = validateConfigSdkCorpus(PROGRAMS, { sdkOperations: SDK_OPERATIONS });
  assert.ok(requests > 0 && requests < 600, `${requests} recorded requests`);
  const program = (steps, touches) => [
    { id: "auth-config-sdk/t", projection: "strict", touches, steps },
  ];
  const write = (mask, body) => ({
    id: "w",
    path: "admin/v2/projects/{project}/config",
    auth: "admin",
    method: "PATCH",
    query: { updateMask: mask },
    body,
  });
  assert.throws(
    () =>
      validateConfigSdkCorpus(
        program(
          [write("signIn.allowDuplicateEmails", { signIn: { allowDuplicateEmails: true } })],
          [],
        ),
      ),
    /does not touch it/,
  );
  assert.throws(
    () =>
      validateConfigSdkCorpus(
        program([write("client.permissions", {})], ["client.permissions.disabledUserSignup"]),
      ),
    /client.permissions needs client.permissions.disabledUserDeletion/,
  );
  assert.throws(
    () =>
      validateConfigSdkCorpus(program([{ id: "x", sdk: "admin.nothing" }], []), {
        sdkOperations: SDK_OPERATIONS,
      }),
    /SDK steps run under an SDK projection|unknown SDK operation/,
  );
  assert.throws(
    () =>
      validateConfigSdkCorpus(
        program(
          [
            {
              id: "x",
              path: "v1/accounts:sendVerificationCode",
              auth: "key",
              body: { phoneNumber: "+15555550100" },
            },
          ],
          [],
        ),
      ),
    /test phone/,
  );
});

test("normalization drops other lanes' members and masks key material", () => {
  const ctx = production();
  const body = {
    name: "projects/111222333444/config",
    signIn: { hashConfig: { algorithm: "SCRYPT", signerKey: "c2VjcmV0", saltSeparator: "Bw==" } },
    client: { apiKey: "AIzaTESTKEY", firebaseSubdomain: SANDBOX_PROJECT },
    mfa: { state: "ENABLED" },
    multiTenant: { allowTenants: true },
    blockingFunctions: {},
    recaptchaConfig: { recaptchaKeys: [{ key: "projects/111222333444/keys/6LdAbc", type: "WEB" }] },
  };
  const recorded = normalizeHttp(200, JSON.stringify(body), ctx, { config: true });
  assert.equal(recorded.body.name, "projects/<project-number>/config");
  assert.deepEqual(recorded.body.signIn.hashConfig, {
    algorithm: "SCRYPT",
    signerKey: "<bytes>",
    saltSeparator: "<bytes>",
  });
  assert.equal(recorded.body.client.apiKey, "<api-key>");
  assert.equal(recorded.body.client.firebaseSubdomain, "demo-auth-account");
  assert.equal(recorded.body.mfa, undefined);
  assert.equal(recorded.body.multiTenant, undefined);
  assert.equal(recorded.body.blockingFunctions, undefined);
  assert.equal(
    recorded.body.recaptchaConfig.recaptchaKeys[0].key,
    "projects/<project-number>/keys/<recaptcha-key-id>",
  );
  // Outside the config route the members are kept (a sign-up answer has none of them anyway).
  assert.deepEqual(normalizeHttp(200, '{"mfa":1}', ctx).body, { mfa: 1 });
});

test("a wrapped action link is recorded as its parameters with the inner link described", () => {
  const ctx = production();
  const inner =
    "https://fireemu-oracle-idp.firebaseapp.com/__/auth/action?apiKey=AIzaTESTKEY&mode=resetPassword&oobCode=CODE1&continueUrl=https://x.example.com/f&lang=en";
  const outer = `https://fireemu-oracle-idp.firebaseapp.com/__/auth/links?link=${encodeURIComponent(inner)}`;
  const recorded = normalizeHttp(200, JSON.stringify({ oobLink: outer, oobCode: "CODE1" }), ctx);
  assert.deepEqual(recorded.body.oobLink, {
    handler: "<action-handler>",
    code: "absent",
    params: {
      link: {
        handler: "<action-handler>",
        code: "the-answer-oobCode",
        params: {
          apiKey: "<api-key>",
          mode: "resetPassword",
          continueUrl: "https://x.example.com/f",
          lang: "en",
        },
      },
    },
  });
  assert.doesNotMatch(JSON.stringify(recorded), /CODE1|AIzaTESTKEY/);
  const sdk = normalizeSdk({ value: describeActionLink(outer) }, ctx);
  assert.equal(sdk.value.params.link.code, "another-code");
});

test("volatile members are placeholders: auth URI sessions and quota start times", () => {
  const ctx = production();
  const recorded = normalizeHttp(
    200,
    JSON.stringify({
      sessionId: "abc",
      quota: { signUpQuotaConfig: { startTime: "2030-01-01T00:00:00Z" } },
    }),
    ctx,
  );
  assert.equal(recorded.body.sessionId, "<sessionId>");
  assert.equal(recorded.body.quota.signUpQuotaConfig.startTime, "<start-time>");
  // The start production supplies for a quota written without one is kept.
  const epoch = normalizeHttp(
    200,
    JSON.stringify({ quota: { signUpQuotaConfig: { startTime: "1970-01-01T00:00:00Z" } } }),
    ctx,
  );
  assert.equal(epoch.body.quota.signUpQuotaConfig.startTime, "1970-01-01T00:00:00Z");
});

test("SDK outcomes are recorded as values or error codes with generated ids masked", () => {
  const ctx = production();
  assert.deepEqual(
    normalizeSdk({ error: { code: "auth/invalid-credential", message: "Firebase: x" } }, ctx),
    {
      sdk: "error",
      code: "auth/invalid-credential",
      message: "Firebase: x",
    },
  );
  const value = normalizeSdk(
    {
      value: {
        uid: "abcdefghijklmnopqrstuvwxyz01",
        metadata: { creationTime: new Date(1700000000000 + 1000).toUTCString() },
        multiFactorConfig: { state: "DISABLED" },
      },
    },
    ctx,
  );
  assert.deepEqual(value, {
    sdk: "ok",
    value: { uid: "<generated-localId>", metadata: { creationTime: "<run-time:http-date>" } },
  });
  assert.deepEqual(normalizeSdk({ value: undefined }, ctx), { sdk: "ok" });
});

test("whole-config drift ignores emptied members but not oneof choices", () => {
  assert.equal(driftForm({ quota: {}, recaptchaConfig: {} }), undefined);
  assert.deepEqual(driftForm({ smsRegionConfig: { allowByDefault: {} } }), {
    smsRegionConfig: { allowByDefault: {} },
  });
  assert.deepEqual(
    configDrift(
      driftForm({ smsRegionConfig: { allowByDefault: {} } }),
      driftForm({ smsRegionConfig: { allowlistOnly: {} } }),
    ),
    ["smsRegionConfig.allowByDefault", "smsRegionConfig.allowlistOnly"],
  );
});

test("config equality reads false and absent alike but keeps oneof members apart", () => {
  assert.ok(configEquals(undefined, false));
  assert.ok(configEquals({}, undefined));
  assert.ok(!configEquals({ allowByDefault: {} }, { allowlistOnly: {} }));
  assert.ok(
    configEquals(
      {
        passwordPolicyEnforcementState: "OFF",
        lastUpdateTime: "t",
        passwordPolicyVersions: [
          { customStrengthOptions: { minPasswordLength: 8 }, schemaVersion: 1 },
        ],
      },
      {
        passwordPolicyEnforcementState: "OFF",
        forceUpgradeOnSignin: false,
        passwordPolicyVersions: [{ customStrengthOptions: { minPasswordLength: 8 } }],
      },
    ),
  );
  assert.ok(
    !configEquals(
      { passwordPolicyEnforcementState: "OFF" },
      { passwordPolicyEnforcementState: "ENFORCE" },
    ),
  );
});

test("a settle reads back what was written and allows what the server adds", () => {
  assert.ok(
    configCovers(
      {
        passwordPolicyEnforcementState: "ENFORCE",
        passwordPolicyVersions: [
          { customStrengthOptions: { maxPasswordLength: 16, minPasswordLength: 6 } },
        ],
      },
      {
        passwordPolicyEnforcementState: "ENFORCE",
        passwordPolicyVersions: [{ customStrengthOptions: { maxPasswordLength: 16 } }],
      },
    ),
  );
  assert.ok(!configCovers({ a: 1 }, { a: 2 }));
  assert.ok(!configCovers({ a: 1 }, undefined), "unset must read back unset");
  assert.ok(configCovers({}, undefined));
  assert.ok(configCovers(undefined, false));
  assert.ok(!configCovers({ allowlistOnly: {} }, { allowByDefault: {} }));
});

test("relative times resolve to whole seconds", () => {
  const now = Date.parse("2026-09-25T00:00:00.500Z");
  assert.deepEqual(withTimes({ a: { $isoFromNow: 60 }, b: [{ $isoFromNow: -1 }] }, now), {
    a: "2026-09-25T00:01:00Z",
    b: ["2026-09-24T23:59:59Z"],
  });
});

/** A fake sandbox: an in-memory config and account list behind the session's fetch. */
function fakeSandbox({ failPatchOn, sideEffect, deferFirstPatch = false } = {}) {
  const state = { config: { emailPrivacyConfig: { enableImprovedEmailPrivacy: true } }, users: [] };
  const calls = [];
  // A write production accepted but has not applied yet lands before the next write.
  const deferred = [];
  const flush = () => deferred.splice(0).forEach((apply) => apply());
  const fetchImpl = async (url, init) => {
    const parsed = new URL(url);
    calls.push(`${init.method} ${parsed.pathname}`);
    const json = (status, body) => new Response(JSON.stringify(body), { status });
    if (parsed.pathname.endsWith("accounts:batchGet")) return json(200, { users: state.users });
    if (parsed.pathname.endsWith("accounts:batchDelete")) {
      state.users = [];
      return json(200, {});
    }
    if (parsed.pathname.endsWith("/config")) {
      if (init.method === "GET") return json(200, state.config);
      const body = JSON.parse(init.body);
      if (failPatchOn && JSON.stringify(body).includes(failPatchOn))
        return json(400, { error: { message: "INVALID_ARGUMENT" } });
      if (sideEffect) Object.assign(state.config, sideEffect);
      const apply = () => {
        for (const path of parsed.searchParams.get("updateMask").split(",")) {
          const keys = path.split(".");
          const value = keys.reduce((v, k) => v?.[k], body);
          let target = state.config;
          for (const k of keys.slice(0, -1)) target = target[k] ??= {};
          if (value === undefined) delete target[keys.at(-1)];
          else target[keys.at(-1)] = value;
        }
      };
      flush();
      if (deferFirstPatch && calls.filter((c) => c.startsWith("PATCH")).length === 1) {
        deferred.push(apply);
        return json(200, body);
      }
      apply();
      return json(200, state.config);
    }
    if (parsed.pathname.endsWith("accounts:signUp")) {
      state.users.push({ localId: "u" });
      throw new Error("connection reset");
    }
    return json(404, {});
  };
  return { state, calls, fetchImpl, flush };
}

test("a program's touched paths are restored and read back even when it fails", async () => {
  const sandbox = fakeSandbox();
  const session = createSession(local(), { fetchImpl: sandbox.fetchImpl });
  const program = {
    id: "auth-config-sdk/t",
    projection: "strict",
    touches: ["emailPrivacyConfig.enableImprovedEmailPrivacy"],
    steps: [
      {
        id: "off",
        path: "admin/v2/projects/{project}/config",
        auth: "admin",
        method: "PATCH",
        query: { updateMask: "emailPrivacyConfig.enableImprovedEmailPrivacy" },
        body: { emailPrivacyConfig: { enableImprovedEmailPrivacy: false } },
        settle: true,
      },
      { id: "fails", path: "v1/accounts:signUp", auth: "key", body: {} },
      { id: "harness-refuses", path: "v1/projects/other/accounts:lookup", auth: "admin", body: {} },
    ],
  };
  await assert.rejects(session.runProgram(program), /guard refused harness-refuses/);
  assert.equal(sandbox.state.config.emailPrivacyConfig.enableImprovedEmailPrivacy, true);
  assert.deepEqual(sandbox.state.users, []);
  assert.ok(
    sandbox.calls.filter((c) => c.startsWith("PATCH")).length === 2,
    "written, then restored",
  );
});

test("a restore writes back only the paths that changed", async () => {
  const sandbox = fakeSandbox({ failPatchOn: '"subject"' });
  sandbox.state.config.notification = { defaultLocale: "en", subject: "S" };
  const session = createSession(local(), { fetchImpl: sandbox.fetchImpl });
  const program = {
    id: "auth-config-sdk/t",
    projection: "strict",
    touches: ["emailPrivacyConfig.enableImprovedEmailPrivacy", "notification.defaultLocale"],
    steps: [
      {
        id: "off",
        path: "admin/v2/projects/{project}/config",
        auth: "admin",
        method: "PATCH",
        query: { updateMask: "emailPrivacyConfig.enableImprovedEmailPrivacy" },
        body: { emailPrivacyConfig: { enableImprovedEmailPrivacy: false } },
      },
    ],
  };
  await session.runProgram(program);
  const patches = sandbox.calls.filter((call) => call.startsWith("PATCH"));
  assert.equal(patches.length, 2, "the step and one restore of the changed path");
  assert.equal(sandbox.state.config.emailPrivacyConfig.enableImprovedEmailPrivacy, true);
});

test("a restore also writes back a written path that does not read as changed yet", async () => {
  const sandbox = fakeSandbox({ deferFirstPatch: true });
  const session = createSession(local(), { fetchImpl: sandbox.fetchImpl });
  const program = {
    id: "auth-config-sdk/t",
    projection: "strict",
    touches: ["emailPrivacyConfig.enableImprovedEmailPrivacy"],
    steps: [
      {
        id: "off",
        path: "admin/v2/projects/{project}/config",
        auth: "admin",
        method: "PATCH",
        query: { updateMask: "emailPrivacyConfig.enableImprovedEmailPrivacy" },
        body: { emailPrivacyConfig: { enableImprovedEmailPrivacy: false } },
      },
    ],
  };
  await session.runProgram(program);
  sandbox.flush();
  assert.equal(sandbox.state.config.emailPrivacyConfig.enableImprovedEmailPrivacy, true);
});

test("a refused path another path's restore brought back counts as restored", async () => {
  // The locale localizes the template; the template itself may not be written.
  const sandbox = fakeSandbox({ failPatchOn: '"subject"' });
  const localized = { en: "Reset", ja: "Reset (ja)" };
  sandbox.state.config.notification = { defaultLocale: "en", subject: localized.en };
  const fetchImpl = async (url, init) => {
    const response = await sandbox.fetchImpl(url, init);
    const n = sandbox.state.config.notification;
    n.subject = localized[n.defaultLocale];
    return response;
  };
  const session = createSession(local(), { fetchImpl });
  const program = {
    id: "auth-config-sdk/t",
    projection: "strict",
    touches: ["notification.defaultLocale", "notification.subject"],
    steps: [
      {
        id: "ja",
        path: "admin/v2/projects/{project}/config",
        auth: "admin",
        method: "PATCH",
        query: { updateMask: "notification.defaultLocale" },
        body: { notification: { defaultLocale: "ja" } },
      },
    ],
  };
  await session.runProgram(program);
  assert.deepEqual(sandbox.state.config.notification, { defaultLocale: "en", subject: "Reset" });
});

test("a restore that does not read back stops the run", async () => {
  const sandbox = fakeSandbox({ failPatchOn: '"enableImprovedEmailPrivacy":true' });
  const session = createSession(local(), { fetchImpl: sandbox.fetchImpl, settleAttempts: 2 });
  const program = {
    id: "auth-config-sdk/t",
    projection: "strict",
    touches: ["emailPrivacyConfig.enableImprovedEmailPrivacy"],
    steps: [
      {
        id: "off",
        path: "admin/v2/projects/{project}/config",
        auth: "admin",
        method: "PATCH",
        query: { updateMask: "emailPrivacyConfig.enableImprovedEmailPrivacy" },
        body: { emailPrivacyConfig: { enableImprovedEmailPrivacy: false } },
      },
    ],
  };
  const error = await session.runProgram(program).catch((e) => e);
  assert.ok(error.fatal, "fatal");
  assert.match(error.message, /harness PATCH/);
});

test("the ledger rules keep lanes apart and hold retries after a failed run", () => {
  const now = Date.parse("2026-09-25T20:00:00Z");
  const line = (entry) => JSON.stringify({ project: SANDBOX_PROJECT, ...entry });
  const open = [
    line({ ts: "2026-09-25T18:00:00Z", event: "started", taskId: "AUTH-MFA-SANDBOX" }),
  ].join("\n");
  assert.match(otherLaneOnSandbox(open, now), /AUTH-MFA-SANDBOX started/);
  const recent = [
    line({ ts: "2026-09-25T18:00:00Z", event: "started", taskId: "AUTH-MFA-SANDBOX" }),
    line({
      ts: "2026-09-25T19:45:00Z",
      event: "finished",
      taskId: "AUTH-MFA-SANDBOX",
      outcome: "recorded",
    }),
  ].join("\n");
  assert.match(otherLaneOnSandbox(recent, now), /wrote a line/);
  assert.equal(otherLaneOnSandbox(recent, now + 20 * 60_000), undefined);
  const mine = (outcome, ts = "2026-09-25T19:30:00Z", extra = {}) =>
    line({
      ts,
      event: "finished",
      taskId: "AUTH-CONFIG-SDK-SANDBOX",
      outcome,
      programs: ["p"],
      ...extra,
    });
  assert.ok(recentAbort(mine("aborted-fatal"), now));
  assert.equal(recentAbort(mine("recorded"), now), undefined);
  assert.equal(recentAbort(mine("aborted", "2026-09-25T18:30:00Z"), now), undefined);
  assert.ok(restoreDue(line({ ts: "t", event: "started", taskId: "AUTH-CONFIG-SDK-SANDBOX" })));
  assert.ok(!restoreDue(mine("recorded")));
  // A failed run that read the baseline back hands the sandbox over; one that did not keeps it.
  assert.ok(!restoreDue(mine("aborted-fatal", undefined, { sandboxAtBaseline: true })));
  assert.ok(restoreDue(mine("aborted-fatal", undefined, { sandboxAtBaseline: false })));
  // The ledger fails closed: an unreadable line, an unreadable time, older `task` keys.
  assert.throws(() => otherLaneOnSandbox(`${recent}\n{not json`, now), /does not parse/);
  assert.match(
    otherLaneOnSandbox(line({ ts: "sometime", event: "finished", taskId: "X" }), now),
    /X wrote a line/,
  );
  assert.match(
    otherLaneOnSandbox(line({ ts: "2026-09-25T18:00:00Z", event: "started", task: "OLD" }), now),
    /OLD started/,
  );
  const read = `${open}\n`;
  assert.deepEqual(
    linesAfter(
      `${read}${line({ ts: "2026-09-25T20:00:01Z", event: "started", taskId: "AUTH-CONFIG-SDK-SANDBOX" })}\n`,
      read.length,
    ),
    [],
    "our own line is no race",
  );
  assert.deepEqual(
    linesAfter(
      `${read}${line({ ts: "2026-09-25T19:00:00Z", event: "started", taskId: "FS-RULES-SANDBOX" })}\n`,
      read.length,
    ).map((e) => e.taskId),
    ["FS-RULES-SANDBOX"],
    "a line appended after our read is a race whatever its time",
  );
});

test("an empty or omitted mask is refused in every role (K13)", () => {
  const ctx = production();
  for (const role of ["step", "sdk-admin", "harness"]) {
    for (const mask of [undefined, "", ","]) {
      assert.throws(
        () =>
          guardHttp(
            patch(mask, { emailPrivacyConfig: { enableImprovedEmailPrivacy: true } }),
            ctx,
            { role },
          ),
        /non-empty updateMask/,
        `${role} ${mask}`,
      );
    }
  }
});

test("a program may write only the config paths it restores", () => {
  const ctx = { ...production(), touches: ["passwordPolicyConfig"] };
  assert.doesNotThrow(() =>
    guardHttp(
      patch("passwordPolicyConfig.forceUpgradeOnSignin", {
        passwordPolicyConfig: { forceUpgradeOnSignin: true },
      }),
      ctx,
      { role: "sdk-admin" },
    ),
  );
  assert.throws(
    () =>
      guardHttp(
        patch("emailPrivacyConfig.enableImprovedEmailPrivacy", {
          emailPrivacyConfig: { enableImprovedEmailPrivacy: false },
        }),
        ctx,
        { role: "step" },
      ),
    /not touched/,
  );
  assert.throws(
    () =>
      guardHttp(
        patch("passwordPolicyConfig", {
          passwordPolicyConfig: {},
          emailPrivacyConfig: { enableImprovedEmailPrivacy: false },
        }),
        ctx,
        { role: "step" },
      ),
    /not touched/,
    "a body member outside the mask still has to be restorable",
  );
  assert.doesNotThrow(
    () =>
      guardHttp(
        patch("emailPrivacyConfig.enableImprovedEmailPrivacy", { emailPrivacyConfig: {} }),
        ctx,
        {
          role: "harness",
        },
      ),
    "the harness restores what it snapshotted",
  );
});

/** A raw-answer map that answers any `$from` with a placeholder string. */
const anyAnswer = {
  get: () =>
    new Proxy({}, { get: (_target, key) => (key === Symbol.toPrimitive ? undefined : "stub") }),
  has: () => true,
};

test("every REST step of the corpus passes the guard as production would see it", () => {
  const ctx = production();
  for (const program of PROGRAMS) {
    for (const step of program.steps.filter((s) => !s.sdk)) {
      const request = buildRequest(
        {
          ...step,
          body: materialize(withTimes(step.body), anyAnswer, new Map()),
          query: materialize(step.query, anyAnswer, new Map()),
        },
        ctx,
        anyAnswer,
      );
      assert.doesNotThrow(
        () =>
          guardHttp(
            {
              url: request.url,
              method: request.init.method,
              headers: request.init.headers,
              body: request.init.body,
            },
            { ...ctx, touches: program.touches ?? [] },
            { role: "step" },
          ),
        `${program.id}#${step.id}`,
      );
    }
  }
});

test("every Admin SDK config update, as the pinned SDK builds it, passes the guard", async () => {
  const require = createRequire(import.meta.url);
  const lib = (file) =>
    fileURLToPath(new URL(`../node_modules/firebase-admin/lib/${file}`, import.meta.url));
  const { ProjectConfig } = require(lib("auth/project-config.js"));
  const { generateUpdateMask } = require(lib("utils/index.js"));
  const ctx = production();
  let checked = 0;
  for (const program of PROGRAMS) {
    for (const step of program.steps.filter((s) => s.sdk === "admin.updateProjectConfig")) {
      let request;
      try {
        request = ProjectConfig.buildServerRequest(step.args[0]);
      } catch {
        continue; // refused by the SDK before any request
      }
      const mask = generateUpdateMask(request).join(",");
      assert.doesNotThrow(
        () =>
          guardHttp(
            {
              ...patch(mask, request),
              url: `${ITK}/v2/projects/${SANDBOX_PROJECT}/config?updateMask=${encodeURIComponent(mask)}`,
            },
            { ...ctx, touches: program.touches ?? [] },
            { role: "sdk-admin" },
          ),
        `${program.id}#${step.id} (${mask})`,
      );
      checked += 1;
    }
  }
  assert.ok(checked >= 8, `${checked} SDK updates reach the server`);
});

test("a program that leaves any other member changed stops the run", async () => {
  const sandbox = fakeSandbox({
    sideEffect: { monitoring: { requestLogging: { enabled: true } } },
  });
  const session = createSession(local(), { fetchImpl: sandbox.fetchImpl });
  const expected = await session.fullConfig();
  const program = {
    id: "auth-config-sdk/t",
    projection: "strict",
    touches: ["emailPrivacyConfig.enableImprovedEmailPrivacy"],
    steps: [
      {
        id: "off",
        path: "admin/v2/projects/{project}/config",
        auth: "admin",
        method: "PATCH",
        query: { updateMask: "emailPrivacyConfig.enableImprovedEmailPrivacy" },
        body: { emailPrivacyConfig: { enableImprovedEmailPrivacy: false } },
      },
    ],
  };
  const error = await session.runProgram(program, { expected }).catch((e) => e);
  assert.ok(error?.fatal, "fatal");
  assert.match(error.message, /left the configuration changed.*monitoring/);
});

test("the SDK transports refuse what the guard cannot see", async () => {
  const { openSdk } = await import("./auth-config-sdk/sdk.mjs");
  const http = await import("node:http");
  const http2 = await import("node:http2");
  const https = await import("node:https");
  const refused = [];
  const opened = await openSdk(local(), {
    check(request, role, options = {}) {
      guardHttp(request, local(), { role, ...options });
    },
    refuse(error) {
      refused.push(error.message);
    },
  });
  try {
    assert.throws(
      () => https.default.get("https://example.com/"),
      /not reviewed|left the local target/,
    );
    assert.throws(() => http2.default.connect("https://example.com"), /HTTP\/2/);
    const request = http.default.request({
      protocol: "http:",
      hostname: "127.0.0.1",
      port: 32320,
      path: "/identitytoolkit.googleapis.com/v1/accounts:lookup",
      method: "POST",
      headers: { "content-type": "application/json" },
    });
    request.on("error", () => {});
    request.write("{}");
    assert.deepEqual(refused, ["an SDK request body written before end()"]);
  } finally {
    await opened.close();
  }
  await assert.rejects(fetch("http://127.0.0.1:1/"), /outside an SDK step/);
});

test("an SDK internal error both recordings answered alike is behaviour, not noise", () => {
  const internal = { sdk: "error", code: "auth/internal-error", message: "m" };
  // Production answers an Admin link for an unknown address under email privacy with no link,
  // which the Admin SDK reports as an internal error, every time.
  assert.equal(classify({ production: internal, fireemu: internal }), "MATCH");
  assert.equal(
    classify({ production: internal, fireemu: { sdk: "ok", value: "link" } }),
    "MISMATCH",
  );
  // Once the recordings disagree, an internal error is noise again.
  assert.equal(
    classify({ production: internal, alternative: { sdk: "ok", value: 1 }, fireemu: internal }),
    "INDETERMINATE",
  );
  const network = { sdk: "error", code: "auth/network-request-failed", message: "m" };
  assert.equal(classify({ production: network, fireemu: network }), "INDETERMINATE");
});
