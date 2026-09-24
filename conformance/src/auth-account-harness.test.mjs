import assert from "node:assert/strict";
import { test } from "node:test";

import {
  CONFIG_PATHS,
  RECORDED_PROJECT,
  SANDBOX_PROJECT,
  TEST_PHONES,
  buildRequest,
  createContext,
  diffRecordings,
  guardRequest,
  isTransient,
  normalizeResponse,
  validateCorpus,
} from "./auth-account/harness.mjs";
import { scanFixture } from "./auth-account/fixture-scan.mjs";

const production = (overrides = {}) =>
  createContext({
    run: "1700000000000",
    project: SANDBOX_PROJECT,
    target: {
      kind: "production",
      apiKey: "AIza-test-key",
      adminToken: "ya29.test-admin",
      quotaProject: SANDBOX_PROJECT,
      projectNumber: "999888777666",
    },
    startedMs: Date.parse("2026-09-23T10:00:00Z"),
    ...overrides,
  });

const local = () =>
  createContext({
    run: "1700000000000",
    project: SANDBOX_PROJECT,
    target: { kind: "local", origin: "http://127.0.0.1:32296", projectNumber: "123456789012" },
    startedMs: Date.parse("2026-09-23T10:00:00Z"),
  });

test("placeholders become run-unique values and normalize back to stable ones", () => {
  const ctx = production();
  const { init } = buildRequest(
    {
      id: "s",
      path: "v1/accounts:signUp",
      auth: "key",
      body: { email: "EMAIL(primary)", mixed: "EMAILMIXED(primary)", localId: "UID(a)" },
    },
    ctx,
    new Map(),
  );
  const body = JSON.parse(init.body);
  assert.equal(body.email, "fireemu-aa-1700000000000-primary@example.com");
  assert.equal(body.mixed, "FireEmu-AA-1700000000000-primary@Example.COM");
  assert.equal(body.localId, "aa-1700000000000-a");
  const recorded = normalizeResponse(200, JSON.stringify(body), ctx);
  assert.deepEqual(recorded.body, {
    email: "fireemu-aa-<run>-primary@example.com",
    mixed: "FireEmu-AA-<run>-primary@Example.COM",
    localId: "aa-<run>-a",
  });
});

test("client, admin and securetoken requests carry the right credentials", () => {
  const ctx = production();
  const client = buildRequest(
    { id: "c", path: "v1/accounts:signUp", auth: "key", body: {} },
    ctx,
    new Map(),
  );
  assert.equal(
    client.url,
    "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=AIza-test-key",
  );
  assert.equal(client.init.headers.authorization, undefined);

  const admin = buildRequest(
    {
      id: "a",
      method: "GET",
      path: "v1/projects/{project}/accounts:batchGet",
      auth: "admin",
      query: { maxResults: 2 },
    },
    ctx,
    new Map(),
  );
  assert.equal(
    admin.url,
    `https://identitytoolkit.googleapis.com/v1/projects/${SANDBOX_PROJECT}/accounts:batchGet?maxResults=2`,
  );
  assert.equal(admin.init.headers.authorization, "Bearer ya29.test-admin");
  assert.equal(admin.init.headers["x-goog-user-project"], SANDBOX_PROJECT);
  assert.equal(admin.init.body, undefined);

  const refresh = buildRequest(
    {
      id: "r",
      api: "securetoken",
      path: "v1/token",
      auth: "key",
      form: { grant_type: "refresh_token", refresh_token: { $from: "c", path: "refreshToken" } },
    },
    ctx,
    new Map([["c", { refreshToken: "rt-1" }]]),
  );
  assert.equal(refresh.url, "https://securetoken.googleapis.com/v1/token?key=AIza-test-key");
  assert.equal(refresh.init.headers["content-type"], "application/x-www-form-urlencoded");
  assert.equal(refresh.init.body, "grant_type=refresh_token&refresh_token=rt-1");

  const onLocal = buildRequest(
    { id: "a", path: "v1/projects/{project}/accounts", auth: "admin", body: {} },
    local(),
    new Map(),
  );
  assert.equal(
    onLocal.url,
    `http://127.0.0.1:32296/identitytoolkit.googleapis.com/v1/projects/${SANDBOX_PROJECT}/accounts`,
  );
  assert.equal(onLocal.init.headers.authorization, "Bearer owner");
});

test("generated strings reach exact lengths", () => {
  const { init } = buildRequest(
    {
      id: "g",
      path: "v1/accounts:signUp",
      auth: "key",
      body: {
        password: { $repeat: "a", count: 4096 },
        name: { $concat: ["x", { $repeat: "é", count: 2 }] },
      },
    },
    production(),
    new Map(),
  );
  const body = JSON.parse(init.body);
  assert.equal(body.password.length, 4096);
  assert.equal(body.name, "xéé");
});

test("production context refuses any project but the sandbox", () => {
  assert.throws(
    () =>
      createContext({
        run: "1",
        project: "fireemu-35fe6",
        target: {
          kind: "production",
          apiKey: "k",
          adminToken: "t",
          quotaProject: "fireemu-35fe6",
          projectNumber: "12345",
        },
      }),
    /sandbox project/,
  );
  assert.throws(
    () =>
      createContext({
        run: "1",
        project: SANDBOX_PROJECT,
        target: { kind: "local", origin: "http://10.0.0.1:1" },
      }),
    /loopback/,
  );
});

test("the corpus guard refuses mail, real SMS and unbounded runs", () => {
  const program = (steps) => [{ id: "p", steps }];
  assert.throws(
    () =>
      validateCorpus(
        program([
          {
            id: "s",
            path: "v1/accounts:sendOobCode",
            auth: "key",
            body: { requestType: "PASSWORD_RESET", email: "EMAIL(primary)" },
          },
        ]),
      ),
    /unknown/,
  );
  validateCorpus(
    program([
      {
        id: "s",
        path: "v1/accounts:sendOobCode",
        auth: "key",
        body: { requestType: "PASSWORD_RESET", email: "EMAIL(unknown-reset)" },
      },
    ]),
  );
  assert.throws(
    () =>
      validateCorpus(
        program([
          {
            id: "s",
            path: "v1/accounts:sendOobCode",
            auth: "key",
            body: { requestType: "VERIFY_AND_CHANGE_EMAIL", email: "EMAIL(unknown-x)" },
          },
        ]),
      ),
    /VERIFY_AND_CHANGE_EMAIL/,
  );
  assert.throws(
    () =>
      validateCorpus(
        program([
          {
            id: "s",
            path: "v1/accounts:sendVerificationCode",
            auth: "key",
            body: { phoneNumber: "+81312345678" },
          },
        ]),
      ),
    /test phone/,
  );
  validateCorpus(
    program([
      {
        id: "s",
        path: "v1/accounts:sendVerificationCode",
        auth: "key",
        body: { phoneNumber: "PHONE(0)" },
      },
    ]),
  );
  assert.throws(
    () =>
      validateCorpus(program([{ id: "s", path: "https://evil.example/x", auth: "key", body: {} }])),
    /relative/,
  );
  const many = Array.from({ length: 2001 }, (_, i) => ({
    id: `s${i}`,
    path: "v1/accounts:signUp",
    auth: "key",
    body: {},
  }));
  assert.throws(() => validateCorpus(program(many)), /request cap/);
  assert.equal(TEST_PHONES.length, 6);
});

test("two recordings expose nondeterministic rows, ignoring key order", () => {
  const a = {
    p: { steps: { x: { status: 200, body: { a: 1, b: 2 } }, y: { status: 200, body: [1, 2] } } },
  };
  const b = {
    p: { steps: { x: { status: 200, body: { b: 2, a: 1 } }, y: { status: 200, body: [2, 1] } } },
  };
  assert.deepEqual(diffRecordings(a, b), ["p#y"]);
});

test("normalization masks secrets, tokens, generated ids and run-window times only", () => {
  const ctx = production();
  const recorded = normalizeResponse(
    200,
    JSON.stringify({
      kind: "identitytoolkit#SignupNewUserResponse",
      idToken: "eyJ.secret",
      refreshToken: "AMf-secret",
      localId: "Xk2mN8pQr4sT6uV8wY0zA1bC3dE5",
      expiresIn: "3600",
      project_id: "999888777666",
      users: [
        {
          localId: "aa-1700000000000-a",
          passwordHash: "c2VjcmV0LWhhc2g=",
          salt: "c2FsdA==",
          createdAt: "1790157600123",
          lastLoginAt: "1600000000000",
          validSince: "1700000000",
          lastRefreshAt: "2026-09-23T10:05:00.000Z",
          providerUserInfo: [
            { providerId: "password", federatedId: "fireemu-aa-1700000000000-a@example.com" },
          ],
        },
        { localId: "a".repeat(128), passwordHash: "UkVEQUNURUQ=", validSince: "1790157601" },
        { localId: "", createdAt: 1790157600123 },
      ],
      echo: `projects/${SANDBOX_PROJECT}/accounts AIza-test-key`,
    }),
    ctx,
  );
  assert.deepEqual(recorded, {
    status: 200,
    body: {
      kind: "identitytoolkit#SignupNewUserResponse",
      idToken: "<idToken>",
      refreshToken: "<refreshToken>",
      localId: "<generated-localId>",
      expiresIn: "3600",
      project_id: "<project-number>",
      users: [
        {
          localId: "aa-<run>-a",
          passwordHash: "<bytes>",
          salt: "<bytes>",
          createdAt: "<run-time:string:ms>",
          lastLoginAt: "1600000000000",
          validSince: "1700000000",
          lastRefreshAt: "<run-time:instant>",
          providerUserInfo: [
            { providerId: "password", federatedId: "fireemu-aa-<run>-a@example.com" },
          ],
        },
        {
          localId: "a".repeat(128),
          passwordHash: "UkVEQUNURUQ=",
          validSince: "<run-time:string:s>",
        },
        { localId: "", createdAt: "<run-time:number:ms>" },
      ],
      echo: `projects/${RECORDED_PROJECT}/accounts <api-key>`,
    },
  });
  const onLocal = normalizeResponse(200, JSON.stringify({ project_id: "123456789012" }), local());
  assert.deepEqual(onLocal.body, { project_id: "<project-number>" });
});

test("resolved requests are guarded: project, path family, mail, SMS", () => {
  const ctx = production();
  const ok = (step) => guardRequest(buildRequest(step, ctx, new Map()), ctx);
  ok({ id: "a", path: "v1/accounts:signUp", auth: "key", body: { email: "EMAIL(x)" } });
  ok({ id: "b", path: "v1/projects/{project}/accounts:lookup", auth: "admin", body: {} });
  ok({ id: "c", path: "v1/projects/{project}/accounts", auth: "admin", body: {} });
  ok({ id: "d", path: "v1/projects/{project}:queryAccounts", auth: "admin", body: {} });
  ok({ id: "e", api: "securetoken", path: "v1/token", auth: "key", form: { grant_type: "x" } });
  const refused = (step, pattern) =>
    assert.throws(() => guardRequest(buildRequest(step, ctx, new Map()), ctx), pattern);
  refused(
    { id: "p1", path: "v1/projects/fireemu-35fe6/accounts:batchDelete", auth: "admin", body: {} },
    /path/,
  );
  refused(
    {
      id: "p2",
      path: "v1/projects/{project}/%2e%2e/fireemu-35fe6/accounts",
      auth: "admin",
      body: {},
    },
    /path/,
  );
  refused(
    {
      id: "p3",
      path: "v1/accounts:lookup",
      auth: "admin",
      body: { targetProjectId: "fireemu-35fe6" },
    },
    /project/,
  );
  refused(
    {
      id: "p4",
      path: "admin/v2/projects/{project}/config",
      method: "PATCH",
      auth: "admin",
      body: {},
    },
    /path/,
  );
  refused({ id: "p5", path: "v2/accounts/mfaEnrollment:start", auth: "key", body: {} }, /path/);
  const config = buildRequest(
    {
      id: "h",
      method: "PATCH",
      path: "admin/v2/projects/{project}/config",
      auth: "admin",
      body: {},
    },
    ctx,
    new Map(),
  );
  guardRequest(config, ctx, { harness: true });
  assert.throws(() => guardRequest(config, ctx), /path/);
  refused(
    { id: "m1", path: "v1/accounts:signUp", auth: "key", body: { email: "a@gmail.Com" } },
    /example\.com/,
  );
  refused(
    {
      id: "m2",
      path: "v1/accounts:signUp",
      auth: "key",
      body: { email: "a@example.com.evil.org" },
    },
    /example\.com/,
  );
  refused(
    {
      id: "m3",
      path: "v1/accounts:signUp",
      auth: "key",
      body: { email: { $concat: ["a@", "gmail.com"] } },
    },
    /example\.com/,
  );
  for (const email of ['"a"@gmail.com', "a(x)@gmail.com", "@gmail.com"]) {
    refused({ id: "m5", path: "v1/accounts:signUp", auth: "key", body: { email } }, /example\.com/);
  }
  refused(
    {
      id: "m4",
      path: "v1/accounts:sendOobCode",
      auth: "key",
      body: { requestType: "PASSWORD_RESET", email: "EMAIL(primary)" },
    },
    /unknown/,
  );
  refused(
    {
      id: "s1",
      path: "v1/accounts:sendVerificationCode",
      auth: "key",
      body: { phoneNumber: "+81312345678" },
    },
    /test phone/,
  );
  refused(
    {
      id: "s2",
      path: "v1/projects/{project}/accounts",
      auth: "admin",
      body: { phoneNumber: "+81312345678" },
    },
    /test phone/,
  );
});

test("config programs may only mask reviewed account-behaviour paths", () => {
  assert.ok(CONFIG_PATHS.has("signIn.allowDuplicateEmails"));
  assert.throws(
    () => validateCorpus([{ id: "p", config: { "signIn.hashConfig": {} }, steps: [] }]),
    /config path/,
  );
  assert.throws(
    () => validateCorpus([{ id: "p", config: { client: {} }, steps: [] }]),
    /config path/,
  );
  validateCorpus([{ id: "p", config: { "signIn.allowDuplicateEmails": true }, steps: [] }]);
});

test("transient answers are indeterminate, behaviour is not", () => {
  assert.equal(isTransient({ status: 0, transport: "ECONNRESET" }), true);
  assert.equal(isTransient({ status: 503, body: {} }), true);
  assert.equal(isTransient({ status: 429, body: {} }), true);
  assert.equal(
    isTransient({ status: 400, body: { error: { message: "TOO_MANY_ATTEMPTS_TRY_LATER : x" } } }),
    true,
  );
  assert.equal(isTransient({ status: 400, body: { error: { message: "QUOTA_EXCEEDED" } } }), true);
  assert.equal(isTransient({ status: 400, body: { error: { message: "EMAIL_EXISTS" } } }), false);
  assert.equal(isTransient({ status: 200, body: {} }), false);
  assert.equal(
    isTransient({ status: -1, unresolved: "step x recorded nothing", dependencyTransient: true }),
    true,
  );
  assert.equal(
    isTransient({ status: -1, unresolved: "step x recorded nothing", dependencyTransient: false }),
    false,
    "a step whose dependency genuinely failed is behaviour",
  );
});

test("the fixture scan refuses secrets and foreign identifiers", () => {
  const secrets = ["AIza-test-key", "ya29.test-admin", SANDBOX_PROJECT, "999888777666"];
  scanFixture(JSON.stringify({ a: "<idToken>", passwordHash: "UkVEQUNURUQ=" }), secrets);
  scanFixture(
    JSON.stringify({ details: [{ "@type": "type.googleapis.com/google.rpc.ErrorInfo" }] }),
    secrets,
    "a proto Any type key is not an email",
  );
  for (const bad of [
    { k: "AIza-test-key" },
    { k: "Bearer ya29.other" },
    { k: `projects/${SANDBOX_PROJECT}` },
    { k: "999888777666" },
    { k: "eyJhbGciOi.x.y" },
    { k: "AMf-vBx" },
    { passwordHash: "c2VjcmV0" },
    { salt: "c2FsdA==" },
    { email: "someone@gmail.com" },
    { email: "\u30c6\u30b9\u30c8@gmail.com" },
  ]) {
    assert.throws(() => scanFixture(JSON.stringify(bad), secrets), /fixture/);
  }
});

test("config read-back matches written fields and treats cleared policies as unset", async () => {
  const { configMatches } = await import("./auth-account/session.mjs");
  const policy = {
    passwordPolicyEnforcementState: "ENFORCE",
    passwordPolicyVersions: [{ customStrengthOptions: { minPasswordLength: 8 } }],
  };
  assert.equal(
    configMatches(
      { ...policy, lastUpdateTime: "2026-09-23T10:00:00Z", forceUpgradeOnSignin: false },
      policy,
    ),
    true,
  );
  assert.equal(configMatches({ passwordPolicyEnforcementState: "OFF" }, policy), false);
  assert.equal(configMatches(undefined, undefined), true);
  assert.equal(configMatches(false, undefined), true, "an unset switch may read back false");
  assert.equal(configMatches(true, undefined), false);
  assert.equal(configMatches(undefined, false), true, "production omits false switches");
  assert.equal(configMatches(null, false), true);
  assert.equal(configMatches(true, false), false);
  assert.equal(configMatches({ passwordPolicyEnforcementState: "OFF" }, undefined), true);
  assert.equal(configMatches(policy, undefined), false);
  assert.equal(configMatches(true, true), true);
  assert.equal(configMatches(false, true), false);
  assert.equal(configMatches({ "+16505550101": "123456" }, { "+16505550101": "123456" }), true);
});
