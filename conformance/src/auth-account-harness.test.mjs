import assert from "node:assert/strict";
import { test } from "node:test";

import {
  RECORDED_PROJECT,
  SANDBOX_PROJECT,
  TEST_PHONES,
  buildRequest,
  createContext,
  diffRecordings,
  normalizeResponse,
  validateCorpus,
} from "./auth-account/harness.mjs";

const production = (overrides = {}) =>
  createContext({
    run: "1700000000000",
    project: SANDBOX_PROJECT,
    target: {
      kind: "production",
      apiKey: "AIza-test-key",
      adminToken: "ya29.test-admin",
      quotaProject: SANDBOX_PROJECT,
    },
    ...overrides,
  });

const local = () =>
  createContext({
    run: "1700000000000",
    project: SANDBOX_PROJECT,
    target: { kind: "local", origin: "http://127.0.0.1:32296" },
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
        target: { kind: "production", apiKey: "k", adminToken: "t", quotaProject: "fireemu-35fe6" },
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

test("normalization masks secrets, tokens, generated ids and times but keeps shape", () => {
  const ctx = production();
  const recorded = normalizeResponse(
    200,
    JSON.stringify({
      kind: "identitytoolkit#SignupNewUserResponse",
      idToken: "eyJ.secret",
      refreshToken: "AMf-secret",
      localId: "Xk2mN8pQr4sT6uV8wY0zA1bC3dE5",
      expiresIn: "3600",
      users: [
        {
          localId: "aa-1700000000000-a",
          passwordHash: "UkVEQUNURUQ=",
          salt: "c2FsdA==",
          createdAt: "1700000000123",
          lastRefreshAt: "2026-09-23T10:00:00.000Z",
          providerUserInfo: [
            { providerId: "password", federatedId: "fireemu-aa-1700000000000-a@example.com" },
          ],
        },
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
      expiresIn: "<seconds>",
      users: [
        {
          localId: "aa-<run>-a",
          passwordHash: "<bytes>",
          salt: "<bytes>",
          createdAt: "<time>",
          lastRefreshAt: "<time>",
          providerUserInfo: [
            { providerId: "password", federatedId: "fireemu-aa-<run>-a@example.com" },
          ],
        },
      ],
      echo: `projects/${RECORDED_PROJECT}/accounts <api-key>`,
    },
  });
  const error = normalizeResponse(
    400,
    JSON.stringify({
      error: {
        code: 400,
        message: "EMAIL_EXISTS",
        errors: [{ message: "EMAIL_EXISTS", domain: "global", reason: "invalid" }],
      },
    }),
    ctx,
  );
  assert.deepEqual(error, {
    status: 400,
    body: {
      error: {
        code: 400,
        message: "EMAIL_EXISTS",
        errors: [{ message: "EMAIL_EXISTS", domain: "global", reason: "invalid" }],
      },
    },
  });
  assert.deepEqual(normalizeResponse(502, "<html>bad gateway</html>", ctx), {
    status: 502,
    nonJson: true,
  });
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
