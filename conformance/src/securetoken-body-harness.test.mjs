// The requests and the guard of the Secure Token body recording, and its preflight: what may leave
// the process, where, and with which credential.

import assert from "node:assert/strict";
import { test } from "node:test";

import { SANDBOX_PROJECT, createContext } from "./auth-account/harness.mjs";
import { encodeBody, ROWS } from "./securetoken-body/corpus.mjs";
import {
  buildRequest,
  emailOf,
  guardRequest,
  localIdOf,
  requests as R,
  tenantNameOf,
  withProject,
} from "./securetoken-body/harness.mjs";
import { preflight } from "./securetoken-body/preflight.mjs";
import { generator, localCtx, NUMBER } from "./securetoken-body/test-support.mjs";
import { createWorld } from "./securetoken-body/test-world.mjs";

const RUN = "1794000000";
const production = () =>
  createContext({
    run: RUN,
    project: SANDBOX_PROJECT,
    target: {
      kind: "production",
      apiKey: "AIza-test-key",
      adminToken: "ya29.test-owner",
      quotaProject: SANDBOX_PROJECT,
      projectNumber: NUMBER,
    },
  });
const req = (ctx, spec) => buildRequest(ctx, withProject(spec, ctx.project));
const TOKENS = { a: "tok-a", b: "tok-b", t: "tok-t" };
const refresh = (id) =>
  R.refresh(
    encodeBody(
      ROWS.find((r) => r.id === id),
      TOKENS,
    ),
  );

test("a refresh row goes to securetoken with the API key alone and no owner credential", () => {
  const ctx = production();
  const { url, init } = req(ctx, refresh("json-camel"));
  assert.equal(url, "https://securetoken.googleapis.com/v1/token?key=AIza-test-key");
  assert.deepEqual(init.headers, { "content-type": "application/json" });
  assert.equal(init.method, "POST");
  assert.equal(init.body, '{"grantType":"refresh_token","refreshToken":"tok-a"}');
  guardRequest({ url, init }, ctx);
});

test("management calls carry the owner credential and the quota project, sign-in only the key", () => {
  const ctx = production();
  ctx.tenantId = "tenant-1";
  const created = req(ctx, R.createAccount(RUN, "a"));
  assert.equal(
    created.url,
    `https://identitytoolkit.googleapis.com/v1/projects/${SANDBOX_PROJECT}/accounts`,
  );
  assert.equal(created.init.headers.authorization, "Bearer ya29.test-owner");
  assert.equal(created.init.headers["x-goog-user-project"], SANDBOX_PROJECT);
  const signIn = req(ctx, R.signIn(RUN, "t", "tenant-1"));
  assert.ok(signIn.url.endsWith("/v1/accounts:signInWithPassword?key=AIza-test-key"));
  assert.equal(signIn.init.headers.authorization, undefined);
  assert.equal(JSON.parse(signIn.init.body).tenantId, "tenant-1");
  for (const spec of [created, signIn]) guardRequest(spec, ctx);
});

test("every reviewed request passes its own guard, locally and in production", () => {
  for (const ctx of [production(), localCtx(RUN)]) {
    ctx.tenantId = "tenant-1";
    const specs = [
      ...ROWS.map((r) => R.refresh(encodeBody(r, TOKENS))),
      R.createAccount(RUN, "a"),
      R.createAccount(RUN, "t", "tenant-1"),
      R.deleteAccount(RUN, "a"),
      R.deleteAccount(RUN, "t", "tenant-1"),
      R.lookupAccount(RUN, "b"),
      R.lookupAccount(RUN, "t", "tenant-1"),
      R.signIn(RUN, "a"),
      R.signIn(RUN, "t", "tenant-1"),
      R.countAccounts(),
      R.createTenant(RUN),
      R.getTenant("tenant-1"),
      R.deleteTenant("tenant-1"),
      R.listTenants(),
      R.listTenants("page-2"),
      R.readConfig(),
      R.writeTenancy(true),
      R.writeTenancy(false),
    ];
    for (const spec of specs) guardRequest(req(ctx, spec), ctx);
  }
});

test("the guard refuses every request outside the reviewed families", () => {
  const ctx = production();
  ctx.tenantId = "tenant-1";
  const raw = (url, init = {}) => ({ url, init: { method: "POST", headers: {}, ...init } });
  const json = (body) => ({
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const itk = "https://identitytoolkit.googleapis.com";
  const cases = {
    "another host": raw("https://example.com/v1/token?key=k"),
    "a path traversal": raw(`${itk}/v1/projects/${SANDBOX_PROJECT}/accounts/../x`),
    "an encoded dot": raw(`${itk}/v1/projects/${SANDBOX_PROJECT}%2faccounts`),
    "another project": raw(`${itk}/v1/projects/fireemu-35fe6/accounts`, json({})),
    "the signUp family": raw(`${itk}/v1/accounts:signUp?key=k`, json({})),
    sendOobCode: raw(`${itk}/v1/accounts:sendOobCode?key=k`, json({})),
    "a phone verification": raw(`${itk}/v1/accounts:sendVerificationCode?key=k`, json({})),
    "a GET of the token endpoint": raw("https://securetoken.googleapis.com/v1/token?key=k", {
      method: "GET",
    }),
    "a refresh with another query": raw(
      "https://securetoken.googleapis.com/v1/token?key=k&tenantId=x",
      { body: "a=b" },
    ),
    "a refresh without the key": raw("https://securetoken.googleapis.com/v1/token", {
      body: "a=b",
    }),
    "a DELETE of the project": raw(`${itk}/v2/projects/${SANDBOX_PROJECT}`, { method: "DELETE" }),
    "a PATCH of another config field": raw(
      `${itk}/admin/v2/projects/${SANDBOX_PROJECT}/config?updateMask=signIn.email.enabled`,
      { method: "PATCH", ...json({ multiTenant: { allowTenants: true } }) },
    ),
    "a PATCH with extra fields": raw(
      `${itk}/admin/v2/projects/${SANDBOX_PROJECT}/config?updateMask=multiTenant.allowTenants`,
      { method: "PATCH", ...json({ multiTenant: { allowTenants: true }, mfa: {} }) },
    ),
    "a tenant the run did not create": raw(`${itk}/v2/projects/${SANDBOX_PROJECT}/tenants/other`, {
      method: "DELETE",
    }),
    "an account in another tenant": raw(
      `${itk}/v1/projects/${SANDBOX_PROJECT}/tenants/other/accounts`,
      json({ localId: `stb-${RUN}-a`, email: emailOf(RUN, "a") }),
    ),
    "a sign-in naming another tenant": raw(
      `${itk}/v1/accounts:signInWithPassword?key=k`,
      json({ email: emailOf(RUN, "a"), password: "p", tenantId: "other" }),
    ),
    "an email of another run": raw(
      `${itk}/v1/projects/${SANDBOX_PROJECT}/accounts`,
      json({ localId: `stb-${RUN}-a`, email: "fireemu-stb-1-a@example.com", password: "p" }),
    ),
    "an email outside example.com": raw(
      `${itk}/v1/projects/${SANDBOX_PROJECT}/accounts`,
      json({ localId: `stb-${RUN}-a`, email: `fireemu-stb-${RUN}-a@gmail.com`, password: "p" }),
    ),
    "a local id of another run": raw(
      `${itk}/v1/projects/${SANDBOX_PROJECT}/accounts:delete`,
      json({ localId: "stb-1-a" }),
    ),
    "a tenant of another name": raw(
      `${itk}/v2/projects/${SANDBOX_PROJECT}/tenants`,
      json({ displayName: "someone-elses" }),
    ),
    "a phone number": raw(
      `${itk}/v1/projects/${SANDBOX_PROJECT}/accounts`,
      json({ localId: `stb-${RUN}-a`, email: emailOf(RUN, "a"), phoneNumber: "+16505550101" }),
    ),
    "an unreviewed query parameter": raw(`${itk}/v2/projects/${SANDBOX_PROJECT}/tenants?filter=x`, {
      method: "GET",
    }),
    "an oversized refresh body": raw("https://securetoken.googleapis.com/v1/token?key=k", {
      body: "x".repeat(5000),
    }),
  };
  for (const [name, request] of Object.entries(cases))
    assert.throws(() => guardRequest(request, ctx), undefined, name);
});

test("the guard keeps a local run on its loopback origin", () => {
  const ctx = localCtx(RUN);
  assert.throws(
    () =>
      guardRequest(
        {
          url: "http://127.0.0.1:2/securetoken.googleapis.com/v1/token?key=k",
          init: { method: "POST", headers: {}, body: "a=b" },
        },
        ctx,
      ),
    /left the local target/,
  );
  assert.throws(
    () =>
      guardRequest(
        { url: "http://127.0.0.1:1/other/v1/token?key=k", init: { method: "POST", headers: {} } },
        ctx,
      ),
    /reviewed family/,
  );
});

test("names carry the run id and fit the tenant display-name rule", () => {
  assert.equal(localIdOf(RUN, "a"), "stb-1794000000-a");
  assert.equal(emailOf(RUN, "a"), "fireemu-stb-1794000000-a@example.com");
  assert.match(tenantNameOf(RUN), /^[A-Za-z][A-Za-z0-9-]{3,19}$/);
  assert.match(tenantNameOf("9999999999"), /^[A-Za-z][A-Za-z0-9-]{3,19}$/);
});

test("property: a guarded request passes exactly when everything it names is the run's own", () => {
  const rng = generator(0xfeed);
  const ctx = localCtx(RUN);
  ctx.tenantId = "tenant-1";
  const own = emailOf(RUN, "b");
  // [field, value, passes]: constructed from what the guard is meant to admit, not from its code.
  const table = [
    ["email", own, true],
    ["email", emailOf("1", "a"), false],
    ["email", `fireemu-stb-${RUN}-a@evil.example`, false],
    ["email", "plain@gmail.com", false],
    ["localId", localIdOf(RUN, "t"), true],
    ["localId", localIdOf("1", "t"), false],
    ["localId", "someone", false],
    ["note", "hello", true],
    ["note", localIdOf(RUN, "a"), true],
    ["note", own, true],
    ["note", "a@b.com", false],
    ["note", "+16505550101", false],
    ["note", "+1 (650) 555-0101", false],
  ];
  for (let round = 0; round < 300; round += 1) {
    const [field, value, passes] = rng.pick(table);
    // Noise around the value cannot make a foreign one pass or an own one fail.
    const body = rng.bool() ? { n: rng.int(1000), [field]: value } : { [field]: value, ok: true };
    const spec = { ...R.deleteAccount(RUN, "a"), body };
    if (field === "email" || field === "note")
      spec.body = { ...body, localId: localIdOf(RUN, "a") };
    let passed = true;
    try {
      guardRequest(req(ctx, spec), ctx);
    } catch {
      passed = false;
    }
    assert.equal(passed, passes, `${field}=${value}`);
  }
});

// ---- preflight ----------------------------------------------------------------------------

test("preflight reads config, the account count and (tenancy on) the tenant list, and writes nothing", async () => {
  const ctx = production();
  const fake = createWorld({ project: SANDBOX_PROJECT, number: NUMBER, tenancy: true });
  const seen = [];
  const fetchImpl = async (url, init) => {
    seen.push(`${init.method} ${new URL(url).pathname}`);
    const parsed = new URL(url);
    const response = await fake.fetch(`http://127.0.0.1:1${parsed.pathname}${parsed.search}`, init);
    return response;
  };
  const { report, problems } = await preflight(ctx, "", { fetchImpl });
  assert.deepEqual(problems, []);
  assert.equal(report.passwordEnabled, true);
  assert.equal(report.multiTenancy, true);
  assert.equal(report.projectAccounts, 0);
  assert.equal(report.tenantsListed, true);
  assert.ok(seen.every((s) => s.startsWith("GET") || s.endsWith("accounts:query")));
  assert.equal(seen.length, 3);
});

test("preflight does not list tenants while tenancy is off, and refuses a dirty sandbox", async () => {
  const ctx = production();
  const fake = createWorld({ project: SANDBOX_PROJECT, number: NUMBER, tenancy: false });
  fake.world.accounts.set("someone", { localId: "someone", email: "x@example.com" });
  const fetchImpl = (url, init) =>
    fake.fetch(`http://127.0.0.1:1${new URL(url).pathname}${new URL(url).search}`, init);
  const { report, problems } = await preflight(ctx, "", { fetchImpl });
  assert.equal(report.tenantsListed, false);
  assert.ok(problems.some((p) => p.includes("1 project-level account")));
  const down = await preflight(ctx, "", {
    fetchImpl: async () => {
      throw new Error("offline");
    },
  });
  assert.ok(down.problems.some((p) => p.includes("config (HTTP 0)")));
  assert.ok(down.problems.some((p) => p.includes("project-level account")));
});
