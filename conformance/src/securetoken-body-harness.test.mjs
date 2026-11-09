// The requests and the guard of the Secure Token body recording, and its preflight: what may leave
// the process, where, and with which credential.

import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mock, test } from "node:test";

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

// ---- the requests, one by one ------------------------------------------------------------

test("every reviewed request is exactly what the earlier recordings sent", () => {
  const A = { id: "", api: "itk", auth: "admin" };
  const password = "fireemu-stb-Password-1";
  const mail = (n) => `fireemu-stb-${RUN}-${n}@example.com`;
  const id = (n) => `stb-${RUN}-${n}`;
  const T = "tenant-1";
  const tenants = "v2/projects/{project}/tenants";
  assert.deepEqual(R.createAccount(RUN, "a"), {
    ...A,
    id: "create-account",
    method: "POST",
    path: "v1/projects/{project}/accounts",
    body: { localId: id("a"), email: mail("a"), password, emailVerified: true },
  });
  assert.deepEqual(R.createAccount(RUN, "t", T), {
    ...A,
    id: "create-account",
    method: "POST",
    path: `v1/projects/{project}/tenants/${T}/accounts`,
    body: { localId: id("t"), email: mail("t"), password, emailVerified: true },
  });
  assert.deepEqual(R.deleteAccount(RUN, "b"), {
    ...A,
    id: "delete-account",
    method: "POST",
    path: "v1/projects/{project}/accounts:delete",
    body: { localId: id("b") },
  });
  assert.deepEqual(R.deleteAccount(RUN, "t", T), {
    ...A,
    id: "delete-account",
    method: "POST",
    path: `v1/projects/{project}/tenants/${T}/accounts:delete`,
    body: { localId: id("t") },
  });
  assert.deepEqual(R.lookupAccount(RUN, "b"), {
    ...A,
    id: "lookup-account",
    method: "POST",
    path: "v1/projects/{project}/accounts:lookup",
    body: { localId: [id("b")] },
  });
  assert.deepEqual(R.lookupAccount(RUN, "t", T), {
    ...A,
    id: "lookup-account",
    method: "POST",
    path: `v1/projects/{project}/tenants/${T}/accounts:lookup`,
    body: { localId: [id("t")] },
  });
  assert.deepEqual(R.signIn(RUN, "a"), {
    id: "sign-in",
    api: "itk",
    auth: "key",
    method: "POST",
    path: "v1/accounts:signInWithPassword",
    body: { email: mail("a"), password, returnSecureToken: true },
  });
  assert.deepEqual(R.signIn(RUN, "t", T).body, {
    email: mail("t"),
    password,
    returnSecureToken: true,
    tenantId: T,
  });
  assert.deepEqual(R.countAccounts(), {
    ...A,
    id: "count-accounts",
    method: "POST",
    path: "v1/projects/{project}/accounts:query",
    body: { returnUserInfo: false },
  });
  assert.deepEqual(R.createTenant(RUN), {
    ...A,
    id: "create-tenant",
    method: "POST",
    path: tenants,
    body: { displayName: `stb-${RUN}`, allowPasswordSignup: true },
  });
  assert.deepEqual(R.getTenant(T), {
    ...A,
    id: "get-tenant",
    method: "GET",
    path: `${tenants}/${T}`,
  });
  assert.deepEqual(R.deleteTenant(T), {
    ...A,
    id: "delete-tenant",
    method: "DELETE",
    path: `${tenants}/${T}`,
  });
  assert.deepEqual(R.listTenants(), {
    ...A,
    id: "list-tenants",
    method: "GET",
    path: tenants,
    query: { pageSize: 100 },
  });
  assert.deepEqual(R.listTenants("tok").query, { pageSize: 100, pageToken: "tok" });
  assert.deepEqual(R.readConfig(), {
    ...A,
    id: "read-config",
    method: "GET",
    path: "admin/v2/projects/{project}/config",
  });
  assert.deepEqual(R.writeTenancy(true), {
    ...A,
    id: "write-tenancy",
    method: "PATCH",
    path: "admin/v2/projects/{project}/config",
    query: { updateMask: "multiTenant.allowTenants" },
    body: { multiTenant: { allowTenants: true } },
  });
  assert.deepEqual(R.writeTenancy(false).body, { multiTenant: { allowTenants: false } });
  assert.deepEqual(R.refresh({ contentType: "application/json", body: "{}" }), {
    id: "refresh",
    api: "securetoken",
    auth: "key",
    method: "POST",
    path: "v1/token",
    contentType: "application/json",
    body: "{}",
  });
});

test("buildRequest: defaults, headers per credential, and the refusal of an unknown credential", () => {
  for (const ctx of [localCtx(RUN), production()]) {
    const local = ctx.target.kind === "local";
    // A key request carries no owner credential; an admin request carries one.
    const keyed = buildRequest(ctx, { id: "x", path: "v1/x", auth: "key", body: {} });
    assert.equal(keyed.init.headers.authorization, undefined);
    assert.equal(keyed.init.headers["x-goog-user-project"], undefined);
    assert.equal(
      new URL(keyed.url).searchParams.get("key"),
      local ? "fake-api-key" : "AIza-test-key",
    );
    const admin = buildRequest(ctx, { id: "x", path: "v1/x", auth: "admin" });
    assert.equal(
      admin.init.headers.authorization,
      local ? "Bearer owner" : "Bearer ya29.test-owner",
    );
    assert.equal("x-goog-user-project" in admin.init.headers, !local);
    if (!local) assert.equal(admin.init.headers["x-goog-user-project"], SANDBOX_PROJECT);
    assert.equal(new URL(admin.url).searchParams.has("key"), false);
    // No method means POST; no body means no content type and no body.
    assert.equal(admin.init.method, "POST");
    assert.equal(admin.init.body, undefined);
    assert.equal(admin.init.headers["content-type"], undefined);
    // The host is the identity toolkit unless a request says securetoken.
    assert.ok(
      admin.url.includes(
        local
          ? "/identitytoolkit.googleapis.com/v1/x"
          : "https://identitytoolkit.googleapis.com/v1/x",
      ),
    );
    const token = buildRequest(ctx, { id: "t", api: "securetoken", path: "v1/token", auth: "key" });
    assert.ok(token.url.includes("securetoken.googleapis.com/v1/token?key="));
    assert.throws(
      () => buildRequest(ctx, { id: "x", path: "v1/x", auth: "none" }),
      /auth must be key or admin/,
    );
    assert.throws(() => buildRequest(ctx, { id: "x", path: "v1/x" }), /auth must be key or admin/);
    // A string body is sent as it is, an object as JSON, with the content type asked for or JSON.
    const text = buildRequest(ctx, {
      id: "x",
      path: "p",
      auth: "key",
      body: "a=b",
      contentType: "application/x-www-form-urlencoded",
    });
    assert.equal(text.init.body, "a=b");
    assert.equal(text.init.headers["content-type"], "application/x-www-form-urlencoded");
    const json = buildRequest(ctx, { id: "x", path: "p", auth: "key", body: { a: 1 } });
    assert.equal(json.init.body, '{"a":1}');
    assert.equal(json.init.headers["content-type"], "application/json");
    // Query values are strings in the URL.
    const queried = buildRequest(ctx, {
      id: "x",
      path: "p",
      auth: "admin",
      query: { pageSize: 100, k: "v w" },
    });
    assert.equal(new URL(queried.url).search, "?pageSize=100&k=v+w");
  }
});

test("a project name is matched literally by the guard", () => {
  const ctx = localCtx(RUN);
  ctx.project = "my.project";
  const at = (project) => ({
    url: `http://127.0.0.1:1/identitytoolkit.googleapis.com/v1/projects/${project}/accounts:query`,
    init: { method: "POST", headers: { "content-type": "application/json" }, body: "{}" },
  });
  guardRequest(at("my.project"), ctx);
  assert.throws(() => guardRequest(at("myXproject"), ctx), /reviewed family/);
});

test("withProject fills every {project} and nothing else", () => {
  assert.equal(withProject({ path: "a/{project}/b/{project}" }, "p").path, "a/p/b/p");
  assert.deepEqual(withProject({ id: "i", path: "x" }, "p"), { id: "i", path: "x" });
});

test("the guard reads the path before the browser normalizes it, and the query not at all", () => {
  const ctx = production();
  const post = (url, body = "a=b") => ({ url, init: { method: "POST", headers: {}, body } });
  // `new URL` collapses these to /v1/token, a reviewed family: only the raw check refuses them.
  for (const url of [
    "https://securetoken.googleapis.com/v1/x/../token?key=k",
    "https://securetoken.googleapis.com/v1/x/%2e%2e/token?key=k",
    "https://securetoken.googleapis.com/v1/./token?key=k",
  ])
    assert.throws(() => guardRequest(post(url), ctx), /not canonical/, url);
  // An encoded slash after the question mark is a value, not a path.
  guardRequest(post("https://securetoken.googleapis.com/v1/token?key=a%2fb"), ctx);
  // A request with no method is a GET.
  guardRequest(
    {
      url: `https://identitytoolkit.googleapis.com/v2/projects/${SANDBOX_PROJECT}/tenants`,
      init: { headers: {} },
    },
    ctx,
  );
  assert.throws(
    () =>
      guardRequest(
        {
          url: `https://identitytoolkit.googleapis.com/v2/projects/${SANDBOX_PROJECT}/accounts`,
          init: { headers: {} },
        },
        ctx,
      ),
    /reviewed family/,
  );
});

test("the guard reads arrays and nested objects of a body, and bounds a refresh body", () => {
  const ctx = localCtx(RUN);
  ctx.tenantId = "tenant-1";
  const lookup = (body) => ({
    url: `http://127.0.0.1:1/identitytoolkit.googleapis.com/v1/projects/${SANDBOX_PROJECT}/accounts:lookup`,
    init: {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    },
  });
  guardRequest(lookup({ localId: [localIdOf(RUN, "a"), localIdOf(RUN, "b")] }), ctx);
  assert.throws(
    () => guardRequest(lookup({ localId: [localIdOf(RUN, "a"), "stb-1-b"] }), ctx),
    /localId/,
  );
  assert.throws(
    () => guardRequest(lookup({ nested: { deep: [{ email: "x@gmail.com" }] } }), ctx),
    /outside example.com|email/,
  );
  assert.throws(() => guardRequest(lookup({ nested: { deep: ["+16505550101"] } }), ctx), /phone/);
  guardRequest(lookup({ nested: { deep: [{ note: "fine" }, 7, null, true] } }), ctx);
  const refreshBody = (size) => ({
    url: "http://127.0.0.1:1/securetoken.googleapis.com/v1/token?key=k",
    init: {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "x".repeat(size),
    },
  });
  guardRequest(refreshBody(4096), ctx);
  assert.throws(() => guardRequest(refreshBody(4097), ctx), /small/);
  // The tenant a request names in its body must be the run's.
  const signIn = (tenantId) => ({
    url: "http://127.0.0.1:1/identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=k",
    init: {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: emailOf(RUN, "t"), password: "p", tenantId }),
    },
  });
  guardRequest(signIn("tenant-1"), ctx);
  assert.throws(() => guardRequest(signIn("tenant-2"), ctx), /tenant this run did not create/);
});

test("only a config PATCH with the one mask and the one field is admitted", () => {
  const ctx = localCtx(RUN);
  const config = (method, mask, body) => ({
    url: `http://127.0.0.1:1/identitytoolkit.googleapis.com/admin/v2/projects/${SANDBOX_PROJECT}/config${mask ? `?updateMask=${mask}` : ""}`,
    init: {
      method,
      headers: { "content-type": "application/json" },
      body: body && JSON.stringify(body),
    },
  });
  guardRequest(config("GET"), ctx);
  guardRequest(
    config("PATCH", "multiTenant.allowTenants", { multiTenant: { allowTenants: false } }),
    ctx,
  );
  for (const bad of [
    config("PATCH", undefined, { multiTenant: { allowTenants: true } }),
    config("PATCH", "multiTenant", { multiTenant: { allowTenants: true } }),
    config("PATCH", "multiTenant.allowTenants", { multiTenant: { allowTenants: true, x: 1 } }),
    config("PATCH", "multiTenant.allowTenants", { multiTenant: {} }),
    config("PATCH", "multiTenant.allowTenants", { other: 1 }),
    config("PATCH", "multiTenant.allowTenants", { multiTenant: { allowTenants: true }, other: 1 }),
    config("DELETE"),
    config("POST", "multiTenant.allowTenants", { multiTenant: { allowTenants: true } }),
  ])
    assert.throws(() => guardRequest(bad, ctx), undefined, `${bad.init.method} ${bad.url}`);
});

test("a preflight read waits a minute at most", async () => {
  const timeouts = mock.method(AbortSignal, "timeout", AbortSignal.timeout);
  try {
    const fake = createWorld({ project: SANDBOX_PROJECT, number: NUMBER, tenancy: true });
    const fetchImpl = (url, init) => {
      const parsed = new URL(url);
      return fake.fetch(`http://127.0.0.1:1${parsed.pathname}${parsed.search}`, init);
    };
    await preflight(production(), "", { fetchImpl });
    assert.equal(timeouts.mock.calls.length, 3);
    assert.ok(timeouts.mock.calls.every((c) => c.arguments[0] === 60_000));
  } finally {
    timeouts.mock.restore();
  }
});

test("a failed tenant list is a failed read, and a count of tenants is a problem", async () => {
  const fetchFor = (fake) => (url, init) => {
    const parsed = new URL(url);
    return fake.fetch(`http://127.0.0.1:1${parsed.pathname}${parsed.search}`, init);
  };
  const broken = createWorld({
    project: SANDBOX_PROJECT,
    number: NUMBER,
    tenancy: true,
    faults: [(r) => (r.path.endsWith("/tenants") ? { status: 500, json: {} } : undefined)],
  });
  const a = await preflight(production(), "", { fetchImpl: fetchFor(broken) });
  assert.deepEqual(a.report.failedReads, ["tenants (HTTP 500)"]);
  assert.deepEqual(a.problems, ["preflight read failed: tenants (HTTP 500)"]);
  const crowded = createWorld({ project: SANDBOX_PROJECT, number: NUMBER, tenancy: true });
  crowded.world.tenants.set("a", { id: "a", name: "projects/1/tenants/a", displayName: "one-one" });
  crowded.world.tenants.set("b", { id: "b", name: "projects/1/tenants/b", displayName: "two-two" });
  const b = await preflight(production(), "", { fetchImpl: fetchFor(crowded) });
  assert.equal(b.report.tenants, 2);
  assert.deepEqual(b.problems, ["2 tenant(s) exist"]);
  // With tenancy off nothing is listed and no tenant is counted.
  const off = createWorld({ project: SANDBOX_PROJECT, number: NUMBER, tenancy: false });
  off.world.tenants.set("a", { id: "a", name: "projects/1/tenants/a", displayName: "one-one" });
  const c = await preflight(production(), "", { fetchImpl: fetchFor(off) });
  assert.equal(c.report.tenants, 0);
  assert.equal(c.report.tenantsListed, false);
  assert.deepEqual(c.problems, []);
});

test("a preflight read does not follow a redirect, and says the read failed", async () => {
  const seen = [];
  const server = createServer((incoming, res) => {
    seen.push(incoming.url);
    res.writeHead(302, { location: "/elsewhere" });
    res.end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const ctx = createContext({
      run: RUN,
      project: SANDBOX_PROJECT,
      target: {
        kind: "local",
        origin: `http://127.0.0.1:${server.address().port}`,
        projectNumber: NUMBER,
      },
    });
    const { report, problems } = await preflight(ctx);
    assert.deepEqual(report.failedReads, ["config (HTTP 0)", "accounts (HTTP 0)"]);
    assert.ok(problems.length >= 2);
    assert.equal(seen.length, 2);
    assert.ok(!seen.includes("/elsewhere"));
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
  // And the init it hands to the fetch says so.
  const inits = [];
  const fake = createWorld({ project: SANDBOX_PROJECT, number: NUMBER, tenancy: true });
  await preflight(production(), "", {
    fetchImpl: (url, init) => {
      inits.push(init.redirect);
      const parsed = new URL(url);
      return fake.fetch(`http://127.0.0.1:1${parsed.pathname}${parsed.search}`, init);
    },
  });
  assert.deepEqual(inits, ["error", "error", "error"]);
});
