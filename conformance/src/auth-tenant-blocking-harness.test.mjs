import assert from "node:assert/strict";
import { test } from "node:test";

import { buildRequest, createContext } from "./auth-account/harness.mjs";
import { PROGRAMS } from "./auth-tenant-blocking/corpus.mjs";
import {
  UNKNOWN_TENANT,
  guardTenantRequest,
  validateTenantCorpus,
} from "./auth-tenant-blocking/guard.mjs";
import {
  createTenantRegistry,
  normalizeTenantResponse,
  tenantShape,
} from "./auth-tenant-blocking/harness.mjs";
import { createEnrollmentRegistry } from "./auth-mfa/harness.mjs";
import { resolveTenants, tenantIdOf } from "./auth-tenant-blocking/session.mjs";

const production = createContext({
  run: "1790000000000",
  project: "fireemu-oracle-idp",
  target: {
    kind: "production",
    apiKey: "AIzaFAKEKEYFORTESTSONLY",
    adminToken: "ya29.owner",
    quotaProject: "fireemu-oracle-idp",
    projectNumber: "637500000000",
  },
  startedMs: 1_790_000_000_000,
});

const OURS = "atb-sel-a-x7k2p";
const FOREIGN = "fsr-tenant-q1w2e";
const guard = (step, options = {}) =>
  guardTenantRequest(buildRequest(step, production, new Map()), production, {
    tenants: new Set([OURS]),
    ...options,
  });
const registries = () => ({
  enrollments: createEnrollmentRegistry(),
  tenants: createTenantRegistry(),
});

test("a request may name only a tenant the program created or the reserved unknown id", () => {
  const lookup = (tenant) => ({
    id: "s",
    path: `v1/projects/{project}/tenants/${tenant}/accounts:lookup`,
    auth: "admin",
    body: { localId: ["x"] },
  });
  guard(lookup(OURS));
  guard(lookup(UNKNOWN_TENANT));
  assert.throws(() => guard(lookup(FOREIGN)), /foreign tenant/);
  const signIn = (tenantId) => ({
    id: "s",
    path: "v1/accounts:signInWithPassword",
    auth: "key",
    body: { email: "EMAIL(a)", password: "p", tenantId },
  });
  guard(signIn(OURS));
  guard(signIn(""));
  guard(signIn(7));
  assert.throws(() => guard(signIn(FOREIGN)), /foreign tenant/);
  const del = (tenant) => ({
    id: "s",
    path: `v2/projects/{project}/tenants/${tenant}`,
    method: "DELETE",
    auth: "admin",
  });
  guard(del(OURS));
  assert.throws(() => guard(del(FOREIGN)), /foreign tenant/);
});

test("only the harness writes the project config, and only reviewed paths and values", () => {
  const patch = (mask, body) => ({
    id: "s",
    path: "admin/v2/projects/{project}/config",
    method: "PATCH",
    auth: "admin",
    query: { updateMask: mask },
    body,
  });
  const allow = patch("multiTenant.allowTenants", { multiTenant: { allowTenants: true } });
  assert.throws(() => guard(allow), /only the harness/);
  guard(allow, { harness: true });
  assert.throws(
    () => guard(patch("signIn.hashConfig", { signIn: { hashConfig: {} } }), { harness: true }),
    /reviewed paths/,
  );
  assert.throws(
    () => guard(patch("mfa", { mfa: { state: "MANDATORY" } }), { harness: true }),
    /not reviewed/,
  );
  assert.throws(
    () =>
      guard(patch("multiTenant.allowTenants", { multiTenant: { allowTenants: true }, mfa: {} }), {
        harness: true,
      }),
    /only its masked paths/,
  );
});

test("project accounts are listed or deleted in bulk only by the harness; tenant ones by rows", () => {
  const bulk = (prefix) => ({
    id: "s",
    path: `${prefix}/accounts:batchDelete`,
    auth: "admin",
    body: { localIds: ["x"], force: true },
  });
  assert.throws(() => guard(bulk("v1/projects/{project}")), /harness/);
  guard(bulk("v1/projects/{project}"), { harness: true });
  guard(bulk(`v1/projects/{project}/tenants/${OURS}`));
});

test("phones are test numbers, also as map keys, and addresses are example.com", () => {
  const create = (body) => ({
    id: "s",
    path: "v2/projects/{project}/tenants",
    method: "POST",
    auth: "admin",
    body,
  });
  guard(create({ displayName: "atb-x", testPhoneNumbers: { "+16505550101": "123456" } }));
  assert.throws(
    () => guard(create({ displayName: "atb-x", testPhoneNumbers: { "+14155550123": "123456" } })),
    /test phone/,
  );
  assert.throws(() => guard(create({ displayName: "atb-x", hashConfig: {} })), /hashConfig/);
  assert.throws(
    () =>
      guard({
        id: "s",
        path: "v1/accounts:sendOobCode",
        auth: "key",
        body: { requestType: "PASSWORD_RESET", email: "someone@gmail.com" },
      }),
    /example\.com/,
  );
});

test("providers live only in the program's tenants and carry no secret", () => {
  const provider = (prefix, method, body) => ({
    id: "s",
    path: `${prefix}/oauthIdpConfigs`,
    method,
    auth: "admin",
    query: { oauthIdpConfigId: "oidc.atb-a" },
    body,
  });
  const body = { clientId: "atb-client", issuer: "https://accounts.google.com" };
  guard(provider(`v2/projects/{project}/tenants/${OURS}`, "POST", body));
  guard(provider("v2/projects/{project}", "GET"));
  assert.throws(() => guard(provider("v2/projects/{project}", "POST", body)), /only listed/);
  assert.throws(
    () =>
      guard(
        provider(`v2/projects/{project}/tenants/${OURS}`, "POST", { ...body, clientSecret: "x" }),
      ),
    /secret/,
  );
  assert.throws(
    () =>
      guard(
        provider(`v2/projects/{project}/tenants/${OURS}`, "POST", {
          ...body,
          issuer: "https://evil.example.com",
        }),
      ),
    /issuer/,
  );
});

test("tenants are named per program by label or order, keeping the shape of their id", () => {
  assert.equal(tenantShape("atb-sel-a-x7k2p"), "atb-sel-a-*5");
  assert.equal(tenantShape("fireemu-00000000000000000001"), "other");
  const r = registries();
  r.tenants.label("atb-sel-a-x7k2p", "a");
  const recorded = normalizeTenantResponse(
    200,
    JSON.stringify({
      name: "projects/fireemu-oracle-idp/tenants/atb-man-min-abcde",
      users: [{ localId: "u", tenantId: "atb-sel-a-x7k2p" }],
    }),
    production,
    r,
  );
  assert.deepEqual(recorded.body, {
    name: "projects/demo-auth-account/tenants/<tenant:1:atb-man-min-*5>",
    users: [{ localId: "u", tenantId: "<tenant:a:atb-sel-a-*5>" }],
  });
  assert.deepEqual(r.tenants.ids().toSorted(), ["atb-man-min-abcde", "atb-sel-a-x7k2p"]);
});

test("a tenant id prefixing another is replaced as a whole", () => {
  const r = registries();
  r.tenants.label("atb-sel-a-x7k2p", "a");
  r.tenants.label("atb-sel-a-x7k2p2", "b");
  assert.deepEqual(r.tenants.replace("tenants/atb-sel-a-x7k2p2"), "tenants/<tenant:b:other>");
});

test("request values name tenants by label, by the step that created them and phones as keys", () => {
  const labels = new Map([["a", OURS]]);
  const raw = new Map([["create", { name: "projects/p/tenants/atb-man-min-abcde" }]]);
  assert.equal(tenantIdOf("projects/p/tenants/atb-x-12345"), "atb-x-12345");
  assert.equal(
    resolveTenants("v1/projects/{project}/tenants/TENANT(a)/accounts", labels, raw),
    `v1/projects/{project}/tenants/${OURS}/accounts`,
  );
  assert.equal(resolveTenants("TENANTOF(create)", labels, raw), "atb-man-min-abcde");
  assert.deepEqual(resolveTenants({ $phoneKeys: { "PHONE(0)": "123456" } }, labels, raw), {
    "+16505550101": "123456",
  });
  assert.throws(() => resolveTenants("TENANT(z)", labels, raw), /not created/);
  assert.throws(() => resolveTenants("TENANTOF(missing)", labels, raw), /recorded nothing/);
});

test("the corpus is valid and stays within the request cap", () => {
  const requests = validateTenantCorpus(PROGRAMS);
  assert.ok(requests > 100 && requests < 2000, `${requests}`);
  for (const program of PROGRAMS) assert.match(program.id, /^atb\/tenant\//);
});

test("the validator refuses unreviewed switches, foreign display names and waits", () => {
  const base = { id: "atb/tenant/x", steps: [{ id: "s", path: "v1/accounts:lookup", body: {} }] };
  assert.throws(
    () => validateTenantCorpus([{ ...base, config: { "multiTenant.allowTenants": true } }]),
    /not a program switch/,
  );
  assert.throws(
    () => validateTenantCorpus([{ ...base, tenants: { a: { displayName: "other" } } }]),
    /starts with atb-/,
  );
  assert.throws(
    () =>
      validateTenantCorpus([
        { ...base, steps: [{ id: "s", path: "v1/accounts:lookup", waitSeconds: 5 }] },
      ]),
    /do not wait/,
  );
  assert.throws(
    () =>
      validateTenantCorpus([
        {
          ...base,
          steps: [{ id: "s", path: "v1/accounts:lookup", body: { phoneNumber: "+1650" } }],
        },
      ]),
    /PHONE\(n\)/,
  );
});

// ---- pre-send review 2026-09-25 -------------------------------------------------------------

test("key material, client secrets and page tokens are masked and refused in a fixture (MF-2)", async () => {
  const { assertNoOpaqueValue } = await import("./auth-tenant-blocking/harness.mjs");
  const recorded = normalizeTenantResponse(
    200,
    JSON.stringify({
      hashConfig: { algorithm: "SCRYPT", signerKey: "c2VjcmV0", saltSeparator: "Bw==", rounds: 8 },
      clientSecret: "shh",
      nextPageToken: "atb-sel-a-x7k2p",
    }),
    production,
    registries(),
  );
  assert.deepEqual(recorded.body, {
    hashConfig: { algorithm: "SCRYPT", signerKey: "<bytes>", saltSeparator: "<bytes>", rounds: 8 },
    clientSecret: "<clientSecret>",
    nextPageToken: "<pageToken>",
  });
  assertNoOpaqueValue(JSON.stringify(recorded));
  assert.throws(() => assertNoOpaqueValue('{"signerKey": "c2VjcmV0"}'), /signerKey/);
  assert.throws(() => assertNoOpaqueValue('{"clientSecret":"x"}'), /clientSecret/);
});

test("a tenant-scoped SMS request names only that tenant's own test numbers (MF-3)", () => {
  const send = (body) => ({ id: "s", path: "v1/accounts:sendVerificationCode", auth: "key", body });
  const phones = new Map([[OURS, new Set(["+16505550102"])]]);
  guard(send({ phoneNumber: "+16505550102", tenantId: OURS }), { tenantPhones: phones });
  assert.throws(
    () => guard(send({ phoneNumber: "+16505550101", tenantId: OURS }), { tenantPhones: phones }),
    /not a test number of tenant/,
  );
  // The project's own test numbers stay allowed without a tenant.
  guard(send({ phoneNumber: "+16505550101" }), { tenantPhones: phones });
  // An enrollment names its tenant through the ID token.
  const token = (tenant) =>
    [
      Buffer.from('{"alg":"none"}').toString("base64url"),
      Buffer.from(JSON.stringify({ firebase: { tenant } })).toString("base64url"),
      "",
    ].join(".");
  const enroll = (tenant, phoneNumber) => ({
    id: "s",
    path: "v2/accounts/mfaEnrollment:start",
    auth: "key",
    body: { idToken: token(tenant), phoneEnrollmentInfo: { phoneNumber } },
  });
  guard(enroll(OURS, "+16505550102"), { tenantPhones: phones });
  assert.throws(
    () => guard(enroll(OURS, "+16505550103"), { tenantPhones: phones }),
    /not a test number/,
  );
});

test("the harness recognises its display names, and the corpus uses only them (MF-4)", async () => {
  const { isHarnessDisplayName, requestedDisplayNames } =
    await import("./auth-tenant-blocking/guard.mjs");
  for (const name of ["atb-sel-a", "atb", "atb_name", "Atb-Upper", "1atb-name", "1atb-bad"])
    assert.ok(isHarnessDisplayName(name), name);
  for (const name of ["fsr-tenant", "", undefined, "catb"]) assert.ok(!isHarnessDisplayName(name));
  const base = { id: "atb/tenant/x" };
  assert.throws(
    () =>
      validateTenantCorpus([
        {
          ...base,
          steps: [
            {
              id: "s",
              path: "v2/projects/{project}/tenants",
              method: "POST",
              body: { displayName: "other" },
            },
          ],
        },
      ]),
    /harness name/,
  );
  const manage = PROGRAMS.find(({ id }) => id === "atb/tenant/manage");
  assert.ok(requestedDisplayNames(manage).has("Atb-Upper"));
});

/**
 * A fake Identity Platform for the stop paths: the project config, tenants and an empty account
 * list. `createFails` answers a tenant create with 503 after creating it.
 */
function fakeSandbox({ tenants = [], createFails = false } = {}) {
  const state = { allowTenants: false, tenants: new Map(tenants.map((t) => [t.id, t])), seq: 0 };
  const json = (status, body) => new Response(JSON.stringify(body), { status });
  const fetchFake = async (url, init = {}) => {
    const { pathname } = new URL(url);
    const method = init.method ?? "GET";
    const body = typeof init.body === "string" ? JSON.parse(init.body) : {};
    if (pathname.endsWith("/accounts:batchGet")) return json(200, {});
    if (pathname.endsWith("/config")) {
      if (method === "PATCH") state.allowTenants = body.multiTenant?.allowTenants === true;
      return json(200, { multiTenant: state.allowTenants ? { allowTenants: true } : {} });
    }
    const tenant = /\/tenants\/([^/]+)$/.exec(pathname)?.[1];
    if (pathname.endsWith("/tenants") && method === "POST") {
      state.seq += 1;
      const id = `${body.displayName}-a${String(state.seq).padStart(4, "0")}`;
      state.tenants.set(id, { id, displayName: body.displayName });
      const answer = { name: `projects/fireemu-oracle-idp/tenants/${id}`, ...body };
      return createFails
        ? json(503, { error: { code: 503, message: "UNAVAILABLE" } })
        : json(200, answer);
    }
    if (pathname.endsWith("/tenants"))
      return json(200, {
        tenants: [...state.tenants.values()].map((t) => ({
          name: `projects/fireemu-oracle-idp/tenants/${t.id}`,
          displayName: t.displayName,
        })),
      });
    if (tenant && method === "DELETE")
      return state.tenants.delete(tenant) ? json(200, {}) : json(404, { error: { code: 404 } });
    return json(404, { error: { code: 404, message: "NOT_FOUND" } });
  };
  return { state, fetchFake };
}

async function withFetch(fetchFake, run) {
  const original = globalThis.fetch;
  globalThis.fetch = fetchFake;
  try {
    return await run();
  } finally {
    globalThis.fetch = original;
  }
}

test("a tenant a list names is never the program's to delete (MF-1)", async () => {
  const { createSession } = await import("./auth-tenant-blocking/session.mjs");
  const foreign = { id: "fsr-tenant-q1w2e", displayName: "fsr-tenant" };
  const { state, fetchFake } = fakeSandbox({ tenants: [foreign] });
  const program = {
    id: "atb/tenant/x",
    tenants: { a: { displayName: "atb-x-a" } },
    steps: [{ id: "list", path: "v2/projects/{project}/tenants", method: "GET", auth: "admin" }],
  };
  const session = createSession(production, { configSettleMs: 0 });
  const result = await withFetch(fetchFake, () => session.runProgram(program));
  assert.equal(result.steps.list.status, 200);
  assert.deepEqual([...state.tenants.keys()], [foreign.id]);
  assert.equal(state.allowTenants, false);
});

test("a harness tenant whose create answer was lost is deleted by its display name (SF-2)", async () => {
  const { createSession } = await import("./auth-tenant-blocking/session.mjs");
  const { state, fetchFake } = fakeSandbox({ createFails: true });
  const program = {
    id: "atb/tenant/x",
    tenants: { a: { displayName: "atb-x-a" } },
    steps: [{ id: "list", path: "v2/projects/{project}/tenants", method: "GET", auth: "admin" }],
  };
  const session = createSession(production, { configSettleMs: 0 });
  await assert.rejects(
    withFetch(fetchFake, () => session.runProgram(program)),
    /HTTP 503/,
  );
  assert.equal(state.tenants.size, 0);
  assert.equal(state.allowTenants, false);
});

test("a harness-named tenant that exists before a program stops it untouched (TB2 reading)", async () => {
  const { createSession } = await import("./auth-tenant-blocking/session.mjs");
  const leftover = { id: "atb-x-a-zzzzz", displayName: "atb-x-a" };
  const { state, fetchFake } = fakeSandbox({ tenants: [leftover] });
  const program = {
    id: "atb/tenant/x",
    tenants: { a: { displayName: "atb-x-a" } },
    steps: [{ id: "list", path: "v2/projects/{project}/tenants", method: "GET", auth: "admin" }],
  };
  const session = createSession(production, { configSettleMs: 0 });
  await assert.rejects(
    withFetch(fetchFake, () => session.runProgram(program)),
    /exist before it starts/,
  );
  assert.deepEqual([...state.tenants.keys()], [leftover.id]);
  assert.equal(state.allowTenants, false);
});

test("a blocking trigger's function URI is recorded as the kind of host it names", async () => {
  const { functionUriKind } = await import("./auth-tenant-blocking/harness.mjs");
  assert.equal(
    functionUriKind("https://atbbeforecreate-abc123-uc.a.run.app"),
    "<functionUri:run.app>",
  );
  assert.equal(
    functionUriKind("https://us-central1-fireemu-oracle-idp.cloudfunctions.net/atbBeforeCreate"),
    "<functionUri:cloudfunctions.net>",
  );
  assert.equal(functionUriKind("fireemu://functions/p/us-central1/x"), "<functionUri:fireemu>");
  const recorded = normalizeTenantResponse(
    200,
    JSON.stringify({
      blockingFunctions: {
        triggers: { beforeCreate: { functionUri: "https://x-1-uc.a.run.app" } },
      },
    }),
    production,
    registries(),
  );
  assert.equal(
    recorded.body.blockingFunctions.triggers.beforeCreate.functionUri,
    "<functionUri:run.app>",
  );
});
