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
