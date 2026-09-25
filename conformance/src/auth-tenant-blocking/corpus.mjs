// AUTH-TENANT-BLOCKING corpus, tenant half: one program per tenant recipe of
// spec/compatibility/closure/AUTH-TENANT-BLOCKING.json. Programs only record answers; they never
// assert. Each program runs on an empty project with multi-tenancy switched on for its own
// duration (owner decision TB2); the session creates the tenants a program names (display names
// start with `atb-`), deletes every tenant the program created or saw created, reads the list
// back and switches multi-tenancy off again.
//
// A request names a tenant as TENANT(label) (created by the harness) or TENANTOF(step) (created
// by a recorded step). Accounts are created through the Admin API where the row does not test
// creation itself, because production limits client account creation per IP. Phones are the
// sandbox's test numbers (M3), addresses @example.com (E1), and custom tokens are minted as the
// AUTH-CREDENTIAL harness mints them (the time-limited signJwt binding, coordinator decision
// 2026-09-25).

import { TEST_PHONE_CODE } from "../auth-account/harness.mjs";
import { MFA_CONFIGS } from "../auth-mfa/guard.mjs";
import { UNKNOWN_TENANT } from "./guard.mjs";

// ---- step builders -------------------------------------------------------------------------

const from = (reference) => ({ $from: reference });
const totp = (startStep, offset = 0) => ({ $totp: startStep, offset });

const client = (id, method, body, extra = {}) => ({
  id,
  path: `v1/accounts:${method}`,
  auth: "key",
  body,
  ...extra,
});
const clientV2 = (id, method, body, extra = {}) => ({
  id,
  path: `v2/accounts/${method}`,
  auth: "key",
  body,
  ...extra,
});
/** An Admin call on a tenant's accounts (`tenant` a label, or a literal id). */
const tenantAdmin = (id, tenant, method, body, extra = {}) => ({
  id,
  path: `v1/projects/{project}/tenants/${tenant}/accounts${method ? `:${method}` : ""}`,
  auth: "admin",
  body,
  ...extra,
});
const projectAdmin = (id, method, body, extra = {}) => ({
  id,
  path: `v1/projects/{project}/accounts${method ? `:${method}` : ""}`,
  auth: "admin",
  body,
  ...extra,
});
/** An Admin-created password account in a tenant (or the project with `tenant` null). */
const adminCreate = (id, tenant, name, extra = {}) => {
  const body = {
    localId: `UID(${name})`,
    email: `EMAIL(${name})`,
    password: "password123",
    emailVerified: true,
    ...extra,
  };
  return tenant === null ? projectAdmin(id, "", body) : tenantAdmin(id, tenant, "", body);
};

const T = (label) => `TENANT(${label})`;
const withTenant = (tenant, body) => (tenant === undefined ? body : { ...body, tenantId: tenant });

const signIn = (id, name, tenant, password = "password123", extra = {}) =>
  client(
    id,
    "signInWithPassword",
    withTenant(tenant, { email: `EMAIL(${name})`, password, returnSecureToken: true }),
    extra,
  );
const signUp = (id, name, tenant, password = "password123") =>
  client(
    id,
    "signUp",
    withTenant(tenant, { email: `EMAIL(${name})`, password, returnSecureToken: true }),
  );
const lookupWith = (id, tokenStep, tenant) =>
  client(id, "lookup", withTenant(tenant, { idToken: from(`${tokenStep}:idToken`) }));
const refreshWith = (id, tokenStep, extraForm = {}) => ({
  id,
  api: "securetoken",
  path: "v1/token",
  auth: "key",
  form: {
    grant_type: "refresh_token",
    refresh_token: from(`${tokenStep}:refreshToken`),
    ...extraForm,
  },
});

/** Tenant management (Admin v2). */
const tenantsPath = "v2/projects/{project}/tenants";
const createTenant = (id, body) => ({ id, path: tenantsPath, method: "POST", auth: "admin", body });
const getTenant = (id, tenant) => ({
  id,
  path: `${tenantsPath}/${tenant}`,
  method: "GET",
  auth: "admin",
});
const patchTenant = (id, tenant, body, mask) => ({
  id,
  path: `${tenantsPath}/${tenant}`,
  method: "PATCH",
  auth: "admin",
  body,
  ...(mask === undefined ? {} : { query: { updateMask: mask } }),
});
const deleteTenant = (id, tenant) => ({
  id,
  path: `${tenantsPath}/${tenant}`,
  method: "DELETE",
  auth: "admin",
});
const listTenants = (id, query = {}) => ({
  id,
  path: tenantsPath,
  method: "GET",
  auth: "admin",
  query,
});

const program = (id, steps, extra = {}) => ({ id, steps, ...extra });

const totpProvider = { state: "ENABLED", totpProviderConfig: { adjacentIntervals: 5 } };
/** A tenant with every first-factor method on. */
const openTenant = (displayName, extra = {}) => ({
  displayName,
  allowPasswordSignup: true,
  enableEmailLinkSignin: true,
  enableAnonymousUser: true,
  ...extra,
});

// ---- T1 tenant management --------------------------------------------------------------------

const manage = program("atb/tenant/manage", [
  createTenant("create-minimal", { displayName: "atb-man-min" }),
  getTenant("get-minimal", "TENANTOF(create-minimal)"),
  createTenant("create-open", openTenant("atb-man-open", { disableAuth: false })),
  getTenant("get-open", "TENANTOF(create-open)"),
  createTenant("create-mfa", {
    displayName: "atb-man-mfa",
    mfaConfig: {
      state: "ENABLED",
      enabledProviders: ["PHONE_SMS"],
      providerConfigs: [totpProvider],
    },
  }),
  getTenant("get-mfa", "TENANTOF(create-mfa)"),
  createTenant("create-phones", {
    displayName: "atb-man-phones",
    testPhoneNumbers: { $phoneKeys: { "PHONE(0)": TEST_PHONE_CODE } },
    smsRegionConfig: { allowByDefault: { disallowedRegions: [] } },
  }),
  getTenant("get-phones", "TENANTOF(create-phones)"),
  createTenant("create-policy", {
    displayName: "atb-man-policy",
    passwordPolicyConfig: {
      passwordPolicyEnforcementState: "ENFORCE",
      passwordPolicyVersions: [{ customStrengthOptions: { minPasswordLength: 8 } }],
    },
  }),
  getTenant("get-policy", "TENANTOF(create-policy)"),
  createTenant("create-settings", {
    displayName: "atb-man-set",
    autodeleteAnonymousUsers: true,
    client: { permissions: { disabledUserSignup: true, disabledUserDeletion: true } },
    emailPrivacyConfig: { enableImprovedEmailPrivacy: true },
    inheritance: { emailSendingConfig: true },
    monitoring: { requestLogging: { enabled: true } },
  }),
  getTenant("get-settings", "TENANTOF(create-settings)"),
  createTenant("create-unknown-field", { displayName: "atb-man-unk", notAField: true }),
  createTenant("create-bad-type", { displayName: "atb-man-type", allowPasswordSignup: "yes" }),
  createTenant("create-name-short", { displayName: "atb" }),
  createTenant("create-name-digit-first", { displayName: "1atb-name" }),
  createTenant("create-name-underscore", { displayName: "atb_name" }),
  createTenant("create-name-long", { displayName: "atb-abcdefghijklmnopq" }),
  createTenant("create-name-upper", { displayName: "Atb-Upper" }),
  createTenant("create-no-name", {}),
  listTenants("list-page-1", { pageSize: 2 }),
  listTenants("list-page-2", { pageSize: 2, pageToken: from("list-page-1:nextPageToken") }),
  listTenants("list-size-zero", { pageSize: 0 }),
  listTenants("list-size-negative", { pageSize: -1 }),
  listTenants("list-size-large", { pageSize: 1001 }),
  listTenants("list-bad-token", { pageToken: "not-a-token" }),
  patchTenant(
    "patch-name",
    "TENANTOF(create-minimal)",
    { displayName: "atb-man-min2" },
    "displayName",
  ),
  patchTenant("patch-no-mask", "TENANTOF(create-minimal)", { allowPasswordSignup: true }),
  patchTenant(
    "patch-unknown-mask",
    "TENANTOF(create-minimal)",
    { displayName: "atb-x" },
    "notAField",
  ),
  patchTenant(
    "patch-bad-type",
    "TENANTOF(create-minimal)",
    { allowPasswordSignup: "yes" },
    "allowPasswordSignup",
  ),
  patchTenant(
    "patch-bad-name",
    "TENANTOF(create-minimal)",
    { displayName: "1atb-bad" },
    "displayName",
  ),
  patchTenant(
    "patch-mfa",
    "TENANTOF(create-minimal)",
    { mfaConfig: { state: "ENABLED", providerConfigs: [totpProvider] } },
    "mfaConfig",
  ),
  patchTenant("patch-mask-omitted-value", "TENANTOF(create-open)", {}, "enableAnonymousUser"),
  getTenant("get-after-patch", "TENANTOF(create-minimal)"),
  getTenant("get-open-after-patch", "TENANTOF(create-open)"),
  getTenant("get-unknown", UNKNOWN_TENANT),
  patchTenant("patch-unknown", UNKNOWN_TENANT, { displayName: "atb-x" }, "displayName"),
  deleteTenant("delete-minimal", "TENANTOF(create-minimal)"),
  getTenant("get-deleted", "TENANTOF(create-minimal)"),
  deleteTenant("delete-again", "TENANTOF(create-minimal)"),
  deleteTenant("delete-unknown", UNKNOWN_TENANT),
]);

// ---- T2 multi-tenancy off ------------------------------------------------------------------

const switchOff = program(
  "atb/tenant/switch-off",
  [
    {
      id: "config-multi-tenant",
      path: "admin/v2/projects/{project}/config",
      method: "GET",
      auth: "admin",
      project: "multiTenant",
    },
    listTenants("list-off"),
    getTenant("get-unknown-off", UNKNOWN_TENANT),
    createTenant("create-off", { displayName: "atb-off" }),
    client("sign-up-unknown-tenant-off", "signUp", {
      email: "EMAIL(off1)",
      password: "password123",
      returnSecureToken: true,
      tenantId: UNKNOWN_TENANT,
    }),
    tenantAdmin("admin-lookup-unknown-tenant-off", UNKNOWN_TENANT, "lookup", {
      localId: ["UID(off1)"],
    }),
  ],
  { multiTenant: false },
);

// ---- T3 tenant selection -------------------------------------------------------------------

const selection = program(
  "atb/tenant/selection",
  [
    adminCreate("create-a1", T("a"), "a1"),
    signIn("sign-in-a1", "a1", T("a")),
    signIn("sign-in-a1-in-b", "a1", T("b")),
    signIn("sign-in-a1-no-tenant", "a1", undefined),
    signIn("sign-in-unknown-tenant", "a1", UNKNOWN_TENANT),
    signIn("sign-in-empty-tenant", "a1", ""),
    signIn("sign-in-number-tenant", "a1", 7),
    lookupWith("lookup-no-tenant", "sign-in-a1", undefined),
    lookupWith("lookup-tenant-a", "sign-in-a1", T("a")),
    lookupWith("lookup-tenant-b", "sign-in-a1", T("b")),
    lookupWith("lookup-unknown-tenant", "sign-in-a1", UNKNOWN_TENANT),
    client("update-tenant-b", "update", {
      idToken: from("sign-in-a1:idToken"),
      displayName: "Moved",
      tenantId: T("b"),
    }),
    tenantAdmin("admin-lookup-a1-after-update", T("a"), "lookup", { localId: ["UID(a1)"] }),
    refreshWith("refresh-a1", "sign-in-a1"),
    refreshWith("refresh-a1-tenant-b", "sign-in-a1", { tenantId: T("b") }),
    signUp("sign-up-a1-address-in-b", "a1", T("b")),
    tenantAdmin("admin-lookup-a1-in-b", T("b"), "lookup", { localId: ["UID(a1)"] }),
    tenantAdmin("admin-lookup-a1-email-in-b", T("b"), "lookup", { email: ["EMAIL(a1)"] }),
    projectAdmin("admin-lookup-a1-in-project", "lookup", { localId: ["UID(a1)"] }),
    projectAdmin("admin-lookup-a1-body-tenant", "lookup", {
      localId: ["UID(a1)"],
      tenantId: T("a"),
    }),
    tenantAdmin("admin-lookup-unknown-tenant", UNKNOWN_TENANT, "lookup", { localId: ["UID(a1)"] }),
    client("create-auth-uri-a", "createAuthUri", {
      identifier: "EMAIL(a1)",
      continueUri: "http://localhost",
      tenantId: T("a"),
    }),
    client("create-auth-uri-b", "createAuthUri", {
      identifier: "EMAIL(a1)",
      continueUri: "http://localhost",
      tenantId: T("b"),
    }),
  ],
  {
    tenants: { a: openTenant("atb-sel-a"), b: openTenant("atb-sel-b") },
  },
);

// ---- T3 custom tokens and tenants ------------------------------------------------------------

const customToken = program(
  "atb/tenant/custom-token",
  [
    client("custom-tenant-a-in-a", "signInWithCustomToken", {
      token: { $token: "tenantA" },
      returnSecureToken: true,
      tenantId: T("a"),
    }),
    client("custom-tenant-a-in-b", "signInWithCustomToken", {
      token: { $token: "tenantA" },
      returnSecureToken: true,
      tenantId: T("b"),
    }),
    client("custom-tenant-a-no-tenant", "signInWithCustomToken", {
      token: { $token: "tenantA" },
      returnSecureToken: true,
    }),
    client("custom-plain-in-a", "signInWithCustomToken", {
      token: { $token: "plain" },
      returnSecureToken: true,
      tenantId: T("a"),
    }),
    client("custom-plain-no-tenant", "signInWithCustomToken", {
      token: { $token: "plain" },
      returnSecureToken: true,
    }),
    client("custom-unknown-tenant-claim", "signInWithCustomToken", {
      token: { $token: "unknownTenant" },
      returnSecureToken: true,
    }),
    lookupWith("lookup-custom-a", "custom-tenant-a-in-a", T("a")),
    tenantAdmin("admin-lookup-custom-a", T("a"), "lookup", { localId: ["UID(ct1)"] }),
    projectAdmin("admin-lookup-custom-project", "lookup", { localId: ["UID(ct1)", "UID(ct2)"] }),
  ],
  {
    tenants: { a: openTenant("atb-ct-a"), b: openTenant("atb-ct-b") },
    tokens: {
      tenantA: { uid: "UID(ct1)", set: { tenant_id: T("a") } },
      plain: { uid: "UID(ct2)" },
      unknownTenant: { uid: "UID(ct3)", set: { tenant_id: UNKNOWN_TENANT } },
    },
  },
);

// ---- T4 credential isolation ---------------------------------------------------------------

const credentials = program(
  "atb/tenant/credentials",
  [
    adminCreate("create-a1", T("a"), "a1"),
    signIn("sign-in-a1", "a1", T("a")),
    client("delete-with-tenant-b", "delete", {
      idToken: from("sign-in-a1:idToken"),
      tenantId: T("b"),
    }),
    tenantAdmin("admin-lookup-after-delete-b", T("a"), "lookup", { localId: ["UID(a1)"] }),
    client("verify-mail-tenant-b", "sendOobCode", {
      requestType: "VERIFY_EMAIL",
      idToken: from("sign-in-a1:idToken"),
      tenantId: T("b"),
    }),
    {
      id: "cookie-in-b",
      path: `v1/projects/{project}/tenants/${T("b")}:createSessionCookie`,
      auth: "admin",
      body: { idToken: from("sign-in-a1:idToken"), validDuration: 3600 },
    },
    {
      id: "cookie-in-project",
      path: "v1/projects/{project}:createSessionCookie",
      auth: "admin",
      body: { idToken: from("sign-in-a1:idToken"), validDuration: 3600 },
    },
    {
      id: "cookie-in-a",
      path: `v1/projects/{project}/tenants/${T("a")}:createSessionCookie`,
      auth: "admin",
      body: { idToken: from("sign-in-a1:idToken"), validDuration: 3600 },
    },
    tenantAdmin("reset-code-a1", T("a"), "sendOobCode", {
      requestType: "PASSWORD_RESET",
      email: "EMAIL(a1)",
      returnOobLink: true,
    }),
    client("reset-check-in-b", "resetPassword", {
      oobCode: from("reset-code-a1:oobCode"),
      tenantId: T("b"),
    }),
    client("reset-check-no-tenant", "resetPassword", { oobCode: from("reset-code-a1:oobCode") }),
    client("reset-in-b", "resetPassword", {
      oobCode: from("reset-code-a1:oobCode"),
      newPassword: "password456",
      tenantId: T("b"),
    }),
    client("reset-in-a", "resetPassword", {
      oobCode: from("reset-code-a1:oobCode"),
      newPassword: "password456",
      tenantId: T("a"),
    }),
    signIn("sign-in-a1-new-password", "a1", T("a"), "password456"),
  ],
  { tenants: { a: openTenant("atb-cred-a"), b: openTenant("atb-cred-b") } },
);

// ---- T5 Admin accounts per tenant ------------------------------------------------------------

const adminAccounts = program(
  "atb/tenant/admin-accounts",
  [
    adminCreate("create-x-in-a", T("a"), "x"),
    adminCreate("create-x-in-b", T("b"), "x"),
    adminCreate("create-x-in-project", null, "x"),
    tenantAdmin("lookup-email-in-a", T("a"), "lookup", { email: ["EMAIL(x)"] }),
    tenantAdmin("lookup-email-in-b", T("b"), "lookup", { email: ["EMAIL(x)"] }),
    projectAdmin("lookup-email-in-project", "lookup", { email: ["EMAIL(x)"] }),
    tenantAdmin("query-in-a", T("a"), "query", { returnUserInfo: true }),
    projectAdmin("query-in-project", "query", { returnUserInfo: true }),
    tenantAdmin("batch-create-in-a", T("a"), "batchCreate", {
      users: [
        { localId: "UID(y)", email: "EMAIL(y)" },
        { localId: "UID(x)", email: "EMAIL(x2)" },
      ],
    }),
    {
      id: "batch-get-in-a",
      path: `v1/projects/{project}/tenants/${T("a")}/accounts:batchGet`,
      method: "GET",
      auth: "admin",
      query: { maxResults: 10 },
    },
    tenantAdmin("update-in-a", T("a"), "update", { localId: "UID(x)", displayName: "Tenant X" }),
    tenantAdmin("lookup-x-in-b-after-update", T("b"), "lookup", { localId: ["UID(x)"] }),
    tenantAdmin("delete-in-a", T("a"), "delete", { localId: "UID(x)" }),
    tenantAdmin("lookup-x-in-a-after-delete", T("a"), "lookup", { localId: ["UID(x)"] }),
    projectAdmin("lookup-x-in-project-after-delete", "lookup", { localId: ["UID(x)"] }),
    tenantAdmin("batch-delete-in-b", T("b"), "batchDelete", { localIds: ["UID(x)"], force: true }),
    tenantAdmin("lookup-x-in-b-after-batch-delete", T("b"), "lookup", { localId: ["UID(x)"] }),
    tenantAdmin("create-in-a-body-tenant-b", T("a"), "", {
      localId: "UID(z)",
      email: "EMAIL(z)",
      tenantId: T("b"),
    }),
  ],
  { tenants: { a: openTenant("atb-adm-a"), b: openTenant("atb-adm-b") } },
);

// ---- T6 tenant sign-in settings --------------------------------------------------------------

const S = T("s");
const settings = program(
  "atb/tenant/settings",
  [
    adminCreate("create-s1", S, "s1"),
    signIn("sign-in-s1", "s1", S),
    patchTenant("password-off", S, { allowPasswordSignup: false }, "allowPasswordSignup"),
    signIn("password-off-sign-in", "s1", S),
    signUp("password-off-sign-up", "s2", S),
    client("password-off-reset-mail", "sendOobCode", {
      requestType: "PASSWORD_RESET",
      email: "EMAIL(s1)",
      tenantId: S,
    }),
    client("password-off-update-password", "update", {
      idToken: from("sign-in-s1:idToken"),
      password: "password789",
      tenantId: S,
    }),
    patchTenant("password-on", S, { allowPasswordSignup: true }, "allowPasswordSignup"),
    patchTenant("link-off", S, { enableEmailLinkSignin: false }, "enableEmailLinkSignin"),
    client("link-off-mail", "sendOobCode", {
      requestType: "EMAIL_SIGNIN",
      email: "EMAIL(s1)",
      continueUrl: "https://{project}.firebaseapp.com/finish",
      canHandleCodeInApp: true,
      tenantId: S,
    }),
    patchTenant("anonymous-off", S, { enableAnonymousUser: false }, "enableAnonymousUser"),
    client("anonymous-off-sign-up", "signUp", { returnSecureToken: true, tenantId: S }),
    patchTenant("anonymous-on", S, { enableAnonymousUser: true }, "enableAnonymousUser"),
    client("anonymous-on-sign-up", "signUp", { returnSecureToken: true, tenantId: S }),
    patchTenant("auth-off", S, { disableAuth: true }, "disableAuth"),
    signIn("auth-off-sign-in", "s1", S),
    refreshWith("auth-off-refresh", "sign-in-s1"),
    lookupWith("auth-off-lookup", "sign-in-s1", S),
    tenantAdmin("auth-off-admin-lookup", S, "lookup", { localId: ["UID(s1)"] }),
    patchTenant("auth-on", S, { disableAuth: false }, "disableAuth"),
    patchTenant(
      "sign-up-off",
      S,
      { client: { permissions: { disabledUserSignup: true } } },
      "client.permissions.disabledUserSignup",
    ),
    signUp("sign-up-off-sign-up", "s3", S),
    patchTenant(
      "deletion-off",
      S,
      { client: { permissions: { disabledUserDeletion: true } } },
      "client.permissions.disabledUserDeletion",
    ),
    signIn("sign-in-s1-again", "s1", S),
    client("deletion-off-delete", "delete", {
      idToken: from("sign-in-s1-again:idToken"),
      tenantId: S,
    }),
    patchTenant(
      "privacy-off",
      S,
      { emailPrivacyConfig: { enableImprovedEmailPrivacy: false } },
      "emailPrivacyConfig.enableImprovedEmailPrivacy",
    ),
    signIn("privacy-off-wrong-password", "s1", S, "wrong-password"),
    signIn("privacy-off-unknown-address", "unknown-s", S),
    client("privacy-off-create-auth-uri", "createAuthUri", {
      identifier: "EMAIL(s1)",
      continueUri: "http://localhost",
      tenantId: S,
    }),
    patchTenant(
      "privacy-on",
      S,
      { emailPrivacyConfig: { enableImprovedEmailPrivacy: true } },
      "emailPrivacyConfig.enableImprovedEmailPrivacy",
    ),
    signIn("privacy-on-wrong-password", "s1", S, "wrong-password"),
    signIn("privacy-on-unknown-address", "unknown-s", S),
    patchTenant(
      "tenant-test-phone",
      S,
      { testPhoneNumbers: { $phoneKeys: { "PHONE(1)": "654321" } } },
      "testPhoneNumbers",
    ),
    client("phone-tenant-number", "sendVerificationCode", { phoneNumber: "PHONE(1)", tenantId: S }),
    client("phone-tenant-number-sign-in", "signInWithPhoneNumber", {
      sessionInfo: from("phone-tenant-number:sessionInfo"),
      code: "654321",
      tenantId: S,
    }),
    getTenant("get-s-at-end", S),
  ],
  {
    tenants: {
      s: openTenant("atb-set-s"),
    },
  },
);

// ---- T7 inheritance of project settings -------------------------------------------------------

const I = T("i");
const inheritance = program(
  "atb/tenant/inheritance",
  [
    getTenant("get-before", I),
    adminCreate("create-i1", I, "i1"),
    signIn("wrong-password-in-tenant", "i1", I, "wrong-password"),
    signIn("wrong-password-in-project", "p1", undefined, "wrong-password"),
    signUp("sign-up-in-tenant", "i2", I),
    signUp("sign-up-in-project", "p2", undefined),
    signIn("sign-in-i1", "i1", I),
    clientV2("phone-enroll-in-tenant", "mfaEnrollment:start", {
      idToken: from("sign-in-i1:idToken"),
      phoneEnrollmentInfo: { phoneNumber: "PHONE(2)" },
      tenantId: I,
    }),
    adminCreate("create-dup-in-tenant", I, "i3", { email: "EMAIL(i1)" }),
    createTenant("create-after", openTenant("atb-inh-late")),
    getTenant("get-after", "TENANTOF(create-after)"),
    signUp("sign-up-in-late-tenant", "l1", "TENANTOF(create-after)"),
    signIn("wrong-password-in-late-tenant", "l1", "TENANTOF(create-after)", "wrong-password"),
  ],
  {
    // The tenant's own test number (pre-send review MF-3): no SMS leaves production.
    tenants: {
      i: openTenant("atb-inh-i", {
        testPhoneNumbers: { $phoneKeys: { "PHONE(2)": TEST_PHONE_CODE } },
      }),
    },
    // Changed after the tenant was created (the session creates tenants first).
    config: {
      "emailPrivacyConfig.enableImprovedEmailPrivacy": false,
      "client.permissions.disabledUserSignup": true,
      "signIn.allowDuplicateEmails": true,
      mfa: MFA_CONFIGS.enabled,
    },
  },
);
// The project account whose wrong-password answer is the control.
inheritance.steps.splice(2, 0, adminCreate("create-p1", null, "p1"));

// ---- T8 tenant password policy ---------------------------------------------------------------

const P = T("p");
const passwordPolicy = program(
  "atb/tenant/password-policy",
  [
    {
      id: "policy-tenant-p",
      path: "v2/passwordPolicy",
      method: "GET",
      auth: "key",
      query: { tenantId: P },
    },
    {
      id: "policy-tenant-q",
      path: "v2/passwordPolicy",
      method: "GET",
      auth: "key",
      query: { tenantId: T("q") },
    },
    { id: "policy-project", path: "v2/passwordPolicy", method: "GET", auth: "key" },
    {
      id: "policy-unknown-tenant",
      path: "v2/passwordPolicy",
      method: "GET",
      auth: "key",
      query: { tenantId: UNKNOWN_TENANT },
    },
    signUp("sign-up-short-in-p", "p1", P, "short1"),
    signUp("sign-up-long-in-p", "p1", P, "longer-password"),
    signUp("sign-up-short-in-q", "q1", T("q"), "short1"),
    client("update-short-in-p", "update", {
      idToken: from("sign-up-long-in-p:idToken"),
      password: "short2",
      tenantId: P,
    }),
    adminCreate("admin-create-short-in-p", P, "p2", { password: "short3" }),
    tenantAdmin("reset-code-p1", P, "sendOobCode", {
      requestType: "PASSWORD_RESET",
      email: "EMAIL(p1)",
      returnOobLink: true,
    }),
    client("reset-short-in-p", "resetPassword", {
      oobCode: from("reset-code-p1:oobCode"),
      newPassword: "short4",
      tenantId: P,
    }),
    signIn("sign-in-p1", "p1", P, "longer-password"),
  ],
  {
    tenants: {
      p: openTenant("atb-pol-p", {
        passwordPolicyConfig: {
          passwordPolicyEnforcementState: "ENFORCE",
          passwordPolicyVersions: [{ customStrengthOptions: { minPasswordLength: 8 } }],
        },
      }),
      q: openTenant("atb-pol-q"),
    },
  },
);

// ---- T9 tenant MFA (M2) ----------------------------------------------------------------------

const M = T("m");
const N = T("n");
const tenantMfa = program(
  "atb/tenant/mfa",
  [
    adminCreate("create-m1", M, "m1"),
    signIn("sign-in-m1", "m1", M),
    clientV2("phone-start-m1", "mfaEnrollment:start", {
      idToken: from("sign-in-m1:idToken"),
      phoneEnrollmentInfo: { phoneNumber: "PHONE(0)" },
      tenantId: M,
    }),
    clientV2("phone-finalize-m1", "mfaEnrollment:finalize", {
      idToken: from("sign-in-m1:idToken"),
      phoneVerificationInfo: {
        sessionInfo: from("phone-start-m1:phoneSessionInfo.sessionInfo"),
        code: TEST_PHONE_CODE,
      },
      displayName: "Phone",
      tenantId: M,
    }),
    signIn("second-factor-m1", "m1", M),
    clientV2("sms-start-m1", "mfaSignIn:start", {
      mfaPendingCredential: from("second-factor-m1:mfaPendingCredential"),
      mfaEnrollmentId: from("second-factor-m1:mfaInfo.0.mfaEnrollmentId"),
      phoneSignInInfo: {},
      tenantId: M,
    }),
    clientV2("sms-finalize-m1-in-n", "mfaSignIn:finalize", {
      mfaPendingCredential: from("second-factor-m1:mfaPendingCredential"),
      mfaEnrollmentId: from("second-factor-m1:mfaInfo.0.mfaEnrollmentId"),
      phoneVerificationInfo: {
        sessionInfo: from("sms-start-m1:phoneResponseInfo.sessionInfo"),
        code: TEST_PHONE_CODE,
      },
      tenantId: N,
    }),
    clientV2("sms-finalize-m1", "mfaSignIn:finalize", {
      mfaPendingCredential: from("second-factor-m1:mfaPendingCredential"),
      mfaEnrollmentId: from("second-factor-m1:mfaInfo.0.mfaEnrollmentId"),
      phoneVerificationInfo: {
        sessionInfo: from("sms-start-m1:phoneResponseInfo.sessionInfo"),
        code: TEST_PHONE_CODE,
      },
      tenantId: M,
    }),
    lookupWith("lookup-m1-second-factor", "sms-finalize-m1", M),
    clientV2("totp-start-m1", "mfaEnrollment:start", {
      idToken: from("sms-finalize-m1:idToken"),
      totpEnrollmentInfo: {},
      tenantId: M,
    }),
    clientV2("totp-finalize-m1", "mfaEnrollment:finalize", {
      idToken: from("sms-finalize-m1:idToken"),
      totpVerificationInfo: {
        sessionInfo: from("totp-start-m1:totpSessionInfo.sessionInfo"),
        verificationCode: totp("totp-start-m1"),
      },
      displayName: "Authenticator",
      tenantId: M,
    }),
    adminCreate("create-n1", N, "n1"),
    signIn("sign-in-n1", "n1", N),
    clientV2("phone-start-n1", "mfaEnrollment:start", {
      idToken: from("sign-in-n1:idToken"),
      phoneEnrollmentInfo: { phoneNumber: "PHONE(1)" },
      tenantId: N,
    }),
    clientV2("totp-start-n1", "mfaEnrollment:start", {
      idToken: from("sign-in-n1:idToken"),
      totpEnrollmentInfo: {},
      tenantId: N,
    }),
    tenantAdmin("admin-factor-n1", N, "update", {
      localId: "UID(n1)",
      mfa: { enrollments: [{ phoneInfo: "PHONE(1)", displayName: "Phone" }] },
    }),
    signIn("sign-in-n1-with-factor", "n1", N),
    patchTenant("tenant-m-mfa-off", M, { mfaConfig: { state: "DISABLED" } }, "mfaConfig"),
    signIn("sign-in-m1-mfa-off", "m1", M),
    getTenant("get-m-at-end", M),
    getTenant("get-n-at-end", N),
  ],
  {
    tenants: {
      m: openTenant("atb-mfa-m", {
        mfaConfig: {
          state: "ENABLED",
          enabledProviders: ["PHONE_SMS"],
          providerConfigs: [totpProvider],
        },
        testPhoneNumbers: { $phoneKeys: { "PHONE(0)": TEST_PHONE_CODE } },
      }),
      n: openTenant("atb-mfa-n", {
        testPhoneNumbers: { $phoneKeys: { "PHONE(1)": TEST_PHONE_CODE } },
      }),
    },
  },
);

// ---- T10 tenant deletion ---------------------------------------------------------------------

const D = T("d");
const deletion = program(
  "atb/tenant/deletion",
  [
    adminCreate("create-d1", D, "d1"),
    signIn("sign-in-d1", "d1", D),
    tenantAdmin("reset-code-d1", D, "sendOobCode", {
      requestType: "PASSWORD_RESET",
      email: "EMAIL(d1)",
      returnOobLink: true,
    }),
    deleteTenant("delete-d", D),
    lookupWith("lookup-after-delete", "sign-in-d1", D),
    lookupWith("lookup-after-delete-no-tenant", "sign-in-d1", undefined),
    refreshWith("refresh-after-delete", "sign-in-d1"),
    tenantAdmin("admin-lookup-after-delete", D, "lookup", { localId: ["UID(d1)"] }),
    signIn("sign-in-after-delete", "d1", D),
    client("reset-after-delete", "resetPassword", {
      oobCode: from("reset-code-d1:oobCode"),
      tenantId: D,
    }),
    createTenant("recreate-same-name", openTenant("atb-del-d")),
    getTenant("get-recreated", "TENANTOF(recreate-same-name)"),
    tenantAdmin("admin-lookup-in-recreated", "TENANTOF(recreate-same-name)", "lookup", {
      localId: ["UID(d1)"],
    }),
  ],
  { tenants: { d: openTenant("atb-del-d") } },
);

// ---- T11 action codes in tenants (AUTH-ACTION E4) ---------------------------------------------

const A = T("a");
const actions = program(
  "atb/tenant/actions",
  [
    adminCreate("create-a1", A, "a1", { emailVerified: false }),
    tenantAdmin("verify-code-a1", A, "sendOobCode", {
      requestType: "VERIFY_EMAIL",
      email: "EMAIL(a1)",
      returnOobLink: true,
    }),
    client("verify-in-b", "update", { oobCode: from("verify-code-a1:oobCode"), tenantId: T("b") }),
    client("verify-no-tenant", "update", { oobCode: from("verify-code-a1:oobCode") }),
    client("verify-in-a", "update", { oobCode: from("verify-code-a1:oobCode"), tenantId: A }),
    tenantAdmin("lookup-a1-verified", A, "lookup", { localId: ["UID(a1)"] }),
    tenantAdmin("link-code-a1", A, "sendOobCode", {
      requestType: "EMAIL_SIGNIN",
      email: "EMAIL(a1)",
      returnOobLink: true,
    }),
    client("link-in-b", "signInWithEmailLink", {
      email: "EMAIL(a1)",
      oobCode: from("link-code-a1:oobCode"),
      tenantId: T("b"),
    }),
    client("link-no-tenant", "signInWithEmailLink", {
      email: "EMAIL(a1)",
      oobCode: from("link-code-a1:oobCode"),
    }),
    client("link-in-a", "signInWithEmailLink", {
      email: "EMAIL(a1)",
      oobCode: from("link-code-a1:oobCode"),
      tenantId: A,
    }),
    client("client-reset-mail-a", "sendOobCode", {
      requestType: "PASSWORD_RESET",
      email: "EMAIL(a1)",
      tenantId: A,
    }),
    client("client-reset-mail-unknown-tenant", "sendOobCode", {
      requestType: "PASSWORD_RESET",
      email: "EMAIL(a1)",
      tenantId: UNKNOWN_TENANT,
    }),
    client("client-verify-mail-a", "sendOobCode", {
      requestType: "VERIFY_EMAIL",
      idToken: from("link-in-a:idToken"),
      tenantId: A,
    }),
    projectAdmin("project-code-for-tenant-user", "sendOobCode", {
      requestType: "PASSWORD_RESET",
      email: "EMAIL(a1)",
      returnOobLink: true,
    }),
  ],
  { tenants: { a: openTenant("atb-act-a"), b: openTenant("atb-act-b") } },
);

// ---- T12 provider isolation ------------------------------------------------------------------

const providerPath = (tenant) =>
  tenant === null
    ? "v2/projects/{project}/oauthIdpConfigs"
    : `v2/projects/{project}/tenants/${tenant}/oauthIdpConfigs`;
const providers = program(
  "atb/tenant/providers",
  [
    {
      id: "create-oidc-in-a",
      path: providerPath(T("a")),
      method: "POST",
      auth: "admin",
      query: { oauthIdpConfigId: "oidc.atb-a" },
      body: {
        displayName: "atb provider",
        enabled: true,
        clientId: "atb-client",
        issuer: "https://accounts.google.com",
        responseType: { idToken: true },
      },
    },
    { id: "list-in-a", path: providerPath(T("a")), method: "GET", auth: "admin" },
    { id: "list-in-b", path: providerPath(T("b")), method: "GET", auth: "admin" },
    { id: "list-in-project", path: providerPath(null), method: "GET", auth: "admin" },
    { id: "get-in-a", path: `${providerPath(T("a"))}/oidc.atb-a`, method: "GET", auth: "admin" },
    { id: "get-in-b", path: `${providerPath(T("b"))}/oidc.atb-a`, method: "GET", auth: "admin" },
    {
      id: "get-in-project",
      path: `${providerPath(null)}/oidc.atb-a`,
      method: "GET",
      auth: "admin",
    },
    client("auth-uri-a", "createAuthUri", {
      providerId: "oidc.atb-a",
      continueUri: "http://localhost",
      tenantId: T("a"),
    }),
    client("auth-uri-b", "createAuthUri", {
      providerId: "oidc.atb-a",
      continueUri: "http://localhost",
      tenantId: T("b"),
    }),
    {
      id: "delete-in-b",
      path: `${providerPath(T("b"))}/oidc.atb-a`,
      method: "DELETE",
      auth: "admin",
    },
    {
      id: "delete-in-a",
      path: `${providerPath(T("a"))}/oidc.atb-a`,
      method: "DELETE",
      auth: "admin",
    },
    {
      id: "get-in-a-after-delete",
      path: `${providerPath(T("a"))}/oidc.atb-a`,
      method: "GET",
      auth: "admin",
    },
  ],
  { tenants: { a: openTenant("atb-prov-a"), b: openTenant("atb-prov-b") } },
);

/** Every tenant program, in recording order. */
export const PROGRAMS = [
  switchOff,
  manage,
  selection,
  customToken,
  credentials,
  adminAccounts,
  settings,
  inheritance,
  passwordPolicy,
  tenantMfa,
  deletion,
  actions,
  providers,
];
