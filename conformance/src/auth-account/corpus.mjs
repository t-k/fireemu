// AUTH-ACCOUNT corpus: one program per recipe of spec/compatibility/closure/AUTH-ACCOUNT.json.
// Programs only record answers; they never assert. Each program runs on an empty project (the
// session wipes before and after) and uses run-unique EMAIL(...)/UID(...) values.

import { TEST_PHONES, TEST_PHONE_CODE } from "./harness.mjs";

/** Sign-in configuration both sides run under; production already has it (see sandbox doc). */
export const BASELINE_CONFIG = {
  "signIn.email.enabled": true,
  "signIn.email.passwordRequired": true,
  "signIn.anonymous.enabled": true,
  "signIn.phoneNumber.enabled": true,
  "signIn.phoneNumber.testPhoneNumbers": Object.fromEntries(
    TEST_PHONES.map((p) => [p, TEST_PHONE_CODE]),
  ),
};

// ---- step builders -------------------------------------------------------------------------

const from = (step, path) => ({ $from: step, path });
const client = (id, method, body, extra = {}) => ({
  id,
  path: `v1/accounts:${method}`,
  auth: "key",
  body,
  ...extra,
});
const adminCall = (id, method, body, extra = {}) => ({
  id,
  path: `v1/projects/{project}/accounts:${method}`,
  auth: "admin",
  body,
  ...extra,
});
const adminCreate = (id, body) => ({
  id,
  path: "v1/projects/{project}/accounts",
  auth: "admin",
  body,
});
const signUp = (id, name, password = "password123") =>
  client(id, "signUp", { email: `EMAIL(${name})`, password, returnSecureToken: true });
const signIn = (id, email, password = "password123") =>
  client(id, "signInWithPassword", { email, password, returnSecureToken: true });
const lookupToken = (id, step) => client(id, "lookup", { idToken: from(step, "idToken") });
const refresh = (id, step, path = "refreshToken") => ({
  id,
  api: "securetoken",
  path: "v1/token",
  auth: "key",
  form: { grant_type: "refresh_token", refresh_token: from(step, path) },
});
const adminLookup = (id, localId) => adminCall(id, "lookup", { localId: [localId] });
const tampered = (step) => ({ $concat: [from(step, "idToken"), "x"] });

const program = (id, steps, extra = {}) => ({ id, steps, ...extra });

// ---- #1-#10: behaviours with historical fireemu-35fe6 evidence, re-recorded here -----------

const clientLifecycle = program("auth-account/client/lifecycle", [
  signUp("sign-up", "primary"),
  signIn("sign-in", "EMAIL(primary)"),
  signIn("wrong-password", "EMAIL(primary)", "wrong-password"),
  signIn("unknown-email", "EMAIL(nobody)"),
  lookupToken("lookup", "sign-in"),
  refresh("refresh", "sign-in"),
  client("delete", "delete", { idToken: from("sign-in", "idToken") }),
  signIn("sign-in-after-delete", "EMAIL(primary)"),
  lookupToken("lookup-after-delete", "sign-in"),
  refresh("refresh-after-delete", "sign-in"),
]);

const clientProfile = program("auth-account/client/profile", [
  signUp("sign-up", "profile"),
  client("set-name-and-photo", "update", {
    idToken: from("sign-up", "idToken"),
    displayName: "Probe User",
    photoUrl: "https://example.com/a.png",
    returnSecureToken: true,
  }),
  lookupToken("lookup-after-set", "sign-up"),
  client("replace-name-and-photo", "update", {
    idToken: from("sign-up", "idToken"),
    displayName: "Second Name",
    photoUrl: "https://example.com/b.png",
    returnSecureToken: false,
  }),
  lookupToken("lookup-after-replace", "sign-up"),
  client("delete-display-name", "update", {
    idToken: from("sign-up", "idToken"),
    deleteAttribute: ["DISPLAY_NAME"],
  }),
  lookupToken("lookup-after-delete-name", "sign-up"),
  client("delete-photo-url", "update", {
    idToken: from("sign-up", "idToken"),
    deleteAttribute: ["PHOTO_URL"],
  }),
  lookupToken("lookup-after-delete-photo", "sign-up"),
  client("update-with-invalid-token", "update", { idToken: "not-a-jwt", displayName: "Nope" }),
  lookupToken("lookup-after-refusal", "sign-up"),
]);

const clientPasswordChange = program("auth-account/client/password-change", [
  signUp("sign-up", "pwchange"),
  client("change-password", "update", {
    idToken: from("sign-up", "idToken"),
    password: "new-password-456",
    returnSecureToken: true,
  }),
  signIn("sign-in-old-password", "EMAIL(pwchange)"),
  signIn("sign-in-new-password", "EMAIL(pwchange)", "new-password-456"),
  lookupToken("lookup-with-pre-change-token", "sign-up"),
  refresh("refresh-pre-change-token", "sign-up"),
  lookupToken("lookup-with-post-change-token", "change-password"),
]);

const clientValidation = program("auth-account/client/validation", [
  client("invalid-email", "signUp", {
    email: "not-an-email",
    password: "password123",
    returnSecureToken: true,
  }),
  client("weak-password", "signUp", {
    email: "EMAIL(weak)",
    password: "123",
    returnSecureToken: true,
  }),
  client("missing-password", "signUp", { email: "EMAIL(nopass)", returnSecureToken: true }),
  client("empty-email", "signUp", { email: "", password: "password123", returnSecureToken: true }),
  client("sign-in-missing-email", "signInWithPassword", {
    password: "password123",
    returnSecureToken: true,
  }),
  client("sign-in-missing-password", "signInWithPassword", {
    email: "EMAIL(weak)",
    returnSecureToken: true,
  }),
  client("sign-in-invalid-email", "signInWithPassword", {
    email: "not-an-email",
    password: "password123",
    returnSecureToken: true,
  }),
]);

const clientAnonymous = program("auth-account/client/anonymous", [
  client("anonymous-sign-up", "signUp", { returnSecureToken: true }),
  lookupToken("lookup", "anonymous-sign-up"),
  refresh("refresh", "anonymous-sign-up"),
  client("delete", "delete", { idToken: from("anonymous-sign-up", "idToken") }),
  lookupToken("lookup-after-delete", "anonymous-sign-up"),
]);

const clientEmailCase = program("auth-account/client/email-case", [
  client("mixed-case-sign-up", "signUp", {
    email: "EMAILMIXED(case)",
    password: "password123",
    returnSecureToken: true,
  }),
  lookupToken("lookup", "mixed-case-sign-up"),
  signIn("lowercase-sign-in", "EMAIL(case)"),
  signIn("mixed-case-sign-in", "EMAILMIXED(case)"),
  client("lowercase-duplicate", "signUp", {
    email: "EMAIL(case)",
    password: "password456",
    returnSecureToken: true,
  }),
  client("exact-duplicate", "signUp", {
    email: "EMAILMIXED(case)",
    password: "password456",
    returnSecureToken: true,
  }),
]);

const adminDisable = program("auth-account/admin/disable", [
  adminCreate("create", {
    localId: "UID(target)",
    email: "EMAIL(target)",
    password: "password123",
  }),
  adminCreate("create-control", {
    localId: "UID(control)",
    email: "EMAIL(control)",
    password: "password123",
  }),
  signIn("sign-in-before", "EMAIL(target)"),
  adminCall("disable", "update", { localId: "UID(target)", disableUser: true }),
  signIn("sign-in-while-disabled", "EMAIL(target)"),
  lookupToken("id-token-while-disabled", "sign-in-before"),
  refresh("refresh-while-disabled", "sign-in-before"),
  adminLookup("admin-lookup-while-disabled", "UID(target)"),
  adminCall("admin-password-while-disabled", "update", {
    localId: "UID(target)",
    password: "password789",
  }),
  adminCall("admin-photo-while-disabled", "update", {
    localId: "UID(target)",
    photoUrl: "https://example.com/c.png",
  }),
  adminCall("re-enable", "update", { localId: "UID(target)", disableUser: false }),
  refresh("refresh-after-re-enable", "sign-in-before"),
  signIn("sign-in-old-password-after-re-enable", "EMAIL(target)"),
  signIn("sign-in-new-password-after-re-enable", "EMAIL(target)", "password789"),
  signIn("control-sign-in", "EMAIL(control)"),
  adminLookup("admin-lookup-after", "UID(target)"),
]);

const clientDeleteEffects = program("auth-account/client/delete-effects", [
  signUp("sign-up", "cdel"),
  client("delete", "delete", { idToken: from("sign-up", "idToken") }),
  signIn("sign-in", "EMAIL(cdel)"),
  lookupToken("old-id-token", "sign-up"),
  refresh("old-refresh-token", "sign-up"),
  client("delete-again", "delete", { idToken: from("sign-up", "idToken") }),
]);

const adminDeleteEffects = program("auth-account/admin/delete-effects", [
  adminCreate("create", { localId: "UID(adel)", email: "EMAIL(adel)", password: "password123" }),
  signIn("sign-in-before", "EMAIL(adel)"),
  adminCall("admin-delete", "delete", { localId: "UID(adel)" }),
  signIn("sign-in-after", "EMAIL(adel)"),
  lookupToken("old-id-token", "sign-in-before"),
  refresh("old-refresh-token", "sign-in-before"),
  adminLookup("admin-lookup", "UID(adel)"),
]);

const astral = "\u{1F600}";
const defaultPolicyClientUpdate = program("auth-account/policy/default/client-update", [
  signUp("sign-up", "policy"),
  ...[
    ["min-6", { $repeat: "a", count: 6 }],
    ["min-5", { $repeat: "a", count: 5 }],
    ["max-4096", { $repeat: "a", count: 4096 }],
    ["max-4097", { $repeat: "a", count: 4097 }],
    ["astral-3-code-points", { $repeat: astral, count: 3 }],
    ["astral-2048-code-points", { $repeat: astral, count: 2048 }],
    ["astral-2048-plus-bmp", { $concat: [{ $repeat: astral, count: 2048 }, "a"] }],
    ["astral-2049-code-points", { $repeat: astral, count: 2049 }],
    ["bmp-4096", { $repeat: "é", count: 4096 }],
    ["bmp-4097", { $repeat: "é", count: 4097 }],
  ].map(([id, password]) =>
    client(`update-${id}`, "update", {
      idToken: from("sign-up", "idToken"),
      password,
      returnSecureToken: false,
    }),
  ),
  signIn("sign-in-with-last-accepted", "EMAIL(policy)", { $repeat: "é", count: 4096 }),
]);

const tamperedToken = program("auth-account/privilege/tampered-token", [
  signUp("sign-up", "tamper"),
  client("tampered-token-with-custom-attributes", "update", {
    idToken: tampered("sign-up"),
    customAttributes: JSON.stringify({ role: "admin" }),
  }),
  client("tampered-token-with-display-name", "update", {
    idToken: tampered("sign-up"),
    displayName: "Nope",
  }),
  lookupToken("lookup-after", "sign-up"),
]);

// ---- #11-#21, #25: Admin and client account operations without production evidence --------

const anonymousUpgrade = program("auth-account/client/anonymous-upgrade", [
  client("anonymous-a", "signUp", { returnSecureToken: true }),
  client("upgrade-with-sign-up", "signUp", {
    idToken: from("anonymous-a", "idToken"),
    email: "EMAIL(upgrade-a)",
    password: "password123",
    returnSecureToken: true,
  }),
  lookupToken("lookup-after-sign-up-upgrade", "upgrade-with-sign-up"),
  signIn("sign-in-upgraded", "EMAIL(upgrade-a)"),
  client("anonymous-b", "signUp", { returnSecureToken: true }),
  client("upgrade-with-update", "update", {
    idToken: from("anonymous-b", "idToken"),
    email: "EMAIL(upgrade-b)",
    password: "password123",
    returnSecureToken: true,
  }),
  lookupToken("lookup-after-update-upgrade", "anonymous-b"),
  client("anonymous-c", "signUp", { returnSecureToken: true }),
  client("upgrade-to-taken-email", "signUp", {
    idToken: from("anonymous-c", "idToken"),
    email: "EMAIL(upgrade-a)",
    password: "password123",
    returnSecureToken: true,
  }),
  lookupToken("lookup-after-collision", "anonymous-c"),
]);

const clientEmailChange = program("auth-account/client/email-change", [
  signUp("sign-up", "change-old"),
  signUp("other", "change-taken"),
  client("change-email", "update", {
    idToken: from("sign-up", "idToken"),
    email: "EMAIL(change-new)",
    returnSecureToken: true,
  }),
  lookupToken("lookup-with-original-token", "sign-up"),
  signIn("sign-in-new-address", "EMAIL(change-new)"),
  signIn("sign-in-old-address", "EMAIL(change-old)"),
  client("change-to-taken", "update", {
    idToken: from("sign-up", "idToken"),
    email: "EMAIL(change-taken)",
    returnSecureToken: true,
  }),
  client("change-to-invalid", "update", {
    idToken: from("sign-up", "idToken"),
    email: "not-an-email",
    returnSecureToken: true,
  }),
  adminCall("admin-lookup", "lookup", { email: ["EMAIL(change-old)", "EMAIL(change-new)"] }),
]);

const adminCreateProgram = program("auth-account/admin/create", [
  adminCreate("every-field", {
    localId: "UID(full)",
    email: "EMAIL(full)",
    emailVerified: true,
    phoneNumber: "PHONE(0)",
    password: "password123",
    displayName: "Full User",
    photoUrl: "https://example.com/full.png",
    disabled: false,
  }),
  adminLookup("lookup-every-field", "UID(full)"),
  adminCreate("generated-local-id", { email: "EMAIL(generated)" }),
  adminCreate("empty-body", {}),
  adminCreate("duplicate-local-id", { localId: "UID(full)", email: "EMAIL(other)" }),
  adminCreate("duplicate-email", { localId: "UID(dup-email)", email: "EMAIL(full)" }),
  adminCreate("duplicate-phone", { localId: "UID(dup-phone)", phoneNumber: "PHONE(0)" }),
  adminCreate("local-id-128", { localId: { $repeat: "a", count: 128 } }),
  adminCreate("local-id-129", { localId: { $repeat: "b", count: 129 } }),
  adminCreate("local-id-slash", { localId: "UID(a)/b" }),
  adminCreate("phone-not-e164", { localId: "UID(bad-phone)", phoneNumber: "6505550101" }),
  adminCreate("malformed-email", { localId: "UID(bad-email)", email: "not-an-email" }),
  adminCreate("malformed-photo-url", { localId: "UID(bad-photo)", photoUrl: "not a url" }),
  adminCreate("short-password", { localId: "UID(short)", password: "12345" }),
  adminCall("lookup-refused-ids", "lookup", {
    localId: [
      "UID(dup-email)",
      "UID(dup-phone)",
      "UID(bad-phone)",
      "UID(bad-email)",
      "UID(bad-photo)",
      "UID(short)",
    ],
  }),
  signIn("sign-in-created", "EMAIL(full)"),
]);

const adminLookupProgram = program("auth-account/admin/lookup", [
  adminCreate("create-a", { localId: "UID(la)", email: "EMAIL(la)", phoneNumber: "PHONE(1)" }),
  adminCreate("create-b", { localId: "UID(lb)", email: "EMAIL(lb)" }),
  adminCall("by-local-id", "lookup", { localId: ["UID(la)"] }),
  adminCall("by-email", "lookup", { email: ["EMAIL(lb)"] }),
  adminCall("by-email-mixed-case", "lookup", { email: ["EMAILMIXED(lb)"] }),
  adminCall("by-phone", "lookup", { phoneNumber: ["PHONE(1)"] }),
  adminCall("mixed-selectors", "lookup", {
    localId: ["UID(la)"],
    email: ["EMAIL(lb)"],
    phoneNumber: ["PHONE(1)"],
  }),
  adminCall("unknown-ids", "lookup", { localId: ["UID(nobody)"], email: ["EMAIL(nobody)"] }),
  adminCall("duplicate-ids", "lookup", { localId: ["UID(la)", "UID(la)"] }),
  adminCall("empty-arrays", "lookup", { localId: [] }),
  adminCall("no-selector", "lookup", {}),
  adminCall("federated-unknown", "lookup", {
    federatedUserId: [{ providerId: "google.com", rawId: "no-such-raw-id" }],
  }),
  adminCall("initial-email", "lookup", { initialEmail: ["EMAIL(la)"] }),
  adminCall("over-100-ids", "lookup", {
    localId: Array.from({ length: 101 }, (_, i) => `UID(many-${i})`),
  }),
]);

const adminUpdate = program("auth-account/admin/update", [
  adminCreate("create", {
    localId: "UID(up)",
    email: "EMAIL(up)",
    password: "password123",
    displayName: "Before",
    photoUrl: "https://example.com/before.png",
  }),
  adminCreate("create-other", {
    localId: "UID(up-other)",
    email: "EMAIL(up-other)",
    phoneNumber: "PHONE(2)",
  }),
  adminCall("email-verified", "update", { localId: "UID(up)", emailVerified: true }),
  adminCall("change-email", "update", { localId: "UID(up)", email: "EMAIL(up-new)" }),
  adminCall("change-email-taken", "update", { localId: "UID(up)", email: "EMAIL(up-other)" }),
  adminCall("set-phone", "update", { localId: "UID(up)", phoneNumber: "PHONE(3)" }),
  adminCall("set-phone-taken", "update", { localId: "UID(up)", phoneNumber: "PHONE(2)" }),
  adminLookup("lookup-after-sets", "UID(up)"),
  adminCall("delete-provider-phone", "update", { localId: "UID(up)", deleteProvider: ["phone"] }),
  adminCall("delete-display-name", "update", {
    localId: "UID(up)",
    deleteAttribute: ["DISPLAY_NAME"],
  }),
  adminCall("delete-photo-url", "update", { localId: "UID(up)", deleteAttribute: ["PHOTO_URL"] }),
  adminLookup("lookup-after-deletes", "UID(up)"),
  adminCall("delete-email", "update", { localId: "UID(up)", deleteAttribute: ["EMAIL"] }),
  adminCall("delete-password", "update", { localId: "UID(up)", deleteAttribute: ["PASSWORD"] }),
  adminLookup("lookup-after-credential-deletes", "UID(up)"),
  adminCall("valid-since", "update", { localId: "UID(up)", validSince: "1700000000" }),
  adminCall("unknown-local-id", "update", { localId: "UID(nobody)", displayName: "x" }),
  adminCall("no-local-id", "update", { displayName: "x" }),
  adminCall("unknown-delete-attribute", "update", {
    localId: "UID(up)",
    deleteAttribute: ["NOT_A_FIELD"],
  }),
]);

const customAttributes = program("auth-account/admin/custom-attributes", [
  adminCreate("create", { localId: "UID(ca)", email: "EMAIL(ca)", password: "password123" }),
  adminCall("set", "update", {
    localId: "UID(ca)",
    customAttributes: JSON.stringify({ role: "editor", level: 3 }),
  }),
  adminLookup("readback", "UID(ca)"),
  signIn("sign-in", "EMAIL(ca)"),
  lookupToken("client-lookup", "sign-in"),
  adminCall("clear", "update", { localId: "UID(ca)", customAttributes: "{}" }),
  adminLookup("readback-after-clear", "UID(ca)"),
  ...[
    "sub",
    "firebase",
    "iss",
    "aud",
    "exp",
    "iat",
    "auth_time",
    "user_id",
    "amr",
    "nonce",
    "at_hash",
    "cnf",
    "acr",
    "c_hash",
    "azp",
  ].map((claim) =>
    adminCall(`reserved-${claim}`, "update", {
      localId: "UID(ca)",
      customAttributes: JSON.stringify({ [claim]: "x" }),
    }),
  ),
  adminCall("size-1000", "update", {
    localId: "UID(ca)",
    customAttributes: { $concat: ['{"k":"', { $repeat: "v", count: 992 }, '"}'] },
  }),
  adminCall("size-1001", "update", {
    localId: "UID(ca)",
    customAttributes: { $concat: ['{"k":"', { $repeat: "v", count: 993 }, '"}'] },
  }),
  adminCall("invalid-json", "update", { localId: "UID(ca)", customAttributes: "{not json" }),
  adminCall("json-array", "update", { localId: "UID(ca)", customAttributes: "[1,2]" }),
  adminCall("json-string", "update", { localId: "UID(ca)", customAttributes: '"text"' }),
  adminCall("json-null", "update", { localId: "UID(ca)", customAttributes: "null" }),
  adminLookup("readback-after-refusals", "UID(ca)"),
]);

const privilegeValidToken = program("auth-account/privilege/valid-token-admin-fields", [
  signUp("sign-up", "priv"),
  adminCreate("victim", {
    localId: "UID(victim)",
    email: "EMAIL(victim)",
    password: "password123",
  }),
  ...[
    ["custom-attributes", { customAttributes: JSON.stringify({ role: "admin" }) }],
    ["email-verified", { emailVerified: true }],
    ["disable-user", { disableUser: true }],
    ["valid-since", { validSince: "1700000000" }],
    ["link-provider", { linkProviderUserInfo: { providerId: "google.com", rawId: "raw-priv" } }],
    ["foreign-local-id", { localId: "UID(victim)", displayName: "Hijacked" }],
  ].map(([id, fields]) =>
    client(`client-update-${id}`, "update", { idToken: from("sign-up", "idToken"), ...fields }),
  ),
  client("client-lookup-with-admin-selectors", "lookup", {
    idToken: from("sign-up", "idToken"),
    localId: ["UID(victim)"],
    email: ["EMAIL(victim)"],
  }),
  adminCall("admin-readback-self", "lookup", { email: ["EMAIL(priv)"] }),
  adminLookup("admin-readback-victim", "UID(victim)"),
]);

const privilegeCredentials = program("auth-account/privilege/credentials", [
  adminCreate("create", { localId: "UID(cred)", email: "EMAIL(cred)" }),
  {
    id: "admin-lookup-with-api-key-only",
    path: "v1/projects/{project}/accounts:lookup",
    auth: "key",
    body: { localId: ["UID(cred)"] },
  },
  {
    id: "admin-lookup-without-credentials",
    path: "v1/projects/{project}/accounts:lookup",
    auth: "none",
    body: { localId: ["UID(cred)"] },
  },
  {
    id: "admin-update-with-api-key-only",
    path: "v1/projects/{project}/accounts:update",
    auth: "key",
    body: { localId: "UID(cred)", displayName: "x" },
  },
  {
    id: "admin-create-with-api-key-only",
    path: "v1/projects/{project}/accounts",
    auth: "key",
    body: { localId: "UID(cred-new)" },
  },
  {
    id: "client-sign-up-without-key",
    path: "v1/accounts:signUp",
    auth: "none",
    body: { returnSecureToken: true },
  },
  client("client-lookup-without-token", "lookup", {}),
  client("client-lookup-null-token", "lookup", { idToken: null }),
  client("client-lookup-empty-token", "lookup", { idToken: "" }),
  client("client-lookup-number-token", "lookup", { idToken: 42 }),
  adminCall("admin-lookup-null-selector", "lookup", { localId: null }),
  adminCall("admin-lookup-string-selector", "lookup", { localId: "UID(cred)" }),
  adminCall("admin-lookup-number-selector", "lookup", { localId: [42] }),
  adminLookup("readback", "UID(cred)"),
]);

const adminDelete = program("auth-account/admin/delete", [
  adminCreate("create", { localId: "UID(d1)", email: "EMAIL(d1)" }),
  adminCall("delete", "delete", { localId: "UID(d1)" }),
  adminCall("delete-again", "delete", { localId: "UID(d1)" }),
  adminCall("delete-unknown", "delete", { localId: "UID(nobody)" }),
  adminCall("delete-without-local-id", "delete", {}),
  adminLookup("readback", "UID(d1)"),
]);

const adminBatchDelete = program("auth-account/admin/batch-delete", [
  adminCreate("create-enabled", { localId: "UID(b1)", email: "EMAIL(b1)" }),
  adminCreate("create-disabled", { localId: "UID(b2)", email: "EMAIL(b2)", disabled: true }),
  adminCreate("create-enabled-2", { localId: "UID(b3)", email: "EMAIL(b3)" }),
  adminCall("without-force", "batchDelete", { localIds: ["UID(b1)", "UID(b2)", "UID(nobody)"] }),
  adminCall("lookup-after-without-force", "lookup", { localId: ["UID(b1)", "UID(b2)", "UID(b3)"] }),
  adminCall("with-force", "batchDelete", { localIds: ["UID(b1)", "UID(b3)"], force: true }),
  adminCall("lookup-after-force", "lookup", { localId: ["UID(b1)", "UID(b2)", "UID(b3)"] }),
  adminCall("empty-list", "batchDelete", { localIds: [], force: true }),
  adminCall("missing-list", "batchDelete", { force: true }),
  adminCall("over-1000", "batchDelete", {
    localIds: Array.from({ length: 1001 }, (_, i) => `UID(none-${i})`),
    force: true,
  }),
  adminCall("duplicate-ids", "batchDelete", { localIds: ["UID(b2)", "UID(b2)"], force: true }),
]);

const adminBatchGet = program("auth-account/admin/batch-get", [
  adminCreate("create-password", {
    localId: "UID(g1)",
    email: "EMAIL(g1)",
    password: "password123",
  }),
  adminCreate("create-disabled", { localId: "UID(g2)", email: "EMAIL(g2)", disabled: true }),
  adminCreate("create-phone", { localId: "UID(g3)", phoneNumber: "PHONE(4)" }),
  adminCall("set-claims", "update", {
    localId: "UID(g1)",
    customAttributes: JSON.stringify({ tier: 1 }),
  }),
  {
    id: "all",
    method: "GET",
    path: "v1/projects/{project}/accounts:batchGet",
    auth: "admin",
    query: { maxResults: 1000 },
  },
  {
    id: "page-1",
    method: "GET",
    path: "v1/projects/{project}/accounts:batchGet",
    auth: "admin",
    query: { maxResults: 2 },
  },
  {
    id: "page-2",
    method: "GET",
    path: "v1/projects/{project}/accounts:batchGet",
    auth: "admin",
    query: { maxResults: 2, nextPageToken: from("page-1", "nextPageToken") },
  },
  {
    id: "max-results-0",
    method: "GET",
    path: "v1/projects/{project}/accounts:batchGet",
    auth: "admin",
    query: { maxResults: 0 },
  },
  {
    id: "max-results-1001",
    method: "GET",
    path: "v1/projects/{project}/accounts:batchGet",
    auth: "admin",
    query: { maxResults: 1001 },
  },
  {
    id: "bad-page-token",
    method: "GET",
    path: "v1/projects/{project}/accounts:batchGet",
    auth: "admin",
    query: { maxResults: 2, nextPageToken: "not-a-token" },
  },
  {
    id: "post-method",
    path: "v1/projects/{project}/accounts:batchGet",
    auth: "admin",
    body: { maxResults: 2 },
  },
]);

const queryFixture = [
  adminCreate("create-q1", { localId: "UID(q1)", email: "EMAIL(q-carol)", displayName: "Carol" }),
  adminCreate("create-q2", { localId: "UID(q2)", email: "EMAIL(q-alice)", displayName: "alice" }),
  adminCreate("create-q3", {
    localId: "UID(q3)",
    email: "EMAIL(q-bob)",
    displayName: "Bob",
    phoneNumber: "PHONE(5)",
  }),
  adminCreate("create-q4", { localId: "UID(q4)", phoneNumber: "PHONE(1)" }),
  adminCreate("create-q5", { localId: "UID(q5)", email: "EMAIL(q-dave)", displayName: "Bob" }),
];
const query = (id, body) => adminCall(id, "query", body);
const adminQuery = program("auth-account/admin/query", [
  ...queryFixture,
  query("count", { returnUserInfo: false }),
  query("default", {}),
  ...["USER_ID", "NAME", "CREATED_AT", "LAST_LOGIN_AT", "USER_EMAIL"].flatMap((sortBy) =>
    ["ASC", "DESC"].map((order) =>
      query(`sort-${sortBy.toLowerCase()}-${order.toLowerCase()}`, { sortBy, order, limit: "10" }),
    ),
  ),
  query("limit-0", { limit: "0" }),
  query("limit-2-offset-1", { limit: "2", offset: "1", sortBy: "USER_ID", order: "ASC" }),
  query("limit-500", { limit: "500" }),
  query("limit-501", { limit: "501" }),
  query("negative-offset", { offset: "-1" }),
  query("expression-email-mixed-case", { expression: [{ email: "EMAILMIXED(q-bob)" }] }),
  query("expression-phone", { expression: [{ phoneNumber: "PHONE(5)" }] }),
  query("expression-user-id", { expression: [{ userId: "UID(q2)" }] }),
  query("expression-two", { expression: [{ userId: "UID(q2)" }, { userId: "UID(q3)" }] }),
  query("expression-two-fields-one-item", {
    expression: [{ userId: "UID(q2)", email: "EMAIL(q-bob)" }],
  }),
  query("expression-empty-item", { expression: [{}] }),
  query("expression-empty-string", { expression: [{ email: "" }] }),
  query("expression-no-match", { expression: [{ email: "EMAIL(nobody)" }] }),
  query("bad-sort", { sortBy: "NOT_A_FIELD" }),
  {
    id: "project-query-accounts",
    path: "v1/projects/{project}:queryAccounts",
    auth: "admin",
    body: { returnUserInfo: false },
  },
]);

const importBasic = program("auth-account/admin/import", [
  adminCall("import-plain", "batchCreate", {
    users: [
      {
        localId: "UID(i1)",
        email: "EMAIL(i1)",
        emailVerified: true,
        displayName: "Imported",
        disabled: false,
      },
      {
        localId: "UID(i2)",
        phoneNumber: "PHONE(2)",
        customAttributes: JSON.stringify({ imported: true }),
      },
      {
        localId: "UID(i3)",
        email: "EMAIL(i3)",
        disabled: true,
        createdAt: "1600000000000",
        lastLoginAt: "1600000100000",
      },
      {
        localId: "UID(i4)",
        email: "EMAIL(i4)",
        providerUserInfo: [
          { providerId: "google.com", rawId: "raw-i4", email: "EMAIL(i4)", displayName: "G" },
        ],
      },
    ],
  }),
  adminCall("lookup-imported", "lookup", { localId: ["UID(i1)", "UID(i2)", "UID(i3)", "UID(i4)"] }),
  adminCall("import-raw-password", "batchCreate", {
    users: [{ localId: "UID(i5)", email: "EMAIL(i5)", rawPassword: "password123" }],
  }),
  signIn("sign-in-raw-password", "EMAIL(i5)"),
  adminCall("import-existing-without-overwrite", "batchCreate", {
    users: [{ localId: "UID(i1)", email: "EMAIL(i1-new)" }],
  }),
  adminCall("import-existing-with-overwrite", "batchCreate", {
    allowOverwrite: true,
    users: [{ localId: "UID(i1)", email: "EMAIL(i1-new)" }],
  }),
  adminLookup("lookup-overwritten", "UID(i1)"),
  adminCall("import-duplicate-local-id-in-request", "batchCreate", {
    users: [
      { localId: "UID(i6)", email: "EMAIL(i6)" },
      { localId: "UID(i6)", email: "EMAIL(i6b)" },
    ],
  }),
  adminCall("import-duplicate-email", "batchCreate", {
    users: [{ localId: "UID(i7)", email: "EMAIL(i3)" }],
  }),
  adminCall("import-duplicate-email-sanity-check", "batchCreate", {
    sanityCheck: true,
    users: [
      { localId: "UID(i8)", email: "EMAIL(i8)" },
      { localId: "UID(i9)", email: "EMAIL(i8)" },
    ],
  }),
  adminCall("import-mixed-valid-and-invalid", "batchCreate", {
    users: [
      { localId: "UID(i10)", email: "EMAIL(i10)" },
      { localId: "UID(i11)", email: "not-an-email" },
      { localId: "UID(i12)", phoneNumber: "6505550101" },
      { email: "EMAIL(i13)" },
    ],
  }),
  adminCall("lookup-after-mixed", "lookup", {
    localId: ["UID(i6)", "UID(i7)", "UID(i8)", "UID(i9)", "UID(i10)", "UID(i11)", "UID(i12)"],
  }),
  adminCall("import-empty", "batchCreate", { users: [] }),
  adminCall("import-1001", "batchCreate", {
    users: Array.from({ length: 1001 }, (_, i) => ({ localId: `UID(bulk-${i})` })),
  }),
]);

const uidReuse = program("auth-account/admin/uid-reuse", [
  adminCreate("create-first", {
    localId: "UID(reuse)",
    email: "EMAIL(reuse-first)",
    password: "password123",
  }),
  signIn("sign-in-first", "EMAIL(reuse-first)"),
  adminCall("delete-first", "delete", { localId: "UID(reuse)" }),
  adminCreate("create-second", {
    localId: "UID(reuse)",
    email: "EMAIL(reuse-second)",
    password: "password456",
  }),
  lookupToken("first-id-token-after-reuse", "sign-in-first"),
  refresh("first-refresh-token-after-reuse", "sign-in-first"),
  signIn("sign-in-first-email", "EMAIL(reuse-first)"),
  signIn("sign-in-second", "EMAIL(reuse-second)", "password456"),
  adminLookup("readback", "UID(reuse)"),
]);

export const PROGRAMS = [
  clientLifecycle,
  clientProfile,
  clientPasswordChange,
  clientValidation,
  clientAnonymous,
  clientEmailCase,
  adminDisable,
  clientDeleteEffects,
  adminDeleteEffects,
  defaultPolicyClientUpdate,
  tamperedToken,
  anonymousUpgrade,
  clientEmailChange,
  adminCreateProgram,
  adminLookupProgram,
  adminUpdate,
  customAttributes,
  privilegeValidToken,
  privilegeCredentials,
  adminDelete,
  adminBatchDelete,
  adminBatchGet,
  adminQuery,
  importBasic,
  uidReuse,
];
