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
];
