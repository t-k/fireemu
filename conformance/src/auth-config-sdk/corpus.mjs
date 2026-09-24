// AUTH-CONFIG-SDK corpus: one or more programs per recipe of
// spec/compatibility/closure/AUTH-CONFIG-SDK.json. Programs only record answers; they never
// assert. Each program runs on an empty project (the session wipes before and after), uses
// run-unique EMAIL(...)/UID(...) values, and names in `touches` every config path its steps may
// change; the session restores those paths and reads them back afterwards.
//
// `projection` is the fireemu configuration the rows are compared under (scope decision K5):
// "strict" (session-signed tokens), "strict-unsigned-emulator" (the Admin SDK's emulator mode)
// or "emulator" (the custom-token program).

import { TEST_PHONES, TEST_PHONE_CODE } from "../auth-account/harness.mjs";
import { PROBE_PHONE } from "./guard.mjs";

const CONFIG = "admin/v2/projects/{project}/config";
const BASELINE_TEST_PHONES = Object.fromEntries(TEST_PHONES.map((p) => [p, TEST_PHONE_CODE]));
const HOSTING = "https://{project}.firebaseapp.com/finish";

// ---- step builders -------------------------------------------------------------------------

const from = (reference) => ({ $from: reference });
const getConfig = (id) => ({ id, path: CONFIG, auth: "admin", method: "GET" });
const patchConfig = (id, mask, body, extra = {}) => ({
  id,
  path: CONFIG,
  auth: "admin",
  method: "PATCH",
  query: { updateMask: mask },
  body,
  ...extra,
});
/** A config write the following steps depend on: the session waits until it reads back. */
const setConfig = (id, mask, body) => patchConfig(id, mask, body, { settle: true });
const clientGet = (id, path, query = {}, auth = "key") => ({
  id,
  path,
  auth,
  method: "GET",
  query,
});
const client = (id, method, body, extra = {}) => ({
  id,
  path: `v1/accounts:${method}`,
  auth: "key",
  body,
  ...extra,
});
const adminCall = (id, method, body) => ({
  id,
  path: `v1/projects/{project}/accounts:${method}`,
  auth: "admin",
  body,
});
const adminCreate = (id, body) => ({
  id,
  path: "v1/projects/{project}/accounts",
  auth: "admin",
  body,
});
const signUp = (id, name, password = "password123") =>
  client(id, "signUp", { email: `EMAIL(${name})`, password, returnSecureToken: true });
const signIn = (id, name, password = "password123") =>
  client(id, "signInWithPassword", {
    email: `EMAIL(${name})`,
    password,
    returnSecureToken: true,
  });
const adminLink = (id, requestType, email, extra = {}) =>
  adminCall(id, "sendOobCode", { requestType, email, returnOobLink: true, ...extra });
const sdk = (id, operation, ...args) => ({ id, sdk: operation, args });

const policy = (state, options, extra = {}) => ({
  passwordPolicyConfig: {
    passwordPolicyEnforcementState: state,
    ...(options ? { passwordPolicyVersions: [{ customStrengthOptions: options }] } : {}),
    ...extra,
  },
});
const ALL_CLASSES = {
  minPasswordLength: 8,
  maxPasswordLength: 20,
  containsLowercaseCharacter: true,
  containsUppercaseCharacter: true,
  containsNumericCharacter: true,
  containsNonAlphanumericCharacter: true,
};
const setPolicy = (id, state, options, extra) =>
  setConfig(id, "passwordPolicyConfig", policy(state, options, extra));
const clearPolicy = (id) => setConfig(id, "passwordPolicyConfig", {});

const recaptcha = (config) => ({ recaptchaConfig: config });
const recaptchaRead = (id, clientType = "CLIENT_TYPE_WEB") =>
  clientGet(id, "v2/recaptchaConfig", { clientType, version: "RECAPTCHA_ENTERPRISE" });

// ---- REST programs (strict) ----------------------------------------------------------------

const read = {
  id: "auth-config-sdk/config/read",
  projection: "strict",
  steps: [
    getConfig("admin-get"),
    { id: "admin-get-v2-path", path: "v2/projects/{project}/config", auth: "admin", method: "GET" },
    clientGet("projects", "v1/projects"),
    clientGet("projects-without-key", "v1/projects", {}, "none"),
    clientGet("password-policy", "v2/passwordPolicy"),
    clientGet("password-policy-unknown-tenant", "v2/passwordPolicy", {
      tenantId: "no-such-tenant",
    }),
    recaptchaRead("recaptcha-web"),
    recaptchaRead("recaptcha-ios", "CLIENT_TYPE_IOS"),
    recaptchaRead("recaptcha-android", "CLIENT_TYPE_ANDROID"),
    clientGet("recaptcha-without-client-type", "v2/recaptchaConfig"),
    clientGet("recaptcha-without-version", "v2/recaptchaConfig", { clientType: "CLIENT_TYPE_WEB" }),
    clientGet("recaptcha-unknown-client-type", "v2/recaptchaConfig", {
      clientType: "CLIENT_TYPE_TV",
      version: "RECAPTCHA_ENTERPRISE",
    }),
    clientGet("recaptcha-params", "v1/recaptchaParams"),
  ],
};

const mask = {
  id: "auth-config-sdk/config/mask",
  projection: "strict",
  touches: [
    "emailPrivacyConfig.enableImprovedEmailPrivacy",
    "client.permissions.disabledUserSignup",
    "client.permissions.disabledUserDeletion",
    "signIn.anonymous.enabled",
    "signIn.allowDuplicateEmails",
  ],
  steps: [
    setConfig("leaf", "emailPrivacyConfig.enableImprovedEmailPrivacy", {
      emailPrivacyConfig: { enableImprovedEmailPrivacy: false },
    }),
    getConfig("read-after-leaf"),
    setConfig("parent", "emailPrivacyConfig", {
      emailPrivacyConfig: { enableImprovedEmailPrivacy: true },
    }),
    setConfig("set-signup-switch", "client.permissions.disabledUserSignup", {
      client: { permissions: { disabledUserSignup: true } },
    }),
    setConfig("masked-but-absent", "client.permissions.disabledUserSignup", {}),
    getConfig("read-after-masked-but-absent"),
    setConfig("outside-mask", "signIn.allowDuplicateEmails", {
      signIn: { allowDuplicateEmails: true },
      client: { permissions: { disabledUserDeletion: true } },
    }),
    getConfig("read-after-outside-mask"),
    setConfig("set-both-switches", "client.permissions.disabledUserSignup", {
      client: { permissions: { disabledUserSignup: true } },
    }),
    setConfig("parent-permissions", "client.permissions", {
      client: { permissions: { disabledUserDeletion: true } },
    }),
    getConfig("read-after-parent-permissions"),
    patchConfig("unknown-path", "unknownMember", {}),
    patchConfig("unknown-nested-path", "signIn.unknownMember", {}),
    patchConfig("duplicate-path", "signIn.allowDuplicateEmails,signIn.allowDuplicateEmails", {
      signIn: { allowDuplicateEmails: false },
    }),
    // Read-only members are written back with the value just read, so an accepted write
    // changes nothing.
    patchConfig("read-only-name", "name", { name: from("read-after-parent-permissions:name") }),
    patchConfig("read-only-subtype", "subtype", { subtype: "IDENTITY_PLATFORM" }),
    patchConfig("read-only-hosting-site", "defaultHostingSite", {
      defaultHostingSite: "{project}",
    }),
    getConfig("read-final"),
  ],
};

const invalid = {
  id: "auth-config-sdk/config/invalid",
  projection: "strict",
  touches: [
    "signIn.phoneNumber.testPhoneNumbers",
    "authorizedDomains",
    "mobileLinksConfig.domain",
    "smsRegionConfig",
    "emailPrivacyConfig.enableImprovedEmailPrivacy",
    "client.permissions.disabledUserSignup",
  ],
  steps: [
    ...[
      ["phone-without-plus", { 16505550101: "123456" }],
      ["phone-letters", { "+1650555abcd": "123456" }],
      ["phone-code-short", { [PROBE_PHONE]: "12345" }],
      ["phone-code-letters", { [PROBE_PHONE]: "abcdef" }],
    ].map(([id, numbers]) =>
      // The six sandbox numbers stay in every probe, so an accepted probe removes none of them.
      patchConfig(id, "signIn.phoneNumber.testPhoneNumbers", {
        signIn: { phoneNumber: { testPhoneNumbers: { ...BASELINE_TEST_PHONES, ...numbers } } },
      }),
    ),
    ...[
      ["domain-with-scheme", "https://app.example.com"],
      ["domain-with-port", "app.example.com:8080"],
      ["domain-wildcard", "*.example.com"],
      ["domain-empty", ""],
      ["domain-with-space", "app example.com"],
    ].map(([id, domain]) =>
      patchConfig(id, "authorizedDomains", {
        authorizedDomains: ["{project}.firebaseapp.com", "{project}.web.app", domain],
      }),
    ),
    patchConfig("mobile-links-unknown-domain", "mobileLinksConfig.domain", {
      mobileLinksConfig: { domain: "CUSTOM_DOMAIN" },
    }),
    patchConfig("sms-region-both", "smsRegionConfig", {
      smsRegionConfig: { allowByDefault: {}, allowlistOnly: {} },
    }),
    patchConfig("sms-region-unknown-code", "smsRegionConfig", {
      smsRegionConfig: { allowByDefault: { disallowedRegions: ["ZZ"] } },
    }),
    patchConfig("sms-region-lower-case", "smsRegionConfig", {
      smsRegionConfig: { allowlistOnly: { allowedRegions: ["us"] } },
    }),
    patchConfig("privacy-string", "emailPrivacyConfig.enableImprovedEmailPrivacy", {
      emailPrivacyConfig: { enableImprovedEmailPrivacy: "yes" },
    }),
    patchConfig("permissions-number", "client.permissions.disabledUserSignup", {
      client: { permissions: { disabledUserSignup: 1 } },
    }),
    patchConfig("unknown-body-member", "emailPrivacyConfig.enableImprovedEmailPrivacy", {
      emailPrivacyConfig: { enableImprovedEmailPrivacy: true },
      unknownMember: true,
    }),
    {
      id: "body-array",
      path: CONFIG,
      auth: "admin",
      method: "PATCH",
      query: { updateMask: "emailPrivacyConfig.enableImprovedEmailPrivacy" },
      rawBody: "[]",
    },
    {
      id: "body-malformed",
      path: CONFIG,
      auth: "admin",
      method: "PATCH",
      query: { updateMask: "emailPrivacyConfig.enableImprovedEmailPrivacy" },
      rawBody: "{",
    },
    getConfig("read-after-refusals"),
  ],
};

const policyConfig = {
  id: "auth-config-sdk/password-policy/config",
  projection: "strict",
  touches: ["passwordPolicyConfig"],
  steps: [
    setPolicy("enforce-minimum", "ENFORCE", { minPasswordLength: 8 }),
    getConfig("read-enforce-minimum"),
    setPolicy("off-with-version", "OFF", { minPasswordLength: 10, containsNumericCharacter: true }),
    getConfig("read-off-with-version"),
    setPolicy("enforce-force-false", "ENFORCE", ALL_CLASSES, { forceUpgradeOnSignin: false }),
    getConfig("read-enforce-force-false"),
    setPolicy("enforce-force-true", "ENFORCE", ALL_CLASSES, { forceUpgradeOnSignin: true }),
    getConfig("read-enforce-force-true"),
    patchConfig("leaf-state-off", "passwordPolicyConfig.passwordPolicyEnforcementState", {
      passwordPolicyConfig: { passwordPolicyEnforcementState: "OFF" },
    }),
    getConfig("read-leaf-state-off"),
    clearPolicy("clear"),
    getConfig("read-cleared"),
    patchConfig(
      "leaf-state-without-version",
      "passwordPolicyConfig.passwordPolicyEnforcementState",
      {
        passwordPolicyConfig: { passwordPolicyEnforcementState: "ENFORCE" },
      },
    ),
    ...[
      ["minimum-5", "ENFORCE", { minPasswordLength: 5 }],
      ["minimum-31", "ENFORCE", { minPasswordLength: 31 }],
      ["minimum-fraction", "ENFORCE", { minPasswordLength: 6.5 }],
      ["maximum-below-minimum", "ENFORCE", { minPasswordLength: 10, maxPasswordLength: 9 }],
      ["maximum-5", "ENFORCE", { maxPasswordLength: 5 }],
      ["maximum-4097", "ENFORCE", { maxPasswordLength: 4097 }],
      ["maximum-4096", "ENFORCE", { maxPasswordLength: 4096 }],
      ["unknown-option", "ENFORCE", { minPasswordLength: 8, containsEmoji: true }],
      [
        "state-unspecified",
        "PASSWORD_POLICY_ENFORCEMENT_STATE_UNSPECIFIED",
        { minPasswordLength: 8 },
      ],
      ["state-unknown", "NOT_ENFORCE", { minPasswordLength: 8 }],
      ["enforce-without-version", "ENFORCE", undefined],
    ].map(([id, state, options]) =>
      patchConfig(id, "passwordPolicyConfig", policy(state, options)),
    ),
    patchConfig("no-versions", "passwordPolicyConfig", {
      passwordPolicyConfig: {
        passwordPolicyEnforcementState: "ENFORCE",
        passwordPolicyVersions: [],
      },
    }),
    patchConfig("two-versions", "passwordPolicyConfig", {
      passwordPolicyConfig: {
        passwordPolicyEnforcementState: "ENFORCE",
        passwordPolicyVersions: [
          { customStrengthOptions: { minPasswordLength: 8 } },
          { customStrengthOptions: { minPasswordLength: 9 } },
        ],
      },
    }),
    patchConfig("schema-version-written", "passwordPolicyConfig", {
      passwordPolicyConfig: {
        passwordPolicyEnforcementState: "ENFORCE",
        passwordPolicyVersions: [
          { customStrengthOptions: { minPasswordLength: 8 }, schemaVersion: 7 },
        ],
      },
    }),
    getConfig("read-final"),
  ],
};

const projectionSteps = [
  ["off", "OFF", { minPasswordLength: 8, containsNumericCharacter: true }, {}],
  ["enforce-minimum-only", "ENFORCE", { minPasswordLength: 12 }, {}],
  ["enforce-maximum-only", "ENFORCE", { maxPasswordLength: 16 }, {}],
  ["enforce-all-force", "ENFORCE", ALL_CLASSES, { forceUpgradeOnSignin: true }],
  ["enforce-all-notify", "ENFORCE", ALL_CLASSES, { forceUpgradeOnSignin: false }],
].flatMap(([name, state, options, extra]) => [
  setPolicy(`set-${name}`, state, options, extra),
  { ...clientGet(`policy-${name}`, "v2/passwordPolicy"), delayMs: 3000 },
]);

const policyProjection = {
  id: "auth-config-sdk/password-policy/projection",
  projection: "strict",
  touches: ["passwordPolicyConfig"],
  steps: [
    ...projectionSteps,
    clearPolicy("clear"),
    { ...clientGet("policy-cleared", "v2/passwordPolicy"), delayMs: 3000 },
  ],
};

const policyExisting = {
  id: "auth-config-sdk/password-policy/existing",
  projection: "strict",
  touches: ["passwordPolicyConfig"],
  steps: [
    adminCreate("create-weak", { email: "EMAIL(weak)", password: "password" }),
    adminCall("admin-update-short", "update", {
      localId: from("create-weak:localId"),
      password: "12345",
    }),
    adminCall("admin-update-long", "update", {
      localId: from("create-weak:localId"),
      password: { $repeat: "a", count: 4097 },
    }),
    setPolicy("enforce-force", "ENFORCE", ALL_CLASSES, { forceUpgradeOnSignin: true }),
    signIn("sign-in-weak-force", "weak", "password"),
    signIn("sign-in-weak-force-wrong", "weak", "Wrong-passw0rd"),
    setPolicy("enforce-notify", "ENFORCE", ALL_CLASSES, { forceUpgradeOnSignin: false }),
    signIn("sign-in-weak-notify", "weak", "password"),
    client("update-weak-to-weak", "update", {
      idToken: from("sign-in-weak-notify:idToken"),
      password: "password2",
      returnSecureToken: true,
    }),
    client("update-weak-to-compliant", "update", {
      idToken: from("sign-in-weak-notify:idToken"),
      password: "Passw0rd!",
      returnSecureToken: true,
    }),
    signIn("sign-in-compliant-notify", "weak", "Passw0rd!"),
    adminLink("reset-link", "PASSWORD_RESET", "EMAIL(weak)"),
    client("reset-to-weak", "resetPassword", {
      oobCode: from("reset-link:oobCode"),
      newPassword: "password",
    }),
    client("reset-to-compliant", "resetPassword", {
      oobCode: from("reset-link:oobCode"),
      newPassword: "Passw0rd?",
    }),
    setPolicy("off", "OFF", ALL_CLASSES),
    adminCreate("create-weak-off", { email: "EMAIL(weak-off)", password: "password" }),
    setPolicy("enforce-force-again", "ENFORCE", ALL_CLASSES, { forceUpgradeOnSignin: true }),
    signIn("sign-in-created-under-off", "weak-off", "password"),
  ],
};

const providers = {
  id: "auth-config-sdk/providers",
  projection: "strict",
  touches: ["signIn.email.enabled", "signIn.anonymous.enabled", "signIn.phoneNumber.enabled"],
  steps: [
    adminCreate("create-email", { email: "EMAIL(existing)", password: "password123" }),
    adminCreate("create-phone", { phoneNumber: "PHONE(1)" }),
    setConfig("email-off", "signIn.email.enabled", { signIn: { email: { enabled: false } } }),
    signUp("email-off-sign-up", "new"),
    signIn("email-off-sign-in", "existing"),
    client("email-off-reset-unknown", "sendOobCode", {
      requestType: "PASSWORD_RESET",
      email: "EMAIL(unknown-reset)",
    }),
    adminLink("email-off-admin-reset", "PASSWORD_RESET", "EMAIL(existing)"),
    adminCreate("email-off-admin-create", { email: "EMAIL(admin-new)", password: "password123" }),
    setConfig("email-on", "signIn.email.enabled", { signIn: { email: { enabled: true } } }),
    setConfig("anonymous-off", "signIn.anonymous.enabled", {
      signIn: { anonymous: { enabled: false } },
    }),
    client("anonymous-off-sign-up", "signUp", { returnSecureToken: true }),
    signUp("anonymous-off-email-sign-up", "anon-off"),
    setConfig("phone-off", "signIn.phoneNumber.enabled", {
      signIn: { phoneNumber: { enabled: false } },
    }),
    client("phone-off-send-new", "sendVerificationCode", { phoneNumber: "PHONE(0)" }),
    client("phone-off-send-existing", "sendVerificationCode", { phoneNumber: "PHONE(1)" }),
    adminCreate("phone-off-admin-create", { phoneNumber: "PHONE(2)" }),
  ],
};

const duplicateEmail = {
  id: "auth-config-sdk/duplicate-email",
  projection: "strict",
  touches: ["signIn.allowDuplicateEmails"],
  steps: [
    setConfig("allow", "signIn.allowDuplicateEmails", { signIn: { allowDuplicateEmails: true } }),
    adminCall("import-two", "batchCreate", {
      users: [
        { localId: "UID(dup-a)", email: "EMAIL(dup)", rawPassword: "password-a" },
        { localId: "UID(dup-b)", email: "EMAIL(dup)", rawPassword: "password-b" },
      ],
    }),
    adminCall("lookup-by-email", "lookup", { email: ["EMAIL(dup)"] }),
    client("create-auth-uri", "createAuthUri", {
      identifier: "EMAIL(dup)",
      continueUri: "http://localhost/finish",
    }),
    signIn("sign-in-first-password", "dup", "password-a"),
    signIn("sign-in-second-password", "dup", "password-b"),
    patchConfig("disallow-with-duplicates", "signIn.allowDuplicateEmails", {
      signIn: { allowDuplicateEmails: false },
    }),
    getConfig("read-after-disallow"),
    adminCall("lookup-after-disallow", "lookup", { email: ["EMAIL(dup)"] }),
  ],
};

const emailPrivacy = {
  id: "auth-config-sdk/email-privacy",
  projection: "strict",
  touches: ["emailPrivacyConfig.enableImprovedEmailPrivacy"],
  steps: [
    adminCreate("create-password", { email: "EMAIL(pw)", password: "password123" }),
    adminCreate("create-mixed", {
      email: "EMAIL(mixed)",
      password: "password123",
      phoneNumber: "PHONE(0)",
    }),
    adminCreate("create-no-password", { email: "EMAIL(nopw)" }),
    ...[false, true].flatMap((on) => {
      const state = on ? "on" : "off";
      return [
        setConfig(`privacy-${state}`, "emailPrivacyConfig.enableImprovedEmailPrivacy", {
          emailPrivacyConfig: { enableImprovedEmailPrivacy: on },
        }),
        ...["pw", "mixed", "nopw", "unknown"].map((name) =>
          client(`${state}-auth-uri-${name}`, "createAuthUri", {
            identifier: `EMAIL(${name})`,
            continueUri: "http://localhost/finish",
          }),
        ),
        client(`${state}-auth-uri-provider`, "createAuthUri", {
          providerId: "google.com",
          continueUri: "http://localhost/finish",
        }),
        client(`${state}-auth-uri-no-continue`, "createAuthUri", { identifier: "EMAIL(pw)" }),
      ];
    }),
  ],
};

const clientPermissions = {
  id: "auth-config-sdk/client-permissions",
  projection: "strict",
  touches: ["client.permissions.disabledUserSignup", "signIn.email.passwordRequired"],
  steps: [
    adminCreate("create-phone", { phoneNumber: "PHONE(1)" }),
    adminCreate("create-email", { email: "EMAIL(existing)" }),
    setConfig("signup-off", "client.permissions.disabledUserSignup", {
      client: { permissions: { disabledUserSignup: true } },
    }),
    client("send-new-number", "sendVerificationCode", { phoneNumber: "PHONE(0)" }),
    client("sign-in-new-number", "signInWithPhoneNumber", {
      sessionInfo: from("send-new-number:sessionInfo"),
      code: "123456",
    }),
    client("send-existing-number", "sendVerificationCode", { phoneNumber: "PHONE(1)" }),
    client("sign-in-existing-number", "signInWithPhoneNumber", {
      sessionInfo: from("send-existing-number:sessionInfo"),
      code: "123456",
    }),
    setConfig("links-on", "signIn.email.passwordRequired", {
      signIn: { email: { passwordRequired: false } },
    }),
    adminLink("link-new", "EMAIL_SIGNIN", "EMAIL(link-new)", { continueUrl: HOSTING }),
    client("sign-in-link-new", "signInWithEmailLink", {
      email: "EMAIL(link-new)",
      oobCode: from("link-new:oobCode"),
    }),
    adminLink("link-existing", "EMAIL_SIGNIN", "EMAIL(existing)", { continueUrl: HOSTING }),
    client("sign-in-link-existing", "signInWithEmailLink", {
      email: "EMAIL(existing)",
      oobCode: from("link-existing:oobCode"),
    }),
  ],
};

const recaptchaProgram = {
  id: "auth-config-sdk/recaptcha",
  projection: "strict",
  touches: ["recaptchaConfig"],
  steps: [
    ...[
      ["unknown-state", { emailPasswordEnforcementState: "SOMETIMES" }],
      ["score-between-steps", { managedRules: [{ endScore: 0.35, action: "BLOCK" }] }],
      ["score-above-one", { managedRules: [{ endScore: 1.5, action: "BLOCK" }] }],
      ["action-unspecified", { managedRules: [{ endScore: 0.3 }] }],
      ["sms-bot-score-phone-off", { phoneEnforcementState: "OFF", useSmsBotScore: true }],
      [
        "toll-fraud-between-steps",
        {
          phoneEnforcementState: "AUDIT",
          useSmsTollFraudProtection: true,
          tollFraudManagedRules: [{ startScore: 0.35, action: "BLOCK" }],
        },
      ],
      ["keys-written", { recaptchaKeys: [{ key: "projects/{project}/keys/k", type: "WEB" }] }],
    ].map(([id, config]) => patchConfig(id, "recaptchaConfig", recaptcha(config))),
    setConfig("off", "recaptchaConfig", {
      recaptchaConfig: { emailPasswordEnforcementState: "OFF", phoneEnforcementState: "OFF" },
    }),
    getConfig("read-off"),
    recaptchaRead("client-off"),
    setConfig(
      "audit-email",
      "recaptchaConfig",
      recaptcha({
        emailPasswordEnforcementState: "AUDIT",
        managedRules: [{ endScore: 0.3, action: "BLOCK" }],
        useAccountDefender: false,
      }),
    ),
    { ...getConfig("read-audit-email"), delayMs: 3000 },
    recaptchaRead("client-audit-web"),
    recaptchaRead("client-audit-ios", "CLIENT_TYPE_IOS"),
    recaptchaRead("client-audit-android", "CLIENT_TYPE_ANDROID"),
    signUp("audit-sign-up-without-token", "audit"),
    signIn("audit-sign-in-without-token", "audit"),
    client("audit-reset-unknown-without-token", "sendOobCode", {
      requestType: "PASSWORD_RESET",
      email: "EMAIL(unknown-audit)",
    }),
    setConfig(
      "audit-phone",
      "recaptchaConfig",
      recaptcha({
        emailPasswordEnforcementState: "AUDIT",
        phoneEnforcementState: "AUDIT",
        useSmsBotScore: true,
        useSmsTollFraudProtection: true,
        tollFraudManagedRules: [{ startScore: 0.8, action: "BLOCK" }],
      }),
    ),
    { ...getConfig("read-audit-phone"), delayMs: 3000 },
    recaptchaRead("client-audit-phone"),
    client("audit-send-code-without-token", "sendVerificationCode", { phoneNumber: "PHONE(2)" }),
    setConfig("clear", "recaptchaConfig", {}),
    getConfig("read-cleared"),
    recaptchaRead("client-cleared"),
  ],
};

const quota = {
  id: "auth-config-sdk/quota",
  projection: "strict",
  touches: ["quota.signUpQuotaConfig"],
  steps: [
    setConfig("set", "quota.signUpQuotaConfig", {
      quota: {
        signUpQuotaConfig: {
          quota: "200",
          startTime: { $isoFromNow: 3600 },
          quotaDuration: "3600s",
        },
      },
    }),
    getConfig("read-set"),
    ...[
      ["negative", { quota: "-1", startTime: { $isoFromNow: 3600 }, quotaDuration: "3600s" }],
      ["zero", { quota: "0", startTime: { $isoFromNow: 3600 }, quotaDuration: "3600s" }],
      ["not-a-number", { quota: "many", startTime: { $isoFromNow: 3600 }, quotaDuration: "3600s" }],
      [
        "very-large",
        { quota: "100000000", startTime: { $isoFromNow: 3600 }, quotaDuration: "3600s" },
      ],
      ["duration-zero", { quota: "200", startTime: { $isoFromNow: 3600 }, quotaDuration: "0s" }],
      [
        "duration-eight-days",
        { quota: "200", startTime: { $isoFromNow: 3600 }, quotaDuration: "691200s" },
      ],
      [
        "start-in-past",
        { quota: "200", startTime: { $isoFromNow: -3600 }, quotaDuration: "3600s" },
      ],
      [
        "start-far-future",
        { quota: "200", startTime: { $isoFromNow: 30 * 86400 }, quotaDuration: "3600s" },
      ],
      ["without-start", { quota: "200", quotaDuration: "3600s" }],
      ["without-duration", { quota: "200", startTime: { $isoFromNow: 3600 } }],
    ].map(([id, config]) =>
      patchConfig(id, "quota.signUpQuotaConfig", { quota: { signUpQuotaConfig: config } }),
    ),
    getConfig("read-after-refusals"),
    setConfig("clear", "quota.signUpQuotaConfig", {}),
    getConfig("read-cleared"),
  ],
};

const mobileSettings = {
  continueUrl: HOSTING,
  canHandleCodeInApp: true,
  iOSBundleId: "com.example.ios",
  androidPackageName: "com.example.android",
  androidInstallApp: true,
  androidMinimumVersion: "12",
};

const mobileLinks = {
  id: "auth-config-sdk/mobile-links",
  projection: "strict",
  touches: ["mobileLinksConfig.domain", "signIn.email.passwordRequired"],
  steps: [
    adminCreate("create", { email: "EMAIL(mobile)", password: "password123" }),
    adminLink("reset-all-settings", "PASSWORD_RESET", "EMAIL(mobile)", mobileSettings),
    adminLink("reset-ios-only", "PASSWORD_RESET", "EMAIL(mobile)", {
      continueUrl: HOSTING,
      iOSBundleId: "com.example.ios",
    }),
    adminLink("reset-android-only", "PASSWORD_RESET", "EMAIL(mobile)", {
      continueUrl: HOSTING,
      androidPackageName: "com.example.android",
    }),
    adminLink("reset-android-version-code", "PASSWORD_RESET", "EMAIL(mobile)", {
      continueUrl: HOSTING,
      androidPackageName: "com.example.android",
      androidMinimumVersionCode: "12",
    }),
    adminLink("reset-install-without-package", "PASSWORD_RESET", "EMAIL(mobile)", {
      continueUrl: HOSTING,
      androidInstallApp: true,
    }),
    adminLink("reset-version-without-package", "PASSWORD_RESET", "EMAIL(mobile)", {
      continueUrl: HOSTING,
      androidMinimumVersion: "12",
    }),
    adminLink("reset-ios-without-continue", "PASSWORD_RESET", "EMAIL(mobile)", {
      iOSBundleId: "com.example.ios",
    }),
    adminLink("reset-in-app-without-continue", "PASSWORD_RESET", "EMAIL(mobile)", {
      canHandleCodeInApp: true,
    }),
    adminLink("reset-link-domain-hosting", "PASSWORD_RESET", "EMAIL(mobile)", {
      ...mobileSettings,
      linkDomain: "{project}.web.app",
    }),
    adminLink("reset-link-domain-other", "PASSWORD_RESET", "EMAIL(mobile)", {
      ...mobileSettings,
      linkDomain: "app.example.com",
    }),
    adminLink("reset-dynamic-link-domain", "PASSWORD_RESET", "EMAIL(mobile)", {
      ...mobileSettings,
      dynamicLinkDomain: "example.page.link",
    }),
    adminLink("verify-all-settings", "VERIFY_EMAIL", "EMAIL(mobile)", mobileSettings),
    setConfig("links-on", "signIn.email.passwordRequired", {
      signIn: { email: { passwordRequired: false } },
    }),
    adminLink("sign-in-all-settings", "EMAIL_SIGNIN", "EMAIL(mobile)", mobileSettings),
    adminLink("sign-in-not-in-app", "EMAIL_SIGNIN", "EMAIL(mobile)", {
      ...mobileSettings,
      canHandleCodeInApp: false,
    }),
    setConfig("dynamic-link-domain", "mobileLinksConfig.domain", {
      mobileLinksConfig: { domain: "FIREBASE_DYNAMIC_LINK_DOMAIN" },
    }),
    getConfig("read-dynamic-link-domain"),
    adminLink("sign-in-under-dynamic-link-domain", "EMAIL_SIGNIN", "EMAIL(mobile)", mobileSettings),
    adminLink("reset-under-dynamic-link-domain", "PASSWORD_RESET", "EMAIL(mobile)", mobileSettings),
  ],
};

const otherFields = {
  id: "auth-config-sdk/other-fields",
  projection: "strict",
  touches: [
    "notification.defaultLocale",
    "notification.sendEmail.resetPasswordTemplate.subject",
    "autodeleteAnonymousUsers",
    "monitoring.requestLogging.enabled",
    "smsRegionConfig",
    "authorizedDomains",
  ],
  steps: [
    adminCreate("create", { email: "EMAIL(other)", password: "password123" }),
    setConfig("locale", "notification.defaultLocale", { notification: { defaultLocale: "ja" } }),
    getConfig("read-locale"),
    adminLink("reset-under-locale", "PASSWORD_RESET", "EMAIL(other)", { continueUrl: HOSTING }),
    setConfig("reset-subject", "notification.sendEmail.resetPasswordTemplate.subject", {
      notification: { sendEmail: { resetPasswordTemplate: { subject: "Reset for %APP_NAME%" } } },
    }),
    getConfig("read-reset-subject"),
    setConfig("autodelete", "autodeleteAnonymousUsers", { autodeleteAnonymousUsers: true }),
    setConfig("request-logging", "monitoring.requestLogging.enabled", {
      monitoring: { requestLogging: { enabled: true } },
    }),
    getConfig("read-switches"),
    setConfig("allowlist-japan", "smsRegionConfig", {
      smsRegionConfig: { allowlistOnly: { allowedRegions: ["JP"] } },
    }),
    client("send-us-under-allowlist", "sendVerificationCode", { phoneNumber: "PHONE(3)" }),
    setConfig("deny-united-states", "smsRegionConfig", {
      smsRegionConfig: { allowByDefault: { disallowedRegions: ["US"] } },
    }),
    getConfig("read-sms-region"),
    client("send-us-under-denylist", "sendVerificationCode", { phoneNumber: "PHONE(4)" }),
    setConfig("add-domain", "authorizedDomains", {
      authorizedDomains: ["{project}.firebaseapp.com", "{project}.web.app", "app.example.com"],
    }),
    clientGet("projects-with-domain", "v1/projects"),
    adminLink("reset-to-added-domain", "PASSWORD_RESET", "EMAIL(other)", {
      continueUrl: "https://app.example.com/finish",
    }),
    setConfig("remove-hosting-domains", "authorizedDomains", {
      authorizedDomains: ["app.example.com"],
    }),
    adminLink("reset-to-removed-domain", "PASSWORD_RESET", "EMAIL(other)", {
      continueUrl: HOSTING,
    }),
    getConfig("read-domains"),
  ],
};

// ---- SDK programs ------------------------------------------------------------------------

const adminConfig = {
  id: "auth-config-sdk/sdk/admin-config",
  projection: "strict-unsigned-emulator",
  touches: [
    "passwordPolicyConfig",
    "emailPrivacyConfig.enableImprovedEmailPrivacy",
    "recaptchaConfig",
    "smsRegionConfig",
    "mobileLinksConfig.domain",
  ],
  steps: [
    sdk("get", "admin.getProjectConfig"),
    {
      ...sdk("update-policy", "admin.updateProjectConfig", {
        passwordPolicyConfig: {
          enforcementState: "ENFORCE",
          forceUpgradeOnSignin: true,
          constraints: { requireUppercase: true, minLength: 8, maxLength: 20 },
        },
      }),
      settleTo: { "passwordPolicyConfig.passwordPolicyEnforcementState": "ENFORCE" },
    },
    sdk("get-after-policy", "admin.getProjectConfig"),
    sdk("update-policy-unknown-state", "admin.updateProjectConfig", {
      passwordPolicyConfig: { enforcementState: "NOT_ENFORCE" },
    }),
    sdk("update-policy-minimum-5", "admin.updateProjectConfig", {
      passwordPolicyConfig: { enforcementState: "ENFORCE", constraints: { minLength: 5 } },
    }),
    sdk("update-policy-fraction", "admin.updateProjectConfig", {
      passwordPolicyConfig: { enforcementState: "ENFORCE", constraints: { minLength: 6.5 } },
    }),
    {
      ...sdk("update-policy-off", "admin.updateProjectConfig", {
        passwordPolicyConfig: { enforcementState: "OFF" },
      }),
      settleTo: { "passwordPolicyConfig.passwordPolicyEnforcementState": "OFF" },
    },
    {
      ...sdk("update-privacy-off", "admin.updateProjectConfig", {
        emailPrivacyConfig: { enableImprovedEmailPrivacy: false },
      }),
      settleTo: { "emailPrivacyConfig.enableImprovedEmailPrivacy": false },
    },
    sdk("get-after-privacy", "admin.getProjectConfig"),
    sdk("update-recaptcha-score-between-steps", "admin.updateProjectConfig", {
      recaptchaConfig: { managedRules: [{ endScore: 0.35, action: "BLOCK" }] },
    }),
    sdk("update-recaptcha-enforce-unknown", "admin.updateProjectConfig", {
      recaptchaConfig: { emailPasswordEnforcementState: "SOMETIMES" },
    }),
    {
      ...sdk("update-recaptcha-off", "admin.updateProjectConfig", {
        recaptchaConfig: {
          emailPasswordEnforcementState: "OFF",
          phoneEnforcementState: "OFF",
          useAccountDefender: false,
        },
      }),
      settleTo: { "recaptchaConfig.emailPasswordEnforcementState": "OFF" },
    },
    {
      ...sdk("update-sms-region", "admin.updateProjectConfig", {
        smsRegionConfig: { allowlistOnly: { allowedRegions: ["US", "JP"] } },
      }),
      settleTo: { "smsRegionConfig.allowlistOnly.allowedRegions": ["US", "JP"] },
    },
    {
      ...sdk("update-mobile-links", "admin.updateProjectConfig", {
        mobileLinksConfig: { domain: "FIREBASE_DYNAMIC_LINK_DOMAIN" },
      }),
      settleTo: { "mobileLinksConfig.domain": "FIREBASE_DYNAMIC_LINK_DOMAIN" },
    },
    sdk("get-after-updates", "admin.getProjectConfig"),
    sdk("update-unknown-member", "admin.updateProjectConfig", { autodeleteAnonymousUsers: true }),
    sdk("update-multi-factor-read-only-check", "admin.updateProjectConfig", {
      multiFactorConfig: { state: "SOMETIMES" },
    }),
  ],
};

const adminTokens = {
  id: "auth-config-sdk/sdk/admin-tokens",
  projection: "strict-unsigned-emulator",
  steps: [
    sdk("sign-up", "web.createUserWithEmailAndPassword", "EMAIL(tok)", "password123"),
    sdk("token", "web.getIdToken", false),
    sdk("verify", "admin.verifyIdToken", { $sdk: "token" }, false),
    sdk("verify-checked", "admin.verifyIdToken", { $sdk: "token" }, true),
    sdk("verify-garbage", "admin.verifyIdToken", "not-a-token", false),
    sdk("cookie", "admin.createSessionCookie", { $sdk: "token" }, 3_600_000),
    sdk("cookie-too-short", "admin.createSessionCookie", { $sdk: "token" }, 60_000),
    sdk("verify-cookie", "admin.verifySessionCookie", { $sdk: "cookie" }, false),
    sdk("verify-cookie-checked", "admin.verifySessionCookie", { $sdk: "cookie" }, true),
    sdk("verify-cookie-as-token", "admin.verifyIdToken", { $sdk: "cookie" }, false),
    sdk("get-user", "admin.getUserByEmail", "EMAIL(tok)"),
    {
      ...sdk("revoke", "admin.revokeRefreshTokens", { $sdk: "sign-up", path: "uid" }),
      delayMs: 1500,
    },
    sdk("verify-after-revoke", "admin.verifyIdToken", { $sdk: "token" }, false),
    sdk("verify-checked-after-revoke", "admin.verifyIdToken", { $sdk: "token" }, true),
    sdk(
      "verify-cookie-checked-after-revoke",
      "admin.verifySessionCookie",
      { $sdk: "cookie" },
      true,
    ),
    sdk("refresh-after-revoke", "web.getIdToken", true),
    sdk("sign-in-again", "web.signInWithEmailAndPassword", "EMAIL(tok)", "password123"),
    sdk("token-again", "web.getIdToken", false),
    sdk("disable", "admin.updateUser", { $sdk: "sign-up", path: "uid" }, { disabled: true }),
    sdk("verify-disabled", "admin.verifyIdToken", { $sdk: "token-again" }, false),
    sdk("verify-checked-disabled", "admin.verifyIdToken", { $sdk: "token-again" }, true),
    sdk("delete", "admin.deleteUser", { $sdk: "sign-up", path: "uid" }),
    sdk("verify-checked-deleted", "admin.verifyIdToken", { $sdk: "token-again" }, true),
    sdk("create-for-links", "admin.createUser", { email: "EMAIL(links)", password: "password123" }),
    sdk("reset-link", "admin.generatePasswordResetLink", "EMAIL(links)", {
      url: HOSTING,
      handleCodeInApp: false,
    }),
    sdk("reset-link-mobile", "admin.generatePasswordResetLink", "EMAIL(links)", {
      url: HOSTING,
      handleCodeInApp: true,
      iOS: { bundleId: "com.example.ios" },
      android: { packageName: "com.example.android", installApp: true, minimumVersion: "12" },
    }),
    sdk("reset-link-without-settings", "admin.generatePasswordResetLink", "EMAIL(links)"),
    sdk("reset-link-unknown", "admin.generatePasswordResetLink", "EMAIL(unknown-links)"),
    sdk("verify-link", "admin.generateEmailVerificationLink", "EMAIL(links)", { url: HOSTING }),
    sdk("sign-in-link-password-required", "admin.generateSignInWithEmailLink", "EMAIL(links)", {
      url: HOSTING,
      handleCodeInApp: true,
    }),
    sdk(
      "change-link",
      "admin.generateVerifyAndChangeEmailLink",
      "EMAIL(links)",
      "EMAIL(links-new)",
      {
        url: HOSTING,
      },
    ),
    sdk("reset-link-empty-link-domain", "admin.generatePasswordResetLink", "EMAIL(links)", {
      url: HOSTING,
      linkDomain: "",
    }),
  ],
};

const customToken = {
  id: "auth-config-sdk/sdk/custom-token",
  projection: "emulator",
  steps: [
    sdk("mint", "admin.createCustomToken", "UID(ct)"),
    sdk("mint-with-claims", "admin.createCustomToken", "UID(ct-claims)", {
      role: "editor",
      level: 3,
    }),
    sdk("mint-reserved-claim", "admin.createCustomToken", "UID(ct-reserved)", { aud: "other" }),
    sdk("mint-long-uid", "admin.createCustomToken", "u".repeat(129)),
    sdk("sign-in", "web.signInWithCustomToken", { $sdk: "mint-with-claims" }),
    sdk("token-result", "web.getIdTokenResult", false),
    sdk("verify", "admin.verifyIdToken", { $sdk: "token-result" }, true),
    sdk("get-user", "admin.getUser", "UID(ct-claims)"),
    sdk("sign-in-plain", "web.signInWithCustomToken", { $sdk: "mint" }),
    sdk("plain-token-result", "web.getIdTokenResult", true),
  ],
};

const webPasswordPolicy = {
  id: "auth-config-sdk/sdk/web-password-policy",
  projection: "strict-unsigned-emulator",
  touches: ["passwordPolicyConfig"],
  steps: [
    adminCreate("create-weak", { email: "EMAIL(weak)", password: "password" }),
    sdk("validate-default", "web.validatePassword", "password"),
    sdk("validate-default-short", "web.validatePassword", "pw"),
    setPolicy("enforce", "ENFORCE", ALL_CLASSES, { forceUpgradeOnSignin: true }),
    sdk("validate-cached", "web.validatePassword", "password"),
    sdk("create-weak-refused", "web.createUserWithEmailAndPassword", "EMAIL(new)", "password"),
    sdk("validate-refreshed", "web.validatePassword", "password"),
    sdk("validate-compliant", "web.validatePassword", "Passw0rd!"),
    sdk("validate-too-long", "web.validatePassword", "Passw0rd!Passw0rd!Pass"),
    sdk("create-compliant", "web.createUserWithEmailAndPassword", "EMAIL(new)", "Passw0rd!"),
    sdk("sign-in-weak-existing", "web.signInWithEmailAndPassword", "EMAIL(weak)", "password"),
    sdk("update-to-weak", "web.updatePassword", "password"),
    setPolicy("off", "OFF", ALL_CLASSES),
    sdk("validate-still-cached", "web.validatePassword", "password"),
    sdk("sign-in-weak-under-off", "web.signInWithEmailAndPassword", "EMAIL(weak)", "password"),
  ],
};

const webFlows = {
  id: "auth-config-sdk/sdk/web-flows",
  projection: "strict-unsigned-emulator",
  touches: [
    "emailPrivacyConfig.enableImprovedEmailPrivacy",
    "signIn.anonymous.enabled",
    "client.permissions.disabledUserSignup",
  ],
  steps: [
    sdk("sign-up", "web.createUserWithEmailAndPassword", "EMAIL(flow)", "password123"),
    sdk("current", "web.currentUser"),
    sdk("token-result", "web.getIdTokenResult", false),
    sdk("token-result-refreshed", "web.getIdTokenResult", true),
    sdk("sign-up-again", "web.createUserWithEmailAndPassword", "EMAIL(flow)", "password123"),
    sdk("update-password", "web.updatePassword", "password456"),
    sdk("reload", "web.reload"),
    sdk("sign-out", "web.signOut"),
    sdk("sign-in-wrong-password", "web.signInWithEmailAndPassword", "EMAIL(flow)", "password123"),
    sdk("sign-in-unknown", "web.signInWithEmailAndPassword", "EMAIL(nobody)", "password123"),
    sdk("sign-in", "web.signInWithEmailAndPassword", "EMAIL(flow)", "password456"),
    sdk("methods-privacy-on", "web.fetchSignInMethodsForEmail", "EMAIL(flow)"),
    setConfig("privacy-off", "emailPrivacyConfig.enableImprovedEmailPrivacy", {
      emailPrivacyConfig: { enableImprovedEmailPrivacy: false },
    }),
    sdk("methods-privacy-off", "web.fetchSignInMethodsForEmail", "EMAIL(flow)"),
    sdk("methods-unknown-privacy-off", "web.fetchSignInMethodsForEmail", "EMAIL(nobody)"),
    sdk(
      "sign-in-wrong-password-privacy-off",
      "web.signInWithEmailAndPassword",
      "EMAIL(flow)",
      "wrong-password",
    ),
    sdk(
      "sign-in-unknown-privacy-off",
      "web.signInWithEmailAndPassword",
      "EMAIL(nobody)",
      "password123",
    ),
    sdk("delete", "web.deleteUser"),
    sdk("anonymous", "web.signInAnonymously"),
    sdk("anonymous-token", "web.getIdTokenResult", false),
    setConfig("anonymous-off", "signIn.anonymous.enabled", {
      signIn: { anonymous: { enabled: false } },
    }),
    sdk("sign-out-anonymous", "web.signOut"),
    sdk("anonymous-refused", "web.signInAnonymously"),
    setConfig("signup-off", "client.permissions.disabledUserSignup", {
      client: { permissions: { disabledUserSignup: true } },
    }),
    sdk("sign-up-refused", "web.createUserWithEmailAndPassword", "EMAIL(flow-2)", "password123"),
    sdk("recaptcha-config-off", "web.initializeRecaptchaConfig"),
  ],
};

export const PROGRAMS = [
  read,
  mask,
  invalid,
  policyConfig,
  policyProjection,
  policyExisting,
  providers,
  duplicateEmail,
  emailPrivacy,
  clientPermissions,
  recaptchaProgram,
  quota,
  mobileLinks,
  otherFields,
  adminConfig,
  adminTokens,
  customToken,
  webPasswordPolicy,
  webFlows,
];
