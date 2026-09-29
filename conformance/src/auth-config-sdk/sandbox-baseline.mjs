// The sandbox baseline of AUTH-CONFIG-SDK: every config path its corpus may change, at the value the
// sandbox holds between runs.
//
// A module of its own, with no side effects, because the runner and the harness registry (which
// puts the value into the lane's harness digest) both read it.

import { TEST_PHONES, TEST_PHONE_CODE } from "../auth-account/harness.mjs";

/**
 * Every config path this corpus may change, at the value the sandbox holds between runs (read
 * 2026-09-25). Production is required to hold it before and after each recording; fireemu is
 * given the sign-in part and the authorized domains, the rest being its own defaults.
 */
export const SANDBOX_BASELINE = {
  "signIn.email.enabled": true,
  "signIn.email.passwordRequired": true,
  "signIn.anonymous.enabled": true,
  "signIn.phoneNumber.enabled": true,
  "signIn.phoneNumber.testPhoneNumbers": Object.fromEntries(
    TEST_PHONES.map((p) => [p, TEST_PHONE_CODE]),
  ),
  authorizedDomains: ["{project}.firebaseapp.com", "{project}.web.app"],
  "signIn.allowDuplicateEmails": undefined,
  "emailPrivacyConfig.enableImprovedEmailPrivacy": true,
  passwordPolicyConfig: undefined,
  "client.permissions.disabledUserSignup": undefined,
  "client.permissions.disabledUserDeletion": undefined,
  // Once written, production keeps a reCAPTCHA config: clearing it leaves both providers
  // unspecified (sandbox, 2026-09-24 22:2xZ). It answers clients as an unset one does.
  recaptchaConfig: {
    emailPasswordEnforcementState: "RECAPTCHA_PROVIDER_ENFORCEMENT_STATE_UNSPECIFIED",
    phoneEnforcementState: "RECAPTCHA_PROVIDER_ENFORCEMENT_STATE_UNSPECIFIED",
    useSmsBotScore: false,
    useSmsTollFraudProtection: false,
  },
  "quota.signUpQuotaConfig": undefined,
  "mobileLinksConfig.domain": "HOSTING_DOMAIN",
  smsRegionConfig: { allowByDefault: {} },
  "notification.defaultLocale": "en",
  "notification.sendEmail.resetPasswordTemplate.subject": "Reset your password for %APP_NAME%",
  autodeleteAnonymousUsers: undefined,
  "monitoring.requestLogging.enabled": undefined,
};
