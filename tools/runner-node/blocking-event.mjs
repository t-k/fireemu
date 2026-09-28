// The event a blocking function receives, built as Identity Platform's delivery builds it: the
// request carries an unsigned blocking token (`{"data":{"jwt":…}}`, the official Auth
// emulator's form), and the codebase's own firebase-functions parsers turn it into the user
// record and the event context, exactly as the SDK's wrapped handler does before it calls the
// handler (firebase-functions `common/providers/identity` `wrapHandler`). The runner keeps its
// own response and error handling (blocking-response.mjs, blocking-error.mjs).
import { dirname, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";

/** A blocking token's payload, decoded without verification as the SDK does under the emulator. */
export function decodeBlockingToken(jwt) {
  if (typeof jwt !== "string") throw new TypeError("the blocking token is not a string");
  const parts = jwt.split(".");
  if (parts.length !== 3) throw new TypeError("the blocking token is not a JWT");
  let payload;
  try {
    payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch {
    throw new TypeError("the blocking token's payload is not JSON");
  }
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    throw new TypeError("the blocking token's payload is not an object");
  }
  // The SDK's unsafeDecodeAuthBlockingToken names the subject as the uid.
  payload.uid = payload.sub;
  return payload;
}

/**
 * The handler's `{user, context}` for a request that carries a blocking token, or undefined
 * for one that does not. `parsers` are the SDK's `parseAuthUserRecord` and
 * `parseAuthEventContext`; the user record is parsed for the user events only.
 */
export function blockingEvent(body, parsers, projectId) {
  const jwt = body?.data?.jwt;
  if (jwt === undefined) return undefined;
  const decoded = decodeBlockingToken(jwt);
  const user =
    decoded.event_type === "beforeCreate" || decoded.event_type === "beforeSignIn"
      ? parsers.parseAuthUserRecord(decoded.user_record)
      : undefined;
  return { user, context: parsers.parseAuthEventContext(decoded, projectId) };
}

function packageRoot(require) {
  let root = dirname(require.resolve("firebase-functions"));
  for (;;) {
    const candidate = join(root, "package.json");
    if (existsSync(candidate) && JSON.parse(readFileSync(candidate, "utf8")).name === "firebase-functions")
      return root;
    const parent = dirname(root);
    if (parent === root) throw new Error("cannot locate the firebase-functions package root");
    root = parent;
  }
}

/**
 * The SDK's parsers from the codebase's firebase-functions (`lib/common/providers/identity.js`,
 * not in its public exports), or null when that SDK does not expose both there; the runner then
 * uses [`portedIdentityParsers`].
 */
export function loadIdentityParsers(require) {
  try {
    const identity = require(join(packageRoot(require), "lib", "common", "providers", "identity.js"));
    const { parseAuthUserRecord, parseAuthEventContext } = identity;
    if (typeof parseAuthUserRecord !== "function" || typeof parseAuthEventContext !== "function")
      return null;
    return { parseAuthUserRecord, parseAuthEventContext };
  } catch {
    return null;
  }
}

// A port of firebase-functions 7.3.2 `lib/common/providers/identity.js` (MIT License, Copyright
// Google LLC): the event a handler receives when the codebase's firebase-functions does not
// expose its own parsers. Identity Platform delivers the same token to every SDK version, so
// the event is built as that SDK builds it rather than refused (an SDK's own parsers are used
// whenever they can be loaded).
const EVENT_MAPPING = {
  beforeCreate: "providers/cloud.auth/eventTypes/user.beforeCreate",
  beforeSignIn: "providers/cloud.auth/eventTypes/user.beforeSignIn",
  beforeSendEmail: "providers/cloud.auth/eventTypes/user.beforeSendEmail",
  beforeSendSms: "providers/cloud.auth/eventTypes/user.beforeSendSms",
};

const utcDate = (value) => (value ? new Date(value).toUTCString() : null);

function parseMetadata(metadata) {
  return {
    creationTime: utcDate(metadata?.creation_time),
    lastSignInTime: utcDate(metadata?.last_sign_in_time),
  };
}

function parseProviderData(providerData) {
  return providerData.map((provider) => ({
    uid: provider.uid,
    displayName: provider.display_name,
    email: provider.email,
    photoURL: provider.photo_url,
    providerId: provider.provider_id,
    phoneNumber: provider.phone_number,
  }));
}

function parseDate(seconds) {
  if (!seconds) return null;
  const date = new Date(seconds * 1000);
  return isNaN(date.getTime()) ? null : date.toUTCString();
}

function parseMultiFactor(multiFactor) {
  if (!multiFactor) return null;
  const enrolledFactors = [];
  for (const factor of multiFactor.enrolled_factors || []) {
    if (!factor.uid) throw new Error("INTERNAL ASSERT FAILED: Invalid multi-factor info response");
    enrolledFactors.push({
      uid: factor.uid,
      factorId: factor.phone_number ? factor.factor_id || "phone" : factor.factor_id,
      displayName: factor.display_name,
      enrollmentTime: factor.enrollment_time ? new Date(factor.enrollment_time).toUTCString() : null,
      phoneNumber: factor.phone_number,
    });
  }
  return enrolledFactors.length > 0 ? { enrolledFactors } : null;
}

function parseAuthUserRecord(record) {
  if (!record?.uid) throw new Error("INTERNAL ASSERT FAILED: Invalid user response");
  return {
    uid: record.uid,
    email: record.email,
    emailVerified: record.email_verified,
    displayName: record.display_name,
    photoURL: record.photo_url,
    phoneNumber: record.phone_number,
    disabled: record.disabled || false,
    metadata: parseMetadata(record.metadata),
    providerData: parseProviderData(record.provider_data),
    passwordHash: record.password_hash,
    passwordSalt: record.password_salt,
    customClaims: record.custom_claims,
    tenantId: record.tenant_id,
    tokensValidAfterTime: parseDate(record.tokens_valid_after_time),
    multiFactor: parseMultiFactor(record.multi_factor),
  };
}

function parseAdditionalUserInfo(decoded) {
  let profile;
  let username;
  if (decoded.raw_user_info) {
    try {
      profile = JSON.parse(decoded.raw_user_info);
    } catch {
      // The SDK only logs an unparsable profile.
    }
  }
  if (profile) {
    if (decoded.sign_in_method === "github.com") username = profile.login;
    if (decoded.sign_in_method === "twitter.com") username = profile.screen_name;
  }
  return {
    providerId: decoded.sign_in_method === "emailLink" ? "password" : decoded.sign_in_method,
    profile,
    username,
    isNewUser: decoded.event_type === "beforeCreate",
    recaptchaScore: decoded.recaptcha_score,
    email: decoded.email,
    phoneNumber: decoded.phone_number,
  };
}

function parseAuthCredential(decoded, time) {
  if (
    !decoded.sign_in_attributes &&
    !decoded.oauth_id_token &&
    !decoded.oauth_access_token &&
    !decoded.oauth_refresh_token
  ) {
    return null;
  }
  return {
    claims: decoded.sign_in_attributes,
    idToken: decoded.oauth_id_token,
    accessToken: decoded.oauth_access_token,
    refreshToken: decoded.oauth_refresh_token,
    expirationTime: decoded.oauth_expires_in
      ? new Date(time + decoded.oauth_expires_in * 1000).toUTCString()
      : undefined,
    secret: decoded.oauth_token_secret,
    providerId: decoded.sign_in_method === "emailLink" ? "password" : decoded.sign_in_method,
    signInMethod: decoded.sign_in_method,
  };
}

function parseAuthEventContext(decoded, projectId, time = new Date().getTime()) {
  const eventType =
    (EVENT_MAPPING[decoded.event_type] || decoded.event_type) +
    (decoded.sign_in_method ? `:${decoded.sign_in_method}` : "");
  return {
    locale: decoded.locale,
    ipAddress: decoded.ip_address,
    userAgent: decoded.user_agent,
    eventId: decoded.event_id,
    eventType,
    authType: decoded.user_record ? "USER" : "UNAUTHENTICATED",
    resource: {
      service: "identitytoolkit.googleapis.com",
      name: decoded.tenant_id
        ? `projects/${projectId}/tenants/${decoded.tenant_id}`
        : `projects/${projectId}`,
    },
    timestamp: new Date(decoded.iat * 1000).toUTCString(),
    additionalUserInfo: parseAdditionalUserInfo(decoded),
    credential: parseAuthCredential(decoded, time),
    emailType: decoded.email_type,
    smsType: decoded.sms_type,
    params: {},
  };
}

/** The ported parsers ([`loadIdentityParsers`] prefers the codebase's own). */
export const portedIdentityParsers = Object.freeze({ parseAuthUserRecord, parseAuthEventContext });
