import { types } from "node:util";
import { createHash } from "node:crypto";
import {
  isProductionPayloadAuthority,
  productionPayloadAuthorityMatches,
  productionPayloadCaptureIsCovered,
  productionPayloadRequestBodyKind,
  productionPayloadStaticHeaderAllowed,
} from "./production-payload-authority.mjs";
import { parseCaptureJsonSpans, storageCaptureBodyIsCovered } from "./production-capture-body.mjs";
import {
  copyProductionCaptureBody,
  copyProductionCaptureArray,
  copyProductionCaptureRecord,
} from "./production-capture-input.mjs";
import { validateProductionSessionUri } from "./production-session.mjs";

const profiles = new WeakMap();
const controls = {
  "owner-exchange": ["POST", "oauth2", /^\/token$/],
  "owner-tokeninfo": ["POST", "oauth2", /^\/tokeninfo$/],
  "project-binding": ["GET", "cloudresourcemanager", /^\/v1\/projects\/[a-z][a-z0-9-]{4,29}$/],
  "bucket-config": ["GET", "storage", /^\/storage\/v1\/b\/[a-z0-9.-]+$/],
  "default-bucket": [
    "GET",
    "firebasestorage",
    /^\/v1alpha\/projects\/[a-z][a-z0-9-]{4,29}\/defaultBucket$/,
  ],
  "auth-config": [
    "GET",
    "identitytoolkit",
    /^\/admin\/v2\/projects\/[a-z][a-z0-9-]{4,29}\/config$/,
  ],
  "api-key-metadata": [
    "GET",
    "apikeys",
    /^\/v2\/projects\/[1-9][0-9]+\/locations\/global\/keys\/[A-Za-z0-9_-]+$/,
  ],
  "api-key-value": [
    "GET",
    "apikeys",
    /^\/v2\/projects\/[1-9][0-9]+\/locations\/global\/keys\/[A-Za-z0-9_-]+\/keyString$/,
  ],
  "rules-release": [
    "GET",
    "firebaserules",
    /^\/v1\/projects\/[a-z][a-z0-9-]{4,29}\/releases\/firebase\.storage\/[a-z0-9.-]+$/,
  ],
  "rules-bucketless": [
    "GET",
    "firebaserules",
    /^\/v1\/projects\/[a-z][a-z0-9-]{4,29}\/releases\/firebase\.storage$/,
  ],
  "rules-ruleset": [
    "GET",
    "firebaserules",
    /^\/v1\/projects\/[a-z][a-z0-9-]{4,29}\/rulesets\/[A-Za-z0-9_-]+$/,
  ],
  "rules-list": ["GET", "firebaserules", /^\/v1\/projects\/[a-z][a-z0-9-]{4,29}\/releases$/],
  "rules-release-delete": [
    "DELETE",
    "firebaserules",
    /^\/v1\/projects\/[a-z][a-z0-9-]{4,29}\/releases\/firebase\.storage\/[a-z0-9.-]+$/,
  ],
  "rules-ruleset-delete": [
    "DELETE",
    "firebaserules",
    /^\/v1\/projects\/[a-z][a-z0-9-]{4,29}\/rulesets\/[A-Za-z0-9_-]+$/,
  ],
  "auth-admin-lookup": [
    "POST",
    "identitytoolkit",
    /^\/v1\/projects\/[a-z][a-z0-9-]{4,29}\/accounts:lookup$/,
  ],
  "auth-admin-delete": [
    "POST",
    "identitytoolkit",
    /^\/v1\/projects\/[a-z][a-z0-9-]{4,29}\/accounts:delete$/,
  ],
  "auth-signup": ["POST", "identitytoolkit", /^\/v1\/accounts:signUp$/],
  "auth-token-lookup": ["POST", "identitytoolkit", /^\/v1\/accounts:lookup$/],
  "auth-signin": ["POST", "identitytoolkit", /^\/v1\/accounts:signInWithPassword$/],
  "auth-refresh": ["POST", "securetoken", /^\/v1\/token$/],
};

function dataRecord(value, keys) {
  if (!value || types.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype)
    throw new Error();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    Reflect.ownKeys(value).some(
      (key) =>
        typeof key !== "string" ||
        (keys && !keys.includes(key)) ||
        !descriptors[key].enumerable ||
        !Object.hasOwn(descriptors[key], "value"),
    )
  )
    throw new Error();
  return Object.fromEntries(
    Object.entries(descriptors).map(([key, descriptor]) => [key, descriptor.value]),
  );
}

/** The wire factory creates this original capability from its resolved route, never from request overrides. */
export function createProductionCaptureProfile(supplied) {
  try {
    const input = dataRecord(supplied, [
      "kind",
      "method",
      "url",
      "sessionPhase",
      "objectName",
      "payloadAuthority",
    ]);
    if (
      ![5, 6].includes(Object.keys(input).length) ||
      typeof input.url !== "string" ||
      !input.url.isWellFormed() ||
      ![null, "initiate", "query", "cancel", "upload", "finalize"].includes(input.sessionPhase)
    )
      throw new Error();
    const url = new URL(input.url);
    if (
      input.payloadAuthority !== undefined &&
      input.payloadAuthority !== null &&
      (!isProductionPayloadAuthority(input.payloadAuthority) ||
        !productionPayloadAuthorityMatches(input.payloadAuthority, {
          method: input.method,
          objectName: input.objectName,
          url: input.url,
        }))
    )
      throw new Error();
    if (url.username || url.password || url.hash || url.port) throw new Error();
    if (input.kind === "storage") {
      if (
        !["https://storage.googleapis.com", "https://firebasestorage.googleapis.com"].includes(
          url.origin,
        ) ||
        !["GET", "POST", "PUT", "PATCH", "DELETE"].includes(input.method) ||
        !/^\/(?:storage\/v1|upload\/storage\/v1|v0)\/b\/[a-z0-9.-]+\/o(?:\/[^/]+(?:\/(?:copyTo|rewriteTo)\/b\/[a-z0-9.-]+\/o\/[^/]+)?)?$/.test(
          url.pathname,
        )
      )
        throw new Error();
      if (
        input.objectName !== null &&
        (typeof input.objectName !== "string" ||
          !input.objectName.isWellFormed() ||
          input.objectName.length === 0)
      )
        throw new Error();
    } else {
      const row = typeof input.kind === "string" && controls[input.kind];
      if (
        !row ||
        input.method !== row[0] ||
        url.origin !== `https://${row[1]}.googleapis.com` ||
        !row[2].test(url.pathname) ||
        input.sessionPhase !== null ||
        input.objectName !== null
      )
        throw new Error();
    }
    const profile = Object.freeze({});
    profiles.set(profile, Object.freeze(input));
    return profile;
  } catch {
    throw new Error("invalid production capture profile");
  }
}

export function isProductionCaptureProfile(value) {
  return profiles.has(value);
}

export function productionCaptureRequestBodyKind(value) {
  return productionPayloadRequestBodyKind(profiles.get(value)?.payloadAuthority);
}
export function approvedProductionCaptureBodySha256(value, direction, body) {
  const profile = profiles.get(value);
  if (!profile || !productionPayloadCaptureIsCovered(profile.payloadAuthority, direction, body))
    return [];
  return [createHash("sha256").update(copyProductionCaptureBody(body)).digest("hex")];
}

const string = (value) => typeof value === "string" && value.isWellFormed() && value.length <= 8192;
const text = (value) => typeof value === "string" && value.isWellFormed() && value.length <= 131072;
const digits = (value) => typeof value === "string" && /^[0-9]{1,20}$/.test(value);
const boolean = (value) => typeof value === "boolean";
const integer = (value) => Number.isSafeInteger(value) && value >= 0;
const literal =
  (...values) =>
  (value) =>
    values.includes(value);
const array =
  (check, maximum = 100) =>
  (value) =>
    Array.isArray(value) && value.length <= maximum && value.every(check);
const schema =
  (fields, required = []) =>
  (value) =>
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    required.every((key) => Object.hasOwn(value, key)) &&
    Object.entries(value).every(([key, child]) => Object.hasOwn(fields, key) && fields[key](child));
const empty = schema({});
const pattern = (expression) => (value) => string(value) && expression.test(value);
const timestamp = pattern(
  /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})$/,
);
// Unbound custom maps have no nonsecret component inventory, even when each value is a string.
const labelMap = empty;
const base64 = (value) => {
  if (!string(value)) return false;
  const bytes = Buffer.from(value, "base64"),
    standard = bytes.toString("base64"),
    url = bytes.toString("base64url");
  return [
    standard,
    standard.replace(/=+$/, ""),
    url,
    url + "=".repeat((4 - (url.length % 4)) % 4),
  ].includes(value);
};
const storageClass = literal(
  "STANDARD",
  "NEARLINE",
  "COLDLINE",
  "ARCHIVE",
  "MULTI_REGIONAL",
  "REGIONAL",
  "DURABLE_REDUCED_AVAILABILITY",
);
const bucketConfiguration = schema(
  {
    kind: literal("storage#bucket"),
    id: string,
    name: string,
    selfLink: string,
    projectNumber: digits,
    generation: digits,
    metageneration: digits,
    location: pattern(/^[A-Za-z0-9-]{1,64}$/),
    locationType: literal("region", "dual-region", "multi-region"),
    storageClass,
    etag: string,
    timeCreated: timestamp,
    updated: timestamp,
    softDeleteTime: timestamp,
    hardDeleteTime: timestamp,
    defaultEventBasedHold: boolean,
    hierarchicalNamespace: schema({ enabled: boolean }),
    iamConfiguration: schema({
      publicAccessPrevention: literal("inherited", "enforced"),
      uniformBucketLevelAccess: schema({ enabled: boolean, lockedTime: timestamp }),
      bucketPolicyOnly: schema({ enabled: boolean, lockedTime: timestamp }),
    }),
    softDeletePolicy: schema({ retentionDurationSeconds: digits, effectiveTime: timestamp }),
    versioning: schema({ enabled: boolean }),
    autoclass: schema({
      enabled: boolean,
      toggleTime: timestamp,
      terminalStorageClass: literal("NEARLINE", "ARCHIVE"),
      terminalStorageClassUpdateTime: timestamp,
    }),
    billing: schema({ requesterPays: boolean }),
    retentionPolicy: schema({
      retentionPeriod: digits,
      effectiveTime: timestamp,
      isLocked: boolean,
    }),
    objectRetention: schema({ mode: literal("Enabled", "Disabled") }),
    labels: labelMap,
    customPlacementConfig: schema({ dataLocations: array(pattern(/^[A-Za-z0-9-]{1,64}$/), 2) }),
    rpo: literal("DEFAULT", "ASYNC_TURBO"),
    encryption: schema({
      defaultKmsKeyName: string,
      googleManagedEncryptionEnforcementConfig: schema({
        restrictionMode: literal("NotRestricted", "FullyRestricted"),
        effectiveTime: timestamp,
      }),
      customerManagedEncryptionEnforcementConfig: schema({
        restrictionMode: literal("NotRestricted", "FullyRestricted"),
        effectiveTime: timestamp,
      }),
      customerSuppliedEncryptionEnforcementConfig: schema({
        restrictionMode: literal("NotRestricted", "FullyRestricted"),
        effectiveTime: timestamp,
      }),
    }),
    cors: array(
      schema({
        origin: array(string),
        method: array(literal("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "*")),
        responseHeader: array(string),
        maxAgeSeconds: integer,
      }),
    ),
    logging: schema({ logBucket: string, logObjectPrefix: string }),
    website: schema({ mainPageSuffix: string, notFoundPage: string }),
    owner: schema({ entity: string, entityId: string }),
    lifecycle: schema({
      rule: array(
        schema({
          action: schema({
            storageClass,
            type: literal("Delete", "SetStorageClass", "AbortIncompleteMultipartUpload"),
          }),
          condition: schema({
            age: integer,
            createdBefore: pattern(/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/),
            isLive: boolean,
            numNewerVersions: integer,
            matchesStorageClass: array(storageClass),
            daysSinceCustomTime: integer,
            customTimeBefore: pattern(/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/),
            daysSinceNoncurrentTime: integer,
            noncurrentTimeBefore: pattern(/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/),
            matchesPrefix: array(string),
            matchesSuffix: array(string),
            sizeAboveBytes: integer,
            sizeBelowBytes: integer,
          }),
        }),
      ),
    }),
  },
  ["name"],
);
const emailTemplate = schema({
  senderLocalPart: string,
  subject: string,
  senderDisplayName: string,
  body: text,
  bodyFormat: literal("BODY_FORMAT_UNSPECIFIED", "PLAIN_TEXT", "HTML"),
  replyTo: string,
  customized: boolean,
});
const authConfiguration = schema(
  {
    name: pattern(/^projects\/[a-z][a-z0-9-]{4,29}\/config$/),
    subtype: literal("FIREBASE_AUTH", "IDENTITY_PLATFORM"),
    signIn: schema({
      email: schema({ enabled: boolean, passwordRequired: boolean }),
      phoneNumber: schema({ enabled: boolean, testPhoneNumbers: empty }),
      anonymous: schema({ enabled: boolean }),
      allowDuplicateEmails: boolean,
      hashConfig: schema({
        algorithm: literal(
          "HASH_ALGORITHM_UNSPECIFIED",
          "HMAC_SHA256",
          "HMAC_SHA1",
          "HMAC_MD5",
          "SCRYPT",
          "PBKDF_SHA1",
          "MD5",
          "HMAC_SHA512",
          "SHA1",
          "BCRYPT",
          "PBKDF2_SHA256",
          "SHA256",
          "SHA512",
          "STANDARD_SCRYPT",
        ),
        signerKey: base64,
        saltSeparator: base64,
        rounds: integer,
        memoryCost: integer,
      }),
    }),
    authorizedDomains: array(pattern(/^[a-zA-Z0-9.-]{1,253}$/)),
    client: schema({
      apiKey: string,
      permissions: schema({ disabledUserSignup: boolean, disabledUserDeletion: boolean }),
      firebaseSubdomain: string,
    }),
    notification: schema({
      sendEmail: schema({
        method: literal("METHOD_UNSPECIFIED", "DEFAULT", "CUSTOM_SMTP"),
        resetPasswordTemplate: emailTemplate,
        verifyEmailTemplate: emailTemplate,
        changeEmailTemplate: emailTemplate,
        legacyResetPasswordTemplate: emailTemplate,
        revertSecondFactorAdditionTemplate: emailTemplate,
        callbackUri: string,
        dnsInfo: schema({
          customDomain: string,
          useCustomDomain: boolean,
          pendingCustomDomain: string,
          customDomainState: literal(
            "VERIFICATION_STATE_UNSPECIFIED",
            "NOT_REQUESTED",
            "PENDING",
            "VERIFIED",
            "FAILED",
          ),
          domainVerificationRequestTime: timestamp,
        }),
        smtp: schema({
          senderEmail: string,
          host: string,
          port: (value) => integer(value) && value <= 65535,
          username: string,
          password: string,
          securityMode: literal("SECURITY_MODE_UNSPECIFIED", "SSL", "START_TLS"),
        }),
      }),
      sendSms: schema({ useDeviceLocale: boolean, smsTemplate: schema({ content: text }) }),
      defaultLocale: string,
    }),
    quota: schema({
      signUpQuotaConfig: schema({
        quota: digits,
        startTime: timestamp,
        quotaDuration: pattern(/^[0-9]+(?:\.[0-9]{1,9})?s$/),
      }),
    }),
    monitoring: schema({ requestLogging: schema({ enabled: boolean }) }),
    multiTenant: schema({ allowTenants: boolean, defaultTenantLocation: string }),
    mfa: schema({
      state: literal("STATE_UNSPECIFIED", "DISABLED", "ENABLED", "MANDATORY"),
      enabledProviders: array(literal("PROVIDER_UNSPECIFIED", "PHONE_SMS")),
      providerConfigs: array(
        schema({
          state: literal("MFA_STATE_UNSPECIFIED", "DISABLED", "ENABLED", "MANDATORY"),
          totpProviderConfig: schema({ adjacentIntervals: integer }),
        }),
      ),
    }),
    blockingFunctions: empty,
    recaptchaConfig: schema({
      managedRules: array(
        schema({
          endScore: (value) => typeof value === "number" && value >= 0 && value <= 1,
          action: literal("RECAPTCHA_ACTION_UNSPECIFIED", "BLOCK"),
        }),
      ),
      recaptchaKeys: array(
        schema({
          key: string,
          type: literal("RECAPTCHA_KEY_CLIENT_TYPE_UNSPECIFIED", "WEB", "ANDROID", "IOS"),
        }),
      ),
      tollFraudManagedRules: array(
        schema({
          startScore: (value) => typeof value === "number" && value >= 0 && value <= 1,
          action: literal("RECAPTCHA_ACTION_UNSPECIFIED", "BLOCK"),
        }),
      ),
      emailPasswordEnforcementState: literal(
        "RECAPTCHA_PROVIDER_ENFORCEMENT_STATE_UNSPECIFIED",
        "OFF",
        "AUDIT",
        "ENFORCE",
      ),
      phoneEnforcementState: literal(
        "RECAPTCHA_PROVIDER_ENFORCEMENT_STATE_UNSPECIFIED",
        "OFF",
        "AUDIT",
        "ENFORCE",
      ),
      useAccountDefender: boolean,
      useSmsBotScore: boolean,
      useSmsTollFraudProtection: boolean,
    }),
    smsRegionConfig: (value) =>
      schema({
        allowByDefault: schema({ disallowedRegions: array(pattern(/^[A-Z]{2}$/)) }),
        allowlistOnly: schema({ allowedRegions: array(pattern(/^[A-Z]{2}$/)) }),
      })(value) && Object.keys(value).length <= 1,
    autodeleteAnonymousUsers: boolean,
    passwordPolicyConfig: schema({
      passwordPolicyEnforcementState: literal(
        "PASSWORD_POLICY_ENFORCEMENT_STATE_UNSPECIFIED",
        "OFF",
        "ENFORCE",
      ),
      passwordPolicyVersions: array(
        schema({
          schemaVersion: integer,
          customStrengthOptions: schema({
            minPasswordLength: integer,
            maxPasswordLength: integer,
            containsLowercaseCharacter: boolean,
            containsUppercaseCharacter: boolean,
            containsNumericCharacter: boolean,
            containsNonAlphanumericCharacter: boolean,
          }),
        }),
        1,
      ),
      forceUpgradeOnSignin: boolean,
      lastUpdateTime: timestamp,
    }),
    emailPrivacyConfig: schema({ enableImprovedEmailPrivacy: boolean }),
    mobileLinksConfig: schema({
      domain: literal("DOMAIN_UNSPECIFIED", "FIREBASE_DYNAMIC_LINK_DOMAIN", "HOSTING_DOMAIN"),
    }),
    defaultHostingSite: string,
  },
  ["name", "subtype", "signIn"],
);
const keyRestrictions = (value) =>
  schema({
    apiTargets: array(
      schema(
        {
          service: pattern(/^[A-Za-z0-9.-]+\.googleapis\.com$/),
          methods: array(pattern(/^[A-Za-z0-9._*-]{1,256}$/)),
        },
        ["service"],
      ),
      100,
    ),
    browserKeyRestrictions: schema({ allowedReferrers: array(string) }),
    serverKeyRestrictions: schema({ allowedIps: array(string) }),
    androidKeyRestrictions: schema({
      allowedApplications: array(schema({ sha1Fingerprint: string, packageName: string })),
    }),
    iosKeyRestrictions: schema({ allowedBundleIds: array(string) }),
  })(value) &&
  [
    "browserKeyRestrictions",
    "serverKeyRestrictions",
    "androidKeyRestrictions",
    "iosKeyRestrictions",
  ].filter((key) => Object.hasOwn(value, key)).length <= 1;
const user = schema({
  localId: string,
  email: string,
  emailVerified: boolean,
  disabled: boolean,
  displayName: string,
  photoUrl: string,
  passwordHash: string,
  salt: string,
  rawPassword: string,
  passwordUpdatedAt: integer,
  validSince: digits,
  createdAt: digits,
  lastLoginAt: digits,
  lastRefreshAt: string,
  customAuth: boolean,
  customAttributes: string,
  initialEmail: string,
  providerUserInfo: array(
    schema({
      providerId: string,
      rawId: string,
      federatedId: string,
      displayName: string,
      email: string,
      photoUrl: string,
    }),
  ),
  tenantId: string,
  phoneNumber: string,
});
const release = schema(
  { name: string, rulesetName: string, createTime: string, updateTime: string },
  ["name", "rulesetName"],
);
const ruleset = schema(
  {
    name: string,
    createTime: string,
    source: schema(
      {
        files: array(
          schema({ name: string, content: text, fingerprint: string }, ["name", "content"]),
          10,
        ),
        language: literal("FIREBASE_RULES"),
      },
      ["files"],
    ),
    metadata: schema({ services: array(string, 10) }),
  },
  ["name", "source"],
);
const lookup = schema({
  kind: literal("identitytoolkit#GetAccountInfoResponse"),
  users: array(user, 2),
});
const auth = schema(
  {
    kind: string,
    localId: string,
    email: string,
    displayName: string,
    idToken: string,
    refreshToken: string,
    expiresIn: digits,
    registered: boolean,
  },
  ["localId", "idToken", "refreshToken", "expiresIn"],
);
const responseSchemas = {
  "owner-exchange": schema(
    {
      access_token: string,
      id_token: string,
      token_type: literal("Bearer", "bearer"),
      expires_in: (value) => integer(value) && value > 0 && value <= 3600,
      scope: string,
    },
    ["access_token", "token_type", "expires_in"],
  ),
  "owner-tokeninfo": schema(
    {
      sub: string,
      azp: string,
      aud: string,
      scope: string,
      expires_in: (value) => digits(value) || integer(value),
      exp: (value) => digits(value) || integer(value),
      access_type: string,
      email: string,
      email_verified: (value) => string(value) || boolean(value),
    },
    ["sub", "azp", "aud", "scope", "expires_in"],
  ),
  "auth-signup": auth,
  "auth-signin": auth,
  "auth-refresh": schema(
    {
      access_token: string,
      id_token: string,
      refresh_token: string,
      token_type: literal("Bearer", "bearer"),
      expires_in: digits,
      user_id: string,
      project_id: string,
    },
    ["id_token", "refresh_token", "expires_in", "user_id", "project_id"],
  ),
  "auth-admin-lookup": lookup,
  "auth-token-lookup": lookup,
  "auth-admin-delete": schema({ kind: literal("identitytoolkit#DeleteAccountResponse") }),
  "rules-release": release,
  "rules-ruleset": ruleset,
  "rules-list": schema({ releases: array(release), nextPageToken: string }),
  "rules-release-delete": empty,
  "rules-ruleset-delete": empty,
  "api-key-value": schema({ keyString: string }, ["keyString"]),
  "default-bucket": schema(
    { name: string, location: string, bucket: schema({ name: string }, ["name"]), storageClass },
    ["name", "bucket"],
  ),
  "project-binding": schema(
    {
      projectNumber: digits,
      projectId: pattern(/^[a-z][a-z0-9-]{4,29}$/),
      lifecycleState: literal(
        "LIFECYCLE_STATE_UNSPECIFIED",
        "ACTIVE",
        "DELETE_REQUESTED",
        "DELETE_IN_PROGRESS",
      ),
      name: string,
      createTime: timestamp,
      labels: labelMap,
      parent: schema({ type: literal("organization", "folder"), id: digits }, ["type", "id"]),
      tags: empty,
      configuredCapabilities: array(string),
    },
    ["projectId", "projectNumber"],
  ),
  "bucket-config": bucketConfiguration,
  "auth-config": authConfiguration,
  "api-key-metadata": schema(
    {
      name: pattern(/^projects\/[1-9][0-9]+\/locations\/global\/keys\/[A-Za-z0-9_-]+$/),
      uid: string,
      displayName: string,
      keyString: string,
      createTime: timestamp,
      updateTime: timestamp,
      deleteTime: timestamp,
      annotations: empty,
      restrictions: keyRestrictions,
      etag: string,
      serviceAccountEmail: string,
    },
    ["name"],
  ),
};
const requestSchemas = {
  "auth-signup": schema({ email: string, password: string, returnSecureToken: boolean }, [
    "email",
    "password",
    "returnSecureToken",
  ]),
  "auth-signin": schema({ email: string, password: string, returnSecureToken: boolean }, [
    "email",
    "password",
    "returnSecureToken",
  ]),
  "auth-token-lookup": schema({ idToken: string }, ["idToken"]),
  "auth-admin-lookup": schema({
    localId: array(string, 2),
    email: array(string, 2),
    targetProjectId: string,
  }),
  "auth-admin-delete": schema({ localId: string, targetProjectId: string }, [
    "localId",
    "targetProjectId",
  ]),
};

function json(body) {
  const value = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(body);
  parseCaptureJsonSpans(value);
  return JSON.parse(value);
}
function form(body) {
  const encoded = new TextDecoder("utf-8", { fatal: true }).decode(body),
    result = Object.create(null);
  for (const row of encoded.split("&")) {
    const offset = row.indexOf("="),
      decode = (value) => decodeURIComponent(value.replaceAll("+", " "));
    if (offset < 1) throw new Error();
    const key = decode(row.slice(0, offset)),
      value = decode(row.slice(offset + 1));
    if (Object.hasOwn(result, key) || !string(value)) throw new Error();
    result[key] = value;
  }
  return result;
}
function sessionUri(value, url, bucket, objectName) {
  try {
    const prefix = /^storage-object\/[a-z0-9]{8,32}\//.exec(objectName)?.[0];
    validateProductionSessionUri(value, {
      dialect: url.origin === "https://storage.googleapis.com" ? "gcs" : "firebase",
      bucket,
      prefix,
      objectName,
    });
    return true;
  } catch {
    return false;
  }
}
function headersCovered(headers, input, profile) {
  const url = new URL(profile.url),
    seen = new Set();
  for (const [name, value] of headers) {
    const key = name.toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    if (
      input.direction === "request" &&
      productionPayloadStaticHeaderAllowed(profile.payloadAuthority, key, value)
    )
      continue;
    let allowed = false;
    if (key === "content-type")
      allowed = [
        "application/json",
        "application/json; charset=UTF-8",
        "application/json; charset=utf-8",
        "application/octet-stream",
        "text/plain",
        "text/plain; charset=UTF-8",
        "text/plain; charset=utf-8",
        "application/x-www-form-urlencoded",
        "application/x-www-form-urlencoded;charset=UTF-8",
        "application/x-www-form-urlencoded; charset=UTF-8",
      ].includes(value);
    else if (key === "content-length") allowed = value === String(input.body.length);
    else if (key === "host") allowed = input.direction === "request" && value === url.host;
    else if (key === "connection") allowed = value === "close";
    else if (["content-encoding", "accept-encoding"].includes(key)) allowed = value === "identity";
    else if (key === "accept")
      allowed = ["application/json", "application/octet-stream", "*/*"].includes(value);
    else if (key === "authorization")
      allowed = /^(?:Bearer|Firebase) [\x21-\x7e]{1,8192}$/.test(value);
    else if (key === "x-goog-user-project")
      allowed = input.direction === "request" && /^[a-z][a-z0-9-]{4,29}$/.test(value);
    else if (key === "transfer-encoding")
      allowed = input.direction === "response" && value === "chunked";
    else if (key === "server")
      allowed =
        input.direction === "response" &&
        ["UploadServer", "ESF", "GSE", "Google Frontend"].includes(value);
    else if (["date", "expires", "last-modified"].includes(key))
      allowed =
        /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), [0-9]{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT$/.test(
          value,
        );
    else if (key === "x-guploader-uploadid") allowed = /^[\x21-\x7e]{1,8192}$/.test(value);
    else if (["location", "x-goog-upload-url", "x-goog-upload-control-url"].includes(key))
      allowed =
        profile.sessionPhase !== null &&
        sessionUri(value, url, input.expectedBucket, profile.objectName);
    else if (key === "x-firebase-storage-download-tokens")
      allowed = value.split(",").every((part) => /^[A-Za-z0-9_+/-]{1,8192}$/.test(part.trim()));
    else if (
      [
        "x-goog-generation",
        "x-goog-metageneration",
        "x-goog-stored-content-length",
        "x-goog-upload-offset",
        "x-goog-upload-size-received",
        "x-goog-upload-header-content-length",
        "x-upload-content-length",
      ].includes(key)
    )
      allowed = digits(value);
    else if (key === "x-goog-upload-protocol") allowed = value === "resumable";
    else if (["x-upload-content-type", "x-goog-upload-header-content-type"].includes(key))
      allowed = value === "application/octet-stream";
    else if (key === "content-range")
      allowed =
        input.direction === "request" &&
        profile.sessionPhase !== null &&
        /^(?:bytes \*\/[1-9][0-9]{0,15}|bytes (?:0|[1-9][0-9]{0,15})-(?:0|[1-9][0-9]{0,15})\/[1-9][0-9]{0,15})$/.test(
          value,
        );
    else if (key === "range")
      allowed =
        input.direction === "response" &&
        profile.sessionPhase !== null &&
        /^bytes=0-[0-9]{1,16}$/.test(value);
    else if (key === "x-goog-upload-command")
      allowed = ["start", "query", "upload", "upload, finalize", "cancel"].includes(value);
    else if (key === "x-goog-upload-status")
      allowed = ["active", "final", "cancelled"].includes(value);
    else if (key === "x-content-type-options") allowed = value === "nosniff";
    if (!allowed) return false;
  }
  return true;
}

/** Closed schemas establish discovery coverage; persistence mode and semantic owner/Auth/Rules proof are separate. */
export function productionCaptureIsCovered(capability, supplied) {
  try {
    const profile = profiles.get(capability);
    if (!profile) return false;
    const input = copyProductionCaptureRecord(supplied, [
      "url",
      "direction",
      "status",
      "complete",
      "headers",
      "body",
      "bodyKind",
      "expectedObjectNames",
      "expectedBucket",
    ]);
    input.body = copyProductionCaptureBody(input.body);
    input.expectedObjectNames = copyProductionCaptureArray(input.expectedObjectNames, 16384);
    input.headers = copyProductionCaptureArray(input.headers, 256).map((pair) => {
      const copy = copyProductionCaptureArray(pair, 2);
      if (
        copy.length !== 2 ||
        typeof copy[0] !== "string" ||
        typeof copy[1] !== "string" ||
        !/^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,128}$/.test(copy[0]) ||
        !copy[1].isWellFormed() ||
        copy[1].length > 16384 ||
        /[\r\n]/.test(copy[1])
      )
        throw new Error();
      return copy;
    });
    const storageOptions = {
      bodyKind: input.bodyKind,
      expectedObjectNames: input.expectedObjectNames,
      expectedBucket: input.expectedBucket,
    };
    if (
      Object.keys(input).length !== 9 ||
      input.url !== profile.url ||
      input.complete !== true ||
      !["request", "response"].includes(input.direction) ||
      !Buffer.isBuffer(input.body) ||
      !["json", "media"].includes(input.bodyKind) ||
      !headersCovered(input.headers, input, profile)
    )
      return false;
    if (input.direction === "request") {
      if (input.status !== null) return false;
      if (input.body.length === 0)
        return ![
          "auth-signup",
          "auth-signin",
          "auth-admin-lookup",
          "auth-admin-delete",
          "auth-refresh",
          "auth-token-lookup",
          "owner-exchange",
        ].includes(profile.kind);
      if (profile.kind === "storage")
        return input.bodyKind === "media"
          ? productionPayloadCaptureIsCovered(profile.payloadAuthority, "request", input.body)
          : storageCaptureBodyIsCovered(input.body, storageOptions);
      if (profile.kind === "owner-exchange")
        return schema(
          {
            grant_type: literal("refresh_token"),
            client_id: string,
            client_secret: string,
            refresh_token: string,
          },
          ["grant_type", "client_id", "client_secret", "refresh_token"],
        )(form(input.body));
      if (profile.kind === "auth-refresh")
        return schema({ grant_type: literal("refresh_token"), refresh_token: string }, [
          "grant_type",
          "refresh_token",
        ])(form(input.body));
      return requestSchemas[profile.kind]?.(json(input.body)) === true;
    }
    if (
      !Number.isSafeInteger(input.status) ||
      ![200, 201, 204, 206, 308, 400, 401, 403, 404, 409, 412].includes(input.status)
    )
      return false;
    if (profile.kind === "storage") {
      if (input.status >= 400) {
        const value = json(input.body);
        return (
          Object.keys(value).length === 1 &&
          Object.hasOwn(value, "error") &&
          value.error?.code === input.status &&
          storageCaptureBodyIsCovered(input.body, { ...storageOptions, bodyKind: "json" })
        );
      }
      if (input.body.length === 0 || input.body.equals(Buffer.from("OK"))) {
        if (input.bodyKind === "media")
          return productionPayloadCaptureIsCovered(
            profile.payloadAuthority,
            "response",
            input.body,
          );
        if (profile.sessionPhase === "initiate")
          return (
            input.status === 200 &&
            input.headers.some(([name]) =>
              ["location", "x-goog-upload-url"].includes(name.toLowerCase()),
            )
          );
        if (["query", "upload"].includes(profile.sessionPhase))
          return [200, 308].includes(input.status);
        if (profile.sessionPhase === "cancel") return input.status === 200;
        return (
          input.body.length === 0 &&
          ["GET", "DELETE"].includes(profile.method) &&
          [200, 204].includes(input.status)
        );
      }
      if (input.bodyKind === "media")
        return productionPayloadCaptureIsCovered(profile.payloadAuthority, "response", input.body);
      return input.status !== 308 && storageCaptureBodyIsCovered(input.body, storageOptions);
    }
    const value = json(input.body);
    if (input.status !== 200)
      return (
        input.status === 404 &&
        profile.kind.startsWith("rules-") &&
        schema(
          {
            error: schema(
              {
                code: literal(404),
                status: literal("NOT_FOUND"),
                message: literal("Not Found", "Requested entity was not found."),
              },
              ["code", "message"],
            ),
          },
          ["error"],
        )(value)
      );
    return responseSchemas[profile.kind]?.(value) === true;
  } catch {
    return false;
  }
}
