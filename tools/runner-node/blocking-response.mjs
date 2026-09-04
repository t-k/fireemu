const disallowedClaims = [
  "acr",
  "amr",
  "at_hash",
  "aud",
  "auth_time",
  "azp",
  "cnf",
  "c_hash",
  "exp",
  "iat",
  "iss",
  "jti",
  "nbf",
  "nonce",
  "firebase",
];

const claimsMaxPayloadSize = 1000;

function validateClaims(name, claims, HttpsError) {
  if (!claims) return;
  const invalid = disallowedClaims.filter((claim) =>
    Object.prototype.hasOwnProperty.call(claims, claim),
  );
  if (invalid.length > 0) {
    throw new HttpsError(
      "invalid-argument",
      `The ${name} claims "${invalid.join(",")}" are reserved and cannot be specified.`,
    );
  }
  if (JSON.stringify(claims).length > claimsMaxPayloadSize) {
    throw new HttpsError(
      "invalid-argument",
      `The ${name} payload should not exceed ${claimsMaxPayloadSize} characters.`,
    );
  }
}

function validateBlockingResult(value, eventType, HttpsError) {
  if (!value || typeof value !== "object") return;
  const hasWireRecord = Object.prototype.hasOwnProperty.call(value, "userRecord");
  const authRequest = hasWireRecord ? value.userRecord : value;
  if (
    !authRequest ||
    typeof authRequest !== "object" ||
    Array.isArray(authRequest)
  ) {
    throw new HttpsError("invalid-argument", "The userRecord response must be an object.");
  }
  validateClaims("customClaims", authRequest.customClaims, HttpsError);
  if (!String(eventType).includes("beforeSignIn") || !authRequest.sessionClaims) return;
  validateClaims("sessionClaims", authRequest.sessionClaims, HttpsError);
  const combined = { ...authRequest.customClaims, ...authRequest.sessionClaims };
  if (JSON.stringify(combined).length > claimsMaxPayloadSize) {
    throw new HttpsError(
      "invalid-argument",
      `The customClaims and sessionClaims payloads should not exceed ${claimsMaxPayloadSize} characters combined.`,
    );
  }
}

export function blockingResult(value, eventType, HttpsError) {
  if (!value || typeof value !== "object") return {};
  validateBlockingResult(value, eventType, HttpsError);
  if (Object.prototype.hasOwnProperty.call(value, "userRecord")) return value;
  const userRecord = {};
  const updateMask = [];
  for (const [publicName, wireName] of [
    ["displayName", "displayName"],
    ["photoURL", "photoUrl"],
    ["disabled", "disabled"],
    ["emailVerified", "emailVerified"],
    ["customClaims", "customClaims"],
    ["sessionClaims", "sessionClaims"],
  ]) {
    if (Object.prototype.hasOwnProperty.call(value, publicName)) {
      userRecord[wireName] = value[publicName];
      updateMask.push(wireName);
    }
  }
  return updateMask.length > 0
    ? { userRecord: { ...userRecord, updateMask: updateMask.join(",") } }
    : {};
}
