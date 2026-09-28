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
  if (claims === undefined || claims === null) return;
  if (typeof claims !== "object" || Array.isArray(claims)) {
    throw new HttpsError("invalid-argument", `The ${name} response must be an object or null.`);
  }
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
  if (!String(eventType).includes("beforeSignIn")) return;
  validateClaims("sessionClaims", authRequest.sessionClaims, HttpsError);
  if (authRequest.sessionClaims === undefined || authRequest.sessionClaims === null) return;
  const combined = { ...authRequest.customClaims, ...authRequest.sessionClaims };
  if (JSON.stringify(combined).length > claimsMaxPayloadSize) {
    throw new HttpsError(
      "invalid-argument",
      `The customClaims and sessionClaims payloads should not exceed ${claimsMaxPayloadSize} characters combined.`,
    );
  }
}

// Validate the representation that will actually cross the HTTP boundary. Callback
// objects can contain getters/toJSON and can remain aliased to user code. Evaluating
// those objects again after validation can change claims, sizes, or the update mask.
// JSON materialization is deliberately before claim checks; the returned value has
// no user getters or callable toJSON hooks and shares no objects with the callback.
function snapshotResponse(candidate, HttpsError) {
  let snapshot;
  try {
    snapshot = JSON.parse(JSON.stringify(candidate));
  } catch {
    // Do not include a thrown value, circular-object path, or credential in the error.
    throw new HttpsError("invalid-argument", "The blocking response must be JSON serializable.");
  }
  if (
    !snapshot ||
    typeof snapshot !== "object" ||
    Array.isArray(snapshot) ||
    !Object.prototype.hasOwnProperty.call(snapshot, "userRecord") ||
    !snapshot.userRecord ||
    typeof snapshot.userRecord !== "object" ||
    Array.isArray(snapshot.userRecord)
  ) {
    throw new HttpsError("invalid-argument", "The userRecord response must be an object.");
  }
  return snapshot;
}

function freezeResponse(snapshot) {
  const pending = [snapshot];
  while (pending.length > 0) {
    const value = pending.pop();
    if (value && typeof value === "object") {
      for (const child of Object.values(value)) pending.push(child);
      Object.freeze(value);
    }
  }
  return snapshot;
}

// The customClaims text as the function's JSON.stringify gives it: what the Functions SDK sends
// Identity Platform, which production reads back as `customAttributes` with its key order
// (AUTH-TENANT-BLOCKING recording 2026-09-28). The runner owns this member; the daemon uses the
// text only when it parses to the claims it applies.
const CUSTOM_CLAIMS_TEXT = "fireemuCustomClaimsText";

function attachCustomClaimsText(snapshot) {
  delete snapshot[CUSTOM_CLAIMS_TEXT];
  // validateBlockingResult has admitted only an object, null or no claims.
  const claims = snapshot.userRecord.customClaims;
  if (claims != null) snapshot[CUSTOM_CLAIMS_TEXT] = JSON.stringify(claims);
  return snapshot;
}

export function blockingResult(value, eventType, HttpsError) {
  // Preserve the runner's established no-result behaviour.
  if (!value || typeof value !== "object") return {};
  if (Array.isArray(value)) {
    throw new HttpsError("invalid-argument", "The userRecord response must be an object.");
  }
  let candidate;
  try {
    if (Object.prototype.hasOwnProperty.call(value, "userRecord")) {
      // Preserve SDK wire-envelope extensions, but never return the caller's object.
      candidate = value;
    } else {
      const userRecord = {};
      const updateMask = [];
      // Each field goes under its public name, as the Functions SDK's generateResponsePayload
      // sends it: Identity Platform does not apply `photoURL` (it reads `photoUrl`), so a
      // function's photoURL is ignored (AUTH-TENANT-BLOCKING recording 2026-09-28,
      // ordering#lookup-profile; the official Auth emulator reads `photoUrl` only too).
      for (const name of [
        "displayName",
        "photoURL",
        "disabled",
        "emailVerified",
        "customClaims",
        "sessionClaims",
      ]) {
        if (Object.prototype.hasOwnProperty.call(value, name)) {
          const field = value[name];
          // Like the Functions SDK's getUpdateMask, undefined means no update;
          // null, false, and an empty string are still explicit updates.
          if (field === undefined) continue;
          userRecord[name] = field;
          updateMask.push(name);
        }
      }
      if (updateMask.length === 0) return {};
      candidate = { userRecord: { ...userRecord, updateMask: updateMask.join(",") } };
    }
  } catch {
    throw new HttpsError("invalid-argument", "The blocking response could not be read.");
  }
  const snapshot = snapshotResponse(candidate, HttpsError);
  validateBlockingResult(snapshot, eventType, HttpsError);
  return freezeResponse(attachCustomClaimsText(snapshot));
}
