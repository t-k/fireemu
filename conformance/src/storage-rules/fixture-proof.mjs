import { constants, createHash, createHmac, createPublicKey, verify } from "node:crypto";

const INPUT_KEYS = ["token", "principal", "runId", "expectedUid", "keySet", "nowSeconds", "validSince", "digestSalt"];
const PRINCIPALS = ["user-a", "user-b", "user-plain", "revoked-token", "foreign-project-token"];
const CLAIM_KEYS = ["iss", "aud", "sub", "user_id", "iat", "exp", "auth_time", "email", "email_verified", "firebase", "role", "level"];
const seconds = (value) => Number.isSafeInteger(value) && value > 0;
const plain = (value) => value !== null && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype;

function dataRecord(value, keys, label) {
  if (!plain(value)) throw new Error(`invalid ${label}`);
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) throw new Error(`invalid ${label}`);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) throw new Error(`invalid ${label}`);
  }
}

function decodeSegment(segment) {
  const bytes = Buffer.from(segment, "base64url");
  if (bytes.toString("base64url") !== segment) throw new Error("invalid fixture token");
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
}

/** Verify one immutable signed snapshot locally. Key provenance and account ownership are caller obligations. */
export function verifyFixtureIdToken(options) {
  dataRecord(options, INPUT_KEYS, "fixture input");
  const { token, principal, runId, expectedUid, keySet, nowSeconds, validSince, digestSalt } = options;
  if (
    !PRINCIPALS.includes(principal) || typeof runId !== "string" || !/^[a-z0-9][a-z0-9-]{0,47}$/.test(runId) ||
    typeof expectedUid !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(expectedUid) || !seconds(nowSeconds) ||
    typeof digestSalt !== "string" || !/^[a-f0-9]{64}$/.test(digestSalt)
  ) throw new Error("invalid fixture input");
  if (typeof token !== "string" || token.length > 16384 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) {
    throw new Error("invalid fixture token");
  }
  let header;
  let claims;
  const segments = token.split(".");
  try {
    header = decodeSegment(segments[0]);
    claims = decodeSegment(segments[1]);
    if (Buffer.from(segments[2], "base64url").toString("base64url") !== segments[2]) throw new Error();
  } catch {
    throw new Error("invalid fixture token");
  }
  dataRecord(keySet, ["fetchedAt", "expiresAt", "publicKeys"], "key snapshot");
  if (!seconds(keySet.fetchedAt) || !seconds(keySet.expiresAt) || keySet.fetchedAt > nowSeconds || keySet.expiresAt <= nowSeconds) throw new Error("invalid key snapshot");
  if (!plain(keySet.publicKeys)) throw new Error("invalid key snapshot");
  const kids = Reflect.ownKeys(keySet.publicKeys);
  if (kids.length === 0 || kids.length > 20 || kids.some((kid) => typeof kid !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(kid))) throw new Error("invalid key snapshot");
  dataRecord(keySet.publicKeys, kids, "key snapshot");
  if (kids.some((kid) => typeof keySet.publicKeys[kid] !== "string" || keySet.publicKeys[kid].length > 10000 || !/^-----BEGIN (?:PUBLIC KEY|CERTIFICATE)-----/.test(keySet.publicKeys[kid]))) {
    throw new Error("invalid key snapshot");
  }
  if (
    !plain(header) || header.alg !== "RS256" || typeof header.kid !== "string" || !Object.hasOwn(keySet.publicKeys, header.kid) ||
    (Object.hasOwn(header, "typ") && header.typ !== "JWT") || Object.keys(header).some((key) => !["alg", "kid", "typ"].includes(key))
  ) throw new Error("invalid fixture header");
  let publicKey;
  try {
    publicKey = createPublicKey(keySet.publicKeys[header.kid]);
    if (publicKey.asymmetricKeyType !== "rsa" || publicKey.asymmetricKeyDetails.modulusLength < 2048) throw new Error();
  } catch {
    throw new Error("invalid signing key");
  }
  if (!verify("RSA-SHA256", Buffer.from(`${segments[0]}.${segments[1]}`), { key: publicKey, padding: constants.RSA_PKCS1_PADDING }, Buffer.from(segments[2], "base64url"))) {
    throw new Error("invalid fixture signature");
  }
  if (!plain(claims) || Object.keys(claims).some((key) => !CLAIM_KEYS.includes(key))) throw new Error("invalid fixture claims");
  if (
    ![claims.iat, claims.exp, claims.auth_time].every(seconds) || claims.auth_time > claims.iat ||
    claims.iat > nowSeconds || claims.exp <= nowSeconds || claims.exp <= claims.iat
  ) throw new Error("invalid fixture time");
  const project = principal === "foreign-project-token" ? "fireemu-oracle-idp" : "fireemu-oracle-query";
  const account = principal === "user-plain" ? "user-a" : principal;
  const email = `storage-rules-${runId}-${account}@example.com`;
  const expectedVerified = principal === "user-a" || principal === "user-plain";
  const firebase = claims.firebase;
  if (
    claims.iss !== `https://securetoken.google.com/${project}` || claims.aud !== project || claims.sub !== expectedUid ||
    (Object.hasOwn(claims, "user_id") && claims.user_id !== expectedUid) || claims.email !== email || claims.email_verified !== expectedVerified ||
    !plain(firebase) || Object.keys(firebase).length !== 2 || firebase.sign_in_provider !== "password" ||
    !plain(firebase.identities) || Object.keys(firebase.identities).length !== 1 ||
    !Array.isArray(firebase.identities.email) || firebase.identities.email.length !== 1 || firebase.identities.email[0] !== email
  ) throw new Error("invalid fixture claims");
  if (principal === "user-a" || principal === "user-b") {
    if (claims.role !== (principal === "user-a" ? "reader" : "writer") || claims.level !== (principal === "user-a" ? 7 : "7")) throw new Error("invalid fixture claims");
  } else if (Object.hasOwn(claims, "role") || Object.hasOwn(claims, "level")) {
    throw new Error("invalid fixture claims");
  }
  if (principal === "revoked-token" ? !seconds(validSince) || validSince <= claims.iat || validSince > nowSeconds : validSince !== null) {
    throw new Error("invalid revocation boundary");
  }
  const proofClaims = { email_verified: claims.email_verified };
  if (Object.hasOwn(claims, "role")) proofClaims.role = claims.role;
  if (Object.hasOwn(claims, "level")) proofClaims.level = claims.level;
  return Object.freeze({
    status: "SIGNED_FIXTURE_LOCAL_ONLY", sendAuthorized: false, principal, project, uid: expectedUid,
    issuedAt: claims.iat, expiresAt: claims.exp, authenticatedAt: claims.auth_time, revocationBoundary: validSince,
    tokenDigest: createHmac("sha256", Buffer.from(digestSalt, "hex")).update("storage-rules-fixture\0").update(token).digest("hex"),
    signingKeyDigest: createHash("sha256").update(keySet.publicKeys[header.kid]).digest("hex"),
    keyFetchedAt: keySet.fetchedAt, keyExpiresAt: keySet.expiresAt, claims: Object.freeze(proofClaims),
  });
}
