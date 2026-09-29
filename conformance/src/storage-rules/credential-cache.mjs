import { createHash, createHmac, createPublicKey } from "node:crypto";

const TOKEN_URL = "https://oauth2.googleapis.com/token";
const CERTIFICATE_URL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";
const entries = [
  ["preflight/auth/owner-token", "owner", "preflight"], ["preflight/auth/signing-keys", "keys", "preflight"],
  ...Array.from({ length: 8 }, (_, index) => [`auth-shared/owner-token/${index + 1}`, "owner", "normal"]),
  ["auth-shared/signing-keys/1", "keys", "normal"],
  ...Array.from({ length: 8 }, (_, index) => [`recovery/auth-shared/owner-token/${index + 1}`, "owner", "recovery"]),
];
const ids = new Map(entries.map(([id, kind, phase]) => [id, { kind, phase }]));
export const CREDENTIAL_CACHE_REQUEST_IDS = Object.freeze(entries.map(([id]) => id));
const nativeLength = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), "length").get;
const plain = (value) => value !== null && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype;
const matches = (value, pattern) => typeof value === "string" && !/[\r\n]/.test(value) && pattern.test(value);

function record(value, keys) {
  if (!plain(value)) throw new Error();
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) throw new Error();
  for (const key of keys) {
    const field = Object.getOwnPropertyDescriptor(value, key);
    if (!field?.enumerable || !Object.hasOwn(field, "value")) throw new Error();
  }
}

function responseBody(response) {
  record(response, ["status", "rawHeaders", "bytes", "startedAtMs", "finishedAtMs"]);
  if (response.status !== 200 || !Buffer.isBuffer(response.bytes) || Object.getPrototypeOf(response.bytes) !== Buffer.prototype) throw new Error();
  const size = nativeLength.call(response.bytes);
  if (size > 256 * 1024) throw new Error();
  const keys = Reflect.ownKeys(response.bytes);
  if (keys.length !== size || keys.some((key, index) => key !== String(index))) throw new Error();
  const bytes = Buffer.alloc(size);
  Uint8Array.prototype.set.call(bytes, response.bytes);
  const body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  if (!plain(body) || Object.keys(body).length > 32) throw new Error();
  return body;
}

function keyLifetime(rawHeaders) {
  if (!Array.isArray(rawHeaders) || Object.getPrototypeOf(rawHeaders) !== Array.prototype || rawHeaders.length % 2 || rawHeaders.length > 128) throw new Error();
  if (Reflect.ownKeys(rawHeaders).length !== rawHeaders.length + 1) throw new Error();
  const values = [];
  for (let index = 0; index < rawHeaders.length; index++) {
    const field = Object.getOwnPropertyDescriptor(rawHeaders, String(index));
    if (!field?.enumerable || !Object.hasOwn(field, "value") || typeof field.value !== "string" || /[\r\n]/.test(field.value)) throw new Error();
    values.push(field.value);
  }
  if (values.reduce((size, value) => size + Buffer.byteLength(value) + 2, 0) > 32768) throw new Error();
  const cache = [];
  const ages = [];
  for (let index = 0; index < values.length; index += 2) {
    const name = values[index].toLowerCase();
    if (name === "cache-control") cache.push(values[index + 1]);
    if (name === "age") ages.push(values[index + 1]);
  }
  if (cache.length !== 1 || ages.length > 1) throw new Error();
  const directives = cache[0].split(",").map((value) => value.trim());
  if (directives.some((value) => /^(?:no-store|no-cache)(?:\s*=|$)/i.test(value))) throw new Error();
  const maxAges = directives.filter((value) => /^max-age(?:\s*=|$)/i.test(value));
  if (maxAges.length !== 1) throw new Error();
  const match = /^max-age\s*=\s*(?:([0-9]+)|"([0-9]+)")$/i.exec(maxAges[0]);
  if (!match) throw new Error();
  const maxAge = Number(match[1] ?? match[2]);
  if (!Number.isSafeInteger(maxAge) || maxAge <= 0 || maxAge > 86400 || (ages.length && !/^(?:0|[1-9]\d{0,5})$/.test(ages[0]))) throw new Error();
  const age = ages.length ? Number(ages[0]) : 0;
  if (age >= maxAge) throw new Error();
  return maxAge - age;
}

/** Explicit counted refreshes only; cached getters never acquire credentials or perform HTTP. */
export function createCountedCredentialCache(options) {
  let adc;
  let counter;
  let sendHttp;
  let nowSeconds;
  let writeProof;
  let digestSalt;
  try {
    record(options, ["adc", "counter", "sendHttp", "nowSeconds", "writeProof", "digestSalt"]);
    record(options.adc, ["type", "client_id", "client_secret", "refresh_token"]);
    if (options.adc.type !== "authorized_user" || !matches(options.adc.client_id, /^[A-Za-z0-9._-]{12,200}$/) || !matches(options.adc.client_secret, /^[!-~]{20,512}$/) || !matches(options.adc.refresh_token, /^[!-~]{20,4096}$/) || !matches(options.digestSalt, /^[a-f0-9]{64}$/) || [options.sendHttp, options.nowSeconds, options.writeProof].some((callback) => typeof callback !== "function") || !plain(options.counter)) throw new Error();
    counter = {};
    for (const name of ["send", "sendPreflight", "snapshot"]) {
      const field = Object.getOwnPropertyDescriptor(options.counter, name);
      if (!field?.enumerable || !Object.hasOwn(field, "value") || typeof field.value !== "function") throw new Error();
      counter[name] = field.value;
    }
    adc = { ...options.adc };
    ({ sendHttp, nowSeconds, writeProof, digestSalt } = options);
  } catch { throw new Error("invalid credential cache input"); }
  let busy = false;
  let journalHealthy = true;
  let owner = null;
  let signing = null;
  let lastObservedAt = 0;

  function now() {
    const value = nowSeconds();
    if (!Number.isSafeInteger(value) || value <= 0 || value < lastObservedAt) throw new Error();
    lastObservedAt = value;
    return value;
  }

  function fresh(value, margin) {
    const current = now();
    if (!value || current < value.fetchedAt || !Number.isSafeInteger(value.expiresAt) || value.expiresAt - current <= margin) throw new Error();
  }

  function canRead() {
    if (busy || !journalHealthy || !["preflight", "normal", "recovery"].includes(counter.snapshot().mode)) throw new Error();
  }

  async function execute(kind, operationId) {
    const info = ids.get(operationId);
    try {
      if (busy || !journalHealthy || !info || info.kind !== kind || counter.snapshot().mode !== info.phase) throw new Error();
    } catch { throw new Error("credential cache request refused"); }
    busy = true;
    if (kind === "owner") owner = null;
    else signing = null;
    try {
      const attempt = async () => {
        const fetchedAt = now();
        const spec = kind === "owner"
          ? { url: TOKEN_URL, method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" }, body: Buffer.from(new URLSearchParams({ grant_type: "refresh_token", client_id: adc.client_id, client_secret: adc.client_secret, refresh_token: adc.refresh_token }).toString()) }
          : { url: CERTIFICATE_URL, method: "GET", headers: { accept: "application/json" }, body: null };
        const response = await sendHttp(spec);
        const body = responseBody(response);
        let value;
        let proof;
        if (kind === "owner") {
          if (["access_token", "token_type", "expires_in"].some((key) => !Object.hasOwn(body, key)) || !matches(body.access_token, /^[!-~]{20,4096}$/) || body.token_type !== "Bearer" || !Number.isSafeInteger(body.expires_in) || body.expires_in <= 30 || body.expires_in > 7200) throw new Error();
          value = Object.freeze({ accessToken: body.access_token, fetchedAt, expiresAt: fetchedAt + body.expires_in });
          proof = Object.freeze({ status: "OWNER_OAUTH_LOCAL_ONLY", sendAuthorized: false, operationId, sourceUrl: TOKEN_URL, fetchedAt, expiresAt: value.expiresAt,
            tokenDigest: createHmac("sha256", Buffer.from(digestSalt, "hex")).update("storage-rules-owner-token\0").update(body.access_token).digest("hex") });
        } else {
          const kids = Object.keys(body);
          if (kids.length === 0 || kids.length > 20) throw new Error();
          const publicKeys = {};
          const keyDigests = {};
          for (const kid of kids) {
            const pem = body[kid];
            if (!matches(kid, /^[A-Za-z0-9_-]{1,128}$/) || typeof pem !== "string" || pem.length > 10000 || !/^-----BEGIN (?:PUBLIC KEY|CERTIFICATE)-----/.test(pem)) throw new Error();
            const key = createPublicKey(pem);
            if (key.asymmetricKeyType !== "rsa" || key.asymmetricKeyDetails.modulusLength < 2048) throw new Error();
            Object.defineProperty(publicKeys, kid, { enumerable: true, value: pem });
            Object.defineProperty(keyDigests, kid, { enumerable: true, value: createHash("sha256").update(pem).digest("hex") });
          }
          value = Object.freeze({ fetchedAt, expiresAt: fetchedAt + keyLifetime(response.rawHeaders), publicKeys: Object.freeze(publicKeys) });
          proof = Object.freeze({ status: "SIGNING_KEYS_LOCAL_ONLY", sendAuthorized: false, operationId, sourceUrl: CERTIFICATE_URL, fetchedAt, expiresAt: value.expiresAt, keyDigests: Object.freeze(keyDigests) });
        }
        fresh(value, kind === "owner" ? 30 : 0);
        try { await writeProof(proof); } catch { journalHealthy = false; throw new Error(); }
        fresh(value, kind === "owner" ? 30 : 0);
        if (counter.snapshot().mode !== info.phase) throw new Error();
        if (kind === "owner") owner = value;
        else signing = value;
        return proof;
      };
      return info.phase === "preflight" ? await counter.sendPreflight(operationId, attempt, (proof) => proof.sendAuthorized === false) : await counter.send(operationId, attempt);
    } catch { throw new Error(journalHealthy ? "credential cache request failed" : "credential cache journal uncertain"); }
    finally { busy = false; }
  }

  return Object.freeze({
    refreshOwner(operationId) { return execute("owner", operationId); },
    fetchSigningKeys(operationId) { return execute("keys", operationId); },
    ownerCredential() {
      try { canRead(); fresh(owner, 30); return Object.freeze({ accessToken: owner.accessToken, expiresAt: owner.expiresAt }); }
      catch { throw new Error("credential cache unavailable"); }
    },
    keySet() {
      try { canRead(); fresh(signing, 0); return Object.freeze({ fetchedAt: signing.fetchedAt, expiresAt: signing.expiresAt, publicKeys: Object.freeze({ ...signing.publicKeys }) }); }
      catch { throw new Error("credential cache unavailable"); }
    },
    snapshot() { return Object.freeze({ busy, journalHealthy, ownerCached: owner !== null, keysCached: signing !== null, sendAuthorized: false }); },
  });
}
