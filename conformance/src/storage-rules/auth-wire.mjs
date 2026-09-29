const QUERY = "fireemu-oracle-query";
const IDP = "fireemu-oracle-idp";
const ORIGIN = "https://identitytoolkit.googleapis.com";
const STEPS = Object.freeze({
  "user-a": ["create", "lookup-created", "set-claims", "lookup-claims", "sign-in", "clear-claims", "lookup-plain", "sign-in-plain", "delete", "absence"],
  "user-b": ["create", "lookup-created", "set-claims", "lookup-claims", "sign-in", "delete", "absence"],
  "revoked-token": ["create", "lookup-created", "sign-in", "revoke", "lookup-revoked", "delete", "absence"],
  "foreign-project-token": ["baseline", "sign-up", "lookup-token", "delete", "absence"],
});
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

function copyJson(value, budget = { remaining: 128 }, depth = 0) {
  if (--budget.remaining < 0 || depth > 8) throw new Error();
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") { if (value.length > 16384) throw new Error(); return value; }
  if (typeof value === "number") { if (!Number.isFinite(value)) throw new Error(); return value; }
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype || value.length > 16) throw new Error();
    const keys = Reflect.ownKeys(value);
    if (keys.length !== value.length + 1) throw new Error();
    const result = [];
    for (let index = 0; index < value.length; index++) {
      const field = Object.getOwnPropertyDescriptor(value, String(index));
      if (!field?.enumerable || !Object.hasOwn(field, "value")) throw new Error();
      result.push(copyJson(field.value, budget, depth + 1));
    }
    return Object.freeze(result);
  }
  if (!plain(value)) throw new Error();
  const keys = Reflect.ownKeys(value);
  if (keys.length > 32 || keys.some((key) => typeof key !== "string" || key.length > 128)) throw new Error();
  record(value, keys);
  const result = {};
  for (const key of keys) Object.defineProperty(result, key, { value: copyJson(Object.getOwnPropertyDescriptor(value, key).value, budget, depth + 1), enumerable: true });
  return Object.freeze(result);
}

function prepare(runId, operationId, spec) {
  record(spec, ["project", "method", "origin", "path", "credential", "apiKeyReference", "body"]);
  if (typeof operationId !== "string") throw new Error();
  const match = /^(auth|recovery\/auth)\/(user-a|user-b|revoked-token|foreign-project-token)\/([a-z-]+)$/.exec(operationId);
  if (!match || match[0] !== operationId) throw new Error();
  const [, prefix, account, step] = match;
  if (!STEPS[account].includes(step) || (prefix === "recovery/auth" && !["delete", "absence"].includes(step))) throw new Error();
  const project = account === "foreign-project-token" ? IDP : QUERY;
  const client = ["sign-in", "sign-in-plain", "sign-up", "lookup-token"].includes(step);
  const action = step === "create" ? "" : ["sign-in", "sign-in-plain"].includes(step) ? "signInWithPassword" : step === "sign-up" ? "signUp" : ["set-claims", "clear-claims", "revoke"].includes(step) ? "update" : step === "delete" ? "delete" : "lookup";
  const path = client ? `/v1/accounts:${action}` : `/v1/projects/${project}/accounts${action ? `:${action}` : ""}`;
  if (spec.project !== project || spec.method !== "POST" || spec.origin !== ORIGIN || spec.path !== path || spec.credential !== (client ? "api-key-only" : "owner-oauth") || spec.apiKeyReference !== (project === QUERY ? "query-api-key" : "idp-api-key")) throw new Error();
  const body = copyJson(spec.body);
  const expectedUid = `storage-rules-${runId}-${account}`;
  const expectedEmail = `${expectedUid}@example.com`;
  const validUid = (value) => account === "foreign-project-token" ? matches(value, /^[A-Za-z0-9._-]{1,128}$/) : value === expectedUid;
  const validPassword = (value) => matches(value, /^[!-~]{20,128}$/);
  if (step === "create") {
    record(body, ["localId", "email", "password", "emailVerified"]);
    if (body.localId !== expectedUid || body.email !== expectedEmail || !validPassword(body.password) || body.emailVerified !== (account === "user-a")) throw new Error();
  } else if (["sign-in", "sign-in-plain", "sign-up"].includes(step)) {
    record(body, ["email", "password", "returnSecureToken"]);
    if (body.email !== expectedEmail || !validPassword(body.password) || body.returnSecureToken !== true) throw new Error();
  } else if (step === "lookup-token") {
    record(body, ["idToken"]);
    if (!matches(body.idToken, /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)) throw new Error();
  } else if (step === "baseline") {
    record(body, ["email"]);
    if (!Array.isArray(body.email) || body.email.length !== 1 || body.email[0] !== expectedEmail) throw new Error();
  } else if (["set-claims", "clear-claims"].includes(step)) {
    record(body, ["localId", "customAttributes"]);
    const attributes = step === "clear-claims" ? "{}" : JSON.stringify({ role: account === "user-a" ? "reader" : "writer", level: account === "user-a" ? 7 : "7" });
    if (!validUid(body.localId) || body.customAttributes !== attributes) throw new Error();
  } else if (step === "revoke") {
    record(body, ["localId", "validSince"]);
    if (!validUid(body.localId) || !matches(body.validSince, /^[1-9]\d{0,15}$/) || !Number.isSafeInteger(Number(body.validSince))) throw new Error();
  } else if (step === "delete") {
    record(body, ["localId"]);
    if (!validUid(body.localId)) throw new Error();
  } else {
    record(body, ["localId"]);
    if (!Array.isArray(body.localId) || body.localId.length !== 1 || !validUid(body.localId[0])) throw new Error();
  }
  return { project, client, path, body: Buffer.from(JSON.stringify(body)) };
}

function parseResponse(response) {
  record(response, ["status", "rawHeaders", "bytes", "startedAtMs", "finishedAtMs"]);
  if (response.status !== 200 || !Buffer.isBuffer(response.bytes) || Object.getPrototypeOf(response.bytes) !== Buffer.prototype) throw new Error();
  const size = nativeLength.call(response.bytes);
  if (size > 2 * 1024 * 1024) throw new Error();
  const keys = Reflect.ownKeys(response.bytes);
  if (keys.length !== size || keys.some((key, index) => key !== String(index))) throw new Error();
  const bytes = Buffer.alloc(size);
  Uint8Array.prototype.set.call(bytes, response.bytes);
  const body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  if (!plain(body)) throw new Error();
  return Object.freeze({ status: 200, body: copyJson(body) });
}

/** Map only the credential session's fixed Auth steps to one injected HTTP attempt. */
export function createAuthWireTransport(options) {
  let runId;
  let apiKeys;
  let ownerCredential;
  let nowSeconds;
  let sendHttp;
  try {
    record(options, ["runId", "apiKeys", "ownerCredential", "nowSeconds", "sendHttp"]);
    record(options.apiKeys, [QUERY, IDP]);
    if (!matches(options.runId, /^[a-z0-9][a-z0-9-]{0,47}$/) || [QUERY, IDP].some((project) => !matches(options.apiKeys[project], /^[A-Za-z0-9_-]{20,128}$/)) || [options.ownerCredential, options.nowSeconds, options.sendHttp].some((callback) => typeof callback !== "function")) throw new Error();
    ({ runId, ownerCredential, nowSeconds, sendHttp } = options);
    apiKeys = { ...options.apiKeys };
  } catch { throw new Error("invalid Auth wire input"); }
  return Object.freeze({
    async send(operationId, spec) {
      let prepared;
      try { prepared = prepare(runId, operationId, spec); } catch { throw new Error("invalid Auth wire request"); }
      const headers = { "content-type": "application/json", accept: "application/json" };
      let url = `${ORIGIN}${prepared.path}`;
      if (prepared.client) url += `?key=${apiKeys[prepared.project]}`;
      else {
        try {
          const credential = ownerCredential();
          record(credential, ["accessToken", "expiresAt"]);
          const { accessToken, expiresAt } = credential;
          const current = nowSeconds();
          if (!matches(accessToken, /^[!-~]{20,4096}$/) || !Number.isSafeInteger(current) || current <= 0 || !Number.isSafeInteger(expiresAt) || expiresAt - current <= 30) throw new Error();
          headers.authorization = `Bearer ${accessToken}`;
          headers["x-goog-user-project"] = prepared.project;
        } catch { throw new Error("Auth owner credential unavailable"); }
      }
      let response;
      try { response = await sendHttp({ url, method: "POST", headers, body: prepared.body }); } catch { throw new Error("Auth wire request failed"); }
      try { return parseResponse(response); } catch { throw new Error("invalid Auth wire response"); }
    },
  });
}
