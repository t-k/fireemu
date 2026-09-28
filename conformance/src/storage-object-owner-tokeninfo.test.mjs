import assert from "node:assert/strict";
import test from "node:test";
const module = await import("./storage-object/owner-tokeninfo.mjs").catch((error) => {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  return {};
});
const principal = Object.freeze({
  subject: "example-owner",
  clientId: "example-client.apps.googleusercontent.com",
  requiredScopes: ["https://www.googleapis.com/auth/cloud-platform"],
});
const data = Object.freeze({
  sub: principal.subject,
  azp: principal.clientId,
  aud: principal.clientId,
  scope: principal.requiredScopes[0] + " openid",
  expires_in: "3600",
});
const verify = (changes = {}) => {
  assert.equal(
    typeof module.verifyProductionOwnerTokenInfo,
    "function",
    "owner tokeninfo validator is missing",
  );
  return module.verifyProductionOwnerTokenInfo({
    data,
    principal,
    requestStartedAtMs: 1000,
    receivedAtMs: 2000,
    ...changes,
  });
};

test("owner identity is compared with the prior principal, including both client fields and required scopes", () => {
  const result = verify();
  assert.equal(result.deadlineMonotonicMs, 3601000);
  assert.match(result.principalSha256, /^[a-f0-9]{64}$/);
  assert.match(result.scopeSha256, /^[a-f0-9]{64}$/);
  assert.ok(Object.isFrozen(result));
  assert.equal(JSON.stringify(result).includes(principal.subject), false);
  assert.equal(JSON.stringify(result).includes(principal.clientId), false);
});

test("wrong subject, audience, authorized party or missing approved scope cannot become a new baseline", () => {
  for (const change of [
    { sub: "NEW_SECRET" },
    { azp: "NEW_SECRET" },
    { aud: "NEW_SECRET" },
    { scope: "openid" },
    { scope: [principal.requiredScopes[0]] },
  ])
    assert.throws(
      () => verify({ data: { ...data, ...change } }),
      /^Error: owner tokeninfo proof is invalid$/,
    );
  assert.throws(
    () => verify({ principal: undefined }),
    /^Error: owner tokeninfo proof is invalid$/,
  );
});

test("email is excluded because the prior principal has no approved email binding", () => {
  const withEmail = verify({
    data: { ...data, email: "different@example.com", email_verified: "true" },
  });
  assert.deepEqual(withEmail, verify());
  assert.throws(
    () => verify({ principal: { ...principal, email: "different@example.com" } }),
    /^Error: owner tokeninfo proof is invalid$/,
  );
});

test("expiry uses conservative request-start monotonic time and a fixed sixty-second dispatch margin", () => {
  assert.equal(verify({ data: { ...data, expires_in: 3600 } }).deadlineMonotonicMs, 3601000);
  for (const expires_in of [0, -1, "", "1.5", "0", "60", 3601, Infinity, "NEW_SECRET"])
    assert.throws(
      () => verify({ data: { ...data, expires_in } }),
      /^Error: owner tokeninfo proof is invalid$/,
    );
  for (const change of [
    { requestStartedAtMs: -1 },
    { receivedAtMs: 999 },
    { receivedAtMs: 31001 },
    { receivedAtMs: NaN },
    { data: { ...data, expires_in: "61" }, receivedAtMs: 2000 },
  ])
    assert.throws(() => verify(change), /^Error: owner tokeninfo proof is invalid$/);
  assert.equal(
    verify({ data: { ...data, expires_in: "61" }, receivedAtMs: 1999 }).deadlineMonotonicMs,
    62000,
  );
});

test("closed data records reject errors, unknown fields, malformed scope lists and accessors", () => {
  let calls = 0;
  const bad = Object.defineProperty({ ...data }, "sub", {
    enumerable: true,
    get() {
      calls++;
      throw new Error("NEW_GETTER_SECRET");
    },
  });
  for (const record of [
    bad,
    { ...data, error: "NEW_SECRET" },
    { ...data, unknown: "NEW_SECRET" },
    { ...data, scope: data.scope + "\nNEW_SECRET" },
    { ...data, scope: data.scope + " openid" },
  ])
    assert.throws(() => verify({ data: record }), /^Error: owner tokeninfo proof is invalid$/);
  const sparseScopes = [];
  sparseScopes.length = 1;
  for (const requiredScopes of [
    [],
    [""],
    [principal.requiredScopes[0], principal.requiredScopes[0]],
    sparseScopes,
    "NEW_SECRET",
  ])
    assert.throws(
      () => verify({ principal: { ...principal, requiredScopes } }),
      /^Error: owner tokeninfo proof is invalid$/,
    );
  assert.equal(calls, 0);
});

test("scope arrays and record proxies cannot change the approved principal or execute traps", () => {
  let calls = 0;
  const requiredScopes = new Proxy([...principal.requiredScopes], {
    get(target, key) {
      if (key === "length") return ++calls <= 3 ? 1 : 0;
      return Reflect.get(target, key);
    },
  });
  assert.throws(
    () =>
      verify({ principal: { ...principal, requiredScopes }, data: { ...data, scope: "openid" } }),
    /^Error: owner tokeninfo proof is invalid$/,
  );
  assert.equal(calls, 0);
  for (const key of ["data", "principal"]) {
    const target = key === "data" ? data : principal;
    const proxy = new Proxy(target, {
      getOwnPropertyDescriptor() {
        calls++;
        throw new Error("NEW_PROXY_SECRET");
      },
    });
    assert.throws(() => verify({ [key]: proxy }), /^Error: owner tokeninfo proof is invalid$/);
  }
  assert.equal(calls, 0);
});

test("non-number monotonic inputs reject before numeric conversion", () => {
  let calls = 0;
  const value = {
    valueOf() {
      calls++;
      return 1000;
    },
  };
  for (const key of ["requestStartedAtMs", "receivedAtMs"])
    assert.throws(() => verify({ [key]: value }), /^Error: owner tokeninfo proof is invalid$/);
  assert.equal(calls, 0);
});

test("every approved scope in an ordinary multiple-scope principal is required", () => {
  const multiple = { ...principal, requiredScopes: [...principal.requiredScopes, "openid"] };
  assert.match(verify({ principal: multiple }).principalSha256, /^[a-f0-9]{64}$/);
  for (const scope of multiple.requiredScopes)
    assert.throws(
      () => verify({ principal: multiple, data: { ...data, scope } }),
      /^Error: owner tokeninfo proof is invalid$/,
    );
});
