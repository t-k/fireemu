import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { EventEmitter } from "node:events";
import test from "node:test";
import { createCredentialFixtureSession } from "./storage-rules/credential-session.mjs";
import { createSingleAttemptHttpsTransport } from "./storage-rules/http-transport.mjs";
import { createStage3RequestCounter } from "./storage-rules/request-counter.mjs";

const QUERY = "fireemu-oracle-query";
const IDP = "fireemu-oracle-idp";
const runId = "wire-test";
const now = 1790553600;
const apiKeys = { [QUERY]: "Synthetic-query-api-key-00001", [IDP]: "Synthetic-idp-api-key-0000002" };
const accessToken = "Synthetic-owner-oauth-token-00003";
const password = "Synthetic-fixture-password-00004!";
const uid = (account) => `storage-rules-${runId}-${account}`;
const email = (account) => `${uid(account)}@example.com`;
const raw = (body = {}, overrides = {}) => ({ status: 200, rawHeaders: ["content-type", "application/json"], bytes: Buffer.from(JSON.stringify(body)), startedAtMs: 1000, finishedAtMs: 1001, ...overrides });
const admin = (account, action, body, project = QUERY) => ({ project, origin: "https://identitytoolkit.googleapis.com", path: `/v1/projects/${project}/accounts${action ? `:${action}` : ""}`, method: "POST", credential: "owner-oauth", apiKeyReference: project === QUERY ? "query-api-key" : "idp-api-key", body });
const client = (account, action, body, project = QUERY) => ({ ...admin(account, action, body, project), path: `/v1/accounts:${action}`, credential: "api-key-only" });
const create = () => admin("user-a", "", { localId: uid("user-a"), email: email("user-a"), password, emailVerified: true });

async function setup({ ownerCredential, nowSeconds, sendHttp, keys = apiKeys, optionDelta = {} } = {}) {
  const module = await import("./storage-rules/auth-wire.mjs").catch((error) => {
    if (error.code === "ERR_MODULE_NOT_FOUND") return {};
    throw error;
  });
  assert.equal(typeof module.createAuthWireTransport, "function");
  const calls = [];
  let ownerReads = 0;
  const wire = module.createAuthWireTransport({ runId, apiKeys: keys,
    ownerCredential: ownerCredential || (() => { ownerReads++; return { accessToken, expiresAt: now + 1000 }; }),
    nowSeconds: nowSeconds || (() => now), sendHttp: sendHttp || (async (spec) => { calls.push(spec); return raw({ localId: uid("user-a") }); }), ...optionDelta });
  return { wire, calls, ownerReads: () => ownerReads };
}

for (const [id, spec] of [
  ["auth/user-a/create", create()],
  ["auth/user-a/lookup-created", admin("user-a", "lookup", { localId: [uid("user-a")] })],
  ["auth/user-a/set-claims", admin("user-a", "update", { localId: uid("user-a"), customAttributes: '{"role":"reader","level":7}' })],
  ["auth/user-a/clear-claims", admin("user-a", "update", { localId: uid("user-a"), customAttributes: "{}" })],
  ["auth/revoked-token/revoke", admin("revoked-token", "update", { localId: uid("revoked-token"), validSince: String(now) })],
  ["auth/foreign-project-token/baseline", admin("foreign-project-token", "lookup", { email: [email("foreign-project-token")] }, IDP)],
  ["auth/foreign-project-token/delete", admin("foreign-project-token", "delete", { localId: "foreign-captured-uid" }, IDP)],
  ["recovery/auth/user-a/delete", admin("user-a", "delete", { localId: uid("user-a") })],
  ["recovery/auth/foreign-project-token/absence", admin("foreign-project-token", "lookup", { localId: ["foreign-captured-uid"] }, IDP)],
]) {
  test(`the fixed Admin route ${id} uses one cached OAuth credential and no API key`, async () => {
    const ctx = await setup();
    const result = await ctx.wire.send(id, spec);
    assert.equal(ctx.calls.length, 1);
    assert.equal(ctx.ownerReads(), 1);
    const call = ctx.calls[0];
    assert.equal(call.url, `${spec.origin}${spec.path}`);
    assert.equal(call.method, "POST");
    assert.equal(call.headers.authorization, `Bearer ${accessToken}`);
    assert.deepEqual(JSON.parse(call.body.toString()), spec.body);
    assert.equal(call.headers["content-type"], "application/json");
    assert.equal(result.status, 200);
    assert.ok(!call.url.includes(apiKeys[QUERY]) && !call.url.includes(apiKeys[IDP]));
  });
}

for (const [id, spec] of [
  ["auth/user-a/sign-in", client("user-a", "signInWithPassword", { email: email("user-a"), password, returnSecureToken: true })],
  ["auth/user-a/sign-in-plain", client("user-a", "signInWithPassword", { email: email("user-a"), password, returnSecureToken: true })],
  ["auth/foreign-project-token/sign-up", client("foreign-project-token", "signUp", { email: email("foreign-project-token"), password, returnSecureToken: true }, IDP)],
  ["auth/foreign-project-token/lookup-token", client("foreign-project-token", "lookup", { idToken: "synthetic.payload.signature" }, IDP)],
]) {
  test(`the fixed client route ${id} uses only its project API key`, async () => {
    const ctx = await setup({ ownerCredential: () => assert.fail("client must not read owner OAuth") });
    await ctx.wire.send(id, spec);
    assert.equal(ctx.calls.length, 1);
    const call = ctx.calls[0];
    assert.equal(call.url, `${spec.origin}${spec.path}?key=${apiKeys[spec.project]}`);
    assert.ok(!Object.hasOwn(call.headers, "authorization"));
    assert.deepEqual(JSON.parse(call.body.toString()), spec.body);
  });
}

for (const delta of [
  { origin: "https://example.com" }, { origin: "http://identitytoolkit.googleapis.com" },
  { method: "GET" }, { project: IDP }, { project: "fireemu-35fe6" },
  { path: `/v1/projects/${QUERY}/accounts:delete` }, { path: `/v1/projects/${QUERY}/accounts/` },
  { path: `/v1/projects/${QUERY}/accounts?key=extra` }, { path: `/v1/projects/${QUERY}/%61ccounts` },
  { credential: "api-key-only" }, { apiKeyReference: "idp-api-key" }, { extra: password },
]) {
  test(`an altered Auth request field ${Object.keys(delta)[0]} is refused before credential access or HTTP`, async () => {
    const ctx = await setup();
    await assert.rejects(ctx.wire.send("auth/user-a/create", { ...create(), ...delta }), /invalid Auth wire request/);
    assert.equal(ctx.calls.length, 0);
    assert.equal(ctx.ownerReads(), 0);
  });
}

for (const id of ["auth/other/create", "Auth/user-a/create", "/auth/user-a/create", "auth/user-a/create/extra", "recovery/auth/user-a/create", "auth/user-b/sign-in-plain", "auth/user-a/baseline", "auth/foreign-project-token/create"]) {
  test(`the undeclared fixture operation ${id} cannot use the HTTP connector`, async () => {
    const ctx = await setup();
    await assert.rejects(ctx.wire.send(id, create()), /invalid Auth wire request/);
    assert.equal(ctx.calls.length, 0);
    assert.equal(ctx.ownerReads(), 0);
  });
}

for (const delta of [{ localId: "some-other-user" }, { email: "other@example.com" }, { emailVerified: false }, { password: "short" }, { tenantId: "other-tenant" }]) {
  test(`an out-of-fixture create body ${Object.keys(delta)[0]} cannot reach HTTP`, async () => {
    const ctx = await setup();
    await assert.rejects(ctx.wire.send("auth/user-a/create", { ...create(), body: { ...create().body, ...delta } }), /invalid Auth wire request/);
    assert.equal(ctx.calls.length, 0);
  });
}

test("lookup cannot include another UID beside the owned query fixture", async () => {
  const ctx = await setup();
  await assert.rejects(ctx.wire.send("auth/user-a/lookup-created", admin("user-a", "lookup", { localId: [uid("user-a"), "other-user"] })), /invalid Auth wire request/);
  assert.equal(ctx.calls.length, 0);
});

test("claims cannot change the reviewed value type", async () => {
  const ctx = await setup();
  await assert.rejects(ctx.wire.send("auth/user-a/set-claims", admin("user-a", "update", { localId: uid("user-a"), customAttributes: '{"role":"reader","level":"7"}' })), /invalid Auth wire request/);
  assert.equal(ctx.calls.length, 0);
});

test("a client issuance must request its secure token explicitly", async () => {
  const ctx = await setup();
  await assert.rejects(ctx.wire.send("auth/user-a/sign-in", client("user-a", "signInWithPassword", { email: email("user-a"), password, returnSecureToken: false })), /invalid Auth wire request/);
  assert.equal(ctx.calls.length, 0);
});

test("a descriptor getter in the spec is refused without being called", async () => {
  const ctx = await setup();
  let touched = false;
  const spec = create();
  Object.defineProperty(spec, "path", { enumerable: true, get() { touched = true; throw new Error(password); } });
  await assert.rejects(ctx.wire.send("auth/user-a/create", spec), (error) => error.message === "invalid Auth wire request");
  assert.equal(touched, false);
  assert.equal(ctx.calls.length, 0);
});

test("an array entry getter is refused without being called", async () => {
  const ctx = await setup();
  let touched = false;
  const ids = [uid("user-a")];
  Object.defineProperty(ids, "0", { enumerable: true, get() { touched = true; throw new Error(password); } });
  await assert.rejects(ctx.wire.send("auth/user-a/lookup-created", admin("user-a", "lookup", { localId: ids })), (error) => error.message === "invalid Auth wire request");
  assert.equal(touched, false);
  assert.equal(ctx.calls.length, 0);
});

for (const extra of [Symbol("secret"), "hidden"]) {
  test("hidden body metadata cannot reach JSON serialization", async () => {
    const ctx = await setup();
    const body = create().body;
    Object.defineProperty(body, extra, { value: password });
    await assert.rejects(ctx.wire.send("auth/user-a/create", { ...create(), body }), /invalid Auth wire request/);
    assert.equal(ctx.calls.length, 0);
  });
}

test("request bytes are copied before the owner credential callback can mutate input", async () => {
  const spec = create();
  const ctx = await setup({ ownerCredential: () => { spec.body.password = "changed"; spec.path = "/wrong"; return { accessToken, expiresAt: now + 1000 }; } });
  await ctx.wire.send("auth/user-a/create", spec);
  assert.equal(JSON.parse(ctx.calls[0].body.toString()).password, password);
  assert.equal(ctx.calls[0].url, `https://identitytoolkit.googleapis.com/v1/projects/${QUERY}/accounts`);
});

test("project API keys are copied at connector creation", async () => {
  const keys = { ...apiKeys };
  const ctx = await setup({ keys });
  keys[QUERY] = "changed";
  await ctx.wire.send("auth/user-a/sign-in", client("user-a", "signInWithPassword", { email: email("user-a"), password, returnSecureToken: true }));
  assert.equal(ctx.calls[0].url.split("?key=")[1], apiKeys[QUERY]);
});

for (const expiresAt of [now - 1, now, now + 30, NaN, Infinity]) {
  test(`an owner credential with expiry ${expiresAt} cannot start a request`, async () => {
    const ctx = await setup({ ownerCredential: () => ({ accessToken, expiresAt }) });
    await assert.rejects(ctx.wire.send("auth/user-a/create", create()), /Auth owner credential unavailable/);
    assert.equal(ctx.calls.length, 0);
  });
}

test("the owner credential callback must return a synchronous cache record", async () => {
  const ctx = await setup({ ownerCredential: async () => ({ accessToken, expiresAt: now + 1000 }) });
  await assert.rejects(ctx.wire.send("auth/user-a/create", create()), /Auth owner credential unavailable/);
  assert.equal(ctx.calls.length, 0);
});

test("an owner credential getter is rejected without reading its secret", async () => {
  let touched = false;
  const credential = { expiresAt: now + 1000 };
  Object.defineProperty(credential, "accessToken", { enumerable: true, get() { touched = true; throw new Error(password); } });
  const ctx = await setup({ ownerCredential: () => credential });
  await assert.rejects(ctx.wire.send("auth/user-a/create", create()), (error) => error.message === "Auth owner credential unavailable");
  assert.equal(touched, false);
  assert.equal(ctx.calls.length, 0);
});

test("the credential expiry is copied before the clock callback can mutate its cache record", async () => {
  const credential = { accessToken, expiresAt: now };
  const ctx = await setup({ ownerCredential: () => credential, nowSeconds: () => { credential.expiresAt = now + 1000; return now; } });
  await assert.rejects(ctx.wire.send("auth/user-a/create", create()), /Auth owner credential unavailable/);
  assert.equal(ctx.calls.length, 0);
});

test("owner and clock callback errors cannot expose private text", async () => {
  for (const delta of [{ ownerCredential: () => { throw new Error(password); } }, { nowSeconds: () => { throw new Error(accessToken); } }]) {
    const ctx = await setup(delta);
    await assert.rejects(ctx.wire.send("auth/user-a/create", create()), (error) => error.message === "Auth owner credential unavailable");
    assert.equal(ctx.calls.length, 0);
  }
});

for (const status of [301, 400, 429, 500]) {
  test(`HTTP ${status} stops after one attempt with no redirect or retry`, async () => {
    let attempts = 0;
    const ctx = await setup({ sendHttp: async () => { attempts++; return raw({ error: { message: password } }, { status }); } });
    await assert.rejects(ctx.wire.send("auth/user-a/create", create()), (error) => error.message === "invalid Auth wire response");
    assert.equal(attempts, 1);
  });
}

test("a lower HTTP exception is masked after exactly one attempt", async () => {
  let attempts = 0;
  const ctx = await setup({ sendHttp: async () => { attempts++; throw new Error(`${password} ${accessToken} ${apiKeys[QUERY]}`); } });
  await assert.rejects(ctx.wire.send("auth/user-a/create", create()), (error) => error.message === "Auth wire request failed");
  assert.equal(attempts, 1);
});

for (const bytes of [Buffer.from([0xff]), Buffer.from([123, 34, 120, 34, 58, 34, 0xff, 34, 125]), Buffer.from("{"), Buffer.from("[]"), Buffer.from("null"), Buffer.from('"value"'), Buffer.alloc(2 * 1024 * 1024 + 1, 32)]) {
  test("invalid or oversized response JSON is refused without reflecting its content", async () => {
    const ctx = await setup({ sendHttp: async () => raw({}, { bytes }) });
    await assert.rejects(ctx.wire.send("auth/user-a/create", create()), (error) => error.message === "invalid Auth wire response");
  });
}

test("the response byte ceiling also rejects JSON whose decoded structure fits its limits", async () => {
  const escaped = (String.fromCharCode(92) + "u0061").repeat(12000);
  const bytes = Buffer.from(`{${Array.from({ length: 30 }, (_, index) => `"p${index}":"${escaped}"`).join(",")}}`);
  assert.ok(bytes.length > 2 * 1024 * 1024);
  const ctx = await setup({ sendHttp: async () => raw({}, { bytes }) });
  await assert.rejects(ctx.wire.send("auth/user-a/create", create()), (error) => error.message === "invalid Auth wire response");
});

test("a response Buffer length getter is refused without reading it", async () => {
  let touched = false;
  const bytes = Buffer.from("{}");
  Object.defineProperty(bytes, "length", { get() { touched = true; throw new Error(password); } });
  const ctx = await setup({ sendHttp: async () => raw({}, { bytes }) });
  await assert.rejects(ctx.wire.send("auth/user-a/create", create()), (error) => error.message === "invalid Auth wire response");
  assert.equal(touched, false);
});

test("a response Buffer subclass cannot introduce unreviewed behavior", async () => {
  const bytes = Buffer.from("{}");
  Object.setPrototypeOf(bytes, Object.create(Buffer.prototype));
  const ctx = await setup({ sendHttp: async () => raw({}, { bytes }) });
  await assert.rejects(ctx.wire.send("auth/user-a/create", create()), /invalid Auth wire response/);
});

test("the complete credential lifecycle reserves and sends the same 29 Auth attempts through HTTPS", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const users = new Map();
  const reserves = [];
  const calls = [];
  const proofs = [];
  const ownership = [];
  const cleanup = [];
  let ownerReads = 0;
  const mint = (user, project) => {
    const claims = { iss: `https://securetoken.google.com/${project}`, aud: project, sub: user.localId, iat: now - 1, exp: now + 1000, auth_time: now - 1,
      email: user.email, email_verified: user.emailVerified, firebase: { identities: { email: [user.email] }, sign_in_provider: "password" }, ...JSON.parse(user.customAttributes) };
    const data = `${Buffer.from(JSON.stringify({ alg: "RS256", kid: "wire" })).toString("base64url")}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}`;
    return `${data}.${sign("RSA-SHA256", Buffer.from(data), privateKey).toString("base64url")}`;
  };
  const https = createSingleAttemptHttpsTransport({ requestImpl: (url, init, onResponse) => {
    const request = new EventEmitter();
    request.destroy = () => {};
    request.end = (bytes) => {
      const key = url.searchParams.get("key");
      const project = key ? Object.keys(apiKeys).find((name) => apiKeys[name] === key) : url.pathname.split("/")[3];
      assert.ok([QUERY, IDP].includes(project));
      assert.equal(init.headers.authorization, key ? undefined : `Bearer ${accessToken}`);
      assert.ok(reserves.at(-1).startsWith("auth/"));
      const operationId = reserves.at(-1);
      calls.push({ operationId, project, key });
      const body = JSON.parse(bytes.toString());
      const storeKey = (localId) => `${project}/${localId}`;
      let responseBody;
      if (url.pathname.endsWith("/accounts") || url.pathname.endsWith(":signUp")) {
        const localId = body.localId || "foreign-captured-uid";
        const user = { localId, email: body.email, emailVerified: body.emailVerified || false, customAttributes: "{}", validSince: String(now - 100) };
        users.set(storeKey(localId), user);
        responseBody = { localId, email: body.email, ...(key ? { idToken: mint(user, project), refreshToken: "synthetic-refresh-secret" } : {}) };
      } else if (url.pathname.endsWith(":lookup")) {
        const matches = body.idToken ? [users.get(storeKey(JSON.parse(Buffer.from(body.idToken.split(".")[1], "base64url")).sub))].filter(Boolean) : body.localId ? body.localId.map((localId) => users.get(storeKey(localId))).filter(Boolean) : [...users.entries()].filter(([name, user]) => name.startsWith(`${project}/`) && body.email.includes(user.email)).map(([, user]) => user);
        responseBody = { users: matches };
      } else if (url.pathname.endsWith(":update")) {
        const user = users.get(storeKey(body.localId));
        if (Object.hasOwn(body, "customAttributes")) user.customAttributes = body.customAttributes;
        if (Object.hasOwn(body, "validSince")) user.validSince = body.validSince;
        responseBody = { localId: user.localId, email: user.email };
      } else if (url.pathname.endsWith(":signInWithPassword")) {
        const user = [...users.entries()].find(([name, user]) => name.startsWith(`${project}/`) && user.email === body.email)[1];
        responseBody = { localId: user.localId, email: user.email, idToken: mint(user, project), refreshToken: "synthetic-refresh-secret" };
      } else if (url.pathname.endsWith(":delete")) {
        users.delete(storeKey(body.localId));
        responseBody = {};
      } else assert.fail("Unexpected Auth wire route");
      queueMicrotask(() => {
        const incoming = new EventEmitter();
        Object.assign(incoming, { statusCode: 200, rawHeaders: ["Content-Type", "application/json"], complete: true, destroy() {} });
        onResponse(incoming);
        incoming.emit("data", Buffer.from(JSON.stringify(responseBody)));
        incoming.emit("end");
      });
    };
    return request;
  } });
  const ctx = await setup({ sendHttp: https.send, ownerCredential: () => { ownerReads++; return { accessToken, expiresAt: now + 1000 }; } });
  const counter = createStage3RequestCounter({ preflightIds: ["preflight/local"], onStarted: async () => {}, onReserve: async (row) => reserves.push(row.operationId), onTerminal: async () => {} });
  await counter.start({ runId });
  await counter.sendPreflight("preflight/local", async () => true, (value) => value);
  counter.admit();
  const session = createCredentialFixtureSession({ runId, counter, transport: ctx.wire.send,
    keySet: { fetchedAt: now - 10, expiresAt: now + 2000, publicKeys: { wire: publicKey.export({ type: "spki", format: "pem" }) } }, digestSalt: "ab".repeat(32),
    passwords: Object.fromEntries(["user-a", "user-b", "revoked-token", "foreign-project-token"].map((name) => [name, password])),
    nowSeconds: () => now, waitUntilSeconds: async () => assert.fail("Token was issued before this second"),
    writeOwnership: async (row) => ownership.push(row), writeProof: async (row) => proofs.push(row), writeCleanup: async (row) => cleanup.push(row),
  });
  await session.prepareQuery();
  const a = session.token("user-a");
  const plain = session.token("user-plain");
  assert.notEqual(a, plain);
  await session.withForeignFixture(async (token) => assert.equal(JSON.parse(Buffer.from(token.split(".")[1], "base64url")).aud, IDP));
  await session.cleanupQuery();
  assert.equal(session.snapshot().mode, "closed");
  assert.equal(users.size, 0);
  assert.equal(calls.length, 29);
  assert.equal(calls.filter((call) => call.project === QUERY).length, 24);
  assert.equal(calls.filter((call) => call.project === IDP).length, 5);
  assert.equal(calls.filter((call) => call.key !== null).length, 6);
  assert.equal(ownerReads, 23);
  assert.deepEqual(calls.map((call) => call.operationId), reserves.slice(1));
  assert.equal(counter.snapshot().requests, 30);
  assert.equal(proofs.length, 5);
  assert.equal(ownership.length, 4);
  assert.equal(cleanup.length, 4);
  const safe = JSON.stringify([proofs, ownership, cleanup, session.snapshot()]);
  for (const secret of [password, accessToken, ...Object.values(apiKeys), a, plain, "synthetic-refresh-secret"]) assert.ok(!safe.includes(secret));
});
