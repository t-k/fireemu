import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { createAuthWireTransport } from "./storage-rules/auth-wire.mjs";
import { createStage3RequestCounter } from "./storage-rules/request-counter.mjs";

const now = 1790553600;
const adc = {
  type: "authorized_user",
  client_id: "synthetic-client.apps.googleusercontent.com",
  client_secret: "synthetic-client-secret-00001",
  refresh_token: "synthetic-refresh-token-with/slash+00002",
};
const token = "synthetic-owner-access-token-00003";
const salt = "cd".repeat(32);
const ownerPreflight = "preflight/auth/owner-token";
const keyPreflight = "preflight/auth/signing-keys";
const certUrl =
  "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";
const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const pem = publicKey.export({ type: "spki", format: "pem" });
const keyBody = { synthetic: pem };
const raw = (body, delta = {}) => ({
  status: 200,
  rawHeaders: ["Cache-Control", "public, max-age=3600, must-revalidate", "Age", "60"],
  bytes: Buffer.from(JSON.stringify(body)),
  startedAtMs: 1,
  finishedAtMs: 2,
  ...delta,
});

async function setup({
  input = adc,
  sendHttp,
  writeProof,
  reserveFailure = false,
  clock = null,
  optionDelta = {},
} = {}) {
  const module = await import("./storage-rules/credential-cache.mjs").catch((error) => {
    if (error.code === "ERR_MODULE_NOT_FOUND") return {};
    throw error;
  });
  assert.equal(typeof module.createCountedCredentialCache, "function");
  const calls = [];
  const proofs = [];
  const reservations = [];
  let current = now;
  const counter = createStage3RequestCounter({
    preflightIds: [ownerPreflight, keyPreflight],
    onStarted: async () => {},
    onReserve: async (row) => {
      reservations.push(row.operationId);
      if (reserveFailure) throw new Error(adc.refresh_token);
    },
    onTerminal: async () => {},
  });
  await counter.start({ runId: "cache-test" });
  const cache = module.createCountedCredentialCache({
    adc: input,
    counter,
    digestSalt: salt,
    nowSeconds: clock || (() => current),
    sendHttp:
      sendHttp ||
      (async (spec) => {
        assert.ok(module.CREDENTIAL_CACHE_REQUEST_IDS.includes(reservations.at(-1)));
        assert.equal(counter.snapshot().requests, reservations.length);
        calls.push({ ...spec, operationId: reservations.at(-1) });
        return spec.url === certUrl
          ? raw(keyBody)
          : raw({ access_token: token, token_type: "Bearer", expires_in: 3600 });
      }),
    writeProof: writeProof || (async (row) => proofs.push(row)),
    ...optionDelta,
  });
  const admit = async () => {
    await cache.refreshOwner(ownerPreflight);
    await cache.fetchSigningKeys(keyPreflight);
    counter.admit();
  };
  return {
    module,
    cache,
    counter,
    calls,
    proofs,
    reservations,
    admit,
    advance: (value) => {
      current = value;
    },
  };
}

test("the two preflight credential attempts reserve before dispatch and return secret-free proofs", async () => {
  const ctx = await setup();
  assert.throws(() => ctx.cache.ownerCredential(), /credential cache unavailable/);
  assert.throws(() => ctx.cache.keySet(), /credential cache unavailable/);
  assert.equal(ctx.calls.length, 0);
  const owner = await ctx.cache.refreshOwner(ownerPreflight);
  const keys = await ctx.cache.fetchSigningKeys(keyPreflight);
  assert.equal(owner.sendAuthorized, false);
  assert.equal(keys.sendAuthorized, false);
  assert.equal(ctx.cache.ownerCredential().accessToken, token);
  assert.equal(ctx.cache.ownerCredential().expiresAt, now + 3600);
  assert.deepEqual(ctx.cache.keySet(), {
    fetchedAt: now,
    expiresAt: now + 3540,
    publicKeys: keyBody,
  });
  assert.deepEqual(ctx.reservations, [ownerPreflight, keyPreflight]);
  assert.equal(ctx.calls.length, 2);
  assert.equal(ctx.counter.snapshot().requests, 2);
  for (const secret of [token, adc.client_secret, adc.refresh_token])
    assert.ok(!JSON.stringify(ctx.proofs).includes(secret));
  assert.match(owner.tokenDigest, /^[a-f0-9]{64}$/);
  assert.equal(keys.sourceUrl, certUrl);
});

test("OAuth refresh uses the exact fixed form endpoint without Bearer or API key headers", async () => {
  const ctx = await setup();
  await ctx.cache.refreshOwner(ownerPreflight);
  const call = ctx.calls[0];
  assert.equal(call.url, "https://oauth2.googleapis.com/token");
  assert.equal(call.method, "POST");
  assert.equal(call.headers["content-type"], "application/x-www-form-urlencoded");
  assert.ok(!Object.hasOwn(call.headers, "authorization"));
  assert.deepEqual(Object.fromEntries(new URLSearchParams(call.body.toString())), {
    grant_type: "refresh_token",
    client_id: adc.client_id,
    client_secret: adc.client_secret,
    refresh_token: adc.refresh_token,
  });
});

test("Firebase public signing keys use only the exact bodyless certificate GET", async () => {
  const ctx = await setup();
  await ctx.cache.fetchSigningKeys(keyPreflight);
  const call = ctx.calls[0];
  assert.equal(call.url, certUrl);
  assert.equal(call.method, "GET");
  assert.equal(call.body, null);
  assert.ok(!Object.hasOwn(call.headers, "authorization"));
});

test("the finite 19 IDs cover preflight, normal renewal and owner-only recovery", async () => {
  const ctx = await setup();
  assert.equal(ctx.module.CREDENTIAL_CACHE_REQUEST_IDS.length, 19);
  assert.ok(Object.isFrozen(ctx.module.CREDENTIAL_CACHE_REQUEST_IDS));
  await ctx.admit();
  for (let slot = 1; slot <= 8; slot++)
    await ctx.cache.refreshOwner(`auth-shared/owner-token/${slot}`);
  await ctx.cache.fetchSigningKeys("auth-shared/signing-keys/1");
  ctx.counter.enterRecovery();
  for (let slot = 1; slot <= 8; slot++)
    await ctx.cache.refreshOwner(`recovery/auth-shared/owner-token/${slot}`);
  assert.equal(ctx.calls.length, 19);
  assert.deepEqual(ctx.reservations, ctx.module.CREDENTIAL_CACHE_REQUEST_IDS);
  assert.deepEqual(
    ctx.calls.map((call) => call.operationId),
    ctx.reservations,
  );
  assert.equal(ctx.counter.snapshot().recovery, 8);
});

for (const [kind, id] of [
  ["owner", "preflight/auth/other"],
  ["owner", keyPreflight],
  ["keys", ownerPreflight],
  ["owner", "auth-shared/owner-token/9"],
  ["keys", "recovery/auth-shared/signing-keys/1"],
  ["owner", `${ownerPreflight}\n`],
]) {
  test(`the unknown or mismatched credential ID ${id.trim()} cannot dispatch`, async () => {
    const ctx = await setup();
    await assert.rejects(
      kind === "owner" ? ctx.cache.refreshOwner(id) : ctx.cache.fetchSigningKeys(id),
      /credential cache request refused/,
    );
    assert.equal(ctx.calls.length, 0);
  });
}

test("a normal or recovery renewal cannot run during preflight", async () => {
  const ctx = await setup();
  for (const id of ["auth-shared/owner-token/1", "recovery/auth-shared/owner-token/1"])
    await assert.rejects(ctx.cache.refreshOwner(id), /credential cache request refused/);
  assert.equal(ctx.calls.length, 0);
});

test("a completed preflight ID cannot be reused after admission", async () => {
  const ctx = await setup();
  await ctx.admit();
  await assert.rejects(ctx.cache.refreshOwner(ownerPreflight), /credential cache request refused/);
  assert.equal(ctx.calls.length, 2);
});

test("a repeated normal ID is not sent twice", async () => {
  const ctx = await setup();
  await ctx.admit();
  await ctx.cache.refreshOwner("auth-shared/owner-token/1");
  await assert.rejects(
    ctx.cache.refreshOwner("auth-shared/owner-token/1"),
    /credential cache request failed/,
  );
  assert.equal(ctx.calls.length, 3);
});

test("ADC data is copied before later caller changes", async () => {
  const input = { ...adc };
  const ctx = await setup({ input });
  input.refresh_token = "changed";
  await ctx.cache.refreshOwner(ownerPreflight);
  assert.equal(
    new URLSearchParams(ctx.calls[0].body.toString()).get("refresh_token"),
    adc.refresh_token,
  );
});

for (const delta of [
  { type: "service_account" },
  { client_id: "short" },
  { client_secret: "short" },
  { refresh_token: "short" },
  { extra: token },
]) {
  test(`invalid ADC field ${Object.keys(delta)[0]} is refused without dispatch`, async () => {
    await assert.rejects(setup({ input: { ...adc, ...delta } }), /invalid credential cache input/);
  });
}

test("an ADC getter is rejected without reading the private value", async () => {
  let touched = false;
  const input = { ...adc };
  Object.defineProperty(input, "refresh_token", {
    enumerable: true,
    get() {
      touched = true;
      throw new Error(adc.refresh_token);
    },
  });
  await assert.rejects(setup({ input }), /invalid credential cache input/);
  assert.equal(touched, false);
});

for (const delta of [
  { access_token: "owner" },
  { token_type: "DPoP" },
  { expires_in: 30 },
  { expires_in: "3600" },
  { expires_in: 7201 },
]) {
  test(`an invalid OAuth response field ${Object.keys(delta)[0]} cannot enable the cache`, async () => {
    const ctx = await setup({
      sendHttp: async () =>
        raw({ access_token: token, token_type: "Bearer", expires_in: 3600, ...delta }),
    });
    await assert.rejects(ctx.cache.refreshOwner(ownerPreflight), /credential cache request failed/);
    assert.throws(() => ctx.cache.ownerCredential(), /credential cache unavailable/);
  });
}

test("getters never renew an expired owner token or key snapshot", async () => {
  const ctx = await setup();
  await ctx.admit();
  ctx.advance(now + 3570);
  assert.throws(() => ctx.cache.ownerCredential(), /credential cache unavailable/);
  assert.throws(() => ctx.cache.keySet(), /credential cache unavailable/);
  assert.equal(ctx.calls.length, 2);
});

test("clock rollback cannot make a cached credential appear fresh", async () => {
  const ctx = await setup();
  await ctx.admit();
  ctx.advance(now - 1);
  assert.throws(() => ctx.cache.ownerCredential(), /credential cache unavailable/);
  assert.throws(() => ctx.cache.keySet(), /credential cache unavailable/);
});

test("clock rollback after observing expiry cannot revive previously expired caches", async () => {
  const ctx = await setup();
  await ctx.admit();
  ctx.advance(now + 4000);
  assert.throws(() => ctx.cache.ownerCredential(), /credential cache unavailable/);
  assert.throws(() => ctx.cache.keySet(), /credential cache unavailable/);
  ctx.advance(now + 60);
  assert.throws(() => ctx.cache.ownerCredential(), /credential cache unavailable/);
  assert.throws(() => ctx.cache.keySet(), /credential cache unavailable/);
  assert.equal(ctx.calls.length, 2);
});

test("the owner TTL starts at dispatch, including HTTP delay", async () => {
  let current = now;
  const ctx = await setup({
    clock: () => current,
    sendHttp: async () => {
      current += 40;
      return raw({ access_token: token, token_type: "Bearer", expires_in: 60 });
    },
  });
  await assert.rejects(ctx.cache.refreshOwner(ownerPreflight), /credential cache request failed/);
  assert.throws(() => ctx.cache.ownerCredential(), /credential cache unavailable/);
});

for (const kind of ["owner", "keys"]) {
  test(`${kind === "owner" ? "an" : "a"} ${kind} proof delayed past cache expiry cannot enable the cache`, async () => {
    let current = now;
    const ctx = await setup({
      clock: () => current,
      writeProof: async () => {
        current += 4000;
      },
    });
    await assert.rejects(
      kind === "owner"
        ? ctx.cache.refreshOwner(ownerPreflight)
        : ctx.cache.fetchSigningKeys(keyPreflight),
      /credential cache request failed/,
    );
    assert.throws(
      () => (kind === "owner" ? ctx.cache.ownerCredential() : ctx.cache.keySet()),
      /credential cache unavailable/,
    );
  });
}

for (const headers of [
  [],
  ["Cache-Control", "public"],
  ["Cache-Control", "max-age=0"],
  ["Cache-Control", "max-age=3600, max-age=7200"],
  ["Cache-Control", "max-age=3600, no-store"],
  ["Cache-Control", "max-age=3600, no-cache"],
  ["Cache-Control", "max-age=3600", "cache-control", "max-age=7200"],
  ["Cache-Control", "max-age=3600", "Age", "3600"],
  ["Cache-Control", "max-age=3600", "Age", "-1"],
  ["Cache-Control", "max-age=3600", "Age", "1", "age", "2"],
]) {
  test("missing, ambiguous or stale certificate cache headers cannot enable keys", async () => {
    const ctx = await setup({ sendHttp: async () => raw(keyBody, { rawHeaders: headers }) });
    await assert.rejects(
      ctx.cache.fetchSigningKeys(keyPreflight),
      /credential cache request failed/,
    );
    assert.throws(() => ctx.cache.keySet(), /credential cache unavailable/);
  });
}

test("certificate max-age without Age remains usable and has a conservative expiry", async () => {
  const ctx = await setup({
    sendHttp: async () => raw(keyBody, { rawHeaders: ["cache-control", 'public, max-age="60"'] }),
  });
  await ctx.cache.fetchSigningKeys(keyPreflight);
  assert.equal(ctx.cache.keySet().expiresAt, now + 60);
});

for (const body of [
  {},
  { key: "not-a-key" },
  { "bad kid": pem },
  [pem],
  Object.fromEntries(Array.from({ length: 21 }, (_, index) => [`key${index}`, pem])),
]) {
  test("an invalid public signing key set cannot enter the cache", async () => {
    const ctx = await setup({ sendHttp: async () => raw(body) });
    await assert.rejects(
      ctx.cache.fetchSigningKeys(keyPreflight),
      /credential cache request failed/,
    );
  });
}

for (const key of [
  generateKeyPairSync("rsa", { modulusLength: 1024 }).publicKey,
  generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey,
]) {
  test("a weak or non-RSA signing key is refused", async () => {
    const ctx = await setup({
      sendHttp: async () => raw({ key: key.export({ type: "spki", format: "pem" }) }),
    });
    await assert.rejects(
      ctx.cache.fetchSigningKeys(keyPreflight),
      /credential cache request failed/,
    );
  });
}

for (const status of [301, 400, 429, 500]) {
  test(`credential HTTP ${status} fails without retrying or reflecting its body`, async () => {
    let calls = 0;
    const ctx = await setup({
      sendHttp: async () => {
        calls++;
        return raw({ error: adc.refresh_token }, { status });
      },
    });
    await assert.rejects(
      ctx.cache.refreshOwner(ownerPreflight),
      (error) => error.message === "credential cache request failed",
    );
    assert.equal(calls, 1);
  });
}

test("an oversized OAuth JSON response cannot enable an otherwise valid token", async () => {
  const ctx = await setup({
    sendHttp: async () =>
      raw({
        access_token: token,
        token_type: "Bearer",
        expires_in: 3600,
        padding: "a".repeat(256 * 1024),
      }),
  });
  await assert.rejects(ctx.cache.refreshOwner(ownerPreflight), /credential cache request failed/);
});

test("invalid UTF-8 inside the response JSON cannot enter a credential proof", async () => {
  const prefix = Buffer.from(
    `{"access_token":"${token}","token_type":"Bearer","expires_in":3600,"padding":"`,
  );
  const bytes = Buffer.concat([prefix, Buffer.from([0xff]), Buffer.from('"}')]);
  const ctx = await setup({ sendHttp: async () => raw({}, { bytes }) });
  await assert.rejects(ctx.cache.refreshOwner(ownerPreflight), /credential cache request failed/);
});

test("response Buffer metadata is rejected without invoking its getter", async () => {
  let touched = false;
  const response = raw({ access_token: token, token_type: "Bearer", expires_in: 3600 });
  Object.defineProperty(response.bytes, "length", {
    get() {
      touched = true;
      throw new Error(token);
    },
  });
  const ctx = await setup({ sendHttp: async () => response });
  await assert.rejects(ctx.cache.refreshOwner(ownerPreflight), /credential cache request failed/);
  assert.equal(touched, false);
});

test("a certificate header getter is refused without being invoked", async () => {
  let touched = false;
  const headers = ["Cache-Control", "max-age=3600"];
  Object.defineProperty(headers, "1", {
    enumerable: true,
    get() {
      touched = true;
      throw new Error(token);
    },
  });
  const ctx = await setup({ sendHttp: async () => raw(keyBody, { rawHeaders: headers }) });
  await assert.rejects(ctx.cache.fetchSigningKeys(keyPreflight), /credential cache request failed/);
  assert.equal(touched, false);
});

test("lower HTTP and reservation exceptions cannot expose ADC secrets", async () => {
  for (const delta of [
    {
      sendHttp: async () => {
        throw new Error(adc.refresh_token);
      },
    },
    { reserveFailure: true },
  ]) {
    const ctx = await setup(delta);
    await assert.rejects(
      ctx.cache.refreshOwner(ownerPreflight),
      (error) => error.message === "credential cache request failed",
    );
    assert.throws(() => ctx.cache.ownerCredential(), /credential cache unavailable/);
  }
});

test("proof journal failure forbids getters and all further credential requests", async () => {
  let calls = 0;
  const ctx = await setup({
    sendHttp: async () => {
      calls++;
      return raw({ access_token: token, token_type: "Bearer", expires_in: 3600 });
    },
    writeProof: async () => {
      throw new Error(token);
    },
  });
  await assert.rejects(
    ctx.cache.refreshOwner(ownerPreflight),
    (error) => error.message === "credential cache journal uncertain",
  );
  assert.throws(() => ctx.cache.ownerCredential(), /credential cache unavailable/);
  await assert.rejects(
    ctx.cache.fetchSigningKeys(keyPreflight),
    /credential cache request refused/,
  );
  assert.equal(calls, 1);
});

test("a normal proof failure disables existing keys and cannot resume through recovery refresh", async () => {
  let failed = false;
  const ctx = await setup({
    writeProof: async () => {
      if (failed) throw new Error(token);
    },
  });
  await ctx.admit();
  failed = true;
  await assert.rejects(
    ctx.cache.refreshOwner("auth-shared/owner-token/1"),
    (error) => error.message === "credential cache journal uncertain",
  );
  assert.equal(ctx.counter.snapshot().mode, "recovery");
  assert.throws(() => ctx.cache.keySet(), /credential cache unavailable/);
  assert.throws(() => ctx.cache.ownerCredential(), /credential cache unavailable/);
  failed = false;
  await assert.rejects(
    ctx.cache.refreshOwner("recovery/auth-shared/owner-token/1"),
    /credential cache request refused/,
  );
  assert.equal(ctx.calls.length, 3);
});

test("a pending credential operation blocks concurrent operations and getter access", async () => {
  let enter;
  let resume;
  const pending = new Promise((resolve) => {
    enter = resolve;
  });
  const resumed = new Promise((resolve) => {
    resume = resolve;
  });
  const ctx = await setup({
    writeProof: async () => {
      enter();
      await resumed;
    },
  });
  const first = ctx.cache.refreshOwner(ownerPreflight);
  await pending;
  await assert.rejects(
    ctx.cache.fetchSigningKeys(keyPreflight),
    /credential cache request refused/,
  );
  assert.throws(() => ctx.cache.ownerCredential(), /credential cache unavailable/);
  resume();
  await first;
  assert.equal(ctx.calls.length, 1);
});

test("the cache supplies the Auth wire getter and only explicit refresh performs OAuth HTTP", async () => {
  const ctx = await setup();
  await ctx.admit();
  const wireCalls = [];
  const wire = createAuthWireTransport({
    runId: "cache-test",
    apiKeys: {
      "fireemu-oracle-query": "synthetic-query-api-key-00004",
      "fireemu-oracle-idp": "synthetic-idp-api-key-0000005",
    },
    ownerCredential: ctx.cache.ownerCredential,
    nowSeconds: () => now,
    sendHttp: async (spec) => {
      wireCalls.push(spec);
      return raw({});
    },
  });
  const spec = {
    project: "fireemu-oracle-query",
    method: "POST",
    origin: "https://identitytoolkit.googleapis.com",
    path: "/v1/projects/fireemu-oracle-query/accounts:lookup",
    credential: "owner-oauth",
    apiKeyReference: "query-api-key",
    body: { localId: ["storage-rules-cache-test-user-a"] },
  };
  await ctx.counter.send("auth/user-a/lookup-created", () =>
    wire.send("auth/user-a/lookup-created", spec),
  );
  assert.equal(wireCalls[0].headers.authorization, `Bearer ${token}`);
  assert.equal(ctx.calls.length, 2);
  ctx.advance(now + 3570);
  await assert.rejects(
    ctx.counter.send("auth/user-a/lookup-claims", () =>
      wire.send("auth/user-a/lookup-claims", spec),
    ),
    /Auth owner credential unavailable/,
  );
  assert.equal(wireCalls.length, 1);
  assert.equal(ctx.calls.length, 2);
  await ctx.cache.refreshOwner("recovery/auth-shared/owner-token/1");
  assert.equal(ctx.calls.length, 3);
});
