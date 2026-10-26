// The Admin SDK App Check instrumentation, against the real firebase-admin copies installed
// under conformance/ and tools/sdk-smoke (13.x and 14.x), plus synthetic packages for the
// version and structure probes. A fake daemon answers over the same frame shapes as the real
// one; the Rust side is tested in crates/fireemu-adapter-functions/tests/admin_app_check.rs.
//
// Oracle for the error shapes: the SDK's own, unpatched `verifySignature` run against real
// RS256 tokens and a real key fetcher, so "the same code and message production raises" is
// compared with what the SDK raises, not with a copy of its strings.
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import baseTest from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import { createAdminChannel, instrumentAdminAppCheck, MAX_IN_FLIGHT } from "./admin-app-check.mjs";

// A hang is a failure of the named test, not of the whole run.
const TEST_TIMEOUT_MS = 20_000;
function test(name, optionsOrFn, maybeFn) {
  return typeof optionsOrFn === "function"
    ? baseTest(name, { timeout: TEST_TIMEOUT_MS }, optionsOrFn)
    : baseTest(name, { timeout: TEST_TIMEOUT_MS, ...optionsOrFn }, maybeFn);
}

const here = dirname(fileURLToPath(import.meta.url));
const required = process.env.FIREEMU_REQUIRE_SDK === "1";
const PROJECT = "demo-app";

/// Every installed firebase-admin copy, one per version. CI installs 14.x under conformance/ and
/// tools/sdk-smoke; a developer can add more package directories (a 13.x copy, say) with
/// FIREEMU_ADMIN_SDK_DIRS, separated by the platform path delimiter.
const copies = new Map();
for (const dir of [
  join(here, "..", "..", "conformance", "node_modules", "firebase-admin"),
  join(here, "..", "sdk-smoke", "node_modules", "firebase-admin"),
  ...(process.env.FIREEMU_ADMIN_SDK_DIRS ?? "").split(delimiter).filter(Boolean),
]) {
  if (!existsSync(join(dir, "package.json"))) continue;
  const version = JSON.parse(readFileSync(join(dir, "package.json"), "utf8")).version;
  if (!copies.has(version)) copies.set(version, dir);
}
const majors = new Set([...copies.keys()].map((v) => Number.parseInt(v, 10)));

test("a firebase-admin 14 copy is installed for these tests", { skip: !required }, () => {
  assert.ok(majors.has(14), "firebase-admin 14 is required here (FIREEMU_REQUIRE_SDK=1) under conformance/ or tools/sdk-smoke");
});

// ---------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------

const b64 = (value) => Buffer.from(typeof value === "string" ? value : JSON.stringify(value)).toString("base64url");
const nowSeconds = () => Math.floor(Date.now() / 1000);
const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const other = generateKeyPairSync("rsa", { modulusLength: 2048 });
const PEM = publicKey.export({ type: "spki", format: "pem" });

function claims(overrides = {}) {
  return {
    iss: "https://firebaseappcheck.googleapis.com/1234567890",
    aud: ["projects/1234567890", `projects/${PROJECT}`],
    sub: "1:1234567890:web:abc",
    iat: nowSeconds() - 10,
    exp: nowSeconds() + 3600,
    jti: "j",
    ...overrides,
  };
}

function token({ header = {}, payload = {}, key = privateKey } = {}) {
  const head = b64({ alg: "RS256", typ: "JWT", kid: "k1", ...header });
  const body = b64(claims(payload));
  const signature = sign("RSA-SHA256", Buffer.from(`${head}.${body}`), key).toString("base64url");
  return `${head}.${body}.${signature}`;
}

/// A source directory whose `firebase-admin` resolves to `adminDir`.
async function codebase(adminDir) {
  const dir = await mkdtemp(join(tmpdir(), "admin-app-check-"));
  await writeFile(join(dir, "package.json"), JSON.stringify({ name: "functions", main: "index.js" }));
  await mkdir(join(dir, "node_modules"), { recursive: true });
  if (adminDir) await symlink(adminDir, join(dir, "node_modules", "firebase-admin"), "dir");
  return dir;
}

/// A fake daemon. `respond(frame)` returns the verdict fields for one question, or undefined
/// to stay silent. The self-test's question (another project) is answered like the real
/// daemon answers it: no matching key.
function fakeDaemon(respond = () => ({ ok: true }), { timeoutMs } = {}) {
  const asked = [];
  const daemon = {
    asked,
    channel: null,
    send(frame) {
      asked.push(frame);
      const verdict =
        frame.projectId === "fireemu-self-test"
          ? { ok: false, reason: "no-matching-kid" }
          : respond(frame);
      if (verdict === undefined) return;
      queueMicrotask(() =>
        daemon.channel.deliver({ type: "appCheck:verdict", requestId: frame.requestId, ...verdict }),
      );
    },
  };
  daemon.channel = createAdminChannel((frame) => daemon.send(frame), { timeoutMs });
  return daemon;
}

async function install(adminDir, respond, options = {}) {
  const sourceDir = await codebase(adminDir);
  const daemon = fakeDaemon(respond, options);
  const handle = await instrumentAdminAppCheck(sourceDir, daemon.channel, {
    enabled: true,
    ...options,
  });
  daemon.handle = handle;
  daemon.sourceDir = sourceDir;
  return { handle, daemon };
}

function sdk(adminDir) {
  const req = createRequire(join(adminDir, "package.json"));
  return {
    ...req("./lib/app/index.js"),
    ...req("./lib/app-check/index.js"),
    jwt: req("./lib/utils/jwt.js"),
    Verifier: req("./lib/app-check/token-verifier.js").AppCheckTokenVerifier,
    Client: req("./lib/app-check/app-check-api-client-internal.js").AppCheckApiClient,
  };
}

let appCounter = 0;
function appCheckOf(admin, options = {}) {
  const app = admin.initializeApp({ projectId: PROJECT, ...options }, `t${++appCounter}`);
  return { app, appCheck: admin.getAppCheck(app) };
}

const shape = (error) => ({
  name: error?.constructor?.name,
  code: error?.code,
  message: error?.message,
  cause: error?.cause ? { code: error.cause.code, message: error.cause.message } : undefined,
});

/// The stock SDK's error for `jwt` with the given key fetcher.
async function stockError(admin, jwtToken, fetchPublicKeys) {
  const verifier = new admin.Verifier({ options: { projectId: PROJECT } });
  verifier.signatureVerifier = new admin.jwt.PublicKeySignatureVerifier({ fetchPublicKeys });
  const original = stockVerifySignature.get(admin.Verifier);
  try {
    await original.call(verifier, jwtToken);
  } catch (error) {
    return error;
  }
  assert.fail("the stock SDK accepted the token");
}
const stockVerifySignature = new Map();

for (const [version, adminDir] of copies) {
  const admin = sdk(adminDir);
  stockVerifySignature.set(admin.Verifier, admin.Verifier.prototype.verifySignature);
  const label = `firebase-admin ${version}`;

  test(`${label}: a daemon-accepted token verifies and the SDK returns its claims`, async () => {
    const { handle, daemon } = await install(adminDir);
    try {
      assert.equal(handle.supported, true);
      assert.equal(handle.report.instrumentation, "ok");
      assert.equal(handle.report.firebaseAdminVersion, version);
      const { app, appCheck } = appCheckOf(admin);
      const jwtToken = token();
      const result = await appCheck.verifyToken(jwtToken);
      assert.equal(result.appId, "1:1234567890:web:abc");
      assert.equal(result.token.sub, "1:1234567890:web:abc");
      const question = daemon.asked.at(-1);
      assert.deepEqual(Object.keys(question).sort(), ["projectId", "requestId", "token", "type"]);
      assert.equal(question.type, "appCheck:verify");
      assert.equal(question.projectId, PROJECT);
      assert.equal(question.token, jwtToken);
      await admin.deleteApp(app);
    } finally {
      handle.restore();
    }
  });

  test(`${label}: every verdict raises the error the analogous production condition raises`, async () => {
    const keys = { k1: PEM };
    const cases = [
      {
        reason: "token-expired",
        jwt: token({ payload: { iat: nowSeconds() - 7200, exp: nowSeconds() - 3600 } }),
        fetch: async () => keys,
      },
      { reason: "invalid-signature", jwt: token({ key: other.privateKey }), fetch: async () => keys },
      { reason: "no-matching-kid", jwt: token({ header: { kid: "unknown" } }), fetch: async () => keys },
    ];
    for (const { reason, jwt: jwtToken, fetch } of cases) {
      const expected = shape(await stockError(admin, jwtToken, fetch));
      const { handle } = await install(adminDir, () => ({ ok: false, reason }));
      try {
        const { app, appCheck } = appCheckOf(admin);
        const actual = await appCheck.verifyToken(jwtToken).then(
          () => assert.fail("accepted"),
          shape,
        );
        assert.deepEqual(actual, expected, reason);
        await admin.deleteApp(app);
      } finally {
        handle.restore();
      }
    }
  });

  test(`${label}: an unanswered question fails like an unreachable key fetch`, async () => {
    const jwtToken = token();
    const expected = shape(
      await stockError(admin, jwtToken, async () => {
        throw new Error("Error fetching Json Web Keys: the key server is unreachable");
      }),
    );
    const wording = [
      ["unavailable", () => ({ ok: false, reason: "unavailable" }), "the daemon cannot verify App Check tokens"],
      ["a reason this runner does not know", () => ({ ok: false, reason: "from-the-future" }), "the daemon cannot verify App Check tokens"],
      ["a reason named like an inherited property", () => ({ ok: false, reason: "constructor" }), "the daemon cannot verify App Check tokens"],
      ["a reason named like another inherited property", () => ({ ok: false, reason: "__proto__" }), "the daemon cannot verify App Check tokens"],
      ["a verdict without a reason", () => ({ ok: false }), "the daemon cannot verify App Check tokens"],
      ["silence", () => undefined, "the daemon did not answer in time"],
    ];
    for (const [name, respond, why] of wording) {
      const { handle, daemon } = await install(adminDir, respond, { timeoutMs: 80 });
      try {
        const { app, appCheck } = appCheckOf(admin);
        const actual = shape(await appCheck.verifyToken(jwtToken).then(() => assert.fail("accepted"), (e) => e));
        assert.equal(actual.code, expected.code, name);
        assert.equal(actual.message, `Error fetching Json Web Keys: ${why}`, name);
        assert.equal(actual.name, expected.name, name);
        assert.equal(daemon.channel.pending(), 0, "no question is left pending");
        await admin.deleteApp(app);
      } finally {
        handle.restore();
      }
    }
  });

  test(`${label}: claim reasons raise invalid-argument with a fixed message`, async () => {
    for (const [reason, pattern] of [
      ["claims", /incorrect "iss" \(issuer\) or "aud" \(audience\) claim/],
      ["not-yet-valid", /"iat" \(issued-at\) claim in the future/],
      ["unknown-app", /names no registered, enabled app/],
      ["malformed", /^Decoding App Check token failed\./],
    ]) {
      const { handle } = await install(adminDir, () => ({ ok: false, reason }));
      try {
        const { app, appCheck } = appCheckOf(admin);
        const error = await appCheck.verifyToken(token()).then(() => assert.fail("accepted"), (e) => e);
        assert.equal(error.code, "app-check/invalid-argument", reason);
        assert.match(error.message, pattern, reason);
        await admin.deleteApp(app);
      } finally {
        handle.restore();
      }
    }
  });

  test(`${label}: the SDK still decodes and checks claims first, and the daemon is not asked`, async () => {
    const { handle, daemon } = await install(adminDir);
    try {
      const { app, appCheck } = appCheckOf(admin);
      const asked = () => daemon.asked.filter((f) => f.projectId === PROJECT).length;
      const rows = [
        ["not a jwt", "garbage", /^Decoding App Check token failed\./],
        ["wrong algorithm", token({ header: { alg: "HS256" } }), /incorrect algorithm/],
        ["another project's audience", token({ payload: { aud: ["projects/other"] } }), /incorrect "aud"/],
        ["a foreign issuer", token({ payload: { iss: "https://evil.example/1" } }), /incorrect "iss"/],
        ["no subject", token({ payload: { sub: undefined } }), /no "sub"/],
        ["an empty subject", token({ payload: { sub: "" } }), /empty string "sub"/],
      ];
      for (const [name, jwtToken, pattern] of rows) {
        const before = asked();
        const error = await appCheck.verifyToken(jwtToken).then(() => assert.fail(name), (e) => e);
        assert.equal(error.code, "app-check/invalid-argument", name);
        assert.match(error.message, pattern, name);
        assert.equal(asked(), before, `${name}: the daemon was not asked`);
      }
      assert.throws(() => appCheck.verifyToken(5), { message: "App check token must be a non-null string." });
      await admin.deleteApp(app);
    } finally {
      handle.restore();
    }
  });

  test(`${label}: consume:true is refused locally and never reaches the transport`, async () => {
    const { handle } = await install(adminDir, () => ({ ok: true }));
    const attempts = [];
    const realRequest = { http: http.request, https: https.request };
    const realConnect = net.Socket.prototype.connect;
    const realFetch = globalThis.fetch;
    http.request = (...a) => { attempts.push(["http.request", String(a[0]?.href ?? a[0])]); throw new Error("blocked"); };
    https.request = (...a) => { attempts.push(["https.request", String(a[0]?.href ?? a[0])]); throw new Error("blocked"); };
    net.Socket.prototype.connect = function () { attempts.push(["net.connect"]); throw new Error("blocked"); };
    globalThis.fetch = async (u) => { attempts.push(["fetch", String(u)]); throw new Error("blocked"); };
    let tokenRequested = 0;
    try {
      // A credential that would happily authorize the consume request.
      const credential = {
        getAccessToken: async () => {
          tokenRequested += 1;
          return { access_token: "would-work", expires_in: 3600 };
        },
      };
      const { app, appCheck } = appCheckOf(admin, { credential });
      for (const options of [{ consume: true }, { consume: 1 }]) {
        const error = await appCheck.verifyToken(token(), options).then(() => assert.fail("accepted"), (e) => e);
        assert.equal(error.code, "app-check/unimplemented");
        assert.match(error.message, /APPCHECK-REPLAY-1/);
        assert.match(error.message, /never called/);
      }
      // consume:false and an absent option still verify, and report no consumption.
      for (const options of [undefined, {}, { consume: false }]) {
        const result = await appCheck.verifyToken(token(), options);
        assert.equal(result.alreadyConsumed, undefined);
      }
      // An invalid token with consume:true fails as a token, before any consumption.
      const bad = await appCheck.verifyToken("garbage", { consume: true }).then(() => assert.fail("accepted"), (e) => e);
      assert.match(bad.message, /^Decoding App Check token failed\./);
      assert.deepEqual(attempts, []);
      assert.equal(tokenRequested, 0, "the credential was never asked for an access token");
      await admin.deleteApp(app);
    } finally {
      http.request = realRequest.http;
      https.request = realRequest.https;
      net.Socket.prototype.connect = realConnect;
      globalThis.fetch = realFetch;
      handle.restore();
    }
  });

  test(`${label}: restore puts the SDK back exactly`, async () => {
    const before = [admin.Verifier.prototype.verifySignature, admin.Client.prototype.verifyReplayProtection];
    const { handle } = await install(adminDir);
    assert.notEqual(admin.Verifier.prototype.verifySignature, before[0]);
    assert.notEqual(admin.Client.prototype.verifyReplayProtection, before[1]);
    handle.restore();
    assert.equal(admin.Verifier.prototype.verifySignature, before[0]);
    assert.equal(admin.Client.prototype.verifyReplayProtection, before[1]);
  });
}


// ---------------------------------------------------------------------------------------
// Pairwise matrix: verdict x consume x SDK pre-check x load. The rows are the PICT model
// `verdict: accept, no-matching-kid, invalid-signature, token-expired, malformed, claims,
// not-yet-valid, unknown-app, unavailable, silent, disposed; consume: absent, false, true;
// precheck: none, garbage, wrong-audience; load: single, concurrent`, generated with the
// must-have rows (valid token, consumed valid token, epoch rejection under load, a silent
// daemon, disposal under load, an SDK pre-check failure with consume) first. The expected
// outcome comes from the SDK's own wording, written out here, not from the module's tables.
// ---------------------------------------------------------------------------------------

const MATRIX = [
  ["accept", "absent", "none", "single"],
  ["accept", "true", "none", "single"],
  ["no-matching-kid", "absent", "none", "single"],
  ["no-matching-kid", "true", "none", "concurrent"],
  ["unavailable", "true", "none", "single"],
  ["silent", "absent", "none", "single"],
  ["disposed", "false", "none", "concurrent"],
  ["accept", "true", "garbage", "single"],
  ["no-matching-kid", "absent", "garbage", "concurrent"],
  ["no-matching-kid", "false", "wrong-audience", "single"],
  ["invalid-signature", "true", "wrong-audience", "concurrent"],
  ["token-expired", "absent", "wrong-audience", "concurrent"],
  ["unknown-app", "false", "garbage", "concurrent"],
  ["not-yet-valid", "false", "none", "concurrent"],
  ["disposed", "absent", "wrong-audience", "single"],
  ["silent", "true", "wrong-audience", "concurrent"],
  ["silent", "false", "garbage", "concurrent"],
  ["claims", "false", "wrong-audience", "single"],
  ["not-yet-valid", "true", "wrong-audience", "single"],
  ["unknown-app", "absent", "wrong-audience", "single"],
  ["unavailable", "absent", "wrong-audience", "concurrent"],
  ["invalid-signature", "absent", "garbage", "single"],
  ["malformed", "true", "wrong-audience", "concurrent"],
  ["claims", "true", "none", "concurrent"],
  ["claims", "absent", "garbage", "concurrent"],
  ["unknown-app", "true", "none", "concurrent"],
  ["malformed", "absent", "garbage", "single"],
  ["token-expired", "false", "garbage", "single"],
  ["malformed", "false", "none", "single"],
  ["not-yet-valid", "absent", "garbage", "concurrent"],
  ["disposed", "true", "garbage", "single"],
  ["accept", "false", "wrong-audience", "concurrent"],
  ["token-expired", "true", "none", "concurrent"],
  ["invalid-signature", "false", "none", "single"],
  ["unavailable", "false", "garbage", "single"],
];

const SDK_WORDING = {
  "no-matching-kid": ["app-check/invalid-argument", /has "kid" claim which does not correspond to a known public key\. Most likely the provided App Check token is expired, so get a fresh token from your client app and try again\.$/],
  "invalid-signature": ["app-check/invalid-argument", /^The provided App Check token has invalid signature\.$/],
  "token-expired": ["app-check/app-check-token-expired", /^The provided App Check token has expired\. Get a fresh App Check token from your client app and try again\.$/],
  malformed: ["app-check/invalid-argument", /^Decoding App Check token failed\. Make sure you passed the entire string JWT which represents the Firebase App Check token\.$/],
  claims: ["app-check/invalid-argument", /incorrect "iss" \(issuer\) or "aud" \(audience\) claim/],
  "not-yet-valid": ["app-check/invalid-argument", /"iat" \(issued-at\) claim in the future/],
  "unknown-app": ["app-check/invalid-argument", /names no registered, enabled app/],
  unavailable: ["app-check/invalid-argument", /^Error fetching Json Web Keys: the daemon cannot verify App Check tokens$/],
  silent: ["app-check/invalid-argument", /^Error fetching Json Web Keys: the daemon did not answer in time$/],
  disposed: ["app-check/invalid-argument", /^Error fetching Json Web Keys: the Functions runner is shutting down$/],
};

for (const [version, adminDir] of copies) {
  const admin = sdk(adminDir);
  for (const [verdictName, consumeName, precheck, load] of MATRIX) {
    test(`${version} matrix: ${verdictName} / consume ${consumeName} / ${precheck} / ${load}`, async () => {
      const respond = (frame) => {
        if (verdictName === "accept") return { ok: true };
        if (verdictName === "silent" || verdictName === "disposed") return undefined;
        return { ok: false, reason: verdictName };
      };
      const { handle, daemon } = await install(adminDir, respond, { timeoutMs: verdictName === "silent" ? 60 : 60_000 });
      try {
        const { app, appCheck } = appCheckOf(admin);
        const options = consumeName === "absent" ? undefined : { consume: consumeName === "true" };
        const tokenFor = (i) =>
          precheck === "garbage" ? "not-a-token"
          : precheck === "wrong-audience" ? token({ payload: { aud: ["projects/other"], jti: `j${i}` } })
          : token({ payload: { jti: `j${i}` } });
        const askedBefore = () => daemon.asked.filter((f) => f.projectId === PROJECT).length;
        const before = askedBefore();
        const count = load === "single" ? 1 : 5;
        const calls = Array.from({ length: count }, (_, i) =>
          appCheck.verifyToken(tokenFor(i), options).then((value) => ({ value }), (error) => ({ error })),
        );
        if (verdictName === "disposed" && precheck === "none") {
          await new Promise((resolve) => setTimeout(resolve, 20));
          daemon.channel.dispose();
        }
        const outcomes = await Promise.all(calls);
        for (const outcome of outcomes) {
          if (precheck !== "none") {
            assert.equal(outcome.error?.code, "app-check/invalid-argument");
            assert.match(outcome.error.message, precheck === "garbage" ? /^Decoding App Check token failed\./ : /incorrect "aud"/);
          } else if (verdictName === "accept" && consumeName !== "true") {
            assert.equal(outcome.value?.appId, "1:1234567890:web:abc");
            assert.equal(outcome.value.alreadyConsumed, undefined);
          } else if (verdictName === "accept") {
            assert.equal(outcome.error?.code, "app-check/unimplemented");
            assert.match(outcome.error.message, /APPCHECK-REPLAY-1/);
          } else {
            const [code, message] = SDK_WORDING[verdictName];
            assert.equal(outcome.error?.code, code);
            assert.match(outcome.error.message, message);
          }
        }
        assert.equal(askedBefore() - before, precheck === "none" ? count : 0, "the daemon is asked once per call, and never after an SDK pre-check failure");
        assert.equal(daemon.channel.pending(), 0);
        await admin.deleteApp(app);
      } finally {
        handle.restore();
      }
    });
  }
}

// ---------------------------------------------------------------------------------------
// Behaviour that does not depend on the SDK's version
// ---------------------------------------------------------------------------------------

const anyCopy = [...copies.values()].at(-1);

test("the instrumentation does nothing unless the daemon asked for it", async () => {
  const sourceDir = await codebase(anyCopy);
  const handle = await instrumentAdminAppCheck(sourceDir, fakeDaemon().channel, { enabled: false });
  assert.equal(handle.supported, false);
  assert.equal(handle.report.instrumentation, "disabled");
  const admin = sdk(anyCopy);
  assert.equal(admin.Verifier.prototype.verifySignature, stockVerifySignature.get(admin.Verifier));
});

test("the default is read from FIREEMU_APP_CHECK_ADMIN", async () => {
  const sourceDir = await codebase(anyCopy);
  const saved = process.env.FIREEMU_APP_CHECK_ADMIN;
  try {
    delete process.env.FIREEMU_APP_CHECK_ADMIN;
    assert.equal((await instrumentAdminAppCheck(sourceDir, fakeDaemon().channel)).report.instrumentation, "disabled");
    process.env.FIREEMU_APP_CHECK_ADMIN = "0";
    assert.equal((await instrumentAdminAppCheck(sourceDir, fakeDaemon().channel)).report.instrumentation, "disabled");
  } finally {
    if (saved === undefined) delete process.env.FIREEMU_APP_CHECK_ADMIN;
    else process.env.FIREEMU_APP_CHECK_ADMIN = saved;
  }
});

test("a pending question is failed on dispose, and a late verdict is ignored", async () => {
  const { handle, daemon } = await install(anyCopy, () => undefined, { timeoutMs: 60_000 });
  try {
    const admin = sdk(anyCopy);
    const { app, appCheck } = appCheckOf(admin);
    const outcome = appCheck.verifyToken(token()).then(() => assert.fail("accepted"), (e) => e);
    await new Promise((resolve) => setImmediate(resolve));
    const asked = daemon.asked.at(-1);
    assert.equal(daemon.channel.pending(), 1);
    daemon.channel.dispose();
    const error = await outcome;
    assert.equal(error.message, "Error fetching Json Web Keys: the Functions runner is shutting down");
    daemon.channel.deliver({ type: "appCheck:verdict", requestId: asked.requestId, ok: true });
    assert.equal(daemon.channel.pending(), 0);
    await admin.deleteApp(app);
  } finally {
    handle.restore();
  }
});

test("an answer is matched by request id only; duplicates and strangers are ignored", async () => {
  let release;
  const gate = new Promise((resolve) => (release = resolve));
  const { handle, daemon } = await install(anyCopy, () => undefined);
  try {
    const admin = sdk(anyCopy);
    const { app, appCheck } = appCheckOf(admin);
    const outcome = appCheck.verifyToken(token()).then((r) => ({ ok: true, r }), (e) => ({ ok: false, e }));
    await new Promise((resolve) => setImmediate(resolve));
    const asked = daemon.asked.at(-1);
    const channel = daemon.channel;
    channel.deliver({ type: "appCheck:verdict", requestId: "stranger", ok: true });
    channel.deliver({ type: "other", requestId: asked.requestId, ok: true });
    channel.deliver({ type: "appCheck:verdict", requestId: 5, ok: true });
    assert.equal(channel.pending(), 1, "nothing but the right answer settles it");
    channel.deliver({ type: "appCheck:verdict", requestId: asked.requestId, ok: false, reason: "token-expired" });
    channel.deliver({ type: "appCheck:verdict", requestId: asked.requestId, ok: true });
    const result = await outcome;
    assert.equal(result.ok, false, "the first answer wins");
    assert.equal(result.e.code, "app-check/app-check-token-expired");
    release();
    await gate;
    await admin.deleteApp(app);
  } finally {
    handle.restore();
  }
});

test("more than the in-flight cap is refused locally without being sent", async () => {
  const { handle, daemon } = await install(anyCopy, () => undefined, { timeoutMs: 60_000 });
  try {
    const admin = sdk(anyCopy);
    const { app, appCheck } = appCheckOf(admin);
    const outcomes = [];
    for (let i = 0; i < MAX_IN_FLIGHT + 3; i += 1) {
      outcomes.push(appCheck.verifyToken(token({ payload: { jti: `j${i}` } })).then(() => "ok", (e) => e.message));
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(daemon.asked.filter((f) => f.projectId === PROJECT).length, MAX_IN_FLIGHT);
    assert.equal(daemon.channel.pending(), MAX_IN_FLIGHT);
    daemon.channel.dispose();
    const settled = await Promise.all(outcomes);
    assert.equal(settled.filter((m) => m === "Error fetching Json Web Keys: the daemon cannot verify App Check tokens").length, 3);
    await admin.deleteApp(app);
  } finally {
    handle.restore();
  }
});

test("a send that throws fails that question and leaves nothing pending", async () => {
  const sourceDir = await codebase(anyCopy);
  let armed = false;
  const daemon = fakeDaemon();
  const channel = createAdminChannel((frame) => {
    if (armed && frame.projectId === PROJECT) throw new Error("pipe closed");
    daemon.send(frame);
  });
  daemon.channel = channel;
  const handle = await instrumentAdminAppCheck(sourceDir, channel, { enabled: true });
  try {
    armed = true;
    const admin = sdk(anyCopy);
    const { app, appCheck } = appCheckOf(admin);
    const error = await appCheck.verifyToken(token()).then(() => assert.fail("accepted"), (e) => e);
    assert.equal(error.message, "Error fetching Json Web Keys: the daemon cannot verify App Check tokens");
    assert.equal(channel.pending(), 0);
    await admin.deleteApp(app);
  } finally {
    handle.restore();
  }
});

class NoNetworkAgent extends https.Agent {
  createConnection() {
    throw new Error("test: network access is refused");
  }
}

for (const [name, answer, reported] of [
  ["unavailable", { ok: false, reason: "unavailable" }, "daemon-unavailable"],
  ["a refusal that is not the probe's", { ok: false, reason: "invalid-signature" }, "daemon-unavailable"],
  ["an acceptance", { ok: true }, /self-test did not reach the instrumented signature step/],
]) {
  test(`a daemon that answers the self-test with ${name} leaves nothing patched and says so`, async () => {
    const admin = sdk(anyCopy);
    const before = [admin.Verifier.prototype.verifySignature, admin.Client.prototype.verifyReplayProtection];
    const sourceDir = await codebase(anyCopy);
    const sent = [];
    const channel = createAdminChannel((frame) => {
      sent.push(frame);
      queueMicrotask(() => channel.deliver({ type: "appCheck:verdict", requestId: frame.requestId, ...answer }));
    });
    const handle = await instrumentAdminAppCheck(sourceDir, channel, { enabled: true });
    try {
      assert.equal(handle.supported, false);
      assert.match(handle.report.instrumentation, typeof reported === "string" ? new RegExp(`^${reported}$`) : reported);
      assert.equal(handle.report.firebaseAdminVersion, JSON.parse(readFileSync(join(anyCopy, "package.json"), "utf8")).version);
      assert.equal(admin.Verifier.prototype.verifySignature, before[0], "verifySignature is the SDK's again");
      assert.equal(admin.Client.prototype.verifyReplayProtection, before[1], "verifyReplayProtection is the SDK's again");
      // The stock SDK is back: a later daemon answer is never consulted, and a fireemu token is
      // rejected by the SDK's own key fetch (the agent refuses to open any connection here).
      const asked = sent.length;
      const { app, appCheck } = appCheckOf(admin, { httpAgent: new NoNetworkAgent() });
      const error = await appCheck.verifyToken(token(), { consume: true }).then(() => assert.fail("accepted"), (e) => e);
      assert.match(error.message, /^Error fetching Json Web Keys: /);
      assert.equal(sent.length, asked, "no question was sent to the daemon");
      assert.equal(channel.pending(), 0);
      await admin.deleteApp(app);
    } finally {
      handle.restore();
    }
  });
}

test("a daemon that never answers the self-test is reported after the self-test deadline and nothing stays patched", async () => {
  const admin = sdk(anyCopy);
  const before = admin.Verifier.prototype.verifySignature;
  const sourceDir = await codebase(anyCopy);
  const channel = createAdminChannel(() => {}, { timeoutMs: 120 });
  const started = Date.now();
  const handle = await instrumentAdminAppCheck(sourceDir, channel, { enabled: true, timeoutMs: 120 });
  try {
    assert.equal(handle.report.instrumentation, "daemon-unavailable");
    assert.equal(handle.supported, false);
    assert.equal(admin.Verifier.prototype.verifySignature, before);
    assert.ok(Date.now() - started < 4000);
  } finally {
    handle.restore();
  }
});

// ---------------------------------------------------------------------------------------
// Version and structure probes, on synthetic packages
// ---------------------------------------------------------------------------------------

/// A minimal firebase-admin whose App Check internals can be bent one way at a time.
async function syntheticAdmin({
  version = "14.3.0",
  omit = [],
  routeAround = false,
  verifyToken = null,
  frozen = false,
  omitCode = null,
  errorShape = "object",
} = {}) {
  const root = await mkdtemp(join(tmpdir(), "synthetic-admin-"));
  const lib = (file, text) => mkdir(dirname(join(root, "lib", file)), { recursive: true }).then(() => writeFile(join(root, "lib", file), text));
  await writeFile(join(root, "package.json"), JSON.stringify({ name: "firebase-admin", version, main: "lib/index.js" }));
  await writeFile(join(root, "lib", "index.js"), "").catch(async () => { await mkdir(join(root, "lib")); await writeFile(join(root, "lib", "index.js"), ""); });
  const methods = {
    verifySignature: "verifySignature(t) { return Promise.reject(new Error('stock key fetch')); }",
    mapJwtErrorToAppCheckError: "mapJwtErrorToAppCheckError(e) { return e; }",
    verifyContent: "verifyContent() {}",
    safeDecode: "safeDecode() { return Promise.resolve({}); }",
    verifyToken:
      verifyToken ??
      (routeAround
        ? "verifyToken(t) { return Promise.resolve({ routed: 'around' }); }"
        : "verifyToken(t) { return this.safeDecode(t).then(() => this.verifySignature(t)); }"),
  };
  const body = Object.entries(methods).filter(([k]) => !omit.includes(k)).map(([, v]) => v).join("\n  ");
  await lib("app-check/token-verifier.js", `class AppCheckTokenVerifier { constructor(app) { this.app = app; }\n  ${body}\n}\n${frozen ? "Object.freeze(AppCheckTokenVerifier.prototype);\n" : ""}exports.AppCheckTokenVerifier = AppCheckTokenVerifier;\n`);
  const ctor = errorShape === "object"
    ? "constructor(info) { super(info.message); this.code = 'app-check/' + info.code; }"
    : errorShape === "positional"
      ? "constructor(code, message) { super(message); this.code = 'app-check/' + code; }"
      : errorShape === "wrongcode"
        ? "constructor(info, message) { super(message ?? info.message); this.code = 'weird'; }"
        : "constructor() { super('unrelated'); }";
  await lib("app-check/error.js", `class FirebaseAppCheckError extends Error { ${ctor} }\nexports.FirebaseAppCheckError = FirebaseAppCheckError;\n`);
  const replay = omit.includes("verifyReplayProtection") ? "" : "verifyReplayProtection(t) { return Promise.resolve(false); }";
  await lib("app-check/app-check-api-client-internal.js", `class AppCheckApiClient { ${replay} }\nexports.AppCheckApiClient = AppCheckApiClient;\n`);
  const jwtErrors = omit.includes("JwtError") ? "" : "class JwtError extends Error { constructor(code, message) { super(message); this.code = code; } }\nexports.JwtError = JwtError;\n";
  const allCodes = { NO_MATCHING_KID: "no-matching-kid-error", INVALID_SIGNATURE: "invalid-token", TOKEN_EXPIRED: "token-expired", INVALID_ARGUMENT: "invalid-argument", KEY_FETCH_ERROR: "key-fetch-error" };
  if (omitCode) delete allCodes[omitCode];
  const codes = omit.includes("JwtErrorCode") ? "" : `exports.JwtErrorCode = ${JSON.stringify(allCodes)};\n`;
  await lib("utils/jwt.js", jwtErrors + codes);
  await lib("utils/index.js", omit.includes("findProjectId") ? "" : "exports.findProjectId = (app) => Promise.resolve(app.options.projectId);\n");
  return root;
}

test("a firebase-admin outside the supported majors is left alone", async () => {
  for (const version of ["12.7.0", "15.0.0", "0.1.0"]) {
    const root = await syntheticAdmin({ version });
    const sourceDir = await codebase(root);
    const handle = await instrumentAdminAppCheck(sourceDir, createAdminChannel(() => assert.fail("no question")), { enabled: true });
    assert.equal(handle.supported, false, version);
    assert.match(handle.report.instrumentation, /outside the supported range/);
    assert.equal(handle.report.firebaseAdminVersion, version);
    const req = createRequire(join(root, "package.json"));
    const { AppCheckTokenVerifier } = req("./lib/app-check/token-verifier.js");
    assert.match(AppCheckTokenVerifier.prototype.verifySignature.toString(), /stock key fetch/);
    await rm(root, { recursive: true, force: true });
  }
});

test("a codebase without firebase-admin reports not-installed", async () => {
  const sourceDir = await codebase(null);
  const handle = await instrumentAdminAppCheck(sourceDir, createAdminChannel(() => assert.fail("no question")), { enabled: true });
  assert.equal(handle.supported, false);
  assert.equal(handle.report.instrumentation, "not-installed");
});

for (const [name, options, pattern] of [
  ["verifySignature is missing", { omit: ["verifySignature"] }, /no patchable verifySignature/],
  ["the error mapper is missing", { omit: ["mapJwtErrorToAppCheckError"] }, /no patchable mapJwtErrorToAppCheckError/],
  ["verifyContent is missing", { omit: ["verifyContent"] }, /no patchable verifyContent/],
  ["safeDecode is missing", { omit: ["safeDecode"] }, /no patchable safeDecode/],
  ["verifyReplayProtection is missing", { omit: ["verifyReplayProtection"] }, /no patchable verifyReplayProtection/],
  ["JwtError is missing", { omit: ["JwtError"] }, /no longer defines the JWT errors/],
  ["JwtErrorCode is missing", { omit: ["JwtErrorCode"] }, /no longer defines the JWT errors/],
  ["findProjectId is missing", { omit: ["findProjectId"] }, /no longer defines the JWT errors/],
  ["the error constructor has an unknown shape", { errorShape: "none" }, /shape this instrumentation does not know/],
]) {
  test(`structure probe: ${name} leaves the SDK untouched`, async () => {
    const root = await syntheticAdmin(options);
    const sourceDir = await codebase(root);
    const req = createRequire(join(root, "package.json"));
    const { AppCheckTokenVerifier } = req("./lib/app-check/token-verifier.js");
    const before = Object.getOwnPropertyDescriptors(AppCheckTokenVerifier.prototype);
    const { AppCheckApiClient } = req("./lib/app-check/app-check-api-client-internal.js");
    const clientBefore = Object.getOwnPropertyDescriptors(AppCheckApiClient.prototype);
    const handle = await instrumentAdminAppCheck(sourceDir, createAdminChannel(() => assert.fail("no question")), { enabled: true });
    assert.equal(handle.supported, false);
    assert.match(handle.report.instrumentation, pattern);
    assert.deepEqual(Object.getOwnPropertyDescriptors(AppCheckTokenVerifier.prototype), before);
    assert.deepEqual(Object.getOwnPropertyDescriptors(AppCheckApiClient.prototype), clientBefore);
    await rm(root, { recursive: true, force: true });
  });
}

test("the positional error constructor (13.x) is recognised", async () => {
  const root = await syntheticAdmin({ errorShape: "positional", version: "13.0.0" });
  const sourceDir = await codebase(root);
  const daemon = fakeDaemon();
  const handle = await instrumentAdminAppCheck(sourceDir, daemon.channel, { enabled: true });
  assert.equal(handle.supported, true);
  const req = createRequire(join(root, "package.json"));
  const { AppCheckApiClient } = req("./lib/app-check/app-check-api-client-internal.js");
  const error = await new AppCheckApiClient().verifyReplayProtection("t").then(() => assert.fail("accepted"), (e) => e);
  assert.equal(error.code, "app-check/unimplemented");
  handle.restore();
});

test("self-test: a release that routes around verifySignature is unpatched and reported", async () => {
  const root = await syntheticAdmin({ routeAround: true });
  const sourceDir = await codebase(root);
  const req = createRequire(join(root, "package.json"));
  const { AppCheckTokenVerifier } = req("./lib/app-check/token-verifier.js");
  const { AppCheckApiClient } = req("./lib/app-check/app-check-api-client-internal.js");
  const original = [AppCheckTokenVerifier.prototype.verifySignature, AppCheckApiClient.prototype.verifyReplayProtection];
  const handle = await instrumentAdminAppCheck(sourceDir, createAdminChannel(() => assert.fail("never asked: the step is not reached")), { enabled: true });
  assert.equal(handle.supported, false);
  assert.match(handle.report.instrumentation, /self-test did not reach the instrumented signature step/);
  assert.equal(AppCheckTokenVerifier.prototype.verifySignature, original[0]);
  assert.equal(AppCheckApiClient.prototype.verifyReplayProtection, original[1]);
});

test("a nested second copy of firebase-admin is not the resolved one and stays stock", async () => {
  const resolved = await syntheticAdmin({});
  const nested = await syntheticAdmin({});
  const sourceDir = await codebase(resolved);
  const daemon = fakeDaemon();
  const handle = await instrumentAdminAppCheck(sourceDir, daemon.channel, { enabled: true });
  const stockOf = (root) => createRequire(join(root, "package.json"))("./lib/app-check/token-verifier.js").AppCheckTokenVerifier.prototype.verifySignature;
  assert.match(stockOf(nested).toString(), /stock key fetch/);
  assert.doesNotMatch(stockOf(resolved).toString(), /stock key fetch/);
  handle.restore();
});

test("the channel refuses to ask without a project or a string token, and sends nothing", async () => {
  const sent = [];
  const channel = createAdminChannel((frame) => sent.push(frame));
  for (const [projectId, jwtToken] of [
    ["", "t"],
    [null, "t"],
    [undefined, "t"],
    [7, "t"],
    ["p", undefined],
    ["p", 5],
    ["p", null],
  ]) {
    assert.deepEqual(await channel.ask(projectId, jwtToken), { ok: false, reason: "unavailable" });
  }
  assert.deepEqual(sent, []);
  assert.equal(channel.pending(), 0);
  assert.equal(channel.asked, 7, "every refused question is still counted as asked");
});

test("question ids are unique, and an answer settles only its own question", async () => {
  const sent = [];
  const channel = createAdminChannel((frame) => sent.push(frame), { timeoutMs: 60_000 });
  const first = channel.ask("p", "t1");
  const second = channel.ask("p", "t2");
  assert.equal(sent.length, 2);
  assert.notEqual(sent[0].requestId, sent[1].requestId);
  channel.deliver({ type: "appCheck:verdict", requestId: sent[1].requestId, ok: true });
  assert.deepEqual(await second, { ok: true });
  assert.equal(channel.pending(), 1);
  channel.dispose();
  assert.deepEqual(await first, { ok: false, reason: "disposed" });
});

test("a verdict with a missing or non-string reason becomes unavailable, and only ok:true accepts", async () => {
  for (const [verdict, expected] of [
    [{ ok: true }, { ok: true }],
    [{ ok: "true" }, { ok: false, reason: "unavailable" }],
    [{ ok: 1 }, { ok: false, reason: "unavailable" }],
    [{ ok: false }, { ok: false, reason: "unavailable" }],
    [{ ok: false, reason: "token-expired" }, { ok: false, reason: "token-expired" }],
  ]) {
    const sent = [];
    const channel = createAdminChannel((frame) => sent.push(frame), { timeoutMs: 60_000 });
    const answer = channel.ask("p", "t");
    channel.deliver({ type: "appCheck:verdict", requestId: sent[0].requestId, ...verdict });
    assert.deepEqual(await answer, expected, JSON.stringify(verdict));
  }
});

test("the deadline applies to questions asked after setDeadline, and a timeout leaves nothing pending", async () => {
  const channel = createAdminChannel(() => {}, { timeoutMs: 60_000 });
  channel.setDeadline(30);
  const started = Date.now();
  assert.deepEqual(await channel.ask("p", "t"), { ok: false, reason: "timeout" });
  assert.ok(Date.now() - started < 5_000);
  assert.equal(channel.pending(), 0);
});

for (const [name, options, pattern] of [
  ["a frozen verifier prototype cannot be patched", { frozen: true }, /no patchable verifySignature/],
  ["JwtErrorCode lacks NO_MATCHING_KID", { omitCode: "NO_MATCHING_KID" }, /no longer defines the JWT errors/],
  ["JwtErrorCode lacks INVALID_SIGNATURE", { omitCode: "INVALID_SIGNATURE" }, /no longer defines the JWT errors/],
  ["JwtErrorCode lacks TOKEN_EXPIRED", { omitCode: "TOKEN_EXPIRED" }, /no longer defines the JWT errors/],
  ["JwtErrorCode lacks INVALID_ARGUMENT", { omitCode: "INVALID_ARGUMENT" }, /no longer defines the JWT errors/],
  ["JwtErrorCode lacks KEY_FETCH_ERROR", { omitCode: "KEY_FETCH_ERROR" }, /no longer defines the JWT errors/],
  ["the error constructor reports a different code", { errorShape: "wrongcode" }, /shape this instrumentation does not know/],
]) {
  test(`structure probe: ${name} leaves the SDK untouched`, async () => {
    const root = await syntheticAdmin(options);
    const sourceDir = await codebase(root);
    const req = createRequire(join(root, "package.json"));
    const { AppCheckTokenVerifier } = req("./lib/app-check/token-verifier.js");
    const before = Object.getOwnPropertyDescriptors(AppCheckTokenVerifier.prototype);
    const handle = await instrumentAdminAppCheck(sourceDir, createAdminChannel(() => assert.fail("no question")), { enabled: true });
    assert.equal(handle.supported, false);
    assert.match(handle.report.instrumentation, pattern);
    assert.deepEqual(Object.getOwnPropertyDescriptors(AppCheckTokenVerifier.prototype), before);
    await rm(root, { recursive: true, force: true });
  });
}

for (const [name, verifyToken, expectedAsked] of [
  ["rejects without ever reaching the signature step", "verifyToken(t) { return Promise.reject(new Error('rejected early')); }", 0],
  ["reaches the signature step twice", "verifyToken(t) { return this.verifySignature(t).catch(() => this.verifySignature(t)); }", 2],
  ["swallows the signature failure and accepts", "verifyToken(t) { return this.verifySignature(t).catch(() => ({ swallowed: true })); }", 1],
]) {
  test(`self-test: a release that ${name} is unpatched and reported`, async () => {
    const root = await syntheticAdmin({ verifyToken });
    const sourceDir = await codebase(root);
    const req = createRequire(join(root, "package.json"));
    const { AppCheckTokenVerifier } = req("./lib/app-check/token-verifier.js");
    const { AppCheckApiClient } = req("./lib/app-check/app-check-api-client-internal.js");
    const original = [AppCheckTokenVerifier.prototype.verifySignature, AppCheckApiClient.prototype.verifyReplayProtection];
    const daemon = fakeDaemon();
    const handle = await instrumentAdminAppCheck(sourceDir, daemon.channel, { enabled: true });
    assert.equal(handle.supported, false);
    assert.match(handle.report.instrumentation, /self-test did not reach the instrumented signature step/);
    assert.equal(daemon.asked.length, expectedAsked);
    assert.equal(AppCheckTokenVerifier.prototype.verifySignature, original[0]);
    assert.equal(AppCheckApiClient.prototype.verifyReplayProtection, original[1]);
    await rm(root, { recursive: true, force: true });
  });
}

test("self-test: the probe app's HTTP agent refuses to open a connection", async () => {
  const root = await syntheticAdmin({
    verifyToken:
      "verifyToken(t) { try { this.app.options.httpAgent.createConnection({ host: '127.0.0.1', port: 9 }); globalThis.__agentRefused = false; } catch (e) { globalThis.__agentRefused = /network access is refused/.test(e.message); } return Promise.resolve({}); }",
  });
  const sourceDir = await codebase(root);
  globalThis.__agentRefused = undefined;
  const handle = await instrumentAdminAppCheck(sourceDir, fakeDaemon().channel, { enabled: true });
  assert.equal(handle.supported, false, "the probe routed around the instrumented step");
  assert.equal(globalThis.__agentRefused, true);
  delete globalThis.__agentRefused;
  await rm(root, { recursive: true, force: true });
});

test("the self-test deadline applies only to the self-test", async () => {
  // A daemon that answers only the self-test. A later question is silent and must wait the
  // full deadline, not the shorter self-test deadline.
  const sourceDir = await codebase(anyCopy);
  const daemon = fakeDaemon((frame) => undefined, { timeoutMs: 600 });
  const handle = await instrumentAdminAppCheck(sourceDir, daemon.channel, {
    enabled: true,
    timeoutMs: 600,
    selfTestTimeoutMs: 40,
  });
  try {
    assert.equal(handle.report.instrumentation, "ok", "the fake daemon answers the self-test");
    const started = Date.now();
    const verdict = await daemon.channel.ask(PROJECT, token());
    assert.deepEqual(verdict, { ok: false, reason: "timeout" });
    assert.ok(Date.now() - started >= 500, `waited the ordinary deadline (${Date.now() - started} ms)`);
  } finally {
    handle.restore();
  }
});

test("a settled question leaves no timer behind", async () => {
  const timers = () => process.getActiveResourcesInfo().filter((kind) => kind === "Timeout").length;
  const sent = [];
  const channel = createAdminChannel((frame) => sent.push(frame), { timeoutMs: 60_000 });
  const before = timers();
  const answered = channel.ask("p", "t");
  assert.equal(timers(), before + 1);
  channel.deliver({ type: "appCheck:verdict", requestId: sent[0].requestId, ok: true });
  await answered;
  assert.equal(timers(), before, "the deadline timer is cleared when the answer arrives");
  const disposed = channel.ask("p", "t");
  assert.equal(timers(), before + 1);
  channel.dispose();
  await disposed;
  assert.equal(timers(), before, "and when the channel is disposed");
});

test("a failing send leaves no timer behind", async () => {
  const timers = () => process.getActiveResourcesInfo().filter((kind) => kind === "Timeout").length;
  const channel = createAdminChannel(() => {
    throw new Error("closed");
  }, { timeoutMs: 60_000 });
  const before = timers();
  assert.deepEqual(await channel.ask("p", "t"), { ok: false, reason: "unavailable" });
  assert.equal(timers(), before);
});

// An ES module codebase imports `firebase-admin/app-check` through the package's ESM entry,
// which re-exports the CommonJS module the instrumentation patched: one patch covers both.
for (const [version, adminDir] of copies) {
  const esmEntry = join(adminDir, "lib", "esm", "app-check", "index.js");
  test(`firebase-admin ${version}: the ES module entry shares the patched verifier`, { skip: !existsSync(esmEntry) }, async () => {
    const { handle, daemon } = await install(adminDir);
    try {
      const esmApp = await import(pathToFileURL(join(adminDir, "lib", "esm", "app", "index.js")).href);
      const esmAppCheck = await import(pathToFileURL(esmEntry).href);
      const app = esmApp.initializeApp({ projectId: PROJECT }, `esm-${version}`);
      const jwtToken = token();
      const result = await esmAppCheck.getAppCheck(app).verifyToken(jwtToken);
      assert.equal(result.appId, "1:1234567890:web:abc");
      assert.equal(daemon.asked.at(-1).token, jwtToken, "the daemon was asked through the ESM entry");
      const refused = await esmAppCheck.getAppCheck(app).verifyToken(jwtToken, { consume: true }).then(() => assert.fail("accepted"), (e) => e);
      assert.equal(refused.code, "app-check/unimplemented");
      await esmApp.deleteApp(app);
    } finally {
      handle.restore();
    }
  });
}
