// The blocking event is built from the Identity Platform token by the codebase's own
// firebase-functions parsers, as the SDK's wrapped handler builds it (AUTH-TENANT-BLOCKING
// comparison 2026-09-28): these tests cover the decoding and the wiring, with the parsers as
// doubles; the parity of what they build is the SDK's own.
import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  blockingEvent,
  decodeBlockingToken,
  loadIdentityParsers,
  portedIdentityParsers,
} from "./blocking-event.mjs";

const token = (payload, header = { alg: "none", typ: "JWT" }) =>
  [header, payload].map((part) => Buffer.from(JSON.stringify(part)).toString("base64url")).join(".") +
  ".";

const parsers = {
  parseAuthUserRecord: (record) => ({ parsedUser: record.uid }),
  parseAuthEventContext: (decoded, projectId) => ({
    parsedEvent: decoded.event_type,
    projectId,
    uid: decoded.uid,
  }),
};

test("a blocking token is decoded as the SDK decodes it: its subject is the uid", () => {
  const decoded = decodeBlockingToken(token({ sub: "u1", event_type: "beforeCreate" }));
  assert.equal(decoded.uid, "u1");
  assert.equal(decoded.event_type, "beforeCreate");
  for (const bad of [undefined, 7, "a.b", "a.b.c.d", `x.${Buffer.from("[1]").toString("base64url")}.`, "x.!!!.", `x.${Buffer.from("null").toString("base64url")}.`]) {
    assert.throws(() => decodeBlockingToken(bad), /blocking token/, String(bad));
  }
});

test("a user event gets the parsed record and the parsed context", () => {
  for (const event of ["beforeCreate", "beforeSignIn"]) {
    const built = blockingEvent(
      { data: { jwt: token({ sub: "u1", event_type: event, user_record: { uid: "u1" } }) } },
      parsers,
      "demo-p",
    );
    assert.deepEqual(built, {
      user: { parsedUser: "u1" },
      context: { parsedEvent: event, projectId: "demo-p", uid: "u1" },
    });
  }
  // An event without a user (the email and SMS events) has no user record.
  const sendEmail = blockingEvent(
    { data: { jwt: token({ event_type: "beforeSendEmail" }) } },
    parsers,
    "demo-p",
  );
  assert.equal(sendEmail.user, undefined);
});

test("a body without a token is not a token event", () => {
  assert.equal(blockingEvent({ data: { user: {}, context: {} } }, parsers, "p"), undefined);
  assert.equal(blockingEvent(undefined, parsers, "p"), undefined);
});

test("the parsers are loaded from the codebase's firebase-functions, or not at all", async () => {
  const root = await mkdtemp(join(tmpdir(), "fireemu-identity-"));
  // One codebase per case: Node caches a module by its path.
  const codebase = async (name, identitySource) => {
    const dir = join(root, name);
    const sdk = join(dir, "node_modules", "firebase-functions");
    await mkdir(join(sdk, "lib", "common", "providers"), { recursive: true });
    await writeFile(join(sdk, "package.json"), JSON.stringify({ name: "firebase-functions", main: "lib/index.js" }));
    await writeFile(join(sdk, "lib", "index.js"), "module.exports = {};");
    if (identitySource !== undefined)
      await writeFile(join(sdk, "lib", "common", "providers", "identity.js"), identitySource);
    await writeFile(join(dir, "package.json"), JSON.stringify({ name }));
    return createRequire(join(dir, "package.json"));
  };
  try {
    // No identity module: nothing to parse with.
    assert.equal(loadIdentityParsers(await codebase("none")), null);
    const loaded = loadIdentityParsers(
      await codebase(
        "both",
        "exports.parseAuthUserRecord = () => 'user'; exports.parseAuthEventContext = () => 'context';",
      ),
    );
    assert.equal(loaded.parseAuthUserRecord(), "user");
    assert.equal(loaded.parseAuthEventContext(), "context");
    // A module without both parsers, or one that throws, is not used.
    assert.equal(loadIdentityParsers(await codebase("one", "exports.parseAuthUserRecord = () => 1;")), null);
    assert.equal(loadIdentityParsers(await codebase("throws", "throw new Error('x');")), null);
    // No firebase-functions at all.
    await mkdir(join(root, "bare"), { recursive: true });
    assert.equal(loadIdentityParsers(createRequire(join(root, "bare", "package.json"))), null);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// The recorded AUTH-TENANT-BLOCKING fixture pins firebase-functions 7.3.2, the version the port
// follows; the comparison runs where that fixture is installed.
const pinnedSdk = fileURLToPath(
  new URL("../../conformance/src/auth-tenant-blocking/function/package.json", import.meta.url),
);

const samples = [
  {
    iat: 1_788_004_860, event_id: "e1", event_type: "beforeCreate", sub: "u1", sign_in_method: "password",
    locale: "en", ip_address: "127.0.0.1", user_agent: "agent",
    user_record: {
      uid: "u1", email: "a@example.com", email_verified: false, disabled: false,
      provider_data: [{ provider_id: "password", uid: "a@example.com", email: "a@example.com" }],
      metadata: { creation_time: 1_788_004_860_000 },
    },
  },
  {
    iat: 1_788_004_860, event_id: "e2", event_type: "beforeSignIn", sub: "u2", sign_in_method: "oidc.corp",
    tenant_id: "tenant-a", raw_user_info: "{\"login\":\"x\"}", sign_in_attributes: { a: 1 },
    oauth_access_token: "access", oauth_expires_in: 60,
    user_record: {
      uid: "u2", phone_number: "+15555550100", custom_claims: { role: "r" }, tenant_id: "tenant-a",
      provider_data: [], tokens_valid_after_time: 1_788_004_000,
      multi_factor: { enrolled_factors: [{ uid: "f1", phone_number: "+15555550100", enrollment_time: "2026-09-28T00:00:00Z" }] },
      metadata: { creation_time: 1_788_004_000_000, last_sign_in_time: 1_788_004_860_000 },
    },
  },
  { iat: 1_788_004_860, event_id: "e3", event_type: "beforeSendEmail", email_type: "PASSWORD_RESET", email: "a@example.com" },
  // Edges: an unset validity time, an empty factor list, a GitHub profile, an email link, and a
  // credential of sign-in attributes only (runner manual mutation, closure review M2).
  {
    iat: 1_788_004_860, event_id: "e4", event_type: "beforeSignIn", sub: "u4", sign_in_method: "github.com",
    raw_user_info: "{\"login\":\"octo\"}", sign_in_attributes: { a: 1 },
    user_record: { uid: "u4", provider_data: [], tokens_valid_after_time: 0, multi_factor: { enrolled_factors: [] } },
  },
  {
    iat: 1_788_004_860, event_id: "e5", event_type: "beforeCreate", sub: "u5", sign_in_method: "emailLink",
    user_record: { uid: "u5", provider_data: [] },
  },
];

test("the port answers the edges as firebase-functions 7.3.2 does, without the SDK", () => {
  const time = 1_788_004_900_000;
  const [github, link] = samples.slice(3);
  const record = portedIdentityParsers.parseAuthUserRecord(github.user_record);
  assert.equal(record.tokensValidAfterTime, null);
  assert.equal(record.multiFactor, null);
  const context = portedIdentityParsers.parseAuthEventContext(github, "demo-p", time);
  assert.equal(context.additionalUserInfo.username, "octo");
  assert.deepEqual(context.credential.claims, { a: 1 });
  assert.equal(context.credential.providerId, "github.com");
  const linked = portedIdentityParsers.parseAuthEventContext(link, "demo-p", time);
  assert.equal(linked.additionalUserInfo.providerId, "password");
  assert.equal(linked.credential, null);
});

test("the port builds the event firebase-functions 7.3.2 builds", { skip: !existsSync(pinnedSdk) }, () => {
  const sdk = loadIdentityParsers(createRequire(pinnedSdk));
  assert.ok(sdk, "the pinned SDK exposes its parsers");
  for (const decoded of samples) {
    const time = 1_788_004_900_000;
    assert.deepEqual(
      portedIdentityParsers.parseAuthEventContext(decoded, "demo-p", time),
      sdk.parseAuthEventContext(decoded, "demo-p", time),
      decoded.event_id,
    );
    if (decoded.user_record) {
      assert.deepEqual(
        portedIdentityParsers.parseAuthUserRecord(decoded.user_record),
        sdk.parseAuthUserRecord(decoded.user_record),
        decoded.event_id,
      );
    }
  }
  assert.throws(() => portedIdentityParsers.parseAuthUserRecord({}), /Invalid user response/);
});
