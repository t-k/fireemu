import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { createCountedCredentialCache } from "./storage-rules/credential-cache.mjs";
import { createDispatchGate } from "./storage-rules/dispatch-gate.mjs";

// The seam through which the credential cache and the credential session send: the same counter, admission and capture
// journal as every other request, and the one real transport reachable only inside an armed, counted attempt.
const now = 1790553600;
const adc = { type: "authorized_user", client_id: "synthetic-client.apps.googleusercontent.com", client_secret: "synthetic-client-secret-00001", refresh_token: "synthetic-refresh-token-with/slash+00002" };
const token = "synthetic-owner-access-token-00003";
const salt = "cd".repeat(32);
const ownerPreflight = "preflight/auth/owner-token";
const keyPreflight = "preflight/auth/signing-keys";
const certUrl = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";
const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const pem = publicKey.export({ type: "spki", format: "pem" });
const raw = (body, delta = {}) => ({ status: 200, rawHeaders: ["Cache-Control", "public, max-age=3600, must-revalidate", "Age", "60"], bytes: Buffer.from(JSON.stringify(body)), startedAtMs: 1, finishedAtMs: 2, ...delta });

async function setup({ admission = { check: async () => ({ admitted: true }) }, capture = {}, transport, reservations = {} } = {}) {
  const trace = [];
  const proofs = [];
  const state = { uncertain: false };
  const gate = createDispatchGate({
    reservations: { onStarted: async () => { trace.push("started"); }, onReserve: async (row) => { trace.push(`reserved:${row.operationId}`); }, onTerminal: async (row) => { trace.push(`terminal:${row.outcome}`); }, ...reservations },
    capture: { writeIntent: async (r) => { trace.push(`intent:${r.operationId}:${r.phase}`); }, writeResponse: async (r) => { trace.push(`response:${r.operationId}`); }, writeNote: async (r) => { trace.push(`note:${r.text}`); }, snapshot: () => ({ ...state }), ...capture },
    transport: transport ? { validate() {}, ...transport } : { validate() {}, send: async (spec) => { trace.push(`http:${spec.url}`); return spec.url === certUrl ? raw({ synthetic: pem }) : raw({ access_token: token, token_type: "Bearer", expires_in: 3600 }); } },
    targets: { verify: () => true, prepare: () => { throw new Error("unused"); } },
    credentials: { headersFor: () => ({}) },
    preflightIds: [ownerPreflight, keyPreflight],
    admission: { check: async () => { trace.push("admission"); return admission.check(); }, begin: async () => { trace.push("admission"); return (admission.begin ?? admission.check)(); } },
  });
  return { gate, trace, proofs, state };
}
const cacheOf = (ctx) => createCountedCredentialCache({ adc, counter: ctx.gate.delegated.counter, digestSalt: salt, nowSeconds: () => now, sendHttp: ctx.gate.delegated.http, writeProof: async (proof) => { ctx.proofs.push(proof); } });

test("the gate exposes a delegated counter and a bounded http function", async () => {
  const ctx = await setup();
  assert.equal(Object.isFrozen(ctx.gate.delegated), true);
  assert.deepEqual(Object.keys(ctx.gate.delegated).sort(), ["counter", "http"]);
  assert.deepEqual(Object.keys(ctx.gate.delegated.counter).sort(), ["enterRecovery", "send", "sendPreflight", "snapshot"]);
  assert.equal(Object.isFrozen(ctx.gate.delegated.counter), true);
});

test("the real credential cache runs both preflight refreshes and a normal one through the gate's counter, admission and intent", async () => {
  const ctx = await setup();
  const cache = cacheOf(ctx);
  await ctx.gate.start({ runId: "delegated" });
  ctx.trace.length = 0;
  const owner = await cache.refreshOwner(ownerPreflight);
  assert.equal(owner.sendAuthorized, false);
  assert.deepEqual(ctx.trace.map((entry) => entry.replace(/^note:delegated target [0-9a-f]{64}$/, "note:target")), ["admission", `intent:${ownerPreflight}:preflight`, `reserved:${ownerPreflight}`, "note:target", "http:https://oauth2.googleapis.com/token"]);
  await cache.fetchSigningKeys(keyPreflight);
  ctx.gate.admit();
  assert.equal(ctx.gate.snapshot().requests, 2);
  ctx.trace.length = 0;
  await cache.refreshOwner("auth-shared/owner-token/1");
  assert.deepEqual(ctx.trace.map((entry) => entry.replace(/^note:delegated target [0-9a-f]{64}$/, "note:target")), ["admission", "intent:auth-shared/owner-token/1:normal", "reserved:auth-shared/owner-token/1", "note:target", "http:https://oauth2.googleapis.com/token"]);
  assert.equal(ctx.gate.snapshot().requests, 3);
  assert.equal(cache.ownerCredential().accessToken, token);
});

test("a delegated attempt after a recovery start is counted and journalled as recovery", async () => {
  const ctx = await setup();
  const cache = cacheOf(ctx);
  await ctx.gate.start({ runId: "delegated" });
  await cache.refreshOwner(ownerPreflight);
  await cache.fetchSigningKeys(keyPreflight);
  ctx.gate.admit();
  ctx.gate.enterRecovery();
  ctx.trace.length = 0;
  await cache.refreshOwner("recovery/auth-shared/owner-token/1");
  assert.deepEqual(ctx.trace.slice(0, 3), ["admission", "intent:recovery/auth-shared/owner-token/1:recovery", "reserved:recovery/auth-shared/owner-token/1"]);
  assert.equal(ctx.gate.snapshot().recovery, 1);
});

test("a refused admission stops a delegated send before its intent, its reservation and its request", async () => {
  let refuse = false;
  const ctx = await setup({ admission: { check: async () => { if (refuse) throw new Error("admission refused: revoked"); return { admitted: true }; } } });
  const cache = cacheOf(ctx);
  await ctx.gate.start({ runId: "delegated" });
  refuse = true;
  ctx.trace.length = 0;
  await assert.rejects(() => cache.refreshOwner(ownerPreflight), /credential cache request failed/);
  assert.deepEqual(ctx.trace, ["admission"]);
  // The counter did not move, so nothing was reserved.
  assert.equal(ctx.gate.snapshot().requests, 0);
});

test("an admission that does not answer admitted stops a delegated send", async () => {
  for (const answer of [undefined, null, {}, { admitted: false }]) {
    const ctx = await setup({ admission: { check: async () => answer } });
    await assert.rejects(() => ctx.gate.start({ runId: "delegated" }), /admission refused/);
  }
  let calls = 0;
  const ctx = await setup({ admission: { check: async () => (++calls > 1 ? undefined : { admitted: true }) } });
  await ctx.gate.start({ runId: "delegated" });
  ctx.trace.length = 0;
  await assert.rejects(() => cacheOf(ctx).refreshOwner(ownerPreflight));
  assert.deepEqual(ctx.trace, ["admission"]);
});

test("an intent that cannot be made durable stops a delegated send before its reservation and request", async () => {
  const ctx = await setup({ capture: { writeIntent: async () => { throw new Error("capture uncertain"); } } });
  await ctx.gate.start({ runId: "delegated" });
  ctx.trace.length = 0;
  await assert.rejects(() => cacheOf(ctx).refreshOwner(ownerPreflight));
  assert.equal(ctx.trace.some((entry) => entry.startsWith("reserved:") || entry.startsWith("http:")), false);
});

test("an uncertain capture journal stops a delegated send", async () => {
  const ctx = await setup();
  await ctx.gate.start({ runId: "delegated" });
  ctx.state.uncertain = true;
  ctx.trace.length = 0;
  await assert.rejects(() => cacheOf(ctx).refreshOwner(ownerPreflight));
  assert.equal(ctx.trace.some((entry) => entry.startsWith("intent:") || entry.startsWith("http:")), false);
});

test("the http function works only inside a delegated attempt and once per attempt", async () => {
  const ctx = await setup();
  await ctx.gate.start({ runId: "delegated" });
  const spec = { url: "https://oauth2.googleapis.com/token", method: "POST", headers: {}, body: Buffer.alloc(0) };
  await assert.rejects(() => ctx.gate.delegated.http(spec), /outside a delegated attempt/);
  let second;
  await ctx.gate.delegated.counter.sendPreflight(ownerPreflight, async () => {
    await ctx.gate.delegated.http(spec);
    second = await ctx.gate.delegated.http(spec).catch((error) => error);
    return { sendAuthorized: false };
  }, (result) => result.sendAuthorized === false);
  assert.match(String(second?.message), /more than one/);
  assert.equal(ctx.trace.filter((entry) => entry.startsWith("http:")).length, 1);
  await assert.rejects(() => ctx.gate.delegated.http(spec), /outside a delegated attempt/);
});

test("a delegated attempt cannot start another request from inside itself, and the gate's own send is refused meanwhile", async () => {
  const ctx = await setup();
  await ctx.gate.start({ runId: "delegated" });
  let nested;
  let own;
  await ctx.gate.delegated.counter.sendPreflight(ownerPreflight, async () => {
    nested = await ctx.gate.delegated.counter.sendPreflight(keyPreflight, async () => ({ sendAuthorized: false }), () => true).catch((error) => error);
    own = await ctx.gate.send({ rowId: "x", spec: {}, targetSha256: "0".repeat(64), redacted: "x", credential: "anonymous" }, { phase: "preflight", mutationKey: null, accept: () => true }).catch((error) => error);
    return { sendAuthorized: false };
  }, () => true);
  assert.match(String(nested?.message), /concurrent dispatch is forbidden/);
  assert.match(String(own?.message), /concurrent dispatch is forbidden/);
});

test("a poisoned gate refuses delegated sends", async () => {
  const ctx = await setup({ capture: { writeResponse: async () => { throw new Error("disk full"); } } });
  await ctx.gate.start({ runId: "delegated" });
  const prepared = { rowId: ownerPreflight, spec: { url: "https://x/", method: "GET", headers: {}, body: null }, targetSha256: "0".repeat(64), redacted: "GET https://x/", credential: "anonymous" };
  await assert.rejects(() => ctx.gate.send(prepared, { phase: "preflight", mutationKey: null, accept: () => true }), /capture failed after send/);
  assert.equal(ctx.gate.snapshot().poisoned, true);
  await assert.rejects(() => ctx.gate.delegated.counter.sendPreflight(keyPreflight, async () => ({}), () => true), /poisoned/);
});

test("the delegated counter's snapshot and recovery entry are the gate's own", async () => {
  const ctx = await setup();
  await ctx.gate.start({ runId: "delegated" });
  assert.equal(ctx.gate.delegated.counter.snapshot().mode, "preflight");
  const cache = cacheOf(ctx);
  await cache.refreshOwner(ownerPreflight);
  await cache.fetchSigningKeys(keyPreflight);
  ctx.gate.admit();
  assert.equal(ctx.gate.delegated.counter.snapshot().mode, "normal");
  ctx.gate.delegated.counter.enterRecovery();
  assert.equal(ctx.gate.snapshot().mode, "recovery");
});

test("a preflight attempt that throws closes the run as preflight-failed and is never retried", async () => {
  const ctx = await setup({ transport: { send: async () => { throw new Error("connection reset"); } } });
  const cache = cacheOf(ctx);
  await ctx.gate.start({ runId: "delegated" });
  await assert.rejects(() => cache.refreshOwner(ownerPreflight), /credential cache request failed/);
  assert.equal(ctx.trace.at(-1), "terminal:preflight-failed");
  ctx.trace.length = 0;
  await assert.rejects(() => cache.refreshOwner(ownerPreflight), /credential cache request (failed|refused)/);
  assert.equal(ctx.trace.some((entry) => entry.startsWith("reserved:") || entry.startsWith("intent:")), false);
});

test("a normal delegated attempt that throws moves the counter to recovery and the gate stays usable", async () => {
  let fail = false;
  const ctx = await setup({ transport: { send: async (spec) => { if (fail) throw new Error("connection reset"); return spec.url === certUrl ? raw({ synthetic: pem }) : raw({ access_token: token, token_type: "Bearer", expires_in: 3600 }); } } });
  const cache = cacheOf(ctx);
  await ctx.gate.start({ runId: "delegated" });
  await cache.refreshOwner(ownerPreflight);
  await cache.fetchSigningKeys(keyPreflight);
  ctx.gate.admit();
  fail = true;
  await assert.rejects(() => cache.refreshOwner("auth-shared/owner-token/1"), /credential cache request failed/);
  assert.equal(ctx.gate.snapshot().mode, "recovery");
  assert.equal(ctx.gate.snapshot().poisoned, false);
});

test("a refused admission is visible in the gate's snapshot for the controller", async () => {
  let refuse = false;
  const ctx = await setup({ admission: { check: async () => { if (refuse) throw new Error("admission refused: revoked"); return { admitted: true }; } } });
  await ctx.gate.start({ runId: "delegated" });
  assert.equal(ctx.gate.snapshot().admissionRefused, false);
  refuse = true;
  await assert.rejects(() => cacheOf(ctx).refreshOwner(ownerPreflight));
  assert.equal(ctx.gate.snapshot().admissionRefused, true);
});

test("the delegated counter's snapshot is a frozen copy", async () => {
  const ctx = await setup();
  await ctx.gate.start({ runId: "delegated" });
  const seen = ctx.gate.delegated.counter.snapshot();
  assert.equal(Object.isFrozen(seen), true);
  assert.notEqual(ctx.gate.delegated.counter.snapshot(), seen);
});

test("a delegated request with invalid arguments is refused before its admission, its intent and its reservation", async () => {
  const ctx = await setup();
  await ctx.gate.start({ runId: "delegated" });
  ctx.trace.length = 0;
  let ran = false;
  const attempt = async () => { ran = true; return { sendAuthorized: false }; };
  const calls = [
    () => ctx.gate.delegated.counter.sendPreflight(7, attempt, () => true),
    () => ctx.gate.delegated.counter.sendPreflight(ownerPreflight, { attempt }, () => true),
    () => ctx.gate.delegated.counter.sendPreflight(ownerPreflight, attempt, null),
    () => ctx.gate.delegated.counter.sendPreflight(ownerPreflight, attempt, "accept"),
    () => ctx.gate.delegated.counter.send(null, attempt),
    () => ctx.gate.delegated.counter.send("auth-shared/owner-token/1", undefined),
  ];
  for (const call of calls) await assert.rejects(call, /invalid delegated request/);
  assert.deepEqual(ctx.trace, []);
  assert.equal(ran, false);
  // Nothing was counted or closed: the declared preflight still runs.
  assert.equal(ctx.gate.snapshot().mode, "preflight");
  await cacheOf(ctx).refreshOwner(ownerPreflight);
  assert.equal(ctx.gate.snapshot().requests, 1);
});

test("a delegated send outside a request mode is refused before its intent", async () => {
  const ctx = await setup();
  let ran = false;
  const attempt = async () => { ran = true; return {}; };
  await assert.rejects(() => ctx.gate.delegated.counter.send("auth-shared/owner-token/1", attempt), /delegated request outside a request mode/);
  assert.deepEqual(ctx.trace, ["admission"]);
  const cache = cacheOf(ctx);
  await ctx.gate.start({ runId: "delegated" });
  await cache.refreshOwner(ownerPreflight);
  await cache.fetchSigningKeys(keyPreflight);
  ctx.gate.admit();
  await ctx.gate.finish("finished");
  ctx.trace.length = 0;
  await assert.rejects(() => ctx.gate.delegated.counter.send("auth-shared/owner-token/1", attempt), /delegated request outside a request mode/);
  assert.deepEqual(ctx.trace, ["admission"]);
  assert.equal(ran, false);
});

test("the http budget ends with its attempt even when the attempt made no request", async () => {
  const ctx = await setup();
  await ctx.gate.start({ runId: "delegated" });
  const spec = { url: "https://oauth2.googleapis.com/token", method: "POST", headers: {}, body: Buffer.alloc(0) };
  await ctx.gate.delegated.counter.sendPreflight(ownerPreflight, async () => ({ sendAuthorized: false }), () => true);
  await assert.rejects(() => ctx.gate.delegated.http(spec), /outside a delegated attempt/);
  await assert.rejects(() => ctx.gate.delegated.counter.sendPreflight(keyPreflight, async () => { throw new Error("refused before its request"); }, () => true), /refused before its request/);
  await assert.rejects(() => ctx.gate.delegated.http(spec), /outside a delegated attempt/);
  assert.equal(ctx.trace.some((entry) => entry.startsWith("http:")), false);
});

test("a delegated attempt whose reservation lands in another phase than its intent never reaches the transport", async () => {
  let hook = () => {};
  const ctx = await setup({ capture: { writeIntent: async (r) => { ctx.trace.push(`intent:${r.operationId}:${r.phase}`); hook(); } } });
  const cache = cacheOf(ctx);
  await ctx.gate.start({ runId: "delegated" });
  await cache.refreshOwner(ownerPreflight);
  await cache.fetchSigningKeys(keyPreflight);
  ctx.gate.admit();
  // The counter moves to recovery while the normal request's intent is written: its reservation is then a recovery one.
  hook = () => { hook = () => {}; ctx.gate.enterRecovery(); };
  ctx.trace.length = 0;
  let ran = false;
  await assert.rejects(() => ctx.gate.delegated.counter.send("auth-shared/owner-token/1", async () => { ran = true; return ctx.gate.delegated.http({ url: "https://oauth2.googleapis.com/token", method: "POST", headers: {}, body: Buffer.alloc(0) }); }), /dispatch is not armed/);
  assert.deepEqual(ctx.trace, ["admission", "intent:auth-shared/owner-token/1:normal", "reserved:auth-shared/owner-token/1"]);
  assert.equal(ran, false);
});

test("an admission that answers anything but admitted is recorded as a refusal", async () => {
  for (const answer of [undefined, null, {}, { admitted: false }, { admitted: "true" }]) {
    let calls = 0;
    const ctx = await setup({ admission: { check: async () => (++calls > 1 ? answer : { admitted: true }) } });
    await ctx.gate.start({ runId: "delegated" });
    assert.equal(ctx.gate.snapshot().admissionRefused, false);
    await assert.rejects(() => ctx.gate.delegated.counter.sendPreflight(ownerPreflight, async () => ({}), () => true), /admission refused/);
    assert.equal(ctx.gate.snapshot().admissionRefused, true, JSON.stringify(answer));
  }
  const refused = await setup({ admission: { check: async () => ({ admitted: false }) } });
  await assert.rejects(() => refused.gate.start({ runId: "delegated" }), /admission refused/);
  assert.equal(refused.gate.snapshot().admissionRefused, true);
});

// The delegated seam is bound as tightly as the gate's own send.
async function admitted(ctx) {
  const cache = cacheOf(ctx);
  await ctx.gate.start({ runId: "delegated" });
  await cache.refreshOwner(ownerPreflight);
  await cache.fetchSigningKeys(keyPreflight);
  ctx.gate.admit();
  return cache;
}

test("a delegated request's ID must agree with its phase: recovery IDs only in recovery, preflight IDs only in preflight, neither in the normal phase", async () => {
  const ctx = await setup();
  await ctx.gate.start({ runId: "delegated" });
  const send = ctx.gate.delegated.counter;
  const attempt = async () => ({ sendAuthorized: false });
  // Preflight mode.
  ctx.trace.length = 0;
  await assert.rejects(send.sendPreflight("auth-shared/owner-token/1", attempt, () => true), /delegated request ID does not match its phase/);
  await assert.rejects(send.sendPreflight("recovery/auth-shared/owner-token/1", attempt, () => true), /delegated request ID does not match its phase/);
  await assert.rejects(send.send("preflight/auth/owner-token", attempt), /delegated request outside a request mode|does not match|preflight/);
  assert.deepEqual(ctx.trace.filter((entry) => entry.startsWith("intent:") || entry.startsWith("reserved:")), []);
  const cache = cacheOf(ctx);
  await cache.refreshOwner(ownerPreflight);
  await cache.fetchSigningKeys(keyPreflight);
  ctx.gate.admit();
  // Normal mode.
  ctx.trace.length = 0;
  for (const id of ["recovery/auth-shared/owner-token/1", "preflight/auth/owner-token"]) await assert.rejects(send.send(id, attempt), /delegated request ID does not match its phase/, id);
  await assert.rejects(send.sendPreflight("auth-shared/owner-token/2", attempt, () => true), /delegated request outside a request mode|preflight/);
  assert.deepEqual(ctx.trace.filter((entry) => entry.startsWith("intent:") || entry.startsWith("reserved:")), []);
  // Recovery mode.
  ctx.gate.enterRecovery();
  for (const id of ["auth-shared/owner-token/2", "auth/foreign-project-token/delete", "preflight/auth/owner-token"]) await assert.rejects(send.send(id, attempt), /delegated request ID does not match its phase/, id);
  assert.deepEqual(ctx.trace.filter((entry) => entry.startsWith("intent:") || entry.startsWith("reserved:")), []);
  await send.send("recovery/auth-shared/owner-token/1", attempt);
  assert.ok(ctx.trace.some((entry) => entry === "intent:recovery/auth-shared/owner-token/1:recovery"));
});

test("a delegated request's target is bound durably: a digest of the exact request is journalled before it is sent, without any secret", async () => {
  const notes = [];
  const sentSpecs = [];
  const ctx = await setup({ capture: { writeNote: async (r) => { notes.push(r); } }, transport: { send: async (spec) => { sentSpecs.push(spec); return spec.url === certUrl ? raw({ synthetic: pem }) : raw({ access_token: token, token_type: "Bearer", expires_in: 3600 }); } } });
  const cache = await admitted(ctx);
  notes.length = 0;
  await cache.refreshOwner("auth-shared/owner-token/1");
  const bound = notes.filter((note) => /delegated target/.test(note.text));
  assert.equal(bound.length, 1);
  assert.equal(bound[0].operationId, "auth-shared/owner-token/1");
  assert.match(bound[0].text, /^delegated target [0-9a-f]{64}$/);
  const digest = bound[0].text.slice(-64);
  assert.equal(JSON.stringify(notes).includes(adc.refresh_token), false);
  assert.equal(JSON.stringify(notes).includes(adc.client_secret), false);
  // The digest follows the request: another refresh has another digest for the same URL because its body or ID differs, and equal requests digest equally.
  await cache.refreshOwner("auth-shared/owner-token/2");
  const second = notes.filter((note) => /delegated target/.test(note.text)).at(-1);
  assert.notEqual(second.text.slice(-64), digest);
  assert.equal(sentSpecs.length >= 4, true);
});

test("a target digest that cannot be journalled stops the request before it is sent", async () => {
  let failNote = false;
  const sends = [];
  const ctx = await setup({ capture: { writeNote: async (r) => { if (failNote && /delegated target/.test(r.text)) throw new Error("disk full"); } }, transport: { send: async (spec) => { sends.push(spec.url); return spec.url === certUrl ? raw({ synthetic: pem }) : raw({ access_token: token, token_type: "Bearer", expires_in: 3600 }); } } });
  const cache = await admitted(ctx);
  const before = sends.length;
  failNote = true;
  await assert.rejects(() => cache.refreshOwner("auth-shared/owner-token/1"), /credential cache request failed/);
  assert.equal(sends.length, before);
});
