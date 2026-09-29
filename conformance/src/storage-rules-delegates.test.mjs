import assert from "node:assert/strict";
import { createHmac, generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { createController } from "./storage-rules/controller.mjs";
import { buildCorpus } from "./storage-rules/corpus.mjs";
import { createRunnerDelegates } from "./storage-rules/delegates.mjs";
import { createDispatchGate } from "./storage-rules/dispatch-gate.mjs";
import { buildFullRequestManifest } from "./storage-rules/full-manifest.mjs";
import { createResourceLedger } from "./storage-rules/resource-ledger.mjs";
import { createRunLedger } from "./storage-rules/run-ledger.mjs";
import { buildRecoverySchedule, buildSchedule } from "./storage-rules/schedule.mjs";
import { buildRefTables, createRuntimeRefStore } from "./storage-rules/runtime-refs.mjs";
import { createTargetBuilder } from "./storage-rules/target.mjs";
import { createSimulator } from "./storage-rules-simulator.mjs";

// Every delegate real, every endpoint simulated: the Storage/Rules/Firestore simulator plus a fake OAuth endpoint, the
// signing-key endpoint and a small Identity Toolkit. Nothing here reaches a network.
const closure = JSON.parse(readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url)));
const options = { runId: "local-run", sourceCommit: "a".repeat(40), queryProjectNumber: "1".repeat(12), idpProjectNumber: "2".repeat(12), queryApiKeyId: "00000000-0000-4000-8000-000000000001", idpApiKeyId: "00000000-0000-4000-8000-000000000002" };
const binding = { bucket: "synthetic-rules-bucket", prefix: "STORAGE-RULES/local-run/", uidA: "storage-rules-local-run-user-a", uidB: "storage-rules-local-run-user-b" };
const manifest = buildFullRequestManifest(buildCorpus(binding), closure, options);
const salt = "5".repeat(64);
const invalidContent = manifest.rows.filter((r) => r.family === "compile" && r.stage === "test").at(-1).request.body.json.source.files[0].content;
const CERT_URL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";
const OWNER_TOKEN = "synthetic-owner-access-token-00003";
const MALFORMED = { "malformed-token": "Bearer not.a.token", "malformed-oauth": "Bearer ya29.malformed-oauth-value" };
const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const adc = { type: "authorized_user", client_id: "synthetic-client.apps.googleusercontent.com", client_secret: "synthetic-client-secret-00001", refresh_token: "synthetic-refresh-token-with/slash+00002" };
const passwords = Object.fromEntries(["user-a", "user-b", "revoked-token", "foreign-project-token"].map((name) => [name, `Strong-private-${name}-password!`]));
const apiKeys = { "fireemu-oracle-query": "A".repeat(39), "fireemu-oracle-idp": "B".repeat(39) };
const delegatedRow = (row) => ["auth", "credential-cache"].includes(row.family);
const counted = manifest.rows.filter((r) => !delegatedRow(r));
const json = (body) => ({ status: 200, rawHeaders: ["Content-Type", "application/json"], bytes: Buffer.from(JSON.stringify(body)), startedAtMs: 1, finishedAtMs: 2 });

function fakeIdentity(clock) {
  const users = new Map();
  let nextForeign = 0;
  const mint = (user, project) => {
    const iat = clock.now - 1;
    const payload = { iss: `https://securetoken.google.com/${project}`, aud: project, sub: user.localId, user_id: user.localId, iat, exp: iat + 3600, auth_time: iat, email: user.email, email_verified: user.emailVerified, firebase: { identities: { email: [user.email] }, sign_in_provider: "password" }, ...JSON.parse(user.customAttributes || "{}") };
    const data = `${Buffer.from(JSON.stringify({ alg: "RS256", kid: "test", typ: "JWT" })).toString("base64url")}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}`;
    return `${data}.${sign("RSA-SHA256", Buffer.from(data), privateKey).toString("base64url")}`;
  };
  return {
    users,
    handle(spec) {
      const url = new URL(spec.url);
      const body = JSON.parse(spec.body.toString("utf8"));
      const project = url.pathname.startsWith("/v1/projects/") ? url.pathname.split("/")[3] : url.searchParams.get("key") === apiKeys["fireemu-oracle-idp"] ? "fireemu-oracle-idp" : "fireemu-oracle-query";
      const path = url.pathname;
      const key = (uid) => `${project}/${uid}`;
      if (/\/accounts$/.test(path) || path === "/v1/accounts:signUp") {
        const uid = body.localId || `foreign-captured-uid-${++nextForeign}`;
        const user = { localId: uid, email: body.email, emailVerified: body.emailVerified || false, customAttributes: "{}", validSince: String(clock.now - 100) };
        users.set(key(uid), user);
        return json({ localId: uid, email: body.email, ...(path.endsWith(":signUp") ? { idToken: mint(user, project), refreshToken: "private-refresh-secret" } : {}) });
      }
      if (path.endsWith(":lookup")) {
        let found;
        if (body.idToken) found = [users.get(key(JSON.parse(Buffer.from(body.idToken.split(".")[1], "base64url")).sub))].filter(Boolean);
        else if (body.localId) found = body.localId.map((uid) => users.get(key(uid))).filter(Boolean);
        else found = [...users.entries()].filter(([k, user]) => k.startsWith(`${project}/`) && body.email.includes(user.email)).map(([, user]) => user);
        return json({ users: structuredClone(found) });
      }
      if (path.endsWith(":update")) {
        const user = users.get(key(body.localId));
        if (Object.hasOwn(body, "customAttributes")) user.customAttributes = body.customAttributes;
        if (Object.hasOwn(body, "validSince")) user.validSince = body.validSince;
        return json({ localId: user.localId, email: user.email });
      }
      if (path.endsWith(":signInWithPassword")) {
        const user = [...users.entries()].find(([k, u]) => k.startsWith(`${project}/`) && u.email === body.email)?.[1];
        return json({ localId: user.localId, email: user.email, idToken: mint(user, project), refreshToken: "private-refresh-secret" });
      }
      if (path.endsWith(":delete")) { users.delete(key(body.localId)); return json({}); }
      throw new Error(`unexpected identity route ${path}`);
    },
  };
}

async function assemble({ simulatorOptions = {}, respond = () => undefined, admission, evidence } = {}) {
  const clock = { now: Math.floor(Date.now() / 1000) };
  const identity = fakeIdentity(clock);
  const simulator = createSimulator({ manifest, options: { invalidContent, ...simulatorOptions } });
  const seen = { http: [], headers: [], proofs: [], ownership: [], cleanup: [] };
  const trace = [];
  const transport = { send: async (spec) => {
    seen.http.push(`${spec.method} ${new URL(spec.url).host}${new URL(spec.url).pathname}`);
    seen.headers.push(spec.headers);
    const replaced = respond(spec, trace.at(-1), clock);
    if (replaced !== undefined) return replaced;
    if (spec.url === CERT_URL) return { status: 200, rawHeaders: ["Cache-Control", "public, max-age=3600", "Age", "0"], bytes: Buffer.from(JSON.stringify({ test: publicKey.export({ type: "spki", format: "pem" }) })), startedAtMs: 1, finishedAtMs: 2 };
    if (spec.url.startsWith("https://oauth2.googleapis.com/")) return json({ access_token: OWNER_TOKEN, token_type: "Bearer", expires_in: 3600 });
    if (spec.url.startsWith("https://identitytoolkit.googleapis.com/")) return identity.handle(spec);
    return simulator.send(spec);
  } };
  const capture = { writeIntent: async () => {}, writeResponse: async () => {}, writeFacts: async () => {}, writeProof: async (proof) => { seen.proofs.push(proof); }, writeNote: async () => {}, snapshot: () => ({ uncertain: false }) };
  const targets = createTargetBuilder({ manifest, digestSalt: salt });
  const tables = buildRefTables(manifest);
  const refs = createRuntimeRefStore({ tables, runId: options.runId, digestSalt: salt, writeProof: (proof) => capture.writeProof(proof) });
  const objects = createResourceLedger({ manifest });
  const run = createRunLedger({ manifest, objects });
  let real;
  const gate = createDispatchGate({
    reservations: { onStarted: async () => {}, onReserve: async (r) => { trace.push(r.operationId); }, onTerminal: async (r) => { trace.push(`terminal:${r.outcome}`); } },
    capture, transport, targets, credentials: { headersFor: (credential, context) => real.credentials.headersFor(credential, context) },
    preflightIds: manifest.preflightIds, admission: admission ?? { check: async () => ({ admitted: true }) },
  });
  real = createRunnerDelegates({ gate, adc, apiKeys, passwords, digestSalt: salt, runId: "lr", nowSeconds: () => clock.now, waitUntilSeconds: async (value) => { clock.now = Math.max(clock.now, value); },
    evidence: evidence ?? { writeCredentialProof: async (proof) => { seen.proofs.push(proof); }, writeOwnership: async (row) => { seen.ownership.push(row); }, writeCleanup: async (row) => { seen.cleanup.push(row); } }, malformed: MALFORMED });
  const controller = createController({
    manifest, schedule: buildSchedule(manifest), recoverySchedule: buildRecoverySchedule(manifest), gate, targets, refs, tables, objects, run, capture,
    delegates: real.delegates, wait: async () => {}, credentials: real.credentials,
    judgePreflight: (row, outcome) => outcome.verdict !== "unexpected",
  });
  return { controller, gate, simulator, seen, trace, identity, real, clock, objects };
}

test("a whole recording with every delegate real counts each request once and leaves nothing behind", async () => {
  const h = await assemble();
  const result = await h.controller.run();
  assert.equal(result.status, "finished", JSON.stringify(result));
  const state = h.simulator.state();
  assert.deepEqual({ objects: state.objects, rulesets: state.rulesets, release: state.release, documents: state.documents }, { objects: 0, rulesets: 0, release: null, documents: 0 });
  assert.equal(h.identity.users.size, 0);
  // 2 preflight cache rows and the 2 normal cache refreshes are counted with the auth fixture's requests.
  const authIds = h.trace.filter((id) => id.startsWith("auth/") || id.startsWith("auth-shared/") || id.startsWith("preflight/auth/"));
  assert.ok(authIds.some((id) => id === "preflight/auth/owner-token") && authIds.some((id) => id === "auth-shared/owner-token/1") && authIds.some((id) => id === "auth-shared/signing-keys/1"));
  assert.equal(authIds.filter((id) => id.startsWith("auth/")).length, manifest.rows.filter((r) => r.family === "auth" && r.phase === "normal").length);
  const sent = h.trace.filter((id) => !id.startsWith("terminal"));
  assert.equal(new Set(sent).size, sent.length);
  assert.equal(h.gate.snapshot().requests, sent.length);
  assert.equal(h.trace.at(-1), "terminal:finished");
  assert.deepEqual(h.seen.cleanup.map((row) => row.account).sort(), ["foreign-project-token", "revoked-token", "user-a", "user-b"]);
});

test("owner requests carry the owner bearer and the row's project, user requests the chosen scheme, and secrets never leave the transport", async () => {
  const h = await assemble();
  const result = await h.controller.run();
  assert.equal(result.status, "finished", JSON.stringify(result));
  const admin = h.seen.headers.filter((headers) => headers.authorization === `Bearer ${OWNER_TOKEN}`);
  assert.ok(admin.length > 1000);
  assert.ok(admin.every((headers) => ["fireemu-oracle-query", "fireemu-oracle-idp"].includes(headers["x-goog-user-project"])));
  assert.ok(h.seen.headers.some((headers) => /^Firebase eyJ/.test(headers.authorization ?? "")));
  assert.ok(h.seen.headers.some((headers) => headers.authorization === MALFORMED["malformed-token"]));
  assert.ok(h.seen.headers.some((headers) => headers.authorization === MALFORMED["malformed-oauth"]));
  const serialized = JSON.stringify(h.seen.proofs) + JSON.stringify(h.seen.ownership) + JSON.stringify(h.seen.cleanup) + JSON.stringify(h.trace);
  for (const secret of [OWNER_TOKEN, "private-refresh-secret", adc.refresh_token, adc.client_secret, ...Object.values(passwords)]) assert.equal(serialized.includes(secret), false, secret.slice(0, 12));
});

test("the foreign fixture is created before its declared row and deleted right after it", async () => {
  const h = await assemble();
  await h.controller.run();
  const foreignRow = manifest.rows.find((r) => r.request.credential === "foreign-project-token").id;
  const at = (id) => h.trace.indexOf(id);
  assert.ok(at("auth/foreign-project-token/sign-up") < at(foreignRow));
  assert.ok(at(foreignRow) < at("auth/foreign-project-token/delete"));
  assert.ok(at("auth/foreign-project-token/delete") < at("auth/foreign-project-token/absence"));
});

test("an owner token close to expiry is refreshed on demand through the next declared refresh ID, once", async () => {
  let sends = 0;
  const h = await assemble({ respond: (spec, _op, clock) => { if (++sends === 400) clock.now += 3400; return undefined; } });
  const result = await h.controller.run();
  assert.equal(result.status, "finished", JSON.stringify(result));
  const refreshes = h.trace.filter((id) => /^auth-shared\/owner-token\//.test(id));
  assert.deepEqual(refreshes, ["auth-shared/owner-token/1", "auth-shared/owner-token/2"]);
});

test("a stop with the foreign fixture open is recovered: the fixture is abandoned, every account is deleted and the run closes as recovered", async () => {
  const foreignRow = manifest.rows.find((r) => r.request.credential === "foreign-project-token").id;
  // The connection to the service drops on the declared foreign row: its outcome is unknown and the run stops with the fixture open.
  const h = await assemble({ respond: (spec, operationId) => { if (operationId === foreignRow) throw new Error("connection reset"); return undefined; } });
  const stopped = await h.controller.run();
  assert.deepEqual([stopped.status, stopped.reason, stopped.detail?.rowId], ["stopped", "outcome uncertain", foreignRow], JSON.stringify(stopped));
  assert.equal(h.real.snapshot().foreignOpen, true);
  assert.ok(h.identity.users.size >= 4);
  const result = await h.controller.recover();
  assert.equal(result.status, "recovered", JSON.stringify(result));
  assert.equal(h.identity.users.size, 0);
  assert.equal(h.real.snapshot().foreignOpen, false);
  const state = h.simulator.state();
  assert.deepEqual({ objects: state.objects, rulesets: state.rulesets, release: state.release, documents: state.documents }, { objects: 0, rulesets: 0, release: null, documents: 0 });
  assert.equal(h.trace.at(-1), "terminal:recovered");
  assert.deepEqual(h.seen.cleanup.map((row) => row.account).sort(), ["foreign-project-token", "revoked-token", "user-a", "user-b"]);
});

test("a stop after the query accounts were made deletes exactly those accounts in recovery", async () => {
  const h = await assemble({ simulatorOptions: { invalidContent: "never matches anything" } });
  const stopped = await h.controller.run();
  assert.equal(stopped.status, "stopped");
  assert.equal(h.identity.users.size, 3);
  const before = h.trace.length;
  const result = await h.controller.recover();
  assert.equal(result.status, "recovered", JSON.stringify(result));
  const authRecovery = h.trace.slice(before).filter((id) => id.startsWith("recovery/auth/"));
  assert.deepEqual(authRecovery.sort(), ["user-a", "user-b", "revoked-token"].flatMap((account) => [`recovery/auth/${account}/absence`, `recovery/auth/${account}/delete`]).sort());
  assert.equal(h.identity.users.size, 0);
});

test("a stop before the fixture session exists recovers without any account request", async () => {
  const h = await assemble({ respond: (spec, operationId) => { if (operationId === "management/control-0/seed") throw new Error("connection reset"); return undefined; } });
  const stopped = await h.controller.run();
  assert.equal(stopped.reason, "outcome uncertain");
  const before = h.trace.length;
  await h.controller.recover();
  assert.equal(h.trace.slice(before).some((id) => id.startsWith("recovery/auth")), false);
  assert.equal(h.identity.users.size, 0);
});

test("the delegate options are a closed record and the credential provider refuses what it does not know", async () => {
  const good = await assemble();
  assert.throws(() => createRunnerDelegates(null), /invalid runner delegate options/);
  assert.throws(() => createRunnerDelegates({}), /invalid runner delegate options/);
  const noEvidence = { writeCredentialProof: async () => {}, writeOwnership: async () => {}, writeCleanup: async () => {} };
  const base = { gate: good.gate, adc, apiKeys, passwords, digestSalt: salt, runId: "lr", nowSeconds: () => 1, waitUntilSeconds: async () => {}, evidence: noEvidence, malformed: MALFORMED };
  assert.doesNotThrow(() => createRunnerDelegates(base));
  for (const bad of [{ ...base, extra: 1 }, { ...base, userTokenScheme: "Bearer" }, { ...base, evidence: {} }, { ...base, evidence: { ...noEvidence, writeCleanup: 1 } }, { ...base, evidence: Object.assign(Object.create(null), noEvidence) }, { ...base, evidence: Object.assign(() => {}, noEvidence) }, { ...base, malformed: { ...MALFORMED, "malformed-token": "" } }, { ...base, malformed: { "malformed-token": "x" } }, { ...base, gate: {} }, { ...base, nowSeconds: 1 }]) {
    assert.throws(() => createRunnerDelegates(bad), /invalid runner delegate options/);
  }
  const { credentials } = createRunnerDelegates(base);
  assert.throws(() => credentials.headersFor("adc-refresh", { project: "fireemu-oracle-query" }), /unknown credential/);
  assert.throws(() => credentials.headersFor("admin", {}), /no known project/);
  assert.throws(() => credentials.headersFor("admin", { project: "another-project" }), /no known project/);
  assert.deepEqual(credentials.headersFor("anonymous", {}), {});
  assert.equal(credentials.fresh({ request: { credential: "adc-refresh" } }), false);
  assert.equal(credentials.fresh({ request: { credential: "anonymous" } }), true);
  assert.equal(credentials.fresh({ request: { credential: "user-a" } }), false);
});

test("ownership and cleanup receipts reach the real journal as digests, and no file of it holds a secret", async (t) => {
  const { mkdtemp, open, lstat, mkdir, readFile, rm } = await import("node:fs/promises");
  const { createCaptureJournal } = await import("./storage-rules/capture-journal.mjs");
  const directory = await mkdtemp("/private/tmp/storage-rules-delegates-");
  t.after(() => rm(directory, { recursive: true, force: true }));
  const journal = await createCaptureJournal({ directory, runId: options.runId, sourceCommit: options.sourceCommit, manifestDigest: manifest.sha256, digestSalt: salt, requestIds: manifest.rows.map((r) => r.id), io: { open, lstat, mkdir } });
  const h = await assemble({ evidence: journal });
  const result = await h.controller.run();
  assert.equal(result.status, "finished", JSON.stringify(result));
  await journal.close();
  const text = await readFile(`${directory}/captures.jsonl`, "utf8");
  const rows = text.split("\n").filter(Boolean).map((line) => JSON.parse(line));
  assert.deepEqual(rows.filter((row) => row.event === "ownership").map((row) => row.data.account).sort(), ["foreign-project-token", "revoked-token", "user-a", "user-b"]);
  assert.deepEqual(rows.filter((row) => row.event === "cleanup").map((row) => row.data.account).sort(), ["foreign-project-token", "revoked-token", "user-a", "user-b"]);
  assert.equal(rows.filter((row) => row.event === "credential-proof").length, 9);
  assert.ok(rows.filter((row) => row.event === "ownership").every((row) => row.data.runPrefix === "storage-rules-lr" && /^[0-9a-f]{64}$/.test(row.data.emailSha256)));
  for (const secret of [OWNER_TOKEN, "private-refresh-secret", adc.refresh_token, adc.client_secret, "@example.com", ...Object.values(passwords)]) assert.equal(text.includes(secret), false, secret.slice(0, 12));
});

// One gate with only the two credential-cache preflight rows, the real delegates and a fixed clock: enough to drive each
// delegate and credential step directly.
const OWNER_PREFLIGHT = "preflight/auth/owner-token";
const KEYS_PREFLIGHT = "preflight/auth/signing-keys";
const T0 = 1790553600;
const ADMIN = { request: { credential: "admin" } };
const credentialRow = (credential) => ({ request: { credential } });

function unit({ respond = () => undefined } = {}) {
  const clock = { now: T0 };
  const identity = fakeIdentity(clock);
  const trace = [];
  const seen = { http: 0, proofs: [], ownership: [], cleanup: [] };
  const transport = { send: async (spec) => {
    seen.http++;
    const replaced = respond(spec);
    if (replaced !== undefined) return replaced;
    if (spec.url === CERT_URL) return { status: 200, rawHeaders: ["Cache-Control", "public, max-age=3600", "Age", "0"], bytes: Buffer.from(JSON.stringify({ test: publicKey.export({ type: "spki", format: "pem" }) })), startedAtMs: 1, finishedAtMs: 2 };
    if (spec.url.startsWith("https://oauth2.googleapis.com/")) return json({ access_token: OWNER_TOKEN, token_type: "Bearer", expires_in: 3600 });
    if (spec.url.startsWith("https://identitytoolkit.googleapis.com/")) return identity.handle(spec);
    throw new Error(`unexpected request ${spec.url}`);
  } };
  const gate = createDispatchGate({
    reservations: { onStarted: async () => {}, onReserve: async (r) => { trace.push(`${r.phase}:${r.operationId}`); }, onTerminal: async (r) => { trace.push(`terminal:${r.outcome}`); } },
    capture: { writeIntent: async () => {}, writeResponse: async () => {}, writeNote: async () => {}, snapshot: () => ({ uncertain: false }) },
    transport, targets: { verify: () => true, prepare: () => { throw new Error("unused"); } }, credentials: { headersFor: () => ({}) },
    preflightIds: [OWNER_PREFLIGHT, KEYS_PREFLIGHT], admission: { check: async () => ({ admitted: true }) },
  });
  const real = createRunnerDelegates({ gate, adc, apiKeys, passwords, digestSalt: salt, runId: "lr", nowSeconds: () => clock.now, waitUntilSeconds: async (value) => { clock.now = Math.max(clock.now, value); },
    evidence: { writeCredentialProof: async (proof) => { seen.proofs.push(proof); }, writeOwnership: async (row) => { seen.ownership.push(row); }, writeCleanup: async (row) => { seen.cleanup.push(row); } }, malformed: MALFORMED });
  // Start the counter, pass both cache preflights, admit, then spend the first normal refresh of each kind at T0.
  const open = async () => {
    await gate.start({ runId: "lr" });
    await real.delegates["preflight-cache"]({ id: OWNER_PREFLIGHT });
    await real.delegates["preflight-cache"]({ id: KEYS_PREFLIGHT });
    gate.admit();
    await real.delegates["credential-cache"]();
  };
  return { gate, real, clock, trace, seen, identity, open, delegates: real.delegates, credentials: real.credentials };
}
const refreshIds = (trace) => trace.filter((entry) => /owner-token\//.test(entry));

test("the owner token is refreshed when exactly the refresh margin remains, and not a second earlier", async () => {
  const u = unit();
  await u.open();
  // The owner token of auth-shared/owner-token/1 was fetched at T0 and expires at T0 + 3600.
  u.clock.now = T0 + 3600 - 301;
  await u.credentials.ensure(ADMIN);
  assert.deepEqual(refreshIds(u.trace), ["normal:auth-shared/owner-token/1"]);
  u.clock.now = T0 + 3600 - 300;
  await u.credentials.ensure(ADMIN);
  assert.deepEqual(refreshIds(u.trace), ["normal:auth-shared/owner-token/1", "normal:auth-shared/owner-token/2"]);
  // The next stale token spends the next ID; none is reused.
  u.clock.now += 3600 - 300;
  await u.credentials.ensure(ADMIN);
  assert.deepEqual(refreshIds(u.trace), ["normal:auth-shared/owner-token/1", "normal:auth-shared/owner-token/2", "normal:auth-shared/owner-token/3"]);
});

test("the declared normal refresh IDs are a budget: past the eighth a stale owner token stops without a request", async () => {
  const u = unit();
  await u.open();
  for (let index = 2; index <= 8; index++) {
    u.clock.now += 3400;
    await u.credentials.ensure(ADMIN);
    assert.equal(refreshIds(u.trace).at(-1), `normal:auth-shared/owner-token/${index}`);
  }
  u.clock.now += 3400;
  const before = { http: u.seen.http, trace: u.trace.length };
  await assert.rejects(() => u.credentials.ensure(ADMIN), /owner token refresh budget exhausted/);
  assert.deepEqual({ http: u.seen.http, trace: u.trace.length }, before);
});

test("in recovery the owner token is refreshed through the recovery refresh IDs, from the first one", async () => {
  const u = unit();
  await u.open();
  u.gate.enterRecovery();
  u.clock.now += 3400;
  await u.credentials.ensure(ADMIN);
  u.clock.now += 3400;
  await u.credentials.ensure(ADMIN);
  assert.deepEqual(refreshIds(u.trace), ["normal:auth-shared/owner-token/1", "recovery:recovery/auth-shared/owner-token/1", "recovery:recovery/auth-shared/owner-token/2"]);
});

test("only owner rows outside the preflight refresh the owner token", async () => {
  const u = unit();
  await u.gate.start({ runId: "lr" });
  // Preflight: no owner token yet, and no refresh is attempted for an owner row.
  await u.credentials.ensure(ADMIN);
  assert.deepEqual(u.trace, []);
  await u.delegates["preflight-cache"]({ id: OWNER_PREFLIGHT });
  await u.delegates["preflight-cache"]({ id: KEYS_PREFLIGHT });
  u.gate.admit();
  await u.delegates["credential-cache"]();
  u.clock.now += 3400;
  for (const credential of ["anonymous", "user-a", "malformed-token", "foreign-project-token"]) await u.credentials.ensure(credentialRow(credential));
  assert.deepEqual(refreshIds(u.trace), ["normal:auth-shared/owner-token/1"]);
  await u.credentials.ensure(ADMIN);
  assert.equal(refreshIds(u.trace).at(-1), "normal:auth-shared/owner-token/2");
});

test("outside a request mode a stale owner token is refused before any request", async () => {
  const u = unit();
  await u.open();
  await u.gate.finish("finished");
  const before = { http: u.seen.http, trace: u.trace.length };
  await assert.rejects(() => u.credentials.ensure(ADMIN), /no refresh outside a request mode/);
  assert.deepEqual({ http: u.seen.http, trace: u.trace.length }, before);
});

test("the owner credential is fresh only with more than 60 seconds left", async () => {
  const u = unit();
  assert.equal(u.credentials.fresh(ADMIN), false);
  await u.open();
  const expected = [[T0, true], [T0 + 3600 - 61, true], [T0 + 3600 - 60, false], [T0 + 3600 - 45, false], [T0 + 3600, false]];
  assert.deepEqual(expected.map(([now]) => { u.clock.now = now; return [now, u.credentials.fresh(ADMIN)]; }), expected);
});

test("a user token is fresh only with more than 60 seconds left", async () => {
  const u = unit();
  await u.open();
  await u.delegates["prepare-query"]();
  // user-a's token was minted at T0 - 1 and expires at T0 + 3599.
  const expected = [[T0 + 3599 - 61, true], [T0 + 3599 - 60, false], [T0 + 3599 - 45, false]];
  assert.deepEqual(expected.map(([now]) => { u.clock.now = now; return [now, u.credentials.fresh(credentialRow("user-a"))]; }), expected);
});

test("user and foreign credentials without a session or an open fixture are refused, never sent empty", async () => {
  const u = unit();
  assert.throws(() => u.credentials.headersFor("user-a", { project: "fireemu-oracle-query" }), /no session/);
  assert.throws(() => u.credentials.headersFor("foreign-project-token", { project: "fireemu-oracle-idp" }), /no foreign token/);
  assert.equal(u.credentials.fresh(credentialRow("foreign-project-token")), false);
});

test("an unknown preflight cache row is refused without a request", async () => {
  const u = unit();
  await u.gate.start({ runId: "lr" });
  for (const id of ["preflight/auth/other", "auth-shared/owner-token/1", undefined]) await assert.rejects(() => u.delegates["preflight-cache"]({ id }), /unknown preflight cache row/);
  assert.equal(u.seen.http, 0);
  assert.deepEqual(u.trace, []);
});

test("the fixture session is created once", async () => {
  const u = unit();
  await u.open();
  await u.delegates["prepare-query"]();
  const before = { http: u.seen.http, trace: u.trace.length };
  await assert.rejects(() => u.delegates["prepare-query"](), /fixture session already created/);
  assert.deepEqual({ http: u.seen.http, trace: u.trace.length }, before);
  assert.equal(u.real.snapshot().session.mode, "query-ready");
});

test("the foreign fixture opens only after the query accounts and only once at a time, and closes once", async () => {
  const u = unit();
  await u.open();
  await assert.rejects(() => u.delegates["foreign-signup"](), /foreign fixture unavailable/);
  await assert.rejects(() => u.delegates["foreign-cleanup"](), /no foreign fixture is open/);
  await u.delegates["prepare-query"]();
  await u.delegates["foreign-signup"]();
  assert.equal(u.real.snapshot().foreignOpen, true);
  assert.match(u.credentials.headersFor("foreign-project-token", { project: "fireemu-oracle-idp" }).authorization, /^Firebase eyJ/);
  assert.equal(u.credentials.fresh(credentialRow("foreign-project-token")), true);
  const before = { http: u.seen.http, trace: u.trace.length };
  await assert.rejects(() => u.delegates["foreign-signup"](), /foreign fixture unavailable/);
  assert.deepEqual({ http: u.seen.http, trace: u.trace.length }, before);
  assert.equal(u.real.snapshot().foreignOpen, true);
  await u.delegates["foreign-cleanup"]();
  assert.equal(u.real.snapshot().foreignOpen, false);
  assert.throws(() => u.credentials.headersFor("foreign-project-token", { project: "fireemu-oracle-idp" }), /no foreign token/);
  assert.equal(u.credentials.fresh(credentialRow("foreign-project-token")), false);
  assert.deepEqual([...u.identity.users.keys()].filter((key) => key.startsWith("fireemu-oracle-idp/")), []);
  await assert.rejects(() => u.delegates["foreign-cleanup"](), /no foreign fixture is open/);
});

test("a foreign fixture that fails to open fails its step", async () => {
  const u = unit({ respond: (spec) => (spec.url.includes("/projects/fireemu-oracle-idp/accounts:lookup") ? { ...json({}), status: 503 } : undefined) });
  await u.open();
  await u.delegates["prepare-query"]();
  await assert.rejects(() => u.delegates["foreign-signup"]());
  assert.equal(u.real.snapshot().foreignOpen, false);
  assert.throws(() => u.credentials.headersFor("foreign-project-token", { project: "fireemu-oracle-idp" }), /no foreign token/);
});

test("account recovery without a fixture session sends nothing", async () => {
  const u = unit();
  await u.open();
  u.gate.enterRecovery();
  const before = { http: u.seen.http, trace: u.trace.length };
  await u.delegates["recover-accounts"]();
  assert.deepEqual({ http: u.seen.http, trace: u.trace.length }, before);
});

test("account recovery abandons an open foreign fixture as a failure, so its account is deleted in recovery", async () => {
  const u = unit();
  await u.open();
  await u.delegates["prepare-query"]();
  await u.delegates["foreign-signup"]();
  // The counter is still normal: the abandoned fixture is a failure for the session, which moves the counter to recovery
  // before it deletes the foreign account.
  await u.delegates["recover-accounts"]();
  assert.ok(u.trace.includes("recovery:auth/foreign-project-token/delete"), JSON.stringify(u.trace.slice(-12)));
  assert.equal(u.trace.includes("normal:auth/foreign-project-token/delete"), false);
  assert.equal(u.identity.users.size, 0);
  assert.equal(u.real.snapshot().foreignOpen, false);
  assert.equal(u.real.snapshot().session.mode, "recovered");
});

test("account recovery refreshes a stale owner token through a recovery refresh ID before it deletes the accounts", async () => {
  const u = unit();
  await u.open();
  await u.delegates["prepare-query"]();
  u.gate.enterRecovery();
  // 200 seconds left: still usable, but inside the 300-second refresh margin.
  u.clock.now = T0 + 3400;
  await u.delegates["recover-accounts"]();
  const refresh = u.trace.indexOf("recovery:recovery/auth-shared/owner-token/1");
  const firstDelete = u.trace.findIndex((entry) => entry.startsWith("recovery:recovery/auth/"));
  assert.ok(refresh >= 0 && refresh < firstDelete, JSON.stringify(u.trace.slice(-10)));
  assert.equal(u.identity.users.size, 0);
});

test("ownership and cleanup receipts reach the evidence writers exactly, with the address as a salted, tagged HMAC", async () => {
  const u = unit();
  await u.open();
  await u.delegates["prepare-query"]();
  await u.delegates["foreign-signup"]();
  await u.delegates["foreign-cleanup"]();
  await u.delegates["cleanup-query"]();
  const emailSha256 = (account) => createHmac("sha256", Buffer.from(salt, "hex")).update("storage-rules-email\0").update(`storage-rules-lr-${account}@example.com`).digest("hex");
  const uid = (account) => (account === "foreign-project-token" ? "foreign-captured-uid-1" : `storage-rules-lr-${account}`);
  const project = (account) => (account === "foreign-project-token" ? "fireemu-oracle-idp" : "fireemu-oracle-query");
  const accounts = ["user-a", "user-b", "revoked-token", "foreign-project-token"];
  assert.deepEqual(u.seen.ownership, accounts.map((account) => ({ account, project: project(account), uid: uid(account), runPrefix: "storage-rules-lr", emailSha256: emailSha256(account), creationRequestId: `auth/${account}/${account === "foreign-project-token" ? "sign-up" : "create"}` })));
  assert.deepEqual(u.seen.cleanup, ["foreign-project-token", "user-a", "user-b", "revoked-token"].map((account) => ({ account, project: project(account), uid: uid(account), absent: true, requestId: `auth/${account}/absence` })));
  assert.equal(u.seen.proofs.length, 9);
});
