import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { createStage3RequestCounter } from "./storage-rules/request-counter.mjs";

const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const fixedNow = 1790553600;
const runId = "session-test";
const passwords = Object.fromEntries(["user-a", "user-b", "revoked-token", "foreign-project-token"].map((name) => [name, `Strong-private-${name}-password!`]));
const keySet = { fetchedAt: fixedNow - 10, expiresAt: fixedNow + 2000, publicKeys: { test: publicKey.export({ type: "spki", format: "pem" }) } };

function mint(user, project, iat) {
  const payload = {
    iss: `https://securetoken.google.com/${project}`, aud: project, sub: user.localId, user_id: user.localId,
    iat, exp: iat + 3600, auth_time: iat, email: user.email, email_verified: user.emailVerified,
    firebase: { identities: { email: [user.email] }, sign_in_provider: "password" }, ...JSON.parse(user.customAttributes || "{}"),
  };
  const data = `${Buffer.from(JSON.stringify({ alg: "RS256", kid: "test", typ: "JWT" })).toString("base64url")}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}`;
  return `${data}.${sign("RSA-SHA256", Buffer.from(data), privateKey).toString("base64url")}`;
}

async function setup({ mutate = (_id, _spec, response) => response, writeOwnership, writeProof, writeCleanup, freshIat = false, foreignUid = "foreign-captured-uid", reserveFailureId = null, admitCounter = true, keyExpiry = keySet.expiresAt } = {}) {
  const module = await import("./storage-rules/credential-session.mjs").catch((error) => {
    if (error.code === "ERR_MODULE_NOT_FOUND") return {};
    throw error;
  });
  assert.equal(typeof module.createCredentialFixtureSession, "function");
  let currentTime = fixedNow;
  const events = [];
  const requests = [];
  const proofs = [];
  const ownership = [];
  const cleanup = [];
  const users = new Map();
  const counter = createStage3RequestCounter({
    preflightIds: ["preflight/test"], onStarted: async () => events.push(["started"]),
    onReserve: async (row) => { events.push(["reserve", row.operationId]); if (row.operationId === reserveFailureId) throw new Error("private-refresh-secret"); }, onTerminal: async (row) => events.push(["terminal", row.outcome]),
  });
  await counter.start({ runId });
  await counter.sendPreflight("preflight/test", async () => true, (value) => value);
  if (admitCounter) counter.admit();
  const transport = async (id, spec) => {
    assert.deepEqual(events.at(-1), ["reserve", id]);
    requests.push({ id, ...structuredClone(spec) });
    events.push(["transport", id]);
    const { body, project, path } = spec;
    const storeKey = (uid) => `${project}/${uid}`;
    let response;
    if (path.endsWith("/accounts") || path === "/v1/accounts:signUp") {
      const uid = body.localId || foreignUid;
      const user = { localId: uid, email: body.email, emailVerified: body.emailVerified || false, customAttributes: "{}", validSince: String(currentTime - 100) };
      users.set(storeKey(uid), user);
      response = { status: 200, body: { localId: uid, email: body.email, ...(path.endsWith(":signUp") ? { idToken: mint(user, project, currentTime - 1), refreshToken: "private-refresh-secret" } : {}) } };
    } else if (path.endsWith(":lookup")) {
      let matches;
      if (body.idToken) {
        const uid = JSON.parse(Buffer.from(body.idToken.split(".")[1], "base64url")).sub;
        matches = [users.get(storeKey(uid))].filter(Boolean);
      } else if (body.localId) matches = body.localId.map((uid) => users.get(storeKey(uid))).filter(Boolean);
      else matches = [...users.entries()].filter(([key, user]) => key.startsWith(`${project}/`) && body.email.includes(user.email)).map(([, user]) => user);
      response = { status: 200, body: { users: structuredClone(matches) } };
    } else if (path.endsWith(":update")) {
      const user = users.get(storeKey(body.localId));
      if (Object.hasOwn(body, "customAttributes")) user.customAttributes = body.customAttributes;
      if (Object.hasOwn(body, "validSince")) user.validSince = body.validSince;
      response = { status: 200, body: { localId: user.localId, email: user.email } };
    } else if (path.endsWith(":signInWithPassword")) {
      const user = [...users.entries()].find(([key, user]) => key.startsWith(`${project}/`) && user.email === body.email)?.[1];
      response = { status: 200, body: { localId: user.localId, email: user.email, idToken: mint(user, project, currentTime - (freshIat ? 0 : 1)), refreshToken: "private-refresh-secret" } };
    } else if (path.endsWith(":delete")) {
      users.delete(storeKey(body.localId));
      response = { status: 200, body: {} };
    } else throw new Error("unexpected test route");
    return await mutate(id, spec, response, { users, currentTime });
  };
  const session = module.createCredentialFixtureSession({
    runId, counter, transport, keySet: { ...keySet, expiresAt: keyExpiry }, digestSalt: "a1".repeat(32), passwords,
    nowSeconds: () => currentTime, waitUntilSeconds: async (value) => { events.push(["wait", value]); currentTime = value; },
    writeOwnership: writeOwnership || (async (row) => { ownership.push(row); events.push(["ownership", row.account]); }),
    writeProof: writeProof || (async (row) => { proofs.push(row); events.push(["proof", row.principal]); }),
    writeCleanup: writeCleanup || (async (row) => { cleanup.push(row); events.push(["cleanup", row.account]); }),
  });
  return { session, counter, events, requests, proofs, ownership, cleanup, users, advanceTime: (value) => { currentTime = value; } };
}

test("the complete fixture sequence counts 29 Auth requests and proves four owned account absences", async () => {
  const ctx = await setup();
  const prepared = await ctx.session.prepareQuery();
  assert.notEqual(prepared.uidA, prepared.uidB);
  const a = ctx.session.token("user-a");
  const plain = ctx.session.token("user-plain");
  assert.notEqual(a, plain);
  assert.equal(JSON.parse(Buffer.from(a.split(".")[1], "base64url")).sub, JSON.parse(Buffer.from(plain.split(".")[1], "base64url")).sub);
  await ctx.session.withForeignFixture(async (token) => {
    assert.equal(JSON.parse(Buffer.from(token.split(".")[1], "base64url")).aud, "fireemu-oracle-idp");
    ctx.events.push(["foreign-subject"]);
  });
  const foreignSubject = ctx.events.findIndex(([kind]) => kind === "foreign-subject");
  const foreignDelete = ctx.events.findIndex(([kind, id]) => kind === "transport" && id === "auth/foreign-project-token/delete");
  assert.equal(foreignDelete, foreignSubject + 2);
  await ctx.session.cleanupQuery();
  assert.equal(ctx.requests.length, 29);
  assert.equal(ctx.counter.snapshot().requests, 30);
  assert.equal(ctx.users.size, 0);
  assert.equal(ctx.proofs.length, 5);
  assert.equal(ctx.ownership.length, 4);
  assert.equal(ctx.cleanup.length, 4);
  assert.equal(ctx.session.snapshot().mode, "closed");
  const safeRecords = JSON.stringify([ctx.proofs, ctx.ownership, ctx.cleanup, ctx.session.snapshot()]);
  for (const secret of [...Object.values(passwords), a, plain, "private-refresh-secret"]) assert.ok(!safeRecords.includes(secret));
});

test("revocation advances beyond a same-second issuance before its update", async () => {
  const ctx = await setup({ freshIat: true });
  await ctx.session.prepareQuery();
  assert.ok(ctx.events.some(([kind]) => kind === "wait"));
  const proof = ctx.proofs.find((item) => item.principal === "revoked-token");
  assert.ok(proof.issuedAt < proof.revocationBoundary);
  await ctx.session.cleanupQuery();
});

test("a wrong claim readback prevents issuance of the user-a fixture", async () => {
  const ctx = await setup({ mutate: (id, _spec, response) => id === "auth/user-a/lookup-claims" ? { ...response, body: { users: [{ ...response.body.users[0], customAttributes: '{"role":"reader","level":"7"}' }] } } : response });
  await assert.rejects(ctx.session.prepareQuery(), /invalid fixture account readback/);
  assert.ok(!ctx.requests.some((request) => request.id === "auth/user-a/sign-in"));
  await ctx.session.recoverOwnedAccounts();
  assert.equal(ctx.users.size, 0);
});

test("a preexisting foreign account is never signed up or deleted", async () => {
  const ctx = await setup({ mutate: (id, _spec, response) => id === "auth/foreign-project-token/baseline" ? { status: 200, body: { users: [{ localId: "foreign-existing" }] } } : response });
  await ctx.session.prepareQuery();
  await assert.rejects(ctx.session.withForeignFixture(async () => assert.fail("subject forbidden")), /fixture account already exists/);
  assert.ok(!ctx.requests.some((request) => request.project === "fireemu-oracle-idp" && request.path.endsWith(":delete")));
  await ctx.session.recoverOwnedAccounts();
});

test("a foreign token lookup UID mismatch blocks the subject and cleans only its confirmed creation", async () => {
  const ctx = await setup({ mutate: (id, _spec, response) => id === "auth/foreign-project-token/lookup-token" ? { ...response, body: { users: [{ ...response.body.users[0], localId: "other-uid" }] } } : response });
  await ctx.session.prepareQuery();
  await assert.rejects(ctx.session.withForeignFixture(async () => assert.fail("subject forbidden")), /invalid fixture account readback/);
  assert.equal(ctx.counter.snapshot().mode, "recovery");
  await ctx.session.recoverOwnedAccounts();
  assert.equal(ctx.users.size, 0);
  for (const request of ctx.requests.filter((request) => request.path.endsWith(":delete"))) assert.notEqual(request.body.localId, "other-uid");
});

test("ownership journal failure stops after creation and exposes no callback secret", async () => {
  const ctx = await setup({ writeOwnership: async () => { throw new Error(passwords["user-a"]); } });
  await assert.rejects(ctx.session.prepareQuery(), (error) => error.message === "fixture journal uncertain");
  assert.equal(ctx.requests.length, 1);
  await assert.rejects(ctx.session.recoverOwnedAccounts(), /fixture journal uncertain/);
  assert.equal(ctx.requests.length, 1);
});

test("an uncertain account creation cannot be declared recovered from an empty ownership map", async () => {
  const ctx = await setup({ mutate: (id, _spec, response) => {
    if (id === "auth/user-a/create") throw new Error("private-refresh-secret");
    return response;
  } });
  await assert.rejects(ctx.session.prepareQuery(), /fixture request failed/);
  await assert.rejects(ctx.session.recoverOwnedAccounts(), /fixture creation unconfirmed/);
  assert.notEqual(ctx.session.snapshot().mode, "recovered");
  assert.equal(ctx.users.size, 1);
});

test("a wrong creation UID cannot authorize deleting that unowned UID", async () => {
  const ctx = await setup({ mutate: (id, _spec, response) => id === "auth/user-a/create" ? { ...response, body: { ...response.body, localId: "other-uid" } } : response });
  await assert.rejects(ctx.session.prepareQuery(), /invalid fixture creation receipt/);
  await assert.rejects(ctx.session.recoverOwnedAccounts(), /fixture creation unconfirmed/);
  assert.ok(!ctx.requests.some((request) => request.path.endsWith(":delete")));
});

test("proof journal failure blocks all later subject access", async () => {
  const ctx = await setup({ writeProof: async () => { throw new Error("private-refresh-secret"); } });
  await assert.rejects(ctx.session.prepareQuery(), (error) => error.message === "fixture journal uncertain");
  assert.throws(() => ctx.session.token("user-a"), /fixture session unavailable/);
  await assert.rejects(ctx.session.recoverOwnedAccounts(), /fixture journal uncertain/);
});

test("a subject transport failure deletes the foreign account in recovery before rethrowing", async () => {
  const ctx = await setup();
  await ctx.session.prepareQuery();
  await assert.rejects(ctx.session.withForeignFixture(async () => ctx.counter.send("foreign/subject", async () => { throw new Error("private-refresh-secret"); })), (error) => error.message === "fixture subject failed");
  assert.ok(!ctx.users.has("fireemu-oracle-idp/foreign-captured-uid"));
  assert.equal(ctx.counter.snapshot().mode, "recovery");
  // The cleanup that runs in recovery uses the recovery IDs, never the normal cleanup IDs that were never spent.
  const sent = ctx.events.filter(([kind]) => kind === "transport").map(([, id]) => id);
  assert.ok(sent.includes("recovery/auth/foreign-project-token/delete") && sent.includes("recovery/auth/foreign-project-token/absence"));
  assert.equal(sent.includes("auth/foreign-project-token/delete"), false);
  assert.equal(sent.includes("auth/foreign-project-token/absence"), false);
  await ctx.session.recoverOwnedAccounts();
});

for (const succeeds of [false, true]) {
  test(`foreign cleanup uses the protected reserve when its subject ${succeeds ? "uses the last normal request" : "is refused at the normal cap"}`, async () => {
    let entered;
    let resume;
    const paused = new Promise((resolve) => { entered = resolve; });
    const resumed = new Promise((resolve) => { resume = resolve; });
    const ctx = await setup({ writeProof: async (proof) => { if (proof.principal === "foreign-project-token") { entered(); await resumed; } } });
    await ctx.session.prepareQuery();
    const foreign = ctx.session.withForeignFixture(async () => ctx.counter.send("foreign/subject", async () => "subject-result"));
    await paused;
    const target = ctx.counter.snapshot().normalCap - (succeeds ? 1 : 0);
    for (let i = 0; ctx.counter.snapshot().normal < target; i++) await ctx.counter.send(`budget/fill-${i}`, async () => true);
    resume();
    if (succeeds) assert.equal(await foreign, "subject-result");
    else await assert.rejects(foreign, /fixture subject failed/);
    assert.ok(!ctx.users.has("fireemu-oracle-idp/foreign-captured-uid"));
    assert.equal(ctx.counter.snapshot().mode, "recovery");
    assert.equal(ctx.counter.snapshot().recovery, 2);
    await ctx.session.recoverOwnedAccounts();
    assert.equal(ctx.users.size, 0);
  });
}

test("query cleanup uses the protected reserve after normal requests are exhausted", async () => {
  const ctx = await setup();
  await ctx.session.prepareQuery();
  for (let i = 0; ctx.counter.snapshot().normal < ctx.counter.snapshot().normalCap; i++) await ctx.counter.send(`budget/fill-${i}`, async () => true);
  await ctx.session.cleanupQuery();
  assert.equal(ctx.counter.snapshot().recovery, 6);
  assert.equal(ctx.users.size, 0);
  assert.equal(ctx.session.snapshot().mode, "closed");
});

test("a shared-counter failure blocks new foreign fixtures and query token access", async () => {
  const ctx = await setup();
  await ctx.session.prepareQuery();
  await assert.rejects(ctx.counter.send("query/subject", async () => { throw new Error("failed query subject"); }));
  const before = ctx.requests.length;
  assert.throws(() => ctx.session.token("user-a"), /fixture session unavailable/);
  await assert.rejects(ctx.session.withForeignFixture(async () => assert.fail("new subject forbidden")), /fixture session unavailable/);
  assert.equal(ctx.requests.length, before);
  await ctx.session.recoverOwnedAccounts();
});

test("external reservation journal failure blocks tokens and all later fixture HTTP", async () => {
  const ctx = await setup({ reserveFailureId: "query/subject" });
  await ctx.session.prepareQuery();
  await assert.rejects(ctx.counter.send("query/subject", async () => assert.fail("unreserved transport forbidden")));
  assert.equal(ctx.counter.snapshot().mode, "journal-uncertain");
  const before = ctx.requests.length;
  assert.throws(() => ctx.session.token("user-a"), /fixture session unavailable/);
  await assert.rejects(ctx.session.withForeignFixture(async () => assert.fail("new subject forbidden")), /fixture session unavailable/);
  await assert.rejects(ctx.session.recoverOwnedAccounts(), /fixture counter unavailable/);
  assert.equal(ctx.requests.length, before);
});

test("query preparation cannot begin before shared-counter admission", async () => {
  const ctx = await setup({ admitCounter: false });
  await assert.rejects(ctx.session.prepareQuery(), /fixture session unavailable/);
  assert.equal(ctx.requests.length, 0);
});

for (const [principal, expectedRequests] of [["user-a", 5], ["revoked-token", 18]]) {
  test(`counter failure during ${principal} proof stops query preparation before any new normal request`, async () => {
    let entered;
    let resume;
    const paused = new Promise((resolve) => { entered = resolve; });
    const resumed = new Promise((resolve) => { resume = resolve; });
    const ctx = await setup({ writeProof: async (proof) => { if (proof.principal === principal) { entered(); await resumed; } } });
    const preparing = ctx.session.prepareQuery();
    await paused;
    await assert.rejects(ctx.counter.send("query/failure", async () => { throw new Error("failed query subject"); }));
    resume();
    await assert.rejects(preparing, /fixture session unavailable/);
    assert.equal(ctx.requests.length, expectedRequests);
    await ctx.session.recoverOwnedAccounts();
    assert.equal(ctx.users.size, 0);
  });
}

test("counter failure during ownership journal stops before the initial account lookup", async () => {
  let entered;
  let resume;
  const paused = new Promise((resolve) => { entered = resolve; });
  const resumed = new Promise((resolve) => { resume = resolve; });
  const ctx = await setup({ writeOwnership: async () => { entered(); await resumed; } });
  const preparing = ctx.session.prepareQuery();
  await paused;
  await assert.rejects(ctx.counter.send("query/failure", async () => { throw new Error("failed query subject"); }));
  resume();
  await assert.rejects(preparing, /fixture session unavailable/);
  assert.equal(ctx.requests.length, 1);
  await ctx.session.recoverOwnedAccounts();
});

test("counter failure during a foreign proof forbids its new subject and permits only owned cleanup", async () => {
  let entered;
  let resume;
  const paused = new Promise((resolve) => { entered = resolve; });
  const resumed = new Promise((resolve) => { resume = resolve; });
  const ctx = await setup({ writeProof: async (proof) => { if (proof.principal === "foreign-project-token") { entered(); await resumed; } } });
  await ctx.session.prepareQuery();
  let subjects = 0;
  const foreign = ctx.session.withForeignFixture(async () => { subjects++; });
  await paused;
  await assert.rejects(ctx.counter.send("query/failure", async () => { throw new Error("failed query subject"); }));
  resume();
  await assert.rejects(foreign, /fixture session unavailable/);
  assert.equal(subjects, 0);
  assert.equal(ctx.requests.length, 23);
  assert.ok(!ctx.users.has("fireemu-oracle-idp/foreign-captured-uid"));
  await ctx.session.recoverOwnedAccounts();
  assert.equal(ctx.users.size, 0);
});

test("foreign cleanup cannot remove query snapshots with the same project-local UID", async () => {
  const ctx = await setup({ foreignUid: `storage-rules-${runId}-user-a` });
  await ctx.session.prepareQuery();
  const tokenA = ctx.session.token("user-a");
  const tokenPlain = ctx.session.token("user-plain");
  await ctx.session.withForeignFixture(async () => {});
  assert.equal(ctx.session.token("user-a"), tokenA);
  assert.equal(ctx.session.token("user-plain"), tokenPlain);
  await ctx.session.cleanupQuery();
  assert.equal(ctx.users.size, 0);
});

for (const [expiry, keyExpiry, time, error] of [
  ["token", fixedNow + 10000, fixedNow + 3599, /invalid fixture time/],
  ["key snapshot", keySet.expiresAt, keySet.expiresAt, /invalid key snapshot/],
]) {
  test(`foreign ${expiry} expiry during proof persistence refuses the subject and confirms owned absence`, async () => {
    let entered;
    let resume;
    const paused = new Promise((resolve) => { entered = resolve; });
    const resumed = new Promise((resolve) => { resume = resolve; });
    const ctx = await setup({ keyExpiry, writeProof: async (proof) => { if (proof.principal === "foreign-project-token") { entered(); await resumed; } } });
    await ctx.session.prepareQuery();
    let subjects = 0;
    const foreign = ctx.session.withForeignFixture(async () => { subjects++; });
    await paused;
    ctx.advanceTime(time);
    resume();
    await assert.rejects(foreign, error);
    assert.equal(subjects, 0);
    assert.ok(!ctx.users.has("fireemu-oracle-idp/foreign-captured-uid"));
    assert.ok(ctx.cleanup.some((row) => row.account === "foreign-project-token" && row.absent));
    await ctx.session.recoverOwnedAccounts();
    assert.equal(ctx.users.size, 0);
  });
}

test("expiry during the final query proof cannot publish a prepared session", async () => {
  let entered;
  let resume;
  const paused = new Promise((resolve) => { entered = resolve; });
  const resumed = new Promise((resolve) => { resume = resolve; });
  const ctx = await setup({ writeProof: async (proof) => { if (proof.principal === "revoked-token") { entered(); await resumed; } } });
  const preparing = ctx.session.prepareQuery();
  await paused;
  ctx.advanceTime(keySet.expiresAt);
  resume();
  await assert.rejects(preparing, /invalid key snapshot/);
  assert.equal(ctx.session.snapshot().mode, "failed");
  await ctx.session.recoverOwnedAccounts();
  assert.equal(ctx.users.size, 0);
});

test("an uncertain foreign delete is not sent again", async () => {
  const ctx = await setup({ mutate: (id, spec, response, state) => {
    if (id === "auth/foreign-project-token/delete") {
      state.users.set(`fireemu-oracle-idp/${spec.body.localId}`, { localId: spec.body.localId, email: spec.body.localId });
      throw new Error("private-refresh-secret");
    }
    return response;
  } });
  await ctx.session.prepareQuery();
  await assert.rejects(ctx.session.withForeignFixture(async () => {}), /fixture request failed/);
  await assert.rejects(ctx.session.recoverOwnedAccounts(), /fixture cleanup unconfirmed/);
  assert.equal(ctx.requests.filter((request) => request.project === "fireemu-oracle-idp" && request.path.endsWith(":delete")).length, 1);
});

test("post-delete presence cannot produce a closed session", async () => {
  const ctx = await setup({ mutate: (id, _spec, response) => id === "auth/user-a/absence" ? { status: 200, body: { users: [{ localId: "still-present" }] } } : response });
  await ctx.session.prepareQuery();
  await assert.rejects(ctx.session.cleanupQuery(), /fixture cleanup unconfirmed/);
  assert.notEqual(ctx.session.snapshot().mode, "closed");
});

test("a fixture cannot be used before preparation or after cleanup", async () => {
  const ctx = await setup();
  assert.throws(() => ctx.session.token("user-a"), /fixture session unavailable/);
  await ctx.session.prepareQuery();
  await ctx.session.cleanupQuery();
  assert.throws(() => ctx.session.token("user-a"), /fixture session unavailable/);
});

test("concurrent preparation cannot send a second account request", async () => {
  let unblock;
  const pending = new Promise((resolve) => { unblock = resolve; });
  const ctx = await setup({ writeOwnership: async () => pending });
  const preparing = ctx.session.prepareQuery();
  await new Promise((resolve) => setImmediate(resolve));
  await assert.rejects(ctx.session.prepareQuery(), /fixture session busy/);
  assert.equal(ctx.requests.length, 1);
  unblock();
  await preparing;
  await ctx.session.cleanupQuery();
});

// The idp foreign-project fixture (baseline lookup, sign-up, lookup by token, delete, absence) against the shapes the Auth lanes recorded on the Identity Platform sandbox
// (conformance/auth-account-production.json): the absence answer (`auth-account/admin/batch-delete`, step `lookup-after-force`), the sign-up answer
// (`auth-account/client/delete-effects`, step `sign-up`), a password user's lookup (any recorded lookup of a user with an email, a password hash and provider info, and no custom claims) and the delete answer
// (`auth-account/admin/delete`, step `delete`). Placeholders are replaced by the run's own values; every other key is the recorded one.
test("the foreign-project fixture accepts the answers production recorded for sign-up, lookup, delete and absence", async () => {
  const recorded = JSON.parse(readFileSync(new URL("../auth-account-production.json", import.meta.url)));
  const step = (program, name) => recorded.programs[program]?.steps?.[name]?.body ?? assert.fail(`${program} ${name}`);
  const absent = step("auth-account/admin/batch-delete", "lookup-after-force");
  const signUp = step("auth-account/client/delete-effects", "sign-up");
  const deleted = step("auth-account/admin/delete", "delete");
  const passwordUser = Object.values(recorded.programs).flatMap((program) => Object.values(program.steps ?? {})).map((entry) => entry.body?.users?.[0]).find((user) => user && typeof user.email === "string" && typeof user.passwordHash === "string" && Array.isArray(user.providerUserInfo) && !Object.hasOwn(user, "customAttributes") && !Object.hasOwn(user, "tenantId")) ?? assert.fail("no recorded password user");
  assert.deepEqual(absent, { kind: "identitytoolkit#GetAccountInfoResponse" });
  assert.equal(signUp.kind, "identitytoolkit#SignupNewUserResponse");
  assert.deepEqual(deleted, { kind: "identitytoolkit#DeleteAccountResponse" });
  assert.ok(!Object.hasOwn(passwordUser, "tenantId") && !Object.hasOwn(passwordUser, "customAttributes"));
  const mutate = (id, spec, response) => {
    const foreign = id.startsWith("auth/foreign-project-token/");
    if (!foreign) return response;
    if (id.endsWith("/baseline") || id.endsWith("/absence")) return { status: 200, body: structuredClone(absent) };
    if (id.endsWith("/sign-up")) return { status: 200, body: { ...structuredClone(signUp), idToken: response.body.idToken, email: response.body.email, refreshToken: response.body.refreshToken, localId: response.body.localId } };
    if (id.endsWith("/lookup-token")) return { status: 200, body: { kind: "identitytoolkit#GetAccountInfoResponse", users: response.body.users.map((user) => ({ ...structuredClone(passwordUser), localId: user.localId, email: user.email, emailVerified: false, validSince: user.validSince })) } };
    if (id.endsWith("/delete")) return { status: 200, body: structuredClone(deleted) };
    return response;
  };
  const ctx = await setup({ mutate });
  await ctx.session.prepareQuery();
  await ctx.session.withForeignFixture(async () => {});
  await ctx.session.cleanupQuery();
  assert.equal(ctx.users.size, 0);
  assert.equal(ctx.session.snapshot().mode, "closed");
  assert.equal(ctx.cleanup.length, 4);
  assert.deepEqual(ctx.requests.filter((request) => request.id.startsWith("auth/foreign-project-token/")).map((request) => request.id.split("/")[2]), ["baseline", "sign-up", "lookup-token", "delete", "absence"]);
});
