import assert from "node:assert/strict";
import { test } from "node:test";
import { buildAuthCorpus } from "./storage-object/auth-corpus.mjs";
import { createLocalStorageSender } from "./storage-object/sender.mjs";
import { buildStage3DraftPlan } from "./storage-object/stage3-plan.mjs";

const now = 1_800_000_000_000;
const rulesSource =
  "rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n    match /storage-object/{run}/{allPaths=**} {\n      allow read, write: if request.auth != null && request.auth.token.email == 'storage-object@example.com';\n    }\n  }\n}\n";
function fixture({
  existing = false,
  lookupMismatch = false,
  failSignup = false,
  failJournal = false,
  rulesChanged = false,
  expireDuringWireJournal = false,
} = {}) {
  const projectId = "example-project",
    bucket = "example.appspot.com",
    runId = "recordone";
  const plan = buildStage3DraftPlan({ projectId, bucket, runIds: [runId, "recordtwo"] });
  const recipe = buildAuthCorpus({ projectId, bucket, runId }).recipes[0];
  const users = new Map(),
    sent = [],
    journal = [],
    reservations = [];
  let clock = now;
  const token = (uid, email) =>
    [
      Buffer.from(JSON.stringify({ alg: "RS256" })).toString("base64url"),
      Buffer.from(
        JSON.stringify({
          sub: uid,
          user_id: uid,
          aud: projectId,
          iss: `https://securetoken.google.com/${projectId}`,
          email,
          iat: now / 1000,
          exp: now / 1000 + 3600,
        }),
      ).toString("base64url"),
      "private_signature",
    ].join(".");
  const sender = createLocalStorageSender({
    plan,
    origin: "http://127.0.0.1:9199",
    authOrigin: "http://127.0.0.1:9099",
    localControl: { origin: "http://127.0.0.1:9198", token: "synthetic-control-token" },
    localAuth: {
      apiKey: "storage-object-local-key",
      password: "synthetic-local-password",
      now: () => clock,
    },
    credentials: { admin: "Bearer owner" },
    onStart: async () => {},
    onReserve: async (row) => reservations.push(row),
    onJournal: async (row) => {
      if (failJournal && row.accountMutation === "create") throw new Error("journal unavailable");
      journal.push(row);
      if (expireDuringWireJournal && row.credentialProof) clock = now + 3_600_000;
    },
    fetchImpl: async (href, init) => {
      const url = new URL(href),
        body = init.body ? JSON.parse(init.body) : null;
      sent.push({ url, init, body });
      if (url.port === "9198")
        return Response.json({
          loaded: true,
          targeted: false,
          source: rulesChanged ? "changed" : rulesSource,
        });
      if (url.port === "9199") return Response.json({ items: [] });
      assert.equal(init.headers["content-type"], "application/json");
      if (url.pathname.endsWith("accounts:signUp")) {
        assert.equal(init.headers.authorization, undefined);
        assert.equal(url.searchParams.get("key"), "storage-object-local-key");
        if (failSignup) throw new Error(`uncertain request ${href}`);
        const uid = `owned-user-${users.size}`;
        users.set(body.email, { localId: uid, email: body.email });
        return Response.json({
          localId: uid,
          email: body.email,
          idToken: token(uid, body.email),
          expiresIn: "3600",
          refreshToken: "private_refresh",
        });
      }
      if (url.pathname.includes("/projects/")) {
        assert.equal(init.headers.authorization, "Bearer owner");
        assert.equal(body.targetProjectId, projectId);
        if (url.pathname.endsWith("accounts:delete")) {
          const found = [...users].find(([, row]) => row.localId === body.localId);
          assert.ok(found);
          users.delete(found[0]);
          return Response.json({ kind: "identitytoolkit#DeleteAccountResponse" });
        }
        const user = users.get(body.email[0]);
        return Response.json({
          kind: "identitytoolkit#GetAccountInfoResponse",
          ...(user
            ? { users: [user] }
            : existing
              ? { users: [{ localId: "foreign-user", email: body.email[0] }] }
              : {}),
        });
      }
      assert.ok(body.idToken);
      const payload = JSON.parse(Buffer.from(body.idToken.split(".")[1], "base64url"));
      return Response.json({
        users: [{ localId: lookupMismatch ? "foreign-user" : payload.sub, email: payload.email }],
      });
    },
  });
  return {
    sender,
    recipe,
    sent,
    journal,
    reservations,
    users,
    expire: () => {
      clock = now + 3_600_000;
    },
  };
}

test("local account requests share the Storage counter and delete only receipt-bound owned UIDs", async () => {
  const run = fixture();
  await run.sender.start();
  await run.sender.admitNamespace();
  for (const [stepIndex] of run.recipe.accountSetup.entries())
    await run.sender.sendAuthStep({ recipe: run.recipe, stepIndex });
  assert.equal(run.users.size, 2);
  assert.equal(run.sender.snapshot().total, run.reservations.length);
  assert.equal(run.sender.unresolved().length, 2);
  run.sender.beginCleanup();
  for (const [cleanupIndex] of run.recipe.accountCleanup.entries())
    await run.sender.sendAuthStep({ recipe: run.recipe, cleanupIndex });
  assert.equal(run.users.size, 0);
  assert.deepEqual(run.sender.unresolved(), []);
  assert.equal(run.sender.snapshot().total, 11);
  assert.equal(run.journal.filter((row) => row.accountMutation === "create").length, 2);
  assert.equal(JSON.stringify(run.journal).includes("private_signature"), false);
  assert.equal(JSON.stringify(run.journal).includes("private_refresh"), false);
});

test("an existing account cannot be created or deleted by the recipe", async () => {
  const run = fixture({ existing: true });
  await run.sender.start();
  await run.sender.admitNamespace();
  await assert.rejects(run.sender.sendAuthStep({ recipe: run.recipe, stepIndex: 0 }));
  await assert.rejects(run.sender.sendAuthStep({ recipe: run.recipe, stepIndex: 1 }));
  run.sender.beginCleanup();
  await assert.rejects(run.sender.sendAuthStep({ recipe: run.recipe, cleanupIndex: 2 }));
  assert.equal(run.sent.length, 2);
  assert.equal(run.users.size, 0);
});

test("a failed token lookup retains the signup-owned UID for cleanup", async () => {
  const run = fixture({ lookupMismatch: true });
  await run.sender.start();
  await run.sender.admitNamespace();
  await run.sender.sendAuthStep({ recipe: run.recipe, stepIndex: 0 });
  await run.sender.sendAuthStep({ recipe: run.recipe, stepIndex: 1 });
  await assert.rejects(run.sender.sendAuthStep({ recipe: run.recipe, stepIndex: 2 }));
  assert.equal(run.sender.unresolved().length, 1);
  run.sender.beginCleanup();
  await run.sender.sendAuthStep({ recipe: run.recipe, cleanupIndex: 2 });
  await run.sender.sendAuthStep({ recipe: run.recipe, cleanupIndex: 3 });
  assert.equal(run.users.size, 0);
  assert.deepEqual(run.sender.unresolved(), []);
});

test("an uncertain signup keeps responsibility without authorizing an email-based delete", async () => {
  const run = fixture({ failSignup: true });
  await run.sender.start();
  await run.sender.admitNamespace();
  await run.sender.sendAuthStep({ recipe: run.recipe, stepIndex: 0 });
  await assert.rejects(run.sender.sendAuthStep({ recipe: run.recipe, stepIndex: 1 }));
  run.sender.beginCleanup();
  await assert.rejects(run.sender.sendAuthStep({ recipe: run.recipe, cleanupIndex: 2 }));
  assert.equal(run.sender.unresolved().length, 1);
  assert.equal(run.sent.filter((row) => row.url.pathname.endsWith("accounts:delete")).length, 0);
});

test("a failed account journal prevents signup transport", async () => {
  const run = fixture({ failJournal: true });
  await run.sender.start();
  await run.sender.admitNamespace();
  await run.sender.sendAuthStep({ recipe: run.recipe, stepIndex: 0 });
  await assert.rejects(run.sender.sendAuthStep({ recipe: run.recipe, stepIndex: 1 }));
  assert.equal(run.sent.length, 2);
  assert.deepEqual(run.sender.unresolved(), []);
});

test("changed declarations cannot dispatch credentials or another UID", async () => {
  const run = fixture();
  await run.sender.start();
  await run.sender.admitNamespace();
  const changed = structuredClone(run.recipe);
  changed.accountSetup[1].path = "/v1/accounts:update";
  await assert.rejects(run.sender.sendAuthStep({ recipe: changed, stepIndex: 1 }));
  assert.equal(run.sent.length, 1);
});

test("an issued verified token supplies the actual Firebase wire header only under fixed Rules", async () => {
  const run = fixture();
  await run.sender.start();
  await run.sender.admitNamespace();
  for (const [stepIndex] of run.recipe.accountSetup.entries())
    await run.sender.sendAuthStep({ recipe: run.recipe, stepIndex });
  await assert.rejects(run.sender.sendAuthSubject({ recipe: run.recipe, probeIndex: 6 }));
  await run.sender.verifyLocalAuthRules();
  await run.sender.sendAuthSubject({ recipe: run.recipe, probeIndex: 6 });
  const header = run.sent.at(-1).init.headers.authorization;
  assert.match(header, /^Firebase [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  assert.equal(run.journal.at(-1).credentialProof.wireScheme, "Firebase");
  assert.equal(JSON.stringify(run.journal).includes(header.slice(9)), false);
  const total = run.sent.length;
  run.expire();
  await assert.rejects(run.sender.sendAuthSubject({ recipe: run.recipe, probeIndex: 4 }));
  assert.equal(run.sent.length, total);
  assert.equal(run.sender.snapshot().total, run.reservations.length);
});

test("a changed loaded Rules body cannot admit an Auth subject", async () => {
  const run = fixture({ rulesChanged: true });
  await run.sender.start();
  await run.sender.admitNamespace();
  await assert.rejects(run.sender.verifyLocalAuthRules());
  await assert.rejects(run.sender.sendAuthSubject({ recipe: run.recipe, probeIndex: 0 }));
  assert.equal(run.sent.length, 2);
});

test("expiry during durable wire journaling prevents the actual subject request", async () => {
  const run = fixture({ expireDuringWireJournal: true });
  await run.sender.start();
  await run.sender.admitNamespace();
  for (const [stepIndex] of run.recipe.accountSetup.entries())
    await run.sender.sendAuthStep({ recipe: run.recipe, stepIndex });
  await run.sender.verifyLocalAuthRules();
  const sent = run.sent.length;
  await assert.rejects(run.sender.sendAuthSubject({ recipe: run.recipe, probeIndex: 6 }));
  assert.equal(run.sent.length, sent);
  assert.equal(run.sender.unresolved().length, 2);
});
