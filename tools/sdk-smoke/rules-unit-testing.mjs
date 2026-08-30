// @firebase/rules-unit-testing against fireemu, with NO explicit hosts anywhere.
//
// This is the discovery contract in one script: the library reads GCLOUD_PROJECT and
// FIREBASE_EMULATOR_HUB out of the environment `fireemu exec` exported, asks the Emulator
// Hub `GET /emulators` for the running services, and connects to whatever it answers. If
// the Hub is missing, malformed, or reports a service that is not really there, nothing
// below runs at all -- which is exactly the failure a project would hit.
//
// Run it through the daemon (from the repository root):
//
//   fireemu exec --config tools/sdk-smoke/fireemu.rules-unit-testing.json \
//     --project demo-app --functions-port 0 --ui-port 0 --hub-port 4400 \
//     -- sh -c 'cd tools/sdk-smoke && node rules-unit-testing.mjs'

import {
  initializeTestEnvironment,
  assertFails,
  assertSucceeds,
  withFunctionTriggersDisabled,
} from "@firebase/rules-unit-testing";
import { initializeApp, deleteApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";

function check(label, condition) {
  if (!condition) throw new Error(`FAILED: ${label}`);
  console.log(`ok  ${label}`);
}

// The control API is fireemu's own; the smoke uses it only to wait for the functions
// runtime to go idle, which is what makes "no trigger ran" an assertion rather than a race.
const control = process.env.FIREEMU_CONTROL_URL;
const controlToken = process.env.FIREEMU_CONTROL_TOKEN;

async function awaitIdle() {
  const r = await fetch(`${control}sessions/default:awaitIdle`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${controlToken}`,
    },
    body: JSON.stringify({ timeoutSeconds: 20 }),
  });
  if (r.status !== 200) throw new Error(`awaitIdle: ${r.status} ${await r.text()}`);
}

async function main() {
  check(
    "the environment carries the hub and the project, and no explicit host",
    Boolean(process.env.FIREBASE_EMULATOR_HUB) && Boolean(process.env.GCLOUD_PROJECT),
  );
  check(
    "FIREBASE_EMULATOR_HUB is a bare host:port, as firebase-tools writes it",
    /^[^/]+:\d+$/.test(process.env.FIREBASE_EMULATOR_HUB),
  );

  // No projectId, no firestore.host, no firestore.port: everything is discovered.
  const env = await initializeTestEnvironment({});
  check("initializeTestEnvironment discovered the suite through the hub", true);

  // Two published divergences from the official emulator, both about the token
  // `authenticatedContext` mints through `@firebase/util`'s createMockUserToken:
  //
  //  - it defaults to `iat: 0`, so `exp` is 3600 -- a token that expired in 1970. fireemu
  //    verifies every ID token against its virtual clock, so the smoke states the issue
  //    time instead of relying on a token the daemon is right to reject;
  //  - its `sub` names a user that need not exist. fireemu resolves the subject against the
  //    project's Auth store, so the users the contexts stand for are created first.
  //
  // Both are recorded in README.md; a project moving from the official emulator has to do
  // the same two things until they are closed.
  const admin = initializeApp({ projectId: process.env.GCLOUD_PROJECT }, "rut-admin");
  for (const uid of ["alice", "bob"]) {
    await getAuth(admin)
      .createUser({ uid })
      .catch((e) => {
        if (e.code !== "auth/uid-already-exists") throw e;
      });
  }
  const iat = Math.floor(Date.now() / 1000);
  const alice = env.authenticatedContext("alice", { iat });
  const bob = env.authenticatedContext("bob", { iat });
  const anon = env.unauthenticatedContext();

  // --- the rules the daemon loaded are the ones being enforced -----------------------
  await assertSucceeds(alice.firestore().doc("notes/alice").set({ body: "mine" }));
  await assertFails(bob.firestore().doc("notes/alice").set({ body: "not mine" }));
  await assertFails(anon.firestore().doc("notes/alice").get());
  await assertFails(alice.firestore().doc("locked/x").get());
  check("authenticated and unauthenticated contexts get the expected decisions", true);

  // --- withSecurityRulesDisabled ------------------------------------------------------
  // The privileged context reaches what every rule denies, and only inside the callback.
  await env.withSecurityRulesDisabled(async (ctx) => {
    await ctx.firestore().doc("locked/x").set({ seeded: true });
    const snap = await ctx.firestore().doc("locked/x").get();
    check("withSecurityRulesDisabled wrote and read a document no rule allows", snap.exists);
  });
  await assertFails(alice.firestore().doc("locked/x").get());
  check("the privileged bypass did not leak into the ordinary contexts", true);

  // --- clearFirestore -----------------------------------------------------------------
  await env.clearFirestore();
  await env.withSecurityRulesDisabled(async (ctx) => {
    const notes = await ctx.firestore().collection("notes").get();
    const locked = await ctx.firestore().collection("locked").get();
    check("clearFirestore emptied every collection", notes.empty && locked.empty);
  });

  // --- a trigger-suppressed write -----------------------------------------------------
  // mirrorTodo (functions-project/index.js) mirrors every created todo. With background
  // triggers disabled the write lands and the trigger never runs; nothing is replayed when
  // they come back, which is the whole point of the switch for seeding data.
  await withFunctionTriggersDisabled(async () => {
    await assertSucceeds(alice.firestore().doc("todos/seeded").set({ title: "seeded" }));
    await awaitIdle();
    await env.withSecurityRulesDisabled(async (ctx) => {
      const mirror = await ctx.firestore().doc("mirror/seeded").get();
      check("a write made while triggers are disabled fired no trigger", !mirror.exists);
    });
  });

  // Re-enabling delivers nothing retroactively: the seeded todo stays unmirrored.
  await awaitIdle();
  await env.withSecurityRulesDisabled(async (ctx) => {
    const mirror = await ctx.firestore().doc("mirror/seeded").get();
    check("re-enabling triggers did not replay the suppressed write", !mirror.exists);
  });

  // A write after re-enabling does fire, so the switch turned the triggers back on rather
  // than leaving them off.
  await assertSucceeds(alice.firestore().doc("todos/live").set({ title: "live" }));
  await awaitIdle();
  await env.withSecurityRulesDisabled(async (ctx) => {
    const mirror = await ctx.firestore().doc("mirror/live").get();
    check("a write after re-enabling fired its trigger", mirror.exists);
    check(
      "the trigger saw the document it was given",
      mirror.data()?.title === "live",
    );
  });

  await env.cleanup();
  await deleteApp(admin);
  console.log("rules-unit-testing smoke: ok");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
