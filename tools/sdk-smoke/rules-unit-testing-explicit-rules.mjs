// @firebase/rules-unit-testing loads explicit Firestore and Storage rules through the
// emulators discovered from FIREBASE_EMULATOR_HUB. No service host or port is specified.

import { readFile } from "node:fs/promises";

import {
  assertFails,
  assertSucceeds,
  initializeTestEnvironment,
} from "@firebase/rules-unit-testing";

function check(label, condition) {
  if (!condition) throw new Error(`FAILED: ${label}`);
  console.log(`ok  ${label}`);
}

async function main() {
  check(
    "the environment carries the hub and the project",
    Boolean(process.env.FIREBASE_EMULATOR_HUB) && Boolean(process.env.GCLOUD_PROJECT),
  );
  const firestoreRules = await readFile(
    new URL("./rules-unit-testing.rules", import.meta.url),
    "utf8",
  );
  const storageRules = await readFile(
    new URL("./rules-unit-testing.storage.rules", import.meta.url),
    "utf8",
  );
  const env = await initializeTestEnvironment({
    firestore: { rules: firestoreRules },
    storage: { rules: storageRules },
  });

  try {
    const alice = env.authenticatedContext("alice");
    const bob = env.authenticatedContext("bob");
    const anon = env.unauthenticatedContext();

    await assertSucceeds(
      alice.firestore().doc("notes/alice").set({ body: "mine" }),
    );
    await assertFails(
      bob.firestore().doc("notes/alice").set({ body: "not mine" }),
    );
    await assertFails(anon.firestore().doc("notes/alice").get());
    check("Firestore enforces the dynamically loaded rules", true);

    await assertSucceeds(
      alice.storage().ref("users/alice/note.txt").putString("mine"),
    );
    await assertFails(
      bob.storage().ref("users/alice/not-bobs.txt").putString("not mine"),
    );
    await assertFails(
      anon.storage().ref("users/alice/anonymous.txt").putString("anonymous"),
    );
    check("Storage enforces the dynamically loaded rules", true);
  } finally {
    await env.cleanup();
  }

  console.log("rules-unit-testing explicit-rules smoke: ok");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
