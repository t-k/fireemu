// Real rules-unit-testing SDK: every refused mutation must preserve the owner's data.
// Run under an owned fireemu exec with emulator profile and Hub discovery enabled.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { initializeTestEnvironment } from "@firebase/rules-unit-testing";

const projectId = process.env.GCLOUD_PROJECT;
assert.ok(projectId?.startsWith("demo-"), "an isolated demo project is required");
assert.ok(process.env.FIREBASE_EMULATOR_HUB, "owned Hub discovery is required");
const rules = await readFile(new URL("./rules-unit-testing.rules", import.meta.url), "utf8");
const environment = await initializeTestEnvironment({ projectId, firestore: { rules } });
const observations = [];
const bounded = async (promise) => {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("SDK operation timed out")), 10000);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
};

try {
  const owner = environment.authenticatedContext("alice").firestore().doc("notes/alice");
  const foreign = environment.authenticatedContext("bob").firestore().doc("notes/alice");
  const anonymous = environment.unauthenticatedContext().firestore().doc("notes/alice");
  const original = {
    body: "owner data",
    revision: 1,
    nested: { preserved: true },
    values: [1, "two"],
  };
  await bounded(owner.set(original));
  assert.deepEqual((await bounded(owner.get({ source: "server" }))).data(), original);
  for (const [principal, document] of [
    ["foreign", foreign],
    ["anonymous", anonymous],
  ]) {
    for (const operation of ["set", "update", "delete"]) {
      const before = (await bounded(owner.get({ source: "server" }))).data();
      await assert.rejects(
        bounded(
          operation === "delete"
            ? document.delete()
            : operation === "update"
              ? document.update({ body: "unauthorized", revision: 99 })
              : document.set({ body: "unauthorized" }),
        ),
        (error) => error.code === "permission-denied",
        `${principal} ${operation} must be refused`,
      );
      const after = (await bounded(owner.get({ source: "server" }))).data();
      assert.deepEqual(before, original, "baseline changed before refusal");
      assert.deepEqual(after, before, `${principal} ${operation} changed stored content`);
      observations.push({
        principal,
        operation,
        refusal: "permission-denied",
        ownerReadback: "unchanged",
      });
    }
  }
  await bounded(owner.update({ revision: 2 }));
  assert.deepEqual((await bounded(owner.get({ source: "server" }))).data(), {
    ...original,
    revision: 2,
  });
  await bounded(owner.delete());
  assert.equal((await bounded(owner.get({ source: "server" }))).exists, false);
  console.log(
    JSON.stringify(
      {
        status: "pass",
        productionExecuted: false,
        principalSource: "rules-unit-testing mock authenticated contexts",
        observations,
        ownerCleanup: "confirmed absent",
      },
      null,
      2,
    ),
  );
} finally {
  await environment.cleanup();
}
