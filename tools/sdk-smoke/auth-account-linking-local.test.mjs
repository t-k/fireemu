import assert from "node:assert/strict";
import { test } from "node:test";
import {
  REQUIRED_OPERATION_IDS,
  projectUser,
  validateReceipt,
} from "./auth-account-linking-local.mjs";

test("projects only stable account and provider fields", () => {
  assert.deepEqual(
    projectUser({
      uid: "u1",
      email: "A@example.test",
      providerData: [
        { providerId: "password", uid: "u1" },
        { providerId: "google.com", uid: "google-1" },
      ],
    }),
    {
      uid: "u1",
      email: "A@example.test",
      providers: [
        { providerId: "google.com", uid: "google-1" },
        { providerId: "password", uid: "u1" },
      ],
    },
  );
});

test("rejects incomplete or production-looking receipts", () => {
  assert.throws(
    () => validateReceipt({ status: "completed", productionExecuted: true }),
    /productionExecuted/,
  );
  assert.throws(
    () => validateReceipt({ status: "completed", productionExecuted: false }),
    /artifact|cleanup|comparison/,
  );
});

test("accepts a complete local receipt and preserves fixture boundary", () => {
  const receipt = validateReceipt({
    status: "completed",
    productionExecuted: false,
    transport: "real-fireemu-artifact",
    providerBoundary: "local-emulator-fixture",
    sourceCommit: "8b33aac4d",
    artifact: { path: "/tmp/fireemu", sha256: "a".repeat(64) },
    operations: REQUIRED_OPERATION_IDS.map((id) => ({ id })),
    cleanup: { ownedResources: 0, listenersClosed: true, processStopped: true },
    comparison: { contract: "auth-settings-v1", classifications: ["MATCH"] },
  });
  assert.equal(receipt.providerBoundary, "local-emulator-fixture");
});

test("the selected case requires the complete operation sequence", () => {
  assert.deepEqual(REQUIRED_OPERATION_IDS, [
    "signup-a",
    "signup-b",
    "same-provider-signin",
    "cross-provider-same-email-collision",
    "distinct-provider-link",
    "provider-unlink",
  ]);
});
