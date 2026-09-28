import assert from "node:assert/strict";
import { test } from "node:test";
import { seedTokenPresent } from "./storage-object/auth-replay.mjs";

test("empty Firebase token arrays remain an absent-token observation", () => {
  for (const tokens of [undefined, "", [], [""]])
    assert.equal(seedTokenPresent({ downloadTokens: tokens }, "firebase-storage"), false);
  for (const tokens of ["local-token", ["", "local-token"]])
    assert.equal(seedTokenPresent({ downloadTokens: tokens }, "firebase-storage"), true);
});

test("each seed API uses only its declared token field", () => {
  assert.equal(
    seedTokenPresent({ metadata: { firebaseStorageDownloadTokens: "local-token" } }, "gcs-json"),
    true,
  );
  assert.equal(seedTokenPresent({ downloadTokens: "local-token" }, "gcs-json"), false);
  assert.equal(
    seedTokenPresent(
      { metadata: { firebaseStorageDownloadTokens: "local-token" } },
      "firebase-storage",
    ),
    false,
  );
});

test("malformed token observations reject instead of producing an existence flag", () => {
  for (const tokens of [null, false, {}, [1], [null]])
    assert.throws(() => seedTokenPresent({ downloadTokens: tokens }, "firebase-storage"));
});
