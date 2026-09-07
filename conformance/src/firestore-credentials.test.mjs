import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { credentialMetadata, selectCredential } from "./firestore-probe/credentials.mjs";

describe("Firestore probe credential selection", () => {
  const tokens = { ownerToken: "setup-secret", userToken: "user-secret" };

  it("keeps the legacy privileged default and explicit user credentials distinct", () => {
    assert.deepEqual(selectCredential({}, tokens), {
      kind: "owner",
      authorization: "Bearer setup-secret",
    });
    assert.deepEqual(selectCredential({ credential: "user" }, tokens), {
      kind: "user",
      authorization: "Bearer user-secret",
    });
  });

  it("fails closed when a requested user credential is missing", () => {
    for (const userToken of [undefined, "", "   "]) {
      assert.throws(
        () => selectCredential({ credential: "user" }, { ownerToken: "setup-secret", userToken }),
        /Missing Firestore probe user credential/,
      );
    }
  });

  it("supports explicit and legacy anonymous requests without owner fallback", () => {
    assert.deepEqual(selectCredential({ credential: "anonymous" }, tokens), {
      kind: "anonymous",
      authorization: null,
    });
    assert.deepEqual(selectCredential({ owner: false }, tokens), {
      kind: "anonymous",
      authorization: null,
    });
    assert.equal(selectCredential({ owner: false, credential: "user" }, tokens).kind, "user");
  });

  it("rejects unknown credential classes", () => {
    assert.throws(() => selectCredential({ credential: "admin" }, tokens), /Unsupported/);
  });

  it("records only the credential class", () => {
    for (const kind of ["owner", "user", "anonymous"]) {
      const metadata = credentialMetadata(selectCredential({ credential: kind }, tokens));
      assert.deepEqual(metadata, { kind });
      assert.doesNotMatch(JSON.stringify(metadata), /secret|Bearer|authorization/);
    }
  });
});
