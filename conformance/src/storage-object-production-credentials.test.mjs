import assert from "node:assert/strict";
import test from "node:test";

const module = await import("./storage-object/production-credentials.mjs").catch((error) => {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  return {};
});
const valid = "owned-account:recordone:authorization-errors:valid";
const competitor = "owned-account:recordone:authorization-errors:competitor";
const validate = (step, accountRefs = [valid, competitor]) => {
  assert.equal(
    typeof module.validateProductionCredentialDeclaration,
    "function",
    "production credential guard is missing",
  );
  return module.validateProductionCredentialDeclaration(step, { accountRefs });
};
const invalid = (step, refs) =>
  assert.throws(() => validate(step, refs), /^Error: explicit production credential is required$/);

test("owner and anonymous declarations are explicit and never default to an owner credential", () => {
  assert.deepEqual(validate({ credential: "admin" }), { credential: "admin" });
  assert.deepEqual(validate({ credential: "owner" }), { credential: "admin" });
  assert.deepEqual(validate({ credential: "none" }), { credential: "none" });
  assert.deepEqual(validate({ credentialRef: { kind: "anonymous" } }), { credential: "none" });
});

test("missing, inherited, conflicting and unknown declarations reject before a caller can dispatch", () => {
  for (const step of [
    {},
    { credential: undefined },
    { credential: null },
    { credential: "valid" },
    Object.create({ credential: "admin" }),
    { credential: "none", credentialRef: { kind: "anonymous" } },
    { credential: undefined, credentialRef: { kind: "valid", accountRef: valid } },
    { credentialRef: null },
    { credentialRef: {} },
    { credentialRef: { kind: "unknown" } },
  ])
    invalid(step);
});

test("Firebase references must match the declared account inventory and role", () => {
  for (const [kind, accountRef] of [
    ["valid", valid],
    ["competitor", competitor],
  ])
    assert.deepEqual(validate({ credentialRef: { kind, accountRef } }), {
      credentialRef: { kind, accountRef },
    });
  for (const ref of [
    { kind: "valid", accountRef: competitor },
    { kind: "competitor", accountRef: valid },
    { kind: "valid", accountRef: "owned-account:another:authorization-errors:valid" },
    { kind: "valid" },
    { kind: "valid", accountRef: valid, token: "RAW_SECRET" },
    { kind: "anonymous", accountRef: valid },
    { kind: "malformed", accountRef: valid },
  ])
    invalid({ credentialRef: ref });
  invalid({ credentialRef: { kind: "valid", accountRef: valid } }, []);
});

test("the malformed control stays an explicit reference and cannot smuggle a raw token", () => {
  assert.deepEqual(validate({ credentialRef: { kind: "malformed" } }), {
    credentialRef: { kind: "malformed" },
  });
  invalid({ credentialRef: { kind: "malformed", authorization: "Firebase RAW_SECRET" } });
});

test("a prefilled authorization header cannot override any declared credential", () => {
  for (const credential of ["none", "admin"])
    for (const name of ["authorization", "Authorization", "AUTHORIZATION"])
      invalid({ credential, headers: { [name]: "Bearer RAW_SECRET" } });
  assert.deepEqual(
    validate({ credential: "admin", headers: { "content-type": "application/json" } }),
    { credential: "admin" },
  );
});

test("returned declarations are immutable copies independent of later caller changes", () => {
  const step = { credentialRef: { kind: "valid", accountRef: valid } };
  const result = validate(step);
  step.credentialRef.accountRef = competitor;
  assert.equal(result.credentialRef.accountRef, valid);
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.credentialRef));
});

test("each declared value is read once so a changing property cannot promote anonymous access", () => {
  let reads = 0;
  const step = {};
  Object.defineProperty(step, "credential", {
    get() {
      return reads++ === 0 ? "none" : "admin";
    },
  });
  assert.deepEqual(validate(step), { credential: "none" });
  assert.equal(reads, 1);
});

test("invalid structures and throwing properties use a constant error without exposing credentials", () => {
  for (const step of [null, [], "RAW_SECRET", { credential: "admin", headers: [] }]) invalid(step);
  const step = {};
  Object.defineProperty(step, "credential", {
    get() {
      throw new Error("RAW_SECRET");
    },
  });
  invalid(step);
});
