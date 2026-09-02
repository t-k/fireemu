import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { test } from "node:test";

const require = createRequire(import.meta.url);
const { bearerToken, tokenMatches } = require("../functions/conditional-lock-auth.js");

test("the conditional lock probe requires an exact bearer credential", () => {
  const token = "0123456789abcdef0123456789abcdef";
  assert.equal(bearerToken(`Bearer ${token}`), token);
  assert.equal(bearerToken(`bearer ${token}`), null);
  assert.equal(bearerToken("Bearer short"), null);
  assert.equal(bearerToken(undefined), null);
  assert.equal(tokenMatches(token, token), true);
  assert.equal(tokenMatches(token, "fedcba9876543210fedcba9876543210"), false);
  assert.equal(tokenMatches(token, "not-a-token"), false);
});
