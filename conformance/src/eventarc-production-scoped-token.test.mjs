import assert from "node:assert/strict";
import test from "node:test";
import { createScopedToken } from "./eventarc-production/scoped-token.mjs";

const SCOPE = "https://www.googleapis.com/auth/userinfo.email";

test("it asks gcloud for a token of exactly the scope, without a shell, and returns it", async () => {
  const calls = [];
  const scoped = createScopedToken({
    execFile: async (file, args, options) => {
      calls.push({ file, args, options });
      return "ya29.a-token-of-the-narrow-scope-0000\n";
    },
  });
  assert.equal(await scoped(SCOPE), "ya29.a-token-of-the-narrow-scope-0000");
  assert.deepEqual(calls[0].args, ["auth", "application-default", "print-access-token", `--scopes=${SCOPE}`]);
  assert.equal(calls[0].file, "gcloud");
  assert.equal(calls[0].options.timeout, 30_000);
});

test("a failure of gcloud, or output that is not a token, is no token and never carries the message", async () => {
  const failing = createScopedToken({
    execFile: async () => {
      throw new Error("ERROR: secret ya29.leak");
    },
  });
  assert.equal(await failing(SCOPE), null);
  for (const output of ["", "not a token", "ya29.short", `ya29.${"x".repeat(5000)}`, "a b c d e f g h i j k l m n o p q r s t"])
    assert.equal(await createScopedToken({ execFile: async () => output })(SCOPE), null, output.slice(0, 20));
});

test("a scope that is not a Google OAuth scope URL is refused before gcloud is run", async () => {
  const scoped = createScopedToken({ execFile: async () => assert.fail("run") });
  for (const scope of ["", "cloud-platform", "https://example.com/auth/x", `${SCOPE} extra`, `${SCOPE},other`, "--flag", `${SCOPE}\n`])
    await assert.rejects(() => scoped(scope), /not an OAuth scope/, scope);
});
