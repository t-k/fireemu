import assert from "node:assert/strict";
import test from "node:test";

import { TOKEN_LIFETIME_MS, createTokenSource } from "./functions-events/record/token.mjs";

const TOKEN_A = "ya29.synthetic-token-aaaaaaaaaaaaaaaaaaaa";
const TOKEN_B = "ya29.synthetic-token-bbbbbbbbbbbbbbbbbbbb";

test("the token comes from the command, is kept for 45 minutes, and is asked for again after that", async () => {
  let t = 0;
  const printed = [`${TOKEN_A}\n`, TOKEN_B];
  const calls = [];
  const source = createTokenSource({
    printToken: async () => {
      calls.push(t);
      return printed.shift();
    },
    now: () => t,
  });
  assert.equal(await source(), TOKEN_A);
  assert.equal(await source(), TOKEN_A);
  assert.equal(calls.length, 1);
  t += TOKEN_LIFETIME_MS - 1;
  assert.equal(await source(), TOKEN_A);
  t += 1;
  assert.equal(await source(), TOKEN_B);
  assert.equal(calls.length, 2);
  assert.ok(
    TOKEN_LIFETIME_MS < 50 * 60 * 1000,
    "a token is renewed before the 50 minutes the transport allows",
  );
});

test("output that is not an access token is refused, and a failing command fails the source", async () => {
  for (const output of [
    "",
    "ERROR: (gcloud.auth) Reauthentication required",
    "too short",
    `${TOKEN_A} ${TOKEN_B}`,
    undefined,
  ]) {
    const source = createTokenSource({ printToken: async () => output });
    await assert.rejects(source(), /did not print an access token/, String(output));
  }
  const failing = createTokenSource({
    printToken: async () => {
      throw new Error("gcloud exited 1");
    },
  });
  await assert.rejects(failing(), /gcloud exited 1/);
});

test("nothing in the source reads the credential file, the refresh token or the client secret", async () => {
  const { readFileSync } = await import("node:fs");
  for (const file of ["token.mjs", "main.mjs", "bin.mjs"]) {
    const text = readFileSync(
      new URL(`./functions-events/record/${file}`, import.meta.url),
      "utf8",
    );
    assert.ok(
      !/application_default_credentials|refresh_token|client_secret/.test(
        text.replace(/\/\/.*$/gm, ""),
      ),
      file,
    );
  }
});
