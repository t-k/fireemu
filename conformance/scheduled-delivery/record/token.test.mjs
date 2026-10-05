// The token source: one command call at the start, again only when the token in use is 40 minutes old, never more
// than twice again, and a string that is not a token is refused.
import assert from "node:assert/strict";
import test from "node:test";
import { MAX_REFRESHES, TOKEN_LIFETIME_MS, createTokenSource } from "./token.mjs";

const source = (extra = {}) => {
  let clock = 0;
  let calls = 0;
  const get = createTokenSource({
    printToken: () => "token-number-" + ++calls + "\n",
    now: () => clock,
    ...extra,
  });
  return { get, calls: () => calls, at: (ms) => (clock = ms) };
};

test("the constants are 40 minutes and two refreshes", () => {
  assert.equal(TOKEN_LIFETIME_MS, 2_400_000);
  assert.equal(MAX_REFRESHES, 2);
});

test("a token is reused until it is 40 minutes old, then asked for again, at most twice again", async () => {
  const s = source();
  assert.equal(await s.get(), "token-number-1");
  s.at(TOKEN_LIFETIME_MS - 1);
  assert.equal(await s.get(), "token-number-1");
  assert.equal(s.calls(), 1);
  s.at(TOKEN_LIFETIME_MS);
  assert.equal(await s.get(), "token-number-2");
  s.at(TOKEN_LIFETIME_MS * 2 - 1);
  assert.equal(await s.get(), "token-number-2", "the age is counted from the new token");
  s.at(TOKEN_LIFETIME_MS * 2);
  assert.equal(await s.get(), "token-number-3");
  s.at(TOKEN_LIFETIME_MS * 10);
  assert.equal(await s.get(), "token-number-3", "no more than three calls in all");
  assert.equal(s.calls(), 3);
});

test("the first call is not counted as a refresh, and the clock may start anywhere", async () => {
  const s = source();
  s.at(10 ** 12);
  assert.equal(await s.get(), "token-number-1");
  s.at(10 ** 12 + TOKEN_LIFETIME_MS);
  assert.equal(await s.get(), "token-number-2");
});

test("a string that does not look like a token is refused", async () => {
  for (const bad of ["", "short", "has space in it 12345", "line\nbreak12345"]) {
    const get = createTokenSource({ printToken: () => bad });
    await assert.rejects(get(), /did not print an access token/, JSON.stringify(bad));
  }
  const get = createTokenSource({ printToken: async () => "  ya29.a0Af_-~+/=12345  \n" });
  assert.equal(await get(), "ya29.a0Af_-~+/=12345");
  const min = createTokenSource({ printToken: () => "12345678" });
  assert.equal(await min(), "12345678");
  const tooShort = createTokenSource({ printToken: () => "1234567" });
  await assert.rejects(tooShort(), /did not print/);
});

test("a refresh that fails leaves the token in use and is tried again on the next call", async () => {
  let n = 0;
  let clock = 0;
  const get = createTokenSource({
    printToken: () => {
      n++;
      if (n === 2) throw new Error("gcloud failed");
      return "token-number-" + n;
    },
    now: () => clock,
  });
  assert.equal(await get(), "token-number-1");
  clock = TOKEN_LIFETIME_MS;
  await assert.rejects(get(), /gcloud failed/);
  assert.equal(await get(), "token-number-3", "the failed attempt counted as a refresh");
});
