// The last check before a committed fixture is written (fixture-scan.mjs): what it refuses, and
// that it stays linear on the long word runs large documents produce. O-8A recorded documents of
// up to 950,000 characters, and the old email pattern took 33 minutes on them.

import assert from "node:assert/strict";
import { test } from "node:test";

import { hasEmail, scanFixture } from "./fs-query-index/fixture-scan.mjs";

/** The pattern fixture-scan.mjs used before it was made linear: the reference for short texts. */
const REFERENCE = /[\w.+-]+@[\w-]+(\.[\w-]+)+/;

/** A small seeded generator, so a failing property reproduces from its seed. */
function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

test("an email address is found, and text without one is not", () => {
  for (const text of [
    "a@b.c",
    "x a.b+c-d@e-f.g.h y",
    '{"v":"user@example.com"}',
    "no space\n@x.y but a@b.co",
    "_@_._",
    "a+@b.c",
    "a.@b.c",
    "a-@b.c",
    "a@b.c-",
  ]) {
    assert.equal(hasEmail(text), true, text);
  }
  for (const text of [
    "",
    "@",
    "@b.c",
    "a@",
    "a@b",
    "a@b.",
    "a@.c",
    "a @b.c",
    "a@ b.c",
    "a@b..c",
    "projects/p/documents/d",
    "é@b.c",
  ]) {
    assert.equal(hasEmail(text), false, text);
  }
});

test("property: the linear scan agrees with the pattern it replaces on short texts", () => {
  const alphabet = ["a", "b", "1", "_", ".", "+", "-", "@", " ", "\n", "é", '"'];
  for (let seed = 1; seed <= 4000; seed += 1) {
    const random = mulberry32(seed);
    const length = Math.floor(random() * 24);
    const text = Array.from(
      { length },
      () => alphabet[Math.floor(random() * alphabet.length)],
    ).join("");
    assert.equal(hasEmail(text), REFERENCE.test(text), `seed ${seed}: ${JSON.stringify(text)}`);
  }
});

test("the scan of a megabyte of one kind of character finishes at once", () => {
  const size = 1_000_000;
  for (const text of [
    "a".repeat(size),
    "a.".repeat(size / 2),
    `${"a".repeat(size)}@`,
    `@${"a".repeat(size)}`,
    `a@${"b".repeat(size)}`,
    `a@${"b-".repeat(size / 2)}`,
    "a@".repeat(size / 2),
    "a@b.".repeat(size / 4),
    "@.".repeat(size / 2),
  ]) {
    const started = performance.now();
    hasEmail(text);
    assert.ok(performance.now() - started < 1000, `${text.slice(0, 12)}: too slow`);
  }
  // The whole scan, over a fixture holding a 950,000-character word, as the O-8A rows do.
  const started = performance.now();
  scanFixture(JSON.stringify({ pad: "abcdefghij".repeat(95_000) }), ["private-value"]);
  assert.ok(performance.now() - started < 1000, "scanFixture is too slow");
});

test("scanFixture still refuses a token, a project number, an email and a private value", () => {
  assert.throws(() => scanFixture("ya29.abcdefghijklmnop", []), /access token/);
  assert.throws(() => scanFixture("projects/1234567", []), /numeric project name/);
  assert.throws(() => scanFixture("a@b.c", []), /email address/);
  assert.throws(() => scanFixture("xx secret-value yy", ["secret-value"]), /private value/);
  assert.throws(
    () => scanFixture(Buffer.from("secret-value").toString("base64"), ["secret-value"]),
    /private value/,
  );
  assert.doesNotThrow(() => scanFixture('{"v":"fine"}', ["secret-value", ""]));
});
