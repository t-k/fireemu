import assert from "node:assert/strict";
import test from "node:test";
import { scanFixtureText } from "./storage-object-compare/scan.mjs";

const refuses = (text, pattern, options) =>
  assert.throws(() => scanFixtureText(text, options), pattern);

test("masked text passes", () => {
  scanFixtureText(
    '{"name":"storage-object/<RUN>/a.bin","generation":"<GEN:1>","email":"user@example.com"}',
  );
  scanFixtureText('"Expires":"Mon, 01 Jan 1990 00:00:00 GMT"');
});

test("each credential shape is refused, with a reason that does not echo it", () => {
  const cases = [
    ["eyJhbGciOiJSUzI1NiJ9.x.y", /token \(JWT\)/],
    ["ya29.a0AfH6SMB", /OAuth access token/],
    ["AIzaSyD-synthetic-web-api-key-value-000000", /API key/],
    ["AMf-vBy", /refresh token/],
    ["upload_id=AP6rU81BlvOGz-fcTGYWUv7Mij3H11bx", /upload ID/],
    ["AP6rU81BlvOGz-fcTGYWUv7Mij3H11bx", /upload ID/],
    ["995cff2a-95bf-4bb5-90f8-0c0176c17e1f", /UUID/],
    ["key=sha256:0123456789abcdef0123", /hashed secret/],
  ];
  for (const [text, pattern] of cases)
    assert.throws(
      () => scanFixtureText(`x ${text} y`),
      (error) => pattern.test(error.message) && !error.message.includes(text),
      text,
    );
});

test("run-specific values that the masks should have removed are refused", () => {
  refuses("2026-09-30T23:14:41.570Z", /timestamp/);
  refuses("Wed, 30 Sep 2026 23:14:40 GMT", /HTTP date/);
  refuses("generation 1790810081541764", /generation/);
  refuses("project 592603257417 here", /12-digit number/);
  refuses("a 056c7ca3a8c6daa38e0a b", /run ID/, { runIds: ["056c7ca3a8c6daa38e0a"] });
  refuses("the real prod-bucket here", /private or unmasked/, { forbidden: ["prod-bucket"] });
  scanFixtureText("nothing private", { forbidden: ["", undefined] });
  scanFixtureText("a 056c7ca3a8c6daa38e0a b");
});

test("an upload ID placeholder is fine, and a number that is not 12 or 16 digits is fine", () => {
  scanFixtureText("upload_id=<UPLOAD_ID>&x=1");
  scanFixtureText(
    "11 digits 12345678901 and 13 digits 1234567890123 and 15 digits 123456789012345",
  );
});

test("an email must be in example.com", () => {
  scanFixtureText("someone@example.com");
  scanFixtureText('"@type":"type.googleapis.com/x"');
  refuses("someone@example.net", /email outside example\.com \(example\.net\)/);
  refuses('"entity":"user-person@company.co.jp"', /email outside/);
});

test("a SHA-256 or an inline base64 body is not mistaken for a number or an ID", () => {
  scanFixtureText(
    '"sha256":"123456789012a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c","base64":"MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMw=="',
  );
  scanFixtureText(
    '"a1b2c3d4e5f60718293a": "123456789012a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c"',
  );
  refuses('"x":"123456789012"', /12-digit/);
});
