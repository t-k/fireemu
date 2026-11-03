import "./storage-signed-put/test-preload.mjs";

// Closure of the signed XML PUT observation: the normalization of the two values that differ
// between recordings of the same production answer, and the replay of the recorded answers.

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { normalizeBody } from "./storage-signed-put/judge.mjs";

const digest = "7b9e0ce0c9b928551e3474cbab036cc2cd724aeaa8d45166ef240685e91640a7";

describe("normalizeBody masks what a production error derives from the request time", () => {
  it("masks the StringToSign digest, which hashes the canonical request including the date", () => {
    const body = `<Error><StringToSign>GOOG4-RSA-SHA256\n20261103T153459Z\n20261103/auto/storage/goog4_request\n${digest}</StringToSign></Error>`;
    const out = normalizeBody(body, []);
    assert.ok(!out.includes(digest));
    assert.match(out, /goog4_request\n<string-to-sign-digest><\/StringToSign>/);
    assert.match(out, /<date>/);
  });

  it("masks only a 64 hex digit digest at the end of StringToSign, nothing else that looks like one", () => {
    const other = `<Error><Details>${digest}</Details><StringToSign>a\nb\nc\nnot-a-digest</StringToSign><X>${digest}</X></Error>`;
    const out = normalizeBody(other, []);
    assert.equal(out.split(digest).length - 1, 2, "the digests outside StringToSign stay");
    assert.ok(out.includes("not-a-digest</StringToSign>"));
    const short = normalizeBody(`<StringToSign>x\n${digest.slice(1)}</StringToSign>`, []);
    assert.ok(short.includes(digest.slice(1)), "63 digits is not a digest");
    const upper = normalizeBody(`<StringToSign>x\n${digest.toUpperCase()}</StringToSign>`, []);
    assert.ok(upper.includes(digest.toUpperCase()), "the digest is lower case hex");
  });

  it("masks the expiry time an ExpiredToken names", () => {
    const body =
      "<Error><Code>ExpiredToken</Code><Details>The provided token has expired. Request signature expired at: 2026-11-03T15:35:12+00:00</Details></Error>";
    const out = normalizeBody(body, []);
    assert.ok(out.includes("expired at: <time></Details>"));
    assert.equal(
      normalizeBody("at 2026-11-03T15:35:12Z", []),
      "at 2026-11-03T15:35:12Z",
      "only the +00:00 form is masked",
    );
  });
});
