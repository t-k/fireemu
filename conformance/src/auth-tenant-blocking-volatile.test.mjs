// Values production draws anew on every answer, masked where a fixture is written and where
// fireemu's rows are compared with it (recording 2026-09-27: four createAuthUri rows differed
// only in these).

import assert from "node:assert/strict";
import { test } from "node:test";

import { assertNoVolatileValue, maskVolatile } from "./auth-tenant-blocking/volatile.mjs";

const AUTH_URI =
  "https://accounts.google.com/o/oauth2/v2/auth?response_type=id_token&client_id=atb-client&redirect_uri=http://localhost&state=AMbdmDlKSnqwftTzgUGr1JZF&scope=openid%20email%20profile&nonce=98fec5f5dbd7aa";

test("createAuthUri's session handle and the authUri's state and nonce are masked", () => {
  const recorded = {
    status: 200,
    body: {
      kind: "identitytoolkit#CreateAuthUriResponse",
      authUri: AUTH_URI,
      sessionId: "Bq2wwrp0Sc0zxvkG7APC_VGFCRE",
      registered: true,
    },
  };
  assert.deepEqual(maskVolatile(recorded), {
    status: 200,
    body: {
      kind: "identitytoolkit#CreateAuthUriResponse",
      authUri:
        "https://accounts.google.com/o/oauth2/v2/auth?response_type=id_token&client_id=atb-client&redirect_uri=http://localhost&state=<state>&scope=openid%20email%20profile&nonce=<nonce>",
      sessionId: "<sessionId>",
      registered: true,
    },
  });
  // Nested anywhere, in arrays too; other members and the input are left as they are.
  const nested = { steps: { a: recorded }, list: [{ sessionId: "x" }], sessionIdLike: "kept" };
  const masked = maskVolatile(nested);
  assert.equal(masked.steps.a.body.sessionId, "<sessionId>");
  assert.equal(masked.list[0].sessionId, "<sessionId>");
  assert.equal(masked.sessionIdLike, "kept");
  assert.equal(recorded.body.sessionId, "Bq2wwrp0Sc0zxvkG7APC_VGFCRE");
  // An authUri without state or nonce, and a non-string member, are unchanged.
  const plain = "https://example.com/auth?client_id=c";
  assert.equal(maskVolatile({ authUri: plain }).authUri, plain);
  assert.deepEqual(maskVolatile({ sessionId: 5 }), { sessionId: 5 });
  assert.equal(maskVolatile(undefined), undefined);
  // A state value that is not the last parameter, and one that is.
  assert.equal(
    maskVolatile({ authUri: "https://x/?state=abc" }).authUri,
    "https://x/?state=<state>",
  );
  assert.equal(
    maskVolatile({ authUri: "https://x/?a=1&state=abc&b=2" }).authUri,
    "https://x/?a=1&state=<state>&b=2",
  );
});

test("a fixture text with an unmasked volatile value is refused", () => {
  assert.doesNotThrow(() =>
    assertNoVolatileValue(JSON.stringify(maskVolatile({ sessionId: "abc", authUri: AUTH_URI }))),
  );
  assert.throws(() => assertNoVolatileValue('{"sessionId": "abc"}'), /sessionId/);
  assert.throws(() => assertNoVolatileValue(JSON.stringify({ authUri: AUTH_URI })), /authUri/);
});
