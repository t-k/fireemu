import assert from "node:assert/strict";
import { test } from "node:test";

import {
  makeWebChannelFormBody,
  projectWebChannelResponse,
  WEBCHANNEL_PATH,
} from "./webchannel-request-bytes.mjs";

test("fixed WebChannel request bodies bracket 10 MiB without a write", () => {
  assert.equal(
    WEBCHANNEL_PATH,
    "/google.firestore.v1.Firestore/Write/channel?database=projects%2Ffireemu-oracle-sbx%2Fdatabases%2F(default)&VER=8&RID=1&SID=missing-fireemu-byte-probe&AID=0",
  );
  for (const size of [10_485_760, 10_485_761]) {
    const body = makeWebChannelFormBody(size);
    assert.equal(Buffer.byteLength(body), size);
    assert.ok(body.startsWith("count=0&pad="));
    assert.ok(!body.includes("req0___data__"));
  }
  assert.throws(() => makeWebChannelFormBody(1), /unsupported WebChannel byte target/);
});

test("WebChannel response projection keeps HTTP semantics without the sandbox identity", () => {
  assert.deepEqual(
    projectWebChannelResponse(
      400,
      "Unknown SID for projects/fireemu-oracle-sbx/databases/(default)",
    ),
    {
      status: 400,
      code: "WEBCHANNEL_HTTP",
      message: "Unknown SID for projects/demo-firestore-probe/databases/(default)",
    },
  );
  assert.deepEqual(projectWebChannelResponse(200, "4\nnoop"), {
    status: 200,
    code: "OK",
    body: "4\nnoop",
  });
});
