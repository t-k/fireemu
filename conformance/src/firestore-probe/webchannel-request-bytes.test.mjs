import assert from "node:assert/strict";
import { test } from "node:test";

import {
  makeWebChannelFormBody,
  makeWebChannelHandshakeBody,
  parseWebChannelOpening,
  projectWebChannelResponse,
  projectWebChannelSessionStep,
  WEBCHANNEL_PATH,
  webchannelSessionProgram,
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

const CHANNEL =
  "/google.firestore.v1.Firestore/Write/channel?database=projects%2Ffireemu-oracle-sbx%2Fdatabases%2F(default)&VER=8";
const SESSION = "SID={{handshake.sid}}&AID=0&gsessionid={{handshake.gsessionid}}";

test("a valid-session WebChannel program opens, checks, measures and closes one session", () => {
  for (const size of [
    11_534_336, 11_534_337, 12_582_912, 16_777_216, 16_777_217, 33_554_432, 33_554_433,
  ]) {
    assert.deepEqual(webchannelSessionProgram(size), {
      id: `writes/limits/webchannel-request-bytes/${size}`,
      area: "writes",
      steps: [
        {
          id: "handshake",
          method: "POST",
          path: `${CHANNEL}&RID=1&CVER=22&X-HTTP-Session-Id=gsessionid`,
          webchannelSession: "handshake",
        },
        {
          id: "control",
          method: "POST",
          path: `${CHANNEL}&RID=2&${SESSION}`,
          webchannelSession: "control",
          webchannelBodyBytes: 13,
        },
        {
          id: "boundary",
          method: "POST",
          path: `${CHANNEL}&RID=3&${SESSION}`,
          webchannelSession: "boundary",
          webchannelBodyBytes: size,
        },
        {
          id: "terminate",
          method: "GET",
          path: `${CHANNEL}&RID=4&${SESSION}&TYPE=terminate`,
          webchannelSession: "terminate",
        },
      ],
    });
  }
  assert.throws(() => webchannelSessionProgram(10_485_760), /unsupported WebChannel session size/);
  assert.throws(() => webchannelSessionProgram(33_554_434), /unsupported WebChannel session size/);
});

test("session bodies carry the database once and the size only in the pad value", () => {
  assert.equal(
    makeWebChannelHandshakeBody(),
    "count=1&ofs=0&req0___data__=%7B%22database%22%3A%22projects%2Ffireemu-oracle-sbx%2Fdatabases%2F%28default%29%22%7D",
  );
  assert.equal(Buffer.byteLength(makeWebChannelHandshakeBody()), 114);
  assert.equal(makeWebChannelFormBody(13), "count=0&pad=a");
  for (const size of [11_534_336, 11_534_337, 16_777_217, 33_554_433]) {
    const body = makeWebChannelFormBody(size);
    assert.equal(Buffer.byteLength(body), size);
    assert.match(body, /^count=0&pad=a+$/);
  }
  assert.throws(() => makeWebChannelFormBody(12), /unsupported WebChannel byte target/);
});

const frame = (value) => `${JSON.stringify(value).length}\n${JSON.stringify(value)}`;

test("the opening answer yields the SID and session header, which may coincide", () => {
  const opening = frame([[0, ["c", "SIDabcdefghijkl", "", 8, 14, 30000]]]);
  assert.deepEqual(parseWebChannelOpening(200, "gsess-1", opening), {
    sid: "SIDabcdefghijkl",
    gsessionid: "gsess-1",
  });
  // The emulator reuses the SID as the session header.
  assert.deepEqual(parseWebChannelOpening(200, "SIDabcdefghijkl", opening), {
    sid: "SIDabcdefghijkl",
    gsessionid: "SIDabcdefghijkl",
  });
  assert.equal(parseWebChannelOpening(400, "gsess-1", opening), null);
  assert.equal(parseWebChannelOpening(200, null, opening), null);
  assert.equal(parseWebChannelOpening(200, "bad header!", opening), null);
  assert.equal(parseWebChannelOpening(200, "gsess-1", opening.replace(/^\d+/, "3")), null);
  // Only the first chunk is read, by its declared length; a later chunk or entry does not hide
  // the SID, which the terminate step needs.
  assert.deepEqual(parseWebChannelOpening(200, "gsess-1", `${opening}12\n[[1,["noop"]]]`), {
    sid: "SIDabcdefghijkl",
    gsessionid: "gsess-1",
  });
  assert.deepEqual(
    parseWebChannelOpening(
      200,
      "gsess-1",
      frame([
        [0, ["c", "SIDabcdefghijkl", "", 8, 14, 30000]],
        [1, ["noop"]],
      ]),
    ),
    { sid: "SIDabcdefghijkl", gsessionid: "gsess-1" },
  );
  assert.equal(
    parseWebChannelOpening(200, "gsess-1", frame([[0, ["x", "SIDabcdefghijkl"]]])),
    null,
  );
  assert.equal(parseWebChannelOpening(200, "gsess-1", frame([[0, ["c", "short"]]])), null);
  assert.equal(parseWebChannelOpening(200, "gsess-1", "not framed"), null);
});

test("session steps are recorded by shape, never with the SID or session header", () => {
  const session = { sid: "SIDabcdefghijkl", gsessionid: "gsess-1" };
  assert.deepEqual(projectWebChannelSessionStep("handshake", 200, "anything", session), {
    status: 200,
    code: "OK",
    body: "session-opened",
  });
  assert.deepEqual(projectWebChannelSessionStep("handshake", 200, "SIDabcdefghijkl", null), {
    status: 200,
    code: "OK",
    body: "unparsed-opening",
  });
  for (const kind of ["control", "boundary"]) {
    assert.deepEqual(projectWebChannelSessionStep(kind, 200, frame([1, 0, 0]), session), {
      status: 200,
      code: "OK",
      body: "forward-ack",
    });
    assert.deepEqual(projectWebChannelSessionStep(kind, 200, frame([0, 3, 0]), session), {
      status: 200,
      code: "OK",
      body: "forward-ack",
    });
    // The third value counts bytes waiting on the back channel, which this probe never
    // opens, so production may report a non-zero value.
    for (const ack of [
      [0, 1, 57],
      [1, 3, 0],
    ]) {
      assert.deepEqual(
        projectWebChannelSessionStep(kind, 200, frame(ack), session).body,
        "forward-ack",
      );
    }
    for (const other of [
      [1, 0],
      [1, -1, 0],
      [1, 0, -3],
      [1, 0.5, 0],
      [2, 0, 0],
      [1, 0, 0, 0],
      ["1", 0, 0],
    ]) {
      assert.equal(
        projectWebChannelSessionStep(kind, 200, frame(other), session).body,
        "unexpected-forward-answer",
        JSON.stringify(other),
      );
    }
    assert.deepEqual(
      projectWebChannelSessionStep(kind, 200, `x ${session.sid} ${session.gsessionid}`, session),
      { status: 200, code: "OK", body: "unexpected-forward-answer" },
    );
  }
  assert.deepEqual(
    projectWebChannelSessionStep(
      "boundary",
      400,
      JSON.stringify({
        error: {
          code: 400,
          status: "INVALID_ARGUMENT",
          message: "Request payload size exceeds the limit: 11534336 bytes.",
        },
      }),
      session,
    ),
    {
      status: 400,
      code: "INVALID_ARGUMENT",
      message: "Request payload size exceeds the limit: 11534336 bytes.",
    },
  );
  const refusal = projectWebChannelSessionStep(
    "control",
    400,
    `Unknown SID ${session.sid} (${session.gsessionid}) for projects/fireemu-oracle-sbx/databases/(default)`,
    session,
  );
  assert.equal(refusal.code, "WEBCHANNEL_HTTP");
  assert.ok(!JSON.stringify(refusal).includes(session.sid));
  assert.ok(!JSON.stringify(refusal).includes(session.gsessionid));
  assert.ok(!JSON.stringify(refusal).includes("fireemu-oracle-sbx"));
  // The fixture freeze requires a body on every accepted row.
  assert.deepEqual(projectWebChannelSessionStep("terminate", 200, "ok", session), {
    status: 200,
    code: "OK",
    body: "session-terminated",
  });
  assert.throws(() => projectWebChannelSessionStep("other", 200, "", session), /session step/);
});

test("only undici's dropped-connection errors count as a reset, and only with a known phase", async () => {
  const { isDroppedConnection, projectWebChannelReset } =
    await import("./webchannel-request-bytes.mjs");
  assert.equal(isDroppedConnection(new TypeError("fetch failed")), true);
  assert.equal(isDroppedConnection(new TypeError("terminated")), true);
  assert.equal(isDroppedConnection(new Error("fetch failed")), false);
  assert.equal(isDroppedConnection(new Error("request cap reached before network send")), false);
  assert.equal(isDroppedConnection(new TypeError("Invalid URL")), false);
  assert.deepEqual(projectWebChannelReset("reset-before-response"), {
    status: 0,
    code: "connection-reset",
    message: "reset-before-response",
  });
  assert.throws(() => projectWebChannelReset("reset-anywhere"), /reset phase/);
});
