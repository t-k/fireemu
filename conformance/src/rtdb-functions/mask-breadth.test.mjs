import { test } from "node:test";
import assert from "node:assert/strict";
import { maskRecording } from "./mask-breadth.mjs";

test("removes uid, email and nonce from the complete output", () => {
  const nonce = "0123456789abcdef",
    uid = "uid-sentinel",
    email = "email-sentinel@example.test";
  const frame = {
    handler: "g9WrittenV1Retry",
    generation: 1,
    event: {
      context: { params: { group: "ga", id: "a1" }, auth: { uid, email } },
      data: {
        before: { exists: false, value: null },
        after: { exists: true, value: { value: 1, run: nonce } },
      },
    },
  };
  const files = {
    "result.json": JSON.stringify({ nonce }),
    "report.json": JSON.stringify({ steps: [] }),
    "frames.jsonl": JSON.stringify(frame),
  };
  const result = maskRecording({
    runDirectory: "run",
    uid,
    email,
    read: (p) => files[p.split("/").at(-1)],
  });
  const text = JSON.stringify(result);
  for (const secret of [nonce, uid, email]) assert.equal(text.includes(secret), false);
  assert.equal(result.frames[0].event.context.auth.uid, "<uid>");
});
