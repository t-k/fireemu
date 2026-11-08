import { test } from "node:test";
import assert from "node:assert/strict";
import { MASKED_NONCE, maskRecording } from "./kinds-mask.mjs";
import { buildSteps } from "./kinds-sequence.mjs";

const nonce = "0123456789abcdef";
const uid = "uid-sentinel";
const email = "email-sentinel@example.test";
function files(frames) {
  return {
    "result.json": JSON.stringify({ nonce }),
    "report.json": JSON.stringify({ steps: [{ id: "k1", note: nonce }] }),
    "frames.jsonl": frames.map((f) => JSON.stringify(f)).join("\n"),
  };
}
const created = {
  handler: "k9CreatedV1",
  generation: 1,
  seq: 1,
  event: {
    context: { params: { group: "ga", id: "a1" }, auth: { uid, email } },
    data: { exists: true, key: "a1", value: { value: 1, run: nonce } },
  },
};
const mask = (frames, extra = {}) =>
  maskRecording({
    runDirectory: "run",
    uid,
    email,
    envelope: "E",
    recordedOn: "2026-11-08",
    read: (p) => files(frames)[p.split("/").at(-1)],
    ...extra,
  });

test("removes uid, email and nonce from the complete output and stamps each frame with its write", () => {
  const result = mask([created]);
  const text = JSON.stringify(result);
  for (const secret of [nonce, uid, email]) assert.equal(text.includes(secret), false);
  assert.equal(result.kind, "rtdb-kinds-recording-v1");
  assert.equal(result.recording.nonce, MASKED_NONCE);
  assert.equal(result.recording.frames, 1);
  assert.equal(result.frames[0].step, "k1");
  assert.equal(result.frames[0].n, 1);
  assert.equal(result.frames[0].event.context.auth.uid, "<uid>");
  assert.equal(result.frames[0].event.data.value.run, MASKED_NONCE);
  // the plan's own steps, in the masked form, are the ones the frames were stamped against
  assert.equal(buildSteps(MASKED_NONCE)[0].body.run, MASKED_NONCE);
});

test("a frame that belongs to no single write stops the masking", () => {
  const stray = structuredClone(created);
  stray.event.context.params.id = "nobody";
  assert.throws(() => mask([stray]), /frame 1 belongs to no single write/);
});

test("the nonce, the uid and the email are required and checked", () => {
  assert.throws(() => mask([created], { nonce: "short" }), /16-hex nonce/);
  assert.throws(() => mask([created], { uid: undefined }), /uid and email are required/);
  assert.throws(() => mask([created], { email: "" }), /uid and email are required/);
  assert.equal(mask([created], { nonce }).recording.nonce, MASKED_NONCE);
});
