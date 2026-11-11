import { test } from "node:test";
import assert from "node:assert/strict";
import { MASKED_NONCE, maskLocalRun, maskRecording } from "./kinds-mask.mjs";
import { KINDS_V2_SCENARIO } from "./kinds-scenario.mjs";
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

test("a recording of the v2 scenario is stamped against its own steps, ladder included", () => {
  const steps = KINDS_V2_SCENARIO.buildSteps(MASKED_NONCE);
  const rung = steps.find((s) => s.id === "k23");
  const leaf = { ...rung.body, run: nonce };
  const frame = {
    handler: "k9CreatedV2",
    generation: 2,
    seq: 1,
    event: {
      params: { group: "gq2", id: "q2" },
      data: {
        exists: true,
        key: "q2",
        value: { ...leaf, blob: { type: "string", length: rung.body.blob.length } },
      },
    },
  };
  // the first packet's steps know no such group: they refuse the frame
  assert.throws(() => mask([frame]), /belongs to no single write/);
  const result = mask([frame], { steps });
  assert.equal(result.frames[0].step, "k23");
  assert.equal(result.frames[0].event.data.value.run, MASKED_NONCE);
});

test("the answers of the run's writes come from the journal, a refusal with its body", () => {
  const journal = [
    {
      ts: "t",
      action: { step: "rules-install-put", method: "PUT", status: 200, outcome: "ok", bytes: 15 },
    },
    {
      ts: "t",
      action: {
        step: "k24",
        method: "PUT",
        url: `https://x/k9-rtdb/gq3/items/q3.json?auth=${nonce}`,
        status: 200,
        outcome: "ok",
        bytes: 1023947,
      },
    },
    {
      ts: "t",
      action: {
        step: "k25",
        method: "PUT",
        url: "https://x/k9-rtdb/gq4/items/q4.json",
        status: 400,
        outcome: "refused",
        bytes: 98,
        body: `{"error": "${uid} ${email}"}`,
      },
    },
    { ts: "t", action: "phase", detail: "cleanup" },
    { ts: "t" },
    { ts: "t", action: null },
  ]
    .map((row) => JSON.stringify(row))
    .join("\n");
  const result = mask([created], { journal });
  assert.deepEqual(
    result.answers.map((a) => [a.step, a.method, a.status, a.outcome, a.bytes]),
    [
      ["k24", "PUT", 200, "ok", 1023947],
      ["k25", "PUT", 400, "refused", 98],
    ],
  );
  assert.equal(result.answers[1].body, '{"error": "<uid> <email>"}');
  assert.equal(JSON.stringify(result).includes(nonce), false);
  assert.equal(mask([created]).answers.length, 0);
});

test("a local run is stamped the same way, its user identity masked by form", () => {
  const frame = structuredClone(created);
  frame.event.context.auth = { uid: "local-user-1", tokenKeys: ["k9role"] };
  frame.event.data.value.run = MASKED_NONCE;
  frame.event.context.authType = "USER";
  const second = {
    handler: "k9CreatedV2",
    generation: 2,
    seq: 2,
    event: {
      params: { group: "ga", id: "a1" },
      authType: "app_user",
      authId: "local-user-1",
      data: { exists: true, key: "a1", value: { value: 1, run: MASKED_NONCE } },
    },
  };
  const result = maskLocalRun({
    frames: [frame, second],
    steps: buildSteps(MASKED_NONCE),
    label: "strict",
  });
  assert.equal(result.recording.envelope, "strict");
  assert.equal(result.recording.nonce, MASKED_NONCE);
  assert.deepEqual(
    result.frames.map((f) => [f.n, f.step]),
    [
      [1, "k1"],
      [2, "k1"],
    ],
  );
  assert.equal(JSON.stringify(result).includes("local-user-1"), false);
  assert.equal(result.frames[0].event.context.auth.uid, "<uid>");
  assert.equal(result.frames[1].event.authId, "<uid>");
  assert.throws(
    () =>
      maskLocalRun({
        frames: [{ ...second, event: { ...second.event, params: { group: "zz", id: "a1" } } }],
        steps: buildSteps(MASKED_NONCE),
        label: "x",
      }),
    /belongs to no single write/,
  );
});

test("a local run may drop the frames of writes the recording never planned for, and says how many", () => {
  const frame = structuredClone(created);
  frame.event.data.value.run = MASKED_NONCE;
  const stray = structuredClone(frame);
  stray.event.context.params.id = "nobody";
  const steps = buildSteps(MASKED_NONCE);
  assert.throws(
    () => maskLocalRun({ frames: [frame, stray], steps, label: "x" }),
    /frame 2 belongs/,
  );
  const result = maskLocalRun({
    frames: [frame, stray],
    steps,
    label: "x",
    dropUnattributed: true,
  });
  assert.equal(result.frames.length, 1);
  assert.equal(result.recording.dropped, 1);
  assert.equal(result.recording.frames, 1);
  assert.equal(maskLocalRun({ frames: [frame], steps, label: "x" }).recording.dropped, 0);
});

test("a dropped frame leaves no gap in the numbering, and a uid only a 2nd gen event names is masked too", () => {
  const steps = buildSteps(MASKED_NONCE);
  const stray = structuredClone(created);
  stray.event.context.params.id = "nobody";
  const second = {
    handler: "k9CreatedV2",
    generation: 2,
    seq: 1,
    event: {
      params: { group: "ga", id: "a1" },
      authType: "app_user",
      authId: "only-second-gen",
      data: { exists: true, key: "a1", value: { value: 1, run: MASKED_NONCE } },
    },
  };
  const result = maskLocalRun({
    frames: [stray, second],
    steps,
    label: "x",
    dropUnattributed: true,
  });
  assert.deepEqual(
    result.frames.map((f) => f.n),
    [1],
  );
  assert.equal(JSON.stringify(result).includes("only-second-gen"), false);
  assert.equal(result.frames[0].event.authId, "<uid>");
});
