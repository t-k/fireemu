// Turns a kinds run directory into the committed fixture: the run's nonce, uid and email are replaced by
// fixed forms, and every frame is stamped with the one write it belongs to. A frame that fits no single
// write stops the masking: nothing unattributed is committed.

import { readFileSync, writeFileSync } from "node:fs";
import { buildSteps, matchFrame } from "./kinds-sequence.mjs";
import { KINDS_V2_SCENARIO } from "./kinds-scenario.mjs";
import { MASKED_NONCE } from "./mask-recording.mjs";
export { MASKED_NONCE };

/**
 * The answers of a run's writes as the journal logged them (`k<n>` steps only): method, status, outcome, the
 * answer's byte count and, for a refusal, its body. The url is not kept (it carries tokens and paths).
 */
function answersOf(journal) {
  return journal
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line).action)
    .filter((action) => action && typeof action === "object" && /^k\d+$/u.test(action.step))
    .map(({ step, method, status, outcome, bytes, body }) => ({
      step,
      method,
      status,
      outcome,
      bytes,
      ...(body === undefined ? {} : { body }),
    }));
}

export function maskRecording({
  runDirectory,
  uid,
  email,
  nonce: suppliedNonce,
  envelope,
  recordedOn,
  steps = buildSteps(MASKED_NONCE),
  journal,
  read = readFileSync,
}) {
  const json = (name) => JSON.parse(read(`${runDirectory}/${name}`, "utf8"));
  const result = json("result.json");
  const report = json("report.json");
  const nonce = suppliedNonce ?? result.nonce;
  if (!/^[0-9a-f]{16}$/u.test(nonce)) throw Error("the run has no 16-hex nonce");
  if (!uid || !email) throw Error("uid and email are required for masking");
  const mask = (text) =>
    text.split(nonce).join(MASKED_NONCE).split(uid).join("<uid>").split(email).join("<email>");
  const frames = mask(read(`${runDirectory}/frames.jsonl`, "utf8"))
    .split("\n")
    .filter(Boolean)
    .map((line, index) => {
      const frame = JSON.parse(line);
      const match = matchFrame(frame, steps);
      if (match.step === null) throw Error(`frame ${index + 1} belongs to no single write`);
      return { n: index + 1, step: match.step, ...frame };
    });
  return JSON.parse(
    mask(
      JSON.stringify({
        kind: "rtdb-kinds-recording-v1",
        recording: {
          envelope,
          recordedOn,
          instance: "fireemu-q-rtdb2",
          nonce: MASKED_NONCE,
          frames: frames.length,
        },
        steps: report.steps,
        answers: journal === undefined ? [] : answersOf(journal),
        frames,
      }),
    ),
  );
}

/**
 * A local fireemu run's frames in the same form: stamped with the write each belongs to, the local user's
 * identity (an id the emulator made up) replaced by the same `<uid>` the production masking uses. The local
 * run's nonce is already the masked one.
 */
export function maskLocalRun({ frames, steps, label, dropUnattributed = false }) {
  const ids = new Set();
  for (const frame of frames) {
    const holder = frame.generation === 1 ? frame.event?.context : frame.event;
    for (const id of [holder?.auth?.uid, holder?.authId]) if (typeof id === "string") ids.add(id);
  }
  const text = [...ids].reduce((acc, id) => acc.split(id).join("<uid>"), JSON.stringify(frames));
  let dropped = 0;
  const stamped = [];
  for (const [index, frame] of JSON.parse(text).entries()) {
    const match = matchFrame(frame, steps);
    if (match.step !== null) stamped.push({ n: stamped.length + 1, step: match.step, ...frame });
    else if (dropUnattributed) dropped += 1;
    else throw Error(`frame ${index + 1} belongs to no single write`);
  }
  return {
    kind: "rtdb-kinds-recording-v1",
    recording: {
      envelope: label,
      instance: "fireemu-q-rtdb2",
      nonce: MASKED_NONCE,
      frames: stamped.length,
      dropped,
    },
    steps: [],
    answers: [],
    frames: stamped,
  };
}

// Usage:
//   node kinds-mask.mjs <run directory> <output> --uid <uid> --email <email> --envelope <id> --recorded-on <date> [--steps v2]
//   node kinds-mask.mjs --local <frames.jsonl of a local run> <output> --label strict|emulator [--steps v2] [--drop-unattributed]
if (process.argv[1] === new URL(import.meta.url).pathname) {
  const args = process.argv.slice(2);
  const option = (name) => (args.includes(name) ? args[args.indexOf(name) + 1] : undefined);
  const stepsFor = () =>
    option("--steps") === "v2"
      ? KINDS_V2_SCENARIO.buildSteps(MASKED_NONCE)
      : buildSteps(MASKED_NONCE);
  if (args[0] === "--local") {
    const fixture = maskLocalRun({
      frames: readFileSync(args[1], "utf8").split("\n").filter(Boolean).map(JSON.parse),
      steps: stepsFor(),
      label: option("--label"),
      dropUnattributed: args.includes("--drop-unattributed"),
    });
    writeFileSync(args[2], `${JSON.stringify(fixture, null, 2)}\n`, { flag: "wx" });
  } else {
    const [runDirectory, output] = args;
    const fixture = maskRecording({
      runDirectory,
      uid: option("--uid"),
      nonce: option("--nonce"),
      email: option("--email"),
      envelope: option("--envelope"),
      recordedOn: option("--recorded-on"),
      steps: stepsFor(),
      journal: readFileSync(`${runDirectory}/journal.jsonl`, "utf8"),
    });
    writeFileSync(output, `${JSON.stringify(fixture, null, 2)}\n`, { flag: "wx" });
  }
}
