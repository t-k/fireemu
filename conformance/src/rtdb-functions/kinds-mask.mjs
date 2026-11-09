// Turns a kinds run directory into the committed fixture: the run's nonce, uid and email are replaced by
// fixed forms, and every frame is stamped with the one write it belongs to. A frame that fits no single
// write stops the masking: nothing unattributed is committed.

import { readFileSync, writeFileSync } from "node:fs";
import { buildSteps, matchFrame } from "./kinds-sequence.mjs";
import { MASKED_NONCE } from "./mask-recording.mjs";
export { MASKED_NONCE };

export function maskRecording({
  runDirectory,
  uid,
  email,
  nonce: suppliedNonce,
  envelope,
  recordedOn,
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
  const steps = buildSteps(MASKED_NONCE);
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
        frames,
      }),
    ),
  );
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  const [runDirectory, output, ...rest] = process.argv.slice(2);
  const option = (name) => (rest.includes(name) ? rest[rest.indexOf(name) + 1] : undefined);
  const fixture = maskRecording({
    runDirectory,
    uid: option("--uid"),
    nonce: option("--nonce"),
    email: option("--email"),
    envelope: option("--envelope"),
    recordedOn: option("--recorded-on"),
  });
  writeFileSync(output, `${JSON.stringify(fixture, null, 2)}\n`, { flag: "wx" });
}
