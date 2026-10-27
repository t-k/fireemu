// Turns the private output of the CV14 production run (frames.jsonl, report.json, result.json) into the
// committed replay fixture recorded/production-rtdb-triggers.json: the frames as the handlers printed
// them, attributed to their writes, with the run's random nonce replaced by a fixed one. Nothing else is
// changed. Usage: node mask-recording.mjs <run directory> <output file> [--envelope ID --recorded-on DATE]

import { readFileSync, writeFileSync } from "node:fs";

import { buildSteps, matchFrame } from "./sequence.mjs";

export const MASKED_NONCE = "a1b2c3d4e5f60718";
const HEX16 = /^[0-9a-f]{16}$/u;

export function maskRecording({ runDirectory, envelope, recordedOn, read = readFileSync }) {
  const json = (name) => JSON.parse(read(`${runDirectory}/${name}`, "utf8"));
  const result = json("result.json");
  const report = json("report.json");
  const nonce = result.nonce;
  if (!HEX16.test(nonce)) throw new Error("the run has no 16-hex nonce");
  const mask = (text) => text.split(nonce).join(MASKED_NONCE);
  const steps = buildSteps(nonce);
  const lines = mask(read(`${runDirectory}/frames.jsonl`, "utf8"))
    .split("\n")
    .filter((line) => line.length > 0);
  const maskedSteps = buildSteps(MASKED_NONCE);
  const frames = lines.map((line, index) => {
    const frame = JSON.parse(line);
    const match = matchFrame(frame, maskedSteps);
    if (match.step === null) throw new Error(`frame ${index + 1} belongs to no single write`);
    return { n: index + 1, step: match.step.id, ...frame };
  });
  const unmasked = matchFrame(
    JSON.parse(read(`${runDirectory}/frames.jsonl`, "utf8").split("\n")[0]),
    steps,
  );
  if (unmasked.step === null)
    throw new Error("the first frame is not attributed with the run's own nonce");
  return {
    kind: "rtdb-trigger-recording-v1",
    recording: {
      envelope,
      recordedOn,
      instance: "fireemu-q-rtdb2",
      region: "us-central1",
      fixture: { "firebase-functions": "7.3.2", "firebase-admin": "14.3.0" },
      nonce: MASKED_NONCE,
      frames: frames.length,
      outcomeOfTheRun:
        "stopped-needs-review (the only reason: frames carry members the fixture did not name)",
    },
    steps: report.steps.map((step) => ({
      id: step.id,
      context: step.context,
      outcome: step.write?.outcome ?? null,
      status: step.write?.status ?? null,
      delivered: Object.fromEntries(
        Object.entries(step.handlers)
          .filter(([, seen]) => seen.frames > 0)
          .map(([handler, seen]) => [handler, seen.frames]),
      ),
    })),
    frames,
  };
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  const [runDirectory, output, ...rest] = process.argv.slice(2);
  const option = (name) => rest[rest.indexOf(name) + 1];
  const fixture = maskRecording({
    runDirectory,
    envelope: option("--envelope"),
    recordedOn: option("--recorded-on"),
  });
  writeFileSync(output, `${JSON.stringify(fixture, null, 2)}\n`, { flag: "wx" });
}
