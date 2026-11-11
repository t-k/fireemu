// Writes the masked projection of one recording: `node publish.mjs <result.json> <alias> <envelope> <out.json>`. The result file
// is private (it holds the project number and the default service account); the output holds neither, and the command
// refuses to write a file that contains a twelve or thirteen digit number. It never overwrites.
import { readFileSync, writeFileSync } from "node:fs";
import { corpusManifest } from "./corpus.mjs";
import { projectRecording, refuseUnmaskedNumbers } from "./project.mjs";

const [resultPath, alias, envelope, outPath] = process.argv.slice(2);
if (!outPath) throw new Error("usage: publish.mjs <result.json> <alias> <envelope> <out.json>");
const result = JSON.parse(readFileSync(resultPath, "utf8"));
const projectNumber = process.env.TQ_PROJECT_NUMBER;
if (!projectNumber) throw new Error("TQ_PROJECT_NUMBER is required (never printed)");
const recording = projectRecording({
  result,
  alias,
  corpusSha256: corpusManifest().corpusSha256,
  projectNumber,
  meta: {
    run: result.runId.slice(0, 6),
    envelope,
    recorderRequests: result.attempted,
    observationComplete: result.judged.observationComplete,
    findings: result.judged.findings.length,
  },
});
const text = JSON.stringify(recording, null, 2) + "\n";
refuseUnmaskedNumbers(text, projectNumber);
writeFileSync(outPath, text, { flag: "wx" });
console.log(alias, Object.keys(recording.cases).length, "cases", text.length, "bytes");
