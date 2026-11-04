// Builds the committed record of a signed PUT observation (conformance/storage-signed-put-*.json)
// from a run directory: the recorded rows with their bodies normalized as the judge normalizes
// them, the exact byte length and SHA-256 of every body, and the headers that carry meaning (the shape of the volatile ETag and generation too).
// Nothing here is a secret: signatures and credentials were redacted before anything was stored,
// and the project, bucket, signer and run id are replaced by placeholders.

import { Buffer } from "node:buffer";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { judgePut, normalizeHeaders, putRow, volatileHeaderShapes } from "./judge.mjs";
import { CASES } from "./plan.mjs";

/** Reads the raw PUT answers of a run from its journal, keyed by recording and case. */
export function rawAnswers(journalText) {
  const before = new Map();
  const answers = new Map();
  for (const line of journalText.split("\n")) {
    if (line.trim() === "") continue;
    const entry = JSON.parse(line);
    if (entry.phase === "before" && entry.kind === "xml-put") before.set(entry.n, entry);
    if (entry.phase === "after" && before.has(entry.n)) {
      const request = before.get(entry.n);
      answers.set(`${request.recording}:${request.case}`, {
        status: entry.status,
        headers: entry.headers,
        body: Buffer.from(entry.bodyBase64, "base64"),
      });
    }
  }
  return answers;
}

/**
 * @param {{header: object, journalText: string, source: object}} input the run header
 *   (`run-header.json`), the run's journal and what to say about the observation
 */
export function buildFixture({ header, journalText, source }) {
  const masks = [
    [header.target.signer, "<signer>"],
    [header.target.bucket, "<bucket>"],
    [header.target.project, "<project>"],
    [header.runId, "<run>"],
  ].filter(([value]) => value);
  const answers = rawAnswers(journalText);
  const rows = [];
  for (const recording of [1, 2]) {
    for (const testCase of CASES) {
      const answer = answers.get(`${recording}:${testCase.id}`);
      if (!answer) throw new Error(`no answer for ${recording}:${testCase.id}`);
      const verdict = judgePut(testCase, answer);
      const row = putRow({ recording, testCase, answer, verdict, masks });
      rows.push({
        ...row,
        headers: normalizeHeaders(answer.headers),
        volatileHeaders: volatileHeaderShapes(answer.headers),
      });
    }
  }
  return { source, rows };
}

export function readRun(runDir) {
  return {
    header: JSON.parse(readFileSync(join(runDir, "run-header.json"), "utf8")),
    journalText: readFileSync(join(runDir, "journal.jsonl"), "utf8"),
  };
}

/**
 * Command line: `node fixture.mjs --run-dir <dir> --out <file> [--local]`. A production run
 * directory has `run-header.json`; a local run (`record-local`) has only `run-report.json`.
 */
export function main(argv) {
  const value = (name) => {
    const at = argv.indexOf(`--${name}`);
    const next = at < 0 ? undefined : argv[at + 1];
    return next === undefined || next.startsWith("--") ? undefined : next;
  };
  const runDir = value("run-dir");
  const out = value("out");
  if (!runDir || !out) throw new Error("usage: fixture.mjs --run-dir <dir> --out <file> [--local]");
  const local = argv.includes("--local");
  const journalText = readFileSync(join(runDir, "journal.jsonl"), "utf8");
  const header = local
    ? {
        runId: JSON.parse(readFileSync(join(runDir, "run-report.json"), "utf8")).runId,
        target: { bucket: "demo-signed-put.appspot.com", project: "demo-signed-put" },
      }
    : readRun(runDir).header;
  const source = local
    ? {
        observed: new Date().toISOString().slice(0, 10),
        target: "fireemu, strict profile defaults, storage emulator only",
        flow: "the same recorder (run.mjs record-local) against the same 16 cases",
        recordings: 2,
        cases: 16,
      }
    : {
        observed: "2026-11-03",
        target: "production: the default Firebase Storage bucket of a disposable project",
        flow: "Admin SDK File#getSignedUrl({version: 'v4', action: 'write', contentType: 'image/png', extensionHeaders: {'x-goog-content-length-range': '0,10485760'}}) then PUT",
        recordings: 2,
        cases: 16,
        sdk: {
          "firebase-admin": "14.3.0",
          "@google-cloud/storage": "7.22.0",
          "google-auth-library": "9.15.1",
        },
        note: "Bodies are normalized: project, bucket, signer, run id, dates, the StringToSign digest and expiry times are placeholders. bodyBytes and bodySha256 are of the exact bytes.",
      };
  const fixture = buildFixture({ header, journalText, source });
  writeFileSync(out, `${JSON.stringify(fixture, null, 2)}\n`, { flag: "wx" });
  return fixture;
}

if (import.meta.url === `file://${process.argv[1]}`) main(process.argv.slice(2));
