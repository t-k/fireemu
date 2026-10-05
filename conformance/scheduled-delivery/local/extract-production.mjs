// Reduces the private run directory of the second SCHEDULED-FUNCTIONS delivery recording (run 156715222b86ea44,
// 2026-10-05) to the public digest `production-run2.json` that the local comparison reads. It keeps what the
// comparison needs (what the handlers were handed, the retry chains, the job answers) and drops what identifies the
// project beyond its id: the project number, trace ids and client addresses never reach the digest.
//
//   node extract-production.mjs <run-dir> <out.json>
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parseFrames, parseSchedulerEntries } from "../record/logs.mjs";

export const KEPT_HEADERS = [
  "x-cloudscheduler",
  "user-agent",
  "content-length",
  "x-cloudscheduler-jobname",
  "x-cloudscheduler-scheduletime",
  "x-forwarded-proto",
  "accept-encoding",
  "host",
];

const body = (row) => JSON.parse(Buffer.from(row.bodyBase64, "base64").toString("utf8"));
const NUMBER_LIKE = /\b\d{12}\b/;

/** The digest of one run directory. Pure apart from the reads of `runDir`. */
export function extract(runDir) {
  const names = readdirSync(runDir);
  const journalName = names.find((n) => /^journal-[0-9a-f]{16}\.jsonl$/.test(n));
  const resultName = names.find((n) => /^result-[0-9a-f]{16}\.json$/.test(n));
  const rows = readFileSync(join(runDir, journalName), "utf8")
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  const result = JSON.parse(readFileSync(join(runDir, resultName), "utf8"));
  const frameSeen = new Set();
  const schedulerSeen = new Set();
  const frames = [];
  const entries = [];
  for (const row of rows) {
    if (row.state !== "response-persisted" || !String(row.id).startsWith("logs-")) continue;
    const answer = body(row);
    if (row.id.includes("-frames")) frames.push(...parseFrames(answer.entries, frameSeen).frames);
    else entries.push(...parseSchedulerEntries(answer.entries, schedulerSeen));
  }
  const origin = Math.min(...frames.map((f) => Date.parse(f.frame.receivedAt)));
  const handled = frames
    .map(({ frame }) => frame)
    .sort((a, b) => Date.parse(a.receivedAt) - Date.parse(b.receivedAt))
    .map((frame) => {
      const out = {
        handler: frame.handler,
        generation: frame.generation,
        at: Date.parse(frame.receivedAt) - origin,
      };
      if (frame.generation === 2) {
        const headers = frame.request?.headers ?? {};
        Object.assign(out, {
          method: frame.request?.method ?? null,
          url: frame.request?.url ?? null,
          headers: Object.fromEntries(
            KEPT_HEADERS.filter((k) => k in headers).map((k) => [k, headers[k]]),
          ),
          headerNames: Object.keys(headers).toSorted(),
          rawBodyLength: frame.request?.rawBodyLength ?? null,
          event: frame.event,
          eventKeys: frame.eventKeys,
          contextProperty: frame.contextProperty,
          context: frame.context,
        });
      } else {
        Object.assign(out, {
          argumentCount: frame.argumentCount,
          arguments: frame.arguments,
          context: frame.context,
        });
      }
      for (const k of ["failing", "elapsedMs", "phase"]) if (k in frame) out[k] = frame[k];
      return out;
    });
  const attempts = {};
  const types = {};
  for (const { entry } of entries.map((e) => ({ entry: e.entry ?? e }))) {
    const payload = entry.jsonPayload ?? {};
    const kind = String(payload["@type"] ?? "")
      .split(".")
      .at(-1);
    const key = [
      kind,
      payload.targetType ?? "",
      payload.status ?? "",
      payload.debugInfo ?? "",
    ].join("|");
    types[key] = (types[key] ?? 0) + 1;
    const job = entry.resource?.labels?.job_id;
    if (job && (kind === "AttemptStarted" || kind === "AttemptFinished"))
      (attempts[job] ??= []).push({
        kind,
        at: Date.parse(entry.timestamp) - origin,
        status: payload.status ?? null,
        debugInfo: payload.debugInfo ?? null,
      });
  }
  for (const list of Object.values(attempts)) list.sort((a, b) => a.at - b.at);
  const digest = {
    schemaVersion: 1,
    run: {
      id: result.runId,
      project: "fireemu-oracle-sbx",
      region: "us-central1",
      recordedOn: "2026-10-05",
    },
    jobs: result.jobs,
    extraAnswers: result.extraAnswers,
    passes: result.passes.map((p) => ({
      number: p.number,
      forced: p.forced.map((f) => f.id.replace(result.runId, "<runId>")),
    })),
    // when each forced run was requested, on the frames' timeline (a forced run is no natural occurrence)
    forced: result.passes.flatMap((p) =>
      p.forced.map((f) => {
        // the recorder names the request `run-<pass>-<job id>` with the deployed jobs' prefix and the run id shortened
        const label = `run-${p.number}-${f.id.replace(result.runId, "run").replace(/^firebase-schedule-/, "")}`;
        const sent = rows.find((r) => r.id === label && r.state === "before-send");
        if (!sent?.dispatchAt)
          throw new Error(`no journal row for the forced run of ${f.id} in pass ${p.number}`);
        return {
          pass: p.number,
          job: f.id.replace(result.runId, "<runId>"),
          atMs: Date.parse(sent.dispatchAt) - origin,
        };
      }),
    ),
    schedulerEntryTypes: types,
    frameCounts: result.frames,
    frames: handled,
    attempts,
  };
  const text = JSON.stringify(digest);
  // A project number is twelve digits between non-word characters: timestamps, message ids and run ids are not.
  if (NUMBER_LIKE.test(text))
    throw new Error("the digest holds a twelve-digit number: refusing to write it");
  return digest;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [runDir, out] = process.argv.slice(2);
  writeFileSync(out, JSON.stringify(extract(runDir), null, 1) + "\n");
}
