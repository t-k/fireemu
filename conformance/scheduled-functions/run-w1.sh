#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
root="$(cd -- "$script_dir/../.." && pwd -P)"
cd -- "$root"
common_dir="$(git rev-parse --path-format=absolute --git-common-dir)"
repository="$(dirname -- "$common_dir")"
RUSTC_WRAPPER= "$repository/docs.local/tools/heavy-slot" run --lane codex -- cargo build -p fireemu --locked --release --target-dir target/sched-final

exec node --input-type=module - "$root" "$repository" <<'W1_NODE'
import { execFile as execFileCallback } from "node:child_process";
import { promisify } from "node:util";
import { createHash } from "node:crypto";
import { readFile, writeFile, mkdir, mkdtemp, symlink, rm } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

// W1 verdict
export function calendarVerdict(id, production, local) {
  if (id === "rt08") return {
    status: "NOT_COMPARABLE", reason: "S4: Cloud Scheduler attemptDeadline readback has no local counterpart",
  };
  if (!["accepted", "refused"].includes(production)) return {
    status: "NOT_COMPARABLE", reason: "Production create answer is not judged accepted or refused",
  };
  const refusal = local.find((row) => row.accepted === false);
  if (production === "refused") return refusal
    ? { status: "MATCH", reason: "Both production and local refuse the declaration: " + refusal.reason }
    : { status: "DIVERGES", reason: "Production refuses; local accepts the declaration" };
  if (refusal) return {
    status: "DIVERGES", reason: "Production accepts; local refuses: " + refusal.reason,
  };
  if (local.some((row) => row.callback?.matched === true)) return {
    status: "MATCH", reason: id === "ds02"
      ? "Next-time metadata matches; repeated-hour production delivery is not proven"
      : "Local callback matches the advertised next time at a recorded creation anchor",
  };
  if (local.some((row) => row.callback?.reason === "creation bracket crosses advertised boundary")) return {
    status: "NOT_COMPARABLE", reason: "creation bracket crosses advertised boundary",
  };
  return { status: "DIVERGES", reason: [...new Set(local.map((row) => row.callback?.reason))].join("; ") };
}
// W1 orchestration
const [root, repository] = process.argv.slice(2);
const calendarUrl = pathToFileURL(join(root, "conformance/scheduled-functions/"));
const { CASES, collect, resources, createAccepted, createRefusedExact, createRefusedOther } = await import(new URL("calendar-v6.mjs", calendarUrl));
const { calendarFixture } = await import(new URL("calendar-local.mjs", calendarUrl));
const { normalizeString } = await import(pathToFileURL(join(root, "conformance/src/fs-rules/harness.mjs")));
const execFile = promisify(execFileCallback);
const target = join(root, "target/codex-out/calendar");
const binary = join(root, "target/sched-final/release/fireemu");
const runner = join(root, "tools/runner-node/index.mjs");
await mkdir(target, { recursive: true });
// Remove a stale success artifact before starting a new comparison.
await rm(join(target, "w1-result.json"), { force: true });
const recordings = [];
for (const [label, runId] of [["recording-1", "189fb441835b2645"], ["recording-2", "75478d967aa09afc"]]) {
  const directory = join(repository, "docs.local/runs/calendar-v6", label);
  const pins = await readFile(join(directory, "SHA256SUMS-coordinator"), "utf8");
  const journalBytes = await readFile(join(directory, "journal-" + runId + ".jsonl"));
  const resultBytes = await readFile(join(directory, "result-" + runId + ".json"));
  const digests = {};
  for (const [name, bytes] of [["journal-" + runId + ".jsonl", journalBytes], ["result-" + runId + ".json", resultBytes]]) {
    const digest = createHash("sha256").update(bytes).digest("hex");
    if (!pins.split("\n").includes(digest + "  ./" + name)) throw new Error(label + ": recording digest differs");
    digests[name] = digest;
  }
  const journal = journalBytes.toString("utf8").split("\n").filter(Boolean).map(JSON.parse);
  const requests = journal.filter((row) => row.state === "before-send");
  const answers = new Map(journal.filter((row) => row.state === "response-persisted").map((row) => [row.id, row]));
  const headers = new Map(journal.filter((row) => row.state === "response-headers").map((row) => [row.id, row]));
  const projectNumber = /\/projects\/(\d{12,13})\//.exec(requests.find((row) => row.id === "service-cloudscheduler")?.url ?? "")?.[1];
  let index = 0;
  // Replay the collector against persisted bytes. The injected send never performs I/O.
  const replay = await collect({
    runId, projectNumber, accessToken: "w1-offline-replay", save: async () => {},
    clock: () => Date.parse(requests[Math.min(index, requests.length - 1)].dispatchAt),
    sleep: async () => {},
    send: async (spec) => {
      const request = requests[index++];
      if (!request || request.method !== spec.method || request.url !== spec.url ||
          JSON.stringify(request.json ?? null) !== (spec.body ?? "null")) throw new Error("Recording request replay differs");
      const answer = answers.get(request.id);
      if (!answer || answer.status !== headers.get(request.id)?.status) throw new Error("Recording response is incomplete");
      const bytes = Buffer.from(answer.bodyBase64, "base64");
      if (bytes.length !== answer.bodyBytes || bytes.toString("base64") !== answer.bodyBase64) throw new Error("Recording body proof differs");
      return new Response(bytes, { status: answer.status, headers: { "content-type": answer.contentType } });
    },
  });
  const saved = JSON.parse(resultBytes);
  if (!replay.closureReady || !replay.complete || index !== requests.length ||
      JSON.stringify(replay.cases) !== JSON.stringify(saved.cases) || !saved.closureReady || !saved.complete)
    throw new Error(label + ": collector could not validate the complete recording");
  recordings.push({ label, runId, journal, requests, answers, headers, own: resources(runId), digests, projectNumber });
}

const cancellation = new AbortController();
process.once("SIGINT", () => cancellation.abort());
process.once("SIGTERM", () => cancellation.abort());
const result = {
  schemaVersion: 1,
  binarySha256: createHash("sha256").update(await readFile(binary)).digest("hex"),
  runnerSha256: createHash("sha256").update(await readFile(runner)).digest("hex"),
  recordings: recordings.map(({ label, digests }) => ({ label, digests })),
  cases: [], totals: {},
};
for (const profile of ["strict", "emulator"]) {
  result.totals[profile] = { MATCH: 0, DIVERGES: 0, NOT_COMPARABLE: 0 };
  // CLI readbacks establish the omitted-zone defaults. Replay the native UTC answers with omitted SDK zones;
  // v1's interval is zone-independent, while v2's cron boundary distinguishes UTC from Los Angeles.
  for (const item of [...CASES,
    { ...CASES.find((row) => row.id === "gr01"), conditionId: "SCHEDULED-FUNCTIONS/timezone-validation-defaults", case: "v1-default" },
    { ...CASES.find((row) => row.id === "cr01"), conditionId: "SCHEDULED-FUNCTIONS/timezone-validation-defaults", case: "v2-default" },
  ]) {
    const comparisons = [];
    for (const recording of recordings) {
      const id = item.id + "-create";
      const answer = recording.answers.get(id);
      const rawBytes = Buffer.from(answer.bodyBase64, "base64");
      const captured = { status: answer.status, rawBytes, bodyBytes: answer.bodyBytes, json: JSON.parse(rawBytes) };
      const production = createAccepted(item, captured, recording.own) ? "accepted"
        : createRefusedExact(captured) || createRefusedOther(captured) ? "refused" : "unknown";
      const request = recording.requests.find((row) => row.id === id);
      const anchors = [...new Set([request.dispatchAt, recording.headers.get(id).responseAt])];
      const observations = [];
      for (const anchor of anchors) {
        const work = await mkdtemp(join(target, profile + "-" + item.id + "-"));
        const fixture = join(work, "fixture");
        await mkdir(fixture);
        await mkdir(join(work, "home"));
        await symlink(join(root, "conformance/node_modules"), join(fixture, "node_modules"));
        const options = item.case === "v2-default" ? { schedule: item.schedule } : { schedule: item.schedule, timeZone: item.timeZone };
        for (const [key, value] of Object.entries(item.retryConfig ?? {})) {
          const field = { minBackoffDuration: "minBackoffSeconds", maxBackoffDuration: "maxBackoffSeconds", maxRetryDuration: "maxRetrySeconds" }[key];
          options[field ?? key] = field ? Number(value.slice(0, -1)) : value;
        }
        let declaration = calendarFixture(item);
        if (item.case === "v1-default") declaration = declaration.replace(
          "onSchedule(" + JSON.stringify({ schedule: item.schedule, timeZone: item.timeZone }) + ",",
          'require("firebase-functions/v1").pubsub.schedule(' + JSON.stringify(item.schedule) + ").onRun(",
        ).replace("scheduleTime: event.scheduleTime", "scheduleTime: event.timestamp");
        else declaration = declaration.replace(
          JSON.stringify({ schedule: item.schedule, timeZone: item.timeZone }), JSON.stringify(options));
        await writeFile(join(fixture, "index.cjs"), declaration);
        await writeFile(join(fixture, "package.json"), JSON.stringify({ private: true, main: "index.cjs" }));
        const configPath = join(work, "fireemu.json");
        await writeFile(configPath, JSON.stringify({ schemaVersion: 1, profile, daemon: { clockStart: anchor } }));
        const outputPath = join(work, "observation.json");
        const input = { scheduleTime: captured.json.scheduleTime };
        const child = `
          import { writeFile } from "node:fs/promises";
          const { localCalendarClient, exerciseCalendarSession } = await import(${JSON.stringify(new URL("calendar-local.mjs", calendarUrl).href)});
          const client = localCalendarClient({ controlUrl: process.env.FIREEMU_CONTROL_URL, functionsHost: process.env.FIREEMU_FUNCTIONS_HOST, token: process.env.FIREEMU_CONTROL_TOKEN });
          const runtime = await client.control("sessions/default/functions");
          if (runtime.status !== 200 || runtime.json.runnerAlive !== true || !runtime.json.functions?.includes("calendarReceipt") || (!runtime.json.functions.includes("calendarProbe") && ${JSON.stringify(profile)} !== "emulator")) throw new Error("Calendar runner unavailable");
          const callback = !runtime.json.functions.includes("calendarProbe")
            ? { matched: false, reason: "Emulator accepted the manifest but ignored the schedule", evidence: [] }
            : ${JSON.stringify(production)} === "accepted" && ${JSON.stringify(item.id)} !== "rt08"
            ? await exerciseCalendarSession({ input: ${JSON.stringify(input)}, anchor: ${JSON.stringify(anchor)}, ...client }) : null;
          if (callback && (/^local calendar (control request refused|runtime did not become idle|runner is absent or down|exports are missing)/.test(callback.reason ?? "") || callback.evidence.some((row) => row.status !== 200))) throw new Error("Calendar comparison could not run");
          await writeFile(${JSON.stringify(outputPath)}, JSON.stringify({ accepted: true, callback }));
        `;
        let observation;
        try {
          await execFile(binary, ["exec", "--project", "demo-scheduled-calendar", "--only", "functions",
            "--config", configPath, "--functions", fixture,
            ...["http", "functions", "firestore", "storage", "eventarc", "tasks", "pubsub", "ui", "hub", "logging"].flatMap((name) => ["--" + name + "-port", "0"]),
            "--", process.execPath, "--input-type=module", "-e", child], {
            cwd: join(root, "conformance"), encoding: "utf8", timeout: 120000, maxBuffer: 1048576,
            signal: cancellation.signal, killSignal: "SIGTERM",
            env: { PATH: process.env.PATH, HOME: join(work, "home"), FIREEMU_NODE: process.execPath, FIREEMU_RUNNER_NODE: runner },
          });
          observation = JSON.parse(await readFile(outputPath, "utf8"));
        } catch (error) {
          const refusal = /manifest: function "calendarProbe": (?:schedule:|time zone:|Cloud Scheduler refuses this schedule's job)[^\r\n]*/.exec((error.stdout ?? "") + (error.stderr ?? ""));
          if (error.code !== 1 || error.killed || cancellation.signal.aborted || !refusal) throw new Error(profile + "/" + item.id + ": local execution failed; " + (error.stderr ?? error.message));
          observation = { accepted: false, reason: refusal[0] };
        }
        observations.push({ anchor, ...observation });
        await rm(work, { recursive: true, force: true });
      }
      comparisons.push({ recording: recording.label, production, ...calendarVerdict(item.id, production, observations), observations });
    }
    const status = comparisons.some((row) => row.status === "DIVERGES") ? "DIVERGES"
      : comparisons.some((row) => row.status === "NOT_COMPARABLE") ? "NOT_COMPARABLE" : "MATCH";
    const reason = comparisons.map((row) => row.recording + ": " + row.reason).join("; ");
    result.cases.push({ id: item.id, conditionId: item.conditionId, case: item.case, profile, status, reason, comparisons });
    result.totals[profile][status]++;
    console.log(profile + "/" + item.id + " " + status + ": " + reason);
  }
}
let output = JSON.stringify(result, null, 2) + "\n";
for (const { projectNumber } of recordings) output = normalizeString(output, {
  databases: {}, run: "\u0000run\u0000", project: "\u0000project\u0000", target: { kind: "local", projectNumber },
});
await writeFile(join(target, "w1-result.json"), output);
console.log(JSON.stringify(result.totals));
W1_NODE
