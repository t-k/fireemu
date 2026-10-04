#!/usr/bin/env node
// Coordinator-only runner of the calendar v6 packet. Without --send it prints the plan and the
// digest of the packet files and sends nothing. With --send it needs the digest the coordinator
// approved (--expect-digest) and a private run directory; the token comes from
// `gcloud auth application-default print-access-token` and is never written anywhere.
//
//   node calendar-v6-run.mjs --run-dir <dir> --project-number <n> [--send --expect-digest <hex>]
import { createHash, randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { closeSync, fsyncSync, mkdirSync, openSync, writeFileSync, writeSync } from "node:fs";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { CASES, MAX_REQUESTS, PROJECT, collect } from "./calendar-v6.mjs";

const args = process.argv.slice(2);
const flag = (name) => args.includes("--" + name);
const value = (name) => {
  const at = args.indexOf("--" + name);
  return at >= 0 ? args[at + 1] : undefined;
};
const packetFiles = ["calendar-v6.mjs", "calendar-v6-cases.json"];
const digest = createHash("sha256")
  .update(
    packetFiles
      .map(
        (name) =>
          name +
          "\t" +
          createHash("sha256")
            .update(readFileSync(new URL("./" + name, import.meta.url)))
            .digest("hex") +
          "\n",
      )
      .join(""),
  )
  .digest("hex");

console.log(
  JSON.stringify(
    { project: PROJECT, cases: CASES.length, maxRequests: MAX_REQUESTS, packetDigest: digest },
    null,
    2,
  ),
);
if (!flag("send")) {
  console.log("plan only: nothing was sent (use --send --expect-digest <hex> to run)");
  process.exit(0);
}
if (value("expect-digest") !== digest) {
  console.error("the packet digest differs from the approved one");
  process.exit(2);
}
const runDir = value("run-dir");
const projectNumber = value("project-number");
if (!runDir || !/^\d{12,13}$/.test(projectNumber ?? "")) {
  console.error("--run-dir and --project-number are required");
  process.exit(2);
}
mkdirSync(runDir, { recursive: true, mode: 0o700 });
const runId = randomBytes(8).toString("hex");
const journal = openSync(join(runDir, "journal-" + runId + ".jsonl"), "a", 0o600);
const accessToken = execFileSync("gcloud", ["auth", "application-default", "print-access-token"], {
  encoding: "utf8",
}).trim();
let result;
try {
  result = await collect({
    runId,
    projectNumber,
    accessToken,
    // Written and flushed before the request it describes is sent.
    save: async (row) => {
      writeSync(journal, JSON.stringify(row) + "\n");
      fsyncSync(journal);
    },
    send: (request) => fetch(request.url, request),
  });
} catch (error) {
  // The journal holds every request sent so far; the result file says the collector stopped.
  closeSync(journal);
  writeFileSync(
    join(runDir, "result-" + runId + ".json"),
    JSON.stringify(
      { outcome: "calendar-v6-collector-threw", message: String(error?.message) },
      null,
      2,
    ) + "\n",
    { mode: 0o600 },
  );
  console.error("the collector stopped: " + String(error?.message));
  process.exit(4);
}
closeSync(journal);
writeFileSync(join(runDir, "result-" + runId + ".json"), JSON.stringify(result, null, 2) + "\n", {
  mode: 0o600,
});
console.log(JSON.stringify({ runId, ...result, cases: undefined }, null, 2));
// Exit 0 only for a run that may be closed; 3 means the answers need the coordinator's review or
// a read-back first.
process.exit(result.closureReady ? 0 : 3);
