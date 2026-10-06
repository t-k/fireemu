#!/bin/sh
# The coordinator runs this outside the Chromium sandbox; no production target is used.
set -eu
TASK_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
cd "$TASK_ROOT"
/Users/tk/work/firebase-emulator/docs.local/tools/heavy-slot run --lane codex -- env RUSTC_WRAPPER= CARGO_NET_OFFLINE=true cargo build -p fireemu --target-dir target/l3
export FIREEMU_BIN="$TASK_ROOT/target/l3/debug/fireemu"
mkdir -p "$TASK_ROOT/target/l3/tmp" "$TASK_ROOT/target/l3/recordings"
export TMPDIR="$TASK_ROOT/target/l3/tmp"
unset GOOGLE_APPLICATION_CREDENTIALS FIREBASE_TOKEN
for TASK_PROFILE in strict emulator; do
  TASK_OUT="$TASK_ROOT/target/l3/recordings/browser-$TASK_PROFILE.json"
  rm -f "$TASK_OUT"
  TASK_CODE=0
  node conformance/src/fs-listen/record.mjs browser --target local --profile "$TASK_PROFILE" --out "$TASK_OUT" || TASK_CODE=$?
  node --input-type=module - "$TASK_PROFILE" "$TASK_OUT" "$TASK_CODE" <<'NODE'
import { readFileSync } from "node:fs";
const [profile, file, exit] = process.argv.slice(2);
console.log(`profile=${profile} recorderExit=${exit}`);
let recording;
try { recording = JSON.parse(readFileSync(file, "utf8")); }
catch { console.log("NO RECORDING"); process.exit(0); }
let complete = 0;
for (const [id, row] of Object.entries(recording.rows)) {
  const ok = !row.timedOut && !row.failures?.length && !row.invariantViolations?.length;
  if (ok) complete += 1;
  console.log(`${ok ? "COMPLETE" : "INDETERMINATE"}\t${id}${ok ? "" : `\t${row.failures?.join("; ") ?? ""}`}`);
}
console.log(`totals rows=${Object.keys(recording.rows).length} complete=${complete} requests=${recording.requests} connections=${recording.connections} cleanup=${recording.cleanup.complete} writesKnown=${recording.cleanup.writesKnown}`);
for (const [mode, result] of Object.entries(recording.transport)) console.log(`${mode} requests=${result.transport.requests}/3000 connections=${result.transport.connections}/300 CI=${JSON.stringify(result.transport.ci)}`);
console.log(`errors=${JSON.stringify(recording.errors)} artifact=${file}`);
NODE
done
# A completed rehearsal can contain indeterminate observations; the gate reviews the table.
exit 0
