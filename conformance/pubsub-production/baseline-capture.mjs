// The admitted coordinator supplies credentials through stdin; this collector spawns no processes.
import { existsSync, readFileSync } from "node:fs";
import { mkdir, realpath } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { collectBaseline } from "./fixture-baseline.mjs";
import { assertBaselineAuthority } from "./baseline-authority.mjs";
import { durableFile, syncDirectory } from "./capture.mjs";

export async function captureBaseline({
  root,
  runId,
  projectNumber,
  accessToken,
  guard,
  send,
  signal,
  syncParent = syncDirectory,
}) {
  if (typeof guard !== "function") throw new Error("live admission required");
  if (typeof root !== "string" || !isAbsolute(root) || !/^[a-f0-9]{32}$/.test(runId))
    throw new Error("canonical private root and fresh run id required");
  const canonicalRoot = await realpath(root);
  const base = join(canonicalRoot, "docs.local/runs/codex-lane7");
  if (resolve(root) !== canonicalRoot || (await realpath(base)) !== base)
    throw new Error("canonical private root required");
  const directory = join(base, `fixture-baseline-002-${runId}`);
  await mkdir(directory, { mode: 0o700 });
  await syncParent(base);
  const summary = await collectBaseline({
    projectNumber,
    accessToken,
    guard,
    ...(send ? { send } : {}),
    ...(signal ? { signal } : {}),
    persist: async (row, { signal: activeSignal }) => {
      activeSignal.throwIfAborted();
      if (row.state === "response-persisted") {
        await durableFile(join(directory, `${row.id}.json`), row);
        activeSignal.throwIfAborted();
        await durableFile(
          join(directory, "requests.jsonl"),
          {
            id: row.id,
            state: row.state,
            status: row.status,
            bodySha256: row.bodySha256,
            bodyBytes: row.bodyBytes,
          },
          "a",
        );
      } else {
        await durableFile(join(directory, "requests.jsonl"), row, "a");
      }
    },
  });
  await durableFile(join(directory, "summary.json"), summary);
  return summary;
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    // This input is generated and bounded by the admitted parent; it is never persisted.
    const input = JSON.parse(readFileSync(0, "utf8"));
    const ownerLedger = join(input.root, "docs.local/instructions/owner-decisions.md");
    const quietPath = join(input.root, "docs.local/runs/QUIET-WINDOW");
    const guard = async (_request, { signal }) => {
      signal.throwIfAborted();
      if (existsSync(quietPath)) throw new Error("quiet window active");
      assertBaselineAuthority({
        ...input.authority,
        ledgerText: readFileSync(ownerLedger, "utf8"),
      });
      signal.throwIfAborted();
    };
    const summary = await captureBaseline({ ...input, guard });
    process.stdout.write(`${JSON.stringify(summary)}\n`, () => {
      // Terminate all in-process callbacks, including interrupted persistence or fetch operations.
      process.exit(summary.outcome === "captured-read-only-baseline" ? 0 : 1);
    });
  } catch {
    process.stderr.write("Private read-only baseline capture stopped.\n", () => process.exit(1));
  }
}
