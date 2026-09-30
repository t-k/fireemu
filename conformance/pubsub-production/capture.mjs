// Concrete private response capture; the coordinator holds the existing project lock and supplies its token through stdin.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdir, open, realpath } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { collectPreflight } from "./preflight.mjs";

async function durableFile(path, value, flags = "wx") {
  const handle = await open(path, flags, 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value)}\n`);
    await handle.sync();
  } finally {
    await handle.close();
  }
  const directory = await open(dirname(path), "r");
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
}

export async function capturePreflight({
  directory,
  projectNumber,
  accessToken,
  send = (request) => fetch(request.url, request),
}) {
  const common = execFileSync("git", ["rev-parse", "--path-format=absolute", "--git-common-dir"], {
    cwd: fileURLToPath(new URL("../../", import.meta.url)),
    encoding: "utf8",
  }).trim();
  const base = join(dirname(common), "docs.local/runs/codex-lane7");
  await mkdir(base, { recursive: true, mode: 0o700 });
  if (
    typeof directory !== "string" ||
    !isAbsolute(directory) ||
    !resolve(directory).startsWith(`${resolve(base)}${sep}`)
  ) {
    throw new Error("capture requires an owned private run directory");
  }
  const parent = await realpath(dirname(directory));
  const canonicalBase = await realpath(base);
  if (parent !== canonicalBase && !parent.startsWith(`${canonicalBase}${sep}`)) {
    throw new Error("capture requires an owned private run directory");
  }
  await mkdir(directory, { mode: 0o700 });
  let attempted = 0,
    completed = 0;
  let outcome = "recorded-preflight";
  let errorType;
  try {
    await collectPreflight({
      projectNumber,
      accessToken,
      send: async (request) => {
        const receipt = {
          id: request.id,
          method: request.method,
          url: request.url,
          state: "before-send",
          recordedAt: new Date().toISOString(),
        };
        await durableFile(join(directory, "requests.jsonl"), receipt, "a");
        attempted++;
        return send(request);
      },
      save: async (row) => {
        await durableFile(join(directory, `${row.id}.json`), row);
        await durableFile(
          join(directory, "requests.jsonl"),
          {
            id: row.id,
            state: "response-persisted",
            status: row.status,
            recordedAt: row.recordedAt,
          },
          "a",
        );
        completed++;
      },
    });
  } catch {
    outcome = "incomplete-read-only";
    errorType = "CaptureError";
  }
  const summary = {
    outcome,
    attempted,
    completed,
    unknown: attempted - completed,
    ...(errorType ? { errorType } : {}),
  };
  await durableFile(join(directory, "summary.json"), summary);
  return summary;
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    const { projectNumber, accessToken } = JSON.parse(readFileSync(0, "utf8"));
    const summary = await capturePreflight({
      directory: process.argv[2],
      projectNumber,
      accessToken,
    });
    process.stdout.write(`${JSON.stringify(summary)}\n`);
    if (summary.outcome !== "recorded-preflight") process.exitCode = 1;
  } catch {
    process.stderr.write("Private preflight capture did not complete.\n");
    process.exitCode = 1;
  }
}
