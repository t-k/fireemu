// The real files and processes behind the lean recorder: the private run directory, the shared
// ledger file, the git state and the pins. Small on purpose; the order of the run is in record.mjs.

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, readdir, readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { FIXED_PRODUCTION_RULES_SHA256 } from "./auth-plan.mjs";
import { encodeRow } from "./ledger-rows.mjs";
import { RECORD_BUCKET, RECORD_PROJECT, runnerDigest } from "./record.mjs";
import { buildStage3DraftPlan } from "./stage3-plan.mjs";

const run = promisify(execFile);
const RUN_ID = /^[0-9a-f]{20}$/;
const sha256 = (value) => createHash("sha256").update(value).digest("hex");

async function assertIgnored(path) {
  try {
    await run("git", ["-C", path, "rev-parse", "--show-toplevel"]);
  } catch {
    // Outside every repository, so nothing there can be committed.
    return;
  }
  try {
    await run("git", ["-C", path, "check-ignore", "-q", path]);
  } catch {
    throw new Error(`${path} is not ignored by git; private records must not be committable`);
  }
}

/** Append one JSON line and make it durable before returning. */
async function appendLine(handle, value) {
  const line = `${JSON.stringify(value)}\n`;
  const { bytesWritten } = await handle.write(line);
  if (bytesWritten !== Buffer.byteLength(line)) throw new Error("incomplete private write");
  await handle.sync();
}

/**
 * A factory of private run directories under `root`: new, mode 0700, holding `captures.jsonl`,
 * `events.jsonl` (mode 0600, one durable line per record) and `meta.json`.
 */
export function createPrivateRunFactory({ root }) {
  return async function openPrivateRun(runId) {
    if (!RUN_ID.test(runId ?? "")) throw new Error("invalid run ID");
    const base = resolve(root);
    await mkdir(base, { recursive: true, mode: 0o700 });
    const stat = await lstat(base);
    // `lstat` does not follow a link, so a symbolic link is not a directory here.
    if (!stat.isDirectory()) throw new Error("the private root is not a real directory");
    if ((stat.mode & 0o077) !== 0) throw new Error("the private root must be mode 700");
    await assertIgnored(base);
    const dir = join(base, `storage-object-${runId}`);
    await mkdir(dir, { mode: 0o700 });
    const handles = new Map();
    const file = async (name) => {
      if (!handles.has(name))
        handles.set(
          name,
          await open(
            join(dir, name),
            constants.O_WRONLY | constants.O_CREAT | constants.O_APPEND | constants.O_NOFOLLOW,
            0o600,
          ),
        );
      return handles.get(name);
    };
    return {
      dir,
      capture: async (record) => appendLine(await file("captures.jsonl"), record),
      event: async (event) => appendLine(await file("events.jsonl"), event),
      meta: async (value) => {
        const text = `${JSON.stringify(value, null, 2)}\n`;
        const handle = await open(
          join(dir, "meta.json"),
          constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | constants.O_NOFOLLOW,
          0o600,
        );
        try {
          await handle.writeFile(text);
          await handle.sync();
        } finally {
          await handle.close();
        }
      },
    };
  };
}

/** The shared ledger file: never created here, never followed through a link. */
export function createLedgerFile(path) {
  return {
    async read() {
      try {
        return await readFile(path, "utf8");
      } catch (error) {
        if (error.code === "ENOENT") return "";
        throw error;
      }
    },
    async append(row) {
      const line = encodeRow(row);
      const handle = await open(
        path,
        constants.O_WRONLY | constants.O_APPEND | constants.O_NOFOLLOW,
      );
      try {
        const { bytesWritten } = await handle.write(line);
        if (bytesWritten !== Buffer.byteLength(line)) throw new Error("incomplete ledger write");
        await handle.sync();
      } finally {
        await handle.close();
      }
    },
  };
}

/** Whether the working tree has no change but ignored files, and the commit it is at. */
export async function readGitState(cwd) {
  const status = await run("git", ["status", "--porcelain", "--untracked-files=all"], { cwd });
  const head = await run("git", ["rev-parse", "HEAD"], { cwd });
  return { clean: status.stdout.trim() === "", commit: head.stdout.trim() };
}

/**
 * The digests a packet pins: the runner's own sources, and the shape of the plan and the corpus
 * (built for fixed run IDs, so they do not change from run to run), and the fixed Rules source.
 */
export async function computePins({ sourceDir }) {
  const names = (await readdir(sourceDir)).filter((name) => name.endsWith(".mjs")).toSorted();
  const files = [];
  for (const file of names)
    files.push({ file, sha256: sha256(await readFile(join(sourceDir, file))) });
  const template = buildStage3DraftPlan({
    projectId: RECORD_PROJECT,
    bucket: RECORD_BUCKET,
    runIds: ["0".repeat(20), "1".repeat(20)],
  });
  const first = template.recordings[0];
  return {
    runnerSha256: runnerDigest(files),
    planSha256: sha256(JSON.stringify(template)),
    corpusSha256: sha256(`${first.corpusDigest}:${first.authCorpusDigest}`),
    rulesSourceSha256: FIXED_PRODUCTION_RULES_SHA256,
    files,
  };
}
