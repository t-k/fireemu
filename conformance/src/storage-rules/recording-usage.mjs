import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { isAbsolute } from "node:path";

// Which recordings an approval has already started: one durable JSON line per started run, appended before the run's first
// request. The file is private (mode 0600, this user, one link) and closed in shape; any line that is not exactly a usage
// line refuses the whole ledger. The admission reads it to refuse a third recording under a two-recording approval.
const RUN_ID = /^[a-z0-9][a-z0-9-]{0,47}$/;
const PACKET = /^[0-9a-f]{64}$/;
const MAX_BYTES = 64 * 1024;
const refused = () => new Error("recording usage refused");

export function createRecordingUsage(options) {
  const plainOptions = options !== null && typeof options === "object" && Object.getPrototypeOf(options) === Object.prototype;
  const known = ["path", "packetSha256", "uid", "io"];
  if (!plainOptions || Reflect.ownKeys(options).some((key) => !known.includes(key)) || !["path", "packetSha256"].every((key) => Object.hasOwn(options, key))) throw new Error("invalid recording usage options");
  const { path, packetSha256 } = options;
  const uid = Object.hasOwn(options, "uid") ? options.uid : process.getuid();
  const io = Object.hasOwn(options, "io") ? options.io : { open };
  if (typeof path !== "string" || !isAbsolute(path) || path.includes("\0") || !PACKET.test(packetSha256) || !Number.isInteger(uid) || io === null || typeof io !== "object" || Reflect.ownKeys(io).length !== 1 || typeof io.open !== "function") throw new Error("invalid recording usage options");

  async function guarded(handle) {
    const stat = await handle.stat();
    if (!stat.isFile() || (stat.mode & 0o077) !== 0 || stat.uid !== uid || stat.nlink !== 1 || stat.size > MAX_BYTES) throw refused();
    return stat;
  }

  async function read() {
    let handle;
    try { handle = await io.open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); } catch (error) { if (error?.code === "ENOENT") return []; throw refused(); }
    try {
      await guarded(handle);
      const text = new TextDecoder("utf-8", { fatal: true }).decode(await handle.readFile());
      if (text.length === 0) return [];
      if (!text.endsWith("\n")) throw refused();
      const seen = new Set();
      const mine = [];
      for (const line of text.slice(0, -1).split("\n")) {
        let row;
        try { row = JSON.parse(line); } catch { throw refused(); }
        if (row === null || typeof row !== "object" || Array.isArray(row) || Reflect.ownKeys(row).length !== 2 || !PACKET.test(row.packetSha256) || !RUN_ID.test(row.runId)) throw refused();
        const identity = `${row.packetSha256} ${row.runId}`;
        if (seen.has(identity)) throw refused();
        seen.add(identity);
        if (row.packetSha256 === packetSha256) mine.push(row.runId);
      }
      return mine;
    } catch (error) { throw error?.message === "recording usage refused" ? error : refused(); } finally { await handle.close(); }
  }

  return Object.freeze({
    async startedRunIds() { return read(); },
    /** Append this run's line durably; a run is marked once. */
    async markStarted(runId) {
      if (typeof runId !== "string" || !RUN_ID.test(runId)) throw refused();
      if ((await read()).includes(runId)) throw refused();
      let handle;
      try { handle = await io.open(path, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW | constants.O_NONBLOCK, 0o600); } catch { throw refused(); }
      try {
        await guarded(handle);
        await handle.writeFile(`${JSON.stringify({ packetSha256, runId })}\n`);
        await handle.sync();
      } catch { throw refused(); } finally { await handle.close(); }
    },
  });
}
