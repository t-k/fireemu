import { isDeepStrictEqual } from "node:util";

const decoder = new TextDecoder("utf-8", { fatal: true });
const MAX_BYTES = 1024 * 1024;

function suppliedReads(rows) {
  if (!Array.isArray(rows) || rows.length !== 4) throw new Error("incomplete read-state evidence");
  const output = new Map();
  for (const row of rows) {
    if (
      !row ||
      !["firebase", "gcs"].includes(row.dialect) ||
      !["metadata", "media"].includes(row.kind) ||
      ![200, 404].includes(row.status) ||
      typeof row.bodyBase64 !== "string" ||
      row.bodyBase64.length > Math.ceil(MAX_BYTES / 3) * 4
    )
      throw new Error("invalid read-state evidence");
    const key = `${row.dialect}/${row.kind}`;
    if (output.has(key)) throw new Error("duplicate read-state evidence");
    const bytes = Buffer.from(row.bodyBase64, "base64");
    if (bytes.length > MAX_BYTES || bytes.toString("base64") !== row.bodyBase64)
      throw new Error("invalid read-state encoding");
    let value = bytes;
    if (row.status === 200 && row.kind === "metadata") {
      try {
        value = JSON.parse(decoder.decode(bytes));
      } catch {
        throw new Error("invalid read-state metadata");
      }
      if (!value || typeof value !== "object" || Array.isArray(value))
        throw new Error("invalid read-state metadata");
    }
    output.set(key, { status: row.status, value });
  }
  if (new Set([...output.values()].map((row) => row.status)).size !== 1)
    throw new Error("inconsistent read-state evidence");
  return output;
}

/** Compare supplied complete reads only; request binding and ownership remain the caller's gates. */
export function assertUnchangedReadbacks({ before, after } = {}) {
  const prior = suppliedReads(before),
    current = suppliedReads(after);
  for (const [key, row] of prior) {
    const next = current.get(key);
    if (
      row.status !== next.status ||
      (row.status === 200 && !isDeepStrictEqual(row.value, next.value))
    )
      throw new Error("nominal read changed object state");
  }
  return true;
}
