import { err, ok, type Result } from "neverthrow";
import type { FsDocument } from "./firestoreValue";

// Firestore output timestamps are UTC with 0, 3, 6, or 9 fractional digits.
// Validate precision without reducing the updateTime used by the write precondition.
const updateTimeKey = (value: string | undefined): string | null => {
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{3}|\d{6}|\d{9}))?Z$/.exec(
    value ?? "",
  );
  if (!match) return null;
  const seconds = match[1]!;
  const date = new Date(`${seconds}Z`);
  if (
    seconds.startsWith("0000-") ||
    Number.isNaN(date.getTime()) ||
    date.toISOString().slice(0, 19) !== seconds
  )
    return null;
  return `${seconds}.${(match[2] ?? "").padEnd(9, "0")}Z`;
};

export type DocumentRead = { document: FsDocument; generation: number };

/** Later-issued, published reads take precedence, including snapshot restores that lower time. */
export const selectReloadDocument = (
  reloaded: DocumentRead,
  observed: DocumentRead | null,
): Result<FsDocument, "invalid-update-time"> => {
  const selected =
    observed?.document.name === reloaded.document.name && observed.generation > reloaded.generation
      ? observed.document
      : reloaded.document;
  return updateTimeKey(selected.updateTime) === null ? err("invalid-update-time") : ok(selected);
};
