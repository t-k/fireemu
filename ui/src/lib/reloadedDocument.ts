import { err, ok, type Result } from "neverthrow";
import type { FsDocument } from "./firestoreValue";

// Firestore output timestamps are UTC with 0, 3, 6, or 9 fractional digits.
// Keep all nine digits: JavaScript dates alone would discard sub-millisecond versions.
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

/** Select a reload basis without replacing an already observed newer document version. */
export const selectReloadDocument = (
  reloaded: FsDocument,
  observed: FsDocument | null,
): Result<FsDocument, "invalid-update-time"> => {
  const reloadedKey = updateTimeKey(reloaded.updateTime);
  if (reloadedKey === null) return err("invalid-update-time");
  if (observed?.name === reloaded.name) {
    const observedKey = updateTimeKey(observed.updateTime);
    if (observedKey === null) return err("invalid-update-time");
    if (observedKey > reloadedKey) return ok(observed);
  }
  return ok(reloaded);
};
