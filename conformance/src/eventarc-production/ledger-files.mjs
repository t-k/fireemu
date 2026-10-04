// The issued-names ledgers of a run, read from files: the recording's own and those of the later runs
// before this one (`issued-<runId>.jsonl`, `issued-<runId>-a2-<time>.jsonl`), merged in the order of
// their names. A request that was sent and never answered is read as unknown. The names a later run
// sent a deletion for are returned too: such a name is not deleted again.

import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { createLedger } from "../pubsub-production/ledger.mjs";

/** The ledger files of a run in the directory of its capture, the recording's first. */
export function ledgerFilesOf(directory, runId) {
  const own = `issued-${runId}.jsonl`;
  const later = readdirSync(directory)
    .filter((name) => new RegExp(`^issued-${runId}-a2-\\d{8}T\\d{6}Z\\.jsonl$`).test(name))
    .toSorted();
  return [own, ...later].map((name) => join(directory, name));
}

export function readLedgerFiles(paths, options = {}) {
  const ledger = createLedger(options);
  const deletedByLater = new Set();
  paths.forEach((path, index) => {
    for (const line of readFileSync(path, "utf8").split("\n")) {
      if (line.trim() === "") continue;
      const item = JSON.parse(line);
      if (item.phase === "sent") ledger.sent(item);
      else ledger.answered(item);
      if (index > 0 && item.phase === "sent" && item.action === "delete")
        deletedByLater.add(item.name);
    }
  });
  for (const item of ledger.state().values()) {
    for (const action of item.open)
      (action === "create" ? item.creates : item.deletes).push("unknown");
    item.open.length = 0;
  }
  return { ledger, deletedByLater };
}

export const directoryOf = (path) => dirname(path);
