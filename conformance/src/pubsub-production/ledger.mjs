// The ledger of the names a run sent a creation or a deletion for. A line is written (and flushed) before
// the request is sent and another when it is answered, so that a run that dies in the middle of a request
// still names the resource that may have been created. The cleanup and the later --cleanup-only run read
// the names from here, never from a listing alone: a listing right after an unknown answer is no evidence.

import { readFileSync } from "node:fs";

/** What an answer to a creation or a deletion was: 2xx, a conflict, another definite error, or unknown. */
export function kindOf(reply) {
  if (reply.unknown) return "unknown";
  if (reply.ok) return "ok";
  return reply.code === "ALREADY_EXISTS" ? "conflict" : "error";
}

/**
 * The in-memory view of a ledger, fed by `sent` and `answered`, with the lines written to `journal` (an
 * object with `write`). `state()` gives, for each name, the kinds of its creations and deletions; a request
 * that was sent and never answered counts as unknown.
 */
export function createLedger({
  journal = { write() {} },
  now = () => new Date(),
  names = new Map(),
} = {}) {
  const entry = (name) => {
    if (!names.has(name)) names.set(name, { creates: [], deletes: [], open: [] });
    return names.get(name);
  };
  return Object.freeze({
    /** The same names, writing what is added from now on to another journal. */
    withJournal: (other) => createLedger({ journal: other, now, names }),
    sent({ name, action, transport }) {
      entry(name).open.push(action);
      journal.write({ at: now().toISOString(), phase: "sent", name, action, transport });
    },
    answered({ name, action, transport, kind }) {
      const item = entry(name);
      const at = item.open.indexOf(action);
      if (at >= 0) item.open.splice(at, 1);
      (action === "create" ? item.creates : item.deletes).push(kind);
      journal.write({ at: now().toISOString(), phase: "answered", name, action, transport, kind });
    },
    state: () => names,
  });
}

/** The state of a ledger file: the same view, with a request that was never answered as unknown. */
export function readLedger(path, options = {}) {
  const ledger = createLedger(options);
  for (const line of readFileSync(path, "utf8").split("\n")) {
    if (line.trim() === "") continue;
    const item = JSON.parse(line);
    if (item.phase === "sent") ledger.sent(item);
    else ledger.answered(item);
  }
  for (const item of ledger.state().values()) {
    for (const action of item.open)
      (action === "create" ? item.creates : item.deletes).push("unknown");
    item.open.length = 0;
  }
  return ledger;
}

/** Whether a name may exist because of this run: a creation that was 2xx or unknown. */
export const maybeCreated = (item) =>
  item.creates.some((kind) => kind === "ok" || kind === "unknown") || item.open.includes("create");

/** Whether a deletion of it was not settled. */
export const maybeDeleting = (item) =>
  item.deletes.includes("unknown") || item.open.includes("delete");
