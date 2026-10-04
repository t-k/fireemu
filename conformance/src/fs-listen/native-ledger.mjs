// The names a native Listen recording issued and what is known of each, and the cleanup that
// follows from it. Only a name the run itself wrote and saw confirmed (a complete 2xx) is
// deleted; an unknown answer is settled by a direct read of that very name, and absence alone
// never settles an unknown create. A listing is only a check for strays and deletes nothing.

import { NULL_JOURNAL } from "./journal.mjs";

/** gRPC codes that say the request was not applied (a definite refusal). Anything else is unknown. */
export const DEFINITIVE_CODES = new Set([3, 5, 6, 7, 8, 9, 11, 12, 16]);

export const isDefinitiveRefusal = (error) => DEFINITIVE_CODES.has(error?.code);

const described = (writes) =>
  writes.map((write) =>
    write.delete !== undefined
      ? { name: write.delete, op: "delete" }
      : { name: write.update.name, op: "create" },
  );

/**
 * The issued names: `present` is true, false or "unknown"; `unknownDelete` is sticky. Every Commit
 * is journaled before it is sent (`sending`) and after its answer (`answered`).
 */
export function createLedger({ journal = NULL_JOURNAL } = {}) {
  const names = new Map();
  const entry = (name) => {
    if (!names.has(name)) names.set(name, { present: false, unknownDelete: false });
    return names.get(name);
  };
  return {
    /** Journals the names a Commit is about to send, before the request goes out. */
    sending(writes) {
      journal.append({ type: "names", phase: "before", names: described(writes) });
    },
    /**
     * Records the answer to one Commit: "ok" (a complete 2xx) or "unknown". A definite refusal
     * ("refused") is journaled only: it applied nothing and issued no name.
     */
    answered(writes, outcome) {
      journal.append({ type: "names", phase: "after", outcome, names: described(writes) });
      if (outcome === "refused") return;
      for (const write of writes) {
        const isDelete = write.delete !== undefined;
        const state = entry(isDelete ? write.delete : write.update.name);
        if (outcome === "ok") state.present = !isDelete;
        else if (outcome === "unknown") {
          state.present = "unknown";
          if (isDelete) state.unknownDelete = true;
        }
      }
    },
    entries: () => [...names].map(([name, state]) => [name, { ...state }]),
  };
}

/** The collection a document name lives in: its parent path and its collection id. */
export function collectionOf(name, root) {
  const segments = name.slice(root.length + 1).split("/");
  const collectionId = segments.at(-2);
  const parent = [root, ...segments.slice(0, -2)].join("/");
  return { parent, collectionId };
}

/**
 * Settles the run's names. `issued` is `ledger.entries()`; `client` reads (`missing`), deletes
 * (`commit`) and lists (`listIds`). Returns what was deleted and every reason it is not complete.
 */
export async function settleNames({ issued, client, root, run, journal = NULL_JOURNAL }) {
  const names = issued.map(([name]) => name);
  const state = new Map(issued);
  const before = new Map((await client.missing(names)).map((e) => [e.name, e.exists]));
  const toDelete = [];
  const unsettled = [];
  const unexpectedPresent = [];
  for (const [name, { present }] of issued) {
    const found = before.get(name) === true;
    if (found && present === false) unexpectedPresent.push(name);
    else if (found) toDelete.push(name);
    else if (present === "unknown") unsettled.push(name);
  }
  const unknownDeletes = new Set(issued.filter(([, s]) => s.unknownDelete).map(([name]) => name));
  for (let i = 0; i < toDelete.length; i += 100) {
    const batch = toDelete.slice(i, i + 100).map((name) => ({ delete: name }));
    journal.append({ type: "names", phase: "before", names: described(batch) });
    let outcome = "ok";
    try {
      await client.commit({ writes: batch });
    } catch (error) {
      // A refused delete is read back below; an unknown one is sticky for these names.
      outcome = isDefinitiveRefusal(error) ? "refused" : "unknown";
      if (outcome === "unknown") for (const { delete: name } of batch) unknownDeletes.add(name);
    }
    journal.append({ type: "names", phase: "after", outcome, names: described(batch) });
  }
  const after = new Map((await client.missing(names)).map((e) => [e.name, e.exists]));
  const stillPresent = names.filter((name) => after.get(name) !== false);
  // Strays: run-prefixed names in the collections the run wrote to that it never issued. They are
  // reported, never deleted: nothing here confirmed that they are ours.
  const collections = new Map();
  for (const name of names) {
    const { parent, collectionId } = collectionOf(name, root);
    collections.set(`${parent}\n${collectionId}`, { parent, collectionId });
  }
  const strays = [];
  for (const { parent, collectionId } of collections.values())
    for (const name of await client.listIds({ parent, collectionId, prefix: run }))
      if (!state.has(name)) strays.push(name);
  const sticky = [...unknownDeletes].filter((name) => state.has(name)).toSorted();
  return {
    complete:
      stillPresent.length === 0 &&
      unsettled.length === 0 &&
      sticky.length === 0 &&
      strays.length === 0 &&
      unexpectedPresent.length === 0,
    deleted: toDelete.length,
    stillPresent,
    unsettled,
    unknownDeletes: sticky,
    strays,
    unexpectedPresent,
    checked: names.length,
  };
}
