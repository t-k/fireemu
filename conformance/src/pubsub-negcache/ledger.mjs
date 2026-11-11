// The resource ledger of a run: intent first, answer second, and the settlement rules of the lane
// guide section 5 (coordinator rulings 2026-10-05).
//
//  - An unknown or operation-pending CREATE settles only on an own complete 2xx read that shows the
//    name (or a LIST that shows it). A 404 never settles it, in the run or at A2.
//  - A confirmed CREATE that later reads 404 (or is missing from a LIST) is not settled in the run; only
//    the run's own DELETE answered 2xx followed by an absence read settles it, or the A2 read-back.
//  - A DELETE answered 404 for a resource the run confirmed created is a complete answer, but it
//    settles nothing: an armed cache entry can answer it while the resource exists. It allows another
//    DELETE after a LIST shows the resource still present (three DELETEs at most).
//  - An unknown DELETE is sticky: never re-sent, closes only at A2 (>= 10 min later) with an absence.
//  - A 409 from a later request never settles an earlier request's unknown answer.

export const MAX_DELETES = 3;

const blank = (name, kind) => ({
  name,
  kind,
  creates: [],
  deletes: [],
  confirmed: false, // an own 2xx (create or read) or a LIST showed the name
  createUnknown: false,
  createRejected: false,
  absenceAfterDelete: false,
  presentAfterDelete: false,
  readAbsentBeforeDelete: false,
  a2Absent: false,
});

export function createLedger() {
  const resources = new Map();
  const requests = new Map();
  let seq = 0;
  const get = (name, kind) => {
    if (!resources.has(name)) resources.set(name, blank(name, kind));
    return resources.get(name);
  };
  const api = {
    /** Records the intent before the request is sent. */
    intent({ name, action, kind }) {
      const r = get(name, kind);
      const id = ++seq;
      const entry = { id, name, action, answer: null };
      requests.set(id, entry);
      (action === "create" ? r.creates : r.deletes).push(entry);
      return id;
    },
    /** `result`: 'ok' | 'notfound' | 'conflict' | 'error' | 'unknown' (a complete answer is never 'unknown'). */
    answer(id, result) {
      const entry = requests.get(id);
      if (!entry) throw new Error("unknown request id");
      if (entry.answer !== null) throw new Error("request answered twice");
      entry.answer = result;
      const r = resources.get(entry.name);
      if (entry.action === "create") {
        if (result === "ok") r.confirmed = true;
        else if (result === "unknown") r.createUnknown = true;
        else if (result !== "conflict" && !r.confirmed && !r.createUnknown) r.createRejected = true;
        // a 409 settles nothing about an earlier unknown create, and nothing about itself either
      }
    },
    /** An own read of the resource: 'present' (2xx GET or LIST) or 'absent' (404 / not in the LIST). */
    read(name, what) {
      const r = resources.get(name);
      if (!r) return;
      if (what === "present") {
        r.confirmed = true;
        r.createUnknown = false; // an own positive read settles an unknown create
        r.createRejected = false;
        r.absenceAfterDelete = false;
        r.presentAfterDelete = r.deletes.some((d) => d.answer === "ok");
        return;
      }
      if (what === "absent") {
        const deleted = r.deletes.some((d) => d.answer === "ok");
        if (deleted) {
          r.absenceAfterDelete = true;
          r.presentAfterDelete = false;
        } else if (r.confirmed) r.readAbsentBeforeDelete = true; // read-after-write lag cannot be told from gone
      }
    },
    a2Absent(name) {
      const r = resources.get(name);
      if (r) r.a2Absent = true;
    },
    deleting(name) {
      return (resources.get(name)?.deletes ?? []).some(
        (d) => d.answer === "unknown" || d.answer === null,
      );
    },
    status(name) {
      const r = resources.get(name);
      if (!r) return "never-created";
      // The A2 absence settles a confirmed create or an unknown delete; it never settles an unknown create.
      const unsettledCreate = r.createUnknown && !r.confirmed;
      if (r.a2Absent && !unsettledCreate && !r.deletes.some((d) => d.answer === null))
        return "gone-a2";
      if (r.deletes.some((d) => d.answer === "unknown" || d.answer === null))
        return "delete-unknown";
      if (r.deletes.some((d) => d.answer === "ok")) {
        if (r.absenceAfterDelete) return "deleted";
        return r.presentAfterDelete ? "delete-present" : "delete-unread";
      }
      if (r.deletes.length > 0 && r.confirmed) return "delete-404-present";
      if (r.confirmed) return r.readAbsentBeforeDelete ? "live-suspect" : "live";
      if (r.createUnknown) return "unconfirmed-create";
      if (r.creates.length === 0 || r.createRejected) return "never-created";
      return "unconfirmed-create"; // a 409 only: nothing known
    },
    /** Names the cleanup should try to delete: confirmed and not yet deleted, in creation order. */
    deletable() {
      return [...resources.values()]
        .filter((r) =>
          ["live", "live-suspect", "delete-404-present", "delete-present"].includes(
            api.status(r.name),
          ),
        )
        .filter((r) => r.deletes.length < MAX_DELETES)
        .map((r) => r.name);
    },
    all: () => [...resources.keys()],
    kindOf: (name) => resources.get(name)?.kind,
    closureReady() {
      return [...resources.keys()].every((n) =>
        ["never-created", "deleted", "gone-a2"].includes(api.status(n)),
      );
    },
    open() {
      return [...resources.keys()]
        .filter((n) => !["never-created", "deleted", "gone-a2"].includes(api.status(n)))
        .map((n) => ({ name: n, status: api.status(n) }));
    },
    snapshot: () => structuredClone([...resources.values()]),
  };
  return api;
}
