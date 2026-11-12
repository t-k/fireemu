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

// The state of one incarnation of a name. Every create attempt clears earlier absence and closure
// evidence. After an own 2xx DELETE, a refusal restores delete bookkeeping without that evidence.
const incarnation = () => ({
  creates: [],
  deletes: [],
  confirmed: false, // an own 2xx (create or read) or a LIST showed the name
  createUnknown: false,
  createRejected: false,
  absenceAfterDelete: false,
  presentAfterDelete: false,
  readAbsentBeforeDelete: false,
  retryAdmitted: false, // a complete LIST showed the name present after the latest DELETE that did not delete it
  a2Absent: false,
});
const blank = (name, kind) => ({
  name,
  kind,
  stickyUnknownDelete: false,
  history: [],
  ...incarnation(),
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
      let restore = null; // the previous incarnation, put back if this create is refused
      if (action === "create" && r.deletes.some((d) => d.answer === "ok")) {
        // A create after the run's own successful DELETE: a new incarnation. An unknown DELETE of the
        // old one stays unknown (sticky); everything else starts again.
        restore = { ...r, history: undefined };
        r.history.push({ creates: r.creates, deletes: r.deletes });
        if (r.deletes.some((d) => d.answer === "unknown" || d.answer === null))
          r.stickyUnknownDelete = true;
        Object.assign(r, incarnation());
      }
      if (action === "create") {
        r.absenceAfterDelete = false;
        r.a2Absent = false;
        r.presentAfterDelete = false;
        r.retryAdmitted = false;
      }
      // A DELETE answered before the resource was known (a 404 for a name nobody had created) says
      // nothing about the resource the create then makes.
      if (action === "create" && !r.confirmed && !r.createUnknown)
        r.deletes = r.deletes.filter((d) => d.answer === "unknown" || d.answer === null);
      const id = ++seq;
      const entry = { id, name, action, answer: null, restore };
      requests.set(id, entry);
      (action === "create" ? r.creates : r.deletes).push(entry);
      if (action === "delete") r.retryAdmitted = false;
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
        else if (entry.restore && !r.confirmed && !r.createUnknown) {
          // A refusal restores the earlier delete bookkeeping, but no evidence from before this
          // create attempt. A 409 proves presence; other refusals leave presence unread.
          const { history, ...before } = entry.restore;
          void history;
          Object.assign(r, before);
          r.absenceAfterDelete = false;
          r.a2Absent = false;
          r.presentAfterDelete = result === "conflict";
          r.retryAdmitted = false;
        } else if (result !== "conflict" && !r.confirmed && !r.createUnknown)
          r.createRejected = true;
        // a 409 settles nothing about an earlier unknown create, and nothing about itself either
      }
    },
    /**
     * An own read of the resource: 'present' (2xx GET or LIST) or 'absent' (404 / not in the LIST).
     * `via` is 'get' or 'list'; only a complete LIST that shows the name admits another DELETE after a
     * DELETE that did not delete it.
     */
    read(name, what, via = "get") {
      const r = resources.get(name);
      if (!r) return;
      if (what === "present") {
        r.confirmed = true;
        if (via === "list") r.retryAdmitted = true;
        r.a2Absent = false; // a later positive read outweighs an earlier absence
        // An own positive read settles an unknown create: status() reads `confirmed` first.
        r.absenceAfterDelete = false;
        r.presentAfterDelete = r.deletes.some((d) => d.answer === "ok");
        return;
      }
      if (what === "absent") {
        const deleted = r.deletes.some((d) => d.answer === "ok");
        if (deleted) r.absenceAfterDelete = true;
        else if (r.confirmed) r.readAbsentBeforeDelete = true; // read-after-write lag cannot be told from gone
      }
    },
    a2Absent(name) {
      const r = resources.get(name);
      if (r) r.a2Absent = true;
    },
    deleting(name) {
      const r = resources.get(name);
      return (
        r?.stickyUnknownDelete === true ||
        (r?.deletes ?? []).some((d) => d.answer === "unknown" || d.answer === null)
      );
    },
    status(name) {
      const r = resources.get(name);
      if (!r) return "never-created";
      // The A2 absence settles a confirmed create or an unknown delete; it never settles an unknown create.
      const unsettledCreate = r.createUnknown && !r.confirmed;
      if (
        r.a2Absent &&
        r.creates.length > 0 &&
        !unsettledCreate &&
        !r.deletes.some((d) => d.answer === null)
      )
        return "gone-a2";
      if (
        r.stickyUnknownDelete ||
        r.deletes.some((d) => d.answer === "unknown" || d.answer === null)
      )
        return "delete-unknown";
      if (r.creates.length === 0) return "never-created";
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
    /**
     * Names the cleanup should try to delete, in creation order: confirmed and not yet deleted, or
     * shown present by a LIST after a DELETE. A DELETE that answered 404 (or another error) is retried
     * only when a complete LIST showed the name present after it: a failed or partial LIST, or a LIST
     * that shows it absent, admits nothing.
     */
    deletable() {
      return [...resources.values()]
        .filter((r) => {
          const status = api.status(r.name);
          if (["live", "live-suspect", "delete-present"].includes(status)) return true;
          return status === "delete-404-present" && r.retryAdmitted;
        })
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
