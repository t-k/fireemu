// The two throwaway Email/Password accounts of the Node SDK recording (cases 108 and 108C), made
// and removed through the Identity Toolkit admin routes with the owner's access token. An answer
// that is not a complete 2xx or a 4xx is unknown, and an unknown answer is settled only by a
// positive read: a create by finding the account (then it is deleted), a delete by a lookup that
// finds no user. Absence of an answer, or a 404, never settles anything.

import { NULL_JOURNAL } from "./journal.mjs";

const TIMEOUT_MS = 30_000;

/** `base` is the Identity Toolkit root of the target: production or the local Auth emulator. */
export function createAccountClient({ base, project, headers, fetchImpl = globalThis.fetch }) {
  const root = `${base}/v1/projects/${project}`;
  let requests = 0;
  async function call(route, body) {
    requests += 1;
    let response;
    try {
      response = await fetchImpl(`${root}${route}`, {
        method: "POST",
        headers: { "content-type": "application/json", ...headers },
        body: JSON.stringify(body),
        redirect: "manual",
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch {
      return { kind: "unknown", why: "transport" };
    }
    let json;
    try {
      json = await response.json();
    } catch {
      return response.status >= 200 && response.status < 300
        ? { kind: "unknown", why: "unreadable-body" }
        : response.status >= 400 && response.status < 500
          ? { kind: "refused", status: response.status }
          : { kind: "unknown", why: `status-${response.status}` };
    }
    if (response.status >= 200 && response.status < 300) return { kind: "ok", json };
    if (response.status >= 400 && response.status < 500)
      return { kind: "refused", status: response.status, json };
    return { kind: "unknown", why: `status-${response.status}` };
  }

  return {
    /** How many requests this client has sent (every create, lookup and delete). */
    requestCount: () => requests,

    /** Creates the account; the result says whether it exists, is refused, or is unknown. */
    async create({ email, password }) {
      const answer = await call("/accounts", { email, password, emailVerified: true });
      if (answer.kind === "ok" && typeof answer.json.localId === "string")
        return { kind: "created", uid: answer.json.localId };
      if (answer.kind === "refused") return { kind: "refused", status: answer.status };
      return { kind: "unknown", why: answer.why ?? "no-localId" };
    },

    /** The uids that exist for the selector; `null` when the answer is not a complete 2xx. */
    async lookup(selector) {
      const answer = await call("/accounts:lookup", selector);
      if (answer.kind === "ok") return (answer.json.users ?? []).map((user) => user.localId);
      // The backend answers a lookup of nobody with 400 USER_NOT_FOUND in some builds: that is a
      // refusal naming the absence, and only that exact text counts.
      if (answer.kind === "refused" && /USER_NOT_FOUND/.test(JSON.stringify(answer.json ?? {})))
        return [];
      return null;
    },

    /**
     * Deletes by uid and reads it back. `settled` only when a complete lookup finds no user; a
     * delete whose own answer was unknown stays `unknownDelete` (it needs the later read-back).
     */
    async remove(uid) {
      const answer = await call("/accounts:delete", { localId: uid });
      const unknownDelete = answer.kind === "unknown";
      const gone = await this.lookup({ localId: [uid] });
      if (gone === null) return { settled: false, unknownDelete, why: "lookup-unknown" };
      if (gone.includes(uid)) return { settled: false, unknownDelete, why: "still-present" };
      return { settled: true, unknownDelete, why: null };
    },
  };
}

/**
 * Makes the accounts of a run and removes them. `cleanup()` settles every account it may have
 * made: a created one is removed and read back; an unknown create is looked up by email and, if
 * found, removed; if not found it stays unsettled (a later create might still land).
 */
export function createAccountSession({ client, run, journal = NULL_JOURNAL }) {
  const made = [];
  const email = (name) => `fsl-${run}-${name}@example.com`;
  return {
    async create(names) {
      const out = {};
      for (const name of names) {
        const entry = {
          name,
          email: email(name),
          password: `Fsl-${run}-${name}-Pw1!`,
          state: "pending",
        };
        made.push(entry);
        // The email is journaled before the create goes out, the uid when the answer brings it.
        journal.append({ type: "account", phase: "before", name, email: entry.email });
        let result;
        try {
          result = await client.create(entry);
        } catch (error) {
          journal.append({
            type: "account",
            phase: "after",
            name,
            email: entry.email,
            state: "unknown",
          });
          throw error;
        }
        entry.state = result.kind;
        entry.uid = result.uid;
        journal.append({
          type: "account",
          phase: "after",
          name,
          email: entry.email,
          state: result.kind,
          ...(result.uid ? { uid: result.uid } : {}),
        });
        if (result.kind !== "created")
          throw new Error(
            `account ${name} was not created: ${result.kind} ${result.status ?? result.why ?? ""}`,
          );
        out[name] = { email: entry.email, password: entry.password, uid: entry.uid };
      }
      return out;
    },

    async cleanup() {
      const rows = [];
      for (const entry of made) {
        // Every row names the account (email, and uid when known) so the later read-back (A2)
        // can look an unsettled one up.
        const named = (row) => ({
          name: entry.name,
          email: entry.email,
          ...(entry.uid ? { uid: entry.uid } : {}),
          ...row,
        });
        let uid = entry.uid;
        if (!uid && entry.state !== "refused") {
          const found = await client.lookup({ email: [entry.email] });
          if (found === null) {
            rows.push(named({ settled: false, why: "create-unknown-lookup-unknown" }));
            continue;
          }
          if (found.length === 0) {
            rows.push(named({ settled: false, why: "create-unknown-not-found" }));
            continue;
          }
          [uid] = found;
          entry.uid = uid;
          journal.append({
            type: "account",
            phase: "after",
            name: entry.name,
            email: entry.email,
            state: "found-by-email",
            uid,
          });
        }
        if (!uid) {
          rows.push(named({ settled: true, why: "refused" }));
          continue;
        }
        journal.append({ type: "account-delete", phase: "before", uid });
        const removed = await client.remove(uid);
        journal.append({
          type: "account-delete",
          phase: "after",
          uid,
          outcome: removed.unknownDelete ? "unknown" : "answered",
          settled: removed.settled,
        });
        rows.push(
          named({
            settled: removed.settled,
            unknownDelete: removed.unknownDelete,
            why: removed.why,
          }),
        );
      }
      // An unknown delete is sticky: the account reads as gone now, but only the separate
      // read-back at least ten minutes later closes it.
      return { complete: rows.every((row) => row.settled && !row.unknownDelete), rows };
    },
  };
}
