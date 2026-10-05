// The durable record of what a production run issued (owner ledger 835 (1)). It is written before
// the first production request and extended around every request that can create or delete a
// name, with an fsync after each line, so a crash, a SIGKILL or a host sleep still leaves the run
// id and every name that may exist. The coordinator's A2 read-back works from it (`readback`).
//
// One JSON object per line:
//   { type: "run", runId, kind, project, envelopeId, startedAt }
//   { type: "names", phase: "before"|"after", outcome?, names: [{ name, op }] }
//   { type: "account", phase: "before"|"after", name, email, state?, uid? }
//   { type: "account-delete", phase: "before"|"after", uid, outcome? }
//   { type: "end", productionRequests }
// The file holds names, emails (`@example.com`) and uids: no token, no key, no password.

import { closeSync, constants, fsyncSync, openSync, writeSync } from "node:fs";

/** The journal of a run that issues nothing in production (a local recording). */
export const NULL_JOURNAL = { append() {}, close() {} };

const REAL_FS = { openSync, writeSync, fsyncSync, closeSync };

/**
 * Creates the journal file (mode 0600, never overwriting one) and returns `append`/`close`.
 * Every `append` is written and fsynced before it returns.
 */
export function createJournal(path, { fs = REAL_FS, now = () => new Date() } = {}) {
  const fd = fs.openSync(
    path,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_APPEND,
    0o600,
  );
  return {
    append(record) {
      fs.writeSync(fd, `${JSON.stringify({ at: now().toISOString(), ...record })}\n`);
      fs.fsyncSync(fd);
    },
    close: () => fs.closeSync(fd),
  };
}

/**
 * What a journal says was issued: the run, every name that may exist, the accounts with the email
 * and the uid when one was learned, and whether the run wrote its end line.
 */
export function issuedFromJournal(text) {
  let run;
  const names = new Set();
  const accounts = new Map();
  let ended = false;
  for (const line of text.split("\n")) {
    if (line.trim() === "") continue;
    let record;
    try {
      record = JSON.parse(line);
    } catch {
      throw new Error("a journal line cannot be read");
    }
    if (record.type === "run") run = record;
    else if (record.type === "names") for (const { name } of record.names) names.add(name);
    else if (record.type === "account") {
      const known = accounts.get(record.email) ?? { name: record.name, email: record.email };
      accounts.set(record.email, {
        ...known,
        ...(record.uid ? { uid: record.uid } : {}),
        ...(record.state ? { state: record.state } : {}),
      });
    } else if (record.type === "end") ended = true;
  }
  if (!run) throw new Error("the journal names no run");
  return { run, names: [...names].toSorted(), accounts: [...accounts.values()], ended };
}

/**
 * What the journal says about each name's create, folded from the `names` lines in order. A
 * `before` line opens each of its names; the `after` line that names it answers it (`ok`, a
 * definite `refused`, or `unknown`); a name that is opened again, or never answered (a crash in the
 * Commit), is answered `unknown`. Per name:
 *   - an `ok` create confirms it (until a later `ok` delete),
 *   - an `unknown` create of a name that is not confirmed leaves it `unconfirmed`,
 *   - a `refused` answer applies nothing,
 *   - a delete (the recorder's cleanup sends one only after it read the name present) settles an
 *     unknown create, and an `ok` delete forgets the confirmation,
 *   - names a `before` line marks `maybe: true` are names that may exist (the SDK cases may write
 *     them), not creates the recorder sent: they are not opened, so never unconfirmed.
 * Returns a Map from name to `{ unconfirmed }`.
 */
export function nameStates(text) {
  const states = new Map();
  const pending = new Map();
  const state = (name) => {
    if (!states.has(name)) states.set(name, { confirmed: false, unconfirmed: false });
    return states.get(name);
  };
  const answer = (name, op, outcome) => {
    const current = state(name);
    if (op === "create") {
      if (outcome === "ok") {
        current.confirmed = true;
        current.unconfirmed = false;
      } else if (outcome !== "refused" && !current.confirmed) current.unconfirmed = true;
    } else if (outcome !== "refused") {
      current.unconfirmed = false;
      if (outcome === "ok") current.confirmed = false;
    }
  };
  for (const line of text.split("\n")) {
    if (line.trim() === "") continue;
    let record;
    try {
      record = JSON.parse(line);
    } catch {
      throw new Error("a journal line cannot be read");
    }
    if (record.type !== "names") continue;
    for (const { name, op } of record.names) {
      if (record.phase === "before") {
        // Opened again without an answer: the earlier one is unknown.
        if (pending.has(name)) answer(name, pending.get(name), "unknown");
        if (record.maybe === true) state(name);
        else pending.set(name, op);
      } else {
        pending.delete(name);
        answer(name, op, record.outcome);
      }
    }
  }
  for (const [name, op] of pending) answer(name, op, "unknown");
  return new Map([...states].map(([name, { unconfirmed }]) => [name, { unconfirmed }]));
}

/**
 * The A2 read-back from a journal: every name read with a complete answer, and every account
 * looked up by its uid and by its email. Read-only; it never deletes. `client.missing` and
 * `accountClient.lookup` are the recorder's own readers.
 *
 * Absence settles a confirmed create and an unknown delete, and never an unknown create (checklist
 * section 3): a name or an account whose create the journal leaves unknown and that reads absent is
 * listed in `unconfirmed` and the read-back is not clean. A name that reads present is listed in
 * `present` (the read-back is not clean either); nothing is deleted.
 */
export async function readbackJournal({ text, client, accountClient, now = () => new Date() }) {
  const issued = issuedFromJournal(text);
  const states = nameStates(text);
  const names = issued.names.length ? await client.missing(issued.names) : [];
  const accounts = [];
  for (const account of issued.accounts) {
    const byEmail = await accountClient.lookup({ email: [account.email] });
    const byUid = account.uid ? await accountClient.lookup({ localId: [account.uid] }) : [];
    accounts.push({ ...account, foundByEmail: byEmail, foundByUid: byUid });
  }
  const unreadable = accounts.some((a) => a.foundByEmail === null || a.foundByUid === null);
  const present = names.filter((n) => n.exists).map((n) => n.name);
  const accountsPresent = accounts.some(
    (a) => (a.foundByEmail ?? []).length > 0 || (a.foundByUid ?? []).length > 0,
  );
  const unconfirmed = [
    ...names.filter((n) => !n.exists && states.get(n.name)?.unconfirmed).map((n) => n.name),
    ...accounts
      .filter(
        (a) =>
          !a.uid &&
          (a.state === undefined || a.state === "unknown") &&
          (a.foundByEmail ?? []).length === 0,
      )
      .map((a) => `account:${a.email}`),
  ];
  return {
    run: issued.run.runId,
    readAt: now().toISOString(),
    ended: issued.ended,
    names,
    accounts,
    present,
    unconfirmed,
    clean: !unreadable && present.length === 0 && !accountsPresent && unconfirmed.length === 0,
  };
}
