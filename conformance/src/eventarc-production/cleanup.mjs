// The cleanup of a recording, and the same code for the later --cleanup-only run (`mode: "later"`).
// The channels it works on are the union of a fresh successful list of each location the run lists (what
// carries the run's prefix) and the ledger (every channel whose creation, or whose deletion, may have
// happened). A listing alone settles nothing: it can be late after an unknown answer.
//
// - A channel from the ledger that the list did not show is read by name first. Only the recorded JSON
//   404 (see `isRecordedNotFound`) settles anything: a 404 with another body says nothing.
// - A creation counts as made only when its operation was read as done without an error (a 2xx alone
//   does not prove it). A channel whose creation is still unknown is not settled by a 404 inside the
//   recording: it stays unsettled until the later run reads its own 404 (at least 10 minutes on), or an
//   own 2xx read, a deletion and a 404.
// - A DELETE is never re-sent after an unknown one, or after a 2xx whose operation was not read as done:
//   such a channel gets read-backs only. The later run may send one DELETE for it after its own 2xx read,
//   unless an earlier later run did (`noDelete`).
// - A probe name (one that cannot carry the prefix) enters the set only when the run's own creation of
//   it was proven by its operation or is still unknown; a conflict means it is not ours, and a name that
//   never was a creation of this run is never touched, whatever a list shows.
// - Every deletion's operation is polled to done and the deletion is read back until the recorded 404.

import { BudgetExceeded } from "../pubsub-production/capture.mjs";
import { createLedger } from "../pubsub-production/ledger.mjs";
import { isRecordedNotFound } from "./client.mjs";

export const PAGE_LIMIT = 20;

async function listOwned({ client, ownership, project, location, report }) {
  const found = new Set();
  let pageToken;
  for (let page = 0; page < PAGE_LIMIT; page += 1) {
    const reply = await client.listChannels(project, location, {
      pageSize: 100,
      ...(pageToken ? { pageToken } : {}),
    });
    if (!reply.ok) {
      report.errors.push(
        `listChannels ${location}: ${reply.unknown ? "unknown answer" : reply.code}`,
      );
      return { found, listed: false };
    }
    // Only what carries the prefix: a probe is never taken from a list.
    for (const item of reply.body?.channels ?? [])
      if (ownership.prefixPattern.test(item.name)) found.add(item.name);
    pageToken = reply.body?.nextPageToken;
    if (!pageToken) return { found, listed: true };
  }
  report.errors.push(`listChannels ${location}: more than ${PAGE_LIMIT} pages`);
  return { found, listed: false };
}

/** Polls an operation of a deletion until it is done: true, false when it never was, null on a failure. */
async function settle({ client, name, sleep, attempts }) {
  let last;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (attempt > 0) await sleep(2000);
    last = await client.getOperation("eventarc", name);
    if (!last.ok) return { done: null, last };
    if (last.body?.done === true) return { done: last.body?.error === undefined, last };
  }
  return { done: false, last };
}

const lastIndex = (kinds, kind) => kinds.lastIndexOf(kind);

/** What the ledger says of a channel: whether a creation of it may have happened and is not settled, and whether a deletion was sent. */
export function ledgerFacts(item) {
  if (item === undefined)
    return { mayExist: false, createPending: false, deleteSent: false, deletePending: false };
  const creates = [
    ...item.creates,
    ...item.open.filter((action) => action === "create").map(() => "unknown"),
  ];
  const deletes = [
    ...item.deletes,
    ...item.open.filter((action) => action === "delete").map(() => "unknown"),
  ];
  const createdOk = creates.includes("ok");
  // Pending: an `unknown` that no later definite answer (the operation read as done, a conflict, an
  // error) resolved.
  const resolved = Math.max(
    lastIndex(creates, "ok"),
    lastIndex(creates, "conflict"),
    lastIndex(creates, "error"),
  );
  const createPending = lastIndex(creates, "unknown") > resolved;
  return {
    mayExist: createdOk || createPending,
    createPending,
    deleteSent: deletes.length > 0,
    deletePending:
      lastIndex(deletes, "unknown") >
      Math.max(lastIndex(deletes, "ok"), lastIndex(deletes, "error")),
  };
}

/** The channels of the ledger the run may be answerable for. */
export function ledgerTargets(ledger, ownership) {
  const targets = new Set();
  for (const [name, item] of ledger.state()) {
    const facts = ledgerFacts(item);
    if (ownership.isOwned(name) && (facts.mayExist || facts.deleteSent)) targets.add(name);
  }
  return targets;
}

const locationOf = (name) => name.split("/")[3];

export async function cleanup({
  client,
  ownership,
  project,
  ledger = createLedger(),
  sleep,
  mode = "recording",
  noDelete = new Set(),
  pollAttempts = 15,
  readBackAttempts = 3,
}) {
  const later = mode === "later";
  const report = {
    deleted: [],
    alreadyGone: [],
    leftover: [],
    errors: [],
    listed: [],
    settled: [],
    unsettled: [],
    budgetSpent: false,
  };
  const targets = ledgerTargets(ledger, ownership);
  const everything = new Set(targets);
  const settled = new Set();
  try {
    // Only the locations the run lists are listed: a target elsewhere (a location that cannot exist) is
    // read by name only.
    const listedLocations = new Set(ownership.locations());
    const locations = new Set([...listedLocations, ...[...targets].map(locationOf)]);
    for (const location of [...locations].toSorted()) {
      const { found, listed } = listedLocations.has(location)
        ? await listOwned({ client, ownership, project, location, report })
        : { found: new Set(), listed: false };
      if (listed) report.listed.push(location);
      const names = new Set(found);
      for (const name of found) everything.add(name);
      for (const name of targets) if (locationOf(name) === location) names.add(name);
      for (const name of names) {
        const facts = ledgerFacts(ledger.state().get(name));
        let exists = found.has(name);
        if (!exists) {
          // Not shown by a fresh list: read it by name before anything is sent to delete it.
          const read = await client.getChannel(name);
          if (isRecordedNotFound(read)) {
            report.alreadyGone.push(name);
            // A creation that is still unknown is not settled by absence inside the recording.
            if (facts.createPending && !later) continue;
            settled.add(name);
            report.settled.push({ name, how: "absent" });
            continue;
          }
          if (!read.ok) {
            report.errors.push(
              `getChannel ${name}: ${read.unknown ? "unknown answer" : read.code}${read.status === 404 ? " (a 404 that is not the recorded shape)" : ""}`,
            );
            continue;
          }
          exists = true;
        }
        // A deletion that was sent and not proven (unknown, or a 2xx whose operation was not read as done)
        // is not sent again inside the recording; the later run sends one after its own 2xx read.
        const mayDelete = !noDelete.has(name) && (!facts.deletePending || later);
        if (mayDelete) {
          const reply = await client.deleteChannel(name);
          if (isRecordedNotFound(reply)) report.alreadyGone.push(name);
          else if (reply.ok) {
            const operation = reply.body?.name;
            if (typeof operation === "string" && reply.body?.done !== true) {
              const { done, last } = await settle({
                client,
                name: operation,
                sleep,
                attempts: pollAttempts,
              });
              client.settleOperation(name, "delete", last);
              if (done !== true)
                report.errors.push(
                  `operation ${operation}: ${done === null ? "unreadable" : done === false ? "not done" : "failed"}`,
                );
            } else client.settleOperation(name, "delete", reply);
            report.deleted.push(name);
          } else if (!reply.unknown) {
            report.errors.push(`deleteChannel ${name}: ${reply.code}`);
            continue;
          }
        }
        let gone = false;
        for (let attempt = 0; attempt < readBackAttempts && !gone; attempt += 1) {
          if (attempt > 0) await sleep(2000);
          gone = isRecordedNotFound(await client.getChannel(name));
        }
        if (gone) {
          settled.add(name);
          report.settled.push({ name, how: mayDelete ? "deleted" : "read-back" });
        } else report.leftover.push(name);
      }
    }
  } catch (error) {
    if (!(error instanceof BudgetExceeded)) throw error;
    report.budgetSpent = true;
    report.errors.push(`the cleanup budget is spent: ${error.message}`);
  }
  report.unsettled = [...everything].filter((name) => !settled.has(name));
  return report;
}
