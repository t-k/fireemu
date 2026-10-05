// The cleanup of a recording, and the same code for the later --cleanup-only run (`mode: "later"`).
// The channels it works on are the union of a fresh successful list of each location the run lists (what
// carries the run's prefix) and the ledger (every channel whose creation, or whose deletion, may have
// happened). A listing alone settles nothing: it can be late after an unknown answer.
//
// - A creation whose answer was a 2xx that named an operation is settled by that operation: the cleanup
//   reads every such operation first, before any list (`pendingCreateOperations`). Done without an error
//   confirms the creation; done with an error (ALREADY_EXISTS included) means this run created nothing.
// - A creation that is still unknown after that (the operation not done or unreadable, or no operation to
//   read) is settled only by an exact own 2xx read that shows the channel, which confirms it (written to
//   the ledger as `confirmed`) and is followed by the deletion. A 404 never settles it, in the recording or
//   in the later run: the name stays unsettled and is reported as unconfirmed
//   (`unknown-create-absent-unconfirmed`), for the coordinator or the owner to accept or to recover.
// - Nothing a later request for the same name answers (the deliberate duplicate creation, for one) settles
//   an earlier creation: only its own operation or an own 2xx read does.
// - A channel from the ledger that the list did not show is read by name first. Only the recorded JSON
//   404 (see `isRecordedNotFound`) says anything: a 404 with another body says nothing.
// - A DELETE is never re-sent after an unknown one, or after a 2xx whose operation was not read as done:
//   such a channel gets read-backs only, and inside the recording it stays unsettled whatever they find.
//   The later run settles it by its own read-back, and may send one DELETE for it after its own 2xx read,
//   unless an earlier later run did (`noDelete`).
// - A probe name (one that cannot carry the prefix) enters the set only when the run's own creation of
//   it was proven by its operation or is still unknown; a conflict means it is not ours, and a name that
//   never was a creation of this run is never touched, whatever a list shows.
// - Every deletion's operation is polled to done and the deletion is read back until the recorded 404.

import { BudgetExceeded } from "../pubsub-production/capture.mjs";
import { createLedger } from "../pubsub-production/ledger.mjs";
import { isRecordedNotFound } from "./client.mjs";

export const PAGE_LIMIT = 20;
/** The reads of one pending creation's operation (about 6 s), so that the cleanup budget still covers 12 channels. */
export const OPERATION_READS = 4;

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

/** A ledger kind is `<kind>` or `<kind>@<operation>` (the operation of the request it answers). */
const parseKind = (kind) => {
  const at = kind.indexOf("@");
  return at < 0
    ? { base: kind, operation: null }
    : { base: kind.slice(0, at), operation: kind.slice(at + 1) };
};

const DEFINITE = new Set(["ok", "conflict", "error"]);

/** The creations of an item as parsed kinds; a creation still open is an unknown creation. */
const createsOf = (item) =>
  [...item.creates, ...item.open.filter((action) => action === "create").map(() => "unknown")].map(
    parseKind,
  );

/** The operations a creation named that no read settled, in the order they were named. */
function unsettledOperations(parsed) {
  const settled = new Set(
    parsed
      .filter(({ base, operation }) => operation !== null && DEFINITE.has(base))
      .map(({ operation }) => operation),
  );
  return [
    ...new Set(
      parsed
        .filter(
          ({ base, operation }) =>
            base === "unknown" && operation !== null && !settled.has(operation),
        )
        .map(({ operation }) => operation),
    ),
  ];
}

/** The operations of this channel's creations that are still to be read, by the creation that named each. */
export function pendingCreateOperations(item) {
  if (item === undefined) return [];
  const parsed = createsOf(item);
  return parsed.some(({ base }) => base === "confirmed") ? [] : unsettledOperations(parsed);
}

/**
 * What the ledger says of a channel: whether a creation of it may have happened and is not settled, and
 * whether a deletion was sent. A creation is pending until its own operation is read as done, or an own 2xx
 * read of the channel confirmed it; a later request for the same name resolves nothing of it.
 */
export function ledgerFacts(item) {
  if (item === undefined)
    return { mayExist: false, createPending: false, deleteSent: false, deletePending: false };
  const creates = createsOf(item);
  const deletes = [
    ...item.deletes,
    ...item.open.filter((action) => action === "delete").map(() => "unknown"),
  ].map((kind) => parseKind(kind).base);
  const confirmed = creates.some(({ base }) => base === "confirmed");
  const createdOk = confirmed || creates.some(({ base }) => base === "ok");
  const createPending =
    !confirmed &&
    (creates.some(({ base, operation }) => base === "unknown" && operation === null) ||
      unsettledOperations(creates).length > 0);
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

/** The part of a channel name from `locations/` on: the same channel whether the project is named by ID or by number. */
const channelTail = (name) => name.split("/").slice(2).join("/");

/**
 * Whether a read is an exact own 2xx read that shows the channel `name`: the answer names a channel
 * with the same location and ID (the project may be spelled by number).
 */
const showsChannel = (read, name) =>
  read.ok &&
  typeof read.body?.name === "string" &&
  channelTail(read.body.name) === channelTail(name);

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
    unconfirmed: [],
    budgetSpent: false,
  };
  const factsOf = (name) => ledgerFacts(ledger.state().get(name));
  const initial = ledgerTargets(ledger, ownership);
  let targets = initial;
  let everything = new Set(targets);
  const settled = new Set();
  try {
    // First of all, the operation of every creation whose 2xx named one: that is the positive evidence
    // of the creation (or of its failure), stronger than any read of the channel.
    for (const name of initial)
      for (const operation of pendingCreateOperations(ledger.state().get(name))) {
        const { last } = await settle({
          client,
          name: operation,
          sleep,
          attempts: OPERATION_READS,
        });
        client.settleOperation(name, "create", last, operation);
      }
    // A name whose creations all ended with an error in their operation was never created by this run.
    targets = ledgerTargets(ledger, ownership);
    everything = new Set(targets);
    for (const name of initial)
      if (!targets.has(name)) {
        settled.add(name);
        report.settled.push({ name, how: "operation" });
      }
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
        const facts = factsOf(name);
        // A deletion that was sent and not proven (unknown, or a 2xx whose operation was not read as done)
        // is not settled inside the recording by anything the channel reads as: only the later run closes it.
        const open = facts.deletePending && !later;
        let confirmedBy = found.has(name) ? "list" : null;
        if (!found.has(name)) {
          // Not shown by a fresh list: read it by name before anything is sent to delete it.
          const read = await client.getChannel(name);
          if (isRecordedNotFound(read)) {
            report.alreadyGone.push(name);
            // A creation that is still unknown is not settled by absence, in the recording or later.
            if (facts.createPending) report.unconfirmed.push(name);
            else if (!open) {
              settled.add(name);
              report.settled.push({ name, how: "absent" });
            }
            continue;
          }
          if (!read.ok) {
            report.errors.push(
              `getChannel ${name}: ${read.unknown ? "unknown answer" : read.code}${read.status === 404 ? " (a 404 that is not the recorded shape)" : ""}`,
            );
            continue;
          }
          if (facts.createPending && !showsChannel(read, name)) {
            report.errors.push(`getChannel ${name}: a 2xx read that does not show the channel`);
            continue;
          }
          confirmedBy = "read";
        }
        // An own 2xx read (or the fresh list) that shows a channel confirms its pending creation.
        if (facts.createPending && confirmedBy !== null)
          ledger.answered({ name, action: "create", transport: "rest", kind: "confirmed" });
        // The later run sends one DELETE after its own 2xx read.
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
              client.settleOperation(name, "delete", last, operation);
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
          if (!open) {
            settled.add(name);
            report.settled.push({ name, how: mayDelete ? "deleted" : "read-back" });
          }
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
