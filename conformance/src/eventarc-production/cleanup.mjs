// The cleanup of a recording, and the same code for the later --cleanup-only run. The channels it works
// on are the union of a fresh successful list of each location the run named (what carries the run's
// prefix) and the ledger (every channel whose creation, or whose deletion, may have happened: a 2xx or an
// unknown answer, or a request that was sent and never answered). A listing alone settles nothing: it
// can be late after an unknown answer. A channel from the ledger that the list did not show is read by
// name first. A probe name (one that cannot carry the prefix) enters the set only when the run's own
// creation of it was a 2xx or unknown: a conflict means it is not ours, and a name that never was a
// creation of this run is never touched, whatever a list shows. The long-running operation of each
// deletion is polled to done and the deletion is read back until the channel answers NOT_FOUND. A
// deletion is sent once (an unknown answer is not re-sent). A channel is settled only by its own
// complete 404.

import { BudgetExceeded } from "../pubsub-production/capture.mjs";
import { createLedger, maybeCreated, maybeDeleting } from "../pubsub-production/ledger.mjs";

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
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (attempt > 0) await sleep(2000);
    const reply = await client.getOperation("eventarc", name);
    if (!reply.ok) return null;
    if (reply.body?.done === true) return reply.body?.error === undefined;
  }
  return false;
}

/** The channels of the ledger the run may be answerable for. */
export function ledgerTargets(ledger, ownership) {
  const targets = new Set();
  for (const [name, item] of ledger.state())
    if (ownership.isOwned(name) && (maybeCreated(item) || maybeDeleting(item))) targets.add(name);
  return targets;
}

const locationOf = (name) => name.split("/")[3];

export async function cleanup({
  client,
  ownership,
  project,
  ledger = createLedger(),
  sleep,
  pollAttempts = 8,
  readBackAttempts = 3,
}) {
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
  const locations = new Set([...ownership.locations(), ...[...targets].map(locationOf)]);
  try {
    for (const location of [...locations].toSorted()) {
      const { found, listed } = await listOwned({ client, ownership, project, location, report });
      if (listed) report.listed.push(location);
      const names = new Set(found);
      for (const name of found) everything.add(name);
      for (const name of targets) if (locationOf(name) === location) names.add(name);
      for (const name of names) {
        if (!found.has(name)) {
          // Not shown by a fresh list: read it by name before anything is sent to delete it.
          const read = await client.getChannel(name);
          if (read.code === "NOT_FOUND") {
            report.alreadyGone.push(name);
            settled.add(name);
            report.settled.push({ name, how: "absent" });
            continue;
          }
          if (!read.ok) {
            report.errors.push(
              `getChannel ${name}: ${read.unknown ? "unknown answer" : read.code}`,
            );
            continue;
          }
        }
        const reply = await client.deleteChannel(name);
        if (reply.code === "NOT_FOUND") report.alreadyGone.push(name);
        else if (reply.ok) {
          const operation = reply.body?.name;
          if (typeof operation === "string" && reply.body?.done !== true) {
            const done = await settle({ client, name: operation, sleep, attempts: pollAttempts });
            if (done !== true)
              report.errors.push(
                `operation ${operation}: ${done === null ? "unreadable" : done === false ? "not done" : "failed"}`,
              );
          }
          report.deleted.push(name);
        } else if (!reply.unknown) {
          report.errors.push(`deleteChannel ${name}: ${reply.code}`);
          continue;
        }
        let gone = false;
        for (let attempt = 0; attempt < readBackAttempts && !gone; attempt += 1) {
          if (attempt > 0) await sleep(2000);
          gone = (await client.getChannel(name)).code === "NOT_FOUND";
        }
        if (gone) {
          settled.add(name);
          report.settled.push({ name, how: "deleted" });
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
