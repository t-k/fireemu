// The cleanup of a recording, and the same code for the later --cleanup-only run. The names it works on
// are the union of a fresh successful listing (what carries the run's prefix) and the ledger (every name
// whose creation, or whose deletion, may have happened: a 2xx or an unknown answer, or a request that was
// sent and never answered). A listing alone settles nothing: it can be late after an unknown answer, and
// a list whose items do not match the prefix would leave resources silently. A name from the ledger that
// the listing did not show is read by name first. A probe name enters the set only when the run's own
// creation of it was a 2xx or unknown; a conflict means it is not ours, and a name that never was a
// creation of this run is never touched. Snapshots come first, then subscriptions, then topics. Every
// deletion is sent once (an unknown answer is not re-sent) and read back until the resource answers
// NOT_FOUND. A name is settled only by an own complete 404 (or, for a probe name that is invalid, the
// INVALID_ARGUMENT that says it cannot exist).

import { BudgetExceeded } from "./capture.mjs";
import { createLedger, maybeCreated, maybeDeleting } from "./ledger.mjs";

const KINDS = [
  ["snapshots", "listSnapshots", "getSnapshot", "deleteSnapshot"],
  ["subscriptions", "listSubscriptions", "getSubscription", "deleteSubscription"],
  ["topics", "listTopics", "getTopic", "deleteTopic"],
];
const LIST_KEY = { snapshots: "snapshots", subscriptions: "subscriptions", topics: "topics" };
export const PAGE_LIMIT = 50;

async function listOwned({ client, ownership, project, kind, list, report }) {
  const found = new Set();
  let pageToken;
  for (let page = 0; page < PAGE_LIMIT; page += 1) {
    const reply = await client[list](project, {
      pageSize: 100,
      ...(pageToken ? { pageToken } : {}),
    });
    if (!reply.ok) {
      report.errors.push(`${list}: ${reply.unknown ? "unknown answer" : reply.code}`);
      return { found, failed: true };
    }
    for (const item of reply.body?.[LIST_KEY[kind]] ?? [])
      if (ownership.prefixPattern.test(item.name)) found.add(item.name);
    pageToken = reply.body?.nextPageToken;
    if (!pageToken) return { found, failed: false };
  }
  report.errors.push(`${list}: more than ${PAGE_LIMIT} pages`);
  return { found, failed: true };
}

/** The names of the ledger this run may be answerable for, by kind of resource. */
export function ledgerTargets(ledger, ownership) {
  const targets = new Set();
  for (const [name, item] of ledger.state())
    if (ownership.isOwned(name) && (maybeCreated(item) || maybeDeleting(item))) targets.add(name);
  return targets;
}

export async function cleanup({
  client,
  ownership,
  project,
  ledger = createLedger(),
  sleep,
  readBackAttempts = 3,
}) {
  const report = {
    deleted: [],
    alreadyGone: [],
    leftover: [],
    errors: [],
    settled: [],
    unsettled: [],
    budgetSpent: false,
  };
  const probes = new Set(ownership.probes());
  // A probe name the service refuses as invalid cannot exist: it answers INVALID_ARGUMENT to a read and
  // to a deletion, which is as gone as NOT_FOUND.
  const goneCodes = (name) =>
    probes.has(name) ? ["NOT_FOUND", "INVALID_ARGUMENT"] : ["NOT_FOUND"];
  const kindOf = (name) => name.split("/")[2];
  const targets = ledgerTargets(ledger, ownership);
  const settled = new Set();
  const everything = new Set(targets);
  try {
    for (const [kind, list, get, remove] of KINDS) {
      const { found } = await listOwned({ client, ownership, project, kind, list, report });
      const names = new Set(found);
      for (const name of found) everything.add(name);
      for (const name of targets) if (kindOf(name) === kind) names.add(name);
      for (const name of names) {
        if (!found.has(name)) {
          // Not shown by the listing: read it by name before anything is sent to delete it.
          const read = await client[get](name);
          if (goneCodes(name).includes(read.code)) {
            report.alreadyGone.push(name);
            settled.add(name);
            report.settled.push({ name, how: "absent" });
            continue;
          }
          if (!read.ok) {
            report.errors.push(`${get} ${name}: ${read.unknown ? "unknown answer" : read.code}`);
            continue;
          }
        }
        const reply = await client[remove](name);
        if (reply.ok) report.deleted.push(name);
        else if (goneCodes(name).includes(reply.code)) report.alreadyGone.push(name);
        else if (!reply.unknown) {
          report.errors.push(`${remove} ${name}: ${reply.code}`);
          continue;
        }
        let gone = false;
        for (let attempt = 0; attempt < readBackAttempts && !gone; attempt += 1) {
          if (attempt > 0) await sleep(2000);
          gone = goneCodes(name).includes((await client[get](name)).code);
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
