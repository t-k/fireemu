// The cleanup of a recording: everything that carries the run's prefix (and every probe name the run
// registered) is deleted, snapshots first, then subscriptions, then topics, and every deletion is read
// back until the resource answers NOT_FOUND. A resource of someone else is never touched: the list is
// filtered by the run's own pattern, and the client refuses any other name.

const KINDS = [
  ["snapshots", "listSnapshots", "getSnapshot", "deleteSnapshot"],
  ["subscriptions", "listSubscriptions", "getSubscription", "deleteSubscription"],
  ["topics", "listTopics", "getTopic", "deleteTopic"],
];
const LIST_KEY = { snapshots: "snapshots", subscriptions: "subscriptions", topics: "topics" };
const PAGE_LIMIT = 50;

async function listOwned({ client, ownership, project, kind, list, report }) {
  const found = new Set();
  let pageToken;
  for (let page = 0; page < PAGE_LIMIT; page += 1) {
    const reply = await client[list](project, {
      pageSize: 100,
      ...(pageToken ? { pageToken } : {}),
    });
    if (!reply.ok) {
      report.errors.push(`${list}: ${reply.code}`);
      break;
    }
    for (const item of reply.body?.[LIST_KEY[kind]] ?? [])
      if (ownership.prefixPattern.test(item.name)) found.add(item.name);
    pageToken = reply.body?.nextPageToken;
    if (!pageToken) break;
  }
  return found;
}

/**
 * Deletes what the run created. `client` is a REST client, `known` the names the run created, which are
 * deleted even when a listing failed. Returns what was deleted, what was already gone, and what is left.
 */
export async function cleanup({
  client,
  ownership,
  project,
  known = [],
  sleep,
  readBackAttempts = 3,
}) {
  const report = { deleted: [], alreadyGone: [], leftover: [], errors: [] };
  const probes = new Set(ownership.probes());
  const kindOf = (name) => name.split("/")[2];
  for (const [kind, list, get, remove] of KINDS) {
    const names = await listOwned({ client, ownership, project, kind, list, report });
    for (const name of [...known, ...probes])
      if (kindOf(name) === kind && ownership.isOwned(name)) names.add(name);
    for (const name of names) {
      // A probe may have been refused, so it is read before it is deleted.
      let reply = await client[remove](name);
      if (reply.unknown) reply = await client[remove](name);
      if (reply.ok) report.deleted.push(name);
      else if (reply.code === "NOT_FOUND") report.alreadyGone.push(name);
      else {
        report.errors.push(`${remove} ${name}: ${reply.code}`);
        continue;
      }
      let gone = false;
      for (let attempt = 0; attempt < readBackAttempts && !gone; attempt += 1) {
        if (attempt > 0) await sleep(2000);
        const back = await client[get](name);
        gone = back.code === "NOT_FOUND";
      }
      if (!gone) report.leftover.push(name);
    }
  }
  return report;
}
