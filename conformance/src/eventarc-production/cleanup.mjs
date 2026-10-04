// The cleanup of a recording: every channel that carries the run's prefix, found in a fresh successful
// list of each location the run named (a location whose list cannot be read is an error, never a
// guess), and every probe name that such a list shows. Each channel is deleted, the long-running
// operation of the deletion is polled to done, and the deletion is read back until the channel answers
// NOT_FOUND. A channel of someone else is never touched: the list is filtered by the run's own pattern.

const PAGE_LIMIT = 20;

async function listOwned({ client, ownership, project, location, report }) {
  const found = new Set();
  let pageToken;
  for (let page = 0; page < PAGE_LIMIT; page += 1) {
    const reply = await client.listChannels(project, location, {
      pageSize: 100,
      ...(pageToken ? { pageToken } : {}),
    });
    if (!reply.ok) {
      report.errors.push(`listChannels ${location}: ${reply.code}`);
      return null;
    }
    for (const item of reply.body?.channels ?? [])
      if (ownership.isOwned(item.name)) found.add(item.name);
    pageToken = reply.body?.nextPageToken;
    if (!pageToken) return found;
  }
  report.errors.push(`listChannels ${location}: more than ${PAGE_LIMIT} pages`);
  return null;
}

/** Polls an operation of the deletion until it is done: true, false when it never was, null on a failure. */
async function settle({ client, name, sleep, attempts }) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (attempt > 0) await sleep(2000);
    const reply = await client.getOperation("eventarc", name);
    if (!reply.ok) return null;
    if (reply.body?.done === true) return reply.body?.error === undefined;
  }
  return false;
}

export async function cleanup({
  client,
  ownership,
  project,
  sleep,
  pollAttempts = 8,
  readBackAttempts = 3,
}) {
  const report = { deleted: [], alreadyGone: [], leftover: [], errors: [], listed: [] };
  for (const location of ownership.locations()) {
    const names = await listOwned({ client, ownership, project, location, report });
    if (names === null) continue;
    report.listed.push(location);
    for (const name of names) {
      let reply = await client.deleteChannel(name);
      // A deletion is safe to repeat.
      if (reply.unknown) reply = await client.deleteChannel(name);
      if (reply.code === "NOT_FOUND") report.alreadyGone.push(name);
      else if (!reply.ok) {
        report.errors.push(`deleteChannel ${name}: ${reply.code}`);
        continue;
      } else {
        const operation = reply.body?.name;
        if (typeof operation === "string" && reply.body?.done !== true) {
          const done = await settle({ client, name: operation, sleep, attempts: pollAttempts });
          if (done !== true) {
            report.errors.push(
              `operation ${operation}: ${done === null ? "unreadable" : done === false ? "not done" : "failed"}`,
            );
          }
        }
        report.deleted.push(name);
      }
      let gone = false;
      for (let attempt = 0; attempt < readBackAttempts && !gone; attempt += 1) {
        if (attempt > 0) await sleep(2000);
        gone = (await client.getChannel(name)).code === "NOT_FOUND";
      }
      if (!gone) report.leftover.push(name);
    }
  }
  return report;
}
