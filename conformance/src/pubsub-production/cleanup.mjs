// Cleanup joins fresh listings with issued names. Every proof is a complete own read, never list absence.
// Unknown creations need exact-name positive confirmation. Unknown deletions are never resubmitted.
import { BudgetExceeded } from "./capture.mjs";
import { createLedger, maybeCreated, maybeDeleting } from "./ledger.mjs";

const KINDS = [
  ["snapshots", "listSnapshots", "getSnapshot", "deleteSnapshot"],
  ["subscriptions", "listSubscriptions", "getSubscription", "deleteSubscription"],
  ["topics", "listTopics", "getTopic", "deleteTopic"],
];
export const PAGE_LIMIT = 50;
const object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

async function listOwned({ client, ownership, project, kind, list, report }) {
  const found = new Set();
  let pageToken;
  for (let page = 0; page < PAGE_LIMIT; page += 1) {
    const reply = await client[list](project, {
      pageSize: 100,
      ...(pageToken ? { pageToken } : {}),
    });
    if (
      !reply.ok ||
      !object(reply.body) ||
      (reply.body[kind] !== undefined && !Array.isArray(reply.body[kind])) ||
      (reply.body.nextPageToken !== undefined && typeof reply.body.nextPageToken !== "string")
    ) {
      report.errors.push(
        `${list}: ${reply.unknown ? "unknown answer" : reply.ok ? "unreadable list" : reply.code}`,
      );
      return found;
    }
    for (const item of reply.body[kind] ?? []) {
      if (!object(item) || typeof item.name !== "string") {
        report.errors.push(`${list}: unreadable list item`);
        return found;
      }
      if (ownership.prefixPattern.test(item.name)) found.add(item.name);
    }
    pageToken = reply.body.nextPageToken;
    if (!pageToken) return found;
  }
  report.errors.push(`${list}: more than ${PAGE_LIMIT} pages`);
  return found;
}

export function ledgerTargets(ledger, ownership) {
  return new Set(
    [...ledger.state()]
      .filter(
        ([name, item]) => ownership.isOwned(name) && (maybeCreated(item) || maybeDeleting(item)),
      )
      .map(([name]) => name),
  );
}

export async function cleanup({
  client,
  ownership,
  project,
  ledger = createLedger(),
  sleep,
  readBackAttempts = 3,
  a2ElapsedMs,
}) {
  const report = {
    deleted: [],
    alreadyGone: [],
    leftover: [],
    errors: [],
    settled: [],
    unsettled: [],
    unconfirmed: [],
    outstandingActions: [],
    budgetSpent: false,
  };
  const targets = ledgerTargets(ledger, ownership);
  const a2EligibleRequestIds = new Set(
    [...ledger.state().values()].flatMap((item) => item.requests.map((request) => request.id)),
  );
  const settled = new Set();
  const everything = new Set(targets);
  const isAbsent = (reply) => reply.unknown !== true && reply.code === "NOT_FOUND";
  const settle = (name, reply, how) => {
    if (!ledger.settleAbsent(name, reply, { a2ElapsedMs, a2EligibleRequestIds })) return false;
    settled.add(name);
    report.settled.push({ name, how });
    return true;
  };
  try {
    for (const [kind, list, get, remove] of KINDS) {
      const found = await listOwned({ client, ownership, project, kind, list, report });
      const names = new Set(found);
      for (const name of found) everything.add(name);
      for (const name of targets) if (name.split("/")[2] === kind) names.add(name);
      for (const name of names) {
        // The own read also confirms unknown creation requests, if and only if the body names this resource.
        if (!found.has(name) || ledger.unconfirmed(name) || ledger.deleting(name)) {
          const read = await client[get](name);
          if (isAbsent(read)) {
            if (settle(name, read, "absent")) report.alreadyGone.push(name);
            continue;
          }
          if (!read.ok) {
            report.errors.push(`${get} ${name}: ${read.unknown ? "unknown answer" : read.code}`);
            continue;
          }
          if (!ledger.observeRead(name, read)) {
            report.errors.push(`${get} ${name}: unreadable resource name`);
            continue;
          }
        }
        if (ledger.unconfirmed(name) || ledger.deleting(name)) {
          report.leftover.push(name);
          continue;
        }
        const reply = await client[remove](name);
        if (reply.ok) report.deleted.push(name);
        else if (isAbsent(reply)) report.alreadyGone.push(name);
        else if (!reply.unknown) {
          report.errors.push(`${remove} ${name}: ${reply.code}`);
          continue;
        }
        let gone = false;
        for (let attempt = 0; attempt < readBackAttempts && !gone; attempt += 1) {
          if (attempt > 0) await sleep(2000);
          const read = await client[get](name);
          if (isAbsent(read)) {
            gone = settle(name, read, "deleted");
            // Unknown DELETE is sticky in this run; another in-run absence cannot improve its proof.
            if (!gone) break;
          }
        }
        if (!gone) report.leftover.push(name);
      }
    }
  } catch (error) {
    if (!(error instanceof BudgetExceeded)) throw error;
    report.budgetSpent = true;
    report.errors.push(`the cleanup budget is spent: ${error.message}`);
  }
  report.unsettled = [...everything].filter((name) => !settled.has(name));
  report.unconfirmed = [...everything].filter((name) => ledger.unconfirmed(name));
  report.outstandingActions = ledger.outstanding();
  return report;
}
