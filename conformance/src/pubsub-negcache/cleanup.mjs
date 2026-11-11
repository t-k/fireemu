// Cleanup of one run: delete what the run created, once per round, and read absence from LISTs.
// A DELETE answered 404 for a confirmed resource settles nothing (an armed cache entry can answer
// it while the resource exists); a LIST that still shows the resource allows another DELETE, three
// in total. An unknown DELETE is never re-sent and stays open for the coordinator's A2 read-back.

import { deleteRequest, getRequest, listRequest } from "./requests.mjs";
import { Refusal } from "./requests.mjs";
import { MAX_DELETES } from "./ledger.mjs";

export const QUIET_MS = 12000; // longer than the cache window plus the largest recorded jitter
export const ROUND_GAP_MS = 30000;
const ORDER = { snapshot: 0, subscription: 1, topic: 2 };

export async function cleanup({ ledger, exec, clock, runId, lastActivityAt, journal }) {
  const report = { rounds: 0, lists: 0, confirmReads: 0, deletes: 0, refused: [] };
  const maintenance = { maintenance: true };
  const wait = async (ms) => {
    await clock.sleepUntil(Math.max(clock.now(), lastActivityAt() + ms));
  };
  const tryExec = async (request, meta) => {
    try {
      return await exec(request, meta, maintenance);
    } catch (error) {
      if (error instanceof Refusal) {
        report.refused.push(error.message);
        return null;
      }
      journal.write({ event: "cleanup-stop", reason: error.message });
      throw error;
    }
  };
  await wait(QUIET_MS);
  // An unconfirmed create is read once: a 2xx read confirms it and makes it deletable; a 404 does not settle it.
  for (const name of ledger.all().filter((n) => ledger.status(n) === "unconfirmed-create")) {
    report.confirmReads += 1;
    await tryExec(getRequest(name, runId), { cell: "cleanup", step: "confirm", op: "confirm" });
  }
  // A resource whose DELETE already answered 404 (an armed entry can answer one while the resource
  // exists) is deleted again only after a complete LIST shows it present.
  await readLists(ledger, tryExec, report, ["delete-404-present"]);
  for (let round = 1; round <= MAX_DELETES; round += 1) {
    const names = ledger
      .deletable()
      .toSorted((a, b) => ORDER[ledger.kindOf(a)] - ORDER[ledger.kindOf(b)]);
    if (names.length === 0) break;
    report.rounds = round;
    for (const name of names) {
      report.deletes += 1;
      await tryExec(deleteRequest(name, runId), { cell: "cleanup", step: "delete", op: "delete" });
    }
    await wait(QUIET_MS);
    await readLists(ledger, tryExec, report, READ_STATUSES);
    if (round < MAX_DELETES && ledger.deletable().length > 0) await wait(ROUND_GAP_MS);
  }
  // Names whose DELETE answered 2xx but were never read through a LIST (a list that failed) stay open.
  return report;
}

const READ_STATUSES = [
  "delete-unread",
  "delete-present",
  "delete-404-present",
  "live-suspect",
  "live",
];

async function readLists(ledger, tryExec, report, statuses) {
  for (const kind of ["snapshot", "subscription", "topic"]) {
    const names = ledger
      .all()
      .filter((n) => ledger.kindOf(n) === kind && statuses.includes(ledger.status(n)));
    if (names.length === 0) continue;
    const present = new Set();
    let token;
    let complete = false;
    for (let page = 0; page < 5; page += 1) {
      report.lists += 1;
      const result = await tryExec(listRequest(kind, token), {
        cell: "cleanup",
        step: "list",
        op: `list-${kind}`,
      });
      if (result === null || result.answer.kind !== "ok") break;
      const body = result.answer.body;
      for (const item of body[
        { snapshot: "snapshots", subscription: "subscriptions", topic: "topics" }[kind]
      ] ?? [])
        present.add(item.name);
      token = body.nextPageToken;
      if (!token) {
        complete = true;
        break;
      }
    }
    if (!complete) continue; // a partial list proves no absence
    for (const name of names) ledger.read(name, present.has(name) ? "present" : "absent", "list");
  }
}
