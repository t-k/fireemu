// Review of r6.2 (S-r6.2-3): a log poll reads at most five pages; when the fifth page still carries a token the rest of
// that window is not read, and that is an incomplete read (`more-than-five-pages`), never a silent truncation.
import assert from "node:assert/strict";
import test from "node:test";
import { record } from "./run.mjs";
import { NUMBER, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const SHORT = { passes: 1, naturalWindowMs: 60_000 };
const ENTRIES = "POST logging.googleapis.com/v2/entries:list";

/** Every frame poll answers five pages of no entries; the fifth carries a token when `overflow`. */
const framePages =
  (overflow) =>
  async ({ body }) => {
    if (!String(body.filter).includes("SCHED_DELIVERY_FRAME")) return undefined;
    const pages = ["", "p2", "p3", "p4", "p5"];
    const at = pages.indexOf(body.pageToken ?? "");
    if (at < 0) return undefined;
    const last = at === 4;
    return reply(200, {
      entries: [],
      ...(!last || overflow ? { nextPageToken: last ? "p6" : pages[at + 1] } : {}),
    });
  };

async function go(hooks) {
  const world = createWorld({ hooks });
  const journal = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "test-token",
    save: async (row) => journal.push(row),
    send: world.send,
    runCli: (o) => world.runCli(o),
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
    ...SHORT,
  });
  return { world, journal, result };
}
const sent = (journal) => journal.filter((r) => r.state === "before-send").map((r) => r.id);

test("a fifth frame page that still carries a token is an incomplete read, and nothing closes", async () => {
  const { result, journal } = await go({ [ENTRIES]: framePages(true) });
  assert.ok(sent(journal).includes("logs-final-frames-page-5"));
  assert.equal(sent(journal).includes("logs-final-frames-page-6"), false, "no sixth page is read");
  assert.ok(
    result.incompleteReads.some(
      (r) => r.id === "logs-final-frames" && r.class === "more-than-five-pages",
    ),
    JSON.stringify(result.incompleteReads),
  );
  // every poll window that overflowed is named by its own id
  assert.ok(result.incompleteReads.every((r) => /^logs-.+-frames$/.test(r.id)));
  assert.equal(
    new Set(result.incompleteReads.map((r) => r.id)).size,
    result.incompleteReads.length,
  );
  assert.equal(result.closureReady, false);
  assert.equal(result.cleanup.verified, true, "the resources are still cleaned up and read back");
});

test("near miss: exactly five pages with no token on the fifth is complete", async () => {
  const { result, journal } = await go({ [ENTRIES]: framePages(false) });
  assert.ok(sent(journal).includes("logs-final-frames-page-5"));
  assert.deepEqual(result.incompleteReads, []);
  assert.equal(result.closureReady, true);
});

test("a scheduler-entry poll that overflows is named by its own kind", async () => {
  const { result } = await go({
    [ENTRIES]: async ({ body }) => {
      if (!String(body.filter).includes("cloud_scheduler_job")) return undefined;
      const pages = ["", "p2", "p3", "p4", "p5"];
      const at = pages.indexOf(body.pageToken ?? "");
      return reply(200, { entries: [], nextPageToken: at === 4 ? "p6" : pages[at + 1] });
    },
  });
  assert.ok(
    result.incompleteReads.some(
      (r) => r.id === "logs-final-scheduler" && r.class === "more-than-five-pages",
    ),
  );
  assert.ok(result.incompleteReads.every((r) => /^logs-.+-scheduler$/.test(r.id)));
  assert.equal(result.closureReady, false);
});
