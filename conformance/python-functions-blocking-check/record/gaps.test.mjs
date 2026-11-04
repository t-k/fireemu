// What the first mutation pass of this packet left alive, each pinned by a scenario that tells the mutant from the original:
// the waits and ceilings, page ids and bounds, the observing flags, the non-JSON answers, the cleanup's loops and step names,
// and the command line's messages.
import assert from "node:assert/strict";
import test from "node:test";
import { createGuard } from "./guard.mjs";
import { judge } from "./judge.mjs";
import { FRAME_MARK, PROJECT, functionName, packageIds, sourceBuckets } from "./plan.mjs";
import {
  CLEANUP_CEILING,
  LOG_POLL_SECONDS,
  MAX_REQUESTS,
  NORMAL_CEILING,
  configDigest,
  normalizedConfig,
  record,
} from "./run.mjs";
import { emailOf } from "./script.mjs";
import { LOCAL_ID, NUMBER, createWorld, productionFrames, reply } from "./world.mjs";
import { READY_MAX_POLLS, READY_POLL_SECONDS } from "./deploy.mjs";
import { localChecks, main, readApiKey } from "./main.mjs";
import { SETTLE_MS } from "./readback.mjs";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const RUN = "0123456789abcdef";
const error = (code, status) => reply(code, { error: { code, status, message: "x" } });
const path = (request) => new URL(request.url).pathname;
async function go(
  worldOptions = {},
  wrapSend = (send) => send,
  options = {},
  wrapCli = (cli) => cli,
) {
  const world = createWorld({ runId: RUN, ...worldOptions });
  const journal = [];
  const sleeps = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async (row) => journal.push(row),
    send: wrapSend(world.send, world),
    runCli: wrapCli((o) => world.runCli(o), world),
    clock: () => world.now,
    sleep: async (ms) => (sleeps.push(ms), world.advance(ms)),
    ...options,
  });
  return { world, journal, sleeps, result };
}
const ids = (journal) => journal.filter((r) => r.state === "before-send").map((r) => r.id);

// ---- constants and waits ---------------------------------------------------------------------------------

test("the ceilings, the poll interval and the deploy waits are the packet's", () => {
  assert.deepEqual(
    [
      NORMAL_CEILING,
      CLEANUP_CEILING,
      MAX_REQUESTS,
      LOG_POLL_SECONDS,
      READY_POLL_SECONDS,
      READY_MAX_POLLS,
    ],
    [150, 100, 250, 60, 30, 40],
  );
  assert.equal(SETTLE_MS, 600_000);
});

test("every wait is in seconds converted to milliseconds, with the packet's defaults", async () => {
  const waits = {
    propagation: 7,
    window: 13,
    logPoll: 5,
    logDelay: 11,
    ready: 3,
    settle: 4,
    operation: 2,
  };
  const { sleeps } = await go(
    { silent: true, leaveOnDelete: true },
    (send) => async (request) =>
      request.method === "GET" && path(request).includes("/operations/del-")
        ? reply(200, { name: path(request), done: false })
        : send(request),
    { waits },
  );
  assert.ok(sleeps.includes(7000) && sleeps.includes(11000) && sleeps.includes(3000));
  assert.equal(
    sleeps.filter((ms) => ms === 4000).length,
    6,
    "the settle polls after the CLI delete",
  );
  assert.equal(sleeps.filter((ms) => ms === 2000).length, 12, "the leftover operation reads");
  assert.deepEqual(sleeps.filter((ms) => ms === 5000).length >= 2 && sleeps.includes(3000), true);
  const defaults = await go(
    { leaveOnDelete: true, deployState: "DEPLOYING" },
    (send) => async (request) =>
      request.method === "GET" && path(request).includes("/operations/del-")
        ? reply(200, { name: path(request), done: false })
        : send(request),
  );
  assert.equal(
    defaults.sleeps.filter((ms) => ms === 30_000).length,
    39 + 6,
    "40 readiness polls (39 gaps) and the 6 settle gaps",
  );
  assert.equal(defaults.sleeps.filter((ms) => ms === 10_000).length, 12);
});

test("the normal request ceiling is exact", async () => {
  for (const ceiling of [20, 21]) {
    const { journal } = await go({}, (send) => send, { normalCeiling: ceiling });
    assert.equal(
      ids(journal).findIndex(
        (id) =>
          id.startsWith("cleanup-") || id.startsWith("leftover") || id.startsWith("delete-package"),
      ),
      ceiling,
    );
  }
});

// ---- page ids and bounds ---------------------------------------------------------------------------------

test("list pages: the second page of a list without a query is asked for with ?, one with a query with &, and the ids number them", async () => {
  const seen = [];
  let first = true;
  const { journal } = await go({}, (send) => async (request) => {
    if (request.method === "GET" && /\/locations\/-\/functions(\?|$)/.test(request.url) && first) {
      first = false;
      seen.push(request.url);
      return reply(200, { nextPageToken: "abc" });
    }
    if (request.method === "GET" && /\/locations\/-\/functions\?pageToken=abc/.test(request.url))
      seen.push(request.url);
    return send(request);
  });
  assert.ok(
    seen.some((u) => u.endsWith("/functions?pageToken=abc")),
    seen.join(),
  );
  assert.ok(ids(journal).includes("preflight-functions-v2-page-2"));
  assert.ok(!ids(journal).includes("preflight-functions-v2-page-3"));
  const six = [];
  let n = 0;
  const stop = await go({}, (send) => async (request) => {
    if (request.method === "GET" && /\/locations\/-\/functions(\?|$)/.test(request.url) && n < 9) {
      n++;
      six.push(request.url);
      return reply(200, { nextPageToken: "t" + n });
    }
    return send(request);
  });
  assert.equal(stop.result.stoppedBecause, "lists");
  assert.equal(six.length, 5, "a sixth page is never read");
});

test("the log reads page by token, number their pages, give up after five, and five pages are read to their end", async () => {
  const world = createWorld({ runId: RUN, logPageSize: 4 });
  const journal = [];
  await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async (r) => journal.push(r),
    send: world.send,
    runCli: world.runCli,
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
  });
  assert.ok(ids(journal).filter((id) => id.startsWith("logs-observe-1-frames")).length >= 1);
  const origin = {
    logName: "projects/p/logs/run.googleapis.com%2Fstdout",
    resource: {
      type: "cloud_run_revision",
      labels: { service_name: "pcblock", location: "us-central1" },
    },
  };
  for (const [pad, flagged] of [
    [4, false],
    [10, true],
  ]) {
    const w = createWorld({ runId: RUN, logPageSize: 1, silent: true });
    for (let i = 0; i < pad; i++)
      w.entries.push({
        insertId: "pad" + i,
        timestamp: new Date(w.now + 500).toISOString(),
        ...origin,
        textPayload: FRAME_MARK + " {",
      });
    const j = [];
    const r = await record({
      runId: RUN,
      projectNumber: NUMBER,
      accessToken: "tok-abcdefgh",
      save: async (x) => j.push(x),
      send: w.send,
      runCli: w.runCli,
      clock: () => w.now,
      sleep: async (ms) => w.advance(ms),
      waits: { window: 60, logPoll: 60 },
    });
    assert.equal(
      r.incompleteReads.some((x) => x.class === "more-than-five-pages"),
      flagged,
      "pad " + pad,
    );
    const pages = ids(j)
      .filter((id) => id.startsWith("logs-observe-1-frames"))
      .map((id) => (id.includes("-page-") ? Number(id.split("-").at(-1)) : 1));
    assert.deepEqual(
      pages,
      Array.from({ length: Math.min(pages.length, 5) }, (_, i) => i + 1),
    );
    assert.ok(Math.max(...pages) <= 5, "pad " + pad);
  }
});

test("each log window starts five seconds before the last one ended, whatever the clock does between them", async () => {
  const world = createWorld({ runId: RUN });
  const journal = [];
  let tick = 0;
  await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async (r) => journal.push(r),
    send: world.send,
    runCli: world.runCli,
    clock: () => world.now + 1000 * tick++,
    sleep: async (ms) => world.advance(ms),
  });
  const filters = journal
    .filter((r) => r.state === "before-send" && /^logs-[a-z0-9-]+-frames$/.test(r.id))
    .map((r) => [r.id, r.json.filter]);
  const at = (filter, key) => Date.parse(new RegExp(`timestamp${key}"([^"]+)"`).exec(filter)[1]);
  assert.ok(filters.length >= 3);
  for (let i = 1; i < filters.length - 1; i++)
    assert.equal(at(filters[i][1], ">="), at(filters[i - 1][1], "<=") - 5000, filters[i][0]);
  const last = filters.at(-1);
  assert.equal(last[0], "logs-final-frames");
  assert.equal(
    at(last[1], ">=") - at(filters[0][1], ">="),
    5000,
    "the final poll reads from the start of the run",
  );
});

test("the observe loop waits for both frames, not one, and takes one step when the window is shorter than a poll", async () => {
  const { journal } = await go({}, (send) => async (request) => {
    const response = await send(request);
    if (
      request.method === "POST" &&
      request.url.includes("entries:list") &&
      !JSON.parse(request.body).filter.includes("severity")
    ) {
      const body = await response.json();
      const kept = (body.entries ?? []).filter((e) => !e.textPayload.includes("blocking-sdk"));
      return reply(200, kept.length ? { entries: kept } : {});
    }
    return response;
  });
  assert.deepEqual(
    ids(journal).filter((id) => /^logs-observe-\d+-frames$/.test(id)),
    ["logs-observe-1-frames", "logs-observe-2-frames"],
  );
  const short = await go({ silent: true }, (send) => send, { waits: { window: 3, logPoll: 60 } });
  assert.deepEqual(
    ids(short.journal).filter((id) => /^logs-observe-\d+-frames$/.test(id)),
    ["logs-observe-1-frames"],
  );
});

// ---- observing reads and non-JSON answers -------------------------------------------------------------

test("a 403 on the reads that observe is data: the repository, the source buckets, the invoker policy and the leftover operations", async () => {
  const buckets = await go(
    {},
    (send) => async (request) =>
      request.url.includes("gcf-v2-sources") ? error(403, "PERMISSION_DENIED") : send(request),
  );
  assert.notEqual(buckets.result.outcome, "pcblock-auth-stop");
  assert.equal(buckets.result.inventory.sourceObjects.sources, null);
  assert.ok(buckets.result.incompleteReads.some((r) => r.id === "preflight-source-objects"));
  const paged = await go(
    {},
    (send) => async (request) =>
      request.url.includes("gcf-v2-uploads")
        ? reply(200, { items: [{ name: "a" }], nextPageToken: "t" })
        : send(request),
  );
  assert.equal(paged.result.inventory.sourceObjects.uploads, null);
  assert.equal(paged.result.closureReady, false);
  const none = await go({ withSourceBuckets: false });
  assert.deepEqual(none.result.inventory.sourceObjects, {
    uploads: { added: [], removed: [] },
    sources: { added: [], removed: [] },
  });
  assert.deepEqual(none.result.incompleteReads, []);
  const op = await go(
    { leaveOnDelete: true },
    (send) => async (request) =>
      request.method === "GET" && path(request).includes("/operations/del-")
        ? error(403, "PERMISSION_DENIED")
        : send(request),
  );
  assert.notEqual(op.result.outcome, "pcblock-auth-stop");
  const pkg = await go({}, (send) => async (request) => {
    if (request.method === "DELETE" && path(request).endsWith(packageIds()[0])) {
      await send(request);
      return reply(200, {
        name: "projects/fireemu-oracle-idp/locations/us-central1/operations/pk-1",
        done: false,
      });
    }
    if (request.method === "GET" && path(request).endsWith("/operations/pk-1"))
      return error(403, "PERMISSION_DENIED");
    return send(request);
  });
  assert.notEqual(pkg.result.outcome, "pcblock-auth-stop");
});

test("a 200 that is not JSON is read as nothing, never as a crash, on every read the run depends on", async () => {
  for (const [name, match, because] of [
    ["identity", (r) => r.url.includes("firebase.googleapis.com"), "identity"],
    ["services", (r) => r.url.includes("serviceusage"), "services"],
    ["config", (r) => r.method === "GET" && path(r).endsWith("/config"), "config"],
    ["accounts", (r) => path(r).endsWith("accounts:query"), "accounts"],
  ]) {
    const { result } = await go(
      {},
      (send) => async (request) =>
        match(request) ? new Response("<html>", { status: 200 }) : send(request),
    );
    assert.equal(result.stoppedBecause, because, name);
    assert.equal(result.outcome, "pcblock-stopped-clean", name);
  }
  for (const [name, match] of [
    ["function", (r) => r.method === "GET" && path(r).endsWith("/functions/pcblock")],
    ["config after deploy", (r) => r.id === "config-after-deploy"],
    ["sign-up", (r) => path(r) === "/v1/accounts:signUp"],
  ]) {
    let served = false;
    const { result } = await go({}, (send, world) => async (request) => {
      const hit =
        name === "config after deploy"
          ? request.method === "GET" &&
            path(request).endsWith("/config") &&
            world.cliRuns.includes("deploy") &&
            !world.cliRuns.includes("delete")
          : match(request);
      if (!served && hit) {
        served = true;
        return new Response("<html>", { status: 200 });
      }
      return send(request);
    });
    assert.equal(served, true, name);
    assert.equal(result.stoppedBecause, undefined, name);
    assert.ok(result.outcome.startsWith("pcblock-"), name);
  }
});

test("a read answered exactly 400 is incomplete", async () => {
  const { result } = await go(
    {},
    (send) => async (request) =>
      request.method === "GET" && path(request).endsWith("/functions/pcblock")
        ? error(400, "INVALID_ARGUMENT")
        : send(request),
  );
  assert.ok(result.incompleteReads.some((r) => r.id === "readback-function" && r.class === "4xx"));
  assert.equal(result.closureReady, false);
});

test("an unreadable sign-up answer is not an account id and leaves the account unconfirmed", async () => {
  const { result, world } = await go(
    {},
    (send) => async (request) =>
      path(request) === "/v1/accounts:signUp"
        ? (await send(request), new Response("<html>", { status: 200 }))
        : send(request),
  );
  assert.equal(result.signUp.localId, null);
  assert.deepEqual(
    result.unconfirmedCreates.map((c) => c.label),
    ["account"],
  );
  assert.ok(!world.calls.some((c) => c.endsWith("accounts:delete")));
  assert.equal(result.cleanup.verified, false, "the account count differs");
});

// ---- the cleanup, step by step -------------------------------------------------------------------------------

test("a count answered without recordsCount counts as zero", async () => {
  const { result } = await go(
    {},
    (send) => async (request) =>
      path(request).endsWith("accounts:query") ? reply(200, {}) : send(request),
  );
  assert.equal(result.inventory.before.accounts, 0);
  assert.equal(result.cleanup.accountsAfter, 0);
  assert.equal(result.cleanup.verified, true);
});

test("each cleanup step that fails is named, the rest run, and the cleanup is not verified", async () => {
  const pkg = packageIds()[0];
  for (const [id, step, options] of [
    ["cleanup-account-delete", "account-delete", {}],
    ["leftover-delete-function", "leftover-function", { leaveOnDelete: true }],
    [`delete-package-${pkg}`, "package-" + pkg, {}],
    ["readback-gone-function", "readback-function", {}],
    ["readback-gone-account", "readback-account", {}],
    ["final-functions-v2", "final-lists", {}],
    ["config-after", "config-after", {}],
    ["accounts-after", "accounts-after", {}],
    ["inventory-source-objects-uploads", "source-objects", {}],
    ["iam-after", "inventory", {}],
  ]) {
    const world = createWorld({ runId: RUN, ...options });
    const result = await record({
      runId: RUN,
      projectNumber: NUMBER,
      accessToken: "tok-abcdefgh",
      runCli: world.runCli,
      clock: () => world.now,
      sleep: async (ms) => world.advance(ms),
      send: world.send,
      save: async (row) => {
        if (row.id === id && row.state === "before-send") throw new Error("disk full");
      },
    });
    assert.deepEqual(
      result.cleanup.errors.map((e) => e.step),
      [step],
      id,
    );
    assert.match(result.cleanup.error, /persistence failed/);
    assert.equal(result.closureReady, false, id);
  }
});

test("a function that is still listed after its delete is polled up to four times, thirty seconds apart", async () => {
  for (const stale of [2, 9]) {
    let deleted = null;
    let served = 0;
    const { journal, sleeps, result } = await go(
      { leaveOnDelete: true },
      (send, world) => async (request) => {
        if (request.method === "DELETE" && path(request).endsWith("/functions/pcblock"))
          deleted = structuredClone(world.functions.get(functionName()));
        const response = await send(request);
        if (
          deleted &&
          request.method === "GET" &&
          path(request).endsWith("/locations/-/functions") &&
          served < stale
        ) {
          served++;
          const body = await response.json();
          return reply(200, { functions: [...(body.functions ?? []), deleted] });
        }
        return response;
      },
    );
    const polls = ids(journal).filter(
      (id) => id.startsWith("after-leftover-") && id.endsWith("-functions-v2"),
    );
    assert.deepEqual(
      polls,
      Array.from(
        { length: Math.min(stale + 1, 4) },
        (_, n) => `after-leftover-${n + 1}-functions-v2`,
      ),
      "stale " + stale,
    );
    assert.equal(
      sleeps.filter((ms) => ms === 30_000).length,
      6 + Math.min(stale, 4),
      "stale " + stale,
    );
    assert.equal(result.cleanup.functionGone, stale < 4);
  }
});

test("an image delete that comes back unfinished is polled until done, at most six times, ten seconds apart; each kind of answer", async () => {
  const id = packageIds()[0];
  const make = (reply_) =>
    go({}, (send) => async (request) => {
      if (request.method === "DELETE" && path(request).endsWith(id)) {
        await send(request);
        return reply_;
      }
      if (request.method === "GET" && path(request).endsWith("/operations/pk-1"))
        return reply(200, { name: "x", done: false });
      return send(request);
    });
  const pending = await make(
    reply(200, {
      name: "projects/fireemu-oracle-idp/locations/us-central1/operations/pk-1",
      done: false,
    }),
  );
  assert.deepEqual(
    ids(pending.journal)
      .filter((x) => x.startsWith("package-operation"))
      .map((x) => x.split("-").at(-1)),
    ["1", "2", "3", "4", "5", "6"],
  );
  assert.equal(pending.sleeps.filter((ms) => ms === 10_000).length, 6);
  for (const answer of [
    reply(200, { done: false }),
    reply(200, {
      name: "projects/fireemu-oracle-idp/locations/us-central1/operations/pk-1",
      done: true,
    }),
    error(500, "INTERNAL"),
  ]) {
    const other = await make(answer);
    assert.equal(ids(other.journal).filter((x) => x.startsWith("package-operation")).length, 0);
  }
});

test("a stop signal does not stop the cleanup: every kind of cleanup request is sent after it", async () => {
  const signal = { aborted: false };
  const { result, world } = await go(
    { leaveOnDelete: true },
    (send) => async (request) => {
      if (path(request) === "/v1/accounts:signUp") signal.aborted = true;
      if (request.method === "DELETE" && path(request).endsWith(packageIds()[0])) {
        await send(request);
        return reply(200, {
          name: "projects/fireemu-oracle-idp/locations/us-central1/operations/pk-1",
          done: false,
        });
      }
      return send(request);
    },
    { signal },
  );
  assert.equal(result.cleanup.errors, undefined);
  assert.equal(result.cleanup.verified, true);
  assert.equal(world.functions.size + world.packages.size, 0);
});

test("a 401 after the CLI delete started is the last request, and the CLI delete is not run twice", async () => {
  let fired = false;
  let after = 0;
  const { result, world } = await go({}, (send, w) => async (request) => {
    if (fired) after++;
    if (
      !fired &&
      request.method === "GET" &&
      path(request).endsWith("/locations/-/functions") &&
      w.cliRuns.includes("delete")
    ) {
      fired = true;
      return error(401, "UNAUTHENTICATED");
    }
    return send(request);
  });
  assert.equal(result.outcome, "pcblock-auth-stop");
  assert.equal(after, 0);
  assert.equal(world.cliRuns.filter((a) => a === "delete").length, 1);
});

test("lists that cannot be read in the cleanup leave the function not gone, and an unreadable image list leaves nothing verified", async () => {
  const lists = await go(
    {},
    (send, world) => async (request) =>
      request.method === "GET" &&
      path(request).endsWith("/locations/-/functions") &&
      world.cliRuns.includes("delete")
        ? error(500, "INTERNAL")
        : send(request),
  );
  assert.equal(lists.result.cleanup.functionGone, false);
  assert.equal(lists.result.cleanup.verified, false);
  const runs = await go(
    {},
    (send, world) => async (request) =>
      request.method === "GET" &&
      path(request).endsWith("/locations/-/services") &&
      world.cliRuns.includes("delete")
        ? error(500, "INTERNAL")
        : send(request),
  );
  assert.equal(runs.result.cleanup.verified, false);
  const packages = await go(
    {},
    (send, world) => async (request) =>
      request.method === "GET" &&
      path(request).endsWith("/packages") &&
      world.cliRuns.includes("delete")
        ? error(500, "INTERNAL")
        : send(request),
  );
  assert.equal(packages.result.cleanup.listsEmpty, false);
  assert.equal(packages.result.cleanup.verified, false);
  const stillListed = await go({}, (send, world) => async (request) => {
    const response = await send(request);
    if (
      request.method === "GET" &&
      path(request).endsWith("/locations/-/services") &&
      ids([]).length === 0 &&
      world.cliRuns.includes("delete") &&
      request.url.length
    ) {
      const body = await response.json();
      return reply(200, {
        services: [
          ...(body.services ?? []),
          { name: "projects/p/locations/us-central1/services/pcblock" },
        ],
      });
    }
    return response;
  });
  assert.equal(stillListed.result.cleanup.functionGone, false);
});

test("an error after the function was issued but before the deploy is recorded and the cleanup runs", async () => {
  const world = createWorld({ runId: RUN });
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    runCli: world.runCli,
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
    send: world.send,
    save: async (row) => {
      if (row.id === "cli-deploy") throw new Error("disk full");
    },
  });
  assert.equal(result.stoppedBecause, "disk full");
  assert.equal(result.outcome, "pcblock-incomplete-clean");
  const early = createWorld({ runId: RUN });
  const r2 = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    runCli: early.runCli,
    clock: () => early.now,
    sleep: async (ms) => early.advance(ms),
    send: early.send,
    save: async (row) => {
      if (row.id === "issue-function") throw new Error("disk full");
    },
  });
  assert.equal(r2.stoppedBecause, "disk full");
  assert.deepEqual(early.cliRuns, ["dry-run"]);
  assert.equal(
    r2.outcome,
    "pcblock-incomplete-clean",
    "the function was issued, so this is a cleaned-up run, not a stop before anything exists",
  );
});

test("a CLI delete that did not finish cleanly makes the CLI-made function look vanished, a clean one does not", async () => {
  for (const flaw of [{ exitCode: 1 }, { timedOut: true }, { signal: "SIGTERM" }, { error: "x" }]) {
    const { result } = await go(
      {},
      (send) => send,
      {},
      (cli) => async (o) => (o.action === "delete" ? { ...(await cli(o)), ...flaw } : cli(o)),
    );
    assert.deepEqual(
      result.vanishedAfterCreate.map((v) => v.label),
      ["function"],
      JSON.stringify(flaw),
    );
    assert.equal(result.closureReady, false);
  }
  const good = await go();
  assert.deepEqual(good.result.vanishedAfterCreate, []);
  const rest = await go(
    { leaveOnDelete: true },
    (send) => send,
    {},
    (cli) => async (o) => (o.action === "delete" ? { ...(await cli(o)), exitCode: 1 } : cli(o)),
  );
  assert.deepEqual(rest.result.vanishedAfterCreate, [], "deleted by the REST cleanup itself");
});

test("the inventory notes the services and IAM changes, and nothing when a read failed", async () => {
  let phase = 0;
  const { result } = await go({}, (send) => async (request) => {
    if (request.url.includes("serviceusage") && ++phase === 2) return error(500, "INTERNAL");
    return send(request);
  });
  assert.equal(result.inventory.services, null);
  let added = 0;
  const changed = await go(
    {},
    (send) => async (request) =>
      request.url.includes("serviceusage") && ++added === 2
        ? reply(200, { services: [{ config: { name: "extra.googleapis.com" } }] })
        : send(request),
  );
  assert.deepEqual(changed.result.inventory.services.added, ["extra.googleapis.com"]);
  assert.ok(changed.result.inventory.services.removed.length > 0);
  const source = await go({}, (send, world) => async (request) => {
    if (
      request.method === "GET" &&
      request.url.includes("gcf-v2-uploads") &&
      world.cliRuns.includes("delete")
    )
      world.sourceBuckets.get(request.url.split("/b/")[1].split("/o")[0]).splice(0, 1);
    return send(request);
  });
  assert.deepEqual(source.result.inventory.sourceObjects.uploads.removed, ["old-upload.zip"]);
  assert.equal(source.result.inventory.sourceObjects.uploads.added.length, 1);
});

// ---- the judge, the guard and the command line ----------------------------------------------------------

test("a one-character account id is an id, and the verdicts keep what they expected", () => {
  const frames = JSON.parse(
    JSON.stringify(productionFrames({ runId: RUN, localId: LOCAL_ID })),
  ).map((frame) => ({ frame }));
  const observed = {
    signUp: { class: "2xx", status: 200, localId: "x" },
    registration: null,
    invoker: null,
  };
  assert.equal(
    judge({ email: emailOf(RUN), localId: null, frames, observed }).cases["signup-allowed"].status,
    "as-expected",
  );
  const r = judge({
    email: emailOf(RUN),
    localId: LOCAL_ID,
    frames,
    observed: { ...observed, signUp: { ...observed.signUp, localId: LOCAL_ID } },
  });
  assert.deepEqual(r.cases["blocking-sdk"].expected, {
    eventType: "names beforeCreate",
    isNewUser: true,
  });
  const rawOnly = judge({
    email: emailOf(RUN),
    localId: LOCAL_ID,
    frames: frames.filter((e) => e.frame.kind === "blocking-raw"),
    observed,
  });
  assert.deepEqual(rawOnly.cases["blocking-sdk"].expected, { sdkRan: true });
});

test("the guard: a one-character page token, and a URL with only a user name, only a password or only a fragment", () => {
  const g = createGuard(RUN, NUMBER);
  const base = `https://cloudfunctions.googleapis.com/v2/projects/${PROJECT}/locations/-/functions`;
  assert.equal(g.allow({ method: "GET", url: `${base}?pageToken=a` }), true);
  assert.equal(g.allow({ method: "GET", url: base }), true);
  assert.equal(g.allow({ method: "GET", url: base.replace("https://", "https://user@") }), false);
  assert.equal(g.allow({ method: "GET", url: base.replace("https://", "https://:pw@") }), false);
  assert.equal(g.allow({ method: "GET", url: base + "#f" }), false);
  assert.equal(
    g.allow({
      method: "GET",
      url: `https://storage.googleapis.com/storage/v1/b/${sourceBuckets(NUMBER)[0]}/o?maxResults=1000`,
    }),
    true,
  );
});

test("the web config key has a length range of 20 to 64 characters", () => {
  const read = (apiKey) => readApiKey("/w", () => JSON.stringify({ projectId: PROJECT, apiKey }));
  assert.equal(read("a".repeat(19)).error, "the web config has no usable apiKey");
  assert.deepEqual(read("a".repeat(20)), { apiKey: "a".repeat(20) });
  assert.deepEqual(read("a".repeat(64)), { apiKey: "a".repeat(64) });
  assert.equal(read("a".repeat(65)).error, "the web config has no usable apiKey");
});

test("the read-back's exit codes and messages for a bad project number, a gate and an early run", async () => {
  const d = mkdtempSync(join(tmpdir(), "pcb-gap-"));
  const at = Date.parse("2026-11-05T00:00:00Z");
  writeFileSync(
    join(d, `journal-${RUN}.jsonl`),
    JSON.stringify({ dispatchAt: new Date(at).toISOString() }) + "\n",
  );
  writeFileSync(
    join(d, `result-${RUN}.json`),
    JSON.stringify({
      unconfirmedCreates: [],
      signUp: { localId: null },
      inventory: { before: { accounts: 1 } },
      configBefore: { sha256: "c".repeat(64) },
    }),
  );
  const D = "d".repeat(64);
  const err = [];
  const base = {
    token: () => "tok-abcdefgh",
    readback: async () => ({ allAbsent: true, attempted: 0, unknown: 0 }),
    now: () => at + SETTLE_MS + 1000,
  };
  const call = (argv, deps = base) =>
    main(argv, { env: { HOME: "/h" }, deps, out: () => {}, err: (m) => err.push(m), digest: D });
  const rb = (n, extra = []) => [
    "readback",
    "--run-dir",
    d,
    "--project-number",
    n,
    "--run-id",
    RUN,
    ...extra,
  ];
  assert.equal(await call(rb("12345678901234", ["--send", "--expect-digest", D])), 2);
  assert.match(err.at(-1), /--project-number is 12 or 13 digits/);
  assert.equal(await call(rb("123456789012")), 2);
  assert.equal(
    await call(rb("123456789012", ["--send", "--expect-digest", D]), {
      ...base,
      now: () => at + 1000,
    }),
    2,
  );
  assert.equal(await call(rb("123456789012", ["--send", "--expect-digest", D])), 0);
  const empty = { ...base, readback: async () => ({ allAbsent: false, attempted: 0, unknown: 0 }) };
  assert.equal(
    await call(rb("123456789012", ["--send", "--expect-digest", D]), {
      ...empty,
      now: () => at + SETTLE_MS + 2000,
    }),
    3,
  );
  assert.equal(await call(["deploy"]), 2);
  assert.equal(await call(["check", "x"]), 2);
  const env = { GOOGLE_APPLICATION_CREDENTIALS: "x", HOME: "/h" };
  const refused = [];
  assert.equal(
    await main(rb("123456789012", ["--send", "--expect-digest", D]), {
      env,
      deps: base,
      out: () => {},
      err: (m) => refused.push(m),
      digest: D,
    }),
    2,
  );
  assert.match(refused.join(), /GOOGLE_APPLICATION_CREDENTIALS is set/);
  assert.deepEqual(localChecks({ values: {}, env: {}, deps: {} }).slice(-1), ["HOME is not set"]);
});

// ---- second pass ----------------------------------------------------------------------------------------

test("the function is confirmed by a list that shows it, and stays unconfirmed when nothing does", async () => {
  const timedOut = (cli) => async (o) =>
    o.action === "deploy" ? { ...(await cli(o)), timedOut: true } : cli(o);
  const hideRead = (send) => async (request) =>
    request.method === "GET" && path(request).endsWith("/functions/pcblock")
      ? error(404, "NOT_FOUND")
      : send(request);
  const byList = await go({}, hideRead, {}, timedOut);
  assert.deepEqual(byList.result.unconfirmedCreates, [], "the list showed it");
  const hideList = (send) => async (request) =>
    request.method === "GET" && path(request).endsWith("/locations/-/functions")
      ? reply(200, {})
      : send(request);
  const neither = await go(
    { deployState: "DEPLOYING" },
    (send) => hideRead(hideList(send)),
    { waits: { readyPolls: 1 } },
    timedOut,
  );
  assert.deepEqual(
    neither.result.unconfirmedCreates.map((c) => c.label),
    ["function"],
  );
  const listNot200 = await go(
    { deployState: "DEPLOYING" },
    (send, world) => async (request) =>
      request.method === "GET" &&
      path(request).endsWith("/locations/-/functions") &&
      world.cliRuns.includes("deploy")
        ? reply(202, { functions: [{ name: functionName() }] })
        : hideRead(send)(request),
    { waits: { readyPolls: 1 } },
    timedOut,
  );
  assert.deepEqual(
    listNot200.result.unconfirmedCreates.map((c) => c.label),
    ["function"],
  );
});

test("the request ids of every list and phase are the packet's", async () => {
  const { journal } = await go({ leaveOnDelete: true });
  const all = ids(journal);
  for (const id of [
    "preflight-run-services",
    "ready-1-run-services",
    "cleanup-1-run-services",
    "after-leftover-1-run-services",
    "final-run-services",
    "preflight-functions-v2",
    "final-functions-v2",
    "preflight-packages",
    "cleanup-packages",
    "final-packages",
    "readback-gone-function",
    "readback-gone-account",
    "leftover-delete-function",
  ])
    assert.ok(all.includes(id), id);
});

test("a leftover function's operation reads are numbered one to twelve", async () => {
  const { journal } = await go(
    { leaveOnDelete: true },
    (send) => async (request) =>
      request.method === "GET" && path(request).includes("/operations/del-")
        ? reply(200, { name: path(request), done: false })
        : send(request),
  );
  assert.deepEqual(
    ids(journal).filter((id) => id.startsWith("leftover-operation-")),
    Array.from({ length: 12 }, (_, n) => `leftover-operation-${n + 1}`),
  );
});

test("a package operation that is done at the second read is read twice", async () => {
  let polls = 0;
  const id = packageIds()[0];
  const { journal } = await go({}, (send) => async (request) => {
    if (request.method === "DELETE" && path(request).endsWith(id)) {
      await send(request);
      return reply(200, {
        name: "projects/fireemu-oracle-idp/locations/us-central1/operations/pk-1",
        done: false,
      });
    }
    if (request.method === "GET" && path(request).endsWith("/operations/pk-1"))
      return reply(200, { name: "x", done: ++polls >= 2 });
    return send(request);
  });
  assert.equal(polls, 2);
  assert.deepEqual(
    ids(journal).filter((x) => x.startsWith("package-operation")),
    [`package-operation-${id}-1`, `package-operation-${id}-2`],
  );
});

test("a read-back step that fails leaves its name unread, not gone, and a 403 on a direct read of an absence is data", async () => {
  const world = createWorld({ runId: RUN });
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    runCli: world.runCli,
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
    send: world.send,
    save: async (row) => {
      if (row.id === "readback-gone-function" && row.state === "before-send")
        throw new Error("disk full");
    },
  });
  assert.equal(result.cleanup.readBack.function, false);
  assert.equal(result.cleanup.verified, false);
  const forbidden = await go(
    {},
    (send, w) => async (request) =>
      request.method === "GET" &&
      path(request).endsWith("/functions/pcblock") &&
      w.cliRuns.includes("delete")
        ? error(403, "PERMISSION_DENIED")
        : send(request),
  );
  assert.notEqual(forbidden.result.outcome, "pcblock-auth-stop");
  assert.equal(forbidden.result.cleanup.readBack.function, false);
  assert.equal(forbidden.result.cleanup.verified, false);
});

test("a single incomplete read, with the cleanup verified, still keeps the run from closing", async () => {
  let served = false;
  const { result } = await go({}, (send) => async (request) => {
    if (!served && request.method === "GET" && path(request).endsWith("/functions/pcblock")) {
      served = true;
      return error(400, "INVALID_ARGUMENT");
    }
    return send(request);
  });
  assert.equal(result.incompleteReads.length, 1);
  assert.equal(result.cleanup.verified, true);
  assert.equal(result.closureReady, false);
  assert.equal(result.readBackRequired, false);
  assert.equal(result.outcome, "pcblock-needs-review");
});

test("a source bucket that could not be read before the run, and can after it, gives no comparison and no cleanup error", async () => {
  let first = true;
  const { result } = await go({}, (send) => async (request) => {
    if (request.url.includes("gcf-v2-sources") && first) {
      first = false;
      return error(403, "PERMISSION_DENIED");
    }
    return send(request);
  });
  assert.equal(result.inventory.sourceObjects.sources, null);
  assert.equal(result.cleanup.errors, undefined);
  assert.ok(result.inventory.sourceObjects.uploads);
});

test("an image list that cannot be read in the preflight stops the run, and a list past five pages is recorded", async () => {
  const stop = await go(
    {},
    (send) => async (request) =>
      request.method === "GET" && path(request).endsWith("/packages")
        ? error(500, "INTERNAL")
        : send(request),
  );
  assert.equal(stop.result.stoppedBecause, "lists");
  assert.equal(stop.result.outcome, "pcblock-stopped-clean");
  let n = 0;
  const pages = await go(
    {},
    (send) => async (request) =>
      request.method === "GET" && path(request).endsWith("/packages") && n < 9
        ? (n++, reply(200, { nextPageToken: "t" + n }))
        : send(request),
  );
  assert.equal(pages.result.stoppedBecause, "lists");
  assert.ok(
    pages.result.incompleteReads.some(
      (r) => r.id === "preflight-packages" && r.class === "more-than-five-pages",
    ),
  );
});

test("a stopped run reports no errors seen, and a CLI delete row is journaled", async () => {
  const stopped = await go({ baselineBlocking: { triggers: { beforeCreate: {} } } });
  assert.equal(stopped.result.errorsSeen, 0);
  const { journal } = await go();
  assert.ok(journal.some((r) => r.id === "cli-delete" && r.state === "cli-result"));
});

test("a configuration read that fails after the cleanup is neither equal nor empty", async () => {
  const { result } = await go(
    {},
    (send, world) => async (request) =>
      request.method === "GET" &&
      path(request).endsWith("/config") &&
      world.cliRuns.includes("delete")
        ? error(500, "INTERNAL")
        : send(request),
  );
  assert.equal(result.cleanup.configAfterEmptyBlocking, null);
});

test("the read-back's pages and ids, its two lists, the package names and the account count", async () => {
  const { readbackRun } = await import("./readback.mjs");
  const world = createWorld({ runId: RUN });
  const run = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    send: world.send,
    runCli: world.runCli,
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
  });
  const baseline = {
    localId: run.signUp.localId,
    accountsBefore: run.inventory.before.accounts,
    configBeforeDigest: run.configBefore.sha256,
  };
  const read = async (send) => {
    const rows = [];
    const out = await readbackRun({
      runId: RUN,
      projectNumber: NUMBER,
      accessToken: "tok-abcdefgh",
      save: async (r) => rows.push(r),
      send,
      clock: () => world.now,
      ...baseline,
    });
    return { out, ids: rows.filter((r) => r.state === "before-send").map((r) => r.id) };
  };
  const clean = await read(world.send);
  for (const id of [
    "readback-function",
    "readback-account",
    `readback-package-${packageIds()[0]}`,
    "list-functions-v2",
    "list-run-services",
    "list-packages",
    "read-config",
    "read-accounts",
  ])
    assert.ok(clean.ids.includes(id), id);
  let pageCalls = 0;
  const paged = await read(async (request) => {
    if (request.method === "GET" && path(request).endsWith("/packages") && pageCalls++ === 0)
      return reply(200, { nextPageToken: "t" });
    return world.send(request);
  });
  assert.ok(paged.ids.includes("list-packages-page-2"));
  assert.ok(!paged.ids.includes("list-packages-page-3"));
  const noRun = await read(async (request) =>
    request.method === "GET" && path(request).endsWith("/locations/-/services")
      ? reply(500, { error: { status: "INTERNAL" } })
      : world.send(request),
  );
  assert.equal(noRun.out.lists.functionAndService, false);
  assert.equal(noRun.out.allAbsent, false);
  const listed = await read(async (request) => {
    if (request.method === "GET" && path(request).endsWith("/packages"))
      return reply(200, {
        packages: [
          { name: `projects/p/locations/l/repositories/gcf-artifacts/packages/${packageIds()[1]}` },
          { name: "projects/p/locations/l/repositories/gcf-artifacts/packages/other" },
        ],
      });
    return world.send(request);
  });
  assert.deepEqual(listed.out.lists.packages, [packageIds()[1]]);
  assert.equal(listed.out.allAbsent, false);
  for (const [answer, after] of [
    [() => reply(500, { error: { status: "INTERNAL" } }), null],
    [() => reply(200, {}), 0],
  ]) {
    const counted = await read(async (request) =>
      request.method === "POST" && path(request).endsWith("accounts:query")
        ? answer()
        : world.send(request),
    );
    assert.equal(counted.out.accounts.after, after);
    assert.equal(counted.out.allAbsent, false);
  }
});

test("the read-back refuses to run for a missing journal with exit code 2", async () => {
  const d = mkdtempSync(join(tmpdir(), "pcb-gap2-"));
  const code = await main(
    [
      "readback",
      "--run-dir",
      d,
      "--project-number",
      "123456789012",
      "--run-id",
      RUN,
      "--send",
      "--expect-digest",
      "d".repeat(64),
    ],
    {
      env: { HOME: "/h" },
      deps: { token: () => "tok-abcdefgh", now: () => Date.now() },
      out: () => {},
      err: () => {},
      digest: "d".repeat(64),
    },
  );
  assert.equal(code, 2);
});

test("an empty blocking section is the same whichever of its three forms the CLI leaves, and the form is recorded", async () => {
  for (const deleteLeaves of [{}, { triggers: {} }]) {
    const { result } = await go({ deleteLeaves });
    assert.deepEqual(result.cleanup.configDifference, [], JSON.stringify(deleteLeaves));
    assert.equal(result.cleanup.configRestored, true);
    assert.equal(result.outcome, "pcblock-recorded");
    assert.deepEqual(result.cleanup.blockingForm, {
      before: "null",
      after: JSON.stringify(deleteLeaves),
    });
  }
  const other = await go({
    deleteLeaves: { triggers: {}, forwardInboundCredentials: { idToken: true } },
  });
  assert.deepEqual(other.result.cleanup.configDifference, ["blockingFunctions"]);
  assert.equal(other.result.outcome, "pcblock-needs-recovery");
  assert.deepEqual(normalizedConfig({ a: 1, blockingFunctions: {} }), { a: 1 });
  assert.deepEqual(
    normalizedConfig({ a: 1, blockingFunctions: { triggers: { beforeCreate: {} } } }),
    { a: 1, blockingFunctions: { triggers: { beforeCreate: {} } } },
  );
  assert.equal(normalizedConfig(null), null);
  assert.equal(configDigest({ a: 1 }), configDigest({ a: 1, blockingFunctions: {} }));
  assert.notEqual(
    configDigest({ a: 1 }),
    configDigest({ a: 1, blockingFunctions: { triggers: { x: 1 } } }),
  );
});

test("a 403 on the account lookup of the cleanup is data, and the raw-only verdict keeps its observation", async () => {
  const { result } = await go(
    {},
    (send) => async (request) =>
      path(request).endsWith("accounts:lookup") ? error(403, "PERMISSION_DENIED") : send(request),
  );
  assert.notEqual(result.outcome, "pcblock-auth-stop");
  assert.equal(result.cleanup.readBack.account, false);
  const frames = JSON.parse(
    JSON.stringify(productionFrames({ runId: RUN, localId: LOCAL_ID })),
  ).map((frame) => ({ frame }));
  const raw = judge({
    email: emailOf(RUN),
    localId: LOCAL_ID,
    frames: frames.filter((e) => e.frame.kind === "blocking-raw"),
    observed: {
      signUp: { class: "2xx", status: 200, localId: LOCAL_ID },
      registration: null,
      invoker: null,
    },
    errors: [{ function: "pcblock", text: "t" }],
  });
  assert.deepEqual(raw.cases["blocking-sdk"].observed, { rawDelivered: true, errors: 1 });
});

test("a configuration that cannot be read after the cleanup records no blocking form", async () => {
  const { result } = await go(
    {},
    (send, world) => async (request) =>
      request.method === "GET" &&
      path(request).endsWith("/config") &&
      world.cliRuns.includes("delete")
        ? error(500, "INTERNAL")
        : send(request),
  );
  assert.equal(result.cleanup.blockingForm, undefined);
});
