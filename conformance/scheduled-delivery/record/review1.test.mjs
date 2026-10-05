// The first presend review's findings for the orchestrator: every cleanup step stands alone (M3), a CLI run that
// timed out or died is an unknown answer (S1), the direct read-back and the ownership filter decide (S2), an
// unreadable adminSdkConfig stops (S4), a signal moves to the cleanup (S5), the services are read again (S8), and a
// rejected credential still lets the one CLI delete run (S10).
import assert from "node:assert/strict";
import test from "node:test";
import { functionName, scheduleId } from "./plan.mjs";
import { record } from "./run.mjs";
import { NUMBER, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const P = "/v1/projects/fireemu-oracle-sbx";
const error = (code, status) => reply(code, { error: { code, message: "x", status } });
const SHORT = { passes: 1, naturalWindowMs: 60_000 };
const FN = (v, name) =>
  `cloudfunctions.googleapis.com/${v}/projects/fireemu-oracle-sbx/locations/us-central1/functions/${name}`;
const JOBS = "cloudscheduler.googleapis.com" + P + "/locations/us-central1/jobs";
const empty = (w) =>
  w.jobs.size +
    w.topics.size +
    w.subs.size +
    w.functionsV1.size +
    w.functionsV2.size +
    w.runServices.size ===
  0;

async function go(worldOptions = {}, options = {}, { cli } = {}) {
  const world = createWorld(worldOptions);
  const journal = [];
  const sleeps = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "test-token",
    save: async (row) => journal.push(row),
    send: world.send,
    runCli: async (o) => (cli ? cli(o, world) : world.runCli(o)),
    clock: () => world.now,
    sleep: async (ms) => {
      sleeps.push(ms);
      world.advance(ms);
    },
    ...options,
  });
  return { world, journal, sleeps, result };
}
const ids = (journal) => journal.filter((r) => r.state === "before-send").map((r) => r.id);
const stepsFailed = (result) => (result.cleanup.errors ?? []).map((e) => e.step);

test("a refused request in one cleanup step does not skip the later steps (M3)", async () => {
  // The leftover's delete answers with an operation name the allowlist refuses; the cleanup still goes on.
  const { result, world, journal } = await go(
    {
      leaveOnDelete: ["schedOkV1"],
      hooks: {
        ["DELETE " + FN("v1", "schedOkV1")]: async ({ w }) => {
          w.functionsV1.delete(functionName("schedOkV1"));
          return reply(200, { name: "operations/a+b", done: false });
        },
      },
    },
    SHORT,
  );
  assert.deepEqual(stepsFailed(result), ["leftover-schedOkV1"]);
  assert.match(result.cleanup.error, /request not allowed/);
  assert.ok(ids(journal).includes("final-jobs") && ids(journal).includes("iam-after"));
  assert.ok(empty(world));
  assert.equal(result.cleanup.verified, true);
  assert.equal(result.closureReady, false, "a cleanup with an error never closes");
});

test("a throwing CLI delete is an unknown answer, and the REST cleanup still runs (M3, S1)", async () => {
  const { result, world } = await go({}, SHORT, {
    cli: async (o, w) => {
      if (o.action === "delete") throw new Error("spawn failed");
      return w.runCli(o);
    },
  });
  assert.deepEqual(stepsFailed(result), ["cli-delete"]);
  assert.deepEqual(result.unknownMutationList, [{ id: "cli-delete", class: "cli-error" }]);
  assert.equal(result.readBackRequired, true);
  assert.equal(result.closureReady, false);
  assert.ok(
    world.calls.some((c) => c.startsWith("DELETE cloudfunctions")),
    "the leftovers are deleted through REST",
  );
  assert.ok(empty(world));
  assert.equal(result.cleanup.verified, true);
});

test("a failed write of one journal row skips only its own step (M3)", async () => {
  let failed = false;
  const rows = [];
  const { result, world } = await go(
    { leaveOnDelete: ["schedOkV2"] },
    {
      ...SHORT,
      save: async (row) => {
        if (
          !failed &&
          row.state === "before-send" &&
          row.id === "delete-job-0-schedOkV2-us-central1"
        ) {
          failed = true;
          throw new Error("disk");
        }
        rows.push(row);
      },
    },
  );
  assert.deepEqual(stepsFailed(result), ["job-firebase-schedule-schedOkV2-us-central1"]);
  assert.equal(world.jobs.size, 1, "that job stays; the CLI delete had removed the others");
  assert.ok(ids(rows).includes("final-jobs"), "the later steps ran");
  assert.equal(result.cleanup.verified, false);
});

for (const [name, result, cls] of [
  [
    "a timed-out deploy",
    { timedOut: true, exitCode: null, signal: "SIGKILL", error: null },
    "cli-timeout",
  ],
  [
    "a CLI that could not be run",
    { timedOut: false, exitCode: null, signal: null, error: "spawn" },
    "cli-error",
  ],
  [
    "a CLI killed by a signal",
    { timedOut: false, exitCode: null, signal: "SIGKILL", error: null },
    "cli-signal",
  ],
]) {
  test(`${name} is an unknown answer that needs the read-back (S1)`, async () => {
    const out = await go({}, SHORT, {
      cli: async (o, w) => {
        const real = await w.runCli(o);
        return o.action === "deploy" ? { ...real, ...result, errored: null } : real;
      },
    });
    assert.deepEqual(
      out.result.unknownMutationList.map((u) => [u.id, u.class]),
      [["cli-deploy", cls]],
    );
    assert.equal(out.result.readBackRequired, true);
    assert.equal(out.result.closureReady, false);
    assert.equal(out.result.cleanup.verified, true);
  });
}

test("a timed-out CLI delete is a sticky unknown DELETE (S1)", async () => {
  const { result } = await go({}, SHORT, {
    cli: async (o, w) => {
      const real = await w.runCli(o);
      return o.action === "delete"
        ? { ...real, timedOut: true, exitCode: null, signal: "SIGKILL" }
        : real;
    },
  });
  assert.deepEqual(result.unknownMutationList, [{ id: "cli-delete", class: "cli-timeout" }]);
  assert.equal(result.closureReady, false);
});

test("lists that read empty do not settle a name that a direct read still shows (S2a)", async () => {
  for (const answer of [
    () => reply(200, { name: functionName("schedOkV2") }),
    () => error(503, "UNAVAILABLE"),
  ]) {
    const { result } = await go(
      {
        hooks: {
          ["GET " + FN("v2", "schedOkV2")]: async ({ w }) =>
            w.cliRuns.includes("delete") ? answer() : undefined,
        },
      },
      SHORT,
    );
    assert.equal(result.cleanup.listsEmpty, true);
    assert.equal(result.cleanup.readBack["function-schedOkV2"], false);
    assert.equal(result.cleanup.verified, false);
    assert.equal(result.outcome, "calendar-delivery-needs-recovery");
  }
});

test("a job that is not one of the eight is never deleted, and does not stop the cleanup (S2b)", async () => {
  const foreign = "firebase-schedule-other-us-central1";
  const { result, world, journal } = await go({}, SHORT, {
    cli: async (o, w) => {
      const real = await w.runCli(o);
      if (o.action === "delete")
        w.jobs.set(foreign, {
          name: "projects/fireemu-oracle-sbx/locations/us-central1/jobs/" + foreign,
        });
      return real;
    },
  });
  assert.equal(
    world.calls.some((c) => c.startsWith("DELETE") && c.endsWith(foreign)),
    false,
  );
  assert.ok(world.jobs.has(foreign));
  assert.equal(result.cleanup.listsEmpty, false);
  assert.equal(result.cleanup.verified, false);
  assert.ok(ids(journal).includes("final-jobs") && ids(journal).includes("services-after"));
  assert.equal(result.cleanup.errors, undefined);
});

test("a cleanup read-back that cannot be sent leaves the name unread, which is not absent (S2a)", async () => {
  let failed = false;
  const { result } = await go(
    {},
    {
      ...SHORT,
      save: async (row) => {
        if (
          !failed &&
          row.state === "before-send" &&
          row.id === "readback-gone-function-schedFailV1"
        ) {
          failed = true;
          throw new Error("disk");
        }
      },
    },
  );
  assert.equal(result.cleanup.readBack["function-schedFailV1"], false);
  assert.equal(result.cleanup.verified, false);
  assert.deepEqual(stepsFailed(result), ["readback-function-schedFailV1"]);
});

test("an unreadable adminSdkConfig of any kind stops at preflight (S4)", async () => {
  const key = "GET firebase.googleapis.com/v1beta1/projects/fireemu-oracle-sbx/adminSdkConfig";
  for (const answer of [
    () => error(503, "UNAVAILABLE"),
    () => error(403, "PERMISSION_DENIED"),
    () => new Response("x", { status: 200 }),
  ]) {
    const { result, world } = await go({ hooks: { [key]: async () => answer() } });
    assert.equal(result.stoppedBecause, "admin-sdk-config");
    assert.deepEqual(world.cliRuns, []);
  }
});

test("a signal after the deploy stops at the next request and runs the cleanup (S5)", async () => {
  const signal = { aborted: false };
  const { result, world } = await go(
    {},
    {
      ...SHORT,
      signal,
      save: async (row) => {
        if (row.state === "before-send" && row.id === "readback-jobs") signal.aborted = true;
      },
    },
  );
  assert.equal(result.stoppedBecause, "stopped by a signal");
  assert.deepEqual(result.passes, []);
  assert.equal(result.cleanup.verified, true);
  assert.equal(result.outcome, "calendar-delivery-incomplete-clean");
  assert.deepEqual(world.cliRuns, ["dry-run", "deploy", "delete"]);
  assert.ok(empty(world));
});

test("a signal before anything exists is a clean stop that throws nothing", async () => {
  const signal = { aborted: true };
  const { result, world } = await go({}, { signal });
  assert.equal(result.stoppedBecause, "stopped by a signal");
  assert.equal(result.outcome, "calendar-delivery-stopped-clean");
  assert.deepEqual(world.cliRuns, []);
});

test("the enabled services are read again after the deploy and the difference is recorded (S8)", async () => {
  const { result, journal } = await go({}, SHORT, {
    cli: async (o, w) => {
      const real = await w.runCli(o);
      if (o.action === "deploy") w.services.add("containerregistry.googleapis.com");
      if (o.action === "delete") w.services.delete("storage.googleapis.com");
      return real;
    },
  });
  assert.deepEqual(result.inventory.services, {
    added: ["containerregistry.googleapis.com"],
    removed: ["storage.googleapis.com"],
  });
  const row = journal.find((r) => r.state === "before-send" && r.id === "services-after");
  assert.equal(
    row.url,
    "https://serviceusage.googleapis.com/v1/projects/" +
      NUMBER +
      "/services?filter=state:ENABLED&pageSize=200",
  );
  const bad = await go(
    {
      hooks: {
        ["GET serviceusage.googleapis.com/v1/projects/" + NUMBER + "/services"]: async ({ w }) =>
          w.cliRuns.includes("delete") ? error(503, "UNAVAILABLE") : undefined,
      },
    },
    SHORT,
  );
  assert.equal(bad.result.inventory.services, null);
});

test("a rejected credential before any deploy runs no CLI at all; after one it runs the one delete (S10)", async () => {
  const early = await go({ hooks: { ["GET " + JOBS]: async () => error(401, "UNAUTHENTICATED") } });
  assert.equal(early.result.outcome, "calendar-delivery-auth-stop");
  assert.deepEqual(early.world.cliRuns, []);
  const late = await go(
    {
      hooks: {
        ["GET " + JOBS + "/" + scheduleId("schedOkV2")]: async ({ w }) =>
          w.cliRuns.includes("deploy") ? error(401, "UNAUTHENTICATED") : undefined,
      },
    },
    SHORT,
  );
  assert.deepEqual(late.world.cliRuns, ["dry-run", "deploy", "delete"]);
  assert.equal(late.result.readBackRequired, true);
  assert.equal(late.result.closureReady, false);
  assert.ok(ids(late.journal).length > 0);
  const inCleanup = await go({
    hooks: {
      ["GET pubsub.googleapis.com" + P + "/topics"]: async ({ w }) =>
        w.cliRuns.includes("delete") ? error(401, "UNAUTHENTICATED") : undefined,
    },
  });
  assert.deepEqual(
    inCleanup.world.cliRuns,
    ["dry-run", "deploy", "delete"],
    "the delete is not repeated",
  );
});

test("a CLI delete that throws after a rejected credential is recorded and ends the run (S10)", async () => {
  const { result, world } = await go(
    {
      hooks: {
        ["GET " + JOBS + "/" + scheduleId("schedOkV2")]: async ({ w }) =>
          w.cliRuns.includes("deploy") ? error(401, "UNAUTHENTICATED") : undefined,
      },
    },
    SHORT,
    {
      cli: async (o, w) => {
        if (o.action === "delete") throw new Error("no spawn");
        return w.runCli(o);
      },
    },
  );
  assert.equal(result.outcome, "calendar-delivery-auth-stop");
  assert.deepEqual(result.unknownMutationList, [{ id: "cli-delete", class: "cli-error" }]);
  assert.deepEqual(world.cliRuns, ["dry-run", "deploy"]);
});

test("nothing created means a clean stop even when the stop is the request ceiling", async () => {
  const { result } = await go({}, { normalCeiling: 5 });
  assert.equal(result.outcome, "calendar-delivery-stopped-clean");
  assert.equal(result.closureReady, false);
});
