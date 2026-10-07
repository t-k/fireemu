// The read-back's near misses: a name that a list still holds but that a direct read says is 404 never closes, at
// the level of the read and of the command's exit code; and the ten-minute guard is exact.
import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { main } from "./main.mjs";
import { SETTLE_MS, readbackRun } from "./readback.mjs";
import { functionName, scheduleId } from "./plan.mjs";
import { NUMBER, START, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const DIGEST = "d".repeat(64);
const ENV = { HOME: "/tmp/fireemu-test/user", PATH: "/usr/bin" };
const notFound = (what) => reply(404, { error: { code: 404, message: what, status: "NOT_FOUND" } });

// Each case: the list holds a name of the run, the direct read of that name answers 404 NOT_FOUND.
const NEAR_MISSES = [
  {
    label: "a job",
    setup: (w) =>
      w.jobs.set(scheduleId("schedOkV2"), {
        name: "projects/x/locations/y/jobs/" + scheduleId("schedOkV2"),
      }),
    hook: {
      ["GET cloudscheduler.googleapis.com/v1/projects/fireemu-oracle-sbx/locations/us-central1/jobs/" +
      scheduleId("schedOkV2")]: async () => notFound("Job not found."),
    },
  },
  {
    label: "a topic",
    setup: (w) => w.topics.add(scheduleId("schedOkV1")),
    hook: {
      ["GET pubsub.googleapis.com/v1/projects/fireemu-oracle-sbx/topics/" +
      scheduleId("schedOkV1")]: async () => notFound("topic"),
    },
  },
  {
    label: "a subscription",
    setup: (w) =>
      w.subs.set("projects/fireemu-oracle-sbx/subscriptions/fe-sd-" + RUN + "-pull-schedokv1", {
        topic: "t",
        queue: [],
      }),
    hook: {
      ["GET pubsub.googleapis.com/v1/projects/fireemu-oracle-sbx/subscriptions/fe-sd-" +
      RUN +
      "-pull-schedokv1"]: async () => notFound("subscription"),
    },
  },
  {
    label: "a function",
    setup: (w) =>
      w.functionsV2.set(functionName("schedOkV2"), {
        name: functionName("schedOkV2"),
        state: "ACTIVE",
      }),
    hook: {
      ["GET cloudfunctions.googleapis.com/v2/" + functionName("schedOkV2")]: async () =>
        notFound("function"),
    },
  },
];

for (const near of NEAR_MISSES) {
  test(`${near.label} held by a list but 404 on its direct read does not close the read-back`, async () => {
    const world = createWorld({ hooks: near.hook });
    near.setup(world);
    const result = await readbackRun({
      runId: RUN,
      projectNumber: NUMBER,
      accessToken: "test-token",
      save: async () => {},
      send: world.send,
      clock: () => world.now,
    });
    assert.ok(
      Object.values(result.names).every((n) => n.absent === true),
      "every direct read says absent",
    );
    assert.equal(result.allAbsent, false);
  });
}

const tmp = () => mkdtempSync(join(tmpdir(), "readback2-"));
const journalAt = (run, ms) =>
  writeFileSync(
    join(run, "journal-" + RUN + ".jsonl"),
    JSON.stringify({
      id: "x",
      state: "response-persisted",
      responseAt: new Date(ms).toISOString(),
    }) + "\n",
  );
const cleanResult = (run) =>
  writeFileSync(join(run, "result-" + RUN + ".json"), JSON.stringify({ unconfirmedCreates: [] }));
const args = (run) => [
  "readback",
  "--run-dir",
  run,
  "--project-number",
  NUMBER,
  "--run-id",
  RUN,
  "--send",
  "--expect-digest",
  DIGEST,
];

test("the command exits 3, not 0, for a name held by a list but 404 on its direct read", async () => {
  for (const near of NEAR_MISSES) {
    const run = tmp();
    try {
      journalAt(run, START);
      cleanResult(run);
      const world = createWorld({ hooks: near.hook });
      near.setup(world);
      const lines = [];
      const code = await main(args(run), {
        env: ENV,
        deps: {
          token: () => "test-token",
          send: world.send,
          readback: (o) => readbackRun({ ...o, clock: () => world.now }),
          now: () => START + SETTLE_MS,
        },
        digest: DIGEST,
        out: (t) => lines.push(String(t)),
        err: (t) => lines.push("ERR " + String(t)),
      });
      assert.equal(code, 3, near.label);
      assert.equal(JSON.parse(lines.at(-1)).allAbsent, false);
    } finally {
      rmSync(run, { recursive: true, force: true });
    }
  }
});

test("the ten-minute guard is exact: one millisecond short refuses without reading, the full ten minutes reads", async () => {
  for (const [offset, expected] of [
    [SETTLE_MS - 1, 2],
    [SETTLE_MS, 0],
  ]) {
    const run = tmp();
    try {
      journalAt(run, START);
      cleanResult(run);
      const world = createWorld();
      const code = await main(args(run), {
        env: ENV,
        deps: {
          token: () => "test-token",
          send: world.send,
          readback: (o) => readbackRun({ ...o, clock: () => world.now }),
          now: () => START + offset,
        },
        digest: DIGEST,
        out: () => {},
        err: () => {},
      });
      assert.equal(code, expected);
      assert.equal(world.calls.length > 0, expected === 0);
      assert.equal(
        readdirSync(run).length,
        expected === 0 ? 4 : 2,
        "journal, run result, and the read-back's two files",
      );
    } finally {
      rmSync(run, { recursive: true, force: true });
    }
  }
});

test("the guard counts from the latest request of the run, not the first, and not from the readback's own files", async () => {
  const run = tmp();
  try {
    writeFileSync(
      join(run, "journal-" + RUN + ".jsonl"),
      [START + 5 * 60_000, START, START + 8 * 60_000]
        .map((ms) =>
          JSON.stringify({
            id: "x",
            state: "response-persisted",
            responseAt: new Date(ms).toISOString(),
          }),
        )
        .join("\n") + "\n",
    );
    cleanResult(run);
    const world = createWorld();
    const attempt = (now) =>
      main(args(run), {
        env: ENV,
        deps: {
          token: () => "test-token",
          send: world.send,
          readback: (o) => readbackRun({ ...o, clock: () => world.now }),
          now: () => now,
        },
        digest: DIGEST,
        out: () => {},
        err: () => {},
      });
    assert.equal(await attempt(START + 8 * 60_000 + SETTLE_MS - 1), 2);
    assert.equal(await attempt(START + 8 * 60_000 + SETTLE_MS), 0);
    assert.equal(
      await attempt(START + 8 * 60_000 + SETTLE_MS + 1),
      0,
      "a second read-back is allowed and leaves its own files",
    );
  } finally {
    rmSync(run, { recursive: true, force: true });
  }
});
