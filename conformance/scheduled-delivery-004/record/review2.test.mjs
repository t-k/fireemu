// What the diff-scoped mutation of the review fixes left alive: the journal row of the CLI delete, the step names a
// failure is recorded under, a final read that cannot be written leaves the lists unsettled, an unreadable list is
// an answer and not a thrown error, the settling sleeps of the cleanup, and the latest activity of a journal.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { lastActivity } from "./main.mjs";
import { functionName } from "./plan.mjs";
import { record } from "./run.mjs";
import { NUMBER, START, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const error = (code, status) => reply(code, { error: { code, message: "x", status } });
const SHORT = { passes: 1, naturalWindowMs: 60_000 };
const FN2 = (name) =>
  `cloudfunctions.googleapis.com/v2/projects/fireemu-oracle-sbx/locations/us-central1/functions/${name}`;
const LIST1 = "cloudfunctions.googleapis.com/v1/projects/fireemu-oracle-sbx/locations/-/functions";
const LIST2 = "cloudfunctions.googleapis.com/v2/projects/fireemu-oracle-sbx/locations/-/functions";
const LISTR = "run.googleapis.com/v2/projects/fireemu-oracle-sbx/locations/-/services";
const JOBS =
  "cloudscheduler.googleapis.com/v1/projects/fireemu-oracle-sbx/locations/us-central1/jobs";
const PUBSUB = "pubsub.googleapis.com/v1/projects/fireemu-oracle-sbx";

async function go(worldOptions = {}, options = {}, cli) {
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
const failOnce = (id) => {
  let failed = false;
  return async (row) => {
    if (!failed && row.state === "before-send" && row.id === id) {
      failed = true;
      throw new Error("disk");
    }
  };
};

test("the result of the CLI delete is journaled as its own row", async () => {
  const { journal } = await go({}, SHORT);
  const rows = journal.filter((r) => r.id === "cli-delete");
  assert.equal(rows.length, 1);
  assert.equal(rows[0].state, "cli-result");
  assert.equal(rows[0].result.action, "delete");
});

test("a leftover delete that returns no usable operation is not an error of its step", async () => {
  const key = "DELETE " + FN2("declNullV2");
  const gone = (w) => {
    w.functionsV2.delete(functionName("declNullV2"));
    w.runServices.delete("declnullv2");
  };
  for (const answer of [
    (w) => (gone(w), reply(200, {})),
    (w) => (gone(w), reply(200, { name: "projects/x/operations/y", done: true })),
    () => error(400, "INVALID_ARGUMENT"),
    (w) => (gone(w), reply(200, { name: 5 })),
    (w) => (gone(w), reply(200, { done: false })),
  ]) {
    const { result } = await go({
      leaveOnDelete: ["declNullV2"],
      hooks: { [key]: async ({ w }) => answer(w) },
    });
    assert.equal(result.cleanup.errors, undefined);
    assert.equal(result.cleanup.error, undefined);
  }
});

test("a failure is recorded under the name of the step that failed", async () => {
  const sub = await go({}, { ...SHORT, save: failOnce("delete-subscription-schedFailV1") });
  assert.deepEqual(
    sub.result.cleanup.errors.map((e) => e.step),
    ["subscription-schedFailV1"],
  );
  const topicAdded = async (o, w) => {
    const real = await w.runCli(o);
    if (o.action === "delete") w.topics.add("firebase-schedule-schedRetryV1-us-central1");
    return real;
  };
  const topic = await go(
    {},
    { ...SHORT, save: failOnce("topic-present-schedRetryV1") },
    topicAdded,
  );
  assert.deepEqual(
    topic.result.cleanup.errors.map((e) => e.step),
    ["topic-schedRetryV1"],
  );
});

test("lists that could not be settled stay unsettled when the final read cannot even be written", async () => {
  const { result } = await go({}, { ...SHORT, save: failOnce("final-jobs") });
  assert.equal(result.cleanup.listsEmpty, false);
  assert.equal(result.cleanup.verified, false);
  assert.deepEqual(
    result.cleanup.errors.map((e) => e.step),
    ["final-lists"],
  );
});

test("a final list that cannot be read is an answer, not a thrown error, in each of the six", async () => {
  for (const [label, key] of [
    ["final-jobs", "GET " + JOBS],
    ["final-topics", "GET " + PUBSUB + "/topics"],
    ["final-subscriptions", "GET " + PUBSUB + "/subscriptions"],
    ["final-functions-v1", "GET " + LIST1],
    ["final-functions-v2", "GET " + LIST2],
    ["final-run-services", "GET " + LISTR],
  ]) {
    const seen = { last: "" };
    const { result } = await go(
      {
        hooks: {
          [key]: async () => (seen.last.startsWith(label) ? error(500, "INTERNAL") : undefined),
        },
      },
      {
        ...SHORT,
        save: async (r) => {
          if (r.state === "before-send") seen.last = r.id;
        },
      },
    );
    assert.equal(result.cleanup.listsEmpty, false, label);
    assert.equal(result.cleanup.errors, undefined, label);
  }
});

test("a cleanup that never settles sleeps half a minute after every poll that found something", async () => {
  const { sleeps } = await go({
    leaveOnDelete: ["declNullV2"],
    hooks: {
      ["DELETE " + FN2("declNullV2")]: async () =>
        reply(200, { name: "projects/x/operations/y", done: true }),
    },
  });
  assert.equal(sleeps.filter((ms) => ms === 30_000).length, 6 + 4);
});

test("the latest request of a journal counts, wherever it stands in the file", () => {
  const dir = mkdtempSync(join(tmpdir(), "review2-"));
  try {
    const path = join(dir, "journal.jsonl");
    writeFileSync(
      path,
      [START + 8 * 60_000, START, START + 5 * 60_000]
        .map((ms) => JSON.stringify({ responseAt: new Date(ms).toISOString() }))
        .join("\n") + "\n",
    );
    assert.equal(lastActivity(path), START + 8 * 60_000);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---- the command line, the token source and the read-back ---------------------------------------------

import { main } from "./main.mjs";
import { SETTLE_MS, readbackRun } from "./readback.mjs";
import { createTokenSource } from "./token.mjs";

const DIGEST = "d".repeat(64);
const ENV = { HOME: "/home/test", PATH: "/usr/bin" };
const argv = (run, extra = [], project = NUMBER) => [
  "readback",
  "--run-dir",
  run,
  "--project-number",
  project,
  "--run-id",
  RUN,
  ...extra,
];
const sink = () => {
  const lines = [];
  return { out: (t) => lines.push(String(t)), err: (t) => lines.push("ERR " + String(t)), lines };
};
const tmp = () => mkdtempSync(join(tmpdir(), "review2-"));
const attempt = async (args, { env = ENV, now = START + SETTLE_MS } = {}) => {
  const io = sink();
  const code = await main(args, {
    env,
    deps: {
      token: () => "test-token",
      send: createWorld().send,
      readback: async () => ({ allAbsent: true, attempted: 0, unknown: 0 }),
      now: () => now,
    },
    digest: DIGEST,
    ...io,
  });
  return { code, lines: io.lines };
};

test("the read-back command's own arguments are refused each by themselves", async () => {
  const run = tmp();
  try {
    const journal = join(run, "journal-" + RUN + ".jsonl");
    writeFileSync(journal, JSON.stringify({ responseAt: new Date(START).toISOString() }) + "\n");
    writeFileSync(join(run, "result-" + RUN + ".json"), JSON.stringify({ unconfirmedCreates: [] }));
    assert.equal((await attempt(argv(run, ["--send", "--expect-digest", DIGEST]))).code, 0);
    assert.equal((await attempt(argv(run, ["--expect-digest", DIGEST]))).code, 2, "no --send");
    assert.equal(
      (await attempt(argv(run, ["--send", "--expect-digest", "e".repeat(64)]))).code,
      2,
      "another digest",
    );
    assert.equal((await attempt(argv(run, ["--send"]))).code, 2, "no digest");
    const fourteen = await attempt(
      argv(run, ["--send", "--expect-digest", DIGEST], "1".repeat(14)),
    );
    assert.equal(fourteen.code, 2);
    assert.match(fourteen.lines.at(-1), /12 or 13 digits/);
    assert.equal(
      (
        await attempt(argv(run, ["--send", "--expect-digest", DIGEST], "1".repeat(13)), {
          now: START + SETTLE_MS + 1,
        })
      ).code,
      0,
    );
    const noHome = await attempt(argv(run, ["--send", "--expect-digest", DIGEST]), {
      env: { PATH: "/usr/bin" },
    });
    assert.equal(noHome.code, 2);
    assert.match(noHome.lines.at(-1), /HOME is not set/);
    const early = await attempt(argv(run, ["--send", "--expect-digest", DIGEST]), {
      now: START + 300_000,
    });
    assert.equal(early.code, 2);
    assert.match(early.lines.at(-1), /was 300 seconds ago/);
    rmSync(journal);
    const none = await attempt(argv(run, ["--send", "--expect-digest", DIGEST]));
    assert.equal(none.code, 2);
    assert.match(none.lines.at(-1), /no journal of run/);
  } finally {
    rmSync(run, { recursive: true, force: true });
  }
});

test("a journal whose stamps are not dates has no last activity", () => {
  const dir = tmpdir();
  const path = join(mkdtempSync(join(dir, "review2-")), "journal.jsonl");
  try {
    writeFileSync(
      path,
      JSON.stringify({ responseAt: "garbage" }) +
        "\n" +
        JSON.stringify({ dispatchAt: null }) +
        "\n",
    );
    assert.equal(lastActivity(path), null);
  } finally {
    rmSync(join(path, ".."), { recursive: true, force: true });
  }
});

test("a token of 4096 characters is accepted and one of 4097 is refused", async () => {
  assert.equal(await createTokenSource({ printToken: () => "a".repeat(4096) })(), "a".repeat(4096));
  await assert.rejects(
    createTokenSource({ printToken: () => "a".repeat(4097) })(),
    /did not print/,
  );
});

const readbackWith = (worldOptions = {}, setup = () => {}, save = async () => {}) => {
  const world = createWorld(worldOptions);
  setup(world);
  return readbackRun({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "test-token",
    save,
    send: world.send,
    clock: () => world.now,
  });
};

test("the pages of a read-back list are named page by page", async () => {
  const rows = [];
  await readbackWith(
    { listPageSize: 1 },
    (w) => {
      for (let i = 0; i < 3; i++) w.topics.add("other" + i);
    },
    async (row) => rows.push(row),
  );
  const ids = rows
    .filter((r) => r.state === "before-send" && r.id.startsWith("list-topics"))
    .map((r) => r.id);
  assert.deepEqual(ids, ["list-topics", "list-topics-page-2", "list-topics-page-3"]);
});

test("a function or Cloud Run list that cannot be read is an answer: unsettled, not thrown", async () => {
  for (const key of ["GET " + LIST1, "GET " + LIST2, "GET " + LISTR]) {
    const result = await readbackWith({ hooks: { [key]: async () => error(500, "INTERNAL") } });
    assert.equal(result.lists.functionsAndServices, false, key);
    assert.equal(result.allAbsent, false, key);
    assert.equal(result.incompleteReads.length, 1, key);
  }
});

test("an exception that is not a credential stop is not swallowed by the read-back", async () => {
  await assert.rejects(
    readbackWith(
      {},
      () => {},
      async () => {
        throw new Error("disk");
      },
    ),
    /private persistence failed/,
  );
});
