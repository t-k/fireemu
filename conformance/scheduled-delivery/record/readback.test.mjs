// The read-only read-back (S6): which names it reads, that it sends nothing but GETs, how it judges absence, and the
// command that refuses to run before ten minutes have passed since the run's last request.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { functionName, scheduleId } from "./plan.mjs";
import { lastActivity, main } from "./main.mjs";
import {
  READBACK_MAX_REQUESTS,
  SETTLE_MS,
  readbackAllow,
  readbackNames,
  readbackRun,
} from "./readback.mjs";
import { NUMBER, START, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const error = (code, status) => reply(code, { error: { code, message: "x", status } });
const tmp = () => mkdtempSync(join(tmpdir(), "readback-test-"));

async function readback(worldOptions = {}, setup = () => {}, options = {}) {
  const world = createWorld(worldOptions);
  setup(world);
  const rows = [];
  const result = await readbackRun({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "test-token",
    save: async (row) => rows.push(row),
    send: world.send,
    clock: () => world.now,
    ...options,
  });
  return { world, rows, result };
}
const sent = (rows) => rows.filter((r) => r.state === "before-send");

test("the constants are ten minutes and sixty requests", () => {
  assert.equal(SETTLE_MS, 600_000);
  assert.equal(READBACK_MAX_REQUESTS, 60);
});

test("every name of the run is read directly: five functions, eight jobs, two topics, two subscriptions", () => {
  const names = readbackNames(RUN);
  assert.equal(names.length, 17);
  assert.deepEqual(
    names.slice(0, 5).map(([label]) => label),
    [
      "function-schedOkV2",
      "function-schedRetryV2",
      "function-schedSlowV2",
      "function-schedOkV1",
      "function-schedFailV1",
    ],
  );
  assert.ok(names[0][1].endsWith("/v2/" + functionName("schedOkV2")));
  assert.ok(
    names[3][1].includes("/v1/projects/") && names[3][1].endsWith(functionName("schedOkV1")),
  );
  assert.deepEqual(
    names.slice(10, 13).map(([label]) => label),
    ["job-zero", "job-duration", "job-count"],
  );
  assert.ok(names[10][1].endsWith("/jobs/fe-sd-" + RUN + "-zero"));
  assert.ok(names.at(-1)[1].endsWith("/subscriptions/fe-sd-" + RUN + "-pull-schedfailv1"));
});

test("an empty project reads as all absent, with only GETs and every name and list read", async () => {
  const { result, rows, world } = await readback();
  assert.equal(result.allAbsent, true);
  assert.equal(Object.keys(result.names).length, 17);
  assert.ok(Object.values(result.names).every((n) => n.status === 404 && n.absent === true));
  assert.deepEqual(result.incompleteReads, []);
  assert.equal(result.authStop, null);
  assert.equal(result.unknown, 0);
  assert.ok(
    world.calls.every((c) => c.startsWith("GET ")),
    world.calls.join("\n"),
  );
  assert.deepEqual(
    sent(rows)
      .map((r) => r.id)
      .slice(17),
    [
      "list-functions-v1",
      "list-functions-v2",
      "list-run-services",
      "list-jobs",
      "list-topics",
      "list-subscriptions",
    ],
  );
  assert.equal(result.attempted, 23);
});

test("a name that still reads 200, or any answer but 404 NOT_FOUND, is not absent, and so nothing closes", async () => {
  for (const [hook, label] of [
    [() => reply(200, { name: "x" }), "function-schedOkV2"],
    [() => error(503, "UNAVAILABLE"), "function-schedOkV2"],
    [() => error(404, "OTHER"), "function-schedOkV2"],
    [() => reply(404, {}), "function-schedOkV2"],
  ]) {
    const { result } = await readback({
      hooks: {
        ["GET " +
        "cloudfunctions.googleapis.com/v2/projects/fireemu-oracle-sbx/locations/us-central1/functions/schedOkV2"]:
          async () => hook(),
      },
    });
    assert.equal(result.names[label].absent, false);
    assert.equal(result.allAbsent, false);
  }
});

test("a run's own job, topic or subscription in a list keeps the read-back from closing", async () => {
  const jobs = await readback({}, (w) =>
    w.jobs.set(scheduleId("schedOkV2"), {
      name: "projects/x/locations/y/jobs/" + scheduleId("schedOkV2"),
    }),
  );
  assert.deepEqual(jobs.result.lists.jobs, [scheduleId("schedOkV2")]);
  assert.equal(jobs.result.allAbsent, false);
  const topics = await readback({}, (w) => w.topics.add(scheduleId("schedFailV1")));
  assert.deepEqual(topics.result.lists.topics, [scheduleId("schedFailV1")]);
  assert.equal(topics.result.allAbsent, false);
  const subs = await readback({}, (w) =>
    w.subs.set("projects/fireemu-oracle-sbx/subscriptions/fe-sd-" + RUN + "-pull-schedokv1", {
      topic: "t",
      queue: [],
    }),
  );
  assert.deepEqual(subs.result.lists.subscriptions, ["fe-sd-" + RUN + "-pull-schedokv1"]);
  assert.equal(subs.result.allAbsent, false);
  const fns = await readback({}, (w) =>
    w.functionsV2.set(functionName("schedOkV2"), {
      name: functionName("schedOkV2"),
      state: "ACTIVE",
    }),
  );
  assert.equal(fns.result.lists.functionsAndServices, false);
  assert.equal(fns.result.allAbsent, false);
});

test("a foreign job or topic in a list does not matter, only the run's own names do; any subscription does", async () => {
  const { result } = await readback({}, (w) => {
    w.jobs.set("other-job", { name: "projects/x/locations/y/jobs/other-job" });
    w.topics.add("other-topic");
  });
  assert.equal(result.allAbsent, true);
  assert.deepEqual(result.lists.jobs, []);
  // Preflight proved the subscriptions list empty and the run holds the lock: the whole list must be empty again.
  const withSub = await readback({}, (w) => {
    w.subs.set("projects/fireemu-oracle-sbx/subscriptions/other-sub", { topic: "t", queue: [] });
  });
  assert.deepEqual(withSub.result.lists.subscriptions, ["other-sub"]);
  assert.equal(withSub.result.allAbsent, false);
});

test("a list that cannot be read, or runs over five pages, is incomplete and nothing closes", async () => {
  const bad = await readback({
    hooks: {
      "GET pubsub.googleapis.com/v1/projects/fireemu-oracle-sbx/topics": async () =>
        error(500, "INTERNAL"),
    },
  });
  assert.deepEqual(bad.result.incompleteReads, [{ id: "list-topics", status: 500 }]);
  assert.equal(bad.result.lists.topics, null);
  assert.equal(bad.result.allAbsent, false);
  const many = await readback({ listPageSize: 1 }, (w) => {
    for (let i = 0; i < 7; i++) w.topics.add("other" + i);
  });
  assert.deepEqual(many.result.incompleteReads, [
    { id: "list-topics", status: "more-than-five-pages" },
  ]);
  assert.equal(sent(many.rows).filter((r) => r.id.startsWith("list-topics")).length, 5);
  assert.equal(many.result.allAbsent, false);
});

test("a rejected credential ends the read-back and nothing closes", async () => {
  const { result, rows } = await readback({
    hooks: {
      "GET pubsub.googleapis.com/v1/projects/fireemu-oracle-sbx/topics/firebase-schedule-schedOkV1-us-central1":
        async () => error(403, "PERMISSION_DENIED"),
    },
  });
  assert.deepEqual(result.authStop, { id: "readback-topic-schedOkV1", status: 403 });
  assert.equal(result.allAbsent, false);
  assert.equal(
    sent(rows).at(-1).id,
    "readback-topic-schedOkV1",
    "nothing after the refused request",
  );
});

test("a lost answer is unknown and keeps the read-back from closing", async () => {
  const { result } = await readback({
    hooks: {
      ["GET cloudscheduler.googleapis.com/v1/projects/fireemu-oracle-sbx/locations/us-central1/jobs/" +
      scheduleId("schedOkV2")]: async () => "throw",
    },
  });
  assert.equal(result.unknown, 1);
  assert.equal(result.names["job-schedOkV2"].status, null);
  assert.equal(result.allAbsent, false);
});

test("the read-back's allowlist lets reads of the run's names through and refuses every mutation", () => {
  const allow = readbackAllow(RUN, NUMBER);
  const base =
    "https://cloudscheduler.googleapis.com/v1/projects/fireemu-oracle-sbx/locations/us-central1/jobs/";
  const job = scheduleId("schedOkV2");
  const spec = (method, url, json) => ({
    id: "t",
    method,
    url,
    ...(json === undefined ? {} : { json }),
  });
  assert.equal(allow(spec("GET", base + job)), true);
  assert.equal(allow(spec("GET", base + "other-job")), false);
  for (const refused of [
    spec("DELETE", base + job),
    spec("POST", base + job + ":run", {}),
    spec("POST", base + job + ":pause", {}),
    spec(
      "POST",
      "https://pubsub.googleapis.com/v1/projects/fireemu-oracle-sbx/subscriptions/fe-sd-" +
        RUN +
        "-pull-schedokv1:pull",
      { maxMessages: 1 },
    ),
    spec(
      "PUT",
      "https://pubsub.googleapis.com/v1/projects/fireemu-oracle-sbx/subscriptions/fe-sd-" +
        RUN +
        "-pull-schedokv1",
      {
        topic: "projects/fireemu-oracle-sbx/topics/" + scheduleId("schedOkV1"),
        ackDeadlineSeconds: 10,
      },
    ),
    spec("DELETE", "https://cloudfunctions.googleapis.com/v2/" + functionName("schedOkV2")),
    spec("POST", "https://logging.googleapis.com/v2/entries:list", {
      resourceNames: ["projects/fireemu-oracle-sbx"],
      filter: "x",
      orderBy: "timestamp asc",
      pageSize: 1,
    }),
  ])
    assert.equal(allow(refused), false, refused.method + " " + refused.url);
});

// ---- the command ----------------------------------------------------------------------------------

const ARGS = (run, extra = []) => [
  "readback",
  "--run-dir",
  run,
  "--project-number",
  NUMBER,
  "--run-id",
  RUN,
  ...extra,
];
const ENV = { HOME: "/home/test", PATH: "/usr/bin" };
const io = () => {
  const lines = [];
  return {
    out: (t) => lines.push(["out", String(t)]),
    err: (t) => lines.push(["err", String(t)]),
    lines,
  };
};
const DIGEST = "d".repeat(64);
const journalAt = (run, ms) =>
  writeFileSync(
    join(run, "journal-" + RUN + ".jsonl"),
    JSON.stringify({
      id: "x",
      state: "before-send",
      dispatchAt: new Date(ms - 5000).toISOString(),
    }) +
      "\n" +
      JSON.stringify({
        id: "x",
        state: "response-persisted",
        responseAt: new Date(ms).toISOString(),
      }) +
      "\n" +
      "not json\n" +
      JSON.stringify({ id: "y", state: "issued" }) +
      "\n",
  );

test("the last activity of a journal is its latest dispatch or answer, and a missing journal is null", () => {
  const run = tmp();
  try {
    assert.equal(lastActivity(join(run, "none.jsonl")), null);
    journalAt(run, START);
    assert.equal(lastActivity(join(run, "journal-" + RUN + ".jsonl")), START);
    writeFileSync(join(run, "empty.jsonl"), "\n");
    assert.equal(lastActivity(join(run, "empty.jsonl")), null);
  } finally {
    rmSync(run, { recursive: true, force: true });
  }
});

test("the command refuses without its arguments, the approved digest, a journal, or ten quiet minutes", async () => {
  const run = tmp();
  try {
    const deps = {
      token: () => "test-token",
      send: createWorld().send,
      readback: async () => assert.fail("must not run"),
    };
    const attempt = async (argv, now) => {
      const sink = io();
      const code = await main(argv, {
        env: ENV,
        deps: { ...deps, now: () => now },
        digest: DIGEST,
        ...sink,
      });
      return { code, lines: sink.lines };
    };
    const noArgs = await attempt(["readback"], START);
    assert.equal(noArgs.code, 2);
    assert.match(
      noArgs.lines.at(-1)[1],
      /--run-dir is required\n- --project-number is required\n- --run-id is required/,
    );
    const bad = await attempt(
      ["readback", "--run-dir", run, "--project-number", "1", "--run-id", "zz"],
      START,
    );
    assert.match(bad.lines.at(-1)[1], /12 or 13 digits\n- --run-id is 16 hexadecimal digits/);
    const noSend = await attempt(ARGS(run), START);
    assert.equal(noSend.code, 2);
    assert.equal(
      noSend.lines.at(-1)[1],
      "readback needs --send and the approved --expect-digest; this packet's digest is " + DIGEST,
    );
    const wrong = await attempt(ARGS(run, ["--send", "--expect-digest", "e".repeat(64)]), START);
    assert.equal(wrong.code, 2);
    const noJournal = await attempt(ARGS(run, ["--send", "--expect-digest", DIGEST]), START);
    assert.equal(
      noJournal.lines.at(-1)[1],
      "there is no journal of run " + RUN + " in the run directory",
    );
    journalAt(run, START);
    const early = await attempt(
      ARGS(run, ["--send", "--expect-digest", DIGEST]),
      START + SETTLE_MS - 1,
    );
    assert.equal(early.code, 2);
    assert.equal(
      early.lines.at(-1)[1],
      "the last request of run " + RUN + " was 599 seconds ago; wait until ten minutes have passed",
    );
    assert.deepEqual(readdirSync(run), ["journal-" + RUN + ".jsonl"], "nothing was written");
  } finally {
    rmSync(run, { recursive: true, force: true });
  }
});

test("the command reads, writes its own journal and result, and exits 0 only when everything is absent", async () => {
  const run = tmp();
  try {
    journalAt(run, START);
    writeFileSync(join(run, "result-" + RUN + ".json"), JSON.stringify({ unconfirmedCreates: [] }));
    const world = createWorld();
    const sink = io();
    const code = await main(ARGS(run, ["--send", "--expect-digest", DIGEST]), {
      env: ENV,
      deps: {
        token: () => "test-token",
        send: world.send,
        readback: (o) => readbackRun({ ...o, clock: () => world.now }),
        now: () => START + SETTLE_MS,
      },
      digest: DIGEST,
      ...sink,
    });
    assert.equal(code, 0, sink.lines.join("\n"));
    const files = readdirSync(run).toSorted();
    const journal = files.find((f) => f.startsWith("readback-" + RUN + "-"));
    const result = files.find((f) => f.startsWith("readback-result-" + RUN + "-"));
    assert.ok(journal && result, files.join());
    assert.ok(readFileSync(join(run, journal), "utf8").endsWith("\n"));
    const text = readFileSync(join(run, result), "utf8");
    assert.equal(text, JSON.stringify(JSON.parse(text), null, 2) + "\n");
    assert.equal(JSON.parse(text).allAbsent, true);
    assert.equal(
      sink.lines[0][1],
      JSON.stringify(
        {
          project: "fireemu-oracle-sbx",
          command: "readback",
          maxRequests: 60,
          packetDigest: DIGEST,
        },
        null,
        2,
      ),
    );
    assert.equal(
      sink.lines.at(-1)[1],
      JSON.stringify(
        { runId: RUN, allAbsent: true, attempted: 23, unknown: 0, unconfirmedCreates: [] },
        null,
        2,
      ),
    );
    world.topics.add(scheduleId("schedOkV1"));
    const again = io();
    const second = await main(ARGS(run, ["--send", "--expect-digest", DIGEST]), {
      env: ENV,
      deps: {
        token: () => "test-token",
        send: world.send,
        readback: (o) => readbackRun({ ...o, clock: () => world.now }),
        now: () => START + SETTLE_MS + 1,
      },
      digest: DIGEST,
      ...again,
    });
    assert.equal(second, 3, "something is still there");
    const boom = io();
    const third = await main(ARGS(run, ["--send", "--expect-digest", DIGEST]), {
      env: ENV,
      deps: {
        token: () => "test-token",
        send: world.send,
        readback: async () => {
          throw new Error("boom");
        },
        now: () => START + SETTLE_MS + 2,
      },
      digest: DIGEST,
      ...boom,
    });
    assert.equal(third, 4);
    assert.equal(boom.lines.at(-1)[1], "the read-back stopped: boom");
  } finally {
    rmSync(run, { recursive: true, force: true });
  }
});
