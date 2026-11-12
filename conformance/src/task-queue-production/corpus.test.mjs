// The program of the recording: its shape, the pin of its manifest, and the properties the guard and the recorder rely on
// (a step is time-free once reduced to its shape; every task carries the run's marker; every name stays in the run's queues).
import "./record/isolation.mjs";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  ABSENT_QUEUE,
  CONDITION_IDS,
  FOREIGN_PROJECT,
  MAY_FORBID,
  NOT_DELIVERED,
  ADMISSION_PAIRS,
  isNotDelivered,
  PROGRAM,
  corpusManifest,
  formatTime,
  materialize,
  functionOfRoleOrAbsent,
  materializeCreate,
  minStarts,
  plannedShapes,
  plannedTaskNames,
  shapeOf,
  taskId,
} from "./corpus.mjs";
import { MANIFEST_PATH, manifestText } from "./corpus-manifest.mjs";
import { PROJECT, REGION, ROLE_IDS, queueName, runMarker } from "./plan.mjs";

const RUN = "0123456789abcdef";
const targets = Object.fromEntries(
  ROLE_IDS.map((role) => [
    role,
    {
      uri: "https://" + role + "-abc-uc.a.run.app",
      serviceAccountEmail: "x@y.gserviceaccount.com",
    },
  ]),
);
const ctx = (runId = RUN, now = 1_800_000_000_000) => ({ runId, now, targets });
const hex16 = (n) => n.toString(16).padStart(16, "0").slice(-16);
// A small deterministic generator, so that the properties below run on the same inputs everywhere.
function* random(seed) {
  let x = seed >>> 0 || 1;
  while (true) {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    yield x;
  }
}

test("the program has unique keys, known roles, known conditions and a queue read for every role", () => {
  const keys = PROGRAM.map((s) => s.key);
  assert.equal(new Set(keys).size, keys.length);
  const shortIds = new Set(CONDITION_IDS.map((id) => id.split("/")[1]));
  for (const step of PROGRAM) {
    assert.ok([...ROLE_IDS, ABSENT_QUEUE].includes(step.role), step.key);
    assert.ok(["create", "delete", "get-task", "get-queue"].includes(step.kind), step.key);
    assert.ok(step.groups.length > 0, step.key);
    for (const group of step.groups) assert.ok(shortIds.has(group), step.key + " " + group);
  }
  for (const role of ROLE_IDS)
    assert.ok(
      PROGRAM.some((s) => s.kind === "get-queue" && s.role === role),
      role,
    );
  // Every condition that has production evidence to collect is served by a step, but the stage 2 window, the fireemu-only
  // row and the gates.
  const served = new Set(PROGRAM.flatMap((s) => s.groups));
  const unserved = [...shortIds].filter((id) => !served.has(id)).toSorted();
  assert.deepEqual(unserved, [
    "closure-review",
    "dedup-window-expiry",
    "final-artifact-regression",
    "local-controls",
  ]);
});

test("the committed manifest is the manifest of the program, and its pin is stable", () => {
  assert.deepEqual(JSON.parse(readFileSync(MANIFEST_PATH, "utf8")), JSON.parse(manifestText()));
  const a = corpusManifest();
  const b = corpusManifest();
  assert.equal(a.corpusSha256, b.corpusSha256);
  assert.match(a.corpusSha256, /^[0-9a-f]{64}$/);
  assert.equal(a.steps.length, PROGRAM.length);
});

test("a created task carries the run's marker in its data and its case, and its name stays in the run's queue", () => {
  const marker = runMarker(RUN);
  for (const spec of PROGRAM.filter((s) => s.kind === "create")) {
    const { json, url } = materializeCreate(spec, ctx());
    assert.ok(
      url.startsWith(
        `https://cloudtasks.googleapis.com/v2/projects/${PROJECT}/locations/${REGION}/queues/`,
      ),
    );
    if (spec.omit === "task") {
      assert.deepEqual(json, {});
      continue;
    }
    const task = json.task;
    if (task.name !== undefined) {
      const foreign = task.name.startsWith("projects/" + FOREIGN_PROJECT + "/");
      assert.ok(foreign || task.name.startsWith("projects/" + PROJECT + "/"), spec.key);
      assert.ok(task.name.includes(marker) || task.name.endsWith("/tasks/"), spec.key);
    }
    if (spec.emptyRequest) {
      assert.equal(task.httpRequest, undefined);
      continue;
    }
    const text = Buffer.from(task.httpRequest.body, "base64").toString("utf8");
    assert.ok(text.includes(marker), spec.key);
    const data = JSON.parse(text).data;
    assert.equal(data.run, marker);
    if (spec.bodyText === undefined || spec.bodyText.includes('"case":"' + spec.key + '"'))
      assert.equal(data.case, spec.key, spec.key);
    assert.equal(task.httpRequest.oidcToken.audience, task.httpRequest.url);
    assert.equal(task.httpRequest.httpMethod, "POST");
  }
});

test("the boundary steps have the sizes they are named for", () => {
  const step = (key) => PROGRAM.find((s) => s.key === key);
  const idOf = (key) => {
    const name = materializeCreate(step(key), ctx()).json.task.name;
    return name.slice(name.lastIndexOf("/tasks/") + "/tasks/".length);
  };
  assert.equal(idOf("id-500").length, 500);
  assert.equal(idOf("id-501").length, 501);
  const bodyBytes = (key) =>
    Buffer.from(materializeCreate(step(key), ctx()).json.task.httpRequest.body, "base64").length;
  assert.ok(bodyBytes("size-1000k") > 1_000_000 && bodyBytes("size-1000k") < 1_000_200);
  assert.ok(bodyBytes("size-1100k") > 1_100_000 && bodyBytes("size-1100k") < 1_100_200);
  assert.ok(bodyBytes("env-large") > 100_000 && bodyBytes("env-large") < 100_200);
  assert.equal(idOf("id-space").includes(" "), true);
  assert.equal(idOf("id-slash").includes("/"), true);
  assert.equal(materializeCreate(step("id-empty"), ctx()).json.task.name.endsWith("/tasks/"), true);
});

test("the schedule offsets are relative to the send time, and the forms are the forms they are named for", () => {
  const now = Date.parse("2026-11-12T03:04:05.678Z");
  const at = (key) =>
    materializeCreate(
      PROGRAM.find((s) => s.key === key),
      ctx(RUN, now),
    ).json.task.scheduleTime;
  assert.equal(at("sch-now"), "2026-11-12T03:04:05.678Z");
  assert.equal(at("sch-past"), "2026-11-12T02:04:05.678Z");
  assert.equal(at("sch-20s"), "2026-11-12T03:04:25.678Z");
  assert.match(at("sch-nanos"), /\.\d{9}Z$/);
  assert.match(at("sch-offset"), /\+09:00$/);
  assert.equal(Date.parse(at("sch-offset")), now + 5000);
  assert.equal(Date.parse(at("sch-30d-less")), now + 30 * 86_400_000 - 3_600_000);
  assert.equal(Date.parse(at("sch-30d-more")), now + 30 * 86_400_000 + 3_600_000);
  assert.equal(at("sch-text"), "tomorrow");
  assert.equal(at("sch-no-zone"), "2026-11-12T00:00:00");
  assert.equal(formatTime(0, "iso"), "1970-01-01T00:00:00.000Z");
});

test("a step's shape does not depend on the time it is sent, and different steps have different shapes", () => {
  const gen = random(7);
  const creates = PROGRAM.filter((s) => s.kind === "create");
  for (let n = 0; n < 8; n++) {
    const runId = hex16(gen.next().value * 65_537 + n);
    const t1 = 1_700_000_000_000 + (gen.next().value % 1_000_000_000);
    const t2 = t1 + (gen.next().value % 86_400_000);
    for (const spec of creates) {
      const a = shapeOf(materializeCreate(spec, ctx(runId, t1)).json);
      const b = shapeOf(materializeCreate(spec, ctx(runId, t2)).json);
      assert.equal(a, b, spec.key);
    }
  }
  const shapes = creates.map((s) => shapeOf(materializeCreate(s, ctx()).json));
  assert.equal(new Set(shapes).size, shapes.length, "every create has its own shape");
  assert.equal(plannedShapes(RUN, targets).size, shapes.length);
  for (const spec of creates)
    assert.ok(
      plannedShapes(RUN, targets).has(
        functionOfRoleOrAbsent(RUN, spec.role) +
          "\n" +
          shapeOf(materializeCreate(spec, ctx()).json),
      ),
    );
});

test("a shape that is not a step of the program is not planned, whatever small change makes it", () => {
  const planned = plannedShapes(RUN, targets);
  const spec = PROGRAM.find((s) => s.key === "env-named");
  const base = materializeCreate(spec, ctx()).json;
  const queue = "tqdef" + RUN.slice(0, 6);
  const keyOf = (json, q = queue) => q + "\n" + shapeOf(json);
  assert.ok(planned.has(keyOf(base)));
  const mutate = (fn) => {
    const copy = structuredClone(base);
    fn(copy);
    return keyOf(copy);
  };
  for (const change of [
    (j) => (j.task.httpRequest.url = "https://evil.example/"),
    (j) => (j.task.httpRequest.httpMethod = "GET"),
    (j) => (j.task.httpRequest.headers["X-Extra"] = "1"),
    (j) => (j.task.httpRequest.oidcToken.serviceAccountEmail = "z@y.gserviceaccount.com"),
    (j) => (j.task.name += "x"),
    (j) => (j.task.dispatchDeadline = "20s"),
    (j) => (j.task.scheduleTime = "2026-01-01T00:00:00Z"),
    (j) => (j.responseView = "FULL"),
    (j) => (j.extra = true),
    (j) => (j.task.httpRequest.body += "AA"),
  ])
    assert.equal(planned.has(mutate(change)), false, change.toString());
  // A different run's task is not this run's shape.
  const other = materializeCreate(spec, ctx("fedcba9876543210")).json;
  assert.equal(planned.has(keyOf(other, "tqdef" + "fedcba")), false);
  // The same body is another step's shape only on that step's queue.
  assert.equal(planned.has(keyOf(base, "tqretry" + RUN.slice(0, 6))), false);
});

test("reads and deletes name only tasks of the program, in the run's queues", () => {
  const names = plannedTaskNames(RUN);
  assert.ok(names.size > 0);
  for (const name of names) {
    assert.ok(name.startsWith(`projects/${PROJECT}/locations/${REGION}/queues/`));
    assert.ok(name.includes("/tasks/" + runMarker(RUN) + "-"));
  }
  const del = PROGRAM.find((s) => s.key === "del-dup-sched");
  assert.equal(materialize(del, ctx()).method, "DELETE");
  assert.equal(
    materialize(del, ctx()).url,
    "https://cloudtasks.googleapis.com/v2/" +
      queueName("tqdef" + RUN.slice(0, 6)) +
      "/tasks/" +
      taskId(RUN, "dup-sched"),
  );
  assert.equal(
    materialize(
      PROGRAM.find((s) => s.key === "queue-tqrate"),
      ctx(),
    ).method,
    "GET",
  );
});

test("the deliveries a case is waited for follow the steps that are not delivered and the retry cases", () => {
  assert.equal(minStarts("retry-ladder"), 6);
  assert.equal(minStarts("env-default"), 1);
  assert.equal(minStarts("sch-31d"), 0);
  for (const key of NOT_DELIVERED) assert.equal(minStarts(key), 0);
  for (const key of MAY_FORBID) assert.ok(PROGRAM.some((s) => s.key === key));
});

test("property: every time form parses back to the instant it was made from (to the millisecond)", () => {
  const gen = random(5);
  for (let n = 0; n < 200; n++) {
    const ms =
      1_500_000_000_000 + (gen.next().value % 1_000_000_000) * 3 + (gen.next().value % 1000);
    assert.equal(Date.parse(formatTime(ms, "iso")), ms);
    assert.equal(Date.parse(formatTime(ms, "offset")), ms);
    assert.equal(Date.parse(formatTime(ms, "nanos")), ms);
    assert.match(formatTime(ms, "iso"), /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
    assert.match(formatTime(ms, "offset"), /\+09:00$/);
    assert.match(formatTime(ms, "nanos"), /\.\d{9}Z$/);
  }
});

test("property: no step of any run names a task outside that run's queues, and no step is sent to a queue of another run", () => {
  const gen = random(99);
  for (let n = 0; n < 6; n++) {
    const runId = hex16(gen.next().value * 131 + n);
    const marker = runMarker(runId);
    const suffix = runId.slice(0, 6);
    for (const spec of PROGRAM) {
      const request = materialize(spec, ctx(runId));
      const queue = new URL(request.url).pathname.split("/queues/")[1].split("/")[0];
      assert.ok(queue.endsWith(suffix), spec.key);
      const name = request.json?.task?.name;
      if (name && !name.includes(FOREIGN_PROJECT))
        assert.ok(
          name.includes("/queues/" + queue + "/") || spec.key === "id-other-queue",
          spec.key,
        );
      if (name && !name.includes(FOREIGN_PROJECT) && !name.endsWith("/tasks/"))
        assert.ok(name.includes(marker), spec.key);
    }
  }
});

test("the pairwise table covers every pair of values of the four axes, with the three seed rows in it", () => {
  const axes = [
    ["none", "plain", "max500", "over501", "badchar"],
    ["none", "past", "near", "limit29d", "over31d", "malformed"],
    ["none", "d15", "d1800", "d14", "d1801", "malformed"],
    ["small", "large100k"],
  ];
  for (let a = 0; a < 4; a++)
    for (let b = a + 1; b < 4; b++)
      for (const x of axes[a])
        for (const y of axes[b])
          assert.ok(
            ADMISSION_PAIRS.some((row) => row[a] === x && row[b] === y),
            `${a}:${x} ${b}:${y}`,
          );
  for (const seed of [
    ["none", "none", "none", "small"],
    ["max500", "limit29d", "d1800", "large100k"],
    ["over501", "malformed", "malformed", "small"],
  ])
    assert.ok(
      ADMISSION_PAIRS.some((row) => row.join() === seed.join()),
      seed.join(),
    );
  assert.equal(new Set(ADMISSION_PAIRS.map((row) => row.join())).size, ADMISSION_PAIRS.length);
  // A pair step's request is the one its row says.
  for (const [index, row] of ADMISSION_PAIRS.entries()) {
    const spec = PROGRAM.find((s) => s.key === "pw-" + String(index + 1).padStart(2, "0"));
    const task = materializeCreate(spec, ctx()).json.task;
    assert.deepEqual(spec.pair, { id: row[0], schedule: row[1], deadline: row[2], body: row[3] });
    assert.equal(task.name === undefined, row[0] === "none");
    assert.equal(task.scheduleTime === undefined, row[1] === "none");
    assert.equal(task.dispatchDeadline === undefined, row[2] === "none");
    const bytes = Buffer.from(task.httpRequest.body, "base64").length;
    assert.equal(bytes > 100_000, row[3] === "large100k");
    const tail = task.name?.slice(task.name.lastIndexOf("/tasks/") + 7);
    if (row[0] === "max500") assert.equal(tail.length, 500);
    if (row[0] === "over501") assert.equal(tail.length, 501);
    if (row[0] === "badchar") assert.ok(tail.includes(" "));
    assert.equal(isNotDelivered(spec.key), ["limit29d", "over31d"].includes(row[1]));
  }
});

test("the shape keeps the form of a time: the digits of the fraction, the zone, and whether it is text at all", () => {
  const shape = (key) =>
    shapeOf(
      materializeCreate(
        PROGRAM.find((s) => s.key === key),
        ctx(),
      ).json,
    );
  const scheduled = (key) => JSON.parse(shape(key)).task.scheduleTime;
  assert.equal(scheduled("sch-20s"), "T.f3Z");
  assert.equal(scheduled("sch-nanos"), "T.f9Z");
  assert.equal(scheduled("sch-offset"), "T.f3offset");
  assert.equal(scheduled("sch-text"), "tomorrow");
  assert.equal(scheduled("sch-no-zone"), "2026-11-12T00:00:00");
  assert.equal(scheduled("sch-leap-second"), "TZ");
  assert.equal(JSON.parse(shape("env-named")).task.scheduleTime, undefined);
});

test("the fields a step is named for are in its request: the script, the unknown field, the view, the headers, the pad", () => {
  const task = (key) =>
    materializeCreate(
      PROGRAM.find((s) => s.key === key),
      ctx(),
    ).json;
  const data = (key) =>
    JSON.parse(Buffer.from(task(key).task.httpRequest.body, "base64").toString("utf8")).data;
  assert.equal(data("retry-ladder").script.length, 6);
  assert.deepEqual(data("retry-ladder").script[1], { status: "resource-exhausted" });
  assert.equal(task("err-unknown-field").task.fireemuUnknownField, 1);
  assert.equal(task("env-view-full").responseView, "FULL");
  assert.equal(task("env-default").responseView, undefined);
  assert.equal(task("env-headers").task.httpRequest.headers["X-Fireemu-Probe"], "kept");
  assert.equal(task("env-headers").task.httpRequest.headers["Content-Type"], "application/json");
  assert.equal(data("env-large").pad.length, 100_000);
  assert.equal(data("env-default").pad, undefined);
  assert.equal(task("dead-15").task.dispatchDeadline, "15s");
  assert.equal(task("dl-fraction").task.dispatchDeadline, "15.5s");
  assert.equal(task("env-default").task.dispatchDeadline, undefined);
  assert.deepEqual(data("dead-15").script, [{ status: "ok", sleepMs: 20_000 }, { status: "ok" }]);
  assert.equal(data("env-default").script, undefined);
});
