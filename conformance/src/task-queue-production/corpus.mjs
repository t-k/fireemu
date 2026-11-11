// The program of the TASK-QUEUE-FUNCTIONS recording: the ordered requests of one run against the run's own queues, as
// data. A step is symbolic (a time is an offset from the moment it is sent, a task id is a suffix of the run's marker);
// `materialize` turns a step into the request the recorder sends, and `shapeOf` reduces a request body to the time-free
// shape the guard checks, so the guard can only let through what this program builds.
//
// Nothing here sends or reads anything. The conditions each step serves are the closure record's
// (spec/compatibility/closure/TASK-QUEUE-FUNCTIONS.json).
import { createHash } from "node:crypto";
import {
  PROJECT,
  REGION,
  ROLE_IDS,
  functionOfRole,
  queueName,
  runMarker,
  suffixOf,
} from "./plan.mjs";

const C = "TASK-QUEUE-FUNCTIONS/";
export const CONDITION_IDS = Object.freeze(
  [
    "create-answer-shape",
    "create-errors-shape",
    "task-id-validation",
    "dedup-live",
    "dedup-after-completion",
    "dedup-window-expiry",
    "schedule-time-boundaries",
    "schedule-delay-and-eta",
    "dispatch-deadline",
    "body-and-header-limits",
    "dispatch-envelope-headers",
    "dispatch-envelope-body",
    "task-name-generation",
    "queue-config-mapping",
    "retry-on-status",
    "retry-backoff-schedule",
    "retry-limits",
    "max-concurrent-dispatches",
    "max-dispatches-per-second",
    "delete-task",
    "local-controls",
    "final-artifact-regression",
    "closure-review",
  ].map((id) => C + id),
);

/** The queue that is never deployed: a createTask on it is the "queue does not exist" probe. */
export const ABSENT_QUEUE = "tqnone";
/** A project id that is not this one, in a task name: the answer to a name that points elsewhere. It is never a real project. */
export const FOREIGN_PROJECT = "tq-not-this-project";

const DAY = 86_400;
const ok = { status: "ok" };
const alwaysInternal = [{ status: "internal" }];
const hold = (sleepMs) => [{ status: "ok", sleepMs }];

/**
 * The steps in the order they are sent. Fields: `key` (the case id; it is the task id suffix and the `data.case` the
 * deliveries carry), `kind` (`create`, `delete`, `get-task`, `get-queue`), `role`, `pauseBefore` (seconds), `groups` (the
 * conditions it serves), and for a create the task: `id`, `name`, `schedule`, `deadline`, `headers`, `script`, `bodyText`,
 * `padBytes`, `responseView`, `omit`, `extraTaskKey`, `emptyRequest`.
 */
const step = (key, kind, role, groups, rest = {}) => ({ key, kind, role, groups, ...rest });
const create = (key, role, groups, rest = {}) => step(key, "create", role, groups, rest);

const TIMING = [
  // The ladders and limits go first so that their windows overlap the admission cases that follow.
  create(
    "retry-ladder",
    "tqretry",
    ["retry-on-status", "retry-backoff-schedule", "dispatch-envelope-headers"],
    {
      id: "retry-ladder",
      script: [
        { status: "internal" },
        { status: "resource-exhausted" },
        { status: "unavailable" },
        { status: "invalid-argument" },
        { status: "not-found" },
        ok,
      ],
    },
  ),
  create("retry-exhaust", "tqretry", ["retry-limits", "retry-backoff-schedule"], {
    id: "retry-exhaust",
    script: alwaysInternal,
  }),
  create("limit-two", "tqlimit", ["retry-limits"], { id: "limit-two", script: alwaysInternal }),
  create("window-six", "tqwindow", ["retry-limits"], { id: "window-six", script: alwaysInternal }),
  create("dead-15", "tqdead", ["dispatch-deadline", "retry-on-status"], {
    id: "dead-15",
    deadline: "15s",
    script: [{ status: "ok", sleepMs: 20_000 }, ok],
  }),
  ...["a", "b", "c", "d"].map((n) =>
    create("conc1-" + n, "tqconc1", ["max-concurrent-dispatches"], {
      id: "conc1-" + n,
      script: hold(3000),
    }),
  ),
  ...["a", "b", "c", "d", "e"].map((n) =>
    create("conc2-" + n, "tqconc2", ["max-concurrent-dispatches"], {
      id: "conc2-" + n,
      script: hold(3000),
    }),
  ),
  ...["a", "b", "c", "d", "e", "f", "g", "h"].map((n) =>
    create("rate-" + n, "tqrate", ["max-dispatches-per-second"], { id: "rate-" + n }),
  ),
];

const ENVELOPE = [
  create("env-default", "tqdef", [
    "create-answer-shape",
    "dispatch-envelope-headers",
    "dispatch-envelope-body",
    "task-name-generation",
  ]),
  create("env-named", "tqdef", ["create-answer-shape", "dispatch-envelope-headers"], {
    id: "env-named",
  }),
  create("env-headers", "tqdef", ["dispatch-envelope-headers", "body-and-header-limits"], {
    id: "env-headers",
    headers: {
      "X-Fireemu-Probe": "kept",
      "User-Agent": "fireemu-probe",
      "X-CloudTasks-TaskName": "forged",
      "X-Google-Probe": "g",
      "X-AppEngine-Probe": "a",
      Authorization: "Bearer not-a-token",
    },
  }),
  create("env-utf8", "tqdef", ["dispatch-envelope-body"], {
    id: "env-utf8",
    bodyText:
      '{"data":{"run":"${run}","case":"env-utf8","label":"\\u00e9\\u3042 \u00e9\u3042\ud83d\ude00"}}',
  }),
  create("env-unordered", "tqdef", ["dispatch-envelope-body"], {
    id: "env-unordered",
    bodyText: '{ "data" : { "z": 1, "run": "${run}", "case": "env-unordered", "a": [ 3, 2, 1 ] } }',
  }),
  create("env-minimal", "tqdef", ["dispatch-envelope-body"], {
    id: "env-minimal",
    bodyText: '{"data":{"run":"${run}","case":"env-minimal"}}',
  }),
  create("env-large", "tqdef", ["dispatch-envelope-body", "body-and-header-limits"], {
    id: "env-large",
    padBytes: 100_000,
  }),
  create("env-view-full", "tqdef", ["create-answer-shape"], {
    id: "env-view-full",
    responseView: "FULL",
  }),
];

const ERRORS = [
  create("err-no-task", "tqdef", ["create-errors-shape"], { omit: "task" }),
  create("err-no-http", "tqdef", ["create-errors-shape"], { emptyRequest: true }),
  create("err-unknown-field", "tqdef", ["create-errors-shape"], {
    id: "err-unknown-field",
    extraTaskKey: "fireemuUnknownField",
  }),
  create("err-queue-missing", ABSENT_QUEUE, ["create-errors-shape"], { id: "err-queue-missing" }),
  create("id-space", "tqdef", ["task-id-validation"], { name: "${queue}/tasks/${marker}-a b" }),
  create("id-slash", "tqdef", ["task-id-validation"], { name: "${queue}/tasks/${marker}-a/b" }),
  create("id-empty", "tqdef", ["task-id-validation"], { name: "${queue}/tasks/" }),
  create("id-dot", "tqdef", ["task-id-validation"], { id: "id.dot" }),
  create("id-punct-ok", "tqdef", ["task-id-validation"], { id: "id_ok-1" }),
  create("id-500", "tqdef", ["task-id-validation"], { id: "id-500", idPad: 500 }),
  create("id-501", "tqdef", ["task-id-validation"], { id: "id-501", idPad: 501 }),
  create("id-other-queue", "tqdef", ["task-id-validation"], {
    name: "${queue:tqconc1}/tasks/${marker}-id-other-queue",
  }),
  create("id-other-project", "tqdef", ["task-id-validation"], {
    name:
      "projects/" +
      FOREIGN_PROJECT +
      "/locations/" +
      REGION +
      "/queues/${fn}/tasks/${marker}-id-other-project",
  }),
];

const SCHEDULE = [
  create("sch-past", "tqdef", ["schedule-time-boundaries", "schedule-delay-and-eta"], {
    id: "sch-past",
    schedule: { offsetSeconds: -3600 },
  }),
  create("sch-now", "tqdef", ["schedule-time-boundaries"], {
    id: "sch-now",
    schedule: { offsetSeconds: 0 },
  }),
  create("sch-20s", "tqdef", ["schedule-delay-and-eta"], {
    id: "sch-20s",
    schedule: { offsetSeconds: 20 },
  }),
  create("sch-nanos", "tqdef", ["schedule-time-boundaries"], {
    id: "sch-nanos",
    schedule: { offsetSeconds: 5, form: "nanos" },
  }),
  create("sch-offset", "tqdef", ["schedule-time-boundaries"], {
    id: "sch-offset",
    schedule: { offsetSeconds: 5, form: "offset" },
  }),
  create("sch-30d-less", "tqdef", ["schedule-time-boundaries"], {
    id: "sch-30d-less",
    schedule: { offsetSeconds: 30 * DAY - 3600 },
  }),
  create("sch-30d-more", "tqdef", ["schedule-time-boundaries"], {
    id: "sch-30d-more",
    schedule: { offsetSeconds: 30 * DAY + 3600 },
  }),
  create("sch-31d", "tqdef", ["schedule-time-boundaries"], {
    id: "sch-31d",
    schedule: { offsetSeconds: 31 * DAY },
  }),
  create("sch-year-9999", "tqdef", ["schedule-time-boundaries"], {
    id: "sch-year-9999",
    schedule: { raw: "9999-12-31T23:59:59Z" },
  }),
  create("sch-text", "tqdef", ["schedule-time-boundaries"], {
    id: "sch-text",
    schedule: { raw: "tomorrow" },
  }),
  create("sch-no-zone", "tqdef", ["schedule-time-boundaries"], {
    id: "sch-no-zone",
    schedule: { raw: "2026-11-12T00:00:00" },
  }),
  create("sch-leap-second", "tqdef", ["schedule-time-boundaries"], {
    id: "sch-leap-second",
    schedule: { raw: "2026-12-31T23:59:60Z" },
  }),
];

const DEADLINE = [
  ["dl-14s", "14s"],
  ["dl-15s", "15s"],
  ["dl-1800s", "1800s"],
  ["dl-1801s", "1801s"],
  ["dl-fraction", "15.5s"],
  ["dl-bare", "30"],
  ["dl-negative", "-1s"],
  ["dl-zero", "0s"],
].map(([key, deadline]) => create(key, "tqdef", ["dispatch-deadline"], { id: key, deadline }));

const SIZE = [
  create("size-1000k", "tqdef", ["body-and-header-limits"], {
    id: "size-1000k",
    padBytes: 1_000_000,
  }),
  create("size-1100k", "tqdef", ["body-and-header-limits"], {
    id: "size-1100k",
    padBytes: 1_100_000,
  }),
];

const DEDUP = [
  create("dup-first", "tqdef", ["dedup-after-completion", "dedup-live"], { id: "dup-first" }),
  create("dup-sched", "tqdef", ["dedup-live"], {
    id: "dup-sched",
    schedule: { offsetSeconds: 300 },
  }),
  create("dup-sched-again", "tqdef", ["dedup-live"], {
    id: "dup-sched",
    schedule: { offsetSeconds: 300 },
  }),
  step("get-dup-sched", "get-task", "tqdef", ["dedup-live", "delete-task"], { id: "dup-sched" }),
  step("del-dup-sched", "delete", "tqdef", ["delete-task", "dedup-live"], { id: "dup-sched" }),
  step("del-dup-sched-again", "delete", "tqdef", ["delete-task"], { id: "dup-sched" }),
  create("dup-sched-after-delete", "tqdef", ["dedup-after-completion"], {
    id: "dup-sched",
    schedule: { offsetSeconds: 300 },
  }),
  create("dup-other-queue", "tqconc1", ["dedup-live"], { id: "dup-sched" }),
  step("del-missing", "delete", "tqdef", ["delete-task"], { id: "never-created" }),
  // The first task of the program has finished by now (twenty-five seconds later); the same id is sent again.
  create("dup-first-after-done", "tqdef", ["dedup-after-completion"], {
    id: "dup-first",
    pauseBefore: 25,
  }),
  step("get-dup-first", "get-task", "tqdef", ["dedup-after-completion", "delete-task"], {
    id: "dup-first",
  }),
  step("del-dup-first", "delete", "tqdef", ["delete-task"], { id: "dup-first" }),
];

const QUEUES = [
  ...ROLE_IDS.map((role) => step("queue-" + role, "get-queue", role, ["queue-config-mapping"])),
  step("queue-absent", "get-queue", ABSENT_QUEUE, ["create-errors-shape"]),
];

/** The whole program, in the order it is sent. */
export const PROGRAM = Object.freeze(
  [...TIMING, ...ENVELOPE, ...SCHEDULE, ...ERRORS, ...DEADLINE, ...SIZE, ...DEDUP, ...QUEUES].map(
    (s) => Object.freeze(s),
  ),
);
export const caseKeys = () => PROGRAM.map((s) => s.key);

/** The first minimum of deliveries a case is waited for: an accepted task is delivered at least once unless it is scheduled far away or removed. */
export const NOT_DELIVERED = new Set([
  "sch-30d-less",
  "sch-30d-more",
  "sch-31d",
  "sch-year-9999",
  "dup-sched",
  "dup-sched-again",
  "dup-sched-after-delete",
  "dup-first-after-done",
  "dl-1801s",
]);

/** The deliveries a case is waited for at least: one for an accepted task unless it is not delivered, and the attempts of the retry cases. */
export const MIN_STARTS = Object.freeze({
  "retry-ladder": 6,
  "retry-exhaust": 6,
  "limit-two": 2,
  "window-six": 3,
  "dead-15": 2,
});
export const minStarts = (key) => (NOT_DELIVERED.has(key) ? 0 : (MIN_STARTS[key] ?? 1));

/** Steps whose answer may be a 403 without the credential being at fault (a name that points at another project or queue). */
export const MAY_FORBID = new Set(["id-other-project", "id-other-queue", "err-queue-missing"]);

const b64 = (text) => Buffer.from(text, "utf8").toString("base64");

/** RFC 3339 forms of an instant: the SDK's own (`toISOString`), nine fractional digits, and a numeric offset. */
export function formatTime(ms, form = "iso") {
  const date = new Date(ms);
  const iso = date.toISOString();
  if (form === "nanos") return iso.replace(/\.(\d{3})Z$/, ".$1123456Z");
  if (form === "offset") {
    const shifted = new Date(ms + 9 * 3600_000).toISOString().replace(/Z$/, "+09:00");
    return shifted;
  }
  return iso;
}

export const taskId = (runId, key) => runMarker(runId) + "-" + key;

const bodyTextOf = (spec, ctx) => {
  const marker = runMarker(ctx.runId);
  if (spec.bodyText !== undefined) return spec.bodyText.replaceAll("${run}", marker);
  const data = { run: marker, case: spec.key };
  if (spec.script !== undefined) data.script = spec.script;
  if (spec.padBytes !== undefined) data.pad = "p".repeat(spec.padBytes);
  return JSON.stringify({ data });
};

const nameOf = (spec, ctx) => {
  const marker = runMarker(ctx.runId);
  const fn = functionOfRoleOrAbsent(ctx.runId, spec.role);
  if (spec.name !== undefined)
    return spec.name
      .replaceAll("${queue}", queueName(fn))
      .replace(/\$\{queue:(\w+)\}/g, (_, role) =>
        queueName(functionOfRoleOrAbsent(ctx.runId, role)),
      )
      .replaceAll("${fn}", fn)
      .replaceAll("${marker}", marker);
  if (spec.id === undefined) return undefined;
  const tail =
    spec.idPad !== undefined
      ? (marker + "-" + spec.id).padEnd(spec.idPad, "x")
      : marker + "-" + spec.id;
  return queueName(fn) + "/tasks/" + tail;
};

export const functionOfRoleOrAbsent = (runId, role) =>
  role === ABSENT_QUEUE ? ABSENT_QUEUE + suffixOf(runId) : functionOfRole(runId, role);

/** The createTask request of a step at time `ctx.now` (ms). `ctx.targets[role]` is `{uri, serviceAccountEmail}`. */
export function materializeCreate(spec, ctx) {
  const fn = functionOfRoleOrAbsent(ctx.runId, spec.role);
  const url = `https://cloudtasks.googleapis.com/v2/projects/${PROJECT}/locations/${REGION}/queues/${fn}/tasks`;
  const target = ctx.targets[spec.role] ?? ctx.targets[ROLE_IDS[0]];
  if (spec.omit === "task") return { method: "POST", url, json: {} };
  const task = {};
  const name = nameOf(spec, ctx);
  if (name !== undefined) task.name = name;
  if (!spec.emptyRequest) {
    task.httpRequest = {
      url: target.uri,
      httpMethod: "POST",
      headers: { "Content-Type": "application/json", ...spec.headers },
      body: b64(bodyTextOf(spec, ctx)),
      oidcToken: { serviceAccountEmail: target.serviceAccountEmail, audience: target.uri },
    };
  }
  if (spec.schedule !== undefined)
    task.scheduleTime =
      spec.schedule.raw ??
      formatTime(ctx.now + spec.schedule.offsetSeconds * 1000, spec.schedule.form);
  if (spec.deadline !== undefined) task.dispatchDeadline = spec.deadline;
  if (spec.extraTaskKey !== undefined) task[spec.extraTaskKey] = 1;
  return {
    method: "POST",
    url,
    json: { task, ...(spec.responseView ? { responseView: spec.responseView } : {}) },
  };
}

/** The task name (resource name) a step addresses, for the reads and deletes. */
export function taskNameOf(spec, ctx) {
  const fn = functionOfRoleOrAbsent(ctx.runId, spec.role);
  return queueName(fn) + "/tasks/" + taskId(ctx.runId, spec.id);
}

/** The request of any step. */
export function materialize(spec, ctx) {
  if (spec.kind === "create") return materializeCreate(spec, ctx);
  const fn = functionOfRoleOrAbsent(ctx.runId, spec.role);
  const queueUrl = `https://cloudtasks.googleapis.com/v2/projects/${PROJECT}/locations/${REGION}/queues/${fn}`;
  if (spec.kind === "get-queue") return { method: "GET", url: queueUrl };
  const url = queueUrl + "/tasks/" + taskId(ctx.runId, spec.id);
  if (spec.kind === "get-task") return { method: "GET", url };
  if (spec.kind === "delete") return { method: "DELETE", url };
  throw new Error("unknown step kind " + spec.kind);
}

const TIME_LIKE = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$/;

/**
 * The time-free shape of a createTask body: the planned time is replaced by its form, so the shape of a step is the same
 * whenever it is sent. The guard allows a createTask whose shape is the shape of a step of the program.
 */
export function shapeOf(json) {
  const copy = structuredClone(json);
  const task = copy?.task;
  if (task && typeof task.scheduleTime === "string")
    task.scheduleTime = TIME_LIKE.test(task.scheduleTime)
      ? task.scheduleTime
          .replace(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d/, "T")
          .replace(/\.\d+/, ".fraction")
          .replace(/(Z|[+-]\d\d:\d\d)$/, (z) => (z === "Z" ? "Z" : "offset"))
      : task.scheduleTime;
  return JSON.stringify(copy);
}

const DUMMY_TARGET = { uri: "https://x.run.app", serviceAccountEmail: "a@b.gserviceaccount.com" };

/** The shapes of every createTask of a run, for the guard, with the targets the readbacks will give. */
export function plannedShapes(runId, targets) {
  const filled = Object.fromEntries(
    ROLE_IDS.map((role) => [role, targets?.[role] ?? DUMMY_TARGET]),
  );
  return new Set(
    PROGRAM.filter((s) => s.kind === "create").map((spec) =>
      shapeOf(materializeCreate(spec, { runId, now: 1_800_000_000_000, targets: filled }).json),
    ),
  );
}

/** The task resource names the program deletes and reads, for the guard. */
export function plannedTaskNames(runId) {
  return new Set(
    PROGRAM.filter((s) => s.kind === "delete" || s.kind === "get-task").map((spec) =>
      taskNameOf(spec, { runId }),
    ),
  );
}

/** The manifest: the symbolic program, a pin for the packet and the closure record. */
export function corpusManifest() {
  const steps = PROGRAM.map(({ key, kind, role, groups, ...rest }) => ({
    key,
    kind,
    role,
    groups,
    ...rest,
  }));
  const text = JSON.stringify({ schemaVersion: 1, conditions: CONDITION_IDS, steps });
  return {
    schemaVersion: 1,
    steps,
    conditions: CONDITION_IDS,
    corpusSha256: createHash("sha256").update(text).digest("hex"),
  };
}
