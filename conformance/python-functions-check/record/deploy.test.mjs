// The deploy helpers: the declaration check of the SDK's own discovery, the readiness summary, the CLI plan, and the
// refusals of the source copy.
import assert from "node:assert/strict";
import test from "node:test";
import { tempDir } from "./testtmp.mjs";
import {
  allActive,
  cliPlan,
  declarationProblems,
  nonePresent,
  prepareSource,
  sdkVersionProblems,
  sourceProblems,
  summarize,
} from "./deploy.mjs";
import { ALL_FUNCTIONS, REGION, functionName } from "./plan.mjs";

const TYPES = {
  pcfsc: "google.cloud.firestore.document.v1.created",
  pcfscraw: "google.cloud.firestore.document.v1.created",
  pcfsu: "google.cloud.firestore.document.v1.updated",
  pcps: "google.cloud.pubsub.topic.v1.messagePublished",
  pcpsraw: "google.cloud.pubsub.topic.v1.messagePublished",
  pcst: "google.cloud.storage.object.v1.finalized",
  pcstraw: "google.cloud.storage.object.v1.finalized",
  pcea: "pycheck.thing.v1.happened",
  pcearaw: "pycheck.thing.v1.happened",
};
const endpoints = () =>
  Object.fromEntries(
    ALL_FUNCTIONS.map((fn) => [
      fn,
      {
        entryPoint: fn,
        platform: "gcfv2",
        region: [REGION],
        eventType: TYPES[fn] ?? null,
        filters: fn.startsWith("pcps") ? { topic: "pycheck-orders" } : null,
        schedule: fn.startsWith("pcsch") ? "0 0 1 1 *" : null,
        timeZone: fn.startsWith("pcsch") ? "UTC" : null,
        taskQueue: fn.startsWith("pctask"),
        maxAttempts: fn.startsWith("pctask") ? 1 : null,
        taskInvoker: null,
      },
    ]),
  );

test("the declared endpoints of the fixture pass", () =>
  assert.deepEqual(declarationProblems(endpoints()), []));

const BREAKS = [
  ["a missing function", (e) => delete e.pcps, /expected/],
  ["an extra function", (e) => (e.extra = e.pcps), /expected/],
  ["a wrong entry point", (e) => (e.pcps.entryPoint = "x"), /pcps: entry point/],
  ["a wrong platform", (e) => (e.pcps.platform = "gcfv1"), /pcps: platform/],
  ["another region", (e) => (e.pcps.region = ["europe-west1"]), /pcps: region/],
  ["two regions", (e) => (e.pcps.region = [REGION, "europe-west1"]), /pcps: region/],
  ["a wrong event type", (e) => (e.pcst.eventType = "x"), /pcst: event type/],
  ["a wrong schedule", (e) => (e.pcsch.schedule = "every 1 minutes"), /pcsch: schedule/],
  ["a wrong time zone", (e) => (e.pcschraw.timeZone = "Asia/Tokyo"), /pcschraw: time zone/],
  ["not a task queue", (e) => (e.pctask.taskQueue = false), /pctask: not a task queue/],
  ["retries on", (e) => (e.pctaskraw.maxAttempts = 3), /pctaskraw: max attempts/],
  ["another topic", (e) => (e.pcps.filters = { topic: "other" }), /pcps: topic/],
  [
    "a task queue invoker (firebase-tools would grant it)",
    (e) => (e.pctask.taskInvoker = ["public"]),
    /pctask: task queue invoker/,
  ],
  [
    "a private task queue invoker is still a declared one",
    (e) => (e.pctaskraw.taskInvoker = ["private"]),
    /pctaskraw: task queue invoker/,
  ],
];
for (const [name, edit, pattern] of BREAKS)
  test(`a declaration problem is reported: ${name}`, () => {
    const e = endpoints();
    edit(e);
    const problems = declarationProblems(e);
    assert.ok(
      problems.some((p) => pattern.test(p)),
      JSON.stringify(problems),
    );
  });

const lists = (states, services = states) => ({
  v2: {
    functions: Object.entries(states).map(([fn, state]) => ({ name: functionName(fn), state })),
  },
  run: {
    services:
      services &&
      Object.keys(services).map((fn) => ({
        name: `projects/p/locations/${REGION}/services/${fn}`,
      })),
  },
});
const active = Object.fromEntries(ALL_FUNCTIONS.map((fn) => [fn, "ACTIVE"]));

test("readiness needs every function ACTIVE with its Cloud Run service", () => {
  assert.equal(allActive(summarize(lists(active))), true);
  assert.equal(allActive(summarize(lists({ ...active, pcps: "DEPLOYING" }, active))), false);
  const { pcps: _, ...rest } = active;
  assert.equal(allActive(summarize(lists(active, rest))), false, "no service yet");
  assert.equal(allActive(summarize(lists(rest))), false);
  assert.equal(allActive(summarize({})), false);
});

test("gone needs no function, no service and no stray of the same id in another region", () => {
  assert.equal(nonePresent(summarize({ v2: { functions: [] }, run: { services: [] } })), true);
  assert.equal(nonePresent(summarize(lists({}, {}))), true);
  assert.equal(nonePresent(summarize(lists(active))), false);
  assert.equal(
    nonePresent(summarize(lists({}, { pcps: 1 }))),
    false,
    "a service without its function",
  );
  const stray = {
    v2: {
      functions: [
        {
          name: "projects/fireemu-oracle-events/locations/europe-west1/functions/pcps",
          state: "ACTIVE",
        },
      ],
    },
    run: { services: [] },
  };
  assert.equal(summarize(stray).pcps.stray, true);
  assert.equal(nonePresent(summarize(stray)), false);
});

const options = {
  configHome: "/h/config",
  configPath: "/s/firebase.json",
  workDir: "/s",
  home: "/h",
  path: "/n:/usr/bin",
};
test("the dry run is the deploy argv with --dry-run last", () => {
  const deploy = cliPlan("deploy", options);
  const dry = cliPlan("dry-run", options);
  assert.deepEqual(dry.args, [...deploy.args, "--dry-run"]);
  assert.ok(deploy.args.includes("--force") && deploy.args.includes("--non-interactive"));
  assert.deepEqual(
    deploy.args.slice(deploy.args.indexOf("--only"), deploy.args.indexOf("--only") + 2),
    ["--only", "functions:pycheck"],
  );
  assert.equal(deploy.args.includes("--dry-run"), false);
});

test("the delete names exactly the thirteen functions, one region and the project, forced and non-interactive", () => {
  const { args } = cliPlan("delete", options);
  assert.equal(args[0], "functions:delete");
  assert.deepEqual(args.slice(1, 14), ALL_FUNCTIONS);
  for (const flag of ["--force", "--non-interactive", "--region", "--project"])
    assert.ok(args.includes(flag), flag);
});

test("the CLI environment is explicit and carries no ambient credential", () => {
  const { env } = cliPlan("deploy", options);
  assert.deepEqual(Object.keys(env).toSorted(), [
    "FIREBASE_CONFIG",
    "GCLOUD_PROJECT",
    "GOOGLE_CLOUD_QUOTA_PROJECT",
    "HOME",
    "PATH",
    "SHELL",
    "XDG_CONFIG_HOME",
  ]);
  assert.equal(env.SHELL, "/bin/bash");
  assert.equal(env.GCLOUD_PROJECT, "fireemu-oracle-events");
});

test("the CLI plan refuses an unknown action, a relative path and a missing PATH", () => {
  assert.throws(() => cliPlan("destroy", options), /unknown CLI action/);
  for (const key of ["configHome", "configPath", "workDir", "home"])
    assert.throws(() => cliPlan("deploy", { ...options, [key]: "relative" }), /absolute/);
  assert.throws(() => cliPlan("deploy", { ...options, path: "" }), /PATH/);
});

test("the source copy needs a full commit SHA", () => {
  const target = tempDir("pc-deploy-");
  for (const bad of [
    "main",
    "abc123",
    "HEAD",
    "0".repeat(39),
    "g".repeat(40),
    "0".repeat(40) + "; rm -rf /",
  ])
    assert.throws(
      () => prepareSource({ repoRoot: "/nonexistent", commit: bad, target }),
      /full SHA/,
    );
});

test("an offline discovery that fails is a problem, not a throw", () => {
  const failing = () => {
    throw Object.assign(new Error("boom"), { stderr: "Traceback: ImportError" });
  };
  const problems = sourceProblems({ fixtureDir: "/x", directory: "/y", discoverFn: failing });
  assert.equal(problems.length, 1);
  assert.match(problems[0], /discovery of the fixture failed: Traceback/);
  assert.deepEqual(
    sourceProblems({ fixtureDir: "/x", directory: "/y", discoverFn: endpointsFn }),
    [],
  );
});
function endpointsFn() {
  return endpoints();
}

test("the SDK version in the environment must be the pinned one", () => {
  assert.deepEqual(
    sdkVersionProblems("/v", () => "0.6.0\n"),
    [],
  );
  assert.match(sdkVersionProblems("/v", () => "0.7.0")[0], /0\.7\.0, not 0\.6\.0/);
  assert.match(
    sdkVersionProblems("/v", () => {
      throw new Error("no");
    })[0],
    /cannot be imported/,
  );
});
