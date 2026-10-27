// The 1st gen target operations of the CV14 recorder: the same discipline as the 2nd gen ones of the
// FUNCTIONS-HTTP recorder (exact names, one delete that is never repeated, a read-back, the upload
// ledger settled before the target counts as clean), on the v1 API, where a function has no Cloud Run
// service of its own and a delete is polled through `operations/<id>`.

import assert from "node:assert/strict";
import { test } from "node:test";

import { PROJECT } from "../../functions-http/harness.mjs";
import {
  assertGen1Absent,
  cleanupGen1,
  deployGen1,
  gen1FunctionUrl,
  gen1PackageName,
  readDeployedGen1,
  resolveGen1Target,
  validateGen1Record,
} from "./gen1.mjs";

const spec = (extra = {}) => ({
  functionName: "rtdbCreatedV1",
  region: "us-central1",
  codebase: "rtdb-functions-oracle",
  generation: "gcfv1",
  ...extra,
});
const RESOURCE = `projects/${PROJECT}/locations/us-central1/functions/rtdbCreatedV1`;
const OPERATION = "operations/b3BlcmF0aW9uLTE";
// Gen1 image packages are named by the function's snake_case name alone (FE stage 2: `fs_created_v1`).
const PACKAGE = `projects/${PROJECT}/locations/us-central1/repositories/gcf-artifacts/packages/rtdb_created_v1`;

const record = (over = {}) => ({
  name: RESOURCE,
  status: "ACTIVE",
  entryPoint: "rtdbCreatedV1",
  runtime: "nodejs22",
  labels: {
    "firebase-functions-codebase": "rtdb-functions-oracle",
    "deployment-tool": "cli-firebase",
  },
  eventTrigger: {
    eventType: "providers/google.firebase.database/eventTypes/ref.create",
    resource: "x",
  },
  ...over,
});

test("a 1st gen spec is a plain object with the same reviewed fields, and its generation is gcfv1", () => {
  const target = resolveGen1Target(spec());
  assert.equal(target.generation, "gcfv1");
  assert.equal(target.functionName, "rtdbCreatedV1");
  assert.equal(target.project, PROJECT);
  assert.equal(target.key, "rtdbCreatedV1");
  assert.equal(target.resourceId, "us-central1/rtdbCreatedV1");
  assert.ok(Object.isFrozen(target));
  assert.equal(resolveGen1Target(target), target, "a resolved spec is returned unchanged");
  assert.equal(gen1FunctionUrl(target), `https://cloudfunctions.googleapis.com/v1/${RESOURCE}`);
  for (const bad of [
    spec({ generation: "gcfv2" }),
    spec({ generation: undefined }),
    spec({ project: "someone-else" }),
    spec({ functionName: "default" }),
    spec({ region: "US-central1" }),
    spec({ extra: 1 }),
    "http",
    null,
    [],
  ]) {
    assert.throws(() => resolveGen1Target(bad), /./u, JSON.stringify(bad));
  }
});

test("the function must be absent before a deploy", async () => {
  const target = resolveGen1Target(spec());
  const urls = [];
  const absent = async (method, url, _b, _k, allowed) => {
    urls.push([method, url, allowed]);
    return { status: 404, value: {} };
  };
  await assertGen1Absent(absent, target);
  assert.deepEqual(urls, [["GET", gen1FunctionUrl(target), [200, 404]]]);
  const present = async () => ({ status: 200, value: record() });
  await assert.rejects(() => assertGen1Absent(present, target), /already exists/);
});

test("a deployed record must name the reviewed resource, codebase and tool, and be active", () => {
  const target = resolveGen1Target(spec());
  assert.doesNotThrow(() => validateGen1Record(record(), target));
  const cases = [
    [{ name: `${RESOURCE}x` }, /name/],
    [{ status: "DEPLOYING" }, /not active/],
    [{ entryPoint: "other" }, /runtime or entry point/],
    [{ runtime: "nodejs20" }, /runtime or entry point/],
    [{ labels: {} }, /codebase/],
    [
      { labels: { "firebase-functions-codebase": "other", "deployment-tool": "cli-firebase" } },
      /codebase/,
    ],
    [{ labels: { "firebase-functions-codebase": "rtdb-functions-oracle" } }, /tool/],
    [{ eventTrigger: undefined }, /event trigger/],
    [{ eventTrigger: {} }, /event trigger/],
  ];
  for (const [over, message] of cases) {
    assert.throws(() => validateGen1Record(record(over), target), message, JSON.stringify(over));
  }
  assert.throws(() => validateGen1Record(null, target), /name/);
});

test("a read of the deployed function keeps the record's trigger for the evidence", async () => {
  const target = resolveGen1Target(spec());
  const state = {};
  await readDeployedGen1(async () => ({ status: 200, value: record() }), target, state);
  assert.equal(
    state.record.eventTrigger.eventType,
    "providers/google.firebase.database/eventTypes/ref.create",
  );
});

test("a deploy starts the upload ledger entry as a 1st gen one, then runs the CLI with the codebase selector", async () => {
  const target = resolveGen1Target(spec());
  const begun = [];
  const uploads = {
    region: "us-central1",
    beginDeploy: async (key, options) => {
      begun.push([key, options]);
      return { observe() {}, receipt() {}, finish: async () => ({ clean: true }) };
    },
  };
  const ran = [];
  const state = { started: false, cleaned: false };
  const events = [];
  await deployGen1(
    target,
    "cv14-1",
    state,
    uploads,
    "/adc",
    {},
    "/run",
    async (args, _a, _b, kind, _d, track) => {
      ran.push([args, kind]);
      track.onEvent({ type: "external-upload" }, "line");
    },
    (event, line) => events.push([event.type, line]),
  );
  assert.deepEqual(begun, [["cv14-1:rtdbCreatedV1", { generation: 1 }]]);
  assert.deepEqual(ran, [
    [["deploy", "--only", "functions:rtdb-functions-oracle:rtdbCreatedV1"], "cliDeploy"],
  ]);
  assert.deepEqual(events, [["external-upload", "line"]]);
  assert.equal(state.started, true);
  assert.equal(state.target, target);
  await assert.rejects(
    () =>
      deployGen1(
        target,
        "cv14-1",
        {},
        { region: "europe-west1", beginDeploy: begun.push },
        "/adc",
        {},
        "/run",
        async () => {},
      ),
    /region/,
  );
});

function world({
  present = true,
  operation = { name: OPERATION, metadata: { target: RESOURCE }, done: false },
  polls = 2,
  failDelete = false,
  stays = false,
  packages = {},
} = {}) {
  const calls = [];
  let remaining = polls;
  let exists = present;
  const control = async (method, url, _body, kind, allowed = [200]) => {
    calls.push({ method, url, kind });
    let answer;
    if (method === "DELETE") {
      if (failDelete) throw new Error("socket hang up");
      exists = stays;
      answer = { status: 200, value: operation };
    } else if (url.includes("artifactregistry.googleapis.com")) {
      const [path, query] = url.split("/v1/")[1].split("?");
      const hit = packages[path.replace(/\/versions$/u, "")];
      if (query !== undefined) {
        answer = {
          status: 200,
          value: {
            ...(hit?.versions ? { versions: hit.versions.map((name) => ({ name })) } : {}),
            ...(hit?.token ? { nextPageToken: hit.token } : {}),
          },
        };
      } else
        answer = hit
          ? { status: 200, value: { name: hit.name ?? path } }
          : { status: 404, value: {} };
    } else if (url.includes("/v1/operations/")) {
      remaining -= 1;
      answer = { status: 200, value: { name: OPERATION, done: remaining <= 0 } };
    } else answer = exists ? { status: 200, value: record() } : { status: 404, value: {} };
    if (!allowed.includes(answer.status)) throw new Error(`status ${answer.status}`);
    return answer;
  };
  return { control, calls };
}
const noSleep = async () => {};

test("a function is deleted once by its exact resource, the operation is polled, and the read-back settles it", async () => {
  const target = resolveGen1Target(spec());
  const w = world();
  const logs = [];
  const finished = [];
  const state = {
    started: true,
    cleaned: false,
    target,
    upload: { finish: async (arg) => (finished.push(arg), { clean: true }) },
    deployTrack: { exited: true, exitCode: 0 },
  };
  await cleanupGen1(w.control, target, state, {
    log: async (a, d) => logs.push([a, d]),
    sleep: noSleep,
  });
  assert.equal(state.cleaned, true, state.cleanupError);
  assert.deepEqual(
    w.calls.map((c) => `${c.method} ${c.url.replace(/^https:\/\/[^/]+/u, "")}`),
    [
      `GET /v1/${RESOURCE}`,
      `DELETE /v1/${RESOURCE}`,
      `GET /v1/${OPERATION}`,
      `GET /v1/${OPERATION}`,
      `GET /v1/${RESOURCE}`,
      `GET /v1/${PACKAGE}`,
      `GET /v1/${PACKAGE}%2Fcache`,
    ],
  );
  assert.ok(w.calls.every((c) => c.kind === "cleanup"));
  assert.deepEqual(finished, [{ cliExited: true, exitCode: 0 }]);
  assert.ok(logs.some(([a]) => a === "function-deleted"));
});

test("an absent function is not deleted, and a delete that cannot be trusted leaves the target residual", async () => {
  const target = resolveGen1Target(spec());
  const gone = world({ present: false });
  const state = { started: true, cleaned: false, target };
  await cleanupGen1(gone.control, target, state, { log: async () => {}, sleep: noSleep });
  assert.equal(state.cleaned, true);
  assert.equal(gone.calls.filter((c) => c.method === "DELETE").length, 0);

  const notStarted = { started: false, cleaned: false, target };
  const idle = world();
  await cleanupGen1(idle.control, target, notStarted, { log: async () => {}, sleep: noSleep });
  assert.equal(idle.calls.length, 0, "nothing is sent for a deploy that never started");

  for (const [name, options, message] of [
    ["a delete that threw", { failDelete: true }, /socket hang up/],
    [
      "an operation of another function",
      { operation: { name: OPERATION, metadata: { target: `${RESOURCE}2` }, done: false } },
      /unreviewed delete operation/,
    ],
    [
      "an operation name outside the reviewed form",
      { operation: { name: "operations/../x", metadata: { target: RESOURCE } } },
      /unreviewed delete operation/,
    ],
    ["an operation that never ends", { polls: 99 }, /did not complete/],
  ]) {
    const w = world(options);
    const residual = { started: true, cleaned: false, target };
    await cleanupGen1(w.control, target, residual, { log: async () => {}, sleep: noSleep });
    assert.equal(residual.cleaned, false, name);
    assert.match(residual.cleanupError, message, name);
    assert.equal(
      w.calls.filter((c) => c.method === "DELETE").length,
      options.failDelete ? 1 : 1,
      name,
    );
    assert.ok(w.calls.filter((c) => c.url.includes("/operations/")).length <= 10, name);
  }
});

test("an upload that is not accounted for keeps the target from being clean even when the function is gone", async () => {
  const target = resolveGen1Target(spec());
  const w = world({ present: false });
  const state = {
    started: true,
    cleaned: false,
    target,
    upload: { finish: async () => ({ clean: false, reasons: ["unexplained-object:x"] }) },
    deployTrack: { exited: true, exitCode: 0 },
  };
  await cleanupGen1(w.control, target, state, { log: async () => {}, sleep: noSleep });
  assert.equal(state.cleaned, false);
  assert.match(state.cleanupError, /source upload not cleaned: unexplained-object:x/);
});

test("a function that is still there after the delete operation ended leaves the target residual", async () => {
  const target = resolveGen1Target(spec());
  const w = world({ stays: true });
  const state = { started: true, cleaned: false, target };
  await cleanupGen1(w.control, target, state, { log: async () => {}, sleep: noSleep });
  assert.equal(state.cleaned, false);
  assert.match(state.cleanupError, /function remains after delete/);
});

test("the image packages of a 1st gen function are read by their exact names after the delete", async () => {
  const target = resolveGen1Target(spec());
  const clean = world();
  const state = { started: true, cleaned: false, target };
  await cleanupGen1(clean.control, target, state, { log: async () => {}, sleep: noSleep });
  assert.equal(state.cleaned, true, state.cleanupError);
  const reads = clean.calls.filter((c) => c.url.includes("artifactregistry"));
  assert.deepEqual(
    reads.map((c) => c.url),
    [
      `https://artifactregistry.googleapis.com/v1/${PACKAGE}`,
      `https://artifactregistry.googleapis.com/v1/${PACKAGE}%2Fcache`,
    ],
  );
  assert.ok(reads.every((c) => c.kind === "cleanup" && c.method === "GET"));

  // an empty package is no residue, a version left in either is
  const empty = world({ packages: { [PACKAGE]: { versions: [] } } });
  const emptyState = { started: true, cleaned: false, target };
  await cleanupGen1(empty.control, target, emptyState, { log: async () => {}, sleep: noSleep });
  assert.equal(emptyState.cleaned, true, emptyState.cleanupError);
  for (const name of [PACKAGE, `${PACKAGE}%2Fcache`]) {
    const left = world({ packages: { [name]: { versions: [`${name}/versions/sha256:x`] } } });
    const leftState = { started: true, cleaned: false, target };
    await cleanupGen1(left.control, target, leftState, { log: async () => {}, sleep: noSleep });
    assert.equal(leftState.cleaned, false, name);
    assert.match(leftState.cleanupError, /owned image version remains in rtdb_created_v1/);
  }
  // a version list that goes on is more than empty
  const longer = world({ packages: { [PACKAGE]: { versions: [], token: "more" } } });
  const longerState = { started: true, cleaned: false, target };
  await cleanupGen1(longer.control, target, longerState, { log: async () => {}, sleep: noSleep });
  assert.match(longerState.cleanupError, /owned image version remains/);
  // a package that answers with another name is not read as ours
  const renamed = world({ packages: { [PACKAGE]: { name: `${PACKAGE}x`, versions: [] } } });
  const renamedState = { started: true, cleaned: false, target };
  await cleanupGen1(renamed.control, target, renamedState, { log: async () => {}, sleep: noSleep });
  assert.match(renamedState.cleanupError, /package name changed/);
  // the name is the snake_case of the function's name
  assert.equal(
    gen1PackageName(resolveGen1Target(spec({ functionName: "rtdbDeletedV1" })))
      .split("/")
      .at(-1),
    "rtdb_deleted_v1",
  );
});

test("the upload ledger is settled before the image residue is checked, so a residue does not leave the deploy's placeholder open", async () => {
  const target = resolveGen1Target(spec());
  const order = [];
  const w = world({ packages: { [PACKAGE]: { versions: [`${PACKAGE}/versions/sha256:x`] } } });
  const watched = async (method, url, ...rest) => {
    if (url.includes("artifactregistry")) order.push("residue-read");
    return w.control(method, url, ...rest);
  };
  const state = {
    started: true,
    cleaned: false,
    target,
    upload: { finish: async () => (order.push("finish"), { clean: true }) },
    deployTrack: { exited: true, exitCode: 0 },
  };
  await cleanupGen1(watched, target, state, { log: async () => {}, sleep: noSleep });
  assert.equal(state.cleaned, false);
  assert.match(state.cleanupError, /owned image version remains/);
  assert.equal(order[0], "finish", order.join(","));
  assert.ok(order.includes("residue-read"));
  // an unclean upload and a residue: both are cleanup errors, the residue is the one reported first
  const both = {
    started: true,
    cleaned: false,
    target,
    upload: { finish: async () => ({ clean: false, reasons: ["unexplained-object:x"] }) },
    deployTrack: { exited: true, exitCode: 0 },
  };
  await cleanupGen1(w.control, target, both, { log: async () => {}, sleep: noSleep });
  assert.equal(both.cleaned, false);
  assert.match(both.cleanupError, /owned image version remains/);
  assert.match(both.uploadCleanupError, /unexplained-object:x/);
});
