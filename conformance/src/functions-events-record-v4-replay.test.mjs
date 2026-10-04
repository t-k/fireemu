// The judges the v4 run showed to be wrong or missing (readiness names, the CLI's own error count, the region of each
// endpoint, the REST delete rules), run over the bodies that run recorded: committed with only the project number
// replaced (record/recorded/v4-run), and over the real 153 responses when the shared docs.local is visible.

import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  cliFailed,
  erroredFunctions,
  regionProblems,
  runCli,
  summarize,
} from "./functions-events/record/deploy.mjs";
import { RULES, destination } from "./functions-events/record/guard.mjs";
import { HANDLERS } from "./functions-events/record/logs.mjs";

const recorded = (name) =>
  readFileSync(
    new URL(`./functions-events/record/recorded/v4-run/${name}`, import.meta.url),
    "utf8",
  );
const body = (name) => JSON.parse(recorded(`${name}.json`)).body;
const list = (items, complete = true) => ({ items, complete });
const empty = () => list([]);
const GEN1 = HANDLERS.filter((h) => h.generation === 1).map((h) => h.name);
const GEN2 = HANDLERS.filter((h) => h.generation === 2).map((h) => h.name);

// ---- readiness over the recorded lists --------------------------------------------------------------

test("readiness on the recorded poll: 21 handlers are active (11 Gen1, the 10 Gen2 that were in us-central1), pubsubPublishedV2 is not", () => {
  const summary = summarize({
    v1: list(body("0028-lists.functions-v1").functions),
    v2: list(body("0029-lists.functions-v2").functions),
    run: empty(),
    eventarc: empty(),
  });
  assert.equal(summary.functionsListed, 32, "the v2 list also lists the Gen1 functions");
  assert.deepEqual(
    summary.functionsActive.toSorted(),
    [...GEN1, ...GEN2.filter((n) => n !== "pubsubPublishedV2")].toSorted(),
  );
  assert.equal(summary.ready, false);
  assert.equal(
    summary.functionsActive.length,
    21,
    "the v4 judge found 11: it lower-cased the Gen2 names the API keeps in case",
  );
});

test("readiness needs all 22 active, Gen2 names matched exactly: a lower-cased name is not the function", () => {
  const items = (names, state) =>
    names.map((name) => ({ name: `projects/p/locations/us-central1/functions/${name}`, state }));
  const v1 = list(
    GEN1.map((name) => ({
      name: `projects/p/locations/us-central1/functions/${name}`,
      status: "ACTIVE",
    })),
  );
  const ready = summarize({ v1, v2: list(items(GEN2, "ACTIVE")), run: empty(), eventarc: empty() });
  assert.equal(ready.functionsActive.length, 22);
  const lowered = summarize({
    v1,
    v2: list(
      items(
        GEN2.map((n) => n.toLowerCase()),
        "ACTIVE",
      ),
    ),
    run: empty(),
    eventarc: empty(),
  });
  assert.equal(lowered.functionsActive.length, 11, "only the Gen1 functions");
  const unknown = summarize({
    v1,
    v2: list(items(GEN2, "UNKNOWN")),
    run: empty(),
    eventarc: empty(),
  });
  assert.equal(unknown.functionsActive.length, 11);
});

test("the cleanup summary on the recorded final lists: one function (UNKNOWN), its Run service and trigger, so not absent", () => {
  const summary = summarize({
    v1: empty(),
    v2: list(body("0140-lists.functions-v2").functions),
    run: list(body("0141-lists.run-services").services),
    eventarc: list(body("0142-lists.eventarc-triggers").triggers),
  });
  assert.equal(summary.functionsListed, 1);
  assert.deepEqual(summary.functionsActive, []);
  assert.deepEqual(summary.runServices, ["storageArchivedV2"]);
  assert.deepEqual(summary.eventarcTriggers, ["storageArchivedV2"]);
  assert.equal(summary.absent, false);
  assert.equal(summary.complete, true);
});

// ---- the CLI's own error count ---------------------------------------------------------------------

test("the CLI delete's recorded summary says 1 Functions Errored; the deploy's says 0", () => {
  assert.equal(erroredFunctions(recorded("cli-delete-tail.txt")), 1);
  assert.equal(erroredFunctions(recorded("cli-deploy-tail.txt")), 0);
});

test("erroredFunctions reads the summary line and nothing else", () => {
  assert.equal(erroredFunctions("3 Functions Errored"), 3);
  assert.equal(erroredFunctions("[2026-10-04T16:34:49.427Z] 1 Function Errored\n"), 1);
  assert.equal(
    erroredFunctions("[t] 0 Functions Errored\n[t] 2 Functions Errored\n"),
    2,
    "the last summary counts",
  );
  assert.equal(erroredFunctions("[t] 10 Functions Errored   \n"), 10);
  for (const text of [
    "",
    "Deploy complete!",
    "0 Function Deployments Aborted",
    "a 3 Functions Errored b",
    "Functions Errored",
    "x Functions Errored",
    "-1 Functions Errored",
  ])
    assert.equal(erroredFunctions(text), null, JSON.stringify(text));
});

test("a CLI result fails on a non-zero exit, a timeout, an error, or any errored function, even with exit 0", () => {
  assert.equal(cliFailed({ exitCode: 0, errored: 0 }), false);
  assert.equal(cliFailed({ exitCode: 0, errored: null }), false, "a dry run prints no summary");
  assert.equal(cliFailed({ exitCode: 0 }), false);
  assert.equal(
    cliFailed({ exitCode: 0, errored: 1 }),
    true,
    "the v4 delete: exit 0 and 1 Functions Errored",
  );
  assert.equal(cliFailed({ exitCode: 0, errored: 7 }), true);
  assert.equal(cliFailed({ exitCode: 1, errored: 0 }), true);
  assert.equal(cliFailed({ exitCode: null, errored: 0 }), true);
  assert.equal(cliFailed({ exitCode: 0, timedOut: true }), true);
  assert.equal(cliFailed({ exitCode: 0, error: "the CLI had to be killed" }), true);
  assert.equal(cliFailed(undefined), true);
});

test("runCli reports the errored count from the output file it wrote", async () => {
  for (const [file, expected] of [
    ["cli-delete-tail.txt", 1],
    ["cli-deploy-tail.txt", 0],
  ]) {
    const directory = mkdtempSync(join(tmpdir(), "fe-cli-"));
    const script = join(directory, "print.js");
    writeFileSync(script, `process.stdout.write(${JSON.stringify(recorded(file))});`);
    const result = await runCli({
      action: "delete",
      plan: { args: [], cwd: directory, env: { PATH: "/usr/bin" } },
      firebaseJs: script,
      node: process.execPath,
      directory,
    });
    assert.equal(result.exitCode, 0, file);
    assert.equal(result.errored, expected, file);
    assert.equal(cliFailed(result), expected > 0, file);
  }
  const directory = mkdtempSync(join(tmpdir(), "fe-cli-"));
  const script = join(directory, "quiet.js");
  writeFileSync(script, 'process.stdout.write("Deploy complete!\\n");');
  const quiet = await runCli({
    action: "deploy",
    plan: { args: [], cwd: directory, env: { PATH: "/usr/bin" } },
    firebaseJs: script,
    node: process.execPath,
    directory,
  });
  assert.equal(quiet.errored, null);
});

// ---- the region of each endpoint -------------------------------------------------------------------

test("the dry run's recorded manifest: no endpoint names a region, and only the Pub/Sub Gen2 trigger is refused", () => {
  const { endpoints } = JSON.parse(recorded("dry-run-manifest.json"));
  assert.equal(Object.keys(endpoints).length, 22);
  assert.ok(Object.values(endpoints).every((e) => e.region === undefined || e.region === null));
  const problems = regionProblems(endpoints);
  assert.equal(problems.length, 1, JSON.stringify(problems));
  assert.match(problems[0], /^pubsubPublishedV2: no region is set/);
  const pinned = {
    ...endpoints,
    pubsubPublishedV2: { ...endpoints.pubsubPublishedV2, region: ["us-central1"] },
  };
  assert.deepEqual(regionProblems(pinned), []);
});

test("regionProblems: a set region must be exactly us-central1, and an unset one only where the resource places the trigger", () => {
  const endpoint = (over) => ({
    platform: "gcfv2",
    eventTrigger: { eventType: "google.cloud.pubsub.topic.v1.messagePublished" },
    ...over,
  });
  const refused = (e) => regionProblems({ x: e }).length === 1;
  assert.deepEqual(regionProblems({ x: endpoint({ region: ["us-central1"] }) }), []);
  for (const region of [
    ["us-east1"],
    ["us-central1", "us-east1"],
    [],
    "us-central1",
    ["US-CENTRAL1"],
    ["us-central1 "],
  ])
    assert.ok(refused(endpoint({ region })), JSON.stringify(region));
  assert.ok(refused(endpoint({})), "a Gen2 Pub/Sub trigger with no region goes to us-east1");
  assert.ok(
    refused(endpoint({ eventTrigger: { eventType: "google.firebase.database.ref.v1.written" } })),
  );
  assert.ok(refused(endpoint({ eventTrigger: undefined })));
  assert.deepEqual(
    regionProblems({
      x: endpoint({ eventTrigger: { eventType: "google.cloud.firestore.document.v1.created" } }),
    }),
    [],
  );
  assert.deepEqual(
    regionProblems({
      x: endpoint({ eventTrigger: { eventType: "google.cloud.storage.object.v1.finalized" } }),
    }),
    [],
  );
  assert.deepEqual(
    regionProblems({
      x: { platform: "gcfv1", eventTrigger: { eventType: "google.pubsub.topic.publish" } },
    }),
    [],
  );
  assert.ok(refused({ platform: "gcfv1", region: ["us-east1"] }));
  assert.deepEqual(regionProblems({}), []);
});

// ---- the REST delete rules -----------------------------------------------------------------------

test("the recorder's rules allow the REST delete of a Gen2 function of the run and the operation reads, nothing broader", () => {
  const P = "fireemu-oracle-events";
  const fn = (region, name) =>
    `https://cloudfunctions.googleapis.com/v2/projects/${P}/locations/${region}/functions/${name}`;
  const del = (url) => destination({ method: "DELETE", url, mutation: true }).rule;
  for (const name of GEN2) assert.equal(del(fn("us-central1", name)), "functions-v2-delete", name);
  assert.equal(
    destination({
      method: "GET",
      url: `https://cloudfunctions.googleapis.com/v2/projects/${P}/locations/us-central1/operations/operation-1791131667207-65d0656c5167c-7952d5be-c715c3b6`,
      mutation: false,
    }).rule,
    "functions-v2-operation-get",
  );
  const refused = [
    fn("us-central1", "fsCreatedV1"),
    fn("us-central1", "storageArchivedV2x"),
    fn("us-central1", "storagearchivedv2"),
    fn("us-east1", "pubsubPublishedV2"),
    fn("us-central1", "other"),
    `${fn("us-central1", "fsCreatedV2")}?force=true`,
    `${fn("us-central1", "fsCreatedV2")}/`,
    `https://cloudfunctions.googleapis.com/v1/projects/${P}/locations/us-central1/functions/fsCreatedV1`,
    `https://cloudfunctions.googleapis.com/v2/projects/other/locations/us-central1/functions/fsCreatedV2`,
  ];
  for (const url of refused)
    assert.ok(destination({ method: "DELETE", url, mutation: true }).problem, url);
  assert.match(
    destination({ method: "DELETE", url: fn("us-central1", "fsCreatedV2"), mutation: false })
      .problem,
    /mutation=false/,
  );
  assert.equal(
    RULES.filter((r) => r.name.startsWith("functions-v2-")).length,
    3,
    "the list, the delete and the operation read",
  );
  assert.equal(
    RULES.filter((r) => r.method === "DELETE" && r.host === "cloudfunctions.googleapis.com").length,
    1,
  );
});

// ---- over the real 153 responses (when this checkout can see them) ----------------------------------

const realRuns =
  process.env.FE_SANDBOX_RUNS ?? join(import.meta.dirname, "../../../../docs.local/runs");
const realResponses = join(
  realRuns,
  "functions-events-formal-20261004T161049Z-17272a4f69f41f21",
  "transport",
  "responses",
);
const haveReal = existsSync(join(realResponses, "0153-capture.list.json"));
const real = (file) => JSON.parse(readFileSync(join(realResponses, file), "utf8")).body;

test(
  "real run: the committed fixtures are the recorded bodies with only the project number replaced",
  { skip: !haveReal },
  () => {
    for (const name of readdirSync(
      new URL("./functions-events/record/recorded/v4-run/", import.meta.url),
    ).filter((f) => /^\d{4}-.*\.json$/.test(f))) {
      const text = readFileSync(join(realResponses, name), "utf8");
      const number = /(\d{12})-compute@/.exec(text)?.[1];
      const sanitized = (number ? text.replaceAll(number, "123456789012") : text).replaceAll(
        /uploads-\d{12}/g,
        "uploads-100000000001",
      );
      assert.deepEqual(JSON.parse(recorded(name)), JSON.parse(sanitized), name);
    }
  },
);

test(
  "real run: every one of the 40 readiness polls shows the same 21 active handlers and is not ready",
  { skip: !haveReal },
  () => {
    const files = readdirSync(realResponses).toSorted();
    const firstCleanup = files.findIndex((f) => f.includes("cleanup."));
    const v1 = files.filter((f, i) => f.includes("lists.functions-v1") && i < firstCleanup);
    const v2 = files.filter((f, i) => f.includes("lists.functions-v2") && i < firstCleanup);
    assert.equal(v1.length, 40);
    assert.equal(v2.length, 40);
    for (let i = 0; i < 40; i += 1) {
      const summary = summarize({
        v1: list(real(v1[i]).functions ?? []),
        v2: list(real(v2[i]).functions ?? []),
        run: empty(),
        eventarc: empty(),
      });
      assert.equal(summary.functionsActive.length, 21, `poll ${i + 1}`);
      assert.ok(!summary.functionsActive.includes("pubsubPublishedV2"));
      assert.equal(summary.ready, false);
    }
  },
);

test("real run: the cleanup lists read as the run recorded them", { skip: !haveReal }, () => {
  const files = readdirSync(realResponses).toSorted();
  const last = (kind) => files.filter((f) => f.includes(kind)).at(-1);
  const summary = summarize({
    v1: list(real(last("lists.functions-v1")).functions ?? []),
    v2: list(real(last("lists.functions-v2")).functions ?? []),
    run: list(real(last("lists.run-services")).services ?? []),
    eventarc: list(real(last("lists.eventarc-triggers")).triggers ?? []),
  });
  assert.deepEqual(
    [summary.functionsListed, summary.runServices, summary.eventarcTriggers, summary.absent],
    [1, ["storageArchivedV2"], ["storageArchivedV2"], false],
  );
  const run = JSON.parse(
    readFileSync(join(realResponses, "..", "..", "production-run.json"), "utf8"),
  );
  assert.match(
    run.cleanup.problems[0],
    /"functionsListed":1,"runServices":\["storageArchivedV2"\]/,
  );
});

test(
  "real run: the dry run's manifest in the CLI log is the committed one",
  { skip: !haveReal },
  () => {
    const log = readFileSync(
      join(realResponses, "..", "..", "cli", "cli-dry-run-stdout.txt"),
      "utf8",
    )
      .split("\n")
      .find((l) => l.includes("Got response from /__/functions.yaml"));
    assert.deepEqual(
      JSON.parse(log.slice(log.indexOf("{"))),
      JSON.parse(recorded("dry-run-manifest.json")),
    );
  },
);
