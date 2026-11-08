// The Cloud Tasks-only profile of the check (`PYCHECK_PROFILE=tasks`): two functions under task queue names this project has
// never used, the same judgement as the events profile for `tasks-request`, and nothing sent for the other families. The
// profile is read when `plan.mjs` is imported, so this file runs its tests in a child process that has it set; run without
// the variable it checks that the default profile is the events profile, unchanged.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { ALL_FUNCTIONS, FAMILIES, JOB_IDS, PROFILE, QUEUE_IDS } from "./plan.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const read = (name) => readFileSync(join(root, name), "utf8");

// Every function and queue name any recording on fireemu-oracle-events has used (the thirteen of the events packet; the
// queues of the first two passes are pctask and pctaskraw, deleted on 2026-11-04 and again on 2026-11-07).
const USED_NAMES = [
  "pcfsc",
  "pcfscraw",
  "pcfsu",
  "pcps",
  "pcpsraw",
  "pcst",
  "pcstraw",
  "pcea",
  "pcearaw",
  "pcsch",
  "pcschraw",
  "pctask",
  "pctaskraw",
];

if (process.env.PYCHECK_PROFILE !== "tasks") {
  test("the default profile is the events profile and keeps the thirteen functions and the fixture", async () => {
    assert.equal(PROFILE, "events");
    assert.equal(ALL_FUNCTIONS.length, 13);
    assert.deepEqual([...ALL_FUNCTIONS].toSorted(), [...USED_NAMES].toSorted());
    assert.deepEqual(FAMILIES.tasks, { sdk: "pctask", raw: "pctaskraw" });
    assert.equal(JOB_IDS.length, 2);
    const { PACKET_FILES } = await import("./main.mjs");
    assert.deepEqual(PACKET_FILES.slice(-3), [
      "fixture/main.py",
      "fixture/requirements.txt",
      "firebase.json",
    ]);
  });

  test("the tasks profile suite passes in a child process that selects it", () => {
    const env = { ...process.env, PYCHECK_PROFILE: "tasks" };
    delete env.NODE_TEST_CONTEXT;
    const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url)], {
      env,
      encoding: "utf8",
      timeout: 120_000,
    });
    assert.equal(child.status, 0, child.stdout.slice(-6000) + child.stderr.slice(-2000));
    const passed = Number(/ℹ pass (\d+)/.exec(child.stdout)?.[1]);
    assert.ok(passed >= 10, "the tasks tests ran: " + passed);
    assert.match(child.stdout, /ℹ fail 0/);
  });

  test("the events world's CLI makes the Eventarc channel and its managed topic when the channel is absent", async () => {
    const { createWorld } = await import("./world.mjs");
    const absent = createWorld({ seedChannels: [] });
    assert.equal(absent.channels.size, 0);
    await absent.runCli({ action: "deploy" });
    assert.ok(absent.channels.has("firebase"));
    assert.ok(absent.topics.has("eventarc-channel-us-central1-firebase-450"));
    const present = createWorld({ seedChannels: ["firebase"] });
    await present.runCli({ action: "deploy" });
    assert.ok(!present.topics.has("eventarc-channel-us-central1-firebase-450"));
  });

  test("an unknown profile is refused when plan.mjs is imported", () => {
    const env = { ...process.env, PYCHECK_PROFILE: "everything" };
    delete env.NODE_TEST_CONTEXT;
    const child = spawnSync(
      process.execPath,
      ["--input-type=module", "-e", `await import(${JSON.stringify(join(here, "plan.mjs"))})`],
      { env, encoding: "utf8" },
    );
    assert.notEqual(child.status, 0);
    assert.match(
      child.stderr,
      /Error: PYCHECK_PROFILE is events or tasks, not "everything"\n/,
      "the message itself, not the source line the stack prints",
    );
  });
} else {
  const { packetDigest, PACKET_FILES, packetFiles } = await import("./main.mjs");
  const { declarationProblems, cliPlan, prepareSource } = await import("./deploy.mjs");
  const { operations } = await import("./script.mjs");
  const { judge } = await import("./judge.mjs");
  const { CLEANUP_CEILING, NORMAL_CEILING, record } = await import("./run.mjs");
  const { READBACK_MAX_REQUESTS, readbackRun } = await import("./readback.mjs");
  const plan = await import("./plan.mjs");
  const { NUMBER, createWorld } = await import("./world.mjs");
  const { tempDir } = await import("./testtmp.mjs");
  const { execFileSync } = await import("node:child_process");
  const { mkdirSync, writeFileSync } = await import("node:fs");

  const RUN = "0123456789abcdef";
  const SDK = "pc3task";
  const RAW = "pc3taskraw";

  test("the profile selects the Cloud Tasks family under two names no recording has used", () => {
    assert.equal(PROFILE, "tasks");
    assert.deepEqual(ALL_FUNCTIONS, [SDK, RAW]);
    assert.deepEqual(QUEUE_IDS, [SDK, RAW]);
    assert.deepEqual(JOB_IDS, []);
    assert.deepEqual(plan.SCHEDULER_FUNCTIONS, []);
    assert.deepEqual(plan.TASK_FUNCTIONS, [SDK, RAW]);
    for (const name of ALL_FUNCTIONS) {
      assert.match(
        name,
        /^[a-z][a-z0-9]*$/,
        "a lowercase id valid as a Python name, a Cloud Run service and a queue",
      );
      assert.ok(!USED_NAMES.includes(name), name + " was used before");
      for (const used of USED_NAMES)
        assert.ok(!name.startsWith(used) && !used.startsWith(name), name + " is built on " + used);
    }
    assert.ok(RAW.endsWith("raw"), "the recorder waits for the raw twins by their suffix");
    assert.deepEqual(plan.queueName(SDK).split("/").slice(-2), ["queues", SDK]);
    assert.equal(plan.FIXTURE_DIR, "fixture-tasks");
    assert.equal(plan.FIREBASE_JSON, "firebase-tasks.json");
  });

  test("the packet files are the tasks fixture and its configuration, in the events packet's order", () => {
    assert.equal(PACKET_FILES.length, 17);
    assert.deepEqual(PACKET_FILES.slice(-3), [
      "fixture-tasks/main.py",
      "fixture-tasks/requirements.txt",
      "firebase-tasks.json",
    ]);
    assert.deepEqual(PACKET_FILES.slice(0, -3), packetFiles("events").slice(0, -3));
    assert.ok(!PACKET_FILES.includes("fixture/main.py") && !PACKET_FILES.includes("firebase.json"));
    assert.deepEqual(packetFiles("tasks"), PACKET_FILES);
    const contents = Object.fromEntries(
      [...packetFiles("events"), ...packetFiles("tasks")].map((n) => [n, Buffer.from("c " + n)]),
    );
    const read_ = (n) => contents[n];
    assert.notEqual(packetDigest(read_, "events"), packetDigest(read_, "tasks"));
    assert.equal(
      packetDigest(read_),
      packetDigest(read_, "tasks"),
      "the default is the process's profile",
    );
    const expected = createHash("sha256")
      .update(
        PACKET_FILES.map(
          (n) => `${n}\t${createHash("sha256").update(contents[n]).digest("hex")}\n`,
        ).join(""),
      )
      .digest("hex");
    assert.equal(packetDigest(read_), expected);
    assert.match(packetDigest(), /^[0-9a-f]{64}$/, "every packet file exists");
  });

  test("the tasks fixture is the events fixture's helpers and its two Cloud Tasks functions under the new names", () => {
    const original = read("fixture/main.py");
    const tasks = read("fixture-tasks/main.py");
    const blocks = tasks.split("\n\n\n");
    const covered = [];
    for (const [index, block] of blocks.entries()) {
      if (index === 0) {
        // The module text and the imports are this file's own; every constant must be a constant of the original.
        for (const line of block.split("\n").filter((l) => /^[A-Z_]+ = /.test(l)))
          assert.ok(original.includes(line + "\n"), "constant not in the original: " + line);
        continue;
      }
      if (block.startsWith("_PROTOTYPES = {")) {
        const [dict, assign] = block.split("\n\n");
        const entry = dict.split("\n")[1];
        assert.ok(original.includes(entry + "\n"), "prototype not in the original: " + entry);
        covered.push(assign);
        assert.ok(
          original.includes(assign.replaceAll("pc3task", "pctask")),
          "assignment not in the original: " + assign,
        );
        continue;
      }
      assert.ok(
        original.includes(block.replaceAll("pc3task", "pctask")),
        "block not in the original:\n" + block,
      );
      covered.push(block);
    }
    for (const helper of [
      "def _versions(",
      "def _run_of(",
      "def _emit(",
      "def _request_view(",
      "def _is_text(",
      "def _raw_request(",
      "def _with_trigger(",
      "def _prototype(",
      "def pc3task(",
    ])
      assert.ok(
        covered.some((b) => b.includes(helper)),
        helper + " is missing",
      );
    const defined = [...tasks.matchAll(/^(?:def |)(pc3\w*)(?:\(| = )/gm)]
      .map((m) => m[1])
      .toSorted();
    assert.deepEqual(defined, [RAW, SDK].toSorted());
    assert.equal(read("fixture-tasks/requirements.txt"), read("fixture/requirements.txt"));
    const config = JSON.parse(read("firebase-tasks.json"));
    assert.deepEqual(config, {
      functions: [
        {
          source: "fixture-tasks",
          codebase: "pycheck",
          runtime: "python312",
          ignore: ["venv", "__pycache__", "*.pyc"],
        },
      ],
    });
    assert.deepEqual(JSON.parse(read("firebase.json")).functions[0].codebase, "pycheck");
  });

  const endpoint = (over = {}) => ({
    entryPoint: "x",
    platform: "gcfv2",
    region: ["us-central1"],
    eventType: null,
    filters: null,
    channel: null,
    schedule: null,
    timeZone: null,
    taskQueue: true,
    maxAttempts: 1,
    taskInvoker: null,
    ...over,
  });
  const declared = () => ({
    [SDK]: endpoint({ entryPoint: SDK }),
    [RAW]: endpoint({ entryPoint: RAW }),
  });

  test("the offline discovery must declare exactly the two functions, as task queues of one attempt and no invoker", () => {
    assert.deepEqual(declarationProblems(declared()), []);
    const extra = { ...declared(), pctask: endpoint({ entryPoint: "pctask" }) };
    assert.match(declarationProblems(extra)[0], /fixture exports/);
    const one = { [SDK]: declared()[SDK] };
    assert.match(declarationProblems(one)[0], /fixture exports/);
    const attempts = declared();
    attempts[RAW].maxAttempts = 3;
    assert.deepEqual(declarationProblems(attempts), [`${RAW}: max attempts 3`]);
    const invoker = declared();
    invoker[SDK].taskInvoker = ["private"];
    assert.deepEqual(declarationProblems(invoker), [`${SDK}: task queue invoker ["private"]`]);
    const notQueue = declared();
    notQueue[SDK].taskQueue = false;
    assert.deepEqual(declarationProblems(notQueue), [`${SDK}: not a task queue function`]);
    const entry = declared();
    entry[RAW].entryPoint = "other";
    assert.deepEqual(declarationProblems(entry), [`${RAW}: entry point other`]);
  });

  test("the CLI plan deploys the codebase and deletes exactly the two functions", () => {
    const options = {
      configHome: "/c",
      configPath: "/s/firebase-tasks.json",
      workDir: "/s",
      home: "/h",
      path: "/bin",
    };
    const deploy = cliPlan("deploy", options).args;
    assert.deepEqual(deploy.slice(deploy.indexOf("--only"), deploy.indexOf("--only") + 2), [
      "--only",
      "functions:pycheck",
    ]);
    assert.equal(deploy[deploy.indexOf("--config") + 1], "/s/firebase-tasks.json");
    const del = cliPlan("delete", options).args;
    assert.deepEqual(del.slice(0, 3), ["functions:delete", SDK, RAW]);
    assert.equal(del[3], "--config");
  });

  test("the source copy of the tasks profile is the tasks fixture and its configuration", () => {
    const repo = tempDir("pc-tasks-repo-");
    const dir = join(repo, "conformance/python-functions-check");
    mkdirSync(join(dir, "fixture-tasks"), { recursive: true });
    mkdirSync(join(dir, "fixture"), { recursive: true });
    writeFileSync(join(dir, "fixture-tasks/main.py"), "tasks = 1\n");
    writeFileSync(join(dir, "fixture/main.py"), "events = 1\n");
    writeFileSync(join(dir, "firebase-tasks.json"), "{}\n");
    writeFileSync(join(dir, "firebase.json"), "{}\n");
    const git = (...args) =>
      execFileSync("git", ["-C", repo, ...args], { encoding: "utf8" }).trim();
    git("init", "-q");
    git("add", "-A");
    const env = {
      ...process.env,
      GIT_AUTHOR_NAME: "t",
      GIT_AUTHOR_EMAIL: "t@example.com",
      GIT_COMMITTER_NAME: "t",
      GIT_COMMITTER_EMAIL: "t@example.com",
    };
    const tree = execFileSync("git", ["-C", repo, "write-tree"], { encoding: "utf8", env }).trim();
    const commit = execFileSync("git", ["-C", repo, "commit-tree", tree, "-m", "c"], {
      encoding: "utf8",
      env,
    }).trim();
    const target = join(tempDir("pc-tasks-target-"), "source");
    const { configPath, fixtureDir } = prepareSource({ repoRoot: repo, commit, target });
    assert.equal(
      configPath,
      join(target, "conformance/python-functions-check/firebase-tasks.json"),
    );
    assert.equal(fixtureDir, join(target, "conformance/python-functions-check/fixture-tasks"));
    assert.equal(readFileSync(join(fixtureDir, "main.py"), "utf8"), "tasks = 1\n");
  });

  test("the source operations are the two task creations and nothing else, and they wait for the function targets", () => {
    const targets = Object.fromEntries(
      [SDK, RAW].map((fn) => [
        fn,
        { uri: "https://x.run.app", serviceAccountEmail: "a@b.gserviceaccount.com" },
      ]),
    );
    const ready = operations({ runId: RUN, bucket: "b", targets });
    assert.deepEqual(
      ready.map((op) => op.key),
      [`task-${SDK}`, `task-${RAW}`],
    );
    for (const op of ready)
      assert.match(op.request.url, new RegExp(`/queues/${op.reaches[0]}/tasks$`));
    const waiting = operations({ runId: RUN, bucket: "b", targets: {} });
    assert.deepEqual(
      waiting.map((op) => op.needs),
      [[`task-target:${SDK}`], [`task-target:${RAW}`]],
    );
  });

  // The observation of run 57ab27296dedaedc (docs.local/runs/python-functions-check/r1-20261104T103214Z, result file
  // judged.cases["tasks-request"].observed): the headers, header names, authorization and body production delivered to the
  // raw Cloud Tasks function, with the queue name and the host renamed to the new function.
  const recordedFrame = (fn = RAW) => ({
    function: fn,
    kind: "raw-request",
    run: "pcrun-" + RUN,
    versions: { "firebase-functions": "0.6.0" },
    request: {
      method: "POST",
      path: "/",
      header_names: [
        "accept-encoding",
        "authorization",
        "content-length",
        "content-type",
        "forwarded",
        "function-execution-id",
        "host",
        "traceparent",
        "user-agent",
        "x-cloud-trace-context",
        "x-cloudtasks-queuename",
        "x-cloudtasks-tasketa",
        "x-cloudtasks-taskexecutioncount",
        "x-cloudtasks-taskname",
        "x-cloudtasks-taskretrycount",
        "x-forwarded-for",
        "x-forwarded-proto",
      ],
      headers: {
        "accept-encoding": "gzip, deflate, br",
        "content-length": "62",
        "content-type": "application/json",
        host: fn + "-xei277hwaa-uc.a.run.app",
        "user-agent": "Google-Cloud-Tasks",
        "x-cloudtasks-queuename": fn,
        "x-cloudtasks-tasketa": "1793788668.938251",
        "x-cloudtasks-taskexecutioncount": "0",
        "x-cloudtasks-taskname": "7862371040359843201",
        "x-cloudtasks-taskretrycount": "0",
        "x-forwarded-proto": "https",
      },
      authorization: { scheme: "Bearer", segments: 3 },
      body_length: 62,
      body_text: JSON.stringify({ data: { label: fn, run: "pcrun-" + RUN } }),
    },
  });
  const sdkFrame = () => ({
    function: SDK,
    kind: "sdk-event",
    run: "pcrun-" + RUN,
    versions: { "firebase-functions": "0.6.0" },
    data: { label: SDK, run: "pcrun-" + RUN },
    has_auth: false,
    has_app: false,
  });
  const judged = (frames, sent = { [`task-${RAW}`]: { class: "2xx", status: 200 } }) =>
    judge({ runId: RUN, frames, sent, mode: "production" });

  test("the recorded Cloud Tasks delivery is judged as expected under the new names, and only its cases are judged", () => {
    const j = judged([recordedFrame(), sdkFrame()]);
    assert.deepEqual(Object.keys(j.cases).toSorted(), ["sdk-versions", "tasks-request"]);
    assert.equal(
      j.cases["tasks-request"].status,
      "as-expected",
      JSON.stringify(j.cases["tasks-request"]),
    );
    assert.equal(j.cases["tasks-request"].observed.sdkFrames, 1);
    assert.equal(j.cases["sdk-versions"].status, "as-expected");
    assert.equal(j.complete, true);
    assert.deepEqual(j.counts, {
      "as-expected": 2,
      differs: 0,
      observed: 0,
      "not-delivered": 0,
      "not-sent": 0,
    });
  });

  test("each rule of tasks-request still fails on its own deviation, and the old queue name no longer counts", () => {
    const mutate = (fn) => {
      const f = recordedFrame();
      fn(f.request);
      return judged([f]).cases["tasks-request"];
    };
    const cases = {
      "content-type-json": (r) => (r.headers["content-type"] = "text/plain"),
      "queue-name-header": (r) => (r.headers["x-cloudtasks-queuename"] = "pctaskraw"),
      "task-name-header": (r) =>
        (r.header_names = r.header_names.filter((n) => n !== "x-cloudtasks-taskname")),
      "retry-count-header": (r) =>
        (r.header_names = r.header_names.filter((n) => n !== "x-cloudtasks-taskretrycount")),
      "execution-count-header": (r) =>
        (r.header_names = r.header_names.filter((n) => n !== "x-cloudtasks-taskexecutioncount")),
      "eta-header": (r) =>
        (r.header_names = r.header_names.filter((n) => n !== "x-cloudtasks-tasketa")),
      "bearer-token": (r) => (r.authorization = { scheme: "Bearer", segments: 2 }),
      "body-callable-format": (r) => (r.body_text = "{}"),
      method: (r) => (r.method = "PUT"),
    };
    for (const [rule, change] of Object.entries(cases)) {
      const c = mutate(change);
      assert.equal(c.status, "differs", rule);
      assert.deepEqual(c.notes, [rule], rule);
    }
    // A frame of the events profile's function is another function's: nothing was delivered here.
    assert.equal(
      judged([recordedFrame("pctaskraw")]).cases["tasks-request"].status,
      "not-delivered",
    );
    assert.equal(judged([]).cases["tasks-request"].status, "not-delivered");
    const unsent = judge({ runId: RUN, frames: [], sent: {}, mode: "production" });
    assert.equal(unsent.cases["tasks-request"].status, "not-sent");
    assert.deepEqual(unsent.cases["tasks-request"].expected, null);
    assert.deepEqual(unsent.cases["tasks-request"].notes, [`task-${RAW}`]);
  });

  async function go(worldOptions = {}, options = {}) {
    const world = createWorld({ runId: RUN, ...worldOptions });
    const journal = [];
    const sleeps = [];
    const result = await record({
      runId: RUN,
      projectNumber: NUMBER,
      accessToken: "test-token-abcdefgh",
      save: async (row) => journal.push(row),
      send: world.send,
      runCli: (o) => world.runCli(o),
      clock: () => world.now,
      sleep: async (ms) => {
        sleeps.push(ms);
        world.advance(ms);
      },
      ...options,
    });
    return { world, journal, sleeps, result };
  }
  const mutations = (world) =>
    world.calls.filter(
      (c) => !c.startsWith("GET ") && !c.includes("entries:list") && !c.includes("getIamPolicy"),
    );

  // The CLI's functions:delete disables a task queue and leaves it (recorded in both passes: the recorder's own DELETE of
  // each queue answered 200), so the realistic world leaves the queues for the recorder to delete.
  // At the baseline the channel `firebase` is absent (pass 2's A2 read channelsAfter []) and there is no App Engine app (404).
  const CLI_LEAVES_QUEUES = {
    leaveOnDelete: [`queue:${SDK}`, `queue:${RAW}`],
    seedChannels: [],
    appEngine: false,
  };

  test("a clean run of the profile deploys two functions, creates two tasks, cleans up and reads every name back", async () => {
    const { world, result, journal } = await go(CLI_LEAVES_QUEUES);
    assert.equal(result.outcome, "pycheck-recorded");
    assert.equal(result.closureReady, true);
    assert.equal(result.readBackRequired, false);
    assert.equal(result.unknown, 0);
    assert.deepEqual(world.cliRuns, ["dry-run", "deploy", "delete"]);
    assert.equal(world.functions.size + world.queues.size + world.packages.size, 0);
    assert.equal(world.topics.size, 0);
    assert.equal(result.cleanup.verified, true);
    assert.equal(result.cli.deploy.exitCode, 0);
    // The deploy made no event trigger, so it made no Eventarc channel: the run owns none and sends nothing to Eventarc.
    assert.equal(world.channels.size, 0);
    assert.equal(result.cleanup.channel.absentAlready, true);
    assert.equal(result.cleanup.readBack.channel, true);
    assert.deepEqual(
      world.calls.filter((c) => /^(POST|PUT|DELETE|PATCH) eventarc/.test(c)),
      [],
    );
    const queueDeletes = journal.filter(
      (row) => /^delete-queue-/.test(row.id) && row.state === "response-persisted",
    );
    assert.deepEqual(
      queueDeletes.map((row) => row.status),
      [200, 200],
    );
    const labels = Object.keys(result.cleanup.readBack).toSorted();
    for (const fn of [SDK, RAW]) {
      assert.ok(labels.includes("function-" + fn));
      assert.ok(labels.includes("queue-" + fn));
      for (const id of plan.packageIds(fn)) assert.ok(labels.includes("package-" + id));
    }
    assert.ok(Object.values(result.cleanup.readBack).every((v) => v === true));
    assert.deepEqual(Object.keys(result.operations), [`task-${SDK}`, `task-${RAW}`]);
    assert.deepEqual(result.judged.counts, {
      "as-expected": 2,
      differs: 0,
      observed: 0,
      "not-delivered": 0,
      "not-sent": 0,
    });
    assert.equal(result.judged.complete, true);
    assert.deepEqual(result.frames, { [SDK]: 1, [RAW]: 1 });
    // Nothing of another family is created, published, uploaded or run.
    const sent = mutations(world);
    assert.deepEqual(
      sent.filter((c) =>
        /pubsub|firestore|storage\.googleapis\.com\/upload|eventarcpublishing|:run$/.test(c),
      ),
      [],
    );
    assert.ok(!journal.some((row) => row.id === "issue-topic" || row.id === "create-topic"));
    assert.ok(!sent.some((c) => c.startsWith("PUT pubsub")));
    assert.equal(sent.filter((c) => c.startsWith("POST cloudtasks")).length, 2);
    assert.deepEqual(
      sent.filter((c) => c.startsWith("DELETE cloudtasks")).toSorted(),
      [
        `DELETE cloudtasks.googleapis.com/v2/projects/fireemu-oracle-events/locations/us-central1/queues/${SDK}`,
        `DELETE cloudtasks.googleapis.com/v2/projects/fireemu-oracle-events/locations/us-central1/queues/${RAW}`,
      ].toSorted(),
      "the recorder deletes each queue once",
    );
    assert.equal(result.cleanup.readBack[`queue-${SDK}`], true);
    assert.equal(world.queues.size, 0);
    assert.equal(sent.filter((c) => c.startsWith("DELETE cloudscheduler")).length, 0);
  });

  // What the 15.28.2 CLI did in the first pass (r1-20261104T103214Z, result file cli.deploy.cliWrites): one POST to the functions
  // collection and one to the queues collection per function, so the shared parser counts each collection URL as retried.
  const REAL_WRITES = [
    {
      method: "POST",
      url: `cloudfunctions.googleapis.com/v2/projects/fireemu-oracle-events/locations/us-central1/functions`,
      requests: 2,
      statuses: [200, 200],
      class: "retried",
    },
    {
      method: "POST",
      url: `cloudtasks.googleapis.com/v2/projects/fireemu-oracle-events/locations/us-central1/queues`,
      requests: 2,
      statuses: [200, 200],
      class: "retried",
    },
  ];

  test("the CLI's repeated collection writes leave the run needing the read-back, and the read-back closes it", async () => {
    const { world, result } = await go({ ...CLI_LEAVES_QUEUES, cliWrites: REAL_WRITES });
    assert.equal(result.outcome, "pycheck-needs-review");
    assert.equal(result.closureReady, false);
    assert.equal(result.readBackRequired, true);
    assert.equal(result.cleanup.verified, true);
    // (The fake CLI returns the same writes for its dry run, deploy and delete, so each appears once per action.)
    assert.deepEqual(
      [...new Set(result.unknownMutationList.map((m) => m.request))],
      [
        "POST cloudfunctions.googleapis.com/v2/projects/fireemu-oracle-events/locations/us-central1/functions",
        "POST cloudtasks.googleapis.com/v2/projects/fireemu-oracle-events/locations/us-central1/queues",
      ],
    );
    assert.deepEqual(
      result.unconfirmedCreates,
      [],
      "every name was shown by an own read, so none stays unconfirmed",
    );
    const back = await readbackRun({
      runId: RUN,
      projectNumber: NUMBER,
      bucket: result.bucket,
      uploadObjects: [],
      baseline: result.inventory.before,
      enabled: [],
      channel: result.cleanup.channel,
      carried: [],
      accessToken: "test-token-abcdefgh",
      save: async () => {},
      send: world.send,
    });
    assert.equal(back.allAbsent, true);
    assert.equal(back.unknown, 0);
    assert.equal(back.inventory.baseline, true);
  });

  test("the profile's request count is the one the packet states, inside the ceilings", async () => {
    const { result } = await go(CLI_LEAVES_QUEUES);
    assert.equal(result.attempted, 84, "the packet states 84 requests in the fake world");
    assert.ok(result.attempted < NORMAL_CEILING + CLEANUP_CEILING);
  });

  test("every request of a run is allowed by the guard for this profile, and none is for the other profile's names", async () => {
    const { world } = await go();
    assert.ok(world.calls.length > 0);
    const text = world.calls.join("\n");
    for (const used of ["pcfsc", "pcsch", "pcps", "pcst", "pcea"])
      assert.ok(!text.includes("/" + used), used + " was addressed");
    assert.ok(!/\/(pctask|pctaskraw)(\/|$|\n)/m.test(text), "the old queue names were addressed");
  });

  test("the job rules of the guard match nothing in this profile (an empty alternative would match an empty id)", async () => {
    const { createGuard } = await import("./guard.mjs");
    const guard = createGuard(RUN, NUMBER);
    const base =
      "https://cloudscheduler.googleapis.com/v1/projects/fireemu-oracle-events/locations/us-central1/jobs";
    for (const [method, url] of [
      ["GET", base + "/"],
      ["POST", base + "/:run"],
      ["DELETE", base + "/"],
      ["GET", base + "/firebase-schedule-pcschraw-us-central1"],
    ])
      assert.equal(
        guard.allow({ method, url, id: "x" }),
        false,
        `${method} ${url} must not be allowed`,
      );
    assert.equal(
      guard.allow({ method: "GET", url: base + "?pageSize=500", id: "x" }),
      true,
      "the list of jobs is still read",
    );
    const queues =
      "https://cloudtasks.googleapis.com/v2/projects/fireemu-oracle-events/locations/us-central1/queues";
    assert.equal(guard.allow({ method: "DELETE", url: `${queues}/${SDK}`, id: "x" }), true);
    assert.equal(guard.allow({ method: "DELETE", url: `${queues}/pctask`, id: "x" }), false);
    assert.equal(guard.allow({ method: "DELETE", url: `${queues}/`, id: "x" }), false);
  });

  // A deleted queue name cannot be created again for up to three days (the 400 of 2026-11-07, "existed too recently").
  test("a queue name deleted by an earlier run is refused by Cloud Tasks, and the later run does not close", async () => {
    const tombstones = new Set();
    const first = await go({ queueTombstones: tombstones, ...CLI_LEAVES_QUEUES });
    assert.equal(first.result.outcome, "pycheck-recorded");
    assert.deepEqual(
      [...tombstones].toSorted(),
      [RAW, SDK].toSorted(),
      "the delete burns the names",
    );
    const second = await go({ queueTombstones: tombstones, ...CLI_LEAVES_QUEUES });
    assert.notEqual(second.result.outcome, "pycheck-recorded");
    assert.equal(second.result.closureReady, false);
    assert.deepEqual(
      second.result.unconfirmedCreates.map((c) => c.label).toSorted(),
      [`queue-${RAW}`, `queue-${SDK}`].toSorted(),
    );
    assert.ok(second.result.unconfirmedCreates.every((c) => c.class === "cli-write-retried"));
    // The recorded second pass: exit 2, two functions errored, the queue collection written twice and refused with 400 twice.
    assert.equal(second.result.cli.deploy.exitCode, 2);
    assert.equal(second.result.cli.deploy.errored, 2);
    assert.deepEqual(
      second.result.cli.deploy.cliWrites.map((w) => [w.method, w.requests, w.statuses, w.class]),
      [["POST", 2, [400, 400], "retried"]],
    );
    assert.equal(second.result.operations[`task-${RAW}`].sent, true);
    assert.equal(second.result.judged.cases["tasks-request"].status, "not-delivered");
    assert.equal(second.result.judged.complete, false);
    assert.deepEqual(
      second.result.cleanup.readBack &&
        Object.entries(second.result.cleanup.readBack).filter(([, v]) => v !== true),
      [],
      "the cleanup still reads every name back as absent",
    );
    assert.equal(second.result.readBackRequired, true);
  });

  test("the read-back (A2) of a clean run closes, and reads the profile's names only", async () => {
    const { world, result } = await go(CLI_LEAVES_QUEUES);
    const rows = [];
    const back = await readbackRun({
      runId: RUN,
      projectNumber: NUMBER,
      bucket: result.bucket,
      uploadObjects: [],
      baseline: result.inventory.before,
      enabled: [],
      channel: result.cleanup.channel,
      carried: [],
      accessToken: "test-token-abcdefgh",
      save: async (row) => rows.push(row),
      send: world.send,
    });
    assert.equal(back.allAbsent, true);
    assert.equal(back.unknown, 0);
    const urls = rows.map((r) => r.url).filter(Boolean);
    for (const fn of [SDK, RAW]) {
      assert.ok(urls.some((u) => u.endsWith("/functions/" + fn)));
      assert.ok(urls.some((u) => u.endsWith("/queues/" + fn)));
    }
    assert.ok(
      !urls.some((u) => /\/functions\/pc(?!3)/.test(u)),
      "no function of the events profile is read",
    );
    assert.ok(!urls.some((u) => /\/jobs\/firebase-schedule/.test(u)));
    assert.equal(back.attempted, 28, "the packet states 28 read-back requests in the fake world");
    assert.ok(back.attempted <= READBACK_MAX_REQUESTS);
  });
}
