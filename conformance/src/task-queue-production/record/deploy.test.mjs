// The deploy side: the SDK's own discovery of the committed fixture, what a discovery must declare, the CLI plan, and the
// readiness reads. The upload receipt, the inventory and the IAM comparison are the Python Functions check's, whose tests are
// not repeated; what this file adds is what the run's suffix and the task queue functions change.
import "./isolation.mjs";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { PROJECT, REGION, ROLES, ROLE_IDS, functionName, functionsOf } from "../plan.mjs";
import {
  allActive,
  cliPlan,
  cliWritesFromOutput,
  declarationProblems,
  inventoryDifferences,
  nonePresent,
  prepareSource,
  repositoryDifferences,
  sdkVersionProblems,
  sourceProblems,
  summarize,
} from "./deploy.mjs";
import { go } from "./harness.mjs";
import { tempDir } from "./testtmp.mjs";

const RUN = "0123456789abcdef";
const here = fileURLToPath(new URL(".", import.meta.url));
const conformance = join(here, "../../..");

/** The endpoints the SDK writes for the fixture: one task queue trigger per role, unset options as null. */
const endpointsOf = (runId = RUN, change = () => {}) => {
  const out = {};
  for (const fn of functionsOf(runId)) {
    const options = ROLES[fn.slice(0, -6)];
    const group = (name, keys) =>
      Object.fromEntries(keys.map((k) => [k, options[name]?.[k] ?? null]));
    out[fn] = {
      platform: "gcfv2",
      region: [REGION],
      entryPoint: fn,
      taskQueueTrigger: {
        retryConfig: group("retryConfig", [
          "maxAttempts",
          "maxDoublings",
          "maxBackoffSeconds",
          "maxRetrySeconds",
          "minBackoffSeconds",
        ]),
        rateLimits: group("rateLimits", ["maxConcurrentDispatches", "maxDispatchesPerSecond"]),
      },
    };
  }
  change(out);
  return out;
};
const fn = (role) => role + RUN.slice(0, 6);

test("the declarations the SDK writes for the fixture are the declarations the run expects", () => {
  assert.deepEqual(declarationProblems(endpointsOf(), RUN), []);
});

test("a declaration that differs in any one way is a problem", () => {
  const problems = (change) => declarationProblems(endpointsOf(RUN, change), RUN);
  assert.match(problems((e) => (e[fn("tqdef")].region = ["us-east1"]))[0], /region/);
  assert.match(problems((e) => (e[fn("tqdef")].platform = "gcfv1"))[0], /platform/);
  assert.match(problems((e) => (e[fn("tqdef")].entryPoint = "x"))[0], /entry point/);
  assert.match(problems((e) => delete e[fn("tqdef")].taskQueueTrigger)[0], /not a task queue/);
  assert.match(
    problems((e) => (e[fn("tqdef")].taskQueueTrigger.invoker = ["public"]))[0],
    /invoker/,
  );
  assert.match(
    problems((e) => (e[fn("tqretry")].taskQueueTrigger.retryConfig.maxAttempts = 7))[0],
    /tqretry.*maxAttempts/,
  );
  assert.match(
    problems((e) => (e[fn("tqrate")].taskQueueTrigger.rateLimits.maxDispatchesPerSecond = 2))[0],
    /tqrate.*maxDispatchesPerSecond/,
  );
  assert.match(
    problems((e) => (e[fn("tqdef")].taskQueueTrigger.retryConfig.maxAttempts = 3))[0],
    /tqdef.*retryConfig/,
    "the default queue declares no option",
  );
  assert.match(problems((e) => delete e[fn("tqdead")])[0], /fixture exports/);
  assert.match(problems((e) => (e.extra = e[fn("tqdef")]))[0], /fixture exports/);
  // Another run's suffix is not this run's function.
  assert.match(declarationProblems(endpointsOf("fedcba9876543210"), RUN)[0], /fixture exports/);
});

test("the committed fixture, run through the SDK's own discovery, declares what the run expects", () => {
  const copy = tempDir("tq-disc-");
  cpSync(join(conformance, "task-queue-functions/functions"), join(copy, "functions"), {
    recursive: true,
  });
  writeFileSync(join(copy, "functions/suffix.json"), JSON.stringify({ suffix: RUN.slice(0, 6) }));
  const deps = join(conformance, "node_modules");
  assert.ok(
    existsSync(join(deps, "firebase-functions/package.json")),
    "conformance dependencies are installed",
  );
  symlinkSync(deps, join(copy, "functions/node_modules"));
  const discover = (suffixDir, extra = {}) =>
    sourceProblems({
      checkDependencies: false,
      fixtureDir: join(copy, "functions"),
      node: process.execPath,
      directory: join(copy, suffixDir),
      runId: RUN,
      ...extra,
    });
  assert.deepEqual(discover("d1"), []);
  // The same fixture under another suffix is refused for this run.
  writeFileSync(join(copy, "functions/suffix.json"), JSON.stringify({ suffix: "ffffff" }));
  assert.match(discover("d2")[0], /fixture exports/);
  // A discovery that fails is a problem, not a throw.
  assert.match(
    discover("d3", {
      discoverFn: () => {
        throw new Error("boom");
      },
    })[0],
    /discovery of the fixture failed: boom/,
  );
});

test("the source copy is the committed fixture with the run's suffix and nothing else changed", () => {
  const repo = tempDir("tq-repo-");
  const dir = "conformance/task-queue-functions";
  mkdirSync(join(repo, dir), { recursive: true });
  cpSync(join(conformance, "task-queue-functions"), join(repo, dir), { recursive: true });
  const git = (...args) => execFileSync("git", ["-C", repo, ...args], { encoding: "utf8" });
  git("init", "-q");
  git("add", ".");
  // A commit object made by plumbing: no signing, because nothing here is a commit anyone keeps.
  const tree = git("write-tree").trim();
  const commit = execFileSync("git", ["-C", repo, "commit-tree", tree, "-m", "x"], {
    encoding: "utf8",
    env: {
      PATH: process.env.PATH,
      GIT_AUTHOR_NAME: "t",
      GIT_AUTHOR_EMAIL: "t@e.x",
      GIT_COMMITTER_NAME: "t",
      GIT_COMMITTER_EMAIL: "t@e.x",
    },
  }).trim();
  const target = tempDir("tq-target-");
  const prepared = prepareSource({ repoRoot: repo, commit, target, runId: RUN });
  assert.equal(prepared.configPath, join(target, dir, "firebase.json"));
  assert.equal(prepared.fixtureDir, join(target, dir, "functions"));
  assert.deepEqual(JSON.parse(readFileSync(join(prepared.fixtureDir, "suffix.json"), "utf8")), {
    suffix: RUN.slice(0, 6),
  });
  assert.equal(
    readFileSync(join(prepared.fixtureDir, "index.js"), "utf8"),
    readFileSync(join(conformance, "task-queue-functions/functions/index.js"), "utf8"),
  );
  assert.throws(
    () => prepareSource({ repoRoot: repo, commit: "HEAD", target, runId: RUN }),
    /full SHA/,
  );
  assert.throws(
    () => prepareSource({ repoRoot: repo, commit, target: tempDir("tq-t2-"), runId: "xyz" }),
    /invalid run ID/,
  );
});

test("the pinned SDK is read from the dependency tree", () => {
  const deps = tempDir("tq-deps-");
  assert.match(sdkVersionProblems(deps)[0], /cannot be read/);
  mkdirSync(join(deps, "firebase-functions"));
  writeFileSync(join(deps, "firebase-functions/package.json"), '{"version":"7.3.1"}');
  assert.match(sdkVersionProblems(deps)[0], /7\.3\.1, not 7\.3\.2/);
  writeFileSync(join(deps, "firebase-functions/package.json"), '{"version":"7.3.2"}');
  assert.deepEqual(sdkVersionProblems(deps), []);
});

test("the CLI plans are explicit: the delete names the run's eight functions, the dry run is the deploy argv plus --dry-run", () => {
  const options = {
    configHome: "/c",
    configPath: "/s/firebase.json",
    workDir: "/s",
    home: "/h",
    path: "/n/bin:/usr/bin",
    runId: RUN,
  };
  const deploy = cliPlan("deploy", options);
  const dry = cliPlan("dry-run", options);
  const del = cliPlan("delete", options);
  assert.deepEqual(dry.args, [...deploy.args, "--dry-run"]);
  assert.equal(deploy.args[0], "deploy");
  assert.ok(deploy.args.includes("--force") && deploy.args.includes("--non-interactive"));
  assert.equal(deploy.args[deploy.args.indexOf("--only") + 1], "functions:task-queue");
  assert.equal(deploy.args[deploy.args.indexOf("--project") + 1], PROJECT);
  assert.deepEqual(del.args.slice(1, 9), functionsOf(RUN));
  assert.equal(del.args[del.args.indexOf("--region") + 1], REGION);
  assert.deepEqual(Object.keys(deploy.env).toSorted(), [
    "FIREBASE_CONFIG",
    "GCLOUD_PROJECT",
    "GOOGLE_CLOUD_QUOTA_PROJECT",
    "HOME",
    "PATH",
    "XDG_CONFIG_HOME",
  ]);
  assert.equal(deploy.env.GCLOUD_PROJECT, PROJECT);
  assert.throws(
    () => cliPlan("deploy", { ...options, configPath: "relative" }),
    /absolute configPath/,
  );
  assert.throws(() => cliPlan("deploy", { ...options, path: "" }), /explicit PATH/);
  assert.throws(() => cliPlan("destroy", options), /unknown CLI action/);
  assert.throws(() => cliPlan("delete", { ...options, runId: undefined }), /run ID/);
});

test("readiness is read from the lists: present and active for every function, a stray id elsewhere is not ours", () => {
  const fns = functionsOf(RUN);
  const lists = (state = "ACTIVE", omit = []) => ({
    v2: {
      functions: fns
        .filter((f) => !omit.includes(f))
        .map((f) => ({ name: functionName(f), state })),
    },
    run: {
      services: fns.filter((f) => !omit.includes(f)).map((f) => ({ name: "x/services/" + f })),
    },
  });
  assert.equal(allActive(summarize(lists(), RUN)), true);
  assert.equal(allActive(summarize(lists("DEPLOYING"), RUN)), false);
  assert.equal(allActive(summarize(lists("ACTIVE", [fns[3]]), RUN)), false);
  assert.equal(nonePresent(summarize({ v2: { functions: [] }, run: { services: [] } }, RUN)), true);
  assert.equal(nonePresent(summarize(lists(), RUN)), false);
  const stray = summarize(
    {
      v2: {
        functions: [
          { name: `projects/${PROJECT}/locations/us-east1/functions/${fns[0]}`, state: "ACTIVE" },
        ],
      },
      run: { services: [] },
    },
    RUN,
  );
  assert.equal(stray[fns[0]].stray, true);
  assert.equal(nonePresent(stray), false);
  assert.equal(ROLE_IDS.length, 8);
});

test("the inventory compares the queues too: a queue that appears or disappears is a difference", () => {
  const before = {
    queues: ["q1"],
    packages: [],
    channels: [],
    triggers: [],
    subscriptions: [],
    topics: [],
    services: [],
    sourceObjects: { uploads: [], sources: [] },
  };
  const kinds = ["channels", "triggers", "subscriptions", "topics", "packages", "queues"];
  const same = inventoryDifferences({ before, after: structuredClone(before), kinds });
  assert.deepEqual(same.differences, []);
  assert.equal(same.complete, true);
  const added = inventoryDifferences({ before, after: { ...before, queues: ["q1", "q2"] }, kinds });
  assert.deepEqual(added.differences, [{ kind: "queues", added: ["q2"], removed: [] }]);
  const gone = inventoryDifferences({ before, after: { ...before, queues: [] }, kinds });
  assert.deepEqual(gone.differences, [{ kind: "queues", added: [], removed: ["q1"] }]);
  const unread = inventoryDifferences({ before, after: { ...before, queues: null }, kinds });
  assert.deepEqual(unread.missing, ["queues"]);
  // The build's copy of each of the run's functions may appear in the sources bucket; another object may not.
  const copy = (name) => ({ ...before, sourceObjects: { uploads: [], sources: [name] } });
  assert.deepEqual(
    inventoryDifferences({
      runId: RUN,
      before,
      after: copy("tqretry012345/function-source.zip"),
      kinds,
    }).differences,
    [],
  );
  assert.equal(
    inventoryDifferences({ before, after: copy("other/function-source.zip"), kinds }).differences
      .length,
    1,
  );
});

test("the dependency tree is checked with the discovery: the pinned SDK and no link that leaves the tree", () => {
  const fixture = tempDir("tq-deps-fixture-");
  const nodeModules = join(fixture, "node_modules/firebase-functions");
  mkdirSync(nodeModules, { recursive: true });
  writeFileSync(join(nodeModules, "package.json"), '{"version":"7.3.2","main":"index.js"}');
  writeFileSync(join(nodeModules, "index.js"), "");
  writeFileSync(join(fixture, "package.json"), "{}");
  const clean = sourceProblems({
    fixtureDir: fixture,
    node: "n",
    directory: "d",
    runId: RUN,
    discoverFn: () => endpointsOf(),
  });
  assert.deepEqual(clean, []);
  writeFileSync(join(nodeModules, "package.json"), '{"version":"7.0.0","main":"index.js"}');
  const old = sourceProblems({
    fixtureDir: fixture,
    node: "n",
    directory: "d",
    runId: RUN,
    discoverFn: () => endpointsOf(),
  });
  assert.match(old[0], /7\.0\.0, not 7\.3\.2/);
  writeFileSync(join(nodeModules, "package.json"), '{"version":"7.3.2","main":"index.js"}');
  symlinkSync("/", join(fixture, "node_modules/escape"));
  const linked = sourceProblems({
    fixtureDir: fixture,
    node: "n",
    directory: "d",
    runId: RUN,
    discoverFn: () => endpointsOf(),
  });
  assert.match(linked[0], /leave the tree/);
});

test("a function is active only with its Cloud Run service, and only a build of this run's functions is the build's copy", () => {
  const fns = functionsOf(RUN);
  const noService = {
    v2: { functions: fns.map((f) => ({ name: functionName(f), state: "ACTIVE" })) },
    run: { services: fns.slice(1).map((f) => ({ name: "x/services/" + f })) },
  };
  const summary = summarize(noService, RUN);
  assert.equal(summary[fns[0]].present, true);
  assert.equal(summary[fns[0]].active, false);
  assert.equal(allActive(summary), false);
  const before = {
    queues: [],
    packages: [],
    channels: [],
    triggers: [],
    subscriptions: [],
    topics: [],
    services: [],
    sourceObjects: { uploads: [], sources: [] },
  };
  const kinds = ["queues"];
  const copy = (name) => ({ ...before, sourceObjects: { uploads: [], sources: [name] } });
  for (const name of [
    "tqretryXYZ/function-source.zip",
    "tqretryabcdef/function-source.zip",
    "tqretry0123abc/function-source.zip",
    "tqnone012345/function-source.zip",
    "tqretry0123ab/function-source.zip.bak",
    "tqretry0123ab/other.zip",
  ])
    assert.equal(
      inventoryDifferences({ runId: RUN, before, after: copy(name), kinds }).differences.length,
      1,
      name,
    );
  for (const role of ROLE_IDS)
    assert.deepEqual(
      inventoryDifferences({
        runId: RUN,
        before,
        after: copy(role + RUN.slice(0, 6) + "/function-source.zip"),
        kinds,
      }).differences,
      [],
      role,
    );
});

test("the repository policy is compared as read: a change, an unread side and no change", () => {
  const policy = { cleanupPolicies: { keep: { id: "keep" } }, cleanupPolicyDryRun: null };
  assert.deepEqual(repositoryDifferences(policy, structuredClone(policy)), {
    complete: true,
    differences: [],
  });
  const changed = { ...policy, cleanupPolicies: { keep: { id: "keep" }, extra: { id: "extra" } } };
  assert.deepEqual(repositoryDifferences(policy, changed), {
    complete: true,
    differences: [{ kind: "repository", before: policy, after: changed }],
  });
  assert.equal(repositoryDifferences(policy, null).complete, false);
  assert.equal(repositoryDifferences(undefined, policy).complete, false);
  assert.equal(repositoryDifferences(null, null).complete, false);
});

test("CLI writes distinguish functionId and queue name but retain real resends", async () => {
  for (const kind of ["function", "queue"]) {
    const url =
      kind === "function"
        ? "https://cloudfunctions.googleapis.com/v2/projects/p/locations/r/functions"
        : "https://cloudtasks.googleapis.com/v2/projects/p/locations/r/queues";
    const lines = (id) =>
      [
        `>>> [apiv2][query] POST ${url} ${kind === "function" ? JSON.stringify({ functionId: id }) : "[none]"}`,
        `>>> [apiv2][body] POST ${url} ${JSON.stringify({ name: `projects/p/locations/r/${kind === "function" ? "functions" : "queues"}/${id}` })}`,
        `<<< [apiv2][status] POST ${url} 200`,
      ].join("\n");
    const once = functionsOf(RUN).map(lines).join("\n");
    assert.equal(cliWritesFromOutput(once).length, 8, kind);
    assert.ok(
      cliWritesFromOutput(once).every((w) => w.class === "ok"),
      kind,
    );
    const twice = cliWritesFromOutput(once + "\n" + lines(functionsOf(RUN)[0]));
    assert.equal(twice.filter((w) => w.class === "retried").length, 1, kind);
    assert.equal(twice.find((w) => w.class === "retried").requests, 2);
    for (const [cliWrites, expected] of [
      [cliWritesFromOutput(once), 0],
      [twice, 1],
    ]) {
      const { result } = await go({}, {}, undefined, (runCli) => async (options) => {
        const result = await runCli(options);
        return options.action === "deploy" ? { ...result, cliWrites } : result;
      });
      assert.equal(
        result.unknownMutationList.filter((m) => m.class === "cli-write-retried").length,
        expected,
      );
    }
    const queryIds = functionsOf(RUN)
      .map(
        (id) =>
          `>>> [apiv2][query] POST ${url}?functionId=${id} [none]\n<<< [apiv2][status] POST ${url}?functionId=${id} 200`,
      )
      .join("\n");
    assert.ok(cliWritesFromOutput(queryIds).every((w) => w.class === "ok"));
  }
});

test("burst discovery and CLI deletion require only the selected role", () => {
  const name = fn("tqrate");
  const endpoints = endpointsOf();
  assert.deepEqual(declarationProblems({ [name]: endpoints[name] }, RUN, "burst"), []);
  assert.match(declarationProblems(endpoints, RUN, "burst")[0], /fixture exports/);
  const plan = cliPlan("delete", {
    configHome: "/c",
    configPath: "/s/firebase.json",
    workDir: "/s",
    home: "/h",
    path: "/n/bin:/usr/bin",
    runId: RUN,
    program: "burst",
  });
  assert.deepEqual(plan.args.slice(1, plan.args.indexOf("--config")), [name]);
});
