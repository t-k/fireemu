// The deploy side of the recorder: the CLI plan, the judgement of a CLI run, the offline discovery of the
// fixture, and the readiness reads.
import assert from "node:assert/strict";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
  cpSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import {
  allActive,
  cliFailed,
  cliPlan,
  declarationProblems,
  dependencyProblems,
  discoverManifest,
  erroredFunctions,
  escapingLinks,
  nonePresent,
  prepareSource,
  regionProblems,
  runCli,
  sourceProblems,
  summarize,
} from "./deploy.mjs";
import { ALL_FUNCTIONS, functionName } from "./plan.mjs";

const here = dirname(new URL(import.meta.url).pathname);
const sdkRoot =
  process.env.FE_SOURCE_SDK_ROOT ?? join(here, "../../node_modules/firebase-functions");
const maybe = existsSync(join(sdkRoot, "package.json")) ? test : test.skip;
const tmp = () => mkdtempSync(join(tmpdir(), "deploy-test-"));

test("the plan of the deploy, the dry run and the delete is exact", () => {
  const options = {
    configHome: "/cfg",
    configPath: "/src/firebase.json",
    workDir: "/work",
    home: "/home",
    path: "/bin",
  };
  const only = ALL_FUNCTIONS.map((n) => "functions:scheduled-delivery:" + n).join(",");
  const deploy = cliPlan("deploy", options);
  assert.deepEqual(deploy.args, [
    "deploy",
    "--config",
    "/src/firebase.json",
    "--project",
    "fireemu-oracle-sbx",
    "--only",
    only,
    "--non-interactive",
    "--force",
    "--debug",
  ]);
  assert.deepEqual(
    cliPlan("dry-run", options).args,
    [...deploy.args, "--dry-run"],
    "the exact deploy argv, with --dry-run last",
  );
  assert.deepEqual(cliPlan("delete", options).args, [
    "functions:delete",
    ...ALL_FUNCTIONS,
    "--config",
    "/src/firebase.json",
    "--region",
    "us-central1",
    "--project",
    "fireemu-oracle-sbx",
    "--non-interactive",
    "--force",
    "--debug",
  ]);
  assert.deepEqual(Object.keys(deploy.env).toSorted(), [
    "FIREBASE_CONFIG",
    "GCLOUD_PROJECT",
    "GOOGLE_CLOUD_QUOTA_PROJECT",
    "HOME",
    "PATH",
    "XDG_CONFIG_HOME",
  ]);
  assert.equal(deploy.env.GOOGLE_CLOUD_QUOTA_PROJECT, "fireemu-oracle-sbx");
  assert.equal(deploy.cwd, "/work");
  assert.throws(() => cliPlan("rollback", options), /unknown CLI action/);
  for (const key of ["configHome", "configPath", "workDir", "home"])
    assert.throws(() => cliPlan("deploy", { ...options, [key]: "relative" }), new RegExp(key));
  assert.throws(() => cliPlan("deploy", { ...options, path: "" }), /explicit PATH/);
});

test("the Errored line is read from the end of the output, with or without a debug timestamp", () => {
  assert.equal(erroredFunctions("a\n1 Functions Errored\n"), 1);
  assert.equal(erroredFunctions("[2026-10-04T16:30:00.000Z] 3 Functions Errored\n"), 3);
  assert.equal(erroredFunctions("1 Function Errored"), 1);
  assert.equal(
    erroredFunctions("0 Functions Errored\nthen\n2 Functions Errored"),
    2,
    "the last one",
  );
  assert.equal(erroredFunctions("no summary"), null);
  assert.equal(erroredFunctions("a 1 Functions Errored here"), null, "anchored to the line");
  assert.equal(erroredFunctions("1 Functions Errored trailing"), null);
  assert.equal(erroredFunctions("1 Functions Errored  \t"), 1);
  assert.equal(erroredFunctions(undefined), null);
});

test("a CLI run fails on a non-zero exit, a timeout, an error, or any errored function", () => {
  const ok = { exitCode: 0, timedOut: false, error: null, errored: 0 };
  assert.equal(cliFailed(ok), false);
  assert.equal(
    cliFailed({ ...ok, errored: null }),
    false,
    "no summary line is not a failure by itself",
  );
  assert.equal(cliFailed({ ...ok, exitCode: 1 }), true);
  assert.equal(cliFailed({ ...ok, exitCode: null }), true);
  assert.equal(cliFailed({ ...ok, timedOut: true }), true);
  assert.equal(cliFailed({ ...ok, error: "x" }), true);
  assert.equal(
    cliFailed({ ...ok, errored: 1 }),
    true,
    "exit 0 with one function errored: the earlier recording's delete",
  );
  assert.equal(cliFailed(undefined), true);
});

test("runCli runs the process once, keeps its output private and reports the errored count", async () => {
  const dir = tmp();
  try {
    const script = join(dir, "fake-firebase.mjs");
    writeFileSync(
      script,
      'console.log("[2026-10-06T00:00:00.000Z] 2 Functions Errored"); process.exit(0);\n',
    );
    const result = await runCli({
      action: "deploy",
      plan: { args: [], cwd: dir, env: { PATH: dirname(process.execPath) } },
      firebaseJs: script,
      node: process.execPath,
      directory: join(dir, "out"),
      timeoutMs: 20_000,
    });
    assert.equal(result.exitCode, 0);
    assert.equal(result.errored, 2);
    assert.equal(cliFailed(result), true);
    assert.equal(
      readFileSync(join(dir, "out/cli-deploy-stdout.txt"), "utf8").includes("2 Functions Errored"),
      true,
    );
    // A second run of the same action in the same directory is refused: nothing is overwritten.
    assert.throws(
      () =>
        runCli({
          action: "deploy",
          plan: { args: [], cwd: dir, env: {} },
          firebaseJs: script,
          node: process.execPath,
          directory: join(dir, "out"),
        }),
      /EEXIST/,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a CLI that overruns its timeout is stopped, and one that ignores SIGTERM is killed", async () => {
  const dir = tmp();
  try {
    const hang = join(dir, "hang.mjs");
    writeFileSync(hang, 'process.on("SIGTERM", () => {}); setInterval(() => {}, 1000);\n');
    const result = await runCli({
      action: "delete",
      plan: { args: [], cwd: dir, env: { PATH: dirname(process.execPath) } },
      firebaseJs: hang,
      node: process.execPath,
      directory: join(dir, "out"),
      timeoutMs: 300,
      killGraceMs: 300,
    });
    assert.equal(result.timedOut, true);
    assert.equal(cliFailed(result), true);
    assert.notEqual(result.exitCode, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the regions: every function must pin us-central1", () => {
  const ok = { a: { region: ["us-central1"] }, b: { region: ["us-central1"] } };
  assert.deepEqual(regionProblems(ok), []);
  assert.equal(regionProblems({ a: {} }).length, 1);
  assert.equal(regionProblems({ a: { region: null } }).length, 1);
  assert.equal(regionProblems({ a: { region: ["us-east1"] } }).length, 1);
  assert.equal(regionProblems({ a: { region: ["us-central1", "us-east1"] } }).length, 1);
  assert.equal(regionProblems({ a: { region: "us-central1" } }).length, 1);
});

const declared = () => ({
  schedOkV2: {
    platform: "gcfv2",
    region: ["us-central1"],
    scheduleTrigger: { schedule: "every 1 minutes" },
  },
  schedRetryV2: {
    platform: "gcfv2",
    region: ["us-central1"],
    scheduleTrigger: {
      schedule: "every 5 minutes",
      timeZone: "Asia/Tokyo",
      retryConfig: { retryCount: 6, minBackoffSeconds: 4, maxBackoffSeconds: 50, maxDoublings: 2 },
    },
  },
  schedSlowV2: {
    platform: "gcfv2",
    region: ["us-central1"],
    timeoutSeconds: 90,
    scheduleTrigger: { schedule: "every 1 minutes" },
  },
  schedOkV1: {
    platform: "gcfv1",
    region: ["us-central1"],
    scheduleTrigger: { schedule: "every 1 minutes", timeZone: "Asia/Tokyo" },
  },
  schedFailV1: {
    platform: "gcfv1",
    region: ["us-central1"],
    scheduleTrigger: { schedule: "every 5 minutes" },
  },
});

test("the declarations are the ones the packet states, and each departure is named", () => {
  assert.deepEqual(declarationProblems(declared()), []);
  const variants = [
    (e) => {
      delete e.schedOkV2;
    },
    (e) => {
      e.extra = e.schedOkV2;
    },
    (e) => {
      e.schedOkV2.platform = "gcfv1";
    },
    (e) => {
      e.schedOkV2.scheduleTrigger.schedule = "every 2 minutes";
    },
    (e) => {
      e.schedRetryV2.scheduleTrigger.timeZone = "UTC";
    },
    (e) => {
      e.schedOkV1.scheduleTrigger.timeZone = undefined;
    },
    (e) => {
      e.schedRetryV2.scheduleTrigger.retryConfig.retryCount = 5;
    },
    (e) => {
      e.schedSlowV2.timeoutSeconds = 60;
    },
  ];
  for (const [index, mutate] of variants.entries()) {
    const e = declared();
    mutate(e);
    assert.ok(declarationProblems(e).length > 0, "variant " + index);
  }
  const zoned = declared();
  zoned.schedOkV2.scheduleTrigger.timeZone = "Asia/Tokyo";
  assert.equal(
    declarationProblems(zoned).length,
    1,
    "a function that declares no time zone must have none",
  );
  const reordered = declared();
  reordered.schedRetryV2.scheduleTrigger.retryConfig = {
    maxDoublings: 2,
    maxBackoffSeconds: 50,
    retryCount: 6,
    minBackoffSeconds: 4,
  };
  assert.deepEqual(declarationProblems(reordered), [], "key order does not matter");
});

maybe(
  "the real fixture passes the offline discovery, the region check and the declarations",
  () => {
    const dir = tmp();
    try {
      const fixtureDir = join(dir, "fixture");
      cpSync(join(here, "../fixture"), fixtureDir, { recursive: true });
      mkdirSync(join(fixtureDir, "node_modules"), { recursive: true });
      symlinkSync(sdkRoot, join(fixtureDir, "node_modules/firebase-functions"));
      const endpoints = discoverManifest({
        fixtureDir,
        node: process.execPath,
        directory: join(dir, "disc"),
      });
      assert.deepEqual(Object.keys(endpoints).toSorted(), [...ALL_FUNCTIONS].toSorted());
      assert.deepEqual(regionProblems(endpoints), []);
      assert.deepEqual(declarationProblems(endpoints), []);
      // The symlink to the SDK leaves the tree, so the dependency check names it.
      assert.match(
        sourceProblems({
          fixtureDir,
          node: process.execPath,
          directory: join(dir, "disc2"),
        }).join(),
        /links in node_modules leave the tree/,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

test("dependency problems: a missing SDK, a wrong version and a link out of the tree", () => {
  const sdk = (dir, version) => {
    const root = join(dir, "fixture");
    mkdirSync(join(root, "node_modules/firebase-functions"), { recursive: true });
    writeFileSync(join(root, "package.json"), "{}");
    if (version) {
      writeFileSync(
        join(root, "node_modules/firebase-functions/package.json"),
        `{"name":"firebase-functions","version":"${version}","main":"i.js"}`,
      );
      writeFileSync(join(root, "node_modules/firebase-functions/i.js"), "");
    }
    return root;
  };
  const dirs = [tmp(), tmp(), tmp(), tmp()];
  try {
    assert.match(dependencyProblems(sdk(dirs[0], null)).join(), /cannot be resolved/);
    assert.match(dependencyProblems(sdk(dirs[1], "7.3.1")).join(), /7\.3\.1, not 7\.3\.2/);
    assert.deepEqual(dependencyProblems(sdk(dirs[2], "7.3.2")), []);
    const linked = sdk(dirs[3], "7.3.2");
    symlinkSync("/etc", join(linked, "node_modules/out"));
    assert.equal(escapingLinks(join(linked, "node_modules")).length, 1);
    assert.match(dependencyProblems(linked).join(), /1 links in node_modules leave the tree/);
  } finally {
    for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
  }
});

test("the source copy needs a full commit SHA", () => {
  assert.throws(() => prepareSource({ repoRoot: ".", commit: "HEAD", target: tmp() }), /full SHA/);
  assert.throws(
    () => prepareSource({ repoRoot: ".", commit: "abcdef0", target: tmp() }),
    /full SHA/,
  );
});

// ---- readiness ------------------------------------------------------------------------------

const fn1 = (name, status) => ({ name: functionName(name), status });
const fn2 = (name, state) => ({ name: functionName(name), state });
const service = (id) => ({
  name: "projects/fireemu-oracle-sbx/locations/us-central1/services/" + id,
});

test("readiness reads names case-exact for functions and lower-case for Cloud Run", () => {
  const all = summarize({
    v1: { functions: [fn1("schedOkV1", "ACTIVE"), fn1("schedFailV1", "ACTIVE")] },
    v2: {
      functions: [
        fn2("schedOkV2", "ACTIVE"),
        fn2("schedRetryV2", "ACTIVE"),
        fn2("schedSlowV2", "ACTIVE"),
      ],
    },
    run: { services: [service("schedokv2"), service("schedretryv2"), service("schedslowv2")] },
  });
  assert.equal(allActive(all), true);
  assert.equal(nonePresent(all), false);
  // A v2 function that is ACTIVE with no Run service is not ready; a Run service under the cased name does not count.
  const noRun = summarize({
    v1: { functions: [fn1("schedOkV1", "ACTIVE"), fn1("schedFailV1", "ACTIVE")] },
    v2: {
      functions: [
        fn2("schedOkV2", "ACTIVE"),
        fn2("schedRetryV2", "ACTIVE"),
        fn2("schedSlowV2", "ACTIVE"),
      ],
    },
    run: { services: [service("schedOkV2"), service("schedretryv2"), service("schedslowv2")] },
  });
  assert.equal(noRun.schedOkV2.active, false);
  assert.equal(allActive(noRun), false);
  // Another state, another status, the wrong case of a function: not active, not present.
  const odd = summarize({
    v1: {
      functions: [
        fn1("schedOkV1", "DEPLOYING"),
        { name: functionName("schedokv1"), status: "ACTIVE" },
      ],
    },
    v2: { functions: [fn2("schedOkV2", "FAILED")] },
    run: { services: [] },
  });
  assert.deepEqual(odd.schedOkV1, { present: true, active: false, stray: false });
  assert.deepEqual(odd.schedFailV1, { present: false, active: false, stray: false });
  assert.equal(odd.schedOkV2.present, true);
  assert.equal(odd.schedOkV2.active, false);
});

test("a function of one of the names in another region is a stray, and a stray is not an empty project", () => {
  const stray = summarize({
    v1: {},
    v2: {
      functions: [
        {
          name: "projects/fireemu-oracle-sbx/locations/us-east1/functions/schedOkV2",
          state: "ACTIVE",
        },
      ],
    },
    run: {},
  });
  assert.equal(stray.schedOkV2.stray, true);
  assert.equal(stray.schedOkV2.present, false, "it is not the function this run deploys");
  assert.equal(nonePresent(stray), false);
  const v1stray = summarize({
    v1: {
      functions: [
        {
          name: "projects/fireemu-oracle-sbx/locations/us-east1/functions/schedOkV1",
          status: "ACTIVE",
        },
      ],
    },
    v2: {},
    run: {},
  });
  assert.equal(v1stray.schedOkV1.stray, true);
  assert.equal(nonePresent(v1stray), false);
  assert.equal(summarize({ v1: {}, v2: {}, run: {} }).schedOkV2.stray, false);
  // A function with another id in another region is another function.
  assert.equal(
    summarize({
      v1: {},
      v2: {
        functions: [
          {
            name: "projects/fireemu-oracle-sbx/locations/us-east1/functions/other",
            state: "ACTIVE",
          },
        ],
      },
      run: {},
    }).schedOkV2.stray,
    false,
  );
});

test("nothing is left only when no function and no Run service remains", () => {
  const empty = summarize({ v1: {}, v2: {}, run: {} });
  assert.equal(nonePresent(empty), true);
  assert.equal(allActive(empty), false);
  assert.equal(
    nonePresent(summarize({ v1: {}, v2: {}, run: { services: [service("schedokv2")] } })),
    false,
  );
  assert.equal(
    nonePresent(
      summarize({ v1: { functions: [fn1("schedOkV1", "DELETE_IN_PROGRESS")] }, v2: {}, run: {} }),
    ),
    false,
  );
  assert.equal(nonePresent(summarize({ v1: undefined, v2: undefined, run: undefined })), true);
});

test("a list of the real recorded shape (other functions in the project) is read without error", () => {
  const real = JSON.parse(readFileSync(join(here, "../fixtures/prepare-recorded.json"), "utf8"))
    .answers.functionsV1List.body;
  const out = summarize({ v1: real, v2: {}, run: {} });
  assert.equal(nonePresent(out), true, "none of the five is among another project's functions");
  assert.equal(Object.keys(out).length, 5);
  assert.ok(chmodSync && existsSync(here));
});
