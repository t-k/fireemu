import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { appendFile, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { BLOCKING_PROGRAMS } from "./auth-tenant-blocking/blocking-corpus.mjs";
import {
  CLI_DELETE_ALLOWANCE,
  CLI_DEPLOY_ALLOWANCE,
  DEPLOY_REST_BOUND,
  FIXTURE_FUNCTION_COUNT,
  MAX_FIXTURE_OBJECTS,
  REMOVAL_REST_BOUND,
  SETTLE_READS,
} from "./auth-tenant-blocking/budget.mjs";
import {
  CLEANUP_POLICY,
  CLI_METER,
  FIXTURE_FUNCTIONS,
  REQUIRED_APIS,
  createDeployer,
  deploymentCliEnv,
  isFixtureArtifact,
  isFixtureTrigger,
} from "./auth-tenant-blocking/deploy.mjs";
import { validateTenantCorpus } from "./auth-tenant-blocking/guard.mjs";

const PROJECT = "fireemu-oracle-idp";
const NUMBER = "637500000000";
const fn = (name) => ({ functionUri: `https://${name.toLowerCase()}-abc123-uc.a.run.app` });

test("deployment subprocesses do not inherit the recording lock capability", () => {
  const env = deploymentCliEnv({
    FIREEMU_SANDBOX_LOCK_NONCE: "secret",
    FIREEMU_SANDBOX_WRAPPER_PID: "123",
    FIREEMU_AUTH_CAMPAIGN_PID: "456",
    GOOGLE_APPLICATION_CREDENTIALS: "/unreviewed.json",
    NODE_OPTIONS: "--require=/unreviewed.cjs",
    FIREEMU_CLI_METER_FILE: "/elsewhere",
    FIREEMU_CLI_METER_LIMIT: "100000",
    FIREEMU_CLI_METER_COUNT_LOOPBACK: "0",
    SAFE_VALUE: "kept",
  });
  assert.deepEqual(env, { SAFE_VALUE: "kept" });
});

/**
 * A fake of the REST surfaces the deployer calls. `state` is what exists; `calls` records every
 * request as `METHOD path`.
 */
function fakeCloud({
  apis = REQUIRED_APIS,
  functions = [],
  blocking = {},
  packages = [],
  sources = [],
  uploads = [],
  repository = { cleanupPolicies: { [CLEANUP_POLICY.id]: CLEANUP_POLICY } },
  now,
  charge,
  token = async () => "ya29.fake",
  cliCounts = {},
  events = [],
  deleteSticks = false,
  repositoryLag = 0,
  // The fixture functions answer `DEPLOYING` to this many function listings (review S6).
  deployingReads = 0,
} = {}) {
  let deploying = deployingReads;
  let lag = repositoryLag;
  const state = {
    functions: [...functions],
    blocking: structuredClone(blocking),
    packages: [...packages],
    sources: [...sources],
    uploads: [...uploads],
    repository: structuredClone(repository),
  };
  const calls = [];
  const json = (status, body) => new Response(JSON.stringify(body ?? {}), { status });
  const fetchImpl = async (url, init = {}) => {
    const { pathname, hostname } = new URL(url);
    const method = init.method ?? "GET";
    calls.push(`${method} ${hostname}${pathname}`);
    if (hostname === "serviceusage.googleapis.com")
      return json(200, {
        state: apis.includes(pathname.split("/").at(-1)) ? "ENABLED" : "DISABLED",
      });
    if (hostname === "cloudfunctions.googleapis.com") {
      const functionState = deploying > 0 ? "DEPLOYING" : "ACTIVE";
      if (deploying > 0) deploying -= 1;
      return json(200, {
        functions: state.functions.map((name) => ({
          name: `x/functions/${name}`,
          state: functionState,
          serviceConfig: { uri: fn(name).functionUri },
        })),
      });
    }
    if (pathname.endsWith("/config")) {
      if (method === "PATCH") state.blocking = JSON.parse(init.body).blockingFunctions;
      return json(200, { blockingFunctions: state.blocking });
    }
    if (hostname === "artifactregistry.googleapis.com" && pathname.endsWith("/repositories")) {
      state.repository = JSON.parse(init.body);
      return json(200, { name: "operations/create" });
    }
    if (hostname === "artifactregistry.googleapis.com" && pathname.endsWith("/gcf-artifacts")) {
      if (method === "PATCH") state.repository = { ...state.repository, ...JSON.parse(init.body) };
      if (method === "GET" && state.repository && lag > 0) {
        lag -= 1;
        return json(404, {});
      }
      return state.repository ? json(200, state.repository) : json(404, {});
    }
    if (hostname === "artifactregistry.googleapis.com") {
      if (method === "DELETE") {
        if (!deleteSticks) state.packages = state.packages.filter((p) => !pathname.endsWith(p));
        return json(200, {});
      }
      return json(200, {
        packages: state.packages.map((p) => ({ name: `projects/x/packages/${p}` })),
      });
    }
    if (hostname === "storage.googleapis.com") {
      const bucket = pathname.split("/b/")[1].split("/")[0];
      const key = bucket.startsWith("gcf-v2-uploads") ? "uploads" : "sources";
      if (method === "DELETE") {
        const name = decodeURIComponent(pathname.split("/o/")[1]);
        if (!deleteSticks) state[key] = state[key].filter((o) => o !== name);
        return new Response(null, { status: 204 });
      }
      return json(200, { items: state[key].map((name) => ({ name })) });
    }
    if (hostname === "run.googleapis.com")
      return json(200, { bindings: [{ role: "roles/run.invoker", members: ["allUsers"] }] });
    if (hostname.endsWith(".run.app")) return json(400, {});
    return json(404, {});
  };
  const runs = [];
  const runOptions = [];
  const run = async (file, args, options = {}) => {
    // As execFile: a missing working directory fails the spawn.
    if (options.cwd && !existsSync(options.cwd))
      throw Object.assign(new Error("spawn ENOENT"), { code: "ENOENT" });
    runs.push([file.split("/").at(-1), ...args].join(" "));
    runOptions.push(options);
    events.push(`run ${args[0]}`);
    const counted = cliCounts[args[0]] ?? 0;
    if (counted) await appendFile(options.env.FIREEMU_CLI_METER_FILE, ".".repeat(counted));
    // As the meter: a call past its allowance is killed.
    if (counted > Number(options.env.FIREEMU_CLI_METER_LIMIT))
      throw Object.assign(new Error("killed"), { signal: "SIGKILL", stderr: "cli-meter: stop" });
    if (args[0] === "deploy") {
      state.functions.push(...Object.values(FIXTURE_FUNCTIONS));
      state.blocking = {
        triggers: Object.fromEntries(
          Object.entries(FIXTURE_FUNCTIONS).map(([event, name]) => [event, fn(name)]),
        ),
        forwardInboundCredentials: {},
      };
      state.packages.push("fireemu--oracle--idp__us--central1__atb_before_create");
      state.sources.push("atbBeforeCreate/function-source.zip");
      state.uploads.push("d6b1a2c3-random.zip");
    }
    if (args[0] === "functions:delete")
      state.functions = state.functions.filter((name) => !args.includes(name));
    return { stdout: "", stderr: "" };
  };
  const deployer = createDeployer({
    project: PROJECT,
    number: NUMBER,
    token,
    fetchImpl,
    run,
    retryMs: 0,
    settleMs: 0,
    ...(now ? { now } : {}),
    ...(charge ? { charge } : {}),
  });
  return { state, calls, runs, runOptions, deployer };
}

const buildDir = async () => join(await mkdtemp(join(tmpdir(), "atb-deploy-")), "build");
const source = new URL("./auth-tenant-blocking/function", import.meta.url).pathname;

test("the deployer refuses another project", () => {
  assert.throws(
    () => createDeployer({ project: "fireemu-35fe6", number: NUMBER, token: async () => "" }),
    /only to the sandbox/,
  );
});

test("the preflight refuses a missing API, an existing function or a registered trigger (MF-2)", async () => {
  await assert.rejects(
    fakeCloud({
      apis: REQUIRED_APIS.filter((api) => !api.startsWith("pubsub")),
    }).deployer.preflight(),
    /pubsub/,
  );
  await assert.rejects(fakeCloud({ functions: ["other"] }).deployer.preflight(), /functions exist/);
  await assert.rejects(
    fakeCloud({ blocking: { triggers: { beforeCreate: fn("other") } } }).deployer.preflight(),
    /already registered/,
  );
});

test("nothing is removed before a deployment started (MF-1)", async () => {
  const { deployer, calls, runs } = fakeCloud({
    blocking: { triggers: { beforeCreate: fn("other") } },
  });
  await assert.rejects(deployer.preflight());
  assert.deepEqual(await deployer.remove(await buildDir()), { removed: "nothing deployed" });
  assert.ok(!calls.some((c) => c.startsWith("PATCH") || c.startsWith("DELETE")));
  assert.deepEqual(runs, []);
});

test("a removal takes out exactly what the deployment created (MF-1, MF-3)", async () => {
  const { deployer, state, runs } = fakeCloud({
    packages: ["other-image", "fireemu--oracle--idp__us--central1__atb_before_create_other"],
    sources: ["other/function-source.zip", "atbBeforeSignInOther/function-source.zip"],
    uploads: ["older-upload.zip"],
  });
  const dir = await buildDir();
  await deployer.preflight();
  await deployer.deploy(source, dir);
  assert.deepEqual(
    (await deployer.verifyRegistered()).functions,
    Object.values(FIXTURE_FUNCTIONS).toSorted(),
  );
  const removed = await deployer.remove(dir);
  assert.equal(removed.images, 1);
  assert.equal(removed.sources, 2);
  assert.deepEqual(state.functions, []);
  assert.deepEqual(state.blocking, {});
  assert.deepEqual(state.packages, [
    "other-image",
    "fireemu--oracle--idp__us--central1__atb_before_create_other",
  ]);
  assert.deepEqual(state.sources, [
    "other/function-source.zip",
    "atbBeforeSignInOther/function-source.zip",
  ]);
  assert.deepEqual(state.uploads, ["older-upload.zip"]);
  assert.ok(runs.some((r) => r.startsWith("firebase deploy --only functions:atb-blocking")));
  assert.ok(runs.some((r) => r.startsWith("firebase functions:delete atbBeforeCreate")));
});

test("a trigger of another function stops the removal untouched (MF-1)", async () => {
  const { deployer, state } = fakeCloud();
  const dir = await buildDir();
  await deployer.preflight();
  await deployer.deploy(source, dir);
  state.blocking.triggers.beforeCreate = fn("someoneElse");
  await assert.rejects(deployer.remove(dir), /another function/);
  assert.deepEqual(state.blocking.triggers.beforeCreate, fn("someoneElse"));
});

test("a same-named trigger in another project is neither verified nor removed", async () => {
  const { deployer, state, calls } = fakeCloud();
  const dir = await buildDir();
  await deployer.preflight();
  await deployer.deploy(source, dir);
  const foreign = {
    functionUri: "https://us-central1-other-project.cloudfunctions.net/atbBeforeCreate",
  };
  state.blocking.triggers.beforeCreate = foreign;
  await assert.rejects(deployer.verifyRegistered(), /beforeCreate/);
  assert.ok(
    !calls.some((call) => call.startsWith("POST us-central1-other-project.cloudfunctions.net")),
  );
  await assert.rejects(deployer.remove(dir), /another function/);
  assert.deepEqual(state.blocking.triggers.beforeCreate, foreign);
  assert.ok(!calls.some((call) => call.startsWith("PATCH identitytoolkit.googleapis.com")));
});

test("a same-named Run service in another project is not removed", async () => {
  const { deployer, state, calls } = fakeCloud();
  const dir = await buildDir();
  await deployer.preflight();
  await deployer.deploy(source, dir);
  const foreign = { functionUri: "https://atbbeforecreate-def456-uc.a.run.app" };
  state.blocking.triggers.beforeCreate = foreign;
  await assert.rejects(deployer.verifyRegistered(), /beforeCreate/);
  assert.ok(!calls.some((call) => call.startsWith("POST atbbeforecreate-def456-uc.a.run.app")));
  await assert.rejects(deployer.remove(dir), /another function/);
  assert.deepEqual(state.blocking.triggers.beforeCreate, foreign);
  assert.ok(!calls.some((call) => call.startsWith("PATCH identitytoolkit.googleapis.com")));
});

test("every trigger is checked before any warm-up request", async () => {
  const { deployer, state, calls } = fakeCloud();
  const dir = await buildDir();
  await deployer.preflight();
  await deployer.deploy(source, dir);
  state.blocking.triggers.beforeSendSms = {
    functionUri: "https://atbbeforesendsms-def456-uc.a.run.app",
  };
  await assert.rejects(deployer.verifyRegistered(), /beforeSendSms/);
  assert.ok(!calls.some((call) => call.startsWith("POST ")));
});

test("a restore cannot claim a Run trigger without its live fixture service", async () => {
  const trigger = fn("atbBeforeCreate");
  const { deployer, state, calls } = fakeCloud({
    blocking: { triggers: { beforeCreate: trigger } },
  });
  deployer.adoptLeftovers();
  await assert.rejects(deployer.remove(await buildDir()), /another function/);
  assert.deepEqual(state.blocking.triggers.beforeCreate, trigger);
  assert.ok(!calls.some((call) => call.startsWith("PATCH identitytoolkit.googleapis.com")));
});

test("fixture artifacts are recognised by function name only", () => {
  assert.ok(isFixtureArtifact("fireemu--oracle--idp__us--central1__atb_before_create"));
  assert.ok(isFixtureArtifact("fireemu--oracle--idp__us--central1__atb_before_send_sms/cache"));
  // Artifact Registry names a package with its slash encoded (review S5).
  const packages = "projects/x/locations/us-central1/repositories/gcf-artifacts/packages";
  assert.ok(
    isFixtureArtifact(
      `${packages}/fireemu--oracle--idp__us--central1__atb_before_send_sms%2Fcache`,
    ),
  );
  assert.ok(!isFixtureArtifact(`${packages}/fireemu--oracle--idp__us--central1__hello%2Fcache`));
  assert.ok(!isFixtureArtifact("projects/x/packages/%E0%A4%A"));
  assert.ok(isFixtureArtifact("atbBeforeSignIn/function-source.zip"));
  assert.ok(!isFixtureArtifact("fireemu--oracle--idp__us--central1__hello"));
  assert.ok(!isFixtureArtifact("fireemu--oracle--idp__us--central1__atb_before_create_other"));
  assert.ok(!isFixtureArtifact("other--project__us--central1__atb_before_create"));
  assert.ok(!isFixtureArtifact("atbBeforeSignInOther/function-source.zip"));
  assert.ok(
    isFixtureTrigger("beforeCreate", fn("atbBeforeCreate"), fn("atbBeforeCreate").functionUri),
  );
  assert.ok(!isFixtureTrigger("beforeCreate", fn("hello"), fn("atbBeforeCreate").functionUri));
  assert.ok(
    !isFixtureTrigger(
      "beforeCreate",
      fn("atbBeforeCreateOther"),
      fn("atbBeforeCreate").functionUri,
    ),
  );
  assert.ok(
    !isFixtureTrigger(
      "beforeCreate",
      { functionUri: "https://us-central1-other-project.cloudfunctions.net/atbBeforeCreate" },
      fn("atbBeforeCreate").functionUri,
    ),
  );
  assert.ok(
    isFixtureTrigger("beforeCreate", {
      functionUri: "https://us-central1-fireemu-oracle-idp.cloudfunctions.net/atbBeforeCreate",
    }),
  );
});

test("the blocking corpus is valid", () => {
  const requests = validateTenantCorpus(BLOCKING_PROGRAMS);
  assert.ok(requests > 50 && requests < 200, `${requests}`);
  for (const program of BLOCKING_PROGRAMS) {
    assert.match(program.id, /^atb\/blocking\//);
    assert.equal(program.functions, true);
  }
});

test("the preflight prepares gcf-artifacts with the CLI's cleanup policy once (decision C)", async () => {
  const missing = fakeCloud({ repository: null });
  assert.deepEqual(await missing.deployer.preflight(), {
    repository: "created with the cleanup policy",
  });
  assert.equal(missing.state.repository.format, "DOCKER");
  const other = fakeCloud({ repository: { cleanupPolicies: { keep: { id: "keep" } } } });
  assert.deepEqual(await other.deployer.preflight(), { repository: "cleanup policy added" });
  assert.deepEqual(Object.keys(other.state.repository.cleanupPolicies).toSorted(), [
    CLEANUP_POLICY.id,
    "keep",
  ]);
  const ready = fakeCloud();
  assert.deepEqual(await ready.deployer.preflight(), { repository: "unchanged" });
  assert.ok(!ready.calls.some((c) => c.startsWith("POST") || c.startsWith("PATCH")));
});

test("the deployment never passes --force to firebase deploy", async () => {
  const { deployer, runs } = fakeCloud();
  await deployer.preflight();
  await deployer.deploy(source, await buildDir());
  const deploy = runs.find((r) => r.startsWith("firebase deploy"));
  assert.ok(deploy && !deploy.includes("--force"), deploy);
});

test("a restore leaves upload objects alone while another function exists", async () => {
  const { deployer, state } = fakeCloud({ functions: ["hello"], uploads: ["someone.zip"] });
  deployer.adoptLeftovers();
  await assert.rejects(deployer.remove(await buildDir()), /another function exists/);
  assert.deepEqual(state.uploads, ["someone.zip"]);
});

test("a restore removal works without a build copy (confirmation SF-C1)", async () => {
  const { deployer, state } = fakeCloud({
    functions: Object.values(FIXTURE_FUNCTIONS),
    blocking: {
      triggers: Object.fromEntries(
        Object.entries(FIXTURE_FUNCTIONS).map(([event, name]) => [event, fn(name)]),
      ),
    },
  });
  deployer.adoptLeftovers();
  const dir = join(await mkdtemp(join(tmpdir(), "atb-restore-")), "missing", "build");
  await deployer.remove(dir);
  assert.deepEqual(state.functions, []);
  assert.deepEqual(state.blocking, {});
});

test(
  "a removal cannot hang on a request that never answers (review S4)",
  { timeout: 15_000 },
  async () => {
    const { deployer, state } = fakeCloud();
    const dir = join(await mkdtemp(join(tmpdir(), "atb-hang-")), "build");
    await deployer.preflight();
    await deployer.deploy(source, dir);
    // From here every REST request hangs until its signal aborts it.
    const hanging = createDeployer({
      project: PROJECT,
      number: NUMBER,
      token: async () => "ya29.fake",
      fetchImpl: (_url, init = {}) =>
        new Promise((_resolve, reject) => {
          if (!init.signal) return; // never settles: the test would time out
          init.signal.addEventListener("abort", () => reject(init.signal.reason), { once: true });
        }),
      run: async () => ({ stdout: "", stderr: "" }),
      retryMs: 0,
      requestTimeoutMs: 20,
    });
    hanging.adoptLeftovers();
    const started = Date.now();
    await assert.rejects(hanging.remove(dir));
    assert.ok(Date.now() - started < 10_000, "the removal ended");
    assert.ok(state.functions.length > 0, "the fake cloud was not reached");
  },
);

test("functions:delete gets at most the time left until the public deadline (review S4)", async () => {
  let clock = Date.parse("2026-09-27T12:00:00Z");
  const { deployer, runs, runOptions } = fakeCloud({ now: () => clock });
  const dir = join(await mkdtemp(join(tmpdir(), "atb-deadline-")), "build");
  await deployer.preflight();
  await deployer.deploy(source, dir);
  clock += 45 * 60_000;
  await deployer.remove(dir);
  const index = runs.findIndex((r) => r.startsWith("firebase functions:delete"));
  assert.ok(index >= 0);
  assert.equal(runOptions[index].timeout, 15 * 60_000);
  clock -= 45 * 60_000;
  assert.equal(deployer.deletionTimeoutMs(), 20 * 60_000);
  // A late deletion still gets the time a deletion needs: stopping it would keep them public.
  clock += 55 * 60_000;
  assert.equal(deployer.deletionTimeoutMs(), 10 * 60_000);
  clock += 60 * 60_000;
  assert.equal(deployer.deletionTimeoutMs(), 10 * 60_000);
});

test("a restore's deletion gets ten minutes", () => {
  const { deployer } = fakeCloud({ now: () => Date.parse("2026-09-27T12:00:00Z") });
  deployer.adoptLeftovers();
  assert.equal(deployer.deletionTimeoutMs(), 10 * 60_000);
});

test("every CLI call is charged its allowance before it runs, under the meter (total cap)", async () => {
  const events = [];
  const charge = (weight) => events.push(`charge ${weight}`);
  const { deployer, runs, runOptions } = fakeCloud({ charge, events });
  const dir = await buildDir();
  await deployer.cliVersion();
  await deployer.preflight();
  await deployer.deploy(source, dir);
  await deployer.remove(dir);
  assert.deepEqual(events, [
    "charge 0",
    "run --version",
    "charge 0",
    "run ci",
    `charge ${CLI_DEPLOY_ALLOWANCE}`,
    "run deploy",
    `charge ${CLI_DELETE_ALLOWANCE}`,
    "run functions:delete",
  ]);
  // npm installs from the cache only: the campaign sends nothing to the registry.
  assert.ok(
    runs
      .find((r) => r.startsWith("npm ci"))
      .split(" ")
      .includes("--offline"),
  );
  const limits = runOptions.map((options) => options.env.FIREEMU_CLI_METER_LIMIT);
  assert.deepEqual(limits, ["0", "0", String(CLI_DEPLOY_ALLOWANCE), String(CLI_DELETE_ALLOWANCE)]);
  for (const options of runOptions) {
    assert.equal(options.env.NODE_OPTIONS, `--require=${CLI_METER}`);
    // The CLI bills the sandbox, never the ADC file's quota project (review S2).
    assert.equal(options.env.GOOGLE_CLOUD_QUOTA_PROJECT, PROJECT);
    assert.equal(options.env.NO_UPDATE_NOTIFIER, "1");
    assert.equal(options.env.CI, "1");
    assert.equal(options.env.FIREEMU_CLI_METER_COUNT_LOOPBACK, undefined);
  }
  const files = runOptions.map((options) => options.env.FIREEMU_CLI_METER_FILE);
  assert.equal(new Set(files).size, files.length, "each call counts into its own file");
});

test("a refused CLI charge runs nothing, and nothing is then due for removal", async () => {
  const charge = (weight) => {
    if (weight === CLI_DEPLOY_ALLOWANCE)
      throw Object.assign(new Error("request budget: work"), { fatal: true });
  };
  const { deployer, runs } = fakeCloud({ charge });
  const dir = await buildDir();
  await deployer.preflight();
  await assert.rejects(deployer.deploy(source, dir), (error) => error.fatal === true);
  assert.ok(!runs.some((r) => r.startsWith("firebase deploy")));
  assert.deepEqual(await deployer.remove(dir), { removed: "nothing deployed" });
});

test("the requests each CLI call measured are reported with its allowance", async () => {
  const { deployer } = fakeCloud({ cliCounts: { deploy: 57, "functions:delete": 12 } });
  const dir = await buildDir();
  await deployer.preflight();
  await deployer.deploy(source, dir);
  await deployer.remove(dir);
  assert.deepEqual(deployer.cliRequests(), [
    { call: "ci", allowance: 0, used: 0, stopped: false },
    { call: "deploy", allowance: CLI_DEPLOY_ALLOWANCE, used: 57, stopped: false },
    { call: "functions:delete", allowance: CLI_DELETE_ALLOWANCE, used: 12, stopped: false },
  ]);
});

test("a CLI call the meter stopped is reported as stopped", async () => {
  const { deployer, runs } = fakeCloud({ cliCounts: { ci: 1 } });
  await deployer.preflight();
  await assert.rejects(deployer.deploy(source, await buildDir()), /npm ci failed.*SIGKILL/);
  assert.ok(!runs.some((r) => r.startsWith("firebase deploy")));
  assert.deepEqual(deployer.cliRequests(), [{ call: "ci", allowance: 0, used: 0, stopped: true }]);
});

test("the owner token is read once and renewed only after 40 minutes", async () => {
  let clock = Date.parse("2026-09-27T12:00:00Z");
  let tokens = 0;
  const { deployer } = fakeCloud({
    now: () => clock,
    token: async () => {
      tokens += 1;
      return `ya29.${tokens}`;
    },
  });
  const dir = await buildDir();
  await deployer.preflight();
  await deployer.deploy(source, dir);
  await deployer.verifyRegistered();
  assert.equal(tokens, 1);
  clock += 39 * 60_000;
  await deployer.invokers();
  assert.equal(tokens, 1);
  clock += 2 * 60_000;
  await deployer.remove(dir);
  assert.equal(tokens, 2);
});

test("a deployment sends at most DEPLOY_REST_BOUND REST requests (total cap)", async () => {
  // The worst case: the repository is created and reads back with the policy only at the last
  // of its twelve read-backs.
  const { deployer, calls } = fakeCloud({ repository: null, repositoryLag: 11 });
  await deployer.preflight();
  await deployer.deploy(source, await buildDir());
  await deployer.verifyRegistered();
  await deployer.invokers();
  assert.equal(calls.length, DEPLOY_REST_BOUND);
});

test("a removal sends at most REMOVAL_REST_BOUND REST requests (total cap)", async () => {
  // The worst case: every fixture image and more objects than the cap, none of which ever goes,
  // in a restore (which reads the functions before each object listing).
  assert.equal(Object.keys(FIXTURE_FUNCTIONS).length, FIXTURE_FUNCTION_COUNT);
  const images = Object.values(FIXTURE_FUNCTIONS).map(
    (name) =>
      `fireemu--oracle--idp__us--central1__${name.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`)}`,
  );
  const objects = Array.from(
    { length: MAX_FIXTURE_OBJECTS + 3 },
    (_, i) => `atbBeforeCreate/function-source-${i}.zip`,
  );
  const { deployer, calls, state } = fakeCloud({
    functions: Object.values(FIXTURE_FUNCTIONS),
    blocking: {
      triggers: Object.fromEntries(
        Object.entries(FIXTURE_FUNCTIONS).map(([event, name]) => [event, fn(name)]),
      ),
    },
    packages: images,
    sources: objects,
    deleteSticks: true,
    deployingReads: Number.POSITIVE_INFINITY,
  });
  deployer.adoptLeftovers();
  const error = await deployer.remove(await buildDir()).catch((caught) => caught);
  assert.match(error.message, /fixture images remain/);
  assert.match(error.message, new RegExp(`more than ${MAX_FIXTURE_OBJECTS} fixture objects`));
  assert.equal(
    calls.filter((c) => c.startsWith("DELETE artifactregistry")).length,
    FIXTURE_FUNCTION_COUNT,
  );
  assert.equal(calls.filter((c) => c.startsWith("DELETE storage")).length, MAX_FIXTURE_OBJECTS);
  assert.equal(calls.length, REMOVAL_REST_BOUND);
  assert.equal(state.functions.length, 0);
});

test("the CLI's extensions API is required before a deployment (review M1)", async () => {
  // The pinned CLI enables firebaseextensions for every functions deployment without asking.
  assert.ok(REQUIRED_APIS.includes("firebaseextensions.googleapis.com"));
  const { deployer, runs } = fakeCloud({
    apis: REQUIRED_APIS.filter((api) => api !== "firebaseextensions.googleapis.com"),
  });
  await assert.rejects(deployer.preflight(), /firebaseextensions\.googleapis\.com/);
  await assert.rejects(deployer.deploy(source, await buildDir()));
  assert.deepEqual(runs, []);
});

test("an encoded cache image is removed and read back (review S5)", async () => {
  const cache = "fireemu--oracle--idp__us--central1__atb_before_create%2Fcache";
  const other = "fireemu--oracle--idp__us--central1__hello%2Fcache";
  const { deployer, state } = fakeCloud({
    functions: Object.values(FIXTURE_FUNCTIONS),
    packages: [cache, other],
  });
  deployer.adoptLeftovers();
  await deployer.remove(await buildDir());
  assert.deepEqual(state.packages, [other]);
});

test("a removal waits while a function is still deploying (review S6)", async () => {
  const events = [];
  const { deployer, state, calls } = fakeCloud({
    functions: Object.values(FIXTURE_FUNCTIONS),
    deployingReads: 3,
    events,
  });
  deployer.adoptLeftovers();
  await deployer.remove(await buildDir());
  assert.deepEqual(state.functions, []);
  // The URI read and two settling reads answer DEPLOYING; the delete follows the first ACTIVE
  // listing.
  const lists = calls.filter((c) => c.startsWith("GET cloudfunctions"));
  assert.ok(lists.length >= 5, calls.join("\n"));
  assert.deepEqual(events, ["run functions:delete"]);
});

test("a removal stops waiting after its bound and deletes anyway (review S6)", async () => {
  const listings = async (deployingReads) => {
    const { deployer, state, calls } = fakeCloud({
      functions: Object.values(FIXTURE_FUNCTIONS),
      deployingReads,
    });
    deployer.adoptLeftovers();
    await deployer.remove(await buildDir());
    assert.deepEqual(state.functions, []);
    return calls.filter((c) => c.startsWith("GET cloudfunctions")).length;
  };
  assert.equal((await listings(Number.POSITIVE_INFINITY)) - (await listings(0)), SETTLE_READS);
});

test("the pinned CLI starts without sending anything (allowance zero)", async () => {
  const deployer = createDeployer({
    project: PROJECT,
    number: NUMBER,
    token: async () => "ya29.fake",
    fetchImpl: async () => {
      throw new Error("no REST request");
    },
    charge: () => {},
  });
  assert.match(await deployer.cliVersion(), /^\d+\.\d+\.\d+$/);
  assert.deepEqual(deployer.cliRequests(), [
    { call: "--version", allowance: 0, used: 0, stopped: false },
  ]);
});
