// The orchestrator against the in-memory world: the clean run, what stops it before anything is created, every unknown answer,
// the configuration comparison, and the cleanup's rules (only issued names, leftovers once, nothing re-sent, every name read back).
import assert from "node:assert/strict";
import test from "node:test";
import { CONFIG_URL, FUNCTION, PROJECT, functionName, packageIds } from "./plan.mjs";
import {
  MAX_REQUESTS,
  absent,
  configDifference,
  configDigest,
  emptyBlocking,
  iamPolicyOf,
  record,
} from "./run.mjs";
import { emailOf } from "./script.mjs";
import { FUNCTION_URL, LOCAL_ID, NUMBER, SERVICE_URI, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const error = (code, status, message = "x") => reply(code, { error: { code, message, status } });
const path = (request) => new URL(request.url).pathname;

async function go(
  worldOptions = {},
  wrapSend = (send) => send,
  options = {},
  wrapCli = (cli) => cli,
) {
  const world = createWorld({ runId: RUN, ...worldOptions });
  const journal = [];
  const sleeps = [];
  const prepared = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "test-token-abcdefgh",
    save: async (row) => journal.push(row),
    send: wrapSend(world.send, world),
    runCli: wrapCli((o) => world.runCli(o), world),
    clock: () => world.now,
    sleep: async (ms) => {
      sleeps.push(ms);
      world.advance(ms);
    },
    prepareRequest: async (spec) => prepared.push(spec.id),
    ...options,
  });
  return { world, journal, sleeps, result, prepared };
}
const ids = (journal) => journal.filter((r) => r.state === "before-send").map((r) => r.id);
const count = (world, prefix) => world.calls.filter((c) => c.startsWith(prefix)).length;
const writes = (world) =>
  world.calls.filter(
    (c) =>
      !c.startsWith("GET ") &&
      !c.includes("entries:list") &&
      !c.includes("getIamPolicy") &&
      !c.includes("accounts:query") &&
      !c.includes("accounts:lookup"),
  );
const noWrites = (world) => assert.deepEqual(writes(world), []);

test("a clean run records, cleans up, reads every name back, finds the configuration unchanged and may close", async () => {
  const { world, result, journal, prepared } = await go();
  assert.equal(result.outcome, "pcblock-recorded");
  assert.equal(result.closureReady, true);
  assert.equal(result.readBackRequired, false);
  assert.equal(result.unknown, 0);
  assert.deepEqual(world.cliRuns, ["dry-run", "deploy", "delete"]);
  assert.equal(world.functions.size + world.runServices.size + world.packages.size, 0);
  assert.equal(world.accounts.size, 3, "the project has its own accounts again");
  assert.deepEqual(
    world.config.blockingFunctions,
    { forwardInboundCredentials: {} },
    "the trigger the CLI registered is gone; what it wrote beside it stays (production)",
  );
  assert.equal(result.cleanup.verified, true);
  assert.equal(result.cleanup.functionGone, true);
  assert.equal(result.cleanup.listsEmpty, true);
  assert.deepEqual(result.cleanup.configDifference, []);
  assert.equal(result.cleanup.configRestored, true);
  assert.equal(result.cleanup.accountsBefore, 3);
  assert.equal(result.cleanup.accountsAfter, 3);
  assert.deepEqual(result.cleanup.readBack, {
    function: true,
    "package-fireemu--oracle--idp__us--central1__pcblock": true,
    "package-fireemu--oracle--idp__us--central1__pcblock%2Fcache": true,
    "upload-object-1": true,
    account: true,
  });
  assert.deepEqual(result.judged.counts, {
    "as-expected": 7,
    differs: 0,
    observed: 0,
    "not-delivered": 0,
    "not-sent": 0,
  });
  assert.ok(result.attempted <= MAX_REQUESTS);
  assert.equal(prepared.length, result.attempted);
  assert.equal(
    journal.filter((r) => r.status >= 400 && r.status !== 404).length,
    0,
    "the world refused no request",
  );
  assert.equal(JSON.stringify(journal).includes("test-token-abcdefgh"), false);
  assert.equal(result.stage, "done");
});

test("a clean run writes only the sign-up, the account's delete and the two images' deletes, each once, and never the configuration", async () => {
  const { world, journal } = await go();
  const own = [
    /^POST identitytoolkit\.googleapis\.com\/v1\/accounts:signUp$/,
    /^POST identitytoolkit\.googleapis\.com\/v1\/projects\/[^/]+\/accounts:delete$/,
    /^DELETE artifactregistry\.googleapis\.com\/.*\/packages\/fireemu--oracle--idp__us--central1__pcblock(%2Fcache)?$/,
    /^DELETE storage\.googleapis\.com\/storage\/v1\/b\/gcf-v2-uploads-[^/]+\/o\/[^/]+$/,
    /^POST run\.googleapis\.com\/v2\/projects\/[^/]+\/locations\/[^/]+\/services\/pcblock:setIamPolicy$/,
  ];
  for (const call of writes(world))
    assert.ok(
      own.some((re) => re.test(call)),
      "unexpected write: " + call,
    );
  assert.equal(writes(world).length, 6);
  assert.ok(
    !world.calls.some((c) => /config/.test(c) && !c.startsWith("GET ")),
    "the configuration is only read",
  );
  assert.equal(count(world, "DELETE cloudfunctions"), 0, "the CLI deletes the function");
  const writeIds = journal
    .filter(
      (r) =>
        r.state === "before-send" &&
        r.method !== "GET" &&
        !r.url.includes("entries:list") &&
        !r.url.includes("getIamPolicy") &&
        !r.url.includes("accounts:query"),
    )
    .map((r) => r.id);
  assert.equal(new Set(writeIds).size, writeIds.length);
});

test("the journal says what was issued before the deploy, and the order of the phases", async () => {
  const { journal } = await go();
  const rows = journal.filter((r) => r.state === "issued");
  assert.deepEqual(
    rows.map((r) => [r.id, r.kind, r.name, r.transport]),
    [
      ["issue-function", "function", functionName(), "cli"],
      ["issue-account", "account", emailOf(RUN), "rest"],
    ],
  );
  const order = ids(journal);
  const at = (id) => order.indexOf(id);
  assert.ok(
    at("identity") < at("services-before") &&
      at("services-before") < at("config-before") &&
      at("config-before") < at("accounts-before") &&
      at("accounts-before") < at("repository"),
  );
  assert.ok(
    at("preflight-functions-v2") < at("preflight-packages") &&
      at("preflight-packages") < at("preflight-source-objects-uploads"),
  );
  assert.ok(
    at("readback-function") < at("readback-invoker") &&
      at("readback-invoker") < at("config-after-deploy") &&
      at("config-after-deploy") < at("op-sign-up"),
  );
  assert.ok(
    at("op-sign-up") < at("logs-observe-1-frames") &&
      at("logs-observe-1-frames") < at("cleanup-account-delete"),
  );
  assert.ok(
    at("cleanup-account-delete") < at("cleanup-1-functions-v2") &&
      at("cleanup-1-functions-v2") < at("config-after") &&
      at("config-after") < at("accounts-after") &&
      at("accounts-after") < at("logs-final-frames"),
  );
  assert.ok(
    at("readback-gone-account") > at("delete-package-fireemu--oracle--idp__us--central1__pcblock"),
  );
  assert.ok(journal.some((r) => r.id === "cli-deploy" && r.state === "cli-result"));
});

test("the result carries the readbacks, the baselines and the inventory", async () => {
  const { result, world } = await go();
  assert.equal(result.readbacks.function.state, "ACTIVE");
  assert.equal(result.readbacks.function.uri, SERVICE_URI);
  assert.equal(
    result.readbacks.function.serviceAccount,
    "123456789012-compute@developer.gserviceaccount.com",
  );
  assert.deepEqual(result.readbacks.invoker, { members: ["allUsers"], allUsersInvoker: true });
  assert.equal(result.readbacks.function.url, FUNCTION_URL);
  assert.equal(result.readbacks.registration.trigger.functionUri, FUNCTION_URL);
  assert.equal(result.readbacks.registration.functionUrl, FUNCTION_URL);
  assert.equal(result.readbacks.registration.serviceUri, SERVICE_URI);
  assert.deepEqual(result.signUp, { class: "2xx", status: 200, localId: LOCAL_ID });
  assert.equal(result.inventory.before.accounts, 3);
  assert.deepEqual(result.inventory.before.packages, []);
  assert.deepEqual(result.inventory.before.triggers, []);
  assert.deepEqual(result.inventory.before.subscriptions, []);
  assert.deepEqual(result.inventory.before.topics, []);
  assert.ok(result.inventory.before.services.includes("identitytoolkit.googleapis.com"));
  assert.deepEqual(result.inventory.before.sourceObjects, {
    uploads: ["old-upload.zip"],
    sources: [],
  });
  assert.deepEqual(result.inventory.differences, []);
  assert.equal(result.inventory.complete, true);
  assert.equal(
    result.configBefore.sha256,
    configDigest({
      name: `projects/${NUMBER}/config`,
      signIn: { email: { enabled: true, passwordRequired: true } },
      mfa: { state: "DISABLED" },
    }),
  );
  assert.equal(result.configBefore.blockingFunctions, null);
  assert.deepEqual(result.inventory.sourceObjects.uploads, { added: [], removed: [] });
  assert.deepEqual(result.inventory.sourceObjects.sources, {
    added: ["pcblock/function-source.zip"],
    removed: [],
  });
  assert.equal(result.cleanup.uploadObjectsDeleted.length, 1);
  assert.deepEqual(result.inventory.iam, { complete: true, unexpected: [] });
  assert.deepEqual(result.inventory.services, { added: [], removed: [] });
  assert.deepEqual(result.frames, { "blocking-raw": 1, "blocking-sdk": 1 });
  assert.equal(result.errorsSeen, 0);
  assert.deepEqual(result.framesIgnored, { notFrame: 0, unparsed: 0, foreignOrigin: 0 });
  assert.equal(world.signUps, 1);
});

test("the golden journal rows and waits of a clean run", async () => {
  const { journal, sleeps } = await go();
  const rows = journal
    .filter((r) => r.state !== "response-persisted" && r.state !== "response-headers")
    .map((r) => r.id + ":" + r.state);
  assert.ok(rows.includes("identity:before-send") && rows.includes("cli-dry-run:cli-result"));
  assert.deepEqual(sleeps, [60_000, 60_000, 120_000]);
});

// ---- before anything is created -----------------------------------------------------------------------

const STOPS = [
  [
    "a project that is not the sandbox",
    {
      hooks: {
        "GET firebase.googleapis.com/v1beta1/projects/fireemu-oracle-idp": () =>
          reply(200, { projectId: "other", projectNumber: NUMBER }),
      },
    },
    "identity",
  ],
  [
    "a project number that is not the one given",
    {
      hooks: {
        "GET firebase.googleapis.com/v1beta1/projects/fireemu-oracle-idp": () =>
          reply(200, { projectId: PROJECT, projectNumber: "999999999999" }),
      },
    },
    "identity",
  ],
  [
    "a project read that fails",
    {
      hooks: {
        "GET firebase.googleapis.com/v1beta1/projects/fireemu-oracle-idp": () =>
          error(500, "INTERNAL"),
      },
    },
    "identity",
  ],
  [
    "a configuration that cannot be read",
    {
      hooks: {
        [`GET identitytoolkit.googleapis.com/admin/v2/projects/${PROJECT}/config`]: () =>
          error(500, "INTERNAL"),
      },
    },
    "config",
  ],
  [
    "blocking triggers already registered",
    { baselineBlocking: { triggers: { beforeCreate: { functionUri: "https://x.run.app" } } } },
    "blocking-config",
  ],
  [
    "a blocking section that is not the empty baseline",
    { baselineBlocking: { forwardInboundCredentials: { idToken: true } } },
    "blocking-config",
  ],
  [
    "an account count that cannot be read",
    {
      hooks: {
        [`POST identitytoolkit.googleapis.com/v1/projects/${PROJECT}/accounts:query`]: () =>
          error(500, "INTERNAL"),
      },
    },
    "accounts",
  ],
];
for (const [what, options, because] of STOPS)
  test(`${what} stops the run before anything is created`, async () => {
    const { result, world } = await go(options);
    assert.equal(result.stoppedBecause, because);
    assert.equal(result.outcome, "pcblock-stopped-clean");
    assert.equal(result.closureReady, false);
    assert.equal(result.cleanup.verified, false);
    assert.equal(result.stage, "preflight");
    assert.deepEqual(world.cliRuns, []);
    noWrites(world);
  });

test("an empty blocking section, in either form, is the baseline", async () => {
  for (const baselineBlocking of [{}, { triggers: {} }]) {
    const { result, world } = await go({ baselineBlocking });
    assert.equal(result.outcome, "pcblock-recorded", JSON.stringify(baselineBlocking));
    assert.deepEqual(world.config.blockingFunctions, baselineBlocking);
  }
});

test("a missing required API stops the run, and so does a missing repository", async () => {
  for (const id of [
    "compute.googleapis.com",
    "firebaseextensions.googleapis.com",
    "identitytoolkit.googleapis.com",
    "run.googleapis.com",
  ]) {
    const world = createWorld({ runId: RUN });
    world.services.delete(id);
    const result = await record({
      runId: RUN,
      projectNumber: NUMBER,
      accessToken: "tok-abcdefgh",
      save: async () => {},
      send: world.send,
      runCli: world.runCli,
      clock: () => world.now,
      sleep: async (ms) => world.advance(ms),
    });
    assert.deepEqual(result.servicesMissing, [id]);
    assert.equal(result.stoppedBecause, "services");
    assert.deepEqual(world.cliRuns, []);
  }
  const noRepository = await go({}, (send, world) => ((world.repository = false), send));
  assert.equal(noRepository.result.stoppedBecause, "repository");
  assert.deepEqual(noRepository.world.cliRuns, []);
  const unreadable = await go(
    {},
    (send) => async (request) =>
      path(request).endsWith("/gcf-artifacts") ? error(403, "PERMISSION_DENIED") : send(request),
  );
  assert.equal(
    unreadable.result.stoppedBecause,
    "repository",
    "a 403 on the observing repository read is data",
  );
});

const NAMESPACE = [
  [
    "the function",
    (w) => w.functions.set(functionName(), { name: functionName(), state: "ACTIVE" }),
  ],
  ["its Cloud Run service", (w) => w.runServices.add("pcblock")],
  ["its image", (w) => w.packages.add(packageIds()[0])],
  ["its cache image", (w) => w.packages.add(packageIds()[1])],
  [
    "a function of that name in another region",
    (w) =>
      w.functions.set("projects/fireemu-oracle-idp/locations/europe-west1/functions/pcblock", {
        name: "projects/fireemu-oracle-idp/locations/europe-west1/functions/pcblock",
        state: "ACTIVE",
      }),
  ],
];
for (const [what, seed] of NAMESPACE)
  test(`${what} that is already there stops the run before anything is created`, async () => {
    const world = createWorld({ runId: RUN });
    seed(world);
    const result = await record({
      runId: RUN,
      projectNumber: NUMBER,
      accessToken: "tok-abcdefgh",
      save: async () => {},
      send: world.send,
      runCli: world.runCli,
      clock: () => world.now,
      sleep: async (ms) => world.advance(ms),
    });
    assert.equal(result.stoppedBecause, "namespace");
    assert.equal(result.outcome, "pcblock-stopped-clean");
    assert.deepEqual(world.cliRuns, []);
    noWrites(world);
  });

test("other people's functions and images do not stop the run and are never touched", async () => {
  const world = createWorld({ runId: RUN });
  world.functions.set("projects/fireemu-oracle-idp/locations/us-central1/functions/another", {
    name: "projects/fireemu-oracle-idp/locations/us-central1/functions/another",
    state: "ACTIVE",
  });
  world.packages.add("someone-else");
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    send: world.send,
    runCli: world.runCli,
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
  });
  assert.equal(result.outcome, "pcblock-recorded");
  assert.ok(
    world.functions.has("projects/fireemu-oracle-idp/locations/us-central1/functions/another") &&
      world.packages.has("someone-else"),
  );
});

test("a failed CLI dry run stops the run clean, with no deploy", async () => {
  const { result, world } = await go(
    {},
    (send) => send,
    {},
    (cli) => async (o) =>
      o.action === "dry-run"
        ? { action: o.action, exitCode: 1, timedOut: false, error: null, errored: 0 }
        : cli(o),
  );
  assert.equal(result.outcome, "pcblock-stopped-clean");
  assert.equal(result.stoppedBecause, "the CLI dry run failed");
  assert.equal(result.stage, "dry-run");
  assert.equal(result.closureReady, false);
  assert.deepEqual(
    world.cliRuns,
    [],
    "the dry run was the replaced one; no deploy and no delete followed",
  );
  noWrites(world);
});

// ---- after the deploy ---------------------------------------------------------------------------------

test("a failed deploy is cleaned up and the run does not close", async () => {
  const { result, world, journal } = await go({ failDeploy: true });
  assert.deepEqual(world.cliRuns, ["dry-run", "deploy", "delete"]);
  assert.equal(result.outcome, "pcblock-incomplete-clean");
  assert.equal(result.closureReady, false);
  assert.equal(result.cleanup.verified, true);
  assert.equal(count(world, "POST identitytoolkit.googleapis.com/v1/accounts:signUp"), 0);
  assert.deepEqual(
    ids(journal).filter((id) => /^ready-\d+-functions-v2$/.test(id)),
    ["ready-1-functions-v2", "ready-2-functions-v2"],
  );
});

test("a function that never becomes active is waited for as long as allowed, and nothing is signed up", async () => {
  const { result, world, journal, sleeps } = await go(
    { deployState: "DEPLOYING" },
    (send) => send,
    { waits: { readyPolls: 3, ready: 3 } },
  );
  assert.deepEqual(
    ids(journal).filter((id) => /^ready-\d+-functions-v2$/.test(id)),
    ["ready-1-functions-v2", "ready-2-functions-v2", "ready-3-functions-v2"],
  );
  assert.equal(sleeps.filter((ms) => ms === 3000).length, 2);
  assert.equal(result.outcome, "pcblock-incomplete-clean");
  assert.equal(world.signUps, 0);
  assert.equal(result.cleanup.verified, true);
});

test("the CLI's own errors are unknown answers: the function stays unconfirmed until an own read shows it", async () => {
  for (const [flaw, klass] of [
    [{ timedOut: true }, "cli-timeout"],
    [{ signal: "SIGKILL" }, "cli-signal"],
    [{ error: "spawn" }, "cli-error"],
  ]) {
    const { result } = await go(
      {},
      (send) => send,
      {},
      (cli) => async (o) => (o.action === "deploy" ? { ...(await cli(o)), ...flaw } : cli(o)),
    );
    assert.deepEqual(
      result.unknownMutationList.map((u) => [u.id, u.class]),
      [["cli-deploy", klass]],
    );
    assert.deepEqual(
      result.unconfirmedCreates,
      [],
      "the ready list and the function read showed it",
    );
    assert.equal(result.closureReady, false);
    assert.equal(result.readBackRequired, true);
    assert.equal(result.outcome, "pcblock-needs-review");
  }
});

test("a deploy the CLI timed out of, with nothing readable afterwards, leaves the function unconfirmed", async () => {
  const hidden = (send) => async (request) => {
    if (request.method === "GET" && path(request).includes("/functions"))
      return path(request).endsWith("/functions") ? reply(200, {}) : error(404, "NOT_FOUND");
    return send(request);
  };
  const { result } = await go(
    { deployState: "DEPLOYING" },
    hidden,
    { waits: { readyPolls: 1 } },
    (cli) => async (o) => (o.action === "deploy" ? { ...(await cli(o)), timedOut: true } : cli(o)),
  );
  assert.deepEqual(
    result.unconfirmedCreates.map((u) => [u.label, u.id, u.name, u.class]),
    [["function", "cli-deploy", functionName(), "cli-timeout"]],
  );
});

test("a CLI that throws leaves the function unconfirmed as cli-error, records the error, and the cleanup still runs", async () => {
  const { result, world, journal } = await go(
    {},
    (send) => send,
    {},
    (cli) => async (o) => {
      if (o.action === "deploy") throw new Error("spawn failed");
      return cli(o);
    },
  );
  assert.equal(result.stoppedBecause, "spawn failed");
  assert.deepEqual(
    result.unknownMutationList.map((u) => [u.id, u.class]),
    [["cli-deploy", "cli-error"]],
  );
  assert.deepEqual(
    result.unconfirmedCreates.map((u) => [u.label, u.class]),
    [["function", "cli-error"]],
  );
  assert.ok(
    journal.some(
      (r) => r.id === "cli-deploy" && r.state === "cli-result" && r.result.error === "spawn failed",
    ),
  );
  assert.deepEqual(world.cliRuns, ["dry-run", "delete"]);
  assert.equal(result.closureReady, false);
});

// ---- the configuration ----------------------------------------------------------------------------------

test("a trigger that is still registered after the CLI delete is a failed cleanup, is not removed by this run, and goes to the read-back", async () => {
  const { result, world } = await go({ leaveTrigger: true });
  assert.deepEqual(result.cleanup.configDifference, ["blockingFunctions"]);
  assert.equal(result.cleanup.configRestored, false);
  assert.equal(result.cleanup.verified, false);
  assert.equal(result.outcome, "pcblock-needs-recovery");
  assert.equal(result.closureReady, false);
  assert.equal(result.readBackRequired, true);
  assert.ok(
    world.config.blockingFunctions.triggers.beforeCreate,
    "the trigger is still there: the recorder never writes the configuration",
  );
  assert.ok(!world.calls.some((c) => /config/.test(c) && !c.startsWith("GET ")));
});

test("any other change to the configuration is a failed cleanup too, named by its key", async () => {
  const { result } = await go({}, (send, world) => async (request) => {
    if (
      request.method === "GET" &&
      path(request).endsWith("/config") &&
      world.cliRuns.includes("delete")
    )
      world.config.mfa = { state: "ENABLED" };
    return send(request);
  });
  assert.deepEqual(result.cleanup.configDifference, ["mfa"]);
  assert.equal(result.outcome, "pcblock-needs-recovery");
  assert.equal(result.readBackRequired, true);
});

test("a configuration that cannot be read after the cleanup is not a restored one", async () => {
  const { result } = await go(
    {},
    (send, world) => async (request) =>
      request.method === "GET" &&
      path(request).endsWith("/config") &&
      world.cliRuns.includes("delete")
        ? error(500, "INTERNAL")
        : send(request),
  );
  assert.equal(result.cleanup.configDifference, null);
  assert.equal(result.cleanup.configRestored, false);
  assert.equal(result.cleanup.verified, false);
  assert.equal(result.outcome, "pcblock-needs-recovery");
});

test("a configuration with a pre-existing empty blocking section comes back equal", async () => {
  const { result } = await go({ baselineBlocking: { triggers: {} } });
  assert.equal(result.cleanup.configRestored, true);
  assert.deepEqual(result.configBefore.blockingFunctions, { triggers: {} });
});

test("the trigger and the invoker are judged from what was registered, not assumed", async () => {
  const unregistered = await go({}, (send, world) => async (request) => {
    if (
      request.method === "GET" &&
      path(request).endsWith("/config") &&
      world.cliRuns.includes("deploy") &&
      !world.cliRuns.includes("delete")
    )
      delete world.config.blockingFunctions;
    return send(request);
  });
  assert.equal(unregistered.result.judged.cases["trigger-registered"].status, "differs");
  assert.equal(unregistered.result.readbacks.registration.trigger, null);
  const wrongUri = await go({}, (send, world) => async (request) => {
    if (
      request.method === "GET" &&
      path(request).endsWith("/config") &&
      !world.cliRuns.includes("delete") &&
      world.cliRuns.includes("deploy")
    )
      world.config.blockingFunctions.triggers.beforeCreate.functionUri =
        "https://elsewhere.example/";
    return send(request);
  });
  assert.equal(wrongUri.result.judged.cases["trigger-registered"].status, "differs");
  const private_ = await go({ publicInvoker: false });
  assert.equal(private_.result.judged.cases["invoker-public"].status, "differs");
  assert.equal(
    private_.result.outcome,
    "pcblock-recorded",
    "a difference in what production did is data, not a failure",
  );
  const unreadable = await go(
    {},
    (send) => async (request) =>
      path(request).endsWith(":getIamPolicy") && request.method === "GET"
        ? error(403, "PERMISSION_DENIED")
        : send(request),
  );
  assert.equal(unreadable.result.judged.cases["invoker-public"].status, "not-sent");
  assert.notEqual(
    unreadable.result.outcome,
    "pcblock-auth-stop",
    "a 403 on the observing invoker read is data",
  );
  assert.equal(unreadable.result.outcome, "pcblock-recorded");
});

// ---- the account ----------------------------------------------------------------------------------------

test("a refused sign-up is a known answer: nothing to delete, the run goes on to the cleanup", async () => {
  const { result, world } = await go(
    {},
    (send) => async (request) =>
      path(request) === "/v1/accounts:signUp" ? error(400, "INVALID_ARGUMENT") : send(request),
  );
  assert.equal(result.signUp.class, "4xx");
  assert.equal(result.signUp.localId, null);
  assert.deepEqual(result.unconfirmedCreates, [], "a refusal made no account");
  assert.equal(result.readBackRequired, false);
  assert.equal(result.outcome, "pcblock-recorded");
  assert.equal(result.closureReady, true);
  assert.equal(result.judged.cases["signup-allowed"].status, "differs");
  assert.equal(
    count(
      world,
      "POST identitytoolkit.googleapis.com/v1/projects/fireemu-oracle-idp/accounts:query",
    ),
    2,
    "only the two count reads",
  );
  assert.equal(
    count(
      world,
      "POST identitytoolkit.googleapis.com/v1/projects/fireemu-oracle-idp/accounts:lookup",
    ),
    0,
  );
  assert.ok(!world.calls.some((c) => c.endsWith("accounts:delete")));
  assert.deepEqual(world.cliRuns, ["dry-run", "deploy", "delete"]);
  assert.equal(result.cleanup.verified, true);
  assert.deepEqual(result.unconfirmedCreates, [], "a definite refusal leaves nothing unconfirmed");
});

test("a 2xx sign-up with no account id, or one that is not JSON, leaves the account unknown: it is unconfirmed and blocks the close alone", async () => {
  for (const [label, answer] of [
    ["an empty object", () => reply(200, {})],
    ["no JSON", () => new Response("<html>", { status: 200 })],
    ["a 201 without an id", () => reply(201, { kind: "x" })],
  ]) {
    const { result } = await go(
      {},
      (send) => async (request) =>
        path(request) === "/v1/accounts:signUp" ? answer() : send(request),
    );
    assert.deepEqual(
      result.unconfirmedCreates.map((u) => u.label),
      ["account"],
      label,
    );
    assert.equal(result.closureReady, false, label);
    assert.equal(result.readBackRequired, true, label);
    assert.notEqual(result.outcome, "pcblock-recorded", label);
  }
  const only = await go(
    {},
    (send) => async (request) =>
      path(request) === "/v1/accounts:signUp" ? reply(200, {}) : send(request),
  );
  assert.equal(
    only.result.unknownMutationList.length,
    0,
    "nothing but the unconfirmed create blocks",
  );
});

test("a 403 or a 401 on the sign-up (the key's answer) is a refused sign-up: the full cleanup runs", async () => {
  for (const code of [403, 401]) {
    const { result, world, journal } = await go(
      {},
      (send) => async (request) =>
        path(request) === "/v1/accounts:signUp" ? error(code, "PERMISSION_DENIED") : send(request),
    );
    assert.equal(result.signUp.status, code, String(code));
    assert.equal(result.signUp.class, "4xx", String(code));
    assert.deepEqual(world.cliRuns, ["dry-run", "deploy", "delete"], String(code));
    assert.equal(world.packages.size, 0, "the images are deleted");
    assert.equal(result.cleanup.uploadObjectsDeleted.length, 1, "the upload object is deleted");
    assert.ok(
      journal.some((r) => r.id === "config-after"),
      "the configuration is read after the cleanup",
    );
    assert.ok(result.cleanup.readBack["package-fireemu--oracle--idp__us--central1__pcblock"]);
    assert.equal(result.cleanup.verified, true, String(code));
    assert.deepEqual(result.unconfirmedCreates, [], String(code));
  }
  const key = await go(
    {},
    (send) => async (request) =>
      path(request) === "/v1/accounts:signUp" ? error(401, "UNAUTHENTICATED") : send(request),
  );
  assert.equal(
    key.result.signUp.keyRefused,
    true,
    "a 401 is the key's: it is not a stop of the cleanup",
  );
  assert.equal(key.result.closureReady, false, "but the run is not closable");
  const forbidden = await go(
    {},
    (send) => async (request) =>
      path(request) === "/v1/accounts:signUp" ? error(403, "PERMISSION_DENIED") : send(request),
  );
  assert.equal(forbidden.result.signUp.keyRefused, undefined);
  assert.equal(forbidden.result.outcome, "pcblock-recorded");
});

test("an unknown answer to the sign-up is never re-sent, cannot be settled, and is deleted by nothing", async () => {
  for (const [name, wrap] of [
    [
      "transport",
      (send) => async (request) => {
        if (path(request) === "/v1/accounts:signUp") throw new Error("reset");
        return send(request);
      },
    ],
    [
      "503",
      (send) => async (request) =>
        path(request) === "/v1/accounts:signUp" ? error(503, "UNAVAILABLE") : send(request),
    ],
    [
      "302",
      (send) => async (request) =>
        path(request) === "/v1/accounts:signUp"
          ? new Response(null, { status: 302 })
          : send(request),
    ],
  ]) {
    const { result, world, journal } = await go({}, wrap);
    assert.equal(ids(journal).filter((id) => id === "op-sign-up").length, 1, name);
    assert.deepEqual(
      result.unconfirmedCreates.map((u) => [u.label, u.id, u.name]),
      [["account", "op-sign-up", emailOf(RUN)]],
      name,
    );
    assert.equal(result.closureReady, false, name);
    assert.equal(result.readBackRequired, true, name);
    assert.ok(
      !world.calls.some((c) => c.endsWith("accounts:delete")),
      "an account whose id is unknown is never deleted: " + name,
    );
    assert.equal(
      result.cleanup.accountsAfter,
      result.cleanup.accountsBefore,
      "nothing was created in the world: " + name,
    );
  }
});

test("an unknown sign-up that did create the account leaves a different count, which no delete of ours repairs", async () => {
  const { result, world } = await go({}, (send) => async (request) => {
    if (path(request) === "/v1/accounts:signUp") {
      await send(request);
      throw new Error("reset after the write");
    }
    return send(request);
  });
  assert.equal(world.accounts.size, 4);
  assert.equal(result.cleanup.accountsBefore, 3);
  assert.equal(result.cleanup.accountsAfter, 4);
  assert.equal(result.cleanup.verified, false);
  assert.equal(result.outcome, "pcblock-needs-recovery");
  assert.equal(result.readBackRequired, true);
  assert.ok(!world.calls.some((c) => c.endsWith("accounts:delete")));
});

test("the account is deleted once by the id its own sign-up returned, and read back", async () => {
  const { world, journal } = await go();
  const del = journal.find((r) => r.id === "cleanup-account-delete" && r.state === "before-send");
  assert.deepEqual(del.json, { localId: LOCAL_ID });
  assert.equal(
    count(
      world,
      "POST identitytoolkit.googleapis.com/v1/projects/fireemu-oracle-idp/accounts:delete",
    ),
    1,
  );
  assert.ok(ids(journal).includes("readback-gone-account"));
});

test("an account delete answered unknown is sticky and never re-sent; a delete that did not take effect leaves the account to recover", async () => {
  const unknown = await go({}, (send) => async (request) => {
    if (path(request).endsWith("accounts:delete")) {
      await send(request);
      return error(503, "UNAVAILABLE");
    }
    return send(request);
  });
  assert.equal(
    count(
      unknown.world,
      "POST identitytoolkit.googleapis.com/v1/projects/fireemu-oracle-idp/accounts:delete",
    ),
    1,
  );
  assert.deepEqual(unknown.result.unknownMutationList, [
    { id: "cleanup-account-delete", class: "unknown-status" },
  ]);
  assert.deepEqual(
    unknown.result.vanishedAfterCreate.map((v) => v.label),
    ["account"],
  );
  assert.equal(unknown.result.closureReady, false);
  assert.equal(unknown.result.readBackRequired, true);
  const refused = await go(
    {},
    (send) => async (request) =>
      path(request).endsWith("accounts:delete") ? error(500, "INTERNAL") : send(request),
  );
  assert.equal(refused.result.cleanup.readBack.account, false);
  assert.equal(refused.result.cleanup.verified, false);
  assert.equal(refused.result.outcome, "pcblock-needs-recovery");
});

test("a lookup that answers with a user, or fails, is not absence", async () => {
  for (const answer of [
    () => reply(200, { users: [{ localId: LOCAL_ID }] }),
    () => error(500, "INTERNAL"),
    () => reply(400, { error: { message: "USER_NOT_FOUND" } }),
  ]) {
    const { result } = await go(
      {},
      (send) => async (request) =>
        path(request).endsWith("accounts:lookup") ? answer() : send(request),
    );
    assert.equal(result.cleanup.readBack.account, false);
    assert.equal(result.cleanup.verified, false);
  }
});

// ---- the function, its images, the logs ---------------------------------------------------------------

test("a leftover function is deleted once through REST after a fresh list shows it, its operation read until done", async () => {
  const { result, world, journal } = await go({ leaveOnDelete: true });
  assert.equal(result.outcome, "pcblock-recorded");
  assert.equal(count(world, "DELETE cloudfunctions"), 1);
  assert.ok(ids(journal).includes("leftover-delete-function"));
  assert.equal(world.functions.size, 0);
});

test("a leftover function whose delete fails is not re-sent and the run needs recovery", async () => {
  const { result, world } = await go({
    leaveOnDelete: true,
    hooks: {
      ["DELETE cloudfunctions.googleapis.com/v2/" + functionName()]: () => error(500, "INTERNAL"),
    },
  });
  assert.equal(count(world, "DELETE cloudfunctions"), 1);
  assert.equal(result.outcome, "pcblock-needs-recovery");
  assert.equal(result.closureReady, false);
  assert.equal(result.cleanup.verified, false);
  assert.equal(result.unknownMutations, 1);
});

test("a leftover function whose operation never finishes is unknown with its reason", async () => {
  const stuck = await go(
    { leaveOnDelete: true },
    (send) => async (request) =>
      request.method === "GET" && path(request).includes("/operations/del-")
        ? reply(200, { name: path(request), done: false })
        : send(request),
  );
  assert.deepEqual(stuck.result.unknownMutationList, [
    { id: "leftover-delete-function", class: "operation-pending" },
  ]);
  assert.equal(ids(stuck.journal).filter((id) => id.startsWith("leftover-operation-")).length, 12);
  assert.equal(stuck.result.outcome, "pcblock-needs-review");
  const errored = await go(
    { leaveOnDelete: true },
    (send) => async (request) =>
      request.method === "GET" && path(request).includes("/operations/del-")
        ? reply(200, { name: path(request), done: true, error: { code: 13 } })
        : send(request),
  );
  assert.deepEqual(errored.result.unknownMutationList, [
    { id: "leftover-delete-function", class: "operation-error" },
  ]);
  const immediate = await go(
    { leaveOnDelete: true },
    (send) => async (request) =>
      request.method === "DELETE" && path(request).endsWith("/functions/pcblock")
        ? reply(200, { name: "x", done: true, error: { code: 13 } })
        : send(request),
  );
  assert.deepEqual(immediate.result.unknownMutationList, [
    { id: "leftover-delete-function", class: "operation-error" },
  ]);
  const done = await go(
    { leaveOnDelete: true },
    (send) => async (request) =>
      request.method === "DELETE" && path(request).endsWith("/functions/pcblock")
        ? (await send(request), reply(200, { name: "x", done: true }))
        : send(request),
  );
  assert.deepEqual(done.result.unknownMutationList, []);
  assert.equal(ids(done.journal).filter((id) => id.startsWith("leftover-operation")).length, 0);
});

test("an image delete that fails, or comes back unfinished, is handled and each image is deleted once", async () => {
  const id = packageIds()[0];
  const failed = await go({
    hooks: {
      [`DELETE artifactregistry.googleapis.com/v1/projects/fireemu-oracle-idp/locations/us-central1/repositories/gcf-artifacts/packages/${id}`]:
        () => error(500, "INTERNAL"),
    },
  });
  assert.equal(failed.result.outcome, "pcblock-needs-recovery");
  assert.equal(failed.result.cleanup.readBack["package-" + id], false);
  assert.equal(
    ids(failed.journal).filter((x) => x.startsWith("delete-package-")).length,
    2,
    "each image is deleted once, the failed one is not re-sent",
  );
  let polls = 0;
  const pending = await go({}, (send) => async (request) => {
    if (request.method === "DELETE" && path(request).endsWith(id)) {
      await send(request);
      return reply(200, {
        name: "projects/fireemu-oracle-idp/locations/us-central1/operations/pk-1",
        done: false,
      });
    }
    if (request.method === "GET" && path(request).endsWith("/operations/pk-1")) {
      polls++;
      return reply(200, { name: "x", done: false });
    }
    return send(request);
  });
  assert.equal(polls, 6);
  assert.equal(pending.result.outcome, "pcblock-recorded");
});

test("only this function's images are deleted", async () => {
  const world = createWorld({ runId: RUN });
  world.packages.add("other-package");
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    send: world.send,
    runCli: world.runCli,
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
  });
  assert.equal(result.cleanup.packagesDeleted.length, 2);
  assert.ok(world.packages.has("other-package"));
  assert.equal(result.cleanup.listsEmpty, true);
});

test("frames that never arrive are reported and do not block the close; the window is waited in full", async () => {
  const { result, sleeps } = await go({ silent: true });
  assert.equal(result.outcome, "pcblock-recorded");
  assert.equal(result.judged.cases["blocking-request"].status, "not-delivered");
  assert.equal(result.judged.complete, false);
  assert.deepEqual(sleeps, [60_000, 60_000, 60_000, 120_000]);
});

test("the observe loop takes one step when the window is shorter than a poll, and stops once both frames are in", async () => {
  const { journal } = await go({ silent: true }, (send) => send, {
    waits: { window: 3, logPoll: 60 },
  });
  assert.deepEqual(
    ids(journal).filter((id) => /^logs-observe-\d+-frames$/.test(id)),
    ["logs-observe-1-frames"],
  );
  const slow = await go({ silent: true }, (send) => send, { waits: { window: 13, logPoll: 5 } });
  assert.deepEqual(
    ids(slow.journal).filter((id) => /^logs-observe-\d+-frames$/.test(id)),
    ["logs-observe-1-frames", "logs-observe-2-frames", "logs-observe-3-frames"],
  );
  const quick = await go({}, (send) => send, { waits: { window: 13, logPoll: 5 } });
  assert.deepEqual(
    ids(quick.journal).filter((id) => /^logs-observe-\d+-frames$/.test(id)),
    ["logs-observe-1-frames"],
  );
});

test("an ERROR entry and log noise are counted, a log read that fails is incomplete, and a 403 on a log read is data", async () => {
  const world = createWorld({ runId: RUN });
  const origin = {
    logName: "projects/p/logs/run.googleapis.com%2Fstderr",
    resource: {
      type: "cloud_run_revision",
      labels: { service_name: "pcblock", location: "us-central1" },
    },
  };
  const at = new Date(world.now + 1000).toISOString();
  world.entries.push({
    insertId: "junk",
    timestamp: at,
    ...origin,
    textPayload: "PYBLOCK_FRAME {bad",
  });
  world.entries.push({
    insertId: "err",
    timestamp: at,
    severity: "ERROR",
    ...origin,
    textPayload: "Traceback",
  });
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    send: world.send,
    runCli: world.runCli,
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
  });
  assert.equal(result.errorsSeen, 1);
  assert.equal(result.judged.errors.length, 1);
  assert.ok(result.framesIgnored.unparsed >= 1);
  const forbidden = await go(
    {},
    (send) => async (request) =>
      request.url.includes("entries:list") ? error(403, "PERMISSION_DENIED") : send(request),
  );
  assert.notEqual(forbidden.result.outcome, "pcblock-auth-stop");
  assert.ok(
    forbidden.result.incompleteReads.some((r) => r.id.startsWith("logs-") && r.class === "4xx"),
  );
  assert.equal(forbidden.result.closureReady, false);
});

// ---- stops --------------------------------------------------------------------------------------------

test("a 401 on a request of the owner's credential stops the run where it is: the CLI delete runs and no further request is sent", async () => {
  let after = 0;
  let stopped = false;
  const { result, world } = await go({}, (send, w) => async (request) => {
    if (stopped) after++;
    if (!stopped && w.cliRuns.includes("deploy") && request.url.includes("/config")) {
      stopped = true;
      return error(401, "UNAUTHENTICATED");
    }
    return send(request);
  });
  assert.equal(result.outcome, "pcblock-auth-stop");
  assert.equal(result.closureReady, false);
  assert.equal(result.readBackRequired, true);
  assert.equal(after, 0);
  assert.deepEqual(world.cliRuns, ["dry-run", "deploy", "delete"]);
});

test("a 401 before anything exists does not run the CLI delete; a 403 on a write stops, a 403 on an observing read does not", async () => {
  const early = await go(
    {},
    (send) => async (request) =>
      request.url.includes("serviceusage") ? error(401, "UNAUTHENTICATED") : send(request),
  );
  assert.equal(early.result.outcome, "pcblock-auth-stop");
  assert.deepEqual(early.world.cliRuns, []);
  const write = await go(
    {},
    (send) => async (request) =>
      path(request).endsWith("accounts:delete") ? error(403, "PERMISSION_DENIED") : send(request),
  );
  assert.equal(write.result.outcome, "pcblock-auth-stop");
});

test("a 401 during the cleanup is the last request, and the CLI delete is not run twice", async () => {
  let fired = false;
  let after = 0;
  const { result, world } = await go({}, (send) => async (request) => {
    if (fired) after++;
    if (!fired && path(request).endsWith("accounts:delete")) {
      fired = true;
      return error(401, "UNAUTHENTICATED");
    }
    return send(request);
  });
  assert.equal(result.outcome, "pcblock-auth-stop");
  assert.equal(after, 0);
  assert.equal(world.cliRuns.filter((a) => a === "delete").length, 1);
});

test("a stop signal ends the work at the next request and the cleanup still runs", async () => {
  const signal = { aborted: false };
  const { result, world } = await go(
    {},
    (send) => async (request) => {
      if (path(request) === "/v1/accounts:signUp") signal.aborted = true;
      return send(request);
    },
    { signal },
  );
  assert.equal(result.outcome, "pcblock-incomplete-clean");
  assert.equal(result.cleanup.verified, true);
  assert.equal(world.accounts.size, 3);
  assert.equal(world.functions.size, 0);
  const early = await go({}, (send) => send, { signal: { aborted: true } });
  assert.equal(early.result.outcome, "pcblock-stopped-clean");
  assert.equal(early.world.calls.length, 0);
});

test("the normal request ceiling is exact and leaves room for the cleanup", async () => {
  for (const ceiling of [20, 21]) {
    const { journal, result } = await go({}, (send) => send, { normalCeiling: ceiling });
    assert.equal(
      ids(journal).findIndex(
        (id) =>
          id.startsWith("cleanup-") ||
          id === "delete-package-fireemu--oracle--idp__us--central1__pcblock",
      ),
      ceiling >= 1
        ? ids(journal).findIndex(
            (id) => id.startsWith("cleanup-") || id.startsWith("delete-package"),
          )
        : -1,
    );
    assert.ok(result.attempted <= MAX_REQUESTS);
    assert.equal(result.cleanup.verified, true);
  }
  const early = await go({}, (send) => send, { normalCeiling: 5 });
  assert.equal(early.result.outcome, "pcblock-stopped-clean");
  assert.match(early.result.stoppedBecause, /ceiling/);
});

test("an error before anything exists is thrown; after something exists it is recorded and cleaned up", async () => {
  const world = createWorld({ runId: RUN });
  await assert.rejects(
    record({
      runId: RUN,
      projectNumber: NUMBER,
      accessToken: "tok-abcdefgh",
      save: async () => {
        throw new Error("no disk");
      },
      send: world.send,
      runCli: world.runCli,
      clock: () => world.now,
      sleep: async () => {},
    }),
    /private persistence failed/,
  );
  const after = createWorld({ runId: RUN });
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    send: after.send,
    runCli: after.runCli,
    clock: () => after.now,
    sleep: async (ms) => after.advance(ms),
    save: async (row) => {
      if (row.id === "readback-function" && row.state === "before-send")
        throw new Error("disk went away");
    },
  });
  assert.match(result.stoppedBecause, /persistence failed/);
  assert.deepEqual(after.cliRuns, ["dry-run", "deploy", "delete"]);
  assert.equal(result.cleanup.verified, true);
  assert.equal(result.outcome, "pcblock-incomplete-clean");
});

test("a cleanup step that fails is recorded with its name and the others still run", async () => {
  for (const [id, step] of [
    ["cleanup-account-delete", "account-delete"],
    ["readback-gone-account", "readback-account"],
    ["config-after", "config-after"],
    ["accounts-after", "accounts-after"],
    ["final-functions-v2", "final-lists"],
  ]) {
    const world = createWorld({ runId: RUN });
    const result = await record({
      runId: RUN,
      projectNumber: NUMBER,
      accessToken: "tok-abcdefgh",
      send: world.send,
      runCli: world.runCli,
      clock: () => world.now,
      sleep: async (ms) => world.advance(ms),
      save: async (row) => {
        if (row.id === id && row.state === "before-send") throw new Error("disk full");
      },
    });
    assert.deepEqual(
      result.cleanup.errors.map((e) => e.step),
      [step],
      id,
    );
    assert.equal(result.cleanup.verified, false, id);
    assert.equal(result.closureReady, false, id);
  }
});

// ---- every write crossed with every kind of answer ------------------------------------------------------------

const WRITES = [
  ["sign up", (r) => path(r) === "/v1/accounts:signUp", "op-sign-up"],
  ["delete the account", (r) => path(r).endsWith("accounts:delete"), "cleanup-account-delete"],
  [
    "delete an image",
    (r) => r.method === "DELETE" && path(r).endsWith(packageIds()[0]),
    "delete-package-" + packageIds()[0],
  ],
];
const ANSWERS = [
  ["transport error", true, () => "throw"],
  ["500", true, () => error(500, "INTERNAL")],
  ["503", true, () => error(503, "UNAVAILABLE")],
  ["302", true, () => new Response(null, { status: 302 })],
  ["429", false, () => error(429, "RESOURCE_EXHAUSTED")],
  ["400", false, () => error(400, "INVALID_ARGUMENT")],
];
for (const [what, match, id] of WRITES)
  for (const [label, unknown, answer] of ANSWERS)
    test(`${what} answered with ${label} is ${unknown ? "never re-sent and keeps the run open" : "a known refusal"}`, async () => {
      let hit = 0;
      const { result, world, journal } = await go({}, (send) => async (request) => {
        if (match(request)) {
          hit++;
          const out = answer();
          if (out === "throw") throw new Error("transport");
          return out;
        }
        return send(request);
      });
      assert.equal(hit, 1);
      assert.equal(ids(journal).filter((x) => x === id).length, 1);
      if (unknown) {
        assert.equal(result.closureReady, false);
        assert.equal(result.readBackRequired, true);
        assert.ok(
          result.unknownMutationList.some((u) => u.id === id),
          JSON.stringify(result.unknownMutationList),
        );
      } else assert.ok(!result.unknownMutationList.some((u) => u.id === id));
      assert.deepEqual(world.cliRuns, ["dry-run", "deploy", "delete"]);
      assert.equal(result.stage, "done");
    });

// ---- small functions -------------------------------------------------------------------------------------

test("absent accepts only a readable 404 NOT_FOUND, in the Google or the Storage layout", () => {
  assert.equal(absent({ status: 404, json: { error: { status: "NOT_FOUND" } } }), true);
  assert.equal(
    absent({ status: 404, json: { error: { code: 404, errors: [{ reason: "notFound" }] } } }),
    true,
  );
  assert.equal(absent({ status: 404, json: { error: { code: 404 } } }), false);
  assert.equal(
    absent({
      status: 404,
      json: { error: { status: "PERMISSION_DENIED", errors: [{ reason: "notFound" }] } },
    }),
    false,
  );
  assert.equal(absent({ status: 404, json: null }), false);
  assert.equal(absent({ status: 403, json: { error: { status: "NOT_FOUND" } } }), false);
  assert.equal(absent(null), false);
});

test("iamPolicyOf keeps the whole policy without its etag and version, and is null when the read is not a policy it can compare", () => {
  const policy = {
    version: 3,
    etag: "e",
    bindings: [{ role: "r", members: ["u"], condition: { title: "t" } }],
    auditConfigs: [{ service: "allServices" }],
  };
  assert.deepEqual(iamPolicyOf({ status: 200, json: policy }), {
    bindings: policy.bindings,
    auditConfigs: policy.auditConfigs,
  });
  assert.deepEqual(iamPolicyOf({ status: 200, json: {} }), {});
  assert.equal(iamPolicyOf({ status: 403, json: {} }), null);
  assert.equal(iamPolicyOf(null), null);
  assert.equal(iamPolicyOf({ status: 200, json: { bindings: "x" } }), null);
});

test("configDifference names the top-level keys that differ, in order, and is null when a read failed", () => {
  const a = (json) => ({ status: 200, json });
  assert.deepEqual(configDifference(a({ x: 1, y: { z: 1 } }), a({ x: 1, y: { z: 1 } })), []);
  assert.deepEqual(configDifference(a({ x: 1, y: 1, w: 1 }), a({ x: 2, y: 1, v: 1 })), [
    "v",
    "w",
    "x",
  ]);
  assert.deepEqual(configDifference(a({ x: { a: 1 } }), a({ x: { a: 2 } })), ["x"]);
  assert.equal(configDifference(a({}), { status: 500, json: {} }), null);
  assert.equal(configDifference({ status: 500, json: {} }, a({})), null);
  assert.equal(configDifference(null, a({})), null);
  assert.equal(CONFIG_URL.endsWith("/config"), true);
});

test("emptyBlocking accepts no section, an empty one, an empty triggers map, and forwarding that forwards nothing, and nothing else", () => {
  for (const ok of [
    {},
    { blockingFunctions: {} },
    { blockingFunctions: { triggers: {} } },
    { blockingFunctions: { forwardInboundCredentials: {} } },
    { blockingFunctions: { triggers: {}, forwardInboundCredentials: {} } },
    { blockingFunctions: { forwardInboundCredentials: { idToken: false } } },
    {
      blockingFunctions: {
        forwardInboundCredentials: { idToken: false, accessToken: false, refreshToken: false },
      },
    },
  ])
    assert.equal(emptyBlocking(ok), true, JSON.stringify(ok));
  for (const bad of [
    { blockingFunctions: { triggers: { beforeCreate: {} } } },
    { blockingFunctions: { forwardInboundCredentials: { idToken: true } } },
    { blockingFunctions: { forwardInboundCredentials: { idToken: false, refreshToken: true } } },
    { blockingFunctions: { forwardInboundCredentials: { idToken: 0 } } },
    { blockingFunctions: { forwardInboundCredentials: null } },
    { blockingFunctions: { forwardInboundCredentials: [] } },
    { blockingFunctions: { forwardInboundCredentials: "x" } },
    { blockingFunctions: { triggers: [] } },
    { blockingFunctions: { triggers: null } },
    { blockingFunctions: { triggers: {}, other: 1 } },
    { blockingFunctions: { other: 1 } },
    { blockingFunctions: null },
    { blockingFunctions: [] },
    { blockingFunctions: "x" },
  ])
    assert.equal(emptyBlocking(bad), false, JSON.stringify(bad));
  assert.equal(emptyBlocking(null), true, "no config object has no section");
});

test("configDigest depends on the whole body", () => {
  assert.match(configDigest({ a: 1 }), /^[0-9a-f]{64}$/);
  assert.notEqual(configDigest({ a: 1 }), configDigest({ a: 2 }));
  assert.equal(configDigest({ a: 1 }), configDigest({ a: 1 }));
  assert.equal(FUNCTION, "pcblock");
});
