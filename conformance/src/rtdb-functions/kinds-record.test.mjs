import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { admitRun, executeRun, recordBreadth, requiredBreadthSources } from "./breadth-record.mjs";
import { createBreadthBudget } from "./breadth-wiring.mjs";
import { KINDS_PINS, KINDS_SCENARIO } from "./kinds-scenario.mjs";
import { makeWorld } from "./kinds-world.fake.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");

test("the pinned sources are the files in the tree", async () => {
  for (const [file, expected] of Object.entries(KINDS_PINS))
    assert.equal(sha(await readFile(join(here, file))), expected, `${file} changed: re-pin it`);
  assert.deepEqual(Object.keys(KINDS_PINS), [
    "firebase-kinds.json",
    "fixtures-kinds/index.js",
    "fixtures-kinds/frames.js",
    "fixtures-kinds/package.json",
    "fixtures-kinds/package-lock.json",
  ]);
});

async function stage({ drift } = {}) {
  const dir = await mkdtemp(join(tmpdir(), "kinds-stage-"));
  const stageDir = join(dir, "a", "b");
  await mkdir(join(stageDir, "fixtures-kinds"), { recursive: true });
  for (const file of Object.keys(KINDS_PINS))
    await writeFile(join(stageDir, file), await readFile(join(here, file)));
  if (drift) await writeFile(join(stageDir, drift), "changed");
  const modules = (name, version) =>
    mkdir(join(stageDir, "fixtures-kinds/node_modules", name), { recursive: true }).then(() =>
      writeFile(
        join(stageDir, "fixtures-kinds/node_modules", name, "package.json"),
        JSON.stringify({ name, version }),
      ),
    );
  await modules("firebase-functions", "7.3.2");
  await modules("firebase-admin", "14.3.0");
  await mkdir(join(dir, "node_modules/firebase-tools"), { recursive: true });
  await writeFile(
    join(dir, "node_modules/firebase-tools/package.json"),
    JSON.stringify({ version: "15.28.2" }),
  );
  return { dir, stageDir };
}

test("source admission accepts the pinned sources and installed dependencies", async () => {
  const { dir, stageDir } = await stage();
  try {
    await requiredBreadthSources({ pins: KINDS_PINS, fixtureDir: "fixtures-kinds", stageDir });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

for (const file of Object.keys(KINDS_PINS)) {
  test(`source admission refuses a changed ${file}`, async () => {
    const { dir, stageDir } = await stage({ drift: file });
    try {
      await assert.rejects(
        requiredBreadthSources({ pins: KINDS_PINS, fixtureDir: "fixtures-kinds", stageDir }),
        new RegExp(`reviewed source changed: ${file.replace(".", "\\.")}`),
      );
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
}

test("source admission refuses a wrong installed dependency version", async () => {
  const { dir, stageDir } = await stage();
  try {
    await writeFile(
      join(stageDir, "fixtures-kinds/node_modules/firebase-functions/package.json"),
      JSON.stringify({ name: "firebase-functions", version: "7.3.1" }),
    );
    await assert.rejects(
      requiredBreadthSources({ pins: KINDS_PINS, fixtureDir: "fixtures-kinds", stageDir }),
      /fixture dependency firebase-functions 7\.3\.2 is required/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("admission checks the kinds fixture directory for files git does not track", async () => {
  const gitSha = "c".repeat(40);
  const packet = Buffer.from(
    `\`\`\`json cv14-pins\n${JSON.stringify({ baselineRulesSha256: "a".repeat(64) })}\n\`\`\`\n`,
  );
  const approval = `Decision: APPROVE\ngitSha: ${gitSha}\npacketSha256: ${sha(packet)}\n`;
  const run = async (ignoredLine) => {
    const seen = [];
    const deps = {
      git: async (args) => {
        seen.push(args);
        if (args[0] === "rev-parse") return gitSha;
        return args.includes("--ignored") ? ignoredLine : "";
      },
      readFile: async (path) => (path.endsWith("review") ? approval : packet),
      requiredSources: async () => {},
      readPrivateProjectIdentity: async () => "123456789012",
      adcVerdict: async () => ({ ok: true }),
    };
    const env = { FIREEMU_CV14_REVIEW: "/private/review", FIREEMU_CV14_PACKET: "/private/packet" };
    const outcome = await admitRun({
      env,
      privateRoot: "/private",
      root: "/repo",
      deps,
      fixtureDir: "fixtures-kinds",
    }).then(
      () => "admitted",
      (error) => error.message,
    );
    return { outcome, seen };
  };
  const ok = await run("!! conformance/src/rtdb-functions/fixtures-kinds/node_modules/\n");
  assert.equal(ok.outcome, "admitted");
  assert.ok(ok.seen.some((args) => args.includes("conformance/src/rtdb-functions/fixtures-kinds")));
  assert.ok(
    !ok.seen.some((args) => args.includes("conformance/src/rtdb-functions/fixtures-breadth")),
  );
  // an ignored file elsewhere in the directory, or the breadth node_modules entry, is refused
  for (const line of [
    "!! conformance/src/rtdb-functions/fixtures-kinds/.env\n",
    "!! conformance/src/rtdb-functions/fixtures-breadth/node_modules/\n",
  ])
    assert.match((await run(line)).outcome, /fixture directory holds files git does not track/);
});

test("the kinds entry plugs the scenario into the budget, CLI, user, SDK and run directory", async () => {
  const listeners = new Map();
  const seen = {};
  const fakeProcess = {
    argv: ["node", "unused", "--key-file", "/fake/key"],
    env: {},
    on: (signal, cb) => listeners.set(signal, cb),
    off: (signal) => listeners.delete(signal),
  };
  const deps = {
    process: fakeProcess,
    isAbsolute,
    fileURLToPath,
    join,
    STAGE_DIR: "/fake/stage",
    PRIVATE_ROOT: "/fake/private",
    PROJECT: "demo",
    ownerAdc: async () => ({ file: {}, path: "/fake/adc" }),
    createBreadthBudget: (scenario) => (
      (seen.budgetScenario = scenario),
      createBreadthBudget(scenario)
    ),
    createTokenProvider: () => async () => "fake-access",
    adcPreflight: async () => ({ ok: true }),
    fetch: async () => ({}),
    tokenProviderWithSecrets: () => ({ getToken: async () => "fake-access", secrets: [] }),
    admitRun: async ({ deps: inner, fixtureDir }) => {
      seen.fixtureDir = fixtureDir;
      await inner.requiredSources();
      const projectNumber = await inner.readPrivateProjectIdentity();
      await inner.adcVerdict();
      return { packetPins: {}, projectNumber };
    },
    requiredBreadthSources: async (options) => (seen.sources = options),
    readFile: async () => "fake-key",
    parseKeyFile: (x) => x,
    readPrivateProjectIdentity: async () => "123456789012",
    PROJECT_IDENTITY_FILE: "/fake/identity",
    PROJECT_IDENTITY_SHA: "sha",
    mkdir: async (dir) => (seen.runDir = dir),
    randomBytes: () => Buffer.from("nonce"),
    createControl: () => ({}),
    BREADTH_HOSTS: [],
    breadthCli: (run, scenario) => ((seen.cliScenario = scenario), run),
    createAuth: (options) => ((seen.claims = options.claims), { signIn: async () => ({}) }),
    executeRun: async ({ environment }) => {
      seen.environmentScenario = environment.scenario;
      environment.createAuth(() => {});
      environment.createSdk({ uid: "u" });
      return { outcome: "recorded", residual: false };
    },
    openSdk: (runner) => runner,
    browserRunner: (options) => ((seen.browser = options), options),
    INSTANCE: "fireemu-q-rtdb2",
    exitCodeOf: () => 0,
    console: { log() {} },
    readdir: async () => [],
    rm: async () => {},
  };
  const source = recordBreadth
    .toString()
    .replaceAll("import.meta.url", JSON.stringify(import.meta.url));
  const entry = new Function(...Object.keys(deps), "scenario", `return (${source})(scenario);`);
  await entry(...Object.values(deps), KINDS_SCENARIO);
  assert.equal(seen.budgetScenario, KINDS_SCENARIO);
  assert.equal(seen.cliScenario, KINDS_SCENARIO);
  assert.equal(seen.environmentScenario, KINDS_SCENARIO);
  assert.equal(seen.fixtureDir, "fixtures-kinds");
  assert.deepEqual(seen.sources, { pins: KINDS_PINS, fixtureDir: "fixtures-kinds" });
  assert.match(seen.runDir, /^\/fake\/private\/runs\/kinds-/u);
  assert.deepEqual(seen.claims, { k9role: "claims", k9n: 3 });
  assert.equal(seen.browser.pageFile, KINDS_SCENARIO.sdk.pageFile);
  assert.deepEqual(seen.browser.ids, ["k18", "k19", "k20", "k21"]);
  assert.deepEqual(seen.browser.caps, { http: 80, ws: 4 });
  assert.equal(listeners.size, 0);
});

test("a kinds run through the real executeRun writes the private output and cleans up", async () => {
  const dir = await mkdtemp(join(tmpdir(), "kinds-result-"));
  const world = makeWorld({ frames: "all" });
  try {
    const summary = await executeRun({
      environment: {
        projectId: "demo",
        projectNumber: "123456789012",
        nonce: "fake",
        budget: { snapshot: () => ({ cliDeploy: 8 }) },
      },
      runDir: dir,
      packetPins: {},
      assemble: ({ log, runDir }) => ({
        deps: { ...world.deps, log, runDir, nonce: "fake" },
        uploads: { close() {} },
        forms: { summary: () => ({}), maskedLines: () => [] },
        grants: {},
        readGrantsAfter: async () => ({ iam: { removed: [] } }),
      }),
    });
    assert.equal(summary.outcome, "recorded");
    assert.equal(summary.residual, false);
    assert.equal(summary.estimatedUsd, 4.41);
    const result = JSON.parse(await readFile(join(dir, "result.json")));
    assert.deepEqual(result.reasons, []);
    assert.equal(result.deployed, 8);
    assert.equal(Object.keys(result.cleanup.targets).length, 8);
    const frames = (await readFile(join(dir, "frames.jsonl"), "utf8")).trim().split("\n");
    assert.ok(frames.length > 100);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("source admission without a scenario checks the breadth pins and fixture directory", async () => {
  const dir = await mkdtemp(join(tmpdir(), "breadth-stage-"));
  try {
    const stageDir = join(dir, "a", "b");
    const breadthFiles = [
      "firebase-breadth.json",
      "fixtures-breadth/index.js",
      "fixtures-breadth/frames.js",
      "fixtures-breadth/package.json",
      "fixtures-breadth/package-lock.json",
    ];
    await mkdir(join(stageDir, "fixtures-breadth"), { recursive: true });
    for (const file of breadthFiles)
      await writeFile(join(stageDir, file), await readFile(join(here, file)));
    for (const [name, version] of [
      ["firebase-functions", "7.3.2"],
      ["firebase-admin", "14.3.0"],
    ]) {
      await mkdir(join(stageDir, "fixtures-breadth/node_modules", name), { recursive: true });
      await writeFile(
        join(stageDir, "fixtures-breadth/node_modules", name, "package.json"),
        JSON.stringify({ name, version }),
      );
    }
    await mkdir(join(dir, "node_modules/firebase-tools"), { recursive: true });
    await writeFile(
      join(dir, "node_modules/firebase-tools/package.json"),
      JSON.stringify({ version: "15.28.2" }),
    );
    await requiredBreadthSources({ stageDir });
    // the kinds pins are not the breadth ones: the breadth stage fails them
    await assert.rejects(
      requiredBreadthSources({ stageDir, pins: KINDS_PINS, fixtureDir: "fixtures-kinds" }),
      /ENOENT|reviewed source changed/,
    );
    await writeFile(join(stageDir, "fixtures-breadth/index.js"), "changed");
    await assert.rejects(
      requiredBreadthSources({ stageDir }),
      /reviewed source changed: fixtures-breadth\/index\.js/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("admission without a fixture directory looks at the breadth one", async () => {
  const gitSha = "d".repeat(40);
  const packet = Buffer.from(
    `\`\`\`json cv14-pins\n${JSON.stringify({ baselineRulesSha256: "a".repeat(64) })}\n\`\`\`\n`,
  );
  const approval = `Decision: APPROVE\ngitSha: ${gitSha}\npacketSha256: ${sha(packet)}\n`;
  const seen = [];
  const deps = {
    git: async (args) => {
      seen.push(args);
      if (args[0] === "rev-parse") return gitSha;
      return args.includes("--ignored")
        ? "!! conformance/src/rtdb-functions/fixtures-breadth/node_modules/\n"
        : "";
    },
    readFile: async (path) => (path.endsWith("review") ? approval : packet),
    requiredSources: async () => {},
    readPrivateProjectIdentity: async () => "123456789012",
    adcVerdict: async () => ({ ok: true }),
  };
  const env = { FIREEMU_CV14_REVIEW: "/private/review", FIREEMU_CV14_PACKET: "/private/packet" };
  await admitRun({ env, privateRoot: "/private", root: "/repo", deps });
  assert.ok(seen.some((args) => args.includes("conformance/src/rtdb-functions/fixtures-breadth")));
  assert.ok(!seen.some((args) => args.includes("conformance/src/rtdb-functions/fixtures-kinds")));
});

test("the entry takes the browser WebSocket cap from the scenario's limits", async () => {
  const listeners = new Map();
  let browser;
  const deps = {
    process: {
      argv: ["node", "unused", "--key-file", "/fake/key"],
      env: {},
      on: (signal, cb) => listeners.set(signal, cb),
      off: (signal) => listeners.delete(signal),
    },
    isAbsolute,
    fileURLToPath,
    join,
    STAGE_DIR: "/fake/stage",
    PRIVATE_ROOT: "/fake/private",
    PROJECT: "demo",
    ownerAdc: async () => ({ file: {}, path: "/fake/adc" }),
    createBreadthBudget,
    createTokenProvider: () => async () => "fake-access",
    adcPreflight: async () => ({ ok: true }),
    fetch: async () => ({}),
    tokenProviderWithSecrets: () => ({ getToken: async () => "fake-access", secrets: [] }),
    admitRun: async ({ deps: inner }) => {
      await inner.requiredSources();
      await inner.adcVerdict();
      return { packetPins: {}, projectNumber: "123456789012" };
    },
    requiredBreadthSources: async () => {},
    readFile: async () => "fake-key",
    parseKeyFile: (x) => x,
    readPrivateProjectIdentity: async () => "123456789012",
    PROJECT_IDENTITY_FILE: "/fake/identity",
    PROJECT_IDENTITY_SHA: "sha",
    mkdir: async () => {},
    randomBytes: () => Buffer.from("nonce"),
    createControl: () => ({}),
    BREADTH_HOSTS: [],
    breadthCli: (run) => run,
    createAuth: () => ({ signIn: async () => ({}) }),
    executeRun: async ({ environment }) => {
      environment.createSdk({ uid: "u" });
      return { outcome: "recorded", residual: false };
    },
    openSdk: (runner) => runner,
    browserRunner: (options) => (browser = options),
    INSTANCE: "fireemu-q-rtdb2",
    exitCodeOf: () => 0,
    console: { log() {} },
    readdir: async () => [],
    rm: async () => {},
  };
  const source = recordBreadth
    .toString()
    .replaceAll("import.meta.url", JSON.stringify(import.meta.url));
  const entry = new Function(...Object.keys(deps), "scenario", `return (${source})(scenario);`);
  const limits = { ...KINDS_SCENARIO.limits, browserWs: 7, browserHttp: 90 };
  await entry(...Object.values(deps), { ...KINDS_SCENARIO, limits });
  assert.deepEqual(browser.caps, { http: 90, ws: 7 });
  // and the breadth entry passes no caps at all, so the runner keeps its own defaults
  await entry(...Object.values(deps), undefined);
  assert.equal(browser.caps, undefined);
  assert.equal(browser.pageFile, undefined);
  assert.equal(browser.ids, undefined);
});
