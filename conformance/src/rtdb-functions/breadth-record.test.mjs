import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { admitRun } from "./breadth-record.mjs";

const gitSha = "b".repeat(40);
const rulesSha = "a".repeat(64);
const packet = Buffer.from(
  `\`\`\`json cv14-pins\n${JSON.stringify({ baselineRulesSha256: rulesSha })}\n\`\`\`\n`,
);
const digest = (value) => createHash("sha256").update(value).digest("hex");

for (const failure of [
  "paths",
  "tree",
  "ignored",
  "approval",
  "digest",
  "pins",
  "sources",
  "identity",
]) {
  test(`admission refuses ${failure} without a request`, async () => {
    let requests = 0;
    const fetchStub = () => {
      requests++;
      throw Error("unexpected request");
    };
    const content = failure === "pins" ? Buffer.from("no pins") : packet;
    const approval = `Decision: ${failure === "approval" ? "REJECT" : "APPROVE"}\ngitSha: ${gitSha}\npacketSha256: ${failure === "digest" ? rulesSha : digest(content)}\n`;
    const deps = {
      git: async (args) =>
        args[0] === "rev-parse"
          ? gitSha
          : failure === "tree"
            ? " M file"
            : failure === "ignored" && args.includes("--ignored")
              ? "!! fixture"
              : "",
      readFile: async (path) => (path.endsWith("review") ? approval : content),
      requiredSources: async () => {
        if (failure === "sources") throw Error("source mismatch");
      },
      readPrivateProjectIdentity: async () => {
        if (failure === "identity") throw Error("identity mismatch");
        return "123456789012";
      },
      adcVerdict: async () => fetchStub(),
    };
    const env = {
      FIREEMU_CV14_REVIEW: failure === "paths" ? "" : "/private/review",
      FIREEMU_CV14_PACKET: "/private/packet",
    };
    await assert.rejects(() => admitRun({ env, privateRoot: "/private", root: "/repo", deps }));
    assert.equal(requests, 0);
  });
}

test("admission refuses an invalid ADC verdict", async () => {
  const deps = {
    git: async (args) => (args[0] === "rev-parse" ? gitSha : ""),
    readFile: async (path) =>
      path.endsWith("review")
        ? `Decision: APPROVE\ngitSha: ${gitSha}\npacketSha256: ${digest(packet)}\n`
        : packet,
    requiredSources: async () => {},
    readPrivateProjectIdentity: async () => "123456789012",
    adcVerdict: async () => ({ ok: false, reason: "invalid" }),
  };
  await assert.rejects(
    () =>
      admitRun({
        env: { FIREEMU_CV14_REVIEW: "/private/review", FIREEMU_CV14_PACKET: "/private/packet" },
        privateRoot: "/private",
        root: "/repo",
        deps,
      }),
    /ADC token is not usable/,
  );
});

test("journal redacts current secrets from every row", async () => {
  const { mkdtemp, readFile, rm } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { executeRun } = await import("./breadth-record.mjs");
  const { makeWorld } = await import("./breadth-flow.fake.mjs");
  const dir = await mkdtemp(join(tmpdir(), "breadth-test-"));
  const secrets = ["sentinel-key", "sentinel-password", "sentinel-token"];
  try {
    const world = makeWorld({ preflightFails: true });
    await executeRun({
      environment: {
        projectId: "project",
        projectNumber: "12345",
        secrets,
        budget: { snapshot: () => ({ cliDeploy: 0, total: 42 }) },
      },
      runDir: dir,
      packetPins: { baselineRulesSha256: rulesSha },
      assemble: ({ log }) => ({
        deps: {
          ...world.deps,
          log: async (action, detail) => log(action, `${detail} ${secrets.join(" ")}`),
        },
        uploads: { close() {} },
        forms: { summary: () => ({}), maskedLines: () => [] },
        grants: {},
      }),
    });
    const journal = await readFile(join(dir, "journal.jsonl"), "utf8");
    for (const secret of secrets) assert.ok(!journal.includes(secret));
    assert.match(journal, /\*\*\*/);
    assert.equal(JSON.parse(journal.trim().split("\n").at(-1)).detail.total, 42);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("admission completes offline identity checks before counted token refresh and tokeninfo", async () => {
  const { createBreadthBudget } = await import("./breadth-wiring.mjs");
  const { createTokenProvider } = await import("./breadth-record.mjs");
  const events = [];
  const budget = createBreadthBudget();
  const getToken = createTokenProvider({}, budget, {
    acquire: async (_adc, budget, kind) => {
      events.push("refresh");
      budget.take(kind);
      return { value: "fake-access", expiresAt: Infinity };
    },
  });
  const result = await admitRun({
    env: { FIREEMU_CV14_REVIEW: "/private/review", FIREEMU_CV14_PACKET: "/private/packet" },
    privateRoot: "/private",
    root: "/repo",
    deps: {
      git: async (args) => (args[0] === "rev-parse" ? gitSha : ""),
      readFile: async (path) =>
        path.endsWith("review")
          ? `Decision: APPROVE\ngitSha: ${gitSha}\npacketSha256: ${digest(packet)}\n`
          : packet,
      requiredSources: async () => events.push("sources"),
      readPrivateProjectIdentity: async () => {
        events.push("identity");
        return "123456789012";
      },
      adcVerdict: async () => {
        await getToken();
        budget.take("control");
        events.push("tokeninfo");
        return { ok: true };
      },
    },
  });
  assert.equal(result.projectNumber, "123456789012");
  assert.deepEqual(events, ["sources", "identity", "refresh", "tokeninfo"]);
  assert.equal(budget.snapshot().total, 2);
  assert.equal(budget.snapshot().token, 1);
  assert.equal(budget.snapshot().control, 1);
});

test("entry signals close the active browser and all exits remove CLI debug logs", async () => {
  const { recordBreadth } = await import("./breadth-record.mjs");
  const { fileURLToPath } = await import("node:url");
  const { join, isAbsolute } = await import("node:path");
  const { createBreadthBudget } = await import("./breadth-wiring.mjs");
  for (const failure of [false, true]) {
    const listeners = new Map(),
      removed = [],
      events = [];
    let browserClosed = false;
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
      createBreadthBudget,
      createTokenProvider: (_adc, budget) => async () => {
        events.push("refresh");
        budget.take("token");
        return "fake-access";
      },
      adcPreflight: async (fetchImpl) => {
        events.push("tokeninfo");
        await fetchImpl("https://fake.test");
        return { ok: true };
      },
      fetch: async () => ({}),
      tokenProviderWithSecrets: () => ({ getToken: async () => "fake-access", secrets: [] }),
      admitRun: async ({ deps }) => {
        await deps.requiredSources();
        if (failure) throw SyntaxError("PRIVATE_SENTINEL");
        const projectNumber = await deps.readPrivateProjectIdentity();
        await deps.adcVerdict();
        return { packetPins: {}, projectNumber };
      },
      requiredBreadthSources: async () => events.push("sources"),
      readFile: async () => {
        events.push("key");
        return "fake-key";
      },
      parseKeyFile: (x) => x,
      readPrivateProjectIdentity: async () => {
        events.push("identity");
        return "123456789012";
      },
      PROJECT_IDENTITY_FILE: "/fake/identity",
      PROJECT_IDENTITY_SHA: "sha",
      mkdir: async () => {},
      randomBytes: () => Buffer.from("nonce"),
      createControl: () => ({}),
      BREADTH_HOSTS: [],
      breadthCli: (x) => x,
      executeRun: async ({ environment }) => {
        assert.deepEqual(events, ["sources", "key", "identity", "refresh", "tokeninfo"]);
        assert.equal(environment.budget.snapshot().total, 2);
        environment.stop.closeBrowser = () => {
          browserClosed = true;
        };
        listeners.get("SIGTERM")();
        assert.equal(environment.stop.requested, true);
        assert.equal(environment.abort.stopped, true);
        assert.equal(browserClosed, true);
        const host = environment.createSdk({}).allowHost;
        assert.equal(host("s-gke-usc1-nssi2-1.firebaseio.com"), true);
        assert.equal(host("evil.test"), false);
        return { outcome: "recorded", residual: false };
      },
      openSdk: (runner) => runner,
      browserRunner: (opts) => opts,
      INSTANCE: "fireemu-q-rtdb2",
      exitCodeOf: () => 0,
      console: { log() {} },
      readdir: async () => ["firebase-debug.log", "firebase-debug.1.log", "unrelated.log"],
      rm: async (file) => removed.push(file),
    };
    const source = recordBreadth
      .toString()
      .replaceAll("import.meta.url", JSON.stringify(import.meta.url));
    const entry = new Function(...Object.keys(deps), `return (${source})();`);
    if (failure) await assert.rejects(entry(...Object.values(deps)), /PRIVATE_SENTINEL/);
    else await entry(...Object.values(deps));
    assert.deepEqual(removed.sort(), [
      "/fake/stage/firebase-debug.1.log",
      "/fake/stage/firebase-debug.log",
    ]);
    assert.equal(listeners.size, 0);
  }
});

test("outermost entry diagnostics print only a fixed label and error class", async () => {
  const { readFile } = await import("node:fs/promises");
  const { pathToFileURL } = await import("node:url");
  const source = await readFile(new URL("./breadth-record.mjs", import.meta.url), "utf8");
  const tail = source
    .slice(source.indexOf("if (process.argv[1] && import.meta.url"))
    .replaceAll("import.meta.url", JSON.stringify(pathToFileURL("/fake/entry").href));
  const calls = [],
    fakeProcess = { argv: ["node", "/fake/entry"] };
  new Function("process", "pathToFileURL", "recordBreadth", "console", tail)(
    fakeProcess,
    pathToFileURL,
    () => Promise.reject(SyntaxError("PRIVATE_SENTINEL")),
    { error: (...args) => calls.push(args) },
  );
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(calls, [["breadth recorder failed", "SyntaxError"]]);
  assert.equal(fakeProcess.exitCode, 1);
});

test("final output retains nonce uid and function records after an ownership error", async () => {
  const { mkdtemp, readFile, rm, stat } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { executeRun } = await import("./breadth-record.mjs");
  const { makeWorld } = await import("./breadth-flow.fake.mjs");
  const dir = await mkdtemp(join(tmpdir(), "breadth-result-"));
  const world = makeWorld();
  world.deps.ownedNames = () => {
    throw Error("bad ownership");
  };
  try {
    const summary = await executeRun({
      environment: {
        projectId: "demo",
        projectNumber: "123456789012",
        nonce: "nonce",
        budget: { snapshot: () => ({ cliDeploy: 0 }) },
      },
      runDir: dir,
      packetPins: {},
      assemble: ({ log, runDir }) => ({
        deps: { ...world.deps, log, runDir, nonce: "nonce" },
        uploads: { close() {} },
        forms: { summary: () => ({}), maskedLines: () => [] },
        grants: {},
      }),
    });
    const result = JSON.parse(await readFile(join(dir, "result.json")));
    assert.equal(summary.residual, true);
    assert.equal(result.nonce, "nonce");
    assert.equal(result.uid, "fake-uid");
    assert.equal(result.cleanup.user.gone, true);
    assert.equal(result.cleanup.rtdb.closed, true);
    assert.equal(Object.keys(JSON.parse(await readFile(join(dir, "records.json")))).length, 3);
    assert.equal((await stat(join(dir, "result.json"))).mode & 0o777, 0o600);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
