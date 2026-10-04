import assert from "node:assert/strict";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { execFileSync } from "node:child_process";

import { createTransport } from "./functions-events/record/rest.mjs";
import {
  PINNED_DEPENDENCIES,
  CLI_TIMEOUT_MS,
  cliPlan,
  dependencyProblems,
  discoverEndpoints,
  runCli,
  sourceProblems,
  dotenvSha256,
  dotenvText,
  prepareSource,
  summarize,
  readLists,
  waitReady,
} from "./functions-events/record/deploy.mjs";
import { createWorld } from "./functions-events-record-world.mjs";
import { formalHandlers } from "./functions-events/canary-cli.mjs";

const repoRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  cwd: new URL(".", import.meta.url).pathname,
})
  .toString()
  .trim();

test("the dotenv is exactly the fixture's production environment and its digest is stable", () => {
  const text = dotenvText();
  assert.match(text, /^FE_EVENTS_MODE=production\n/);
  assert.match(text, /FE_EVENTS_CAPTURE_MODE=stdout\n$/);
  assert.equal(text.split("\n").filter(Boolean).length, 6);
  assert.match(dotenvSha256(), /^[0-9a-f]{64}$/);
});

test("the CLI plan deploys and deletes the 22 handlers once each, in stdout capture mode", () => {
  const options = {
    configHome: "/tmp/c",
    configPath: "/tmp/f.json",
    workDir: "/tmp/w",
    home: "/tmp/h",
    path: "/usr/bin",
  };
  const deploy = cliPlan("deploy", options);
  assert.equal(deploy.args[deploy.args.indexOf("--only") + 1].split(",").length, 22);
  assert.equal(deploy.env.FE_EVENTS_CAPTURE_MODE, "stdout");
  assert.deepEqual(cliPlan("delete", options).args.slice(1, 23), formalHandlers);
});

test("each CLI action has its own timeout: the dry run is the shortest, the deploy the longest", () => {
  assert.deepEqual(CLI_TIMEOUT_MS, {
    deploy: 40 * 60_000,
    "dry-run": 10 * 60_000,
    delete: 20 * 60_000,
  });
});

test("the deploy carries --force, the dry run is the same command with --dry-run appended, the delete is as before", () => {
  const options = {
    configHome: "/tmp/c",
    configPath: "/tmp/f.json",
    workDir: "/tmp/w",
    home: "/tmp/h",
    path: "/usr/bin",
  };
  const deploy = cliPlan("deploy", options);
  const dryRun = cliPlan("dry-run", options);
  const only = formalHandlers.map((name) => `functions:events:${name}`).join(",");
  assert.deepEqual(deploy.args, [
    "deploy",
    "--config",
    "/tmp/f.json",
    "--project",
    "fireemu-oracle-events",
    "--only",
    only,
    "--non-interactive",
    "--force",
    "--debug",
  ]);
  assert.deepEqual(dryRun.args, [...deploy.args, "--dry-run"]);
  assert.deepEqual(dryRun.env, deploy.env);
  assert.equal(dryRun.cwd, deploy.cwd);
  const remove = cliPlan("delete", options);
  assert.ok(!remove.args.includes("--dry-run"));
  assert.equal(remove.args.filter((a) => a === "--force").length, 1);
  assert.equal(remove.args[0], "functions:delete");
  assert.throws(() => cliPlan("deploy-dry", options), /unknown CLI action/);
});

test("the source copy comes from the pinned commit and carries the dotenv, nothing untracked", () => {
  const commit = execFileSync("git", ["-C", repoRoot, "rev-parse", "HEAD"]).toString().trim();
  const target = mkdtempSync(join(tmpdir(), "fe-src-"));
  const { configPath, fixtureDir } = prepareSource({ repoRoot, commit, target });
  assert.ok(existsSync(configPath));
  assert.equal(readFileSync(join(fixtureDir, ".env.fireemu-oracle-events"), "utf8"), dotenvText());
  assert.ok(existsSync(join(fixtureDir, "index.js")));
  assert.ok(!existsSync(join(fixtureDir, "node_modules")), "node_modules must not come along");
  assert.throws(() => prepareSource({ repoRoot, commit: "HEAD", target }), /full SHA/);
});

function worldTransport(world) {
  const directory = mkdtempSync(join(tmpdir(), "fe-dep-"));
  return createTransport({
    directory,
    ceiling: 1000,
    token: async () => "t",
    apiKey: "k",
    fetch: world.fetch,
  });
}

test("before the deploy nothing is listed; after it the four lists show 22 active handlers", async () => {
  let t = 0;
  const world = createWorld({ now: () => t });
  const transport = worldTransport(world);
  const before = summarize(await readLists(transport));
  assert.equal(before.ready, false);
  assert.equal(before.absent, true);
  world.deploy();
  const after = summarize(await readLists(transport));
  assert.equal(after.ready, true);
  assert.equal(after.functionsActive.length, 22);
  assert.equal(after.absent, false);
});

test("waitReady polls on a schedule and returns the last summary when the handlers never become ready", async () => {
  const world = createWorld({ now: () => 0 });
  const transport = worldTransport(world);
  const slept = [];
  const result = await waitReady({
    transport,
    sleep: async (s) => slept.push(s),
    polls: 3,
    everySeconds: 30,
  });
  assert.equal(result.ready, false);
  assert.equal(result.polls, 3);
  assert.deepEqual(slept, [30, 30]);
});

test("a list that cannot be read is incomplete, so neither ready nor absent can be claimed", async () => {
  const world = createWorld({ now: () => 0 });
  world.failures.push({
    match: (m, u) => u.includes("/v1/") && u.includes("cloudfunctions"),
    status: 503,
  });
  const summary = summarize(await readLists(worldTransport(world)));
  assert.equal(summary.complete, false);
  assert.equal(summary.absent, false);
});

const depsDir = new URL("../functions-events/fixtures/node_modules", import.meta.url).pathname;
const haveDeps = existsSync(depsDir);

test(
  "the source copy carries a verified dependency tree and the SDK discovers exactly the 22 handlers offline",
  { skip: !haveDeps && "the fixture dependencies are not installed here" },
  () => {
    const commit = execFileSync("git", ["-C", repoRoot, "rev-parse", "HEAD"]).toString().trim();
    const target = mkdtempSync(join(tmpdir(), "fe-src-"));
    const { fixtureDir } = prepareSource({ repoRoot, commit, target, depsDir });
    assert.deepEqual(dependencyProblems(fixtureDir), []);
    const directory = mkdtempSync(join(tmpdir(), "fe-disc-"));
    assert.deepEqual(sourceProblems({ fixtureDir, node: process.execPath, directory }), []);
    assert.deepEqual(
      discoverEndpoints({ fixtureDir, node: process.execPath, directory }).toSorted(),
      formalHandlers.toSorted(),
    );
  },
);

test("a copy without dependencies, with the wrong version or with a link out of the tree is a problem", () => {
  const commit = execFileSync("git", ["-C", repoRoot, "rev-parse", "HEAD"]).toString().trim();
  const bare = prepareSource({ repoRoot, commit, target: mkdtempSync(join(tmpdir(), "fe-src-")) });
  assert.ok(dependencyProblems(bare.fixtureDir).some((p) => p.includes("cannot be resolved")));
  assert.ok(
    sourceProblems({
      fixtureDir: bare.fixtureDir,
      node: process.execPath,
      directory: mkdtempSync(join(tmpdir(), "fe-disc-")),
    }).length > 0,
  );
  // a tree with the right names and the wrong version, and one with a link to the outside
  const fake = mkdtempSync(join(tmpdir(), "fe-fake-"));
  mkdirSync(join(fake, "node_modules"), { recursive: true });
  writeFileSync(join(fake, "package.json"), "{}");
  for (const name of Object.keys(PINNED_DEPENDENCIES)) {
    mkdirSync(join(fake, "node_modules", name), { recursive: true });
    writeFileSync(join(fake, "node_modules", name, "index.js"), "");
    writeFileSync(
      join(fake, "node_modules", name, "package.json"),
      JSON.stringify({
        name,
        main: "index.js",
        version: name === "firebase-admin" ? "1.0.0" : PINNED_DEPENDENCIES[name],
      }),
    );
  }
  assert.deepEqual(dependencyProblems(fake), ["firebase-admin is 1.0.0, not 14.3.0"]);
  symlinkSync("/tmp", join(fake, "node_modules", "outside"));
  assert.ok(dependencyProblems(fake).some((p) => p.includes("leave the tree")));
});

test("a CLI that ignores SIGTERM is killed after the grace period and the run goes on", async () => {
  const directory = mkdtempSync(join(tmpdir(), "fe-cli-"));
  const script = join(directory, "stubborn.js");
  writeFileSync(script, 'process.on("SIGTERM", () => {}); setInterval(() => {}, 1000);');
  const result = await runCli({
    action: "deploy",
    plan: { args: [], cwd: directory, env: { PATH: "/usr/bin" } },
    firebaseJs: script,
    node: process.execPath,
    directory,
    timeoutMs: 300,
    killGraceMs: 300,
  });
  assert.equal(result.timedOut, true);
  assert.equal(result.signal, "SIGKILL");
});

test("absence needs the Eventarc list empty, not only free of our names", () => {
  const empty = { items: [], complete: true };
  const lists = (eventarc) => ({ v1: empty, v2: empty, run: empty, eventarc });
  assert.equal(summarize(lists(empty)).absent, true);
  const foreign = {
    items: [{ name: "projects/p/locations/l/triggers/someone-elses-trigger" }],
    complete: true,
  };
  assert.equal(
    summarize(lists(foreign)).absent,
    false,
    "a trigger that is not ours still means the region is not empty",
  );
  const ours = {
    items: [{ name: "projects/p/locations/l/triggers/fscreatedv2-123" }],
    complete: true,
  };
  assert.equal(summarize(lists(ours)).absent, false);
  assert.equal(summarize(lists({ items: [], complete: false })).absent, false);
  // a function or a Run service that is not ours also means the region is not empty
  const function_ = {
    items: [{ name: "projects/p/locations/l/functions/other", status: "ACTIVE" }],
    complete: true,
  };
  assert.equal(summarize({ v1: function_, v2: empty, run: empty, eventarc: empty }).absent, false);
  assert.equal(summarize({ v1: empty, v2: function_, run: empty, eventarc: empty }).absent, false);
  const service = { items: [{ name: "projects/p/locations/l/services/other" }], complete: true };
  assert.equal(summarize({ v1: empty, v2: empty, run: service, eventarc: empty }).absent, false);
  assert.equal(
    summarize({ v1: { ...empty, complete: false }, v2: empty, run: empty, eventarc: empty }).absent,
    false,
  );
});
