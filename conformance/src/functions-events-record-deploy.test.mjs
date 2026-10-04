import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { execFileSync } from "node:child_process";

import { createTransport } from "./functions-events/record/rest.mjs";
import { cliPlan, dotenvSha256, dotenvText, prepareSource, summarize, readLists, waitReady } from "./functions-events/record/deploy.mjs";
import { createWorld } from "./functions-events-record-world.mjs";
import { formalHandlers } from "./functions-events/canary-cli.mjs";

const repoRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], { cwd: new URL(".", import.meta.url).pathname }).toString().trim();

test("the dotenv is exactly the fixture's production environment and its digest is stable", () => {
  const text = dotenvText();
  assert.match(text, /^FE_EVENTS_MODE=production\n/);
  assert.match(text, /FE_EVENTS_CAPTURE_MODE=stdout\n$/);
  assert.equal(text.split("\n").filter(Boolean).length, 6);
  assert.match(dotenvSha256(), /^[0-9a-f]{64}$/);
});

test("the CLI plan deploys and deletes the 22 handlers once each, in stdout capture mode", () => {
  const options = { configHome: "/tmp/c", configPath: "/tmp/f.json", workDir: "/tmp/w", home: "/tmp/h", path: "/usr/bin" };
  const deploy = cliPlan("deploy", options);
  assert.equal(deploy.args[deploy.args.indexOf("--only") + 1].split(",").length, 22);
  assert.equal(deploy.env.FE_EVENTS_CAPTURE_MODE, "stdout");
  assert.deepEqual(cliPlan("delete", options).args.slice(1, 23), formalHandlers);
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
  return createTransport({ directory, ceiling: 1000, token: async () => "t", apiKey: "k", fetch: world.fetch });
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
  const result = await waitReady({ transport, sleep: async (s) => slept.push(s), polls: 3, everySeconds: 30 });
  assert.equal(result.ready, false);
  assert.equal(result.polls, 3);
  assert.deepEqual(slept, [30, 30]);
});

test("a list that cannot be read is incomplete, so neither ready nor absent can be claimed", async () => {
  const world = createWorld({ now: () => 0 });
  world.failures.push({ match: (m, u) => u.includes("/v1/") && u.includes("cloudfunctions"), status: 503 });
  const summary = summarize(await readLists(worldTransport(world)));
  assert.equal(summary.complete, false);
  assert.equal(summary.absent, false);
});
