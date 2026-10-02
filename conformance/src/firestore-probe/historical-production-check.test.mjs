import assert from "node:assert/strict";
import { test } from "node:test";

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import {
  checkHistoricalProduction,
  historicalArtifactIdentity,
  measureArtifact,
} from "./historical-production-check.mjs";

const definitions = [{ id: "writes", steps: [{ id: "same" }, { id: "changed" }] }];
const saved = {
  programs: [
    {
      id: "writes",
      steps: {
        same: {
          production: { status: 200, code: "OK", body: { x: 1 } },
          fireemu: { status: 200, code: "OK", body: { x: 1 } },
        },
        changed: {
          production: { status: 400, code: "INVALID_ARGUMENT" },
          fireemu: { status: 400, code: "INVALID_ARGUMENT" },
        },
      },
    },
  ],
};
const live = {
  writes: {
    steps: {
      same: { status: 200, code: "OK", body: { x: 1 } },
      changed: { status: 200, code: "OK", body: { x: 2 } },
    },
  },
};

test("changed recipes are excluded explicitly, not counted as production regressions", () => {
  const result = checkHistoricalProduction({
    saved,
    live,
    definitions,
    excludedKeys: ["writes#changed"],
  });
  assert.deepEqual(result, {
    comparable: 1,
    baselineMismatches: [],
    currentMismatches: [],
    newMismatches: [],
    indeterminate: [],
    newIndeterminate: [],
  });
});

test("a new mismatch in a comparable recipe fails the comparison", () => {
  const modified = structuredClone(live);
  modified.writes.steps.same.body.x = 2;
  const result = checkHistoricalProduction({
    saved,
    live: modified,
    definitions,
    excludedKeys: ["writes#changed"],
  });
  assert.deepEqual(result.newMismatches, ["writes#same"]);
});

test("missing observations remain indeterminate rather than becoming matches", () => {
  const modified = structuredClone(live);
  delete modified.writes.steps.same;
  const result = checkHistoricalProduction({
    saved,
    live: modified,
    definitions,
    excludedKeys: ["writes#changed"],
  });
  assert.deepEqual(result.indeterminate, ["writes#same"]);
  assert.deepEqual(result.newIndeterminate, ["writes#same"]);
});

test("unlisted recipe additions are rejected", () => {
  const modified = structuredClone(definitions);
  modified[0].steps.push({ id: "new" });
  assert.throws(
    () =>
      checkHistoricalProduction({
        saved,
        live,
        definitions: modified,
        excludedKeys: ["writes#changed"],
      }),
    /recipe identity/,
  );
});

test("the historical check records the artifact it ran and refuses one that changed", () => {
  const sha = "a".repeat(64);
  assert.deepEqual(
    historicalArtifactIdentity({
      root: "/repo",
      binary: "/repo/target/release/fireemu",
      before: sha,
      after: sha,
      version: "fireemu 0.7.1\n",
    }),
    {
      path: "target/release/fireemu",
      sha256Before: sha,
      sha256After: sha,
      version: "fireemu 0.7.1",
    },
  );
  assert.throws(
    () =>
      historicalArtifactIdentity({
        root: "/repo",
        binary: "/repo/target/debug/fireemu",
        before: sha,
        after: "b".repeat(64),
        version: "fireemu 0.7.1",
      }),
    /changed during the historical check/,
  );
  assert.throws(
    () =>
      historicalArtifactIdentity({
        root: "/repo",
        binary: "/repo/fireemu",
        before: "not-a-digest",
        after: "not-a-digest",
        version: "fireemu 0.7.1",
      }),
    /SHA-256/,
  );
});

test("an artifact is measured by its bytes and its --version answer", async () => {
  // The running Node binary stands in for fireemu: both answer --version on stdout.
  const measured = await measureArtifact(process.execPath);
  assert.equal(
    measured.sha256,
    createHash("sha256").update(readFileSync(process.execPath)).digest("hex"),
  );
  assert.equal(measured.version.trim(), process.version);
});

import * as probeRunner from "./run.mjs";

test("historical production launch validates explicit strict selection before launching", () => {
  assert.equal(typeof probeRunner.parseProbeArguments, "function");
  assert.deepEqual(probeRunner.parseProbeArguments(["check-production", "--profile", "strict"]), {
    mode: "check-production",
    profile: "strict",
  });
  assert.deepEqual(probeRunner.parseProbeArguments(["check-production"]), {
    mode: "check-production",
  });
  assert.deepEqual(probeRunner.parseProbeArguments(["check"]), { mode: "check" });
  for (const args of [
    ["check-production", "--profile"],
    ["check-production", "--profile", "unknown"],
    ["check-production", "--profile", "strict", "--profile", "emulator"],
    ["check", "--profile", "strict"],
    ["check-production", "--unknown", "strict"],
  ])
    assert.throws(() => probeRunner.parseProbeArguments(args), /profile|option/);
});

import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

test("strict probe generates a pinned config while preserving settings and rules resolution", async (t) => {
  assert.equal(typeof probeRunner.createFireemuProbeLaunch, "function");
  const root = await mkdtemp(join(tmpdir(), "fireemu-profile-plan-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = {
    schemaVersion: 1,
    profile: "emulator",
    firestore: { rules: "rules/source.rules", edition: "standard" },
    daemon: { clockStart: "2026-01-02T03:04:05Z" },
  };
  const configPath = join(root, "probe.json");
  await writeFile(configPath, JSON.stringify(source));
  const options = {
    binary: process.execPath,
    inPath: "in",
    outPath: "out",
    configPath,
    runDirectory: join(root, "private"),
    cwd: root,
  };
  const ordinary = await probeRunner.createFireemuProbeLaunch(options);
  assert.equal(ordinary.args[ordinary.args.indexOf("--config") + 1], configPath);
  assert.equal(ordinary.requestedProfile, "emulator");
  assert.equal(await readFile(configPath, "utf8"), JSON.stringify(source));
  const strict = await probeRunner.createFireemuProbeLaunch({ ...options, profile: "strict" });
  const generatedPath = strict.args[strict.args.indexOf("--config") + 1];
  assert.notEqual(generatedPath, configPath);
  assert.ok(!strict.args.includes("--profile"));
  assert.deepEqual(JSON.parse(await readFile(generatedPath, "utf8")), {
    ...source,
    profile: "strict",
    firestore: { ...source.firestore, rules: resolve(root, source.firestore.rules) },
  });
  assert.equal(
    strict.config.sourceSha256Before,
    createHash("sha256")
      .update(await readFile(configPath))
      .digest("hex"),
  );
  assert.equal(
    strict.config.sha256Before,
    createHash("sha256")
      .update(await readFile(generatedPath))
      .digest("hex"),
  );
});

test("profile receipt uses actual daemon output and refuses profile lies or changed launch inputs", async (t) => {
  for (const kind of [
    "strict",
    "emulator",
    "profile-lie",
    "requested-marker",
    "duplicate-banner",
    "config-change",
    "source-change",
    "binary-change",
  ]) {
    const root = await mkdtemp(join(tmpdir(), "fireemu-profile-execution-"));
    t.after(() => rm(root, { recursive: true, force: true }));
    const configPath = join(root, "probe.json"),
      binary = join(root, "fireemu"),
      outPath = join(root, "response.json");
    await writeFile(binary, "offline binary fixture");
    await writeFile(
      configPath,
      JSON.stringify({
        schemaVersion: 1,
        profile: "emulator",
        firestore: { rules: "rules/source.rules" },
      }),
    );
    const profile = kind === "emulator" ? "emulator" : "strict";
    const plan = await probeRunner.createFireemuProbeLaunch({
      binary,
      inPath: "in",
      outPath,
      profile,
      configPath,
      runDirectory: join(root, "private"),
      cwd: root,
    });
    const supervisor = async (actual) => {
      assert.equal(actual.command, binary);
      assert.equal(actual.cwd, root);
      assert.deepEqual(actual.args, plan.args);
      const config = JSON.parse(await readFile(actual.args[actual.args.indexOf("--config") + 1]));
      assert.equal(config.profile, profile);
      await writeFile(outPath, JSON.stringify({ writes: { steps: {} } }));
      if (kind === "config-change")
        await writeFile(plan.config.path, JSON.stringify({ ...config, profile: "emulator" }));
      if (kind === "source-change") await writeFile(configPath, "{}");
      if (kind === "binary-change") await writeFile(binary, "changed binary");
      if (kind === "requested-marker") return "requested profile: strict\n";
      const banner = `  profile: ${kind === "profile-lie" ? "emulator" : profile} (actual daemon fixture)\n`;
      return kind === "duplicate-banner" ? banner + banner : banner;
    };
    if (["strict", "emulator"].includes(kind)) {
      const actual = await probeRunner.executeFireemuProbe(plan, supervisor);
      assert.equal(actual.binding.effectiveProfile, profile);
      assert.equal(actual.binding.requestedProfile, profile);
      assert.equal(actual.binding.binary.sha256Before, actual.binding.binary.sha256After);
      assert.equal(actual.binding.config.sha256Before, actual.binding.config.sha256After);
      assert.deepEqual(actual.fireemu, { writes: { steps: {} } });
    } else
      await assert.rejects(probeRunner.executeFireemuProbe(plan, supervisor), /profile|digest/);
  }
});
