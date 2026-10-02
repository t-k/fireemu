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

test("strict historical launch loads the exact recorded production catalog", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "fireemu-recorded-index-plan-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const configPath = join(root, "probe.json");
  const source = { schemaVersion: 1, profile: "emulator", firestore: { rules: "source.rules" } };
  await writeFile(configPath, JSON.stringify(source));
  const launch =
    probeRunner.createHistoricalProductionLaunch ?? probeRunner.createFireemuProbeLaunch;
  const plan = await launch({
    binary: process.execPath,
    inPath: "in",
    outPath: "out",
    configPath,
    runDirectory: join(root, "private"),
    cwd: root,
    profile: "strict",
  });
  const config = JSON.parse(await readFile(plan.config.path));
  assert.equal(typeof config.firestore.indexFile, "string");
  const bytes = await readFile(config.firestore.indexFile);
  assert.equal(bytes.length, 2484);
  assert.equal(
    createHash("sha256").update(bytes).digest("hex"),
    "8a4d4bd7a72c3ce2bed4e0f8c4adc0cdb3a7c428477578295e44a11ae063d01c",
  );
  assert.equal(plan.indexes.authority.sourceGit, "2526c61eda5fc53ac91250307786127ae3c601be");
  assert.equal(plan.indexes.authority.file, "conformance/firestore.indexes.json");
  assert.equal(await readFile(configPath, "utf8"), JSON.stringify(source));
});

test("only strict historical replay reads the portable catalog and pinned matrix authority", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "fireemu-recorded-index-refusal-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const configPath = join(root, "probe.json"),
    fixturePath = join(root, "recorded.json"),
    matrixPath = join(root, "matrix.json");
  await writeFile(
    configPath,
    JSON.stringify({ schemaVersion: 1, profile: "emulator", firestore: { rules: "source.rules" } }),
  );
  const matrixBytes = await readFile(
    new URL("../../firestore-production-matrix.json", import.meta.url),
  );
  const catalogBytes = await readFile(
    new URL("../../firestore-production.indexes.json", import.meta.url),
  );
  await writeFile(matrixPath, matrixBytes);
  await writeFile(fixturePath, catalogBytes);
  const options = {
    binary: process.execPath,
    inPath: "in",
    outPath: "out",
    configPath,
    runDirectory: join(root, "private"),
    cwd: root,
    productionMatrixPath: matrixPath,
    indexFixturePath: fixturePath,
  };
  for (const profile of [undefined, "emulator"]) {
    const plan = await probeRunner.createHistoricalProductionLaunch({
      ...options,
      profile,
      indexFixturePath: join(root, "missing"),
      productionMatrixPath: join(root, "missing-matrix"),
    });
    assert.equal(plan.config.path, configPath);
    assert.equal(plan.indexes, undefined);
  }
  await assert.rejects(
    probeRunner.createHistoricalProductionLaunch({
      ...options,
      profile: "strict",
      indexFixturePath: join(root, "missing"),
    }),
    /ENOENT/,
  );
  for (const bytes of [
    Buffer.from(catalogBytes.toString().replace("ord", "bad")),
    Buffer.from(catalogBytes.toString().trim()),
    await readFile(new URL("../../firestore.indexes.json", import.meta.url)),
  ]) {
    await writeFile(fixturePath, bytes);
    await assert.rejects(
      probeRunner.createHistoricalProductionLaunch({ ...options, profile: "strict" }),
      /fixture bytes or digest/,
    );
  }
  await writeFile(fixturePath, catalogBytes);
  const matrixObservation = JSON.parse(matrixBytes);
  for (const kind of ["missing", "duplicate", "path", "count", "hash", "git"]) {
    const altered = structuredClone(matrixObservation),
      production = altered.evidence.observations.production;
    if (kind === "missing") delete production.inputs.indexFiles;
    if (kind === "duplicate") production.inputs.indexFiles.push(production.inputs.indexFiles[0]);
    if (kind === "path") production.inputs.indexFiles[0].file += "-foreign";
    if (kind === "count") production.inputs.indexFiles[0].bytes++;
    if (kind === "hash") production.inputs.indexFiles[0].sha256 = "sha256-" + "a".repeat(64);
    if (kind === "git") production.source.gitSha = "a".repeat(40);
    await writeFile(matrixPath, JSON.stringify(altered));
    await assert.rejects(
      probeRunner.createHistoricalProductionLaunch({ ...options, profile: "strict" }),
      /matrix index authority changed/,
      kind,
    );
  }
});

test("recorded index receipt rejects changed runtime or fixture bytes and retains exact control", async (t) => {
  for (const kind of ["exact", "runtime-change", "fixture-change"]) {
    const root = await mkdtemp(join(tmpdir(), "fireemu-recorded-index-execution-"));
    t.after(() => rm(root, { recursive: true, force: true }));
    const configPath = join(root, "probe.json"),
      binary = join(root, "binary"),
      outPath = join(root, "out.json"),
      indexFixturePath = join(root, "fixture.json");
    await writeFile(
      configPath,
      JSON.stringify({
        schemaVersion: 1,
        profile: "emulator",
        firestore: { rules: "source.rules" },
      }),
    );
    await writeFile(binary, "offline binary fixture");
    await writeFile(
      indexFixturePath,
      await readFile(new URL("../../firestore-production.indexes.json", import.meta.url)),
    );
    const plan = await probeRunner.createHistoricalProductionLaunch({
      binary,
      inPath: "in",
      outPath,
      profile: "strict",
      configPath,
      runDirectory: join(root, "private"),
      cwd: root,
      indexFixturePath,
    });
    const supervisor = async ({ args }) => {
      const config = JSON.parse(await readFile(args[args.indexOf("--config") + 1]));
      assert.equal(config.firestore.indexFile, plan.indexes.path);
      assert.equal((await readFile(config.firestore.indexFile)).length, 2484);
      await writeFile(outPath, JSON.stringify({ writes: { steps: {} } }));
      if (kind !== "exact")
        await writeFile(kind === "runtime-change" ? plan.indexes.path : indexFixturePath, "{}\n");
      return "  profile: strict (actual daemon fixture)\n";
    };
    if (kind === "exact") {
      const { binding } = await probeRunner.executeFireemuProbe(plan, supervisor);
      assert.deepEqual(binding.indexes.authority, plan.indexes.authority);
      assert.equal(binding.indexes.bytesBefore, binding.indexes.bytesAfter);
      assert.equal(binding.indexes.sha256Before, binding.indexes.sha256After);
    } else
      await assert.rejects(
        probeRunner.executeFireemuProbe(plan, supervisor),
        /index receipt changed/,
      );
  }
});

test("recorded authority parser refuses missing, ambiguous and malformed provenance", async () => {
  const savedMatrix = JSON.parse(
    await readFile(new URL("../../firestore-production-matrix.json", import.meta.url)),
  );
  for (const kind of [
    "unverified",
    "not-live",
    "git",
    "missing",
    "duplicate",
    "path",
    "zero-count",
    "unsafe-count",
    "hash",
  ]) {
    const altered = structuredClone(savedMatrix),
      production = altered.evidence.observations.production;
    if (kind === "unverified") altered.evidence.verified = false;
    if (kind === "not-live") production.observation.mode = "recorded";
    if (kind === "git") production.source.gitSha = "not-a-source";
    if (kind === "missing") delete production.inputs.indexFiles;
    if (kind === "duplicate") production.inputs.indexFiles.push(production.inputs.indexFiles[0]);
    if (kind === "path") production.inputs.indexFiles[0].file = "conformance/foreign.json";
    if (kind === "zero-count") production.inputs.indexFiles[0].bytes = 0;
    if (kind === "unsafe-count")
      production.inputs.indexFiles[0].bytes = Number.MAX_SAFE_INTEGER + 1;
    if (kind === "hash") production.inputs.indexFiles[0].sha256 = "not-a-digest";
    assert.throws(
      () => probeRunner.recordedProductionIndexAuthority(altered),
      /index authority/,
      kind,
    );
  }
});
