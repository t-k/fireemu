import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { platformManifest } from "../platforms/build-platform.mjs";
import { PLATFORMS } from "../platforms/platforms.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const repositoryUrl = "https://github.com/t-k/fireemu";
const retiredRepositoryPath = ["github.com", "reckona", "fireemu"].join("/");

test("every public distribution reference names the canonical repository", () => {
  const launcher = JSON.parse(readFileSync(resolve(repoRoot, "npm/fireemu/package.json"), "utf8"));
  assert.equal(launcher.homepage, `${repositoryUrl}#readme`);
  assert.equal(launcher.bugs, `${repositoryUrl}/issues`);
  assert.equal(launcher.repository.url, `git+${repositoryUrl}.git`);

  for (const platform of PLATFORMS) {
    const manifest = platformManifest(platform, "1.2.3");
    assert.equal(manifest.homepage, `${repositoryUrl}#readme`);
    assert.equal(manifest.repository.url, `git+${repositoryUrl}.git`);
  }

  const search = spawnSync(
    "git",
    [
      "grep",
      "-n",
      retiredRepositoryPath,
      "--",
      "README.md",
      "npm",
      ".github/workflows",
    ],
    { cwd: repoRoot, encoding: "utf8" },
  );
  assert.equal(search.status, 1, search.stdout || search.stderr);
});
