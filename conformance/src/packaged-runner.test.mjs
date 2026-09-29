import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { findPackagedRunner, packagedRunnerCandidates } from "./packaged-runner.mjs";

const withTree = (build, check) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "fireemu-packaged-runner-")));
  try {
    build(root);
    check(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
};

test("the candidates are beside the real binary, then one directory above it", () => {
  assert.deepEqual(packagedRunnerCandidates("/pkg/bin/fireemu", (path) => path), [
    "/pkg/bin/runner-node/index.mjs",
    "/pkg/runner-node/index.mjs",
  ]);
});

test("the candidates follow a symlink to the real binary", () => {
  assert.deepEqual(packagedRunnerCandidates("/pkg/.bin/fireemu", () => "/real/bin/fireemu"), [
    "/real/bin/runner-node/index.mjs",
    "/real/runner-node/index.mjs",
  ]);
});

test("a runner script beside the binary is found; a checkout runner is not", () => {
  withTree(
    (root) => {
      mkdirSync(join(root, "bin", "runner-node"), { recursive: true });
      writeFileSync(join(root, "bin", "fireemu"), "");
      writeFileSync(join(root, "bin", "runner-node", "index.mjs"), "");
    },
    (root) => {
      assert.equal(
        findPackagedRunner(join(root, "bin", "fireemu")),
        join(root, "bin", "runner-node", "index.mjs"),
      );
    },
  );
  withTree(
    (root) => {
      mkdirSync(join(root, "bin"), { recursive: true });
      writeFileSync(join(root, "bin", "fireemu"), "");
      mkdirSync(join(root, "tools", "runner-node"), { recursive: true });
      writeFileSync(join(root, "tools", "runner-node", "index.mjs"), "");
    },
    (root) => assert.equal(findPackagedRunner(join(root, "bin", "fireemu")), undefined),
  );
});

test("the runner one directory above the binary is found through a symlinked binary", () => {
  withTree(
    (root) => {
      mkdirSync(join(root, "pkg", "bin"), { recursive: true });
      mkdirSync(join(root, "pkg", "runner-node"), { recursive: true });
      mkdirSync(join(root, "link"), { recursive: true });
      writeFileSync(join(root, "pkg", "bin", "fireemu"), "");
      writeFileSync(join(root, "pkg", "runner-node", "index.mjs"), "");
      symlinkSync(join(root, "pkg", "bin", "fireemu"), join(root, "link", "fireemu"));
    },
    (root) => {
      assert.ok(findPackagedRunner(join(root, "link", "fireemu")));
    },
  );
});

test("a directory named index.mjs is not a runner script, as in the daemon", () => {
  withTree(
    (root) => {
      mkdirSync(join(root, "bin", "runner-node", "index.mjs"), { recursive: true });
      writeFileSync(join(root, "bin", "fireemu"), "");
    },
    (root) => assert.equal(findPackagedRunner(join(root, "bin", "fireemu")), undefined),
  );
});
