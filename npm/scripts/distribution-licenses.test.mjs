import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { buildPlatformPackage } from "../platforms/build-platform.mjs";
import { prepareLauncher } from "./prepare-launcher.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

test("the copied Firebase CLI widget retains its MIT attribution", () => {
  const source = readFileSync(
    join(
      repoRoot,
      "crates",
      "fireemu-adapter-http",
      "src",
      "identity_toolkit",
      "widget_templates.rs",
    ),
    "utf8",
  );

  assert.match(source, /SPDX-License-Identifier: MIT/);
  assert.match(source, /Copyright \(c\) 2015 Firebase/);
  assert.match(source, /firebase\/firebase-tools/);
  assert.match(source, /Modified by the fireemu project/);
});

test("the canonical third-party license file includes the Firebase CLI MIT notice", () => {
  const noticePath = join(repoRoot, "THIRD_PARTY_LICENSES.txt");
  assert.ok(existsSync(noticePath), "THIRD_PARTY_LICENSES.txt must exist at the repository root");

  const notice = readFileSync(noticePath, "utf8");
  assert.match(notice, /Firebase CLI/);
  assert.match(notice, /The MIT License \(MIT\)/);
  assert.match(notice, /Copyright \(c\) 2015 Firebase/);
  assert.match(notice, /Permission is hereby granted, free of charge/);
});

test("the launcher package includes the canonical third-party license file", () => {
  const root = mkdtempSync(join(tmpdir(), "fireemu-launcher-license-"));
  try {
    mkdirSync(join(root, "npm", "fireemu"), { recursive: true });
    writeFileSync(join(root, "npm", "README.md"), "launcher readme\n");
    writeFileSync(join(root, "LICENSE"), "project license\n");
    writeFileSync(join(root, "THIRD_PARTY_LICENSES.txt"), "third-party notices\n");

    prepareLauncher(root);

    assert.equal(
      readFileSync(join(root, "npm", "fireemu", "THIRD_PARTY_LICENSES.txt"), "utf8"),
      "third-party notices\n",
    );
    const manifest = JSON.parse(
      readFileSync(join(repoRoot, "npm", "fireemu", "package.json"), "utf8"),
    );
    assert.ok(manifest.files.includes("THIRD_PARTY_LICENSES.txt"));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("each platform package includes the canonical third-party license file", () => {
  const root = mkdtempSync(join(tmpdir(), "fireemu-platform-license-"));
  try {
    const binary = join(root, "fireemu");
    const out = join(root, "package");
    writeFileSync(binary, "test binary\n");

    buildPlatformPackage({
      platformName: "darwin-arm64",
      binaryPath: binary,
      outDir: out,
    });

    assert.equal(
      readFileSync(join(out, "THIRD_PARTY_LICENSES.txt"), "utf8"),
      readFileSync(join(repoRoot, "THIRD_PARTY_LICENSES.txt"), "utf8"),
    );
    const manifest = JSON.parse(readFileSync(join(out, "package.json"), "utf8"));
    assert.ok(manifest.files.includes("THIRD_PARTY_LICENSES.txt"));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
