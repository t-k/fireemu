import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { buildPlatformPackage } from "../platforms/build-platform.mjs";
import { prepareLauncher } from "./prepare-launcher.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

function relativeFiles(root, directory = root) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? relativeFiles(root, path) : [path.slice(root.length + 1)];
  });
}

test("public RSA test fixtures are referenced only by signing or hashed compatibility provenance", () => {
  const trackedFiles = execFileSync("git", ["ls-files", "-z"], {
    cwd: repoRoot,
    encoding: "utf8",
  }).split("\0").filter(Boolean);

  for (const suffix of ["A.der.hex", "B.der.hex"]) {
    const fixtureName = ["INSECURE", "TEST", "ONLY", "RSA", suffix].join("_");
    const fixturePath = `crates/fireemu-adapter-http/tests/fixtures/${fixtureName}`;
    const fixtureBytes = readFileSync(join(repoRoot, fixturePath));
    const fixtureDigest = createHash("sha256").update(fixtureBytes).digest("hex");
    const violations = [];

    for (const path of trackedFiles) {
      if (path === fixturePath) continue;

      const contents = readFileSync(join(repoRoot, path));
      if (contents.includes(fixtureBytes)) {
        violations.push(`${path}: contains the fixture bytes`);
        continue;
      }

      const text = contents.toString("utf8");
      const isCompatibilityJson =
        path.startsWith("spec/compatibility/") && path.endsWith(".json");
      if (!isCompatibilityJson) {
        if (
          path !== "crates/fireemu-adapter-http/tests/signing.rs" &&
          text.includes(fixtureName)
        ) {
          violations.push(`${path}: mentions the fixture name`);
        }
        continue;
      }

      let document;
      try {
        document = JSON.parse(contents);
      } catch {
        if (text.includes(fixtureName)) {
          violations.push(`${path}: fixture name is not in a JSON object key`);
        }
        continue;
      }

      const inspect = (value) => {
        if (Array.isArray(value)) {
          value.forEach((entry) => inspect(entry));
        } else if (value && typeof value === "object") {
          Object.entries(value).forEach(([key, entry]) => {
            if (key === fixturePath) {
              if (entry !== fixtureDigest) {
                violations.push(`${path}: fixture key has the wrong SHA256`);
              }
              return;
            }
            inspect(key);
            inspect(entry);
          });
        } else if (typeof value === "string" && value.includes(fixtureName)) {
          violations.push(`${path}: fixture name is a value or free text`);
        }
      };
      inspect(document);
    }

    assert.deepEqual(violations, [], `${fixtureName} has unauthorized references`);
  }
});

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
    const packagedFiles = relativeFiles(out);
    assert.ok(
      packagedFiles.every(
        (path) =>
          !path.includes("tests/fixtures") &&
          !path.includes("INSECURE_TEST_ONLY") &&
          !path.endsWith(".der") &&
          !path.endsWith(".der.hex"),
      ),
      `public test keys entered the platform package: ${packagedFiles.join(", ")}`,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
