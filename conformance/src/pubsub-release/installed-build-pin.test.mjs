import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { validateRuntime } from "../pubsub-production/stream-dlq-compare.mjs";
import { stageInstalledBuildPin } from "./installed-build-pin.mjs";

const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
function fixture(t) {
  const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "pubsub-release-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const bytes = Buffer.from("exact installed artifact");
  const binaryPath = path.join(root, "installed-fireemu");
  fs.writeFileSync(binaryPath, bytes);
  const original = {
    profile: "release",
    rustcWrapper: "",
    head: "1".repeat(40),
    command: ["cargo", "build", "--release"],
    path: "/original/release/fireemu",
    sha256: sha(bytes),
    provenance: { platform: "genuine-platform", remap: true },
  };
  const buildPinPath = path.join(root, "original.json");
  fs.writeFileSync(buildPinPath, JSON.stringify(original));
  return {
    root,
    bytes,
    original,
    binaryPath,
    buildPinPath,
    buildPinSha256: sha(fs.readFileSync(buildPinPath)),
    out: path.join(root, "staged"),
  };
}

test("stages exact installed bytes and preserves original build provenance", (t) => {
  const f = fixture(t);
  let result;
  assert.doesNotThrow(() => {
    result = stageInstalledBuildPin(f);
  });
  const pin = JSON.parse(fs.readFileSync(result.buildPinPath, "utf8"));
  assert.deepEqual(fs.readFileSync(pin.path), f.bytes);
  assert.deepEqual(pin, { ...f.original, path: path.join(f.out, "release/fireemu") });
  assert.equal(sha(fs.readFileSync(result.buildPinPath)), result.buildPinSha256);
});

test("copies the hash-bound input map without rewriting its source entries", (t) => {
  const f = fixture(t);
  const map = Buffer.from('{"files":{"crates/source.rs":"original-source-digest"}}\n');
  const binaryInputsPath = path.join(f.root, "inputs.json");
  fs.writeFileSync(binaryInputsPath, map);
  Object.assign(f.original, { binaryInputsPath, binaryInputsSha256: sha(map) });
  fs.writeFileSync(f.buildPinPath, JSON.stringify(f.original));
  f.buildPinSha256 = sha(fs.readFileSync(f.buildPinPath));
  const result = stageInstalledBuildPin(f);
  const pin = JSON.parse(fs.readFileSync(result.buildPinPath));
  assert.equal(pin.binaryInputsPath, path.join(f.out, "binary-inputs.json"));
  assert.deepEqual(fs.readFileSync(pin.binaryInputsPath), map);
  assert.deepEqual(pin, {
    ...f.original,
    path: path.join(f.out, "release/fireemu"),
    binaryInputsPath: pin.binaryInputsPath,
  });
});

test("rejects noncanonical and symlinked destinations before writing", (t) => {
  for (const variant of ["relative", "dotdot", "symlink"]) {
    const f = fixture(t);
    if (variant === "relative") f.out = "relative-release";
    if (variant === "dotdot") f.out = `${f.root}/missing/../staged`;
    if (variant === "symlink") {
      fs.symlinkSync(f.root, path.join(f.root, "alias"));
      f.out = path.join(f.root, "alias/staged");
    }
    assert.throws(() => stageInstalledBuildPin(f), /unsafe destination/);
    assert.equal(fs.existsSync(path.join(f.root, "staged")), false);
  }
});

test("rejects an existing destination without changing its files", (t) => {
  const f = fixture(t);
  fs.mkdirSync(f.out);
  fs.writeFileSync(path.join(f.out, "keep"), "valuable");
  assert.throws(() => stageInstalledBuildPin(f));
  assert.equal(fs.readFileSync(path.join(f.out, "keep"), "utf8"), "valuable");
});

test("rejects changed receipt, installed bytes, and input-map bytes before staging", (t) => {
  for (const variant of ["receipt", "binary", "map"]) {
    const f = fixture(t);
    if (variant === "receipt") fs.appendFileSync(f.buildPinPath, " ");
    if (variant === "binary") fs.appendFileSync(f.binaryPath, "changed");
    if (variant === "map") {
      const binaryInputsPath = path.join(f.root, "inputs.json");
      fs.writeFileSync(binaryInputsPath, "changed");
      Object.assign(f.original, { binaryInputsPath, binaryInputsSha256: sha("original") });
      fs.writeFileSync(f.buildPinPath, JSON.stringify(f.original));
      f.buildPinSha256 = sha(fs.readFileSync(f.buildPinPath));
    }
    assert.throws(() => stageInstalledBuildPin(f), /digest mismatch/);
    assert.equal(fs.existsSync(f.out), false);
  }
});

test("existing lane runtime validation remains authoritative for staged provenance", (t) => {
  const f = fixture(t);
  const result = stageInstalledBuildPin(f);
  const pin = JSON.parse(fs.readFileSync(result.buildPinPath));
  const env = {
    PUBSUB_EMULATOR_HOST: "127.0.0.1:19876",
    FIREEMU_CONTROL_URL: "http://127.0.0.1:19877/v1/",
    FIREEMU_CONTROL_TOKEN: "unit-only",
  };
  assert.doesNotThrow(() => validateRuntime(pin, env));
  for (const delta of [
    { head: "invalid" },
    { profile: "dev" },
    { rustcWrapper: "wrapper" },
    { command: ["cargo", "check"] },
  ]) {
    assert.throws(() => validateRuntime({ ...pin, ...delta }, env));
  }
  assert.throws(() => validateRuntime(pin, {}));
});

test("CLI binds the installed binary and original receipt to a fresh staged pin", (t) => {
  const f = fixture(t);
  const q = spawnSync(
    process.execPath,
    [
      fileURLToPath(new URL("./installed-build-pin.mjs", import.meta.url)),
      "--bin",
      f.binaryPath,
      "--build-pin",
      f.buildPinPath,
      "--build-pin-sha256",
      f.buildPinSha256,
      "--out",
      f.out,
    ],
    { encoding: "utf8" },
  );
  assert.equal(q.status, 0, q.stderr);
  const result = JSON.parse(q.stdout);
  assert.equal(result.buildPinSha256, sha(fs.readFileSync(result.buildPinPath)));
  assert.deepEqual(fs.readFileSync(JSON.parse(fs.readFileSync(result.buildPinPath)).path), f.bytes);
});

test("rejects symlinked receipts and oversized installed artifacts before staging", (t) => {
  const f = fixture(t);
  const alias = path.join(f.root, "receipt-alias");
  fs.symlinkSync(f.buildPinPath, alias);
  assert.throws(() => stageInstalledBuildPin({ ...f, buildPinPath: alias }), /regular file/);
  const fd = fs.openSync(f.binaryPath, "w");
  fs.ftruncateSync(fd, 100_000_001);
  fs.closeSync(fd);
  assert.throws(() => stageInstalledBuildPin(f), /file size/);
  assert.equal(fs.existsSync(f.out), false);
});

test("installed symlink resolves to the exact artifact without substituting provenance", (t) => {
  const f = fixture(t);
  const alias = path.join(f.root, "installed-alias");
  fs.symlinkSync(f.binaryPath, alias);
  const result = stageInstalledBuildPin({ ...f, binaryPath: alias });
  const pin = JSON.parse(fs.readFileSync(result.buildPinPath));
  assert.equal(pin.head, f.original.head);
  assert.deepEqual(fs.readFileSync(pin.path), f.bytes);
});
