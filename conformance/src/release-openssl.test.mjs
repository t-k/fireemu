import assert from "node:assert/strict";
import { test } from "node:test";

import { federationEnvironment } from "./release-openssl.mjs";

test("only R15-R17 select and validate the federation OpenSSL", () => {
  const env = { PATH: "/system/bin", FIREEMU_FEDERATION_OPENSSL_DIR: "/pinned/bin" };
  for (const id of ["R1", "R10", "R14", "R18"]) {
    assert.equal(
      federationEnvironment(id, env, () => assert.fail("unexpected OpenSSL probe")),
      env,
    );
  }
  for (const id of ["R15", "R16", "R17"]) {
    const actual = federationEnvironment(id, env, (file, args, options) => {
      assert.equal(file, "/pinned/bin/openssl");
      assert.deepEqual(args, ["version"]);
      assert.equal(options.env.PATH, "/pinned/bin:/system/bin");
      assert.equal(options.timeout, 5000);
      return "OpenSSL 3.6.4 25 Aug 2026 (Library: OpenSSL 3.6.4)\n";
    });
    assert.equal(actual.PATH, "/pinned/bin:/system/bin");
    assert.equal(env.PATH, "/system/bin");
  }
});

test("federation refuses old, unrelated, malformed or unavailable OpenSSL clearly", () => {
  for (const version of [
    "OpenSSL 3.0.22",
    "OpenSSL 3.3.9",
    "OpenSSL 1.1.1w",
    "LibreSSL 3.9.2",
    "unrecognized",
  ]) {
    assert.throws(
      () => federationEnvironment("R16", { PATH: "/system/bin" }, () => version),
      /R16 requires OpenSSL >= 3\.4/,
    );
  }
  assert.throws(
    () =>
      federationEnvironment("R15", {}, () => {
        throw new Error("ENOENT");
      }),
    /R15 requires OpenSSL >= 3\.4.*ENOENT/,
  );
  assert.throws(
    () => federationEnvironment("R17", { FIREEMU_FEDERATION_OPENSSL_DIR: "relative" }),
    /absolute/,
  );
  assert.throws(
    () => federationEnvironment("R15", { FIREEMU_FEDERATION_OPENSSL_DIR: "/pinned:other/bin" }),
    /without PATH delimiters/,
  );
});

test("federation accepts the supported boundary and newer versions on the harness PATH", () => {
  for (const version of ["OpenSSL 3.4.0", "OpenSSL 3.5.8", "OpenSSL 4.0.2"]) {
    const env = { PATH: "/supported/bin" };
    assert.equal(
      federationEnvironment("R15", env, (_file, _args, options) => {
        assert.equal(options.env.PATH, env.PATH);
        return version;
      }).PATH,
      env.PATH,
    );
  }
});

test("the version probe preserves the harness PATH's symlink and parent-directory resolution", async () => {
  const { mkdtemp, mkdir, writeFile, chmod, symlink, rm } = await import("node:fs/promises");
  const { execFileSync } = await import("node:child_process");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const dir = await mkdtemp(join(tmpdir(), "fireemu-openssl-path-"));
  try {
    for (const [folder, version] of [
      ["a/bin", "3.6.4"],
      ["b/bin", "3.0.22"],
    ]) {
      await mkdir(join(dir, folder), { recursive: true });
      const tool = join(dir, folder, "openssl");
      await writeFile(tool, `#!/bin/sh\necho "OpenSSL ${version}"\n`);
      await chmod(tool, 0o700);
    }
    await mkdir(join(dir, "b/deep"));
    await symlink(join(dir, "b/deep"), join(dir, "a/link"));
    const directory = `${dir}/a/link/../bin`;
    const env = { PATH: `${directory}:/usr/bin:/bin`, FIREEMU_FEDERATION_OPENSSL_DIR: directory };
    assert.match(
      execFileSync("openssl", ["version"], { env, encoding: "utf8" }),
      /OpenSSL 3\.0\.22/,
    );
    assert.throws(
      () => federationEnvironment("R15", env),
      /R15 requires OpenSSL >= 3\.4.*3\.0\.22/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
