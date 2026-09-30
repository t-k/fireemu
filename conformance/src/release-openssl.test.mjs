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
