import assert from "node:assert/strict";
import tls from "node:tls";
import test, { beforeEach, afterEach } from "node:test";
const testProcessArgs = process.execArgv;
beforeEach(() => {
  process.execArgv = [];
});
afterEach(() => {
  process.execArgv = testProcessArgs;
});
const module = await import("./storage-object/production-tls.mjs").catch((error) => {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  return {};
});
const options = (value) => {
  assert.equal(typeof module.productionTlsOptions, "function", "production TLS policy is missing");
  return module.productionTlsOptions(value);
};
test("each approved origin uses its real SNI, explicit bundled CAs, hostname verification and TLS bounds", () => {
  for (const host of [
    "firebasestorage",
    "storage",
    "identitytoolkit",
    "securetoken",
    "oauth2",
    "firebaserules",
    "apikeys",
    "cloudresourcemanager",
  ]) {
    const result = options(`https://${host}.googleapis.com/path`);
    assert.equal(result.servername, `${host}.googleapis.com`);
    assert.equal(result.rejectUnauthorized, true);
    assert.equal(result.checkServerIdentity, tls.checkServerIdentity);
    assert.equal(result.minVersion, "TLSv1.2");
    assert.equal(result.maxVersion, "TLSv1.3");
    assert.deepEqual(result.ca, tls.getCACertificates("bundled"));
    assert.ok(result.ca.length > 0);
    assert.ok(Object.isFrozen(result));
    assert.ok(Object.isFrozen(result.ca));
  }
});
test("unknown hosts, ports, schemes and URL authority secrets reject without reflecting input", () => {
  for (const value of [
    "http://storage.googleapis.com/path",
    "https://storage.googleapis.com:444/path",
    "https://storage.googleapis.com.evil.example/path",
    "https://unlisted.example/path",
    "https://NEW_SECRET@storage.googleapis.com/path",
    "https://storage.googleapis.com/path#NEW_SECRET",
    { url: "https://storage.googleapis.com/path", ca: "NEW_SECRET" },
  ])
    assert.throws(() => options(value), /^Error: invalid production TLS policy$/);
});
test("environment CA and TLS overrides reject before creating a connection configuration", () => {
  for (const key of [
    "NODE_EXTRA_CA_CERTS",
    "NODE_TLS_REJECT_UNAUTHORIZED",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "NODE_OPTIONS",
    "NODE_USE_SYSTEM_CA",
    "OPENSSL_CONF",
    "OPENSSL_MODULES",
    "OPENSSL_ENGINES",
  ]) {
    const previous = process.env[key];
    try {
      process.env[key] = "NEW_OVERRIDE_SECRET";
      assert.throws(
        () => options("https://storage.googleapis.com/path"),
        /^Error: invalid production TLS policy$/,
      );
    } finally {
      if (previous === undefined) delete process.env[key];
      else process.env[key] = previous;
    }
  }
});

test("unreviewed Node startup flags cannot change the production TLS runtime", () => {
  const previous = process.execArgv;
  try {
    for (const args of [
      ["--use-openssl-ca"],
      ["--openssl-config=NEW_SECRET"],
      ["--import=NEW_SECRET"],
    ]) {
      process.execArgv = args;
      assert.throws(
        () => options("https://storage.googleapis.com/path"),
        /^Error: invalid production TLS policy$/,
      );
    }
  } finally {
    process.execArgv = previous;
  }
});
