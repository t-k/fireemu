import assert from "node:assert/strict";
import { createPublicKey, verify } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, matchesGlob } from "node:path";
import { test } from "node:test";

import * as idp from "./auth-federation/idp.mjs";
import {
  discoveryDocument,
  generateSigningKey,
  idTokenClaims,
  isPrivateKeyLocation,
  issuerFiles,
  jwksDocument,
  loadSigningKey,
  saveSigningKey,
  signIdToken,
} from "./auth-federation/idp.mjs";
import { tempDir } from "./test-tmpdir.mjs";

const decode = (part) => JSON.parse(Buffer.from(part, "base64url").toString("utf8"));

test("an ID token is an RS256 JWS the published JWK verifies", () => {
  const key = generateSigningKey();
  const claims = idTokenClaims({
    issuer: "https://idp.example/issuer",
    clientId: "client",
    subject: "user-1",
    now: 1_800_000_000,
    email: "u@example.com",
  });
  const token = signIdToken(key, claims);
  const [header, payload, signature] = token.split(".");
  assert.deepEqual(decode(header), { alg: "RS256", typ: "JWT", kid: key.jwk.kid });
  assert.deepEqual(decode(payload), {
    iss: "https://idp.example/issuer",
    aud: "client",
    sub: "user-1",
    iat: 1_800_000_000,
    exp: 1_800_003_600,
    email: "u@example.com",
  });
  const publicKey = createPublicKey({ key: jwksDocument(key.jwk).keys[0], format: "jwk" });
  assert.ok(
    verify(
      "sha256",
      Buffer.from(`${header}.${payload}`),
      publicKey,
      Buffer.from(signature, "base64url"),
    ),
  );
  // A header override and a foreign signing key make the negative rows.
  const other = generateSigningKey();
  const forged = signIdToken(key, claims, { header: { kid: "other" }, signWith: other.privateKey });
  const [fh, fp, fs] = forged.split(".");
  assert.equal(decode(fh).kid, "other");
  assert.ok(!verify("sha256", Buffer.from(`${fh}.${fp}`), publicKey, Buffer.from(fs, "base64url")));
});

test("the issuer publishes a discovery document and a public-only JWKS", () => {
  const key = generateSigningKey({ kid: "k1" });
  const issuer = "https://sandbox.example/oidc/run-1";
  const files = issuerFiles(issuer, key.jwk);
  assert.deepEqual(files[".well-known/openid-configuration"], discoveryDocument(issuer));
  assert.equal(files[".well-known/openid-configuration"].jwks_uri, `${issuer}/jwks.json`);
  const [published] = files["jwks.json"].keys;
  assert.deepEqual(Object.keys(published).toSorted(), ["alg", "e", "kid", "kty", "n", "use"]);
  assert.equal(published.d, undefined, "no private member is published");
});

test("private keys are written only below docs.local or the temp dir, mode 600", async () => {
  const roots = { isRepositoryRoot: (dir) => dir === "/work/repo" };
  assert.ok(isPrivateKeyLocation("/work/repo/docs.local/runs/k.pem", roots));
  assert.ok(isPrivateKeyLocation(join(tmpdir(), "k.pem"), roots));
  assert.ok(!isPrivateKeyLocation("/work/repo/conformance/k.pem", roots));
  // A docs.local below the root is tracked by git: refused.
  assert.ok(!isPrivateKeyLocation("/work/repo/conformance/docs.local/k.pem", roots));
  assert.ok(!isPrivateKeyLocation("/work/repo/docs.local", roots));
  const key = generateSigningKey();
  await assert.rejects(saveSigningKey("conformance/k.pem", key), /refusing to write a private key/);
  const dir = tempDir("fed-idp-");
  const path = join(dir, "keys", "signing.pem");
  await saveSigningKey(path, key);
  assert.equal((await stat(path)).mode & 0o777, 0o600);
  assert.match(await readFile(path, "utf8"), /BEGIN PRIVATE KEY/);
  const loaded = await loadSigningKey(path);
  assert.deepEqual(loaded.jwk, key.jwk);
  const claims = { sub: "s" };
  const token = signIdToken(loaded, claims);
  const [h, p, s] = token.split(".");
  const publicKey = createPublicKey({ key: key.jwk, format: "jwk" });
  assert.ok(verify("sha256", Buffer.from(`${h}.${p}`), publicKey, Buffer.from(s, "base64url")));
});

test("the issuer site holds only the discovery document and public keys", () => {
  const { issuerSite } = idp;
  const key = generateSigningKey({ kid: "k1" });
  const run = "a1b2c3";
  const issuer = `https://sandbox--fed-${run}-abc.web.app/oidc/${run}`;
  const { files, config } = issuerSite({ issuer, run, jwks: [key.jwk] });
  const discoveryPath = `/oidc/${run}/.well-known/openid-configuration`;
  const jwksPath = `/oidc/${run}/jwks.json`;
  assert.deepEqual(Object.keys(files).toSorted(), [discoveryPath, jwksPath]);
  const discovery = JSON.parse(files[discoveryPath]);
  assert.equal(discovery.issuer, issuer);
  assert.equal(discovery.jwks_uri, `${issuer}/jwks.json`);
  assert.deepEqual(JSON.parse(files[jwksPath]), jwksDocument(key.jwk));
  // Every published path is served as uncached JSON by a header rule that matches it.
  for (const path of Object.keys(files)) {
    const rules = config.headers.filter((rule) => matchesGlob(path, rule.glob));
    assert.equal(rules.length, 1, path);
    assert.deepEqual(rules[0].headers, {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    });
  }
  // The earlier `/oidc/<run>/**` rule would not have matched the discovery document.
  assert.ok(!matchesGlob(discoveryPath, `/oidc/${run}/**`));
  // A private JWK is published as its public members only.
  const privateJwk = {
    ...key.privateKey.export({ format: "jwk" }),
    kid: "k2",
    alg: "RS256",
    use: "sig",
  };
  const published = issuerSite({ issuer, run, jwks: [privateJwk] }).files[jwksPath];
  assert.doesNotMatch(published, /"(d|p|q|dp|dq|qi)"\s*:/);
});

test("the issuer site refuses a bad run, a foreign issuer path and any secret", () => {
  const { issuerSite, scanPublished } = idp;
  const key = generateSigningKey({ kid: "k1" });
  const site = (run, issuer, forbidden) => issuerSite({ issuer, run, jwks: [key.jwk], forbidden });
  for (const run of ["../../escape", "r1", "A1B2C3"]) {
    assert.throws(() => site(run, `https://h.web.app/oidc/${run}`), /six hex digits/, run);
  }
  assert.throws(() => site("a1b2c3", "https://h.web.app/oidc/d4e5f6"), /is not \/oidc\/a1b2c3/);
  assert.throws(() => site("a1b2c3", "https://h.web.app/oidc/a1b2c3", ["h.web"]), /sandbox secret/);
  assert.throws(() => scanPublished(`{"x":"${"AIza"}${"Sy".padEnd(35, "0")}"}`), /API key/);
  assert.throws(() => scanPublished("-----BEGIN PRIVATE KEY-----"), /private key material/);
  assert.throws(() => scanPublished('{"k": "secret"}'), /private key material/);
  assert.throws(
    () => scanPublished("number 123456789012 inside", ["123456789012"]),
    /sandbox secret/,
  );
  assert.doesNotThrow(() => scanPublished('{"kid": "k1"}', ["123456789012"]));
});
