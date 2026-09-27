import assert from "node:assert/strict";
import { createPublicKey, verify } from "node:crypto";
import { mkdtemp, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

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
    verify("sha256", Buffer.from(`${header}.${payload}`), publicKey, Buffer.from(signature, "base64url")),
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
  assert.ok(isPrivateKeyLocation("/Users/x/repo/docs.local/runs/k.pem"));
  assert.ok(isPrivateKeyLocation(join(tmpdir(), "k.pem")));
  assert.ok(!isPrivateKeyLocation("/Users/x/repo/conformance/k.pem"));
  const key = generateSigningKey();
  await assert.rejects(saveSigningKey("conformance/k.pem", key), /refusing to write a private key/);
  const dir = await mkdtemp(join(tmpdir(), "fed-idp-"));
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
