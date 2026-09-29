// A controlled test identity provider for the AUTH-FEDERATION observations: signing keys made
// per campaign, OpenID Connect ID tokens signed with them, and the discovery document and JWKS
// an issuer publishes. Test tooling only; nothing here is part of fireemu.
//
// Private keys never enter the repository: they are written only below a `docs.local/`
// directory or the system temporary directory, owner-readable only (mode 600).

import { createPrivateKey, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";

import { checkRun } from "./guard.mjs";

const base64url = (input) => Buffer.from(input).toString("base64url");

/** A fresh RS256 signing key and its public JWK (with a random `kid`). */
export function generateSigningKey({ modulusLength = 2048, kid } = {}) {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength });
  const jwk = {
    ...publicKey.export({ format: "jwk" }),
    kid: kid ?? randomBytes(8).toString("hex"),
    alg: "RS256",
    use: "sig",
  };
  return { privateKey, jwk };
}

/**
 * Whether `path` may hold private key material: below the `docs.local/` of a repository root
 * (a directory holding `.git`, which ignores `/docs.local/`) or the temp directory. A
 * `docs.local` deeper in the tree is not ignored by git and is refused.
 */
export function isPrivateKeyLocation(
  path,
  { isRepositoryRoot = (dir) => existsSync(join(dir, ".git")) } = {},
) {
  const absolute = resolve(path);
  const temp = resolve(tmpdir());
  const parts = absolute.split(sep);
  const index = parts.indexOf("docs.local");
  return (
    (index > 0 &&
      index < parts.length - 1 &&
      isRepositoryRoot(parts.slice(0, index).join(sep) || sep)) ||
    absolute === temp ||
    absolute.startsWith(`${temp}${sep}`) ||
    absolute.startsWith(`/private/tmp${sep}`) ||
    absolute.startsWith(`/tmp${sep}`)
  );
}

/** Writes a signing key (private PEM, mode 600) and its public JWK beside it. */
export async function saveSigningKey(path, { privateKey, jwk }) {
  if (!isPrivateKeyLocation(path)) {
    throw new Error(`refusing to write a private key outside docs.local or the temp dir: ${path}`);
  }
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  await writeFile(`${path}.jwk.json`, `${JSON.stringify(jwk)}\n`, { mode: 0o600 });
}

/** Reads a signing key saved by `saveSigningKey`. */
export async function loadSigningKey(path) {
  const privateKey = createPrivateKey(await readFile(path, "utf8"));
  const jwk = JSON.parse(await readFile(`${path}.jwk.json`, "utf8"));
  return { privateKey, jwk };
}

/**
 * A compact RS256 JWS over `claims`. `header` overrides or adds header members (a wrong `kid`
 * or `alg` for the negative rows); `signWith` signs with another key than the named one.
 */
export function signIdToken({ privateKey, jwk }, claims, { header = {}, signWith } = {}) {
  const protectedHeader = { alg: "RS256", typ: "JWT", kid: jwk.kid, ...header };
  const input = `${base64url(JSON.stringify(protectedHeader))}.${base64url(JSON.stringify(claims))}`;
  const signature = sign("sha256", Buffer.from(input), signWith ?? privateKey);
  return `${input}.${signature.toString("base64url")}`;
}

/** OpenID Connect claims for an ID token of `issuer` for `clientId`, times from `now` (s). */
export function idTokenClaims({ issuer, clientId, subject, now, lifetime = 3600, ...extra }) {
  return {
    iss: issuer,
    aud: clientId,
    sub: subject,
    iat: now,
    exp: now + lifetime,
    ...extra,
  };
}

/**
 * The discovery document an issuer serves at `/.well-known/openid-configuration`, with
 * `scopes_supported` when a corpus names them (record-followup).
 */
export function discoveryDocument(issuer, { scopes } = {}) {
  return {
    issuer,
    jwks_uri: `${issuer}/jwks.json`,
    authorization_endpoint: `${issuer}/authorize`,
    response_types_supported: ["id_token"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    ...(scopes ? { scopes_supported: scopes } : {}),
  };
}

/** The JWKS document of the given public keys. */
export function jwksDocument(...jwks) {
  return { keys: jwks.map(({ kty, n, e, kid, alg, use }) => ({ kty, n, e, kid, alg, use })) };
}

/** The files an issuer publishes, keyed by their path below the issuer URL. */
export function issuerFiles(issuer, ...jwks) {
  return {
    ".well-known/openid-configuration": discoveryDocument(issuer),
    "jwks.json": jwksDocument(...jwks),
  };
}

/** Text that must never be published: private key material, an API key, or `forbidden`. */
export function scanPublished(text, forbidden = []) {
  if (/PRIVATE KEY|"(d|p|q|dp|dq|qi|oth|k)"\s*:/.test(text)) {
    throw new Error("refusing to publish private key material");
  }
  if (/AIza[0-9A-Za-z_-]{20,}/.test(text)) throw new Error("refusing to publish an API key");
  for (const secret of forbidden) {
    if (secret && text.includes(String(secret)))
      throw new Error("refusing to publish a sandbox secret");
  }
}

/**
 * What a Hosting preview channel serves for the issuer path `/oidc/<run>`: exactly the
 * discovery document and the JWKS (public members only), keyed by their URL path, and the
 * version config that serves each of them, named by its literal path, as uncached JSON. (A
 * `**` glob does not match the dot segment `.well-known`.)
 */
export function issuerSite({ issuer, run, jwks, forbidden = [], scopes }) {
  const base = `/oidc/${checkRun(run)}`;
  if (new URL(issuer).pathname !== base) throw new Error(`issuer ${issuer} is not ${base}`);
  const files = {
    [`${base}/.well-known/openid-configuration`]: `${JSON.stringify(discoveryDocument(issuer, { scopes }), null, 2)}\n`,
    [`${base}/jwks.json`]: `${JSON.stringify(jwksDocument(...jwks), null, 2)}\n`,
  };
  for (const text of Object.values(files)) scanPublished(text, forbidden);
  const config = {
    headers: Object.keys(files).map((glob) => ({
      glob,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
    })),
  };
  return { files, config };
}
