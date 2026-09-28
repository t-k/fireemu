// Test vectors for fireemu's SAML signature verification (strict profile, owner decision O5
// stage B): responses signed by this harness's signer (whose canonical form is checked against
// xmllint), written to `crates/fireemu-adapter-http/tests/data/saml/` with the certificate that
// verifies them. The private key is made for the run and discarded; only public material and
// signed documents are written.
//
//   node src/auth-federation/saml-fixtures.mjs

import { execFileSync } from "node:child_process";
import { createPrivateKey } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { el, samlResponse, serializeDocument, serializeNoisy, signEnveloped } from "./saml.mjs";
import { tamper } from "./saml-smoke.mjs";

const OUT = fileURLToPath(
  new URL("../../../crates/fireemu-adapter-http/tests/data/saml/", import.meta.url),
);

function makeKey(dir, name) {
  const key = join(dir, `${name}.key.pem`);
  const cert = join(dir, `${name}.cert.pem`);
  execFileSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      key,
      "-out",
      cert,
      "-days",
      "36500",
      "-subj",
      `/CN=fireemu-saml-fixture-${name}`,
    ],
    { stdio: "ignore" },
  );
  return {
    privateKey: createPrivateKey(readFileSync(key, "utf8")),
    certificatePem: readFileSync(cert, "utf8"),
  };
}

const FIELDS = {
  responseId: "_response-1",
  assertionId: "_assertion-1",
  issuer: "https://idp.example.test/saml/fixture",
  audience: "fireemu-fixture-sp",
  destination: "https://demo-project.firebaseapp.com/__/auth/handler",
  inResponseTo: "_request-1",
  nameId: "fixture-user@example.com",
  now: 1_800_000_000,
  lifetime: 300,
  attributes: { role: "reader & <writer>", "display name": 'Fixture "User"' },
};

/** The response model signed at `where` ("assertion", "response" or "both"). */
function signed(key, where, fields = FIELDS) {
  const { response } = samlResponse(fields);
  let out = response;
  if (where === "assertion" || where === "both") {
    const index = out.children.findIndex((child) => child.name === "saml:Assertion");
    const { signed: assertion } = signEnveloped(out.children[index], { ...key, inScope: out.ns });
    out = { ...out, children: out.children.with(index, assertion) };
  }
  if (where === "response" || where === "both") out = signEnveloped(out, key).signed;
  return out;
}

function main() {
  const dir = mkdtempSync(join(tmpdir(), "fireemu-saml-fixtures-"));
  try {
    const key = makeKey(dir, "idp");
    const other = makeKey(dir, "other");
    mkdirSync(OUT, { recursive: true });
    const files = {
      "idp.cert.pem": key.certificatePem,
      "other.cert.pem": other.certificatePem,
    };
    for (const where of ["assertion", "response", "both"]) {
      const model = signed(key, where);
      files[`${where}-signed.xml`] = serializeDocument(model);
      // The same document written differently: the canonical form, and the signature, hold.
      files[`${where}-signed-noisy.xml`] =
        `<?xml version="1.0" encoding="UTF-8"?>\n${serializeNoisy(model, {
          reverseNamespaces: true,
          reverseAttributes: true,
          unused: true,
          redundant: true,
          singleQuotes: true,
          selfClose: true,
          padTags: true,
          charRefs: true,
        })}`;
    }
    files["tampered-signature.xml"] = tamper(serializeDocument(signed(key, "assertion")));
    // Signed, then its NameID changed: the digest no longer matches.
    files["tampered-content.xml"] = serializeDocument(signed(key, "assertion")).replace(
      "fixture-user@example.com",
      "attacker@example.com",
    );
    files["other-key.xml"] = serializeDocument(signed(other, "assertion"));
    files["unsigned.xml"] = serializeDocument(samlResponse(FIELDS).response);
    // Signature wrapping: an unsigned assertion placed before the signed one.
    const wrapped = signed(key, "assertion");
    const forged = samlResponse({
      ...FIELDS,
      assertionId: "_forged",
      nameId: "attacker@example.com",
    }).assertion;
    files["wrapped.xml"] = serializeDocument({
      ...wrapped,
      children: [wrapped.children[0], wrapped.children[1], forged, ...wrapped.children.slice(2)],
    });
    files["doctype.xml"] = serializeDocument(signed(key, "assertion")).replace(
      '<?xml version="1.0" encoding="UTF-8"?>',
      '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE samlp:Response [<!ENTITY x "y">]>',
    );
    const withoutNameId = samlResponse(FIELDS);
    const subject = withoutNameId.assertion.children.findIndex(
      (child) => child.name === "saml:Subject",
    );
    const assertionNoName = {
      ...withoutNameId.assertion,
      children: withoutNameId.assertion.children.with(subject, el("saml:Subject", {}, [])),
    };
    const responseNoName = {
      ...withoutNameId.response,
      children: withoutNameId.response.children.with(2, assertionNoName),
    };
    files["no-name-id.xml"] = serializeDocument(signEnveloped(responseNoName, key).signed);
    for (const [name, text] of Object.entries(files)) writeFileSync(join(OUT, name), text);
    console.log(`wrote ${Object.keys(files).length} files to ${OUT}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

main();
