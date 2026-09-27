import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync, verify } from "node:crypto";
import { test } from "node:test";
import { deflateRawSync } from "node:zlib";

import {
  canonicalize,
  el,
  NS,
  readAuthnRequest,
  samlResponse,
  serializeNoisy,
  signedSamlResponse,
  signEnveloped,
} from "./auth-federation/saml.mjs";

/** `xmllint --exc-c14n` of a document, or undefined when xmllint is not installed. */
function xmllint(xml) {
  try {
    return execFileSync("xmllint", ["--exc-c14n", "-"], { input: xml }).toString("utf8");
  } catch (error) {
    if (error.code === "ENOENT") return undefined;
    throw new Error(`xmllint refused the document: ${error.stderr}\n${xml}`, { cause: error });
  }
}
const HAVE_XMLLINT = xmllint("<a/>") !== undefined;

const NOISE = {
  plain: {},
  "namespaces reversed": { reverseNamespaces: true },
  "attributes reversed": { reverseAttributes: true },
  "unused and redundant declarations": { unused: true, redundant: true },
  "single quotes, self-closed, padded tags": { singleQuotes: true, selfClose: true, padTags: true },
  "character references": { charRefs: true },
  everything: {
    reverseNamespaces: true,
    reverseAttributes: true,
    unused: true,
    redundant: true,
    singleQuotes: true,
    selfClose: true,
    padTags: true,
    charRefs: true,
  },
};

/** Each noisy serialization of `node` canonicalizes (by xmllint) to our canonical form. */
function assertMatchesXmllint(node, inScope, what) {
  const ours = canonicalize(node, inScope);
  for (const [name, options] of Object.entries(NOISE)) {
    const document = serializeNoisy(node, options, inScope);
    assert.equal(xmllint(document), ours, `${what}, ${name}:\n${document}`);
  }
  return ours;
}

const FIELDS = {
  responseId: "_r1",
  assertionId: "_a1",
  issuer: "https://idp.example.test/saml/a1b2c3",
  audience: "fireemu-a1b2c3-sp",
  destination: "https://sandbox.firebaseapp.com/__/auth/handler",
  inResponseTo: "_req-1",
  nameId: "fireemu-fed-a1b2c3@example.com",
  now: 1_800_000_000,
  attributes: { role: "reader & <writer>", "display name": 'A "quoted"\tname' },
};

function key() {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  // The certificate text is carried, not parsed, by the signer.
  const certificatePem = "-----BEGIN CERTIFICATE-----\nMIIBfake\nAA==\n-----END CERTIFICATE-----";
  return { privateKey, publicKey, certificatePem };
}

test(
  "exclusive canonicalization matches xmllint on noisy serializations",
  { skip: !HAVE_XMLLINT },
  () => {
    const { response, assertion } = samlResponse(FIELDS);
    assertMatchesXmllint(response, {}, "response");
    assertMatchesXmllint(
      assertion,
      { samlp: NS.samlp, saml: NS.saml },
      "assertion in the response",
    );
    // Whitespace between elements is content; whitespace and controls in values are escaped.
    const spaced = el(
      "x:root",
      { ns: { x: "urn:x", "": "urn:default" }, attrs: { b: "1\t2\n3\r4", a: '<&">' } },
      [
        "\n  ",
        el("child", { attrs: { z: "", y: "'" } }, ["a & b < c > d\r\n"]),
        "\n  ",
        el("x:empty"),
        el("other", { ns: { "": "" } }, ["undeclared default"]),
        "\n",
      ],
    );
    assertMatchesXmllint(spaced, {}, "whitespace and escaping");
    // A default namespace used below a prefixed apex is rendered where it is used.
    assertMatchesXmllint(
      el("p:a", { ns: { p: "urn:p", "": "urn:d" } }, [el("b", {}, [el("p:c")])]),
      {},
      "default below prefix",
    );
  },
);

test(
  "the enveloped signature digests and signs the canonical forms xmllint produces",
  { skip: !HAVE_XMLLINT },
  () => {
    const { privateKey, publicKey, certificatePem } = key();
    const { response } = samlResponse(FIELDS);
    const assertion = response.children[2];
    const inScope = response.ns;
    const { signed, digested, signedText, signatureValue } = signEnveloped(assertion, {
      privateKey,
      certificatePem,
      inScope,
    });
    // The digest covers the assertion without its signature, as xmllint canonicalizes it.
    assert.equal(digested, assertMatchesXmllint(assertion, inScope, "assertion"));
    const signature = signed.children[1];
    assert.equal(signature.name, "ds:Signature");
    assert.equal(signed.children[0].name, "saml:Issuer", "the signature follows the Issuer");
    const [signedInfo] = signature.children;
    const reference = signedInfo.children[2];
    assert.equal(reference.attrs.URI, "#_a1");
    assert.equal(
      reference.children[2].children[0],
      createHash("sha256").update(digested).digest("base64"),
    );
    // SignedInfo is canonicalized as the apex, with the ds namespace it inherits.
    const signedInfoScope = { ...inScope, ...assertion.ns, ds: NS.ds };
    assert.equal(signedText, assertMatchesXmllint(signedInfo, signedInfoScope, "SignedInfo"));
    assert.ok(
      verify("sha256", Buffer.from(signedText), publicKey, Buffer.from(signatureValue, "base64")),
    );
    // One changed byte of the signed text no longer verifies.
    assert.ok(
      !verify(
        "sha256",
        Buffer.from(signedText.replace("#_a1", "#_a2")),
        publicKey,
        Buffer.from(signatureValue, "base64"),
      ),
    );
  },
);

test(
  "a signed SAMLResponse is a well-formed document in each signature position",
  { skip: !HAVE_XMLLINT },
  () => {
    const { privateKey, certificatePem } = key();
    for (const where of ["assertion", "response", "both"]) {
      const { xml, base64 } = signedSamlResponse(FIELDS, {
        privateKey,
        certificatePem,
        sign: where,
      });
      assert.equal(Buffer.from(base64, "base64").toString("utf8"), xml);
      assert.ok(xmllint(xml), where);
      const signatures = xml.match(/<ds:Signature /g) ?? [];
      assert.equal(signatures.length, where === "both" ? 2 : 1, where);
      assert.match(xml, new RegExp(`URI="#${where === "response" ? "_r1" : "_a1"}"`), where);
      assert.doesNotMatch(xml, /PRIVATE KEY/);
    }
  },
);

test("the AuthnRequest of an authUri gives its ID and RelayState", () => {
  const request =
    '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_req-42" Version="2.0"/>';
  const encoded = deflateRawSync(Buffer.from(request)).toString("base64");
  const uri = `https://sso.example.test/saml?SAMLRequest=${encodeURIComponent(encoded)}&RelayState=rs-1`;
  assert.deepEqual(readAuthnRequest(uri), { xml: request, id: "_req-42", relayState: "rs-1" });
  assert.throws(() => readAuthnRequest("https://sso.example.test/saml"), /no SAMLRequest/);
});

test("a prefix that is not declared is refused", () => {
  assert.throws(() => canonicalize(el("q:a")), /prefix q/);
  assert.throws(
    () => signEnveloped(el("a"), { privateKey: undefined, certificatePem: "" }),
    /no ID/,
  );
});
