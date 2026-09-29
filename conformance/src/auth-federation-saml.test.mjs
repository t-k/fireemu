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
  assert.deepEqual(readAuthnRequest(uri), {
    xml: request,
    id: "_req-42",
    acs: undefined,
    issuer: undefined,
    relayState: "rs-1",
  });
  assert.throws(() => readAuthnRequest("https://sso.example.test/saml"), /no SAMLRequest/);
  // The ACS and Issuer it names are read; a `+` of the base64 is kept, not read as a space.
  const full =
    '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req-43" AssertionConsumerServiceURL="https://p.firebaseapp.com/__/auth/handler"><saml:Issuer>fireemu-a1b2c3-sp</saml:Issuer></samlp:AuthnRequest>';
  let deflated;
  for (let pad = 0; ; pad += 1) {
    deflated = deflateRawSync(Buffer.from(full + " ".repeat(pad))).toString("base64");
    if (deflated.includes("+")) break;
  }
  const raw = `https://sso.example.test/saml?SAMLRequest=${deflated.replaceAll("/", "%2F")}&RelayState=a%2Bb`;
  const read = readAuthnRequest(raw);
  assert.equal(read.id, "_req-43");
  assert.equal(read.acs, "https://p.firebaseapp.com/__/auth/handler");
  assert.equal(read.issuer, "fireemu-a1b2c3-sp");
  assert.equal(read.relayState, "a+b");
});

test("a prefix that is not declared is refused", () => {
  assert.throws(() => canonicalize(el("q:a")), /prefix q/);
  assert.throws(
    () => signEnveloped(el("a"), { privateKey: undefined, certificatePem: "" }),
    /no ID/,
  );
});

test("a response departs from the default only where a field asks it to", async () => {
  const { serializeDocument } = await import("./auth-federation/saml.mjs");
  const fields = {
    responseId: "_r1",
    assertionId: "_a1",
    issuer: "https://idp.example/saml",
    audience: "sp-entity",
    destination: "https://sp.example/__/auth/handler",
    inResponseTo: "_req1",
    nameId: "user@example.com",
    now: 1790000000,
    attributes: { role: "reader" },
  };
  // The defaults are the document the smoke and the Rust vectors were made with.
  assert.equal(serializeDocument(samlResponse(fields).response), "<?xml version=\"1.0\" encoding=\"UTF-8\"?><samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Destination=\"https://sp.example/__/auth/handler\" ID=\"_r1\" InResponseTo=\"_req1\" IssueInstant=\"2026-09-21T14:13:20Z\" Version=\"2.0\"><saml:Issuer>https://idp.example/saml</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"></samlp:StatusCode></samlp:Status><saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_a1\" IssueInstant=\"2026-09-21T14:13:20Z\" Version=\"2.0\"><saml:Issuer>https://idp.example/saml</saml:Issuer><saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">user@example.com</saml:NameID><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData InResponseTo=\"_req1\" NotOnOrAfter=\"2026-09-21T14:18:20Z\" Recipient=\"https://sp.example/__/auth/handler\"></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore=\"2026-09-21T14:12:20Z\" NotOnOrAfter=\"2026-09-21T14:18:20Z\"><saml:AudienceRestriction><saml:Audience>sp-entity</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant=\"2026-09-21T14:13:20Z\" SessionIndex=\"_a1\"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name=\"role\"><saml:AttributeValue>reader</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>");
  const xml = serializeDocument(
    samlResponse({
      ...fields,
      recipient: "https://other.example/acs",
      conditionsNotBefore: 1790000600,
      conditionsNotOnOrAfter: 1789999400,
      confirmationNotOnOrAfter: 1789999500,
      statusCode: "urn:oasis:names:tc:SAML:2.0:status:Requester",
      assertionIssuer: "https://other-idp.example/saml",
      nameIdFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
      attributes: { groups: ["a", "b"] },
    }).response,
  );
  for (const expected of [
    'Recipient="https://other.example/acs"',
    'NotBefore="2026-09-21T14:23:20Z"',
    '<saml:Conditions NotBefore="2026-09-21T14:23:20Z" NotOnOrAfter="2026-09-21T14:03:20Z">',
    'NotOnOrAfter="2026-09-21T14:05:00Z" Recipient=',
    'Value="urn:oasis:names:tc:SAML:2.0:status:Requester"',
    "<saml:Issuer>https://other-idp.example/saml</saml:Issuer><saml:Subject>",
    'Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"',
    '<saml:Attribute Name="groups"><saml:AttributeValue>a</saml:AttributeValue><saml:AttributeValue>b</saml:AttributeValue></saml:Attribute>',
  ]) {
    assert.ok(xml.includes(expected), `${expected} in ${xml}`);
  }
  // The response keeps the IdP's issuer; only the assertion's changes.
  assert.ok(xml.includes('Version="2.0"><saml:Issuer>https://idp.example/saml</saml:Issuer><samlp:Status>'), xml);
  // No InResponseTo at all (an IdP-initiated response).
  const unsolicited = serializeDocument(samlResponse({ ...fields, inResponseTo: null }).response);
  assert.ok(!unsolicited.includes("InResponseTo"), unsolicited);
});

test("a signature may use SHA-1 for the signature and the digest, and SHA-256 stays the default", () => {
  const { privateKey, publicKey, certificatePem } = key();
  const { response } = samlResponse(FIELDS);
  const assertion = response.children[2];
  const sha1 = signEnveloped(assertion, {
    privateKey,
    certificatePem,
    inScope: response.ns,
    algorithm: "sha1",
  });
  const [signedInfo] = sha1.signed.children[1].children;
  const [, method, reference] = signedInfo.children;
  assert.equal(method.attrs.Algorithm, "http://www.w3.org/2000/09/xmldsig#rsa-sha1");
  assert.equal(reference.children[1].attrs.Algorithm, "http://www.w3.org/2000/09/xmldsig#sha1");
  assert.equal(
    reference.children[2].children[0],
    createHash("sha1").update(sha1.digested).digest("base64"),
  );
  assert.ok(
    verify("sha1", Buffer.from(sha1.signedText), publicKey, Buffer.from(sha1.signatureValue, "base64")),
  );
  const defaultSigned = signEnveloped(assertion, { privateKey, certificatePem, inScope: response.ns });
  const [defaultInfo] = defaultSigned.signed.children[1].children;
  assert.equal(defaultInfo.children[1].attrs.Algorithm, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
  assert.equal(defaultInfo.children[2].children[1].attrs.Algorithm, "http://www.w3.org/2001/04/xmlenc#sha256");
  assert.throws(
    () => signEnveloped(assertion, { privateKey, certificatePem, inScope: response.ns, algorithm: "md5" }),
    /algorithm md5/,
  );
  // signedSamlResponse passes the choice through.
  const { xml } = signedSamlResponse(FIELDS, { privateKey, certificatePem, algorithm: "sha1" });
  assert.match(xml, /xmldsig#rsa-sha1/);
  assert.doesNotMatch(xml, /sha256/);
});

test("a response may leave out either NotOnOrAfter and keep the rest", async () => {
  const { serializeDocument } = await import("./auth-federation/saml.mjs");
  const both = serializeDocument(
    samlResponse({ ...FIELDS, conditionsNotOnOrAfter: null, confirmationNotOnOrAfter: null }).response,
  );
  assert.doesNotMatch(both, /NotOnOrAfter/);
  assert.match(both, /<saml:Conditions NotBefore="[^"]+">/);
  assert.match(both, /<saml:SubjectConfirmationData InResponseTo="_req-1" Recipient=/);
  const conditionsOnly = serializeDocument(
    samlResponse({ ...FIELDS, conditionsNotOnOrAfter: null }).response,
  );
  assert.match(conditionsOnly, /<saml:Conditions NotBefore="[^"]+">/);
  assert.match(conditionsOnly, /SubjectConfirmationData InResponseTo="_req-1" NotOnOrAfter=/);
  const confirmationOnly = serializeDocument(
    samlResponse({ ...FIELDS, confirmationNotOnOrAfter: null }).response,
  );
  assert.match(confirmationOnly, /<saml:Conditions NotBefore="[^"]+" NotOnOrAfter="[^"]+">/);
  assert.doesNotMatch(confirmationOnly, /SubjectConfirmationData[^>]*NotOnOrAfter/);
});
