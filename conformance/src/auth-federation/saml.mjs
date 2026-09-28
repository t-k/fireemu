// A controlled SAML identity provider for the AUTH-FEDERATION observations (owner decisions
// O1 and O5, plan H1): responses built as a small element model, canonicalized with
// exclusive XML canonicalization (without comments) by this module, and signed with an
// enveloped XML signature (RSA-SHA256, SHA-256) with Node's crypto. No XML library is used;
// the canonical form is checked byte for byte against `xmllint --exc-c14n` in the tests.
// Test tooling only; nothing here is part of fireemu.

import { createHash, sign } from "node:crypto";
import { inflateRawSync } from "node:zlib";

export const NS = {
  samlp: "urn:oasis:names:tc:SAML:2.0:protocol",
  saml: "urn:oasis:names:tc:SAML:2.0:assertion",
  ds: "http://www.w3.org/2000/09/xmldsig#",
};
const EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";

/**
 * An element: `name` is `prefix:local` or `local`; `ns` holds the namespace declarations
 * written on it (`""` for the default namespace); `attrs` are unprefixed attributes;
 * `children` are elements or strings (text).
 */
export function el(name, { ns = {}, attrs = {} } = {}, children = []) {
  return { name, ns, attrs, children: [children].flat() };
}

const prefixOf = (name) => (name.includes(":") ? name.split(":")[0] : "");

const escapeText = (text) =>
  text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\r", "&#xD;");

const escapeAttr = (value) =>
  value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll('"', "&quot;")
    .replaceAll("\t", "&#x9;")
    .replaceAll("\n", "&#xA;")
    .replaceAll("\r", "&#xD;");

/**
 * Exclusive XML canonicalization (without comments, no InclusiveNamespaces) of `node` as the
 * apex of the canonicalized subtree. `inScope` maps prefixes to the URIs declared by the
 * node's ancestors. An element renders the namespaces it visibly uses (its own prefix; its
 * attributes are unprefixed) unless its nearest output ancestor rendered the same value.
 */
export function canonicalize(node, inScope = {}, rendered = {}) {
  if (typeof node === "string") return escapeText(node);
  const scope = { ...inScope, ...node.ns };
  const prefix = prefixOf(node.name);
  const uri = scope[prefix] ?? "";
  if (prefix && !uri) throw new Error(`prefix ${prefix} of ${node.name} is not declared`);
  const renderedHere = { ...rendered };
  let decls = "";
  if ((rendered[prefix] ?? "") !== uri) {
    decls = prefix ? ` xmlns:${prefix}="${escapeAttr(uri)}"` : ` xmlns="${escapeAttr(uri)}"`;
    renderedHere[prefix] = uri;
  }
  const attrs = Object.entries(node.attrs)
    .toSorted(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([name, value]) => ` ${name}="${escapeAttr(String(value))}"`)
    .join("");
  const inner = node.children.map((child) => canonicalize(child, scope, renderedHere)).join("");
  return `<${node.name}${decls}${attrs}>${inner}</${node.name}>`;
}

/**
 * A serialization of `node` as a standalone document that is well formed but not canonical,
 * for the tests: `inherited` namespaces are declared on the root; options reorder the
 * declarations and attributes, add unused and redundant declarations, use single quotes,
 * self-close empty elements, pad tags with whitespace and write characters as references.
 */
export function serializeNoisy(node, options = {}, inherited = {}, root = true) {
  if (typeof node === "string") {
    return options.charRefs
      ? node
          .split("a")
          .map((part) => escapeText(part).replaceAll("&gt;", "&#62;").replaceAll("&#xD;", "&#13;"))
          .join("&#97;")
      : escapeText(node);
  }
  const q = options.singleQuotes ? "'" : '"';
  const quote = (value) =>
    options.singleQuotes
      ? escapeAttr(String(value)).replaceAll("&quot;", '"').replaceAll("'", "&apos;")
      : escapeAttr(String(value));
  const decls = Object.entries({
    ...(root ? inherited : {}),
    ...(options.redundant && !root ? inherited : {}),
    ...node.ns,
    ...(options.unused ? { unused: "urn:fireemu:unused" } : {}),
  });
  if (options.reverseNamespaces) decls.reverse();
  const attrs = Object.entries(node.attrs);
  if (options.reverseAttributes) attrs.reverse();
  const pad = options.padTags ? "\n\t " : " ";
  const head = [
    ...decls.map(([p, uri]) =>
      p ? `xmlns:${p}=${q}${quote(uri)}${q}` : `xmlns=${q}${quote(uri)}${q}`,
    ),
    ...attrs.map(([name, value]) => `${name}=${q}${quote(value)}${q}`),
  ]
    .map((part) => `${pad}${part}`)
    .join("");
  const scope = { ...inherited, ...node.ns };
  if (!node.children.length && options.selfClose)
    return `<${node.name}${head}${options.padTags ? " " : ""}/>`;
  const inner = node.children.map((child) => serializeNoisy(child, options, scope, false)).join("");
  return `<${node.name}${head}${options.padTags ? "\n" : ""}>${inner}</${node.name}>`;
}

/** A faithful (non-canonical only in its XML declaration) serialization of a document. */
export function serializeDocument(node) {
  return `<?xml version="1.0" encoding="UTF-8"?>${serializeNoisy(node)}`;
}

const sha256Base64 = (text) => createHash("sha256").update(text, "utf8").digest("base64");

/** The DER of a PEM certificate, base64 (the X509Certificate text). */
export function certificateBase64(pem) {
  const body = /-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/.exec(pem)?.[1];
  if (!body) throw new Error("not a PEM certificate");
  return body.replaceAll(/\s+/g, "");
}

/**
 * Signs `target` (an element with an `ID` attribute) with an enveloped signature inserted
 * as its child at `position` (after the Issuer in SAML). `inScope` is the namespaces its
 * ancestors declare. Returns the signed element and the canonical texts that were digested
 * and signed (for the tests).
 */
export function signEnveloped(target, { privateKey, certificatePem, inScope = {}, position = 1 }) {
  const id = target.attrs.ID;
  if (!id) throw new Error("the signed element has no ID");
  const digested = canonicalize(target, inScope);
  const signedInfo = el("ds:SignedInfo", {}, [
    el("ds:CanonicalizationMethod", { attrs: { Algorithm: EXC_C14N } }),
    el("ds:SignatureMethod", { attrs: { Algorithm: RSA_SHA256 } }),
    el("ds:Reference", { attrs: { URI: `#${id}` } }, [
      el("ds:Transforms", {}, [
        el("ds:Transform", { attrs: { Algorithm: ENVELOPED } }),
        el("ds:Transform", { attrs: { Algorithm: EXC_C14N } }),
      ]),
      el("ds:DigestMethod", { attrs: { Algorithm: SHA256 } }),
      el("ds:DigestValue", {}, [sha256Base64(digested)]),
    ]),
  ]);
  const signatureScope = { ...inScope, ...target.ns, ds: NS.ds };
  const signedText = canonicalize(signedInfo, signatureScope);
  const value = sign("sha256", Buffer.from(signedText, "utf8"), privateKey).toString("base64");
  const signature = el("ds:Signature", { ns: { ds: NS.ds } }, [
    signedInfo,
    el("ds:SignatureValue", {}, [value]),
    el("ds:KeyInfo", {}, [
      el("ds:X509Data", {}, [el("ds:X509Certificate", {}, [certificateBase64(certificatePem)])]),
    ]),
  ]);
  const children = [...target.children];
  children.splice(position, 0, signature);
  return { signed: { ...target, children }, digested, signedText, signatureValue: value };
}

const isoSeconds = (seconds) => new Date(seconds * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");

/** `attrs` without the members whose value is undefined or null. */
const present = (attrs) =>
  Object.fromEntries(Object.entries(attrs).filter(([, value]) => value !== undefined && value !== null));

/**
 * The Response and Assertion an IdP sends for an SP-initiated sign-in. Times are unix seconds;
 * `attributes` maps names to a string value or an array of them (one AttributeValue each).
 * Each field below departs from the default document only when given: `recipient` (the
 * destination), `conditionsNotBefore` and `conditionsNotOnOrAfter`, `confirmationNotOnOrAfter`,
 * `statusCode` (Success), `assertionIssuer` (the issuer), `nameIdFormat` (emailAddress), and
 * `inResponseTo: null` for an unsolicited response.
 */
export function samlResponse({
  responseId,
  assertionId,
  issuer,
  audience,
  destination,
  inResponseTo,
  nameId,
  now,
  lifetime = 300,
  attributes = {},
  recipient = destination,
  conditionsNotBefore = now - 60,
  conditionsNotOnOrAfter = now + lifetime,
  confirmationNotOnOrAfter = now + lifetime,
  statusCode = "urn:oasis:names:tc:SAML:2.0:status:Success",
  assertionIssuer = issuer,
  nameIdFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
}) {
  const at = isoSeconds(now);
  const assertion = el(
    "saml:Assertion",
    { ns: { saml: NS.saml }, attrs: { ID: assertionId, IssueInstant: at, Version: "2.0" } },
    [
      el("saml:Issuer", {}, [assertionIssuer]),
      el("saml:Subject", {}, [
        el("saml:NameID", { attrs: { Format: nameIdFormat } }, [nameId]),
        el(
          "saml:SubjectConfirmation",
          { attrs: { Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer" } },
          [
            el("saml:SubjectConfirmationData", {
              attrs: present({
                InResponseTo: inResponseTo,
                NotOnOrAfter: isoSeconds(confirmationNotOnOrAfter),
                Recipient: recipient,
              }),
            }),
          ],
        ),
      ]),
      el(
        "saml:Conditions",
        {
          attrs: {
            NotBefore: isoSeconds(conditionsNotBefore),
            NotOnOrAfter: isoSeconds(conditionsNotOnOrAfter),
          },
        },
        [
          el("saml:AudienceRestriction", {}, [el("saml:Audience", {}, [audience])]),
        ],
      ),
      el("saml:AuthnStatement", { attrs: { AuthnInstant: at, SessionIndex: assertionId } }, [
        el("saml:AuthnContext", {}, [
          el("saml:AuthnContextClassRef", {}, [
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
          ]),
        ]),
      ]),
      ...(Object.keys(attributes).length
        ? [
            el(
              "saml:AttributeStatement",
              {},
              Object.entries(attributes).map(([name, value]) =>
                el(
                  "saml:Attribute",
                  { attrs: { Name: name } },
                  [value].flat().map((one) => el("saml:AttributeValue", {}, [String(one)])),
                ),
              ),
            ),
          ]
        : []),
    ],
  );
  const response = el(
    "samlp:Response",
    {
      ns: { samlp: NS.samlp, saml: NS.saml },
      attrs: present({
        Destination: destination,
        ID: responseId,
        InResponseTo: inResponseTo,
        IssueInstant: at,
        Version: "2.0",
      }),
    },
    [
      el("saml:Issuer", {}, [issuer]),
      el("samlp:Status", {}, [
        el("samlp:StatusCode", { attrs: { Value: statusCode } }),
      ]),
      assertion,
    ],
  );
  return { response, assertion };
}

/**
 * A signed SAMLResponse (base64 of the document): `sign` is "assertion", "response" or
 * "both" (the assertion is signed first, so the response signature covers it).
 */
export function signedSamlResponse(
  fields,
  { privateKey, certificatePem, sign: where = "assertion" },
) {
  const { response } = samlResponse(fields);
  let signedResponse = response;
  const responseScope = {};
  if (where === "assertion" || where === "both") {
    const index = response.children.findIndex((child) => child.name === "saml:Assertion");
    const { signed } = signEnveloped(response.children[index], {
      privateKey,
      certificatePem,
      inScope: { ...responseScope, ...response.ns },
    });
    const children = [...response.children];
    children[index] = signed;
    signedResponse = { ...response, children };
  }
  if (where === "response" || where === "both") {
    signedResponse = signEnveloped(signedResponse, { privateKey, certificatePem }).signed;
  }
  const xml = serializeDocument(signedResponse);
  return { xml, base64: Buffer.from(xml, "utf8").toString("base64") };
}

/** A query parameter decoded without turning `+` into a space (base64 keeps its `+`). */
function rawParameter(url, name) {
  const found = new URL(url).search
    .slice(1)
    .split("&")
    .find((part) => part.split("=")[0] === name);
  return found === undefined ? undefined : decodeURIComponent(found.slice(name.length + 1));
}

/**
 * The AuthnRequest an `authUri` carries (HTTP-Redirect binding: raw DEFLATE, base64): its
 * `ID`, the `AssertionConsumerServiceURL` and `Issuer` it names (when present), and the
 * `RelayState` to send back.
 */
export function readAuthnRequest(authUri) {
  const encoded = rawParameter(authUri, "SAMLRequest");
  if (!encoded) throw new Error("the authUri carries no SAMLRequest");
  const xml = inflateRawSync(Buffer.from(encoded, "base64")).toString("utf8");
  const id = /\sID="([^"]+)"/.exec(xml)?.[1];
  if (!id) throw new Error("the AuthnRequest has no ID");
  return {
    xml,
    id,
    acs: /\sAssertionConsumerServiceURL="([^"]+)"/.exec(xml)?.[1],
    issuer: /<(?:[\w-]+:)?Issuer(?:\s[^>]*)?>([^<]*)<\//.exec(xml)?.[1]?.trim(),
    relayState: rawParameter(authUri, "RelayState"),
  };
}
