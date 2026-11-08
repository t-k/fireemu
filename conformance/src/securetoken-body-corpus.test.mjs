// The Secure Token body corpus: its rows, the bodies they encode to, and the refusals of
// `validateCorpus`. The bodies are checked by field order and byte length, never by token text.

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  ACCOUNTS,
  INVALID_REFRESH_TOKEN,
  ROWS,
  accountsNeeded,
  corpusDigest,
  encodeBody,
  fieldNames,
  rowDigest,
  validateCorpus,
} from "./securetoken-body/corpus.mjs";
import { generator } from "./securetoken-body/test-support.mjs";

const TOKENS = { a: "tok-a-0001", b: "tok-b-0002", t: "tok-t-0003" };
const byId = Object.fromEntries(ROWS.map((r) => [r.id, r]));

test("the corpus validates and every row has a slug id", () => {
  assert.equal(validateCorpus(), ROWS.length);
  assert.equal(new Set(ROWS.map((r) => r.id)).size, ROWS.length);
});

test("the corpus covers the seven questions of the assignment", () => {
  const need = [
    "json-camel", // JSON camelCase
    "json-snake", // JSON snake_case
    "form-snake", // form snake_case (control)
    "form-camel", // form camelCase
    "json-both-tokens-snake-first", // both spellings, different values
    "json-both-tokens-camel-first",
    "json-camel-invalid-token", // camelCase with an invalid token
    "tenant-json-camel", // a tenant user, only ?key=
  ];
  for (const id of need) assert.ok(byId[id], id);
  assert.equal(byId["json-camel"].contentType, "json");
  assert.equal(byId["form-camel"].contentType, "form");
  assert.deepEqual(fieldNames(byId["json-camel"]), ["grantType", "refreshToken"]);
  assert.deepEqual(fieldNames(byId["tenant-json-camel"]), ["grantType", "refreshToken"]);
  assert.equal(byId["tenant-json-camel"].fields[1][1].rt, "t");
});

test("the two-token rows differ by the order of the spellings and use two accounts", () => {
  const first = byId["json-both-tokens-snake-first"].fields.map(([n]) => n);
  const second = byId["json-both-tokens-camel-first"].fields.map(([n]) => n);
  assert.deepEqual(first, ["grant_type", "refresh_token", "refreshToken"]);
  assert.deepEqual(second, ["grant_type", "refreshToken", "refresh_token"]);
  const accounts = (row) => row.fields.map(([, v]) => v?.rt).filter(Boolean);
  assert.deepEqual(accounts(byId["json-both-tokens-snake-first"]), ["a", "b"]);
  assert.deepEqual(accounts(byId["json-both-tokens-camel-first"]), ["b", "a"]);
});

test("a JSON body keeps the field order and both spellings", () => {
  const encoded = encodeBody(byId["json-both-tokens-camel-first"], TOKENS);
  assert.equal(encoded.contentType, "application/json");
  assert.equal(
    encoded.body,
    '{"grant_type":"refresh_token","refreshToken":"tok-b-0002","refresh_token":"tok-a-0001"}',
  );
  assert.deepEqual(Object.keys(JSON.parse(encoded.body)), [
    "grant_type",
    "refreshToken",
    "refresh_token",
  ]);
});

test("a form body is urlencoded and the empty token is sent as an empty value", () => {
  const encoded = encodeBody(byId["form-camel"], TOKENS);
  assert.equal(encoded.contentType, "application/x-www-form-urlencoded");
  assert.equal(encoded.body, "grantType=refresh_token&refreshToken=tok-a-0001");
  assert.equal(
    encodeBody(byId["json-snake-empty-camel-valid"], TOKENS).body,
    '{"grant_type":"refresh_token","refresh_token":"","refreshToken":"tok-a-0001"}',
  );
  assert.ok(
    encodeBody(byId["json-camel-invalid-token"], TOKENS).body.includes(INVALID_REFRESH_TOKEN),
  );
});

test("a row whose account has no token cannot be encoded", () => {
  assert.throws(() => encodeBody(byId["json-camel"], { b: "x" }), /no refresh token for account a/);
  assert.throws(() => encodeBody(byId["json-camel"], { a: "" }), /no refresh token/);
});

test("the corpus needs exactly the accounts of ACCOUNTS", () => {
  assert.deepEqual([...accountsNeeded()].toSorted(), Object.keys(ACCOUNTS).toSorted());
  assert.deepEqual([...accountsNeeded([byId["json-camel"]])], ["a"]);
});

test("a corpus with an unreviewed field, a repeat or a stranger account is refused", () => {
  const row = (fields, extra = {}) => ({
    id: "x",
    question: "q",
    contentType: "json",
    fields,
    ...extra,
  });
  assert.throws(() => validateCorpus([row([["scope", "a"]])]), /unknown field/);
  assert.throws(
    () =>
      validateCorpus([
        row([
          ["grantType", "a"],
          ["grantType", "b"],
        ]),
      ]),
    /repeats/,
  );
  assert.throws(() => validateCorpus([row([["refreshToken", { rt: "z" }]])]), /unknown account/);
  assert.throws(() => validateCorpus([row([["refreshToken", 7]])]), /must be a string/);
  assert.throws(() => validateCorpus([row([], { contentType: "xml" })]), /json or form/);
  assert.throws(() => validateCorpus([row([]), row([])]), /duplicate row/);
  assert.throws(() => validateCorpus([row([], { id: "Bad Id" })]), /slug/);
});

test("digests are stable, differ per row and change with any row change", () => {
  assert.equal(corpusDigest(), corpusDigest());
  assert.equal(new Set(ROWS.map(rowDigest)).size, ROWS.length);
  const changed = ROWS.map((r, i) => (i === 0 ? { ...r, question: "other" } : r));
  assert.notEqual(corpusDigest(changed), corpusDigest());
});

test("property: encoding keeps every field in order, and no token appears in the row spec", () => {
  const rng = generator(0x5eed);
  for (let round = 0; round < 300; round += 1) {
    const spec = rng.pick(ROWS);
    const tokens = Object.fromEntries(
      Object.keys(ACCOUNTS).map((k) => [k, `tok-${k}-${rng.int(1e9).toString(36)}`]),
    );
    const { body, contentType } = encodeBody(spec, tokens);
    const names =
      contentType === "application/json"
        ? Object.keys(JSON.parse(body))
        : [...new URLSearchParams(body).keys()];
    assert.deepEqual(names, fieldNames(spec), spec.id);
    for (const token of Object.values(tokens)) assert.ok(!JSON.stringify(spec).includes(token));
  }
});

// The rows as the assignment and the review describe them, written out independently of corpus.mjs:
// id, content type, then name=value pairs in order (an account token is `<account>`).
const EXPECTED = {
  "form-snake": ["form", "grant_type=refresh_token", "refresh_token=<a>"],
  "json-snake": ["json", "grant_type=refresh_token", "refresh_token=<a>"],
  "json-camel": ["json", "grantType=refresh_token", "refreshToken=<a>"],
  "form-camel": ["form", "grantType=refresh_token", "refreshToken=<a>"],
  "json-mixed-snake-grant-camel-token": ["json", "grant_type=refresh_token", "refreshToken=<a>"],
  "json-mixed-camel-grant-snake-token": ["json", "grantType=refresh_token", "refresh_token=<a>"],
  "form-mixed-snake-grant-camel-token": ["form", "grant_type=refresh_token", "refreshToken=<a>"],
  "json-both-tokens-snake-first": [
    "json",
    "grant_type=refresh_token",
    "refresh_token=<a>",
    "refreshToken=<b>",
  ],
  "json-both-tokens-camel-first": [
    "json",
    "grant_type=refresh_token",
    "refreshToken=<b>",
    "refresh_token=<a>",
  ],
  "form-both-tokens": ["form", "grant_type=refresh_token", "refresh_token=<a>", "refreshToken=<b>"],
  "json-both-grants-snake-first": [
    "json",
    "grant_type=refresh_token",
    "grantType=password",
    "refresh_token=<a>",
  ],
  "json-both-grants-camel-first": [
    "json",
    "grantType=password",
    "grant_type=refresh_token",
    "refresh_token=<a>",
  ],
  "json-snake-empty-camel-valid": [
    "json",
    "grant_type=refresh_token",
    "refresh_token=",
    "refreshToken=<a>",
  ],
  "json-camel-invalid-token": [
    "json",
    "grantType=refresh_token",
    "refreshToken=not-a-refresh-token",
  ],
  "json-snake-invalid-token": [
    "json",
    "grant_type=refresh_token",
    "refresh_token=not-a-refresh-token",
  ],
  "json-camel-wrong-grant": ["json", "grantType=password", "refreshToken=<a>"],
  "json-camel-no-grant": ["json", "refreshToken=<a>"],
  "json-camel-no-token": ["json", "grantType=refresh_token"],
  "tenant-form-snake": ["form", "grant_type=refresh_token", "refresh_token=<t>"],
  "tenant-json-snake": ["json", "grant_type=refresh_token", "refresh_token=<t>"],
  "tenant-json-camel": ["json", "grantType=refresh_token", "refreshToken=<t>"],
  "tenant-form-camel": ["form", "grantType=refresh_token", "refreshToken=<t>"],
  "tenant-json-both-tokens": [
    "json",
    "grant_type=refresh_token",
    "refresh_token=<a>",
    "refreshToken=<t>",
  ],
  "json-snake-after": ["json", "grant_type=refresh_token", "refresh_token=<a>"],
};

test("every row is exactly the request the assignment names, in the order written", () => {
  const written = Object.fromEntries(
    ROWS.map((spec) => [
      spec.id,
      [
        spec.contentType,
        ...spec.fields.map(
          ([name, value]) => `${name}=${value?.rt === undefined ? value : `<${value.rt}>`}`,
        ),
      ],
    ]),
  );
  assert.deepEqual(written, EXPECTED);
  assert.deepEqual(Object.keys(written), Object.keys(EXPECTED));
});

test("every row says what it asks, and the accounts are the project's and the tenant's", () => {
  for (const spec of ROWS) {
    assert.equal(typeof spec.question, "string", spec.id);
    assert.ok(spec.question.length >= 10, spec.id);
  }
  assert.equal(new Set(ROWS.map((r) => r.question)).size, ROWS.length);
  assert.deepEqual(ACCOUNTS, { a: { tenant: false }, b: { tenant: false }, t: { tenant: true } });
  assert.ok(Object.isFrozen(ACCOUNTS) && Object.isFrozen(ROWS));
});
