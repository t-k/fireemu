// Corpus of the Secure Token request-body recording (SECURETOKEN-BODY).
//
// Question: what does production answer to `POST securetoken.googleapis.com/v1/token?key=` when the
// body is JSON or form, snake_case or camelCase, or a mix of the spellings. The Firebase Android
// SDK posts JSON with camelCase `grantType` and `refreshToken`; the Web SDK posts a form with
// snake_case. Only the first and the last were ever seen from a client; the rest is the part of
// the question no recording answers yet.
//
// A row is one request: a content type and an ordered list of fields. The order is part of the
// row, because a parser that keeps the last duplicate and one that keeps the first answer
// differently only when the order differs. A value is a literal, or `{ rt: "a" }` for the refresh
// token of the corpus account `a`. The rows never name a token themselves; the session resolves
// them at send time and nothing resolved is ever written to a file.

import { createHash } from "node:crypto";

/**
 * The accounts a recording creates. `a` and `b` are project users, `t` belongs to the recording's
 * tenant. Two project users exist so that a row with two different tokens can say which one won.
 */
export const ACCOUNTS = Object.freeze({
  a: Object.freeze({ tenant: false }),
  b: Object.freeze({ tenant: false }),
  t: Object.freeze({ tenant: true }),
});

/** A string no sign-in ever issued; the same one the AUTH-CREDENTIAL malformed-token row used. */
export const INVALID_REFRESH_TOKEN = "not-a-refresh-token";

const rt = (account) => ({ rt: account });
const G = "refresh_token";

const row = (id, question, contentType, fields, extra = {}) => ({
  id,
  question,
  contentType,
  fields,
  ...extra,
});

/**
 * @type {ReadonlyArray<{id: string, question: string, contentType: "json" | "form",
 *   fields: Array<[string, unknown]>, account?: string}>}
 */
export const ROWS = Object.freeze([
  // Control rows: shapes whose answers are already recorded (form, snake_case) or the shape the
  // Web SDK uses; they say the session and the account are sound before the question rows run.
  row("form-snake", "control: the recorded Web SDK shape", "form", [
    ["grant_type", G],
    ["refresh_token", rt("a")],
  ]),
  row("json-snake", "control: the same fields as JSON", "json", [
    ["grant_type", G],
    ["refresh_token", rt("a")],
  ]),
  // The question: the Android SDK's body, and its neighbours.
  row("json-camel", "the Android SDK body: JSON with camelCase", "json", [
    ["grantType", G],
    ["refreshToken", rt("a")],
  ]),
  row("form-camel", "camelCase in a form", "form", [
    ["grantType", G],
    ["refreshToken", rt("a")],
  ]),
  row("json-mixed-snake-grant-camel-token", "grant_type with refreshToken", "json", [
    ["grant_type", G],
    ["refreshToken", rt("a")],
  ]),
  row("json-mixed-camel-grant-snake-token", "grantType with refresh_token", "json", [
    ["grantType", G],
    ["refresh_token", rt("a")],
  ]),
  row("form-mixed-snake-grant-camel-token", "grant_type with refreshToken in a form", "form", [
    ["grant_type", G],
    ["refreshToken", rt("a")],
  ]),
  // Both spellings of one field with different values: which one wins, or a refusal.
  row("json-both-tokens-snake-first", "both token spellings, snake_case first", "json", [
    ["grant_type", G],
    ["refresh_token", rt("a")],
    ["refreshToken", rt("b")],
  ]),
  row("json-both-tokens-camel-first", "both token spellings, camelCase first", "json", [
    ["grant_type", G],
    ["refreshToken", rt("b")],
    ["refresh_token", rt("a")],
  ]),
  row("form-both-tokens", "both token spellings in a form", "form", [
    ["grant_type", G],
    ["refresh_token", rt("a")],
    ["refreshToken", rt("b")],
  ]),
  row("json-both-grants-snake-first", "both grant spellings, snake_case first", "json", [
    ["grant_type", G],
    ["grantType", "password"],
    ["refresh_token", rt("a")],
  ]),
  row("json-both-grants-camel-first", "both grant spellings, camelCase first", "json", [
    ["grantType", "password"],
    ["grant_type", G],
    ["refresh_token", rt("a")],
  ]),
  row("json-snake-empty-camel-valid", "refresh_token empty, refreshToken valid", "json", [
    ["grant_type", G],
    ["refresh_token", ""],
    ["refreshToken", rt("a")],
  ]),
  // The refusals of the camelCase spelling.
  row("json-camel-invalid-token", "camelCase with a token nobody issued", "json", [
    ["grantType", G],
    ["refreshToken", INVALID_REFRESH_TOKEN],
  ]),
  row("json-snake-invalid-token", "control: the same invalid token in snake_case", "json", [
    ["grant_type", G],
    ["refresh_token", INVALID_REFRESH_TOKEN],
  ]),
  row("json-camel-wrong-grant", "camelCase with another grant type", "json", [
    ["grantType", "password"],
    ["refreshToken", rt("a")],
  ]),
  row("json-camel-no-grant", "camelCase token without a grant type", "json", [
    ["refreshToken", rt("a")],
  ]),
  row("json-camel-no-token", "camelCase grant type without a token", "json", [["grantType", G]]),
  // A tenant user's token with only the API key: the tenant is read from the token.
  row("tenant-form-snake", "control: a tenant user, recorded form shape", "form", [
    ["grant_type", G],
    ["refresh_token", rt("t")],
  ]),
  row("tenant-json-snake", "a tenant user, JSON snake_case", "json", [
    ["grant_type", G],
    ["refresh_token", rt("t")],
  ]),
  row("tenant-json-camel", "a tenant user, the Android SDK body", "json", [
    ["grantType", G],
    ["refreshToken", rt("t")],
  ]),
  row("tenant-form-camel", "a tenant user, camelCase in a form", "form", [
    ["grantType", G],
    ["refreshToken", rt("t")],
  ]),
  row(
    "tenant-json-both-tokens",
    "a project token in snake_case, a tenant token in camelCase",
    "json",
    [
      ["grant_type", G],
      ["refresh_token", rt("a")],
      ["refreshToken", rt("t")],
    ],
  ),
  // Last: the token of the first row still works, so no row above consumed or revoked it.
  row("json-snake-after", "control: the first account's token still refreshes", "json", [
    ["grant_type", G],
    ["refresh_token", rt("a")],
  ]),
]);

/** The field names a row sends, in order, and nothing that resolves to a credential. */
export function fieldNames(rowSpec) {
  return rowSpec.fields.map(([name]) => name);
}

/** The account a request value `{ rt }` refers to, if it is one. */
export const accountOf = (value) =>
  value !== null && typeof value === "object" && typeof value.rt === "string"
    ? value.rt
    : undefined;

/**
 * The request body of a row for resolved tokens: JSON keeps the field order and the duplicate
 * spellings, a form is `application/x-www-form-urlencoded`. Returns the content type and the
 * body text, whose length is recorded (never the text).
 */
export function encodeBody(rowSpec, tokens) {
  const resolved = rowSpec.fields.map(([name, value]) => {
    const account = accountOf(value);
    if (account === undefined) return [name, value];
    const token = tokens[account];
    if (typeof token !== "string" || token === "")
      throw new Error(`row ${rowSpec.id}: no refresh token for account ${account}`);
    return [name, token];
  });
  if (rowSpec.contentType === "form") {
    return {
      contentType: "application/x-www-form-urlencoded",
      body: new URLSearchParams(resolved).toString(),
    };
  }
  return {
    contentType: "application/json",
    // `Object.fromEntries` would drop a repeated name; the rows never repeat one name, only the
    // two spellings, so the object keeps every field and its order.
    body: JSON.stringify(Object.fromEntries(resolved)),
  };
}

/** Which accounts a corpus needs, as a set of the keys of `ACCOUNTS`. */
export function accountsNeeded(rows = ROWS) {
  const needed = new Set();
  for (const spec of rows)
    for (const [, value] of spec.fields) {
      const account = accountOf(value);
      if (account !== undefined) needed.add(account);
    }
  return needed;
}

const KNOWN_NAMES = new Set(["grant_type", "refresh_token", "grantType", "refreshToken"]);

/**
 * Refuses a corpus that could send anything but a refresh body: an unknown field name, a row
 * that repeats one name, a token of an account the corpus does not create, a duplicate row id.
 * Returns the number of rows.
 */
export function validateCorpus(rows = ROWS) {
  const ids = new Set();
  for (const spec of rows) {
    if (ids.has(spec.id)) throw new Error(`duplicate row ${spec.id}`);
    ids.add(spec.id);
    if (!/^[a-z0-9-]+$/.test(spec.id)) throw new Error(`row id ${spec.id} is not a slug`);
    if (!["json", "form"].includes(spec.contentType))
      throw new Error(`${spec.id}: content type must be json or form`);
    const seen = new Set();
    for (const [name, value] of spec.fields) {
      if (!KNOWN_NAMES.has(name)) throw new Error(`${spec.id}: unknown field ${name}`);
      if (seen.has(name)) throw new Error(`${spec.id}: repeats ${name}`);
      seen.add(name);
      const account = accountOf(value);
      if (account !== undefined && !Object.hasOwn(ACCOUNTS, account))
        throw new Error(`${spec.id}: unknown account ${account}`);
      if (account === undefined && typeof value !== "string")
        throw new Error(`${spec.id}: ${name} must be a string or an account token`);
    }
  }
  return rows.length;
}

const canonical = (value) => JSON.stringify(value);
export const rowDigest = (spec) => createHash("sha256").update(canonical(spec)).digest("hex");
export const corpusDigest = (rows = ROWS) =>
  createHash("sha256").update(canonical(rows)).digest("hex");
