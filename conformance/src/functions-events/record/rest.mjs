// The recorder's REST transport: resolves placeholders, adds the credential, checks the destination
// guard, sends once (a mutation is never retried), stores the raw answer privately and says what kind
// of answer it was. It does not judge: an unexpected status is recorded, never an error.

import { createHash } from "node:crypto";
import { appendFileSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { destination } from "./guard.mjs";
import { PROJECT } from "./script.mjs";

export const TIMEOUT_MS = 60_000;
export const MAX_BODY_BYTES = 1024 * 1024;
export const TOKEN_LIFETIME_MS = 50 * 60 * 1000;

export class GuardRefused extends Error {}
export class BudgetExhausted extends Error {}

/** `unknown` is the answer class a change may not be settled on: no answer, a timeout, a redirect, below 200, 5xx, an unreadable body. */
export function classify({ status, error, bodyReadable }) {
  if (error) return "unknown";
  if (!Number.isInteger(status) || status < 200 || (status >= 300 && status < 400) || status >= 500)
    return "unknown";
  if (!bodyReadable) return "unknown";
  return status < 300 ? "success" : "refusal";
}

export function resolveText(text, vars) {
  return text.replace(/\$\{(\w+)\}/g, (match, name) => {
    if (!(name in vars)) throw new Error(`placeholder ${name} has no value`);
    return String(vars[name]);
  });
}

function resolveDeep(value, vars) {
  if (typeof value === "string") return resolveText(value, vars);
  if (Array.isArray(value)) return value.map((item) => resolveDeep(item, vars));
  if (value && typeof value === "object")
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, resolveDeep(v, vars)]));
  return value;
}

/** `$.a.b`, `$[0].c`, `$.list[0]` against parsed JSON; undefined when absent. */
export function pick(json, path) {
  let current = json;
  for (const part of path.replace(/^\$/, "").match(/\.[A-Za-z_][A-Za-z0-9_]*|\[\d+\]/g) ?? []) {
    if (current === null || current === undefined) return undefined;
    current = part.startsWith("[") ? current[Number(part.slice(1, -1))] : current[part.slice(1)];
  }
  return current;
}

const SECRET_KEYS = new Set([
  "idToken",
  "refreshToken",
  "access_token",
  "refresh_token",
  "id_token",
]);
const mask = (value) =>
  Array.isArray(value)
    ? value.map(mask)
    : value && typeof value === "object"
      ? Object.fromEntries(
          Object.entries(value).map(([k, v]) => [k, SECRET_KEYS.has(k) ? "<masked>" : mask(v)]),
        )
      : value;

/**
 * `createTransport({ fetch, token, apiKey, directory, ceiling, now })`: `token()` returns the OAuth
 * access token, `apiKey` the browser key for the two client sign-in calls, `directory` the private
 * run directory (mode 700) the journal and the raw answers go to, `ceiling` the most requests the
 * run may send.
 */
export function createTransport({
  fetch: send = fetch,
  token,
  apiKey,
  directory,
  ceiling,
  now = () => Date.now(),
  onSent = () => {},
}) {
  mkdirSync(join(directory, "responses"), { recursive: true, mode: 0o700 });
  const journal = join(directory, "journal.jsonl");
  const state = { sent: 0, refused: 0, sequence: 0, vars: {}, ceiling };
  const line = (entry) => appendFileSync(journal, `${JSON.stringify(entry)}\n`, { mode: 0o600 });

  async function request(spec, extraVars = {}) {
    const vars = { ...state.vars, ...extraVars };
    if (spec.when && !(spec.when in vars)) {
      line({
        ts: new Date(now()).toISOString(),
        id: spec.id,
        state: "skipped",
        reason: `${spec.when} has no value`,
      });
      return { id: spec.id, skipped: true };
    }
    const resolved = { ...spec, url: resolveText(spec.url, vars) };
    const answer = destination({
      method: resolved.method,
      url: resolved.url,
      mutation: resolved.mutation,
    });
    if (answer.problem) {
      state.refused += 1;
      line({
        ts: new Date(now()).toISOString(),
        id: spec.id,
        state: "refused-before-send",
        problem: answer.problem,
      });
      throw new GuardRefused(`${spec.id}: ${answer.problem}`);
    }
    if (state.sent >= state.ceiling) {
      line({
        ts: new Date(now()).toISOString(),
        id: spec.id,
        state: "refused-before-send",
        problem: "request ceiling reached",
      });
      throw new BudgetExhausted(`${spec.id}: the ceiling of ${state.ceiling} requests is used`);
    }
    const headers = { accept: "application/json", ...resolved.headers };
    let url = resolved.url;
    // The owner's credential is quota-checked against the sandbox project, not the gcloud login's
    // client project; which destinations take the header is decided per rule in guard.mjs.
    if (resolved.auth === "oauth") {
      headers.authorization = `Bearer ${await token()}`;
      if (answer.quotaProject) headers["x-goog-user-project"] = PROJECT;
    } else if (resolved.auth === "idtoken")
      headers.authorization = `Bearer ${resolveText("${idToken}", vars)}`;
    else if (resolved.auth === "apikey")
      url += `${url.includes("?") ? "&" : "?"}key=${encodeURIComponent(apiKey)}`;
    // auth "none" (the token refresh itself) sends no credential header.
    let body;
    if (resolved.body !== undefined) {
      if (resolved.contentType) {
        headers["content-type"] = resolved.contentType;
        body = String(resolved.body);
      } else {
        headers["content-type"] = "application/json";
        body = JSON.stringify(resolveDeep(resolved.body, vars));
      }
    }
    const sequence = (state.sequence += 1);
    const startedAt = now();
    line({
      ts: new Date(startedAt).toISOString(),
      seq: sequence,
      id: spec.id,
      state: "before-send",
      method: resolved.method,
      url: resolved.url,
      mutation: resolved.mutation,
      bodySha256: body === undefined ? null : createHash("sha256").update(body).digest("hex"),
    });
    state.sent += 1;
    onSent(spec);
    let status;
    let text = "";
    let error;
    let bodyReadable = true;
    try {
      const response = await send(url, {
        method: resolved.method,
        headers,
        body,
        redirect: "manual",
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      status = response.status;
      const buffer = Buffer.from(await response.arrayBuffer());
      if (buffer.length > MAX_BODY_BYTES) bodyReadable = false;
      text = buffer.subarray(0, MAX_BODY_BYTES).toString("utf8");
    } catch (caught) {
      error = caught?.name ?? "Error";
    }
    let json;
    if (text) {
      try {
        json = JSON.parse(text);
      } catch {
        if (status >= 200 && status < 300 && resolved.method !== "DELETE") bodyReadable = false;
      }
    }
    const kind = classify({ status, error, bodyReadable });
    const file = `${String(sequence).padStart(4, "0")}-${spec.id}.json`;
    writeFileSync(
      join(directory, "responses", file),
      `${JSON.stringify({ id: spec.id, status: status ?? null, error: error ?? null, bytes: Buffer.byteLength(text), body: json === undefined ? text : mask(json) })}\n`,
      { mode: 0o600 },
    );
    for (const [name, path] of Object.entries(spec.capture ?? {})) {
      const value = json === undefined ? undefined : pick(json, path);
      if (value !== undefined && value !== null && kind === "success") state.vars[name] = value;
    }
    line({
      ts: new Date(now()).toISOString(),
      seq: sequence,
      id: spec.id,
      state: "response-persisted",
      status: status ?? null,
      error: error ?? null,
      kind,
      bytes: Buffer.byteLength(text),
      durationMs: now() - startedAt,
      expected: status === undefined ? false : spec.expect.includes(status),
      file,
    });
    return {
      id: spec.id,
      status,
      kind,
      json,
      text,
      expected: status === undefined ? false : spec.expect.includes(status),
      file,
    };
  }

  return {
    request,
    state,
    line,
    setCeiling: (n) => {
      state.ceiling = n;
    },
  };
}
