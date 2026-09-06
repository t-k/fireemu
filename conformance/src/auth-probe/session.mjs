// Runs the Identity Toolkit programs against one side and records what it answered.
//
// The target is a base URL (`http://127.0.0.1:<port>/identitytoolkit.googleapis.com` for an
// emulator, `https://identitytoolkit.googleapis.com` for production) and an API key. Every
// `EMAIL(name)` placeholder becomes a unique address for this run at a reserved example
// domain. The recorded value is the HTTP status and the normalized body: tokens, ids, expiry
// and timestamps become placeholders; error messages (Identity Toolkit's machine-readable
// codes) are kept exactly.

import { readFile, writeFile } from "node:fs/promises";

const BASE = process.env.AUTH_PROBE_BASE;
const KEY = process.env.AUTH_PROBE_KEY ?? "fake-api-key";
const IN = process.env.AUTH_PROBE_IN;
const OUT = process.env.AUTH_PROBE_OUT;
const RUN = process.env.AUTH_PROBE_RUN ?? String(Date.now());
const TIMEOUT_MS = Number(process.env.AUTH_PROBE_TIMEOUT_MS ?? 30_000);

const email = (name) => `fireemu-auth-probe-${RUN}-${name}@example.com`;

function lookup(value, path) {
  let current = value;
  for (const segment of path.split(".")) {
    if (current === null || current === undefined) return undefined;
    current = current[segment];
  }
  return current;
}

function resolve(value, raw) {
  if (Array.isArray(value)) return value.map((v) => resolve(v, raw));
  if (value && typeof value === "object") {
    if (typeof value.$from === "string") {
      const found = lookup(raw.get(value.$from), value.path);
      if (found === undefined)
        throw new Error(`step ${value.$from} recorded nothing at ${value.path}`);
      return found;
    }
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, resolve(v, raw)]));
  }
  if (typeof value === "string") {
    return value.replaceAll(/EMAIL\(([a-z]+)\)/g, (_, name) => email(name));
  }
  return value;
}

const OPAQUE = new Set(["idToken", "refreshToken", "localId", "kind", "oobCode", "sessionInfo"]);
const INSTANT = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/;

function normalize(value, key = "") {
  if (typeof value === "string") {
    if (OPAQUE.has(key)) return `<${key}>`;
    if (key === "validSince" || key === "passwordUpdatedAt") return `<${key}>`;
    if (/^\d{13}$/.test(value) && /At$|Time$/.test(key)) return "<millis>";
    if (INSTANT.test(value)) return "<instant>";
    return value.replaceAll(/fireemu-auth-probe-\d+-/g, "fireemu-auth-probe-<run>-");
  }
  if (Array.isArray(value)) return value.map((v) => normalize(v, key));
  if (typeof value === "number" && (key === "validSince" || key === "passwordUpdatedAt")) {
    return `<${key}>`;
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .filter(
          ([k]) =>
            k !== "expiresIn" && k !== "lastLoginAt" && k !== "createdAt" && k !== "lastRefreshAt",
        )
        .map(([k, v]) => [k, normalize(v, k)]),
    );
  }
  return value;
}

async function step(spec, raw) {
  let response;
  try {
    response = await fetch(`${BASE}/${spec.path}?key=${encodeURIComponent(KEY)}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(resolve(spec.body, raw)),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (error) {
    if (error?.name === "TimeoutError" || error?.name === "AbortError") {
      return { recorded: { status: 0, code: "no-response" }, raw: null };
    }
    throw error;
  }
  const text = await response.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return { recorded: { status: response.status, code: "non-json" }, raw: null };
  }
  if (body?.error) {
    // The first word of the message is Identity Toolkit's machine-readable code; production
    // sometimes appends a human sentence after " : ".
    const message = String(body.error.message ?? "");
    return {
      recorded: {
        status: response.status,
        code: message.split(" : ")[0].split(" ")[0] || String(body.error.code ?? ""),
        message: message.slice(0, 200),
      },
      raw: body,
    };
  }
  return { recorded: { status: response.status, code: "OK", body: normalize(body) }, raw: body };
}

async function main() {
  if (!BASE || !IN || !OUT)
    throw new Error("AUTH_PROBE_BASE, AUTH_PROBE_IN and AUTH_PROBE_OUT are required");
  const programs = JSON.parse(await readFile(IN, "utf8"));
  const results = {};
  for (const program of programs) {
    const raw = new Map();
    const steps = {};
    for (const spec of program.steps) {
      let outcome;
      try {
        outcome = await step(spec, raw);
      } catch (error) {
        outcome = {
          recorded: { status: 0, code: "probe-error", message: String(error.message ?? error) },
          raw: null,
        };
      }
      raw.set(spec.id, outcome.raw);
      steps[spec.id] = outcome.recorded;
    }
    results[program.id] = { steps };
  }
  await writeFile(OUT, `${JSON.stringify(results, null, 2)}\n`);
}

await main();
