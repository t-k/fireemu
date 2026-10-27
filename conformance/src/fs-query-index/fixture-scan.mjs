// The last check before the committed fixture is written: it must not contain a secret, the
// sandbox project id in any encoding, or an access token. Kept outside the harness digest so a
// stricter scan never makes saved rows stale.

import { readFile } from "node:fs/promises";

const TOKEN = /\bya29\.[A-Za-z0-9_-]{10,}/;
/** A numeric project name, as ErrorInfo `consumer` and quota messages carry it. */
const PROJECT_NUMBER = /projects\/\d{6,}|project_number\W{0,3}\d{6,}/;
/** The domain of an email address: dot-separated labels, at least two. */
const DOMAIN = /[\w-]+(?:\.[\w-]+)+/y;
const LOCAL_CHAR = /[\w.+-]/;

/**
 * Whether the text holds `local@domain.tld`, as `/[\w.+-]+@[\w-]+(\.[\w-]+)+/` finds it. That
 * pattern retries every start of a long word run, so a megabyte document took minutes; here each
 * `@` is looked at once, with the character before it and the domain after it.
 */
export function hasEmail(text) {
  for (let at = text.indexOf("@"); at !== -1; at = text.indexOf("@", at + 1)) {
    if (at === 0 || !LOCAL_CHAR.test(text[at - 1])) continue;
    DOMAIN.lastIndex = at + 1;
    if (DOMAIN.test(text)) return true;
  }
  return false;
}

function encodings(secret) {
  const bytes = Buffer.from(secret, "latin1");
  const forms = new Set([secret]);
  // Every base64 alignment of the secret, as it could appear inside an encoded blob.
  for (const pad of [0, 1, 2]) {
    const shifted = Buffer.concat([Buffer.alloc(pad), bytes]).toString("base64");
    const stable = shifted.slice(Math.ceil((pad * 4) / 3) + 1, -4);
    if (stable.length >= 8) {
      forms.add(stable);
      forms.add(stable.replaceAll("+", "-").replaceAll("/", "_"));
    }
  }
  return [...forms];
}

/**
 * Refuses the private fixture of a stopped run (`fixture.partial.json`: `partial: true`, and a
 * program finished by one recording has `recordings: 1` and no `second`, so it would pass for a
 * deterministic row) wherever a committed fixture is read.
 */
export function assertCompleteFixture(fixture, path) {
  const programs = Object.values(fixture.programs ?? {});
  if (fixture.partial !== undefined || programs.some((p) => p.recordings !== undefined)) {
    throw new Error(`${path} is the partial fixture of a stopped run, not a committed fixture`);
  }
  return fixture;
}

/** A committed fixture and its text, refused when it is a partial one. */
export async function loadCommittedFixture(path) {
  const text = await readFile(path, "utf8");
  return { fixture: assertCompleteFixture(JSON.parse(text), path), text };
}

export function scanFixture(text, secrets) {
  if (TOKEN.test(text)) throw new Error("fixture contains an access token");
  if (PROJECT_NUMBER.test(text)) throw new Error("fixture contains a numeric project name");
  if (hasEmail(text)) throw new Error("fixture contains an email address");
  for (const secret of secrets.filter(Boolean)) {
    for (const form of encodings(String(secret))) {
      if (text.includes(form)) throw new Error("fixture contains a private value");
    }
  }
}
