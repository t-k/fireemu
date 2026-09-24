// The last check before the committed fixture is written: it must not contain a secret, the
// sandbox project id in any encoding, or an access token. Kept outside the harness digest so a
// stricter scan never makes saved rows stale.

const TOKEN = /\bya29\.[A-Za-z0-9_-]{10,}/;
/** A numeric project name, as ErrorInfo `consumer` and quota messages carry it. */
const PROJECT_NUMBER = /projects\/\d{6,}|project_number\W{0,3}\d{6,}/;
const EMAIL = /[\w.+-]+@[\w-]+(\.[\w-]+)+/;

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

export function scanFixture(text, secrets) {
  if (TOKEN.test(text)) throw new Error("fixture contains an access token");
  if (PROJECT_NUMBER.test(text)) throw new Error("fixture contains a numeric project name");
  if (EMAIL.test(text)) throw new Error("fixture contains an email address");
  for (const secret of secrets.filter(Boolean)) {
    for (const form of encodings(String(secret))) {
      if (text.includes(form)) throw new Error("fixture contains a private value");
    }
  }
}
