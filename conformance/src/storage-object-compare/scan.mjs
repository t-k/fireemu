// The last check before a fixture is committed: a fixture must carry no credential, no identifier
// of a sandbox project, and no value that the masks were meant to remove. A run's own ID, bucket and
// project are refused if they survive; the list of private identifiers (project numbers, other
// sandbox projects) is read from a file outside the repository, never written into it.

const PATTERNS = [
  [/eyJ[A-Za-z0-9_-]{5,}/, "a token (JWT)"],
  [/ya29\./, "an OAuth access token"],
  [/AIza[0-9A-Za-z_-]{20,}/, "an API key"],
  [/AMf-/, "a refresh token"],
  [/(?<![\d])\d{12}(?![\d])/, "a 12-digit number (a project number)"],
  [/upload_id=(?!<UPLOAD_ID>)[^&"\s]/, "an upload ID"],
  [/AP6rU[A-Za-z0-9_-]{10,}/, "an upload ID"],
  [/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/, "a UUID (a download token)"],
  [/\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z/, "a timestamp"],
  [/(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d\d [A-Z][a-z]{2} \d{4} \d\d:\d\d:\d\d GMT/, "an HTTP date"],
  [/(?<![\d])\d{16}(?![\d])/, "a generation"],
  [/sha256:[0-9a-f]{16,}/, "a hashed secret"],
];

/**
 * Throws if `text` carries something that must not be committed. `runIds` are the runs the fixture
 * came from; `forbidden` are exact strings (the real bucket, project and the private identifiers).
 * A 1990 `Expires` date is the one HTTP date production sends as a constant.
 */
export function scanFixtureText(text, { runIds = [], forbidden = [] } = {}) {
  // An inline base64 body is scanned decoded; a SHA-256 is digits and letters by chance.
  for (const [, encoded] of text.matchAll(/"base64":\s*"([A-Za-z0-9+/=]+)"/g))
    scanFixtureText(Buffer.from(encoded, "base64").toString("latin1"), { runIds, forbidden });
  const checked = text
    .replaceAll("Mon, 01 Jan 1990 00:00:00 GMT", "<static>")
    .replace(/"(sha256|base64)":"[A-Za-z0-9+/=]+"/g, '"$1":"<data>"')
    .replace(/"[0-9a-f]{20}":\s*"[0-9a-f]{64}"/g, '"<run>": "<sha256>"');
  for (const runId of runIds)
    if (checked.includes(runId)) throw new Error("fixture holds a run ID");
  for (const value of forbidden.filter(Boolean))
    if (checked.includes(value)) throw new Error("fixture holds a private or unmasked identifier");
  for (const [pattern, what] of PATTERNS)
    if (pattern.test(checked)) throw new Error(`fixture holds ${what}`);
  for (const [, domain] of checked.matchAll(/[^\s"'<>@(),;:\\]+@([^\s@"'<>/?#&\\]+)/g))
    if (domain.toLowerCase() !== "example.com")
      throw new Error(`fixture holds an email outside example.com (${domain})`);
}
