// One side of a language-matrix run, executed inside that side's supervisor.
//
// Reads a claim list, installs it as Security Rules in chunks through the emulator's own
// `PUT /emulator/v1/projects/{project}:securityRules` route -- the same route on both sides,
// which is what makes the two runs comparable -- and probes each claim with two document
// reads. Writes `{ claims: { id: verdict } }` and every compiler diagnostic it saw.
//
// Verdicts:
//   true / false   the positive and negated blocks disagreed, in that order
//   error          both denied: the expression raised or produced a non-boolean
//   compile-error  the claim does not compile; the compiler's message is recorded
//   inconclusive   the pair of reads produced a shape no verdict explains

import { readFile, writeFile } from "node:fs/promises";

const HOST = process.env.RULES_PROBE_FIRESTORE_HOST;
const PROJECT = process.env.RULES_PROBE_PROJECT ?? "demo-conformance";
const IN = process.env.RULES_PROBE_IN;
const OUT = process.env.RULES_PROBE_OUT;
const CHUNK = Number(process.env.RULES_PROBE_CHUNK ?? 60);

const HEADER = "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{db}/documents {";
const FOOTER = "  }\n}";

/** Renders one chunk and remembers which source line each claim's blocks occupy. */
function renderChunk(claims) {
  const lines = HEADER.split("\n");
  /** @type {Map<number, string>} */
  const lineToClaim = new Map();
  claims.forEach((c, i) => {
    lineToClaim.set(lines.length + 1, c.id);
    lines.push(`    match /t${i}/{d} { allow get: if ${c.claim}; }`);
    lineToClaim.set(lines.length + 1, c.id);
    lines.push(`    match /f${i}/{d} { allow get: if !(${c.claim}); }`);
  });
  lines.push(...FOOTER.split("\n"));
  return { source: lines.join("\n"), lineToClaim };
}

async function putRules(source) {
  const response = await fetch(`http://${HOST}/emulator/v1/projects/${PROJECT}:securityRules`, {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ rules: { files: [{ name: "firestore.rules", content: source }] } }),
  });
  const text = await response.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = { raw: text };
  }
  return { status: response.status, body };
}

/** `L14:36 Missing 'match' keyword ...` -> the lines the compiler rejected. */
function rejectedLines(body) {
  const message = body?.error?.message ?? body?.message ?? "";
  const lines = new Map();
  for (const m of String(message).matchAll(/L(\d+):(\d+)\s+([^\n]*)/g)) {
    const line = Number(m[1]);
    if (!lines.has(line)) lines.set(line, m[3].trim());
  }
  return lines;
}

/** Structured `issues` come back with a 200 and never block the load. */
function warnings(body) {
  const out = new Map();
  for (const issue of body?.issues ?? []) {
    const line = issue?.sourcePosition?.line;
    if (typeof line === "number" && !out.has(line)) out.set(line, issue.description ?? "");
  }
  return out;
}

async function pooled(items, worker, width = 16) {
  const results = new Array(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(width, items.length) }, async () => {
      for (;;) {
        const i = next++;
        if (i >= items.length) return;
        results[i] = await worker(items[i], i);
      }
    }),
  );
  return results;
}

const read = async (collection) => {
  const url = `http://${HOST}/v1/projects/${PROJECT}/databases/(default)/documents/${collection}/probe`;
  const response = await fetch(url);
  return response.status;
};

function verdict(positive, negated) {
  if (positive === 404 && negated === 403) return "true";
  if (positive === 403 && negated === 404) return "false";
  if (positive === 403 && negated === 403) return "error";
  return `inconclusive:${positive}/${negated}`;
}

/** Probes one chunk, dropping claims the compiler rejects and retrying. */
async function probeChunk(claims, out, diagnostics) {
  let remaining = claims;
  // Each failed attempt drops at least one claim, so the bound is the chunk size: a
  // compiler that reports one position at a time still converges.
  const attempts = claims.length + 4;
  for (let attempt = 0; attempt < attempts && remaining.length > 0; attempt++) {
    const { source, lineToClaim } = renderChunk(remaining);
    const { status, body } = await putRules(source);
    if (status !== 200) {
      const rejected = rejectedLines(body);
      const bad = new Set();
      for (const [line, description] of rejected) {
        const id = lineToClaim.get(line);
        if (id) {
          bad.add(id);
          if (!out.has(id)) {
            out.set(id, "compile-error");
            diagnostics.push({ id, severity: "ERROR", description });
          }
        }
      }
      if (bad.size === 0) {
        // The compiler blamed a line no claim owns: fall back to halving the chunk.
        if (remaining.length === 1) {
          out.set(remaining[0].id, "compile-error");
          diagnostics.push({
            id: remaining[0].id,
            severity: "ERROR",
            description: String(body?.error?.message ?? "").slice(0, 400),
          });
          return;
        }
        const half = Math.ceil(remaining.length / 2);
        await probeChunk(remaining.slice(0, half), out, diagnostics);
        await probeChunk(remaining.slice(half), out, diagnostics);
        return;
      }
      remaining = remaining.filter((c) => !bad.has(c.id));
      continue;
    }
    for (const [line, description] of warnings(body)) {
      const id = lineToClaim.get(line);
      if (id) diagnostics.push({ id, severity: "WARNING", description });
    }
    const statuses = await pooled(
      remaining.flatMap((_, i) => [`t${i}`, `f${i}`]),
      read,
    );
    remaining.forEach((c, i) => out.set(c.id, verdict(statuses[2 * i], statuses[2 * i + 1])));
    return;
  }
}

async function main() {
  if (!HOST || !IN || !OUT) {
    throw new Error("RULES_PROBE_FIRESTORE_HOST, RULES_PROBE_IN and RULES_PROBE_OUT are required");
  }
  const claims = JSON.parse(await readFile(IN, "utf8"));
  /** @type {Map<string, string>} */
  const out = new Map();
  const diagnostics = [];
  for (let i = 0; i < claims.length; i += CHUNK) {
    await probeChunk(claims.slice(i, i + CHUNK), out, diagnostics);
  }
  await writeFile(
    OUT,
    `${JSON.stringify({ claims: Object.fromEntries(out), diagnostics }, null, 2)}\n`,
  );
}

await main();
