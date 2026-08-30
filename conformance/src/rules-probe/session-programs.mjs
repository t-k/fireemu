// Runs the whole-program probes against one side and records what it answered.
//
// Each program installs its own ruleset, seeds any documents it needs with the privileged
// `Bearer owner` credential (which bypasses rules on both sides), then runs its steps
// unauthenticated so the rules decide. The recorded value is the HTTP status, the canonical
// error status and the message, which is what a client actually sees.

import { readFile, writeFile } from "node:fs/promises";

const HOST = process.env.RULES_PROBE_FIRESTORE_HOST;
const PROJECT = process.env.RULES_PROBE_PROJECT ?? "demo-conformance";
const IN = process.env.RULES_PROBE_IN;
const OUT = process.env.RULES_PROBE_OUT;

const url = (path) => `http://${HOST}${path.replaceAll("PROJECT", PROJECT)}`;
const substitute = (value) =>
  JSON.parse(JSON.stringify(value ?? null).replaceAll("PROJECT", PROJECT));

async function putRules(source) {
  const response = await fetch(`http://${HOST}/emulator/v1/projects/${PROJECT}:securityRules`, {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ rules: { files: [{ name: "firestore.rules", content: source }] } }),
  });
  if (response.ok) return null;
  const text = await response.text();
  return text.slice(0, 400);
}

/** Wipes the emulator's documents so one program never sees another's writes. */
async function clear() {
  await fetch(`http://${HOST}/emulator/v1/projects/${PROJECT}/databases/(default)/documents`, {
    method: "DELETE",
  });
}

async function seed(documents) {
  for (const document of documents ?? []) {
    const response = await fetch(url(document.path), {
      method: "PATCH",
      headers: { "content-type": "application/json", authorization: "Bearer owner" },
      body: JSON.stringify({ fields: substitute(document.fields) }),
    });
    if (!response.ok) {
      throw new Error(`seed ${document.path}: ${response.status} ${await response.text()}`);
    }
  }
}

async function step(spec) {
  const init = { method: spec.method, headers: {} };
  if (spec.body !== undefined) {
    init.headers["content-type"] = "application/json";
    init.body = JSON.stringify(substitute(spec.body));
  }
  const response = await fetch(url(spec.path), init);
  const text = await response.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return { status: response.status, code: "non-json", message: text.slice(0, 200) };
  }
  // `runQuery` streams an array; an error arrives as its single element.
  const error = Array.isArray(body) ? body.find((e) => e?.error)?.error : body?.error;
  if (error) {
    return {
      status: response.status,
      code: error.status ?? String(error.code ?? ""),
      message: String(error.message ?? "").slice(0, 300),
    };
  }
  return { status: response.status, code: "OK", shape: describe(body) };
}

/** The shape of a success, which is all a rules probe needs to compare. */
function describe(body) {
  if (Array.isArray(body)) {
    const documents = body.filter((e) => e?.document).length;
    return `stream(${body.length} entries, ${documents} documents)`;
  }
  if (body && typeof body === "object") {
    if (body.name) return "document";
    if (body.writeResults) return `commit(${body.writeResults.length} results)`;
    return `object(${Object.keys(body).toSorted().join(",")})`;
  }
  return typeof body;
}

async function main() {
  if (!HOST || !IN || !OUT) {
    throw new Error("RULES_PROBE_FIRESTORE_HOST, RULES_PROBE_IN and RULES_PROBE_OUT are required");
  }
  const programs = JSON.parse(await readFile(IN, "utf8"));
  const results = {};
  for (const program of programs) {
    await clear();
    const compileError = await putRules(program.rules);
    if (compileError) {
      results[program.id] = { compileError };
      continue;
    }
    await seed(program.seed);
    const steps = {};
    for (const spec of program.steps) {
      steps[spec.id] = await step(spec);
    }
    results[program.id] = { steps };
  }
  await writeFile(OUT, `${JSON.stringify(results, null, 2)}\n`);
}

await main();
