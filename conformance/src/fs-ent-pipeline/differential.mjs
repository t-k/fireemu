// The differential corpus of the pipeline subset (coordinator ruling of 2026-10-20, PX1d r3):
// fixed pipelines over one seeded document, with the official emulator's answers, which the Rust
// test crates/fireemu-adapter-grpc/tests/pipeline_differential.rs compares with fireemu under
// both profiles (the emulator profile accepts and refuses as the official emulator does, and
// every strict answer that is not UNIMPLEMENTED traces to a production row).
//
//   FIRESTORE_EMULATOR_HOST=127.0.0.1:<port> node src/fs-ent-pipeline/differential.mjs record [rows.jsonl ...]
//     re-runs every row of conformance/fs-ent-pipeline-differential.json (and adds the rows of
//     the given JSON-lines files, {label, stages}, deduplicated by their stages) against the
//     official emulator (Firestore emulator 1.22.0, Enterprise, project demo-app) and rewrites
//     the file. Loopback only; never production.

import { readFile, writeFile } from "node:fs/promises";

export const CORPUS = new URL("../../fs-ent-pipeline-differential.json", import.meta.url);
/** The document every row reads: collection `c`, document `d`. */
export const SEED = {
  i: { integerValue: "1" },
  n: { integerValue: "1" },
  top: { stringValue: "t" },
  dbl: { doubleValue: 1.5 },
};
const DOCS = "projects/demo-app/databases/(default)/documents";

async function call(host, method, path, body) {
  const init = {
    method,
    headers: { authorization: "Bearer owner", "content-type": "application/json" },
  };
  if (body !== undefined) init.body = JSON.stringify(body);
  const response = await fetch(`http://${host}/v1/${path}`, init);
  const text = await response.text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = text;
  }
  return { status: response.status, body: parsed };
}

/** An official answer as the corpus keeps it: the status and the error message or results. */
function answer({ status, body }) {
  const element = Array.isArray(body) ? body[0] : body;
  if (status !== 200) return { status, message: element?.error?.message ?? String(body) };
  const results = (Array.isArray(body) ? body : [body]).flatMap((e) => e.results ?? []);
  return { status, results };
}

const depth = (value) =>
  value !== null && typeof value === "object"
    ? 1 + Math.max(0, ...Object.values(value).map(depth))
    : 0;

async function record(host, inputs) {
  if (!/^(127\.0\.0\.1|localhost):\d+$/.test(host ?? "")) {
    throw new Error("FIRESTORE_EMULATOR_HOST must be a loopback emulator");
  }
  const corpus = JSON.parse(await readFile(CORPUS, "utf8").catch(() => '{"rows":[]}'));
  const rows = corpus.rows.map(({ id, stages }) => ({ id, stages }));
  const seen = new Set(rows.map((row) => JSON.stringify(row.stages)));
  for (const input of inputs) {
    for (const line of (await readFile(input, "utf8")).split("\n").filter(Boolean)) {
      const { label, stages } = JSON.parse(line);
      const key = JSON.stringify(stages);
      // The Rust test reads the corpus with serde_json, which stops at 128 levels of nesting.
      if (seen.has(key) || depth(stages) > 100) continue;
      if (rows.some((row) => row.id === label)) throw new Error(`duplicate row id ${label}`);
      seen.add(key);
      rows.push({ id: label, stages });
    }
  }
  const seeded = await call(host, "PATCH", `${DOCS}/c/d`, { fields: SEED });
  if (seeded.status !== 200) throw new Error(`seed: ${JSON.stringify(seeded)}`);
  for (const row of rows) {
    const body = { structuredPipeline: { pipeline: { stages: row.stages } } };
    row.official = answer(await call(host, "POST", `${DOCS}:executePipeline`, body));
  }
  const text = `${JSON.stringify(
    {
      generator: "conformance/src/fs-ent-pipeline/differential.mjs",
      oracle: "firebase-tools 15.28.2, Firestore emulator 1.22.0, Enterprise, project demo-app",
      seed: { document: "c/d", fields: SEED },
      rows,
    },
    null,
    1,
  )}\n`;
  await writeFile(CORPUS, text);
  console.log(JSON.stringify({ rows: rows.length }));
}

if (import.meta.main) {
  const [mode, ...inputs] = process.argv.slice(2);
  if (mode === "record") await record(process.env.FIRESTORE_EMULATOR_HOST, inputs);
  else {
    console.error("usage: differential.mjs record [rows.jsonl ...]");
    process.exitCode = 2;
  }
}
