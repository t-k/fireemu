// A seeded sweep of generated pipelines (coordinator ruling of 2026-10-20 for round 3 of the
// PX1d review): it draws pipelines from the grammar fireemu accepts (stages, literals, vectors,
// `__type__` and reserved keys, aliases, functions with options, nesting), sends each to one
// loopback target and saves the answers, then compares the official emulator's answers with
// fireemu's under both profiles. `collect` sends each drawn pipeline in four variants: as
// drawn (keys in a drawn order), every map reversed, and both on an empty collection. Local
// use only: CI cannot run the official emulator, so the interesting rows go into conformance/fs-ent-pipeline-differential.json (differential.mjs).
//
//   FIRESTORE_EMULATOR_HOST=127.0.0.1:<port> node src/fs-ent-pipeline/differential-sweep.mjs \
//     collect <seed> <count> <answers.json>
//   FIRESTORE_EMULATOR_HOST=127.0.0.1:<port> node src/fs-ent-pipeline/differential-sweep.mjs \
//     replay <rows.json> <answers.json>
//   FIRESTORE_EMULATOR_HOST=127.0.0.1:<port> node src/fs-ent-pipeline/differential-sweep.mjs \
//     matrix <answers.json>
//   node src/fs-ent-pipeline/differential-sweep.mjs compare <official.json> <emulator.json> \
//     <strict.json> <report.json> [rows.jsonl]
//
// `compare` lists the rows where the emulator profile accepts what the official emulator
// refuses or refuses what it accepts (rows outside the local subset, a stage or function
// fireemu does not run, are counted apart), and the strict answers that are not UNIMPLEMENTED
// and either differ from the official answer or carry a refusal text no production row holds.
// With rows.jsonl it also writes those rows as {label, stages} for differential.mjs record.

import { readFile, writeFile } from "node:fs/promises";

import { SEED } from "./differential.mjs";

const DOCS = "projects/demo-app/databases/(default)/documents";

/** mulberry32: a small seeded generator, so a run can be repeated from its seed. */
function generator(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function grammar(random) {
  const pick = (items) => items[Math.floor(random() * items.length)];
  const chance = (p) => random() < p;
  const int = (n) => ({ integerValue: String(n) });
  const dbl = (d) => ({ doubleValue: d });
  const str = (s) => ({ stringValue: s });
  // A map's entries in a drawn order: the official emulator reads them in wire order (PX1d r5
  // review S6).
  const shuffled = (fields) => {
    const entries = Object.entries(fields);
    for (let i = entries.length - 1; i > 0; i -= 1) {
      const j = Math.floor(random() * (i + 1));
      [entries[i], entries[j]] = [entries[j], entries[i]];
    }
    return Object.fromEntries(entries);
  };
  const map = (fields) => ({ mapValue: { fields: shuffled(fields) } });
  const arr = (...values) => ({ arrayValue: { values } });
  const field = () => ({
    fieldReferenceValue: pick(["i", "n", "top", "dbl", "x", "__name__", "a..b", "i.j"]),
  });
  const key = () => pick(["a", "b", "v", "", "__x__", "__name__", "__type__", "a.b", "a-b", "1a"]);
  const scalar = () =>
    pick([
      () => int(pick([0, 1, -1, 5000000000])),
      () => dbl(pick([1.5, 0, "NaN", "Infinity", "-Infinity", -0.5])),
      () => str(pick(["s", "", "あ"])),
      () => ({ booleanValue: chance(0.5) }),
      () => ({ nullValue: null }),
      () => ({ timestampValue: "2020-01-01T00:00:00Z" }),
      () => ({ bytesValue: "AA==" }),
      () => ({ geoPointValue: pick([{ latitude: 1, longitude: 1 }, {}]) }),
      () => ({ referenceValue: `${DOCS}/${pick(["c/d", "c", "c/x/s", "あ", "c/d/s/e"])}` }),
    ])();
  const vector = () =>
    pick([
      () => map({ __type__: str("__vector__"), value: arr(dbl(1), dbl(2)) }),
      () => map({ __type__: str("__vector__"), value: arr(int(1)) }),
      () => map({ __type__: str("__vector__"), value: arr() }),
      () => map({ __type__: str("__vector__") }),
      () => map({ __type__: str("__vector__"), value: str("x") }),
      () => map({ __type__: str("__vector__"), value: arr(dbl(1)), x: int(1) }),
      () => map({ __type__: str("__vector__"), value: arr(dbl("NaN")) }),
      () => map({ __type__: str("__vector__"), value: arr(dbl("Infinity")) }),
      () => map({ __type__: str("__vector__"), value: arr(field()) }),
      () =>
        map({
          __type__: pick([int(1), { booleanValue: true }, { nullValue: null }, dbl(1.5), map({})]),
        }),
      () => map({ __type__: str("x"), value: arr(int(1)) }),
    ])();
  const functionNames = [
    "equal",
    "not_equal",
    "less_than",
    "greater_than_or_equal",
    "array",
    "map",
    "document_id",
    "collection_id",
    "parent",
    "nope_fn",
    "add",
    "sqrt",
    "count",
    "and",
    "exists",
  ];
  const value = (depth, expressions) => {
    const options = [scalar, scalar, vector];
    if (depth < 3) {
      options.push(
        () =>
          arr(
            ...Array.from({ length: Math.floor(random() * 3) }, () =>
              value(depth + 1, expressions),
            ),
          ),
        () =>
          map(
            Object.fromEntries(
              Array.from({ length: 1 + Math.floor(random() * 2) }, () => [
                key(),
                value(depth + 1, expressions),
              ]),
            ),
          ),
      );
      if (expressions)
        options.push(
          () => functionCall(depth + 1),
          () => functionCall(depth + 1),
        );
    }
    if (expressions) options.push(field, field);
    return pick(options)();
  };
  const functionCall = (depth) => {
    const name = pick(functionNames);
    const arity = pick([0, 1, 2, 2, 2, 3]);
    const f = { name, args: Array.from({ length: arity }, () => value(depth, true)) };
    if (chance(0.15)) f.options = { x: value(depth, chance(0.5)) };
    return { functionValue: f };
  };
  const alias = () =>
    pick(["v", "v", "a.b", "", "__x__", "__name__", "a..b", "`x`", "a".repeat(1500)]);
  const aliases = (n) =>
    map(Object.fromEntries(Array.from({ length: n }, () => [alias(), value(1, true)])));
  const count = () =>
    pick([
      int(1),
      int(-1),
      int(0),
      int(5000000000),
      str("x"),
      { booleanValue: true },
      dbl(1.5),
      { nullValue: null },
      map({}),
    ]);
  const stage = () => {
    const name = pick([
      "where",
      "where",
      "select",
      "select",
      "limit",
      "offset",
      "add_fields",
      "distinct",
      "aggregate",
      "sort",
      "remove_fields",
    ]);
    switch (name) {
      case "where":
        return { name, args: [chance(0.7) ? functionCall(1) : value(1, true)] };
      case "select":
      case "add_fields":
      case "distinct":
        return { name, args: [aliases(Math.floor(random() * 3))] };
      case "limit":
      case "offset":
        return { name, args: [count()] };
      case "aggregate":
        return {
          name,
          args: chance(0.5)
            ? [
                map({
                  c: {
                    functionValue: {
                      name: pick(["count", "sum", "nope_fn"]),
                      args: chance(0.5) ? [field()] : [],
                    },
                  },
                }),
              ]
            : [
                map({ [alias()]: { functionValue: { name: "count", args: [] } } }),
                aliases(Math.floor(random() * 2)),
              ],
        };
      case "sort":
        return chance(0.3)
          ? { name, args: [map({ expression: field(), direction: str("ascending") })] }
          : { name, args: [{ functionValue: { name: "ascending", args: [field()] } }] };
      default:
        return { name, args: [field()] };
    }
  };
  return () => {
    const stages = [{ name: "collection", args: [{ referenceValue: "/c" }] }];
    const n = 1 + Math.floor(random() * 3);
    for (let i = 0; i < n; i += 1) stages.push(stage());
    if (chance(0.05)) stages.at(-1).options = { x: int(1) };
    return stages;
  };
}

async function call(host, method, path, body) {
  const init = {
    method,
    headers: { authorization: "Bearer owner", "content-type": "application/json" },
  };
  // A string is sent as written (a malformed body); anything else as JSON.
  if (body !== undefined) init.body = typeof body === "string" ? body : JSON.stringify(body);
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

function answer({ status, body }) {
  const element = Array.isArray(body) ? body[0] : body;
  if (status !== 200) return { status, message: element?.error?.message ?? String(body) };
  const strip = (v) =>
    Array.isArray(v)
      ? v.map(strip)
      : v && typeof v === "object"
        ? Object.fromEntries(
            Object.entries(v)
              .filter(([k]) => !["name", "createTime", "updateTime"].includes(k))
              .map(([k, x]) => [k, k === "doubleValue" && typeof x === "number" ? x : strip(x)]),
          )
        : v;
  return {
    status,
    results: strip((Array.isArray(body) ? body : [body]).flatMap((e) => e.results ?? [])),
  };
}

/** Sends each pipeline to the loopback target over the seeded document and keeps the answers. */
async function send(host, pipelines) {
  if (!/^(127\.0\.0\.1|localhost):\d+$/.test(host ?? "")) throw new Error("loopback only");
  const seeded = await call(host, "PATCH", `${DOCS}/c/d`, { fields: SEED });
  if (seeded.status !== 200) throw new Error(`seed: ${JSON.stringify(seeded)}`);
  const rows = [];
  for (const { id, stages, text } of pipelines) {
    const body = text ?? { structuredPipeline: { pipeline: { stages } } };
    rows.push({
      id,
      stages,
      text,
      answer: answer(await call(host, "POST", `${DOCS}:executePipeline`, body)),
    });
  }
  return rows;
}

/** Every `fields` and `options` map of a value with its entries in reverse order. */
function reversedMaps(value) {
  if (Array.isArray(value)) return value.map(reversedMaps);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value).map(([key, inner]) => [
      key,
      (key === "fields" || key === "options") && inner && typeof inner === "object" && !Array.isArray(inner)
        ? Object.fromEntries(Object.entries(inner).reverse().map(([k, v]) => [k, reversedMaps(v)]))
        : reversedMaps(inner),
    ]),
  );
}

/** The same stages reading an empty collection, where only checks made before any row refuse. */
const onEmpty = (stages) => [{ name: "collection", args: [{ referenceValue: "/empty" }] }, ...stages.slice(1)];

async function collect(host, seed, count, out) {
  const next = grammar(generator(Number(seed)));
  // Each pipeline in four variants (PX1d r6 review S3): as drawn (G), every map reversed (R),
  // and both on an empty collection (EG, ER).
  const pipelines = Array.from({ length: Number(count) }, (_, i) => {
    const stages = next();
    const reversed = reversedMaps(stages);
    return [
      { id: `sweep-${seed}-${i}-G`, stages },
      { id: `sweep-${seed}-${i}-R`, stages: reversed },
      { id: `sweep-${seed}-${i}-EG`, stages: onEmpty(stages) },
      { id: `sweep-${seed}-${i}-ER`, stages: onEmpty(reversed) },
    ];
  }).flat();
  const rows = await send(host, pipelines);
  await writeFile(out, JSON.stringify({ seed: Number(seed), count: Number(count), rows }));
  console.log(JSON.stringify({ seed: Number(seed), count: rows.length }));
}

/**
 * The finite domains checked exhaustively (coordinator ruling of 2026-10-21 for PX1d r7): every
 * function fireemu runs, in every argument position, with a constant of every value kind (and
 * a field and a function), in a select and, for a condition, in a where, each on the seeded
 * collection, on an empty one, and behind a where that keeps no row; every form of a collection
 * reference in the collection stage, as a collection_group ancestor and as a document function's
 * constant; and malformed bodies.
 */
export function matrix() {
  const int = (n) => ({ integerValue: String(n) });
  const field = (name) => ({ fieldReferenceValue: name });
  const fn = (name, ...args) => ({ functionValue: { name, args } });
  const ref = (path) => ({ referenceValue: path });
  const kinds = {
    null: { nullValue: null },
    boolean: { booleanValue: true },
    integer: int(1),
    double: { doubleValue: 1.5 },
    timestamp: { timestampValue: "2020-01-01T00:00:00Z" },
    string: { stringValue: "s" },
    bytes: { bytesValue: "AA==" },
    document: ref(`${DOCS}/c/d`),
    collection: ref(`${DOCS}/c`),
    geoPoint: { geoPointValue: { latitude: 1, longitude: 2 } },
    array: { arrayValue: { values: [int(1)] } },
    map: { mapValue: { fields: { a: int(1) } } },
    vector: {
      mapValue: {
        fields: {
          __type__: { stringValue: "__vector__" },
          value: { arrayValue: { values: [{ doubleValue: 1 }] } },
        },
      },
    },
    field: field("i"),
    function: fn("document_id", field("__name__")),
  };
  const comparisons = ["equal", "not_equal", "less_than", "less_than_or_equal", "greater_than", "greater_than_or_equal"];
  const calls = [];
  for (const [kind, value] of Object.entries(kinds)) {
    for (const name of comparisons) {
      calls.push([`${name}(${kind}, i)`, fn(name, value, field("i")), true]);
      calls.push([`${name}(i, ${kind})`, fn(name, field("i"), value), true]);
    }
    for (const name of ["document_id", "collection_id", "parent"]) {
      calls.push([`${name}(${kind})`, fn(name, value), false]);
    }
    calls.push([`array(${kind})`, fn("array", value), false]);
    calls.push([`map(${kind}, i)`, fn("map", value, field("i")), false]);
    calls.push([`map("k", ${kind})`, fn("map", { stringValue: "k" }, value), false]);
  }
  const inputs = [
    ["seeded", [{ name: "collection", args: [ref("/c")] }]],
    ["empty", [{ name: "collection", args: [ref("/empty")] }]],
    [
      "filtered",
      [
        { name: "collection", args: [ref("/c")] },
        { name: "where", args: [fn("equal", field("i"), int(99))] },
      ],
    ],
  ];
  const rows = [];
  for (const [label, call, condition] of calls) {
    for (const [input, stages] of inputs) {
      rows.push({
        id: `matrix select ${label} ${input}`,
        stages: [...stages, { name: "select", args: [{ mapValue: { fields: { v: call } } }] }],
      });
      if (condition && input !== "filtered") {
        rows.push({ id: `matrix where ${label} ${input}`, stages: [...stages, { name: "where", args: [call] }] });
      }
    }
  }
  const forms = ["c", "/c", "/c/d", "/c/d/", "//c/d", "/c//d", "/", "", `${DOCS}/c`, `${DOCS}/c/d`, "/c/x/s", "c/x/s", "projects/x/databases/y/documents/c", "/c/"];
  for (const form of forms) {
    rows.push({ id: `matrix collection ${JSON.stringify(form)}`, stages: [{ name: "collection", args: [ref(form)] }] });
    rows.push({
      id: `matrix collection_group ${JSON.stringify(form)}`,
      stages: [{ name: "collection_group", args: [ref(form), { stringValue: "c" }] }],
    });
    for (const name of ["document_id", "collection_id", "parent"]) {
      for (const [input, stages] of inputs) {
        rows.push({
          id: `matrix ${name}(ref ${JSON.stringify(form)}) ${input}`,
          stages: [...stages, { name: "select", args: [{ mapValue: { fields: { v: fn(name, ref(form)) } } }] }],
        });
      }
    }
  }
  for (const kind of ["string", "integer", "null", "map"]) {
    rows.push({ id: `matrix collection(${kind})`, stages: [{ name: "collection", args: [kinds[kind]] }] });
  }
  const good = JSON.stringify({ structuredPipeline: { pipeline: { stages: [{ name: "collection", args: [ref("/c")] }] } } });
  const deep = (n) => `${"[".repeat(n)}${"]".repeat(n)}`;
  for (const [label, text] of [
    ["truncated", good.slice(0, -3)],
    ["trailing input", `${good} trailing`],
    ["trailing comma", good.replace(/}$/, ",}")],
    ["unknown escape", good.replace('"/c"', '"/\\q"').replace("\\\\", "\\")],
    ["deep nesting", `{"structuredPipeline": ${deep(120)}}`],
    ["not an object", "[]"],
    ["empty object", "{}"],
  ]) {
    rows.push({ id: `matrix body ${label}`, stages: [], text });
  }
  return rows;
}

/** Sends the exhaustive matrix to a loopback target. */
async function collectMatrix(host, out) {
  const rows = await send(host, matrix());
  await writeFile(out, JSON.stringify({ input: "matrix", count: rows.length, rows }));
  console.log(JSON.stringify({ input: "matrix", count: rows.length }));
}

/** Replays fixed pipelines, a JSON array of {id, stages} (a review's generated rows). */
async function replay(host, input, out) {
  const pipelines = JSON.parse(await readFile(input, "utf8")).map(({ id, stages }) => ({
    id,
    stages,
  }));
  const rows = await send(host, pipelines);
  await writeFile(out, JSON.stringify({ input, count: rows.length, rows }));
  console.log(JSON.stringify({ input, count: rows.length }));
}

/** JSON with sorted keys, so that two answers compare whatever order their maps were written in. */
const canonical = (value) =>
  JSON.stringify(value, (_, v) =>
    v && typeof v === "object" && !Array.isArray(v)
      ? Object.fromEntries(Object.entries(v).toSorted(([a], [b]) => a.localeCompare(b)))
      : v,
  );

/** An answer with its results in a fixed order (without a sort stage the order is unspecified). */
const sortedResults = (answer) => ({
  ...answer,
  results: (answer.results ?? []).map((r) => canonical(r)).toSorted(),
});

async function compare(officialPath, emulatorPath, strictPath, reportPath, rowsPath) {
  const [official, emulator, strict] = await Promise.all(
    [officialPath, emulatorPath, strictPath].map(async (p) =>
      JSON.parse(await readFile(p, "utf8")),
    ),
  );
  const production = JSON.parse(
    await readFile(new URL("../../fs-ent-pipeline-production.json", import.meta.url), "utf8"),
  );
  const normalize = (m) =>
    String(m)
      .replaceAll(
        "projects/demo-fs-query-index/databases/entpipe1",
        "projects/demo-app/databases/(default)",
      )
      .replace(/ at index \d+\.$/, "");
  const recordedTexts = new Set(
    Object.values(production.programs).flatMap((p) =>
      Object.values(p.steps).flatMap((r) => {
        const e = Array.isArray(r.body) ? r.body[0] : r.body;
        return e?.error?.message ? [normalize(e.error.message)] : [];
      }),
    ),
  );
  const report = {
    seed: official.seed,
    count: official.rows.length,
    acceptsMore: [],
    refusesMore: [],
    outsideSubset: 0,
    strictDiffers: [],
    strictUntraced: [],
    strict501: 0,
    strictAnswered: 0,
    emulatorResultsDiffer: [],
  };
  const interesting = [];
  official.rows.forEach((row, i) => {
    const o = row.answer;
    const e = emulator.rows[i].answer;
    const s = strict.rows[i].answer;
    const line = { id: row.id, official: o, emulator: e, strict: s };
    if (e.status === 200 && o.status !== 200) {
      report.acceptsMore.push(line);
      interesting.push(row);
    } else if (e.status !== 200 && o.status === 200) {
      // fireemu answers UNIMPLEMENTED only for what its local subset does not run.
      if (e.status === 501) report.outsideSubset += 1;
      else {
        report.refusesMore.push(line);
        interesting.push(row);
      }
    }
    // Both answered: the results, not only the status (review r5).
    if (e.status === 200 && o.status === 200 && canonical(sortedResults(e)) !== canonical(sortedResults(o))) {
      report.emulatorResultsDiffer.push(line);
      interesting.push(row);
    }
    if (s.status === 501) report.strict501 += 1;
    else {
      report.strictAnswered += 1;
      if (canonical(s) !== canonical(o)) {
        report.strictDiffers.push(line);
        interesting.push(row);
      } else if (s.status !== 200 && !recordedTexts.has(normalize(s.message))) {
        report.strictUntraced.push(line);
        interesting.push(row);
      }
    }
  });
  await writeFile(reportPath, JSON.stringify(report, null, 1));
  if (rowsPath) {
    await writeFile(
      rowsPath,
      [...new Set(interesting)]
        .map((r) => JSON.stringify({ label: r.id, stages: r.stages }))
        .join("\n") + "\n",
    );
  }
  console.log(
    JSON.stringify({
      seed: report.seed,
      count: report.count,
      acceptsMore: report.acceptsMore.length,
      refusesMore: report.refusesMore.length,
      outsideSubset: report.outsideSubset,
      strict501: report.strict501,
      strictAnswered: report.strictAnswered,
      strictDiffers: report.strictDiffers.length,
      strictUntraced: report.strictUntraced.length,
      emulatorResultsDiffer: report.emulatorResultsDiffer.length,
    }),
  );
}

if (import.meta.main) {
  const [mode, ...args] = process.argv.slice(2);
  if (mode === "collect" && args.length === 3)
    await collect(process.env.FIRESTORE_EMULATOR_HOST, ...args);
  else if (mode === "matrix" && args.length === 1)
    await collectMatrix(process.env.FIRESTORE_EMULATOR_HOST, ...args);
  else if (mode === "replay" && args.length === 2)
    await replay(process.env.FIRESTORE_EMULATOR_HOST, ...args);
  else if (mode === "compare" && args.length >= 4) await compare(...args);
  else {
    console.error(
      "usage: differential-sweep.mjs collect <seed> <count> <out> | matrix <out> | replay <rows.json> <out> | compare <official> <emulator> <strict> <report> [rows.jsonl]",
    );
    process.exitCode = 2;
  }
}
