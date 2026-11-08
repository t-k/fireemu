// FS-RULES Unicode family: string size, normalization, case mapping and regular expressions over
// supplementary characters, combining marks, variation selectors and joined emoji, each as a literal
// in the rules and as a stored field read by the Rules function get(). The facts the fake production
// uses are the test's choice, not claims about production.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { createContext, SANDBOX_PROJECT } from "./fs-rules/harness.mjs";
import {
  corpusDigest,
  countRequests,
  DIFFS_PROGRAMS,
  PRINCIPALS,
  REQUEST_CAP,
  rulesetSource,
  SHAPES_PROGRAMS,
  SHAPES_TWO_PROGRAMS,
  UNICODE_PROGRAMS,
  UNICODE_RULESET_IDS,
  validateCorpus,
} from "./fs-rules-v1/corpus.mjs";
import {
  ceilings,
  corpusFor,
  fixtureText,
  selectPrograms,
  TASK_ID_SHAPES_TWO,
  TASK_ID_UNICODE,
  taskIdFor,
} from "./fs-rules-v1/judge.mjs";
import { shapesReportLine } from "./fs-rules-v1/shapes.mjs";
import { runCorpus } from "./fs-rules-v1/session.mjs";
import { createClock, createWorld } from "./fs-rules-v1/test-world.mjs";
import { DOCUMENTS, FIXES, OFFICIAL, unicodeReport } from "./fs-rules-v1/unicode.mjs";

const PRODUCTION = {
  kind: "production",
  adminToken: "ya29.owner-test-token",
  apiKey: "AIzaUnicodeTestKeyNotReal",
  quotaProject: SANDBOX_PROJECT,
  projectNumber: "555500000004",
};

async function record({ scenario, programs = UNICODE_PROGRAMS, wrapFetch } = {}) {
  const { world, fetchImpl, grpc } = createWorld(scenario);
  const sent = [];
  const wrapped = async (url, init = {}) => {
    if (typeof init.body === "string")
      sent.push({ url: String(url), bytes: Buffer.from(init.body) });
    return fetchImpl(url, init);
  };
  const clock = createClock();
  const ctx = createContext({ run: "1790000000300", startedMs: clock.now(), target: PRODUCTION });
  const out = await runCorpus(
    { programs, principals: PRINCIPALS },
    ctx,
    {
      fetchImpl: wrapFetch ? wrapFetch(wrapped) : wrapped,
      grpc,
      sleep: clock.sleep,
      now: clock.now,
    },
    ceilings(programs),
  );
  return { out, world, sent };
}

const rowsOf = (program) => program.steps.filter((step) => !step.publish);
const program = (suffix) => UNICODE_PROGRAMS.find((p) => p.id === `fs-rules-v1/unicode/${suffix}`);
const step = (suffix, id) => program(suffix).steps.find((s) => s.id === id);
const ids = (suffix) => rowsOf(program(suffix)).map((s) => s.id);

// The code points under test, written as escapes so that no editor or formatter can normalize them.
const E_NFC = "\u{e9}";
const E_NFD = "e\u{301}";
const GA_NFC = "\u{304c}";
const GA_NFD = "\u{304b}\u{3099}";
const KA_MARK = "\u{304b}\u{309a}";
const HFISH = "\u{29e3d}";
const IVS = "\u{8fbb}\u{e0100}";
const ZWJ = "\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}";
const SKIN = "\u{1f44d}\u{1f3fd}";
const FIRE = "\u{1f525}";
const SHARP = "\u00df";
const DOTTED = "\u0130";

const hex = (text) => Buffer.from(text, "utf8").toString("hex");

// ---- the corpus -----------------------------------------------------------------------------

test("the corpus is four programs of 45 get and list rows, valid and under the cap", () => {
  assert.deepEqual(
    UNICODE_PROGRAMS.map((p) => p.id),
    [
      "fs-rules-v1/unicode/units",
      "fs-rules-v1/unicode/case",
      "fs-rules-v1/unicode/regex",
      "fs-rules-v1/unicode/stored",
    ],
  );
  assert.deepEqual(UNICODE_RULESET_IDS, [
    "unicode-units",
    "unicode-case",
    "unicode-regex",
    "unicode-stored",
  ]);
  assert.equal(validateCorpus(UNICODE_PROGRAMS), 45);
  assert.equal(countRequests(UNICODE_PROGRAMS), 45);
  assert.ok(45 <= REQUEST_CAP);
  assert.deepEqual(
    UNICODE_PROGRAMS.map((p) => rowsOf(p).length),
    [12, 8, 8, 17],
  );
  for (const p of UNICODE_PROGRAMS)
    assert.deepEqual(p.steps[0], { id: "publishes", publish: true });
});

test("the row ids are exactly these, and every program has a true and a false control first", () => {
  assert.deepEqual(ids("units"), [
    "ctl-true",
    "ctl-false",
    "hfish-2",
    "hfish-1",
    "kana-2",
    "ivs-3",
    "zwj-8",
    "zwj-5",
    "skin-4",
    "e-eq",
    "e-nfd-size",
    "ga-eq",
  ]);
  assert.deepEqual(ids("case"), [
    "ctl-true",
    "ctl-false",
    "sharp-eq",
    "sharp-size",
    "dotted-size",
    "fi-size",
    "lower-i",
    "sigma",
  ]);
  assert.deepEqual(ids("regex"), [
    "ctl-true",
    "ctl-false",
    "fire-dot",
    "fire-dotdot",
    "fire-two",
    "e-nfd-dot",
    "zwj-dot",
    "zwj-five",
  ]);
  assert.deepEqual(ids("stored"), [
    "ctl-true",
    "ctl-false",
    "nfc-size",
    "nfd-size",
    "nfd-lit-eq",
    "nfd-nfc-lit-eq",
    "nfd-nfc-field-eq",
    "hfish-size",
    "ivs-size",
    "zwj-size",
    "skin-size",
    "sharp-upper-size",
    "dotted-lower-size",
    "q-nfd",
    "q-nfc",
    "lq-nfd",
    "lq-nfc",
  ]);
});

function rule(source, collection) {
  const match = new RegExp(
    `    match /${collection}/\\{id\\} \\{\\n      allow (get|list): if (.*);\\n    \\}\\n`,
    "u",
  ).exec(source);
  assert.ok(match, `${collection} has a rule`);
  return { kind: match[1], condition: match[2] };
}

test("the literal rules are exactly these expressions, each in its own collection", () => {
  const cases = {
    units: [
      ["ctl-true", `"abc".size() == 3`],
      ["ctl-false", `"abc".size() == 4`],
      ["hfish-2", `"${HFISH}".size() == 2`],
      ["hfish-1", `"${HFISH}".size() == 1`],
      ["kana-2", `"${KA_MARK}".size() == 2`],
      ["ivs-3", `"${IVS}".size() == 3`],
      ["zwj-8", `"${ZWJ}".size() == 8`],
      ["zwj-5", `"${ZWJ}".size() == 5`],
      ["skin-4", `"${SKIN}".size() == 4`],
      ["e-eq", `"${E_NFC}" == "${E_NFD}"`],
      ["e-nfd-size", `"${E_NFD}".size() == 2`],
      ["ga-eq", `"${GA_NFC}" == "${GA_NFD}"`],
    ],
    case: [
      ["ctl-true", `"abc".upper() == "ABC"`],
      ["ctl-false", `"abc".upper() == "abc"`],
      ["sharp-eq", `"\u{df}".upper() == "SS"`],
      ["sharp-size", `"\u{df}".upper().size() == 2`],
      ["dotted-size", `"\u{130}".lower().size() == 2`],
      ["fi-size", `"\u{fb01}".upper().size() == 2`],
      ["lower-i", `"I".lower() == "i"`],
      ["sigma", `"\u{391}\u{3a3}".lower() == "\u{3b1}\u{3c2}"`],
    ],
    regex: [
      ["ctl-true", `"abc".matches("a.c")`],
      ["ctl-false", `"abc".matches("a.")`],
      ["fire-dot", `"${FIRE}".matches(".")`],
      ["fire-dotdot", `"${FIRE}".matches("..")`],
      ["fire-two", `"${FIRE}".matches("^.{2}$")`],
      ["e-nfd-dot", `"${E_NFD}".matches(".")`],
      ["zwj-dot", `"${ZWJ}".matches(".")`],
      ["zwj-five", `"${ZWJ}".matches("^.{5}$")`],
    ],
  };
  const prefix = { units: "fsr9-un-", case: "fsr9-uc-", regex: "fsr9-ur-" };
  for (const [name, expected] of Object.entries(cases)) {
    const source = rulesetSource(`unicode-${name}`);
    for (const [id, condition] of expected) {
      assert.deepEqual(
        rule(source, `${prefix[name]}${id}`),
        { kind: "get", condition },
        `${name}#${id}`,
      );
      assert.equal(step(name, id).doc, `${prefix[name]}${id}/x`);
    }
    assert.equal(source.match(/allow (get|list):/g).length, expected.length, name);
    assert.ok(source.startsWith("rules_version = '2';\n"), name);
  }
});

const DATA = "get(/databases/$(database)/documents/fsr9-us-data/d1).data";

test("the stored rules read the stored document with get(), and the list rules read resource.data or nothing", () => {
  const source = rulesetSource("unicode-stored");
  const cases = [
    ["ctl-true", `${DATA}.ctl == "abc"`],
    ["ctl-false", `${DATA}.ctl == "abd"`],
    ["nfc-size", `${DATA}.nfc.size() == 1`],
    ["nfd-size", `${DATA}.nfd.size() == 2`],
    ["nfd-lit-eq", `${DATA}.nfd == "${E_NFD}"`],
    ["nfd-nfc-lit-eq", `${DATA}.nfd == "${E_NFC}"`],
    ["nfd-nfc-field-eq", `${DATA}.nfd == ${DATA}.nfc`],
    ["hfish-size", `${DATA}.hfish.size() == 2`],
    ["ivs-size", `${DATA}.ivs.size() == 3`],
    ["zwj-size", `${DATA}.zwj.size() == 8`],
    ["skin-size", `${DATA}.skin.size() == 4`],
    ["sharp-upper-size", `${DATA}.sharp.upper().size() == 2`],
    ["dotted-lower-size", `${DATA}.dotted.lower().size() == 2`],
  ];
  for (const [id, condition] of cases) {
    assert.deepEqual(rule(source, `fsr9-us-${id}`), { kind: "get", condition }, id);
    const row = step("stored", id);
    assert.equal(row.rpc, "get", id);
    assert.equal(row.doc, `fsr9-us-${id}/x`, id);
    assert.equal(row.as, "none", id);
  }
  assert.deepEqual(rule(source, "fsr9-us-q"), { kind: "list", condition: "true" });
  assert.deepEqual(rule(source, "fsr9-us-lq"), {
    kind: "list",
    condition: "resource.data.s.size() == 2",
  });
  assert.equal(source.match(/allow (get|list):/g).length, cases.length + 2);
  assert.ok(!source.includes("match /fsr9-us-data"), "no client rule on the stored document");
});

const stringFilter = (value) => ({
  fieldFilter: { field: { fieldPath: "s" }, op: "EQUAL", value: { stringValue: value } },
});

test("the stored list rows filter the one field s with the stored form or the composed form", () => {
  for (const [id, collection, value] of [
    ["q-nfd", "fsr9-us-q", E_NFD],
    ["q-nfc", "fsr9-us-q", E_NFC],
    ["lq-nfd", "fsr9-us-lq", E_NFD],
    ["lq-nfc", "fsr9-us-lq", E_NFC],
  ]) {
    const row = step("stored", id);
    assert.equal(row.rpc, "runQuery", id);
    assert.equal(row.as, "anon", id);
    assert.deepEqual(
      row.body.structuredQuery,
      { from: [{ collectionId: collection }], where: stringFilter(value) },
      id,
    );
  }
});

test("the seed stores each string with its exact code points, in the form the corpus names", () => {
  assert.deepEqual(program("stored").seed, [
    {
      doc: "fsr9-us-data/d1",
      fields: {
        ctl: { stringValue: "abc" },
        nfc: { stringValue: E_NFC },
        nfd: { stringValue: E_NFD },
        hfish: { stringValue: HFISH },
        ivs: { stringValue: IVS },
        zwj: { stringValue: ZWJ },
        skin: { stringValue: SKIN },
        sharp: { stringValue: "\u{df}" },
        dotted: { stringValue: "\u{130}" },
      },
    },
    { doc: "fsr9-us-q/d1", fields: { s: { stringValue: E_NFD } } },
    { doc: "fsr9-us-lq/d1", fields: { s: { stringValue: E_NFD } } },
  ]);
  for (const name of ["units", "case", "regex"]) assert.deepEqual(program(name).seed, []);
});

test("the corpus file is ASCII, so no editor or formatter has normalized a string in it", () => {
  const text = readFileSync(new URL("./fs-rules-v1/corpus.mjs", import.meta.url), "utf8");
  const section = text.slice(text.indexOf("FS-RULES: Unicode strings"));
  assert.ok(section.length > 1000);
  // eslint-disable-next-line no-control-regex
  assert.ok(/^[\x00-\x7f]*$/.test(section), "the Unicode section holds only ASCII bytes");
});

test("the rule sources carry the code points as written: no normalization, no escape, no stand-in", () => {
  const units = rulesetSource("unicode-units");
  for (const text of [E_NFC, E_NFD, GA_NFC, GA_NFD, KA_MARK, HFISH, IVS, ZWJ, SKIN])
    assert.ok(units.includes(`"${text}"`), hex(text));
  // The source differs from its own NFC and NFD forms: it holds both forms of the same letter.
  assert.notEqual(units, units.normalize("NFC"));
  assert.notEqual(units, units.normalize("NFD"));
  for (const source of UNICODE_RULESET_IDS.map(rulesetSource)) {
    assert.ok(!/\\u/.test(source), "no \\u escape in a source");
    assert.ok(!source.includes("\u{fffd}"), "no replacement character");
    assert.ok(
      !/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(source),
    );
  }
});

test("every ruleset is version 2 with balanced braces, and every row and seed names a collection that has a rule", () => {
  for (const p of UNICODE_PROGRAMS) {
    const source = rulesetSource(p.ruleset);
    assert.ok(source.startsWith("rules_version = '2';\n"), p.ruleset);
    assert.equal(source.split("{").length, source.split("}").length, `${p.ruleset}: braces`);
    const collections = [
      ...rowsOf(p).map((s) => s.doc?.split("/")[0] ?? s.body.structuredQuery.from[0].collectionId),
      ...p.seed.map((d) => d.doc.split("/")[0]),
    ].filter((c) => c !== "fsr9-us-data");
    for (const collection of collections)
      assert.ok(source.includes(`match /${collection}/{id} {`), `${p.id}: ${collection}`);
  }
});

test("the corpus names no sandbox, number, address or absolute path", () => {
  const text = JSON.stringify(UNICODE_PROGRAMS) + UNICODE_RULESET_IDS.map(rulesetSource).join("\n");
  assert.ok(!text.includes(SANDBOX_PROJECT));
  assert.ok(!/@[\w-]+\./.test(text));
  assert.ok(!/\/Users\/|\/home\//.test(text));
  assert.ok(!/\d{9,}/.test(text));
});

test("program digests differ per program and from the other families, and the earlier families are untouched", () => {
  const digests = UNICODE_PROGRAMS.map((p) => corpusDigest([p]));
  assert.equal(new Set(digests).size, UNICODE_PROGRAMS.length);
  assert.notEqual(corpusDigest(UNICODE_PROGRAMS), corpusDigest(SHAPES_TWO_PROGRAMS));
  assert.equal(
    corpusDigest(SHAPES_PROGRAMS),
    "1d441b962c393d9097a70c3d1e581f4a5a2cf98590fd08d5c21e68165d63558b",
  );
  assert.equal(
    corpusDigest(SHAPES_TWO_PROGRAMS),
    "92709af093bd85e2b5228e2a2872c394128a338a8a570356c2ebd1c71398729a",
  );
  assert.ok(corpusDigest(DIFFS_PROGRAMS).length === 64);
});

// ---- selection ------------------------------------------------------------------------------

test("FS3_CORPUS=unicode picks the family and names its own ledger task; one run never mixes", () => {
  assert.equal(corpusFor({ FS3_CORPUS: "unicode" }), UNICODE_PROGRAMS);
  assert.equal(selectPrograms(undefined, { FS3_CORPUS: "unicode" }).length, 4);
  assert.equal(
    selectPrograms(undefined, {
      FS3_CORPUS: "unicode",
      FS3_PROGRAMS: "fs-rules-v1/unicode/stored",
    }).length,
    1,
  );
  assert.equal(TASK_ID_UNICODE, "FS-RULES-UNICODE");
  assert.notEqual(TASK_ID_UNICODE, TASK_ID_SHAPES_TWO);
  assert.equal(taskIdFor(UNICODE_PROGRAMS), TASK_ID_UNICODE);
  assert.throws(() => taskIdFor([...SHAPES_TWO_PROGRAMS, ...UNICODE_PROGRAMS]), /mixes/);
  assert.throws(() => corpusFor({ FS3_CORPUS: "unicode2" }), /FS3_CORPUS must be .*unicode/);
  assert.throws(
    () => selectPrograms(undefined, { FS3_CORPUS: "shapes2", FS3_PROGRAMS: "fs-rules-v1/unicode" }),
    /no program matches/,
  );
});

// ---- the recorder over the fake production --------------------------------------------------

test("a recording leaves the sandbox as it found it, with the request counts the packet states", async () => {
  const { out, world } = await record();
  assert.equal(out.closureReady, true);
  assert.deepEqual(out.cleanupErrors, []);
  assert.deepEqual(out.failures, []);
  assert.deepEqual(out.unknowns, []);
  assert.equal(out.requests, 45);
  assert.equal(out.harnessRequests, 676);
  assert.equal(out.publications.length, 4);
  assert.equal(world.releases.size, 0);
  assert.equal(world.rulesets.size, 0);
  assert.equal(world.documents.size, 0);
  assert.equal(world.accounts.size, 0);
  for (const p of UNICODE_PROGRAMS) {
    assert.deepEqual(out.results[p.id].steps.publishes, { compiled: true }, p.id);
    for (const s of rowsOf(p)) {
      const recorded = out.results[p.id].steps[s.id];
      assert.deepEqual(Object.keys(recorded).toSorted(), ["body", "status"], `${p.id}#${s.id}`);
    }
  }
});

test("the stored strings reach production byte for byte: NFD stays decomposed, a supplementary character is one UTF-8 sequence", async () => {
  const { world, sent } = await record();
  const data = world.seeded.get("fsr9-us-data/d1");
  assert.deepEqual(
    Object.fromEntries(Object.entries(data).map(([key, value]) => [key, value.stringValue])),
    {
      ctl: "abc",
      nfc: E_NFC,
      nfd: E_NFD,
      hfish: HFISH,
      ivs: IVS,
      zwj: ZWJ,
      skin: SKIN,
      sharp: SHARP,
      dotted: DOTTED,
    },
  );
  const commits = sent.filter((c) => c.url.endsWith(":commit"));
  const stored = commits.find((c) => c.bytes.includes(Buffer.from("fsr9-us-data/d1")));
  assert.ok(stored, "the data document is written through the REST commit");
  const body = stored.bytes;
  // Each field is `"<name>":{"stringValue":"<text>"}` with the text in UTF-8, as written in the corpus.
  for (const [field, text] of [
    ["nfc", E_NFC],
    ["nfd", E_NFD],
    ["hfish", HFISH],
    ["ivs", IVS],
    ["zwj", ZWJ],
    ["skin", SKIN],
    ["sharp", SHARP],
    ["dotted", DOTTED],
  ]) {
    const wire = Buffer.from(`"${field}":{"stringValue":"${text}"}`, "utf8");
    assert.ok(body.includes(wire), `${field}: ${hex(text)}`);
  }
  // The decomposed letter is `e` then U+0301 (cc 81), the composed one c3 a9; neither is rewritten.
  const field = (name) => Buffer.from(`"${name}":{"stringValue":"`, "utf8");
  assert.ok(body.includes(Buffer.concat([field("nfd"), Buffer.from([0x65, 0xcc, 0x81, 0x22])])));
  assert.ok(body.includes(Buffer.concat([field("nfc"), Buffer.from([0xc3, 0xa9, 0x22])])));
  assert.ok(body.includes(Buffer.from([0xf0, 0xa9, 0xb8, 0xbd])), "U+29E3D as one UTF-8 sequence");
  assert.ok(body.includes(Buffer.from([0xf3, 0xa0, 0x84, 0x80])), "U+E0100 as one UTF-8 sequence");
  assert.ok(body.includes(Buffer.from([0xe2, 0x80, 0x8d])), "U+200D as UTF-8");
  assert.ok(!body.toString("latin1").includes("\\ud"), "no surrogate escape on the wire");
  const text = body.toString("utf8");
  assert.notEqual(text, text.normalize("NFC"), "the body still holds a decomposed form");
});

test("the ruleset reaches production with the literals as written", async () => {
  const { sent } = await record();
  const creates = sent
    .filter((c) => c.url.includes("/rulesets") && !c.url.includes("/releases"))
    .map((c) => ({
      bytes: c.bytes,
      content: JSON.parse(c.bytes.toString("utf8")).source.files[0].content,
    }));
  assert.equal(creates.length, 4);
  const units = creates.find((c) => c.content.includes("fsr9-un-hfish-2"));
  // Apart from the marker label, the published text is the corpus text.
  const label = /label == '([^']+)'/.exec(units.content)[1];
  assert.equal(
    units.content,
    rulesetSource("unicode-units").replace(/label == '[^']+'/, `label == '${label}'`),
  );
  assert.ok(units.content.includes(`"${E_NFC}" == "${E_NFD}"`));
  assert.ok(units.content.includes(`"${HFISH}".size() == 2`));
  // On the wire the text is UTF-8 inside a JSON string (the quotes are escaped): e, U+0301 (cc 81)
  // beside c3 a9, and no surrogate escape.
  assert.ok(units.bytes.includes(Buffer.from([0x5c, 0x22, 0x65, 0xcc, 0x81, 0x5c, 0x22])));
  assert.ok(units.bytes.includes(Buffer.from([0x5c, 0x22, 0xc3, 0xa9, 0x5c, 0x22])));
  assert.ok(units.bytes.includes(Buffer.from([0xf0, 0xa9, 0xb8, 0xbd])));
  assert.ok(!units.bytes.toString("latin1").includes("\\ud"));
  // Every ruleset that names the decomposed letter keeps it decomposed.
  const decomposed = creates.filter((c) => c.content.includes(E_NFD));
  assert.equal(decomposed.length, 3);
  for (const c of decomposed) assert.notEqual(c.content, c.content.normalize("NFC"));
});

test("the seed and the query bodies carry the filter string unchanged", async () => {
  const { sent } = await record();
  const queries = sent.filter((c) => c.url.includes(":runQuery"));
  const mine = queries.filter((c) => c.bytes.includes(Buffer.from("fsr9-us-")));
  assert.equal(mine.length, 4 + 0, "four stored list rows");
  const nfd = mine.filter((c) => c.bytes.includes(Buffer.from(`"stringValue":"${E_NFD}"`, "utf8")));
  assert.equal(nfd.length, 2);
  const nfc = mine.filter((c) => c.bytes.includes(Buffer.from(`"stringValue":"${E_NFC}"`, "utf8")));
  assert.equal(nfc.length, 2);
});

test("a refused get reaches its row, and a ruleset production refuses takes its own rows with it", async () => {
  const { out } = await record({
    scenario: { diffs: ({ collection }) => collection !== "fsr9-un-ctl-false" },
  });
  assert.equal(out.results["fs-rules-v1/unicode/units"].steps["ctl-false"].status, 403);
  assert.equal(out.results["fs-rules-v1/unicode/units"].steps["ctl-true"].status, 404);
  const refused = await record({
    scenario: { refuseSource: (source) => source.includes(`"${ZWJ}".matches`) },
  });
  const regex = refused.out.results["fs-rules-v1/unicode/regex"].steps;
  assert.deepEqual(regex.publishes, { compiled: false });
  assert.deepEqual(regex["fire-dot"], {
    status: -1,
    unresolved: "ruleset unicode-regex did not compile",
  });
  for (const name of ["units", "case", "stored"])
    assert.equal(refused.out.results[`fs-rules-v1/unicode/${name}`].steps.publishes.compiled, true);
  assert.equal(refused.out.closureReady, true);
});

test("an unknown answer to the release delete keeps the run from closing", async () => {
  const { world, fetchImpl, grpc } = createWorld();
  const clock = createClock();
  world.onCall = (method, url) =>
    method === "DELETE" && url.includes("/releases/") ? { status: 503 } : undefined;
  const ctx = createContext({ run: "1790000000301", startedMs: clock.now(), target: PRODUCTION });
  const programs = UNICODE_PROGRAMS.slice(1, 2);
  await assert.rejects(
    runCorpus(
      { programs, principals: PRINCIPALS },
      ctx,
      { fetchImpl, grpc, sleep: clock.sleep, now: clock.now },
      ceilings(programs),
    ),
    (error) => {
      assert.equal(error.partial.closureReady, false);
      assert.deepEqual(error.partial.unknowns, [{ call: "delete release", answer: "HTTP 503" }]);
      return true;
    },
  );
});

test("the fixture keeps the other corpora and adds the four programs", async () => {
  const { out } = await record();
  const fixture = JSON.parse(
    fixtureText({
      programs: UNICODE_PROGRAMS,
      recordings: [out, out],
      meta: { harness: "h", startedAt: "t", sha: "s" },
      existing: {
        version: 1,
        recordedAgainst: {},
        programs: { "fs-rules-v1/shapes/queries": { keep: true } },
      },
    }),
  );
  assert.deepEqual(fixture.programs["fs-rules-v1/shapes/queries"], { keep: true });
  assert.equal(Object.keys(fixture.programs).length, 5);
  const rows = unicodeReport(fixture);
  assert.equal(rows.length, 49);
  assert.ok(rows.every((r) => ["allowed", "denied", "compiled"].includes(r.answer)));
});

test("a step that one of the two recordings lacks is unknown, never the other recording's answer", async () => {
  const { out } = await record();
  const id = "fs-rules-v1/unicode/units";
  const lacking = structuredClone(out);
  delete lacking.results[id].steps["hfish-2"];
  const build = (first, second) =>
    JSON.parse(
      fixtureText({
        programs: UNICODE_PROGRAMS,
        recordings: [first, second],
        meta: { harness: "h", startedAt: "t", sha: "s" },
      }),
    );
  for (const [first, second, name, answer] of [
    [out, lacking, "second lacks it", "unknown"],
    [lacking, out, "first lacks it", "missing"],
  ]) {
    const rows = Object.fromEntries(unicodeReport(build(first, second)).map((r) => [r.row, r]));
    assert.equal(rows["units#hfish-2"].answer, answer, name);
    assert.equal(rows["units#hfish-2"].verdict, "unknown", name);
    assert.equal(rows["units#hfish-1"].answer, "allowed", name);
  }
});

// ---- the report ------------------------------------------------------------------------------

const ALL_ROWS = UNICODE_PROGRAMS.flatMap((p) =>
  p.steps.map((s) => `${p.id.split("/").at(-1)}#${s.id}`),
);

test("the official and fireemu answers cover every row, and are answers", () => {
  assert.equal(ALL_ROWS.length, 49);
  assert.deepEqual(Object.keys(OFFICIAL).toSorted(), ALL_ROWS.toSorted());
  assert.deepEqual(Object.keys(FIXES).toSorted(), ALL_ROWS.toSorted());
  for (const table of [OFFICIAL, FIXES])
    for (const answer of Object.values(table))
      assert.ok(["allowed", "denied", "compiled", "refused"].includes(answer), answer);
});

test("the controls behave as named in both measured tables", () => {
  for (const table of [OFFICIAL, FIXES]) {
    for (const name of ["units", "case", "regex", "stored"]) {
      assert.equal(table[`${name}#publishes`], "compiled", name);
      assert.equal(table[`${name}#ctl-true`], "allowed", name);
      assert.equal(table[`${name}#ctl-false`], "denied", name);
    }
  }
});

test("the report compares each answer with the official emulator and with fireemu", () => {
  const allowed = {
    status: 404,
    body: { error: { code: 404, message: 'Document "x" not found.', status: "NOT_FOUND" } },
  };
  const denied = {
    status: 403,
    body: {
      error: {
        code: 403,
        message: "Missing or insufficient permissions.",
        status: "PERMISSION_DENIED",
      },
    },
  };
  const fixture = {
    programs: {
      "fs-rules-v1/unicode/units": {
        steps: {
          publishes: { compiled: true },
          "ctl-true": allowed,
          "ctl-false": denied,
          "hfish-2": denied,
        },
      },
    },
  };
  const rows = Object.fromEntries(
    unicodeReport(fixture, {
      official: { "units#ctl-true": "allowed", "units#ctl-false": "allowed" },
      fixes: { "units#ctl-true": "denied", "units#ctl-false": "denied" },
    }).map((r) => [r.row, r]),
  );
  assert.equal(rows["units#publishes"].verdict, "no-claim");
  assert.equal(rows["units#ctl-true"].verdict, "agrees");
  assert.equal(rows["units#ctl-true"].fixesVerdict, "differs");
  assert.equal(rows["units#ctl-false"].verdict, "differs");
  assert.equal(rows["units#ctl-false"].fixesVerdict, "agrees");
  assert.equal(rows["units#hfish-2"].verdict, "no-claim");
  assert.equal(rows["units#hfish-1"].answer, "missing");
  assert.match(
    shapesReportLine(rows["units#ctl-false"]),
    /^differs {8}agrees {9}units#ctl-false +denied \(official: allowed, fixes: denied\)$/,
  );
});

test("only bare recorded answers count: an unsettled publication, a transport failure or an extra key is unknown", () => {
  const allowed = {
    status: 404,
    body: { error: { code: 404, message: 'Document "x" not found.', status: "NOT_FOUND" } },
  };
  const fixture = {
    programs: {
      "fs-rules-v1/unicode/case": {
        steps: {
          publishes: { compiled: true },
          "sharp-eq": { ...allowed, publication: "unsettled" },
          "sharp-size": { transport: "reset" },
          "fi-size": { ...allowed, extra: 1 },
        },
      },
    },
  };
  const rows = Object.fromEntries(unicodeReport(fixture).map((r) => [r.row, r]));
  assert.equal(rows["case#sharp-eq"].answer, "unknown");
  assert.equal(rows["case#sharp-size"].answer, "unknown");
  assert.equal(rows["case#fi-size"].answer, "unknown");
  assert.equal(rows["case#publishes"].answer, "compiled");
});

test("a stored list row reports how many documents it returned", () => {
  const withDocs = (n) => ({
    status: 200,
    body: Array.from({ length: n }, () => ({
      document: { name: "projects/p/databases/(default)/documents/fsr9-us-q/d1", fields: {} },
      readTime: "t",
    })),
  });
  const fixture = {
    programs: {
      "fs-rules-v1/unicode/stored": {
        steps: {
          publishes: { compiled: true },
          "q-nfd": withDocs(1),
          "q-nfc": { status: 200, body: [{ readTime: "t" }] },
        },
      },
    },
  };
  const rows = Object.fromEntries(unicodeReport(fixture).map((r) => [r.row, r]));
  assert.equal(rows["stored#q-nfd"].documents, 1);
  assert.equal(rows["stored#q-nfc"].documents, 0);
  assert.match(shapesReportLine(rows["stored#q-nfd"]), /allowed docs=1 /);
});

test("a list row that is allowed but returns another number of documents than the dry runs differs", () => {
  assert.deepEqual(DOCUMENTS, { "stored#q-nfd": 1, "stored#q-nfc": 0, "stored#lq-nfd": 1 });
  const withDocs = (n) => ({
    status: 200,
    body: n
      ? Array.from({ length: n }, () => ({
          document: { name: "projects/p/databases/(default)/documents/fsr9-us-q/d1", fields: {} },
          readTime: "t",
        }))
      : [{ readTime: "t" }],
  });
  const report = (steps) =>
    Object.fromEntries(
      unicodeReport({
        programs: {
          "fs-rules-v1/unicode/stored": { steps: { publishes: { compiled: true }, ...steps } },
        },
      }).map((r) => [r.row, r]),
    );
  const same = report({ "q-nfd": withDocs(1), "q-nfc": withDocs(0), "lq-nfd": withDocs(1) });
  for (const row of ["stored#q-nfd", "stored#q-nfc", "stored#lq-nfd"]) {
    assert.equal(same[row].verdict, "agrees", row);
    assert.equal(same[row].fixesVerdict, "agrees", row);
  }
  // Production matching the decomposed spelling with the composed filter, or finding nothing for the
  // stored spelling, is a difference even though both answers are allows.
  const other = report({ "q-nfd": withDocs(0), "q-nfc": withDocs(1), "lq-nfd": withDocs(2) });
  for (const row of ["stored#q-nfd", "stored#q-nfc", "stored#lq-nfd"]) {
    assert.equal(other[row].answer, "allowed", row);
    assert.equal(other[row].verdict, "differs", row);
    assert.equal(other[row].fixesVerdict, "differs", row);
    assert.match(other[row].detail, /^returned \d documents, official and fixes \d$/, row);
  }
  // A refusal on a row that has a document count is judged as a refusal, not by documents.
  const denied = report({
    "lq-nfc": {
      status: 403,
      body: [
        {
          error: {
            code: 403,
            message: "Missing or insufficient permissions.",
            status: "PERMISSION_DENIED",
          },
        },
      ],
    },
  });
  assert.equal(denied["stored#lq-nfc"].verdict, "agrees");
});

// ---- properties (seeded, deterministic: a failing round is reproduced by its seed) -----------

function generator(seed) {
  let state = seed >>> 0;
  const next = () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (n) => Math.floor(next() * n);
  return { int, pick: (items) => items[int(items.length)] };
}

const ALLOWED = {
  status: 404,
  body: { error: { code: 404, message: 'Document "x" not found.', status: "NOT_FOUND" } },
};
const DENIED = {
  status: 403,
  body: {
    error: {
      code: 403,
      message: "Missing or insufficient permissions.",
      status: "PERMISSION_DENIED",
    },
  },
};
const ROWS = UNICODE_PROGRAMS.flatMap((p) =>
  p.steps
    .filter((s) => !s.publish && s.rpc === "get")
    .map((s) => ({ program: p.id, row: `${p.id.split("/").at(-1)}#${s.id}`, id: s.id })),
);

function fixtureOf(answers) {
  const programs = {};
  for (const { program: id, id: stepId } of ROWS) {
    programs[id] ??= { steps: { publishes: { compiled: true } } };
    programs[id].steps[stepId] = answers[`${id.split("/").at(-1)}#${stepId}`];
  }
  return { programs };
}

test("property: a verdict agrees exactly when the answer equals the claim, for any answers and claims", () => {
  for (let round = 0; round < 300; round += 1) {
    const g = generator(round + 1);
    const answers = {};
    const official = {};
    const fixes = {};
    for (const { row } of ROWS) {
      answers[row] = g.pick([ALLOWED, DENIED]);
      if (g.int(4) > 0) official[row] = g.pick(["allowed", "denied"]);
      if (g.int(4) > 0) fixes[row] = g.pick(["allowed", "denied"]);
    }
    const report = unicodeReport(fixtureOf(answers), { official, fixes });
    for (const { row } of ROWS) {
      const r = report.find((x) => x.row === row);
      const answer = answers[row] === ALLOWED ? "allowed" : "denied";
      assert.equal(r.answer, answer, `seed ${round + 1} ${row}`);
      const verdict = (claim) =>
        claim === undefined ? "no-claim" : claim === answer ? "agrees" : "differs";
      assert.equal(r.verdict, verdict(official[row]), `seed ${round + 1} ${row}`);
      assert.equal(r.fixesVerdict, verdict(fixes[row]), `seed ${round + 1} ${row}`);
    }
  }
});

test("property: an answer with any extra key, status or unreadable body is never an allow or a deny", () => {
  const extras = ["publication", "transport", "headers", "attempts", "x"];
  const statuses = [0, 100, 199, 200, 204, 301, 302, 400, 401, 409, 429, 500, 503];
  for (let round = 0; round < 300; round += 1) {
    const g = generator(round + 1000);
    const { row } = g.pick(ROWS);
    const base = g.pick([ALLOWED, DENIED]);
    const broken = g.pick([
      { ...base, [g.pick(extras)]: g.pick([1, "unsettled", true, null]) },
      { status: g.pick(statuses), body: base.body },
      { status: base.status },
      { status: base.status, body: "not json" },
      { status: base.status, body: [] },
      {},
    ]);
    const answers = Object.fromEntries(ROWS.map((r) => [r.row, ALLOWED]));
    answers[row] = broken;
    const reported = unicodeReport(fixtureOf(answers)).find((r) => r.row === row);
    assert.notEqual(reported.answer, "allowed", `seed ${round + 1000} ${JSON.stringify(broken)}`);
    assert.notEqual(reported.answer, "denied", `seed ${round + 1000} ${JSON.stringify(broken)}`);
  }
});
