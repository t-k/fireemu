import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { CONFORMANCE_DIR, REPO_ROOT } from "./config.mjs";
import {
  checkFixtureDigest,
  enrollmentProblems,
  fixturesWithHarnessDigest,
  gitReader,
  bindingProblems,
  HARNESS_LANES,
  isShallowCheckout,
  KNOWN_UNCONNECTED,
  laneStatus,
  lineageProblems,
  loadLineage,
  rawDigest,
  recordedDigests,
  registryPaths,
  rewriteReport,
  scheme2Digest,
  sourceTokens,
  tokensInReportOrder,
  treeReader,
  unconnectedProblems,
  verifyOutcome,
  WAIVED_FIXTURES,
} from "./harness-registry.mjs";

const digestOf = (text) => scheme2Digest({ files: ["a.mjs"], extra: "" }, () => text);

test("a comment or whitespace edit leaves the scheme-2 digest alone", () => {
  const base = "const a = 1;\nfunction f(x) { return x + a; }\n";
  const edited =
    "// provenance: commit 1111\n/** doc */\nconst   a = 1; // trailing\n\n\nfunction f(x) {\n  /* why */ return x +\n  a;\n}\n";
  assert.equal(digestOf(edited), digestOf(base));
});

test("any token edit changes the digest", () => {
  const base = "const a = 1;\nfunction f(x) { return x + a; }\n";
  for (const changed of [
    "const b = 1;\nfunction f(x) { return x + b; }\n",
    "const a = 2;\nfunction f(x) { return x + a; }\n",
    "const a = 1;\nfunction f(x) { return x - a; }\n",
    "const a = 1;\nfunction f(x) { return x + a; }\nf(1);\n",
    'const a = "1";\nfunction f(x) { return x + a; }\n',
  ])
    assert.notEqual(digestOf(changed), digestOf(base), changed);
});

test("an inserted semicolon and an explicit one are the same token", () => {
  const explicit = "const a = 1;\nfunction f(x) { return x + a; }\n";
  assert.equal(digestOf("const a = 1\nfunction f(x) { return x + a }\n"), digestOf(explicit));
});

// A line break that ends a statement is meaning, and the parser (not a tokenizer) decides what is
// a regular expression, so these pairs differ although their token texts and spacing do not.
const ASI_PAIRS = [
  ["return x", "return\n x"],
  ["a\n++b", "a++\nb"],
  ["async function f(){}", "async\nfunction f(){}"],
  ["function* g(){ yield x }", "function* g(){ yield\n x }"],
  ["l: for(;;){ continue l }", "l: for(;;){ continue\n l }"],
  ["l: for(;;){ break l }", "l: for(;;){ break\n l }"],
];

const wrapAsi = (body) => (/^(return|a)/.test(body) ? `function f(){ ${body}; }` : body);

test("a line break the parser turns into a statement end changes the digest", () => {
  for (const [joined, split] of ASI_PAIRS)
    assert.notEqual(digestOf(wrapAsi(joined)), digestOf(wrapAsi(split)), `${joined} / ${split}`);
});

test("code a tokenizer would read as a comment is still digested", () => {
  const withStatement = "export default function(){}\n/[/*]/.test(''); X = 1; //*/\n";
  const withoutStatement = "export default function(){}\n/[/*]/.test('');\n";
  assert.notEqual(digestOf(withStatement), digestOf(withoutStatement));
  const inAsync = "async function g(s){ await /[/*]/.exec(s); X = 1; //*/\n}\n";
  assert.notEqual(digestOf(inAsync), digestOf("async function g(s){ await /[/*]/.exec(s); }\n"));
  assert.ok(sourceTokens(withStatement).includes("X"));
});

test("the quote style of a string is part of the token", () => {
  assert.notEqual(digestOf("const a = 'x';"), digestOf('const a = "x";'));
});

test("comment-looking text inside strings, templates and regular expressions counts", () => {
  assert.notEqual(digestOf('const a = "// one";'), digestOf('const a = "// two";'));
  assert.notEqual(digestOf("const a = `/* one */`;"), digestOf("const a = `/* two */`;"));
  assert.notEqual(digestOf("const r = /\\/\\* one/;"), digestOf("const r = /\\/\\* two/;"));
  assert.notEqual(digestOf("const a = `x ${ /* c */ b } y`;"), digestOf("const a = `x ${ c } y`;"));
  assert.equal(
    digestOf("const a = `x ${ /* c */ b } y`;"),
    digestOf("const a = `x ${\n  b // c\n} y`;"),
  );
});

test("a slash is a division or a regular expression by context", () => {
  assert.deepEqual(
    sourceTokens("a = b / c / d;").filter((t) => t === "/"),
    ["/", "/"],
  );
  assert.ok(sourceTokens("a = /b\\/c/g.test(d);").includes("/b\\/c/g"));
});

test("a token boundary is never ambiguous and a file boundary matters", () => {
  assert.notEqual(digestOf("ab; c;"), digestOf("a; bc;"));
  const two = (a, b) =>
    scheme2Digest({ files: ["a.mjs", "b.mjs"], extra: "" }, (f) => (f === "a.mjs" ? a : b));
  assert.notEqual(two("x; y;", "z;"), two("x;", "y; z;"));
});

test("the extra inputs and the file names are bound", () => {
  const read = () => "const a = 1;";
  assert.notEqual(
    scheme2Digest({ files: ["a.mjs"], extra: "1" }, read),
    scheme2Digest({ files: ["a.mjs"], extra: "2" }, read),
  );
  assert.notEqual(
    scheme2Digest({ files: ["a.mjs"], extra: "" }, read),
    scheme2Digest({ files: ["b.mjs"], extra: "" }, read),
  );
});

test("source that does not parse is refused, never digested", () => {
  assert.throws(() => digestOf("a b"), /a\.mjs/);
  assert.throws(() => digestOf("const = 1;"), /a\.mjs/);
  assert.throws(() => digestOf('const a = "unterminated;'), /a\.mjs/);
  assert.throws(() => digestOf("const a = `unterminated;"), /a\.mjs/);
});

test("the raw digest is the historical one: the sources joined by a newline, then the extra", () => {
  const lane = { files: ["a.mjs", "b.mjs"], extra: '{"p":1}' };
  const reader = (f) => (f === "a.mjs" ? "A" : "B");
  const expected = createHash("sha256").update('A\nB\n{"p":1}').digest("hex");
  assert.equal(rawDigest(lane, reader), expected);
  assert.notEqual(rawDigest(lane, reader), rawDigest({ ...lane, extra: "x" }, reader));
});

// ---- the acceptance rule ------------------------------------------------------------------

const LANE = { files: ["a.mjs"], extra: "" };
const TREE = { "a.mjs": "// note\nconst a = 1;\n" };
const readTree = (f) => TREE[f];

test("a fixture digest is accepted when it is the raw or the scheme-2 digest of the tree", () => {
  const raw = rawDigest(LANE, readTree);
  const s2 = scheme2Digest(LANE, readTree);
  assert.equal(checkFixtureDigest("lane", LANE, raw, { read: readTree, lineage: [] }).state, "raw");
  assert.equal(
    checkFixtureDigest("lane", LANE, s2, { read: readTree, lineage: [] }).state,
    "scheme2",
  );
  const other = checkFixtureDigest("lane", LANE, "0".repeat(64), { read: readTree, lineage: [] });
  assert.equal(other.state, "stale");
});

test("a hop connects a recorded digest to the current scheme-2 digest, for its lane only", () => {
  const recorded = "1".repeat(64);
  const s2 = scheme2Digest(LANE, readTree);
  const hop = { lane: "lane", from: recorded, to: s2, commit: "c".repeat(40), kind: "scheme" };
  assert.equal(
    checkFixtureDigest("lane", LANE, recorded, { read: readTree, lineage: [hop] }).state,
    "lineage",
  );
  assert.equal(
    checkFixtureDigest("other", LANE, recorded, { read: readTree, lineage: [hop] }).state,
    "stale",
  );
  assert.equal(
    checkFixtureDigest("lane", LANE, recorded, {
      read: readTree,
      lineage: [{ ...hop, to: "2".repeat(64) }],
    }).state,
    "stale",
  );
  assert.equal(
    checkFixtureDigest("lane", LANE, "3".repeat(64), { read: readTree, lineage: [hop] }).state,
    "stale",
  );
});

// ---- the lineage file ---------------------------------------------------------------------

const COMMIT_OLD = "a".repeat(40);
const COMMIT_NEW = "b".repeat(40);
const OLD_TEXT = "// provenance 1111\nconst a = 1;\n";
const NEW_TEXT = "// provenance 2222\nconst a = 1;\n";
const files = { [COMMIT_OLD]: { "a.mjs": OLD_TEXT }, [COMMIT_NEW]: { "a.mjs": NEW_TEXT } };
const reader = (commit) => (file) => files[commit]?.[file];
const goodHop = () => ({
  lane: "lane",
  from: rawDigest(LANE, reader(COMMIT_OLD)),
  to: scheme2Digest(LANE, reader(COMMIT_OLD)),
  commit: COMMIT_OLD,
  kind: "scheme",
});
const problems = (hops, lanes = { lane: LANE }) =>
  lineageProblems(
    { version: 1, hops },
    { lanes, reader, shallow: false, current: reader(COMMIT_NEW) },
  );

test("a hop whose recorded digest reproduces at its commit and whose tokens match is sound", () => {
  assert.deepEqual(problems([goodHop()]), []);
});

test("a hop that misreproduces its recorded digest or its scheme-2 digest is refused", () => {
  assert.match(problems([{ ...goodHop(), from: "9".repeat(64) }]).join("\n"), /recorded digest/);
  assert.match(problems([{ ...goodHop(), to: "9".repeat(64) }]).join("\n"), /scheme-2/);
});

test("the tokens must equal the tokens of the current tree (comments and whitespace only)", () => {
  // The hop was made at COMMIT_OLD; the current tree differs by a token, so `to` no longer holds.
  const changed = { ...files, [COMMIT_OLD]: { "a.mjs": "const a = 2;\n" } };
  const hop = {
    ...goodHop(),
    from: rawDigest(LANE, (f) => changed[COMMIT_OLD][f]),
    to: scheme2Digest(LANE, (f) => changed[COMMIT_OLD][f]),
  };
  const found = lineageProblems(
    { version: 1, hops: [hop] },
    {
      lanes: { lane: LANE },
      reader: (c) => (f) => (c === COMMIT_OLD ? changed[c][f] : readTree(f)),
      shallow: false,
      current: readTree,
    },
  );
  assert.match(found.join("\n"), /current tree/);
});

test("unknown lanes, kinds, malformed hops and duplicates are refused", () => {
  assert.match(problems([{ ...goodHop(), lane: "nope" }]).join("\n"), /unknown lane/);
  assert.match(problems([{ ...goodHop(), kind: "reviewed-non-row" }]).join("\n"), /kind/);
  assert.match(problems([{ ...goodHop(), commit: "abc" }]).join("\n"), /40-hex/);
  assert.match(problems([{ ...goodHop(), from: "xyz" }]).join("\n"), /64-hex/);
  assert.match(problems([goodHop(), goodHop()]).join("\n"), /duplicate/);
  assert.match(problems([{ ...goodHop(), extra: 1 }]).join("\n"), /unexpected/);
});

test("a commit that is not in the history is refused; a shallow clone is a hard failure", () => {
  const missing = () => () => {
    throw new Error("bad object");
  };
  assert.match(
    lineageProblems(
      { version: 1, hops: [goodHop()] },
      { lanes: { lane: LANE }, reader: missing, shallow: false, current: readTree },
    ).join("\n"),
    /not readable/,
  );
  assert.match(
    lineageProblems(
      { version: 1, hops: [goodHop()] },
      { lanes: { lane: LANE }, reader, shallow: true, current: readTree },
    ).join("\n"),
    /shallow/,
  );
});

// ---- the checked-in registry --------------------------------------------------------------

test("every fixture with a harnessDigest is enrolled or waived with a reason", () => {
  assert.deepEqual(enrollmentProblems(), []);
});

test("enrollment problems name an unlisted fixture, a waiver without a reason, and a stale entry", () => {
  const found = enrollmentProblems({
    fixtures: ["a-production.json", "b-production.json", "c-production.json"],
    lanes: { a: { fixture: "a-production.json" } },
    waived: [
      { fixture: "b-production.json", reason: "" },
      { fixture: "gone-production.json", reason: "a real reason here" },
    ],
  });
  assert.match(found.join("\n"), /c-production\.json.*neither enrolled nor waived/);
  assert.match(found.join("\n"), /b-production\.json.*reason/);
  assert.match(found.join("\n"), /gone-production\.json.*no such fixture/);
  assert.ok(!found.join("\n").includes("a-production.json"));
});

test("a fixture that is both enrolled and waived is refused", () => {
  const found = enrollmentProblems({
    fixtures: ["a-production.json"],
    lanes: { a: { fixture: "a-production.json" } },
    waived: [{ fixture: "a-production.json", reason: "a real reason here" }],
  });
  assert.match(found.join("\n"), /both enrolled and waived/);
});

test("the checked-in lineage is sound against the git history", () => {
  const lineage = loadLineage();
  const shallow = execFileSync("git", ["rev-parse", "--is-shallow-repository"], {
    cwd: REPO_ROOT,
    encoding: "utf8",
  }).trim();
  const required = process.env.FIREEMU_REQUIRE_FULL_HISTORY === "1";
  assert.ok(shallow === "false" || !required, "the release job needs the full history");
  assert.deepEqual(
    lineageProblems(lineage, {
      lanes: HARNESS_LANES,
      reader: gitReader,
      shallow: shallow === "true",
    }),
    [],
  );
});

test("every enrolled lane is current, or listed as known unconnected at its present digest", () => {
  assert.deepEqual(unconnectedProblems(), []);
});

test("an unconnected lane, a stale known entry and an unneeded one are each a problem", () => {
  const name = "auth-fs-cross-stage2";
  const lanes = { [name]: HARNESS_LANES[name] };
  assert.match(unconnectedProblems({ lanes, known: {} }).join("\n"), /not connected/);
  assert.match(
    unconnectedProblems({
      lanes,
      known: { [name]: { ...KNOWN_UNCONNECTED[name], currentScheme2: "0" } },
    }).join("\n"),
    /out of date/,
  );
  assert.match(
    unconnectedProblems({
      lanes,
      known: { [name]: { ...KNOWN_UNCONNECTED[name], reason: "short" } },
    }).join("\n"),
    /needs a reason/,
  );
  assert.match(
    unconnectedProblems({
      lanes: { "fs-rules": HARNESS_LANES["fs-rules"] },
      known: { "fs-rules": KNOWN_UNCONNECTED[name] },
    }).join("\n"),
    /is connected/,
  );
  assert.match(
    unconnectedProblems({
      lanes,
      known: { ...KNOWN_UNCONNECTED, nope: KNOWN_UNCONNECTED[name] },
    }).join("\n"),
    /no such lane/,
  );
});

test("the release gate's binding check is clean here and refuses a shallow clone", () => {
  assert.deepEqual(bindingProblems({ shallow: false }), []);
  assert.match(bindingProblems({ shallow: true }).join("\n"), /shallow clone/);
});

test("the enrolled lane definitions cover exactly the files their runners digest", () => {
  for (const lane of Object.values(HARNESS_LANES))
    for (const file of lane.files)
      assert.ok(existsSync(join(CONFORMANCE_DIR, "src", file)), `${file} exists`);
  const fixtures = readdirSync(CONFORMANCE_DIR).filter((f) => f.endsWith("-production.json"));
  for (const lane of Object.values(HARNESS_LANES)) assert.ok(fixtures.includes(lane.fixture));
  assert.ok(WAIVED_FIXTURES.every((w) => fixtures.includes(w.fixture)));
  assert.ok(readFileSync(join(CONFORMANCE_DIR, "harness-lineage.json"), "utf8").length > 0);
});

test("each lane's runner digests exactly the files the registry lists", async () => {
  const { harnessDigest: fsRules } = await import("./fs-rules/run.mjs");
  const { harnessDigest: stage1 } = await import("./auth-fs-cross/run.mjs");
  const { stage2HarnessDigest } = await import("./auth-fs-cross/stage2-record.mjs");
  assert.equal(await fsRules(), rawDigest(HARNESS_LANES["fs-rules"], treeReader));
  assert.equal(await stage1(), rawDigest(HARNESS_LANES["auth-fs-cross"], treeReader));
  assert.equal(
    await stage2HarnessDigest(),
    rawDigest(HARNESS_LANES["auth-fs-cross-stage2"], treeReader),
  );
});

// ---- more of the rule -------------------------------------------------------------------

test("a lane's status is the worst of its recorded digests", () => {
  const raw = rawDigest(LANE, readTree);
  const s2 = scheme2Digest(LANE, readTree);
  const recorded = "1".repeat(64);
  const hop = { lane: "lane", from: recorded, to: s2, commit: "c".repeat(40), kind: "scheme" };
  const status = (digests) =>
    laneStatus(
      "lane",
      { ...LANE, fixture: "x" },
      {
        read: readTree,
        lineage: [hop],
        fixture: {
          programs: Object.fromEntries(digests.map((d, i) => [`p${i}`, { harnessDigest: d }])),
        },
      },
    );
  assert.equal(status([raw, "9".repeat(64)]).state, "stale");
  assert.equal(status(["9".repeat(64), raw]).state, "stale");
  assert.equal(status([raw, recorded]).state, "lineage");
  assert.equal(status([recorded, raw]).state, "lineage");
  assert.equal(status([raw, s2]).state, "raw");
  assert.equal(status([s2, raw]).state, "scheme2");
  assert.equal(status([raw, raw]).state, "raw");
});

test("a fixture row without a harnessDigest is an error, not a pass", () => {
  assert.throws(() => recordedDigests("lane", { programs: { a: {} } }), /without a harnessDigest/);
  assert.throws(() => recordedDigests("lane", { programs: {} }), /without a harnessDigest/);
  assert.throws(
    () => recordedDigests("lane", { programs: { a: { harnessDigest: "abc" } } }),
    /without/,
  );
  assert.throws(() => recordedDigests("auth-fs-cross-stage2", {}), /without a harnessDigest/);
  assert.deepEqual(recordedDigests("auth-fs-cross-stage2", { harnessDigest: "a".repeat(64) }), [
    "a".repeat(64),
  ]);
  const same = { harnessDigest: "b".repeat(64) };
  assert.deepEqual(recordedDigests("lane", { programs: { a: same, b: same } }), ["b".repeat(64)]);
});

test("a commit that is not a full lowercase SHA is refused", () => {
  for (const commit of ["abc1234", "a".repeat(39), "a".repeat(41), "A".repeat(40)])
    assert.match(problems([{ ...goodHop(), commit }]).join("\n"), /40-hex/, commit);
});

test("a digest that is not 64 lowercase hex is refused, in either field", () => {
  for (const key of ["from", "to"])
    for (const value of ["abc", "9".repeat(63), "9".repeat(65), "F".repeat(64)])
      assert.match(
        problems([{ ...goodHop(), [key]: value }]).join("\n"),
        /64-hex/,
        `${key} ${value}`,
      );
});

test("the scheme-2 digest of a hop's commit is checked apart from the current tree's", () => {
  // The recorded digest reproduces at the commit and `to` is today's, but the commit's tokens
  // differ from today's: more than comments changed, and the hop must not stand.
  const commitText = { "a.mjs": "const a = 2;\n" };
  const hop = {
    ...goodHop(),
    from: rawDigest(LANE, (f) => commitText[f]),
    to: scheme2Digest(LANE, readTree),
  };
  const found = lineageProblems(
    { version: 1, hops: [hop] },
    {
      lanes: { lane: LANE },
      reader: () => (f) => commitText[f],
      shallow: false,
      current: readTree,
    },
  );
  assert.equal(found.length, 1);
  assert.match(found[0], /scheme-2 digest at/);
});

test("one bad hop does not hide the next", () => {
  const found = problems([
    { ...goodHop(), extra: 1 },
    { ...goodHop(), from: "9".repeat(64) },
  ]);
  assert.match(found.join("\n"), /unexpected/);
  assert.match(found.join("\n"), /recorded digest does not reproduce/);
});

test("a waiver needs a reason of substance", () => {
  const found = enrollmentProblems({
    fixtures: ["a-production.json"],
    lanes: {},
    waived: [{ fixture: "a-production.json", reason: "short" }],
  });
  assert.match(found.join("\n"), /needs a reason/);
});

test("fixture discovery lists only *-production.json files that hold a harnessDigest", () => {
  const dir = mkdtempSync(join(tmpdir(), "registry-"));
  try {
    writeFileSync(
      join(dir, "a-production.json"),
      '{ "programs": { "p": { "harnessDigest": "x" } } }',
    );
    writeFileSync(join(dir, "b-production.json"), '{ "programs": {} }');
    writeFileSync(join(dir, "c.json"), '{ "harnessDigest": "x" }');
    writeFileSync(join(dir, "d-production.json"), '{"harnessDigest":"x"}');
    assert.deepEqual(fixturesWithHarnessDigest(dir), ["a-production.json", "d-production.json"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---- rewrites (the rebind guard) ----------------------------------------------------------

const readSrc = (file) => readFileSync(join(CONFORMANCE_DIR, "src", file), "utf8");
const laneReport = (report, name) => report.lanes.find((l) => l.lane === name);
const NO_GIT = {
  reader: () => () => {
    throw new Error("no history in this test");
  },
  shallow: false,
};

test("the registry lists every input, fixture and the lineage a rewrite must show it", () => {
  const paths = registryPaths();
  assert.ok(paths.includes("conformance/harness-lineage.json"));
  assert.ok(paths.includes("conformance/src/auth-fs-cross/session.mjs"));
  assert.ok(paths.includes("conformance/src/auth-fs-cross/stage2-orchestrator.mjs"));
  assert.ok(paths.includes("conformance/fs-rules-production.json"));
  assert.deepEqual(paths, [...new Set(paths)].toSorted());
  assert.ok(!paths.includes("conformance/src/auth-fs-cross/run.mjs"), "a runner is not an input");
});

test("a rewrite of provenance comments leaves every lane as it was", () => {
  const file = "auth-fs-cross/session.mjs";
  const edited = readSrc(file).replace(
    /^\/\/ Copied from.*$/m,
    "// Copied from elsewhere, at commit 0000",
  );
  assert.notEqual(edited, readSrc(file));
  const report = rewriteReport({ [`conformance/src/${file}`]: edited }, NO_GIT);
  assert.deepEqual(report.problems, []);
  const lane = laneReport(report, "auth-fs-cross");
  assert.deepEqual(lane.changedInputs, [file]);
  assert.equal(lane.digestChanged, false);
  assert.equal(lane.after.state, lane.before.state);
  assert.equal(laneReport(report, "fs-rules").changedInputs.length, 0);
});

test("a comment-only rewrite that disconnects a raw recorded digest proposes the hop, and adds none", () => {
  const file = "fs-rules/session.mjs";
  const edited = readSrc(file).replace(/^\/\/ Executes.*$/m, "// Executes programs, reworded");
  assert.notEqual(edited, readSrc(file));
  const head = "d".repeat(40);
  const report = rewriteReport(
    { [`conformance/src/${file}`]: edited },
    { ...NO_GIT, proposeCommit: head },
  );
  assert.match(report.problems.join("\n"), /fs-rules: the rewrite disconnects/);
  const lane = laneReport(report, "fs-rules");
  assert.equal(lane.digestChanged, false);
  assert.deepEqual(report.proposedHops, [
    {
      lane: "fs-rules",
      from: laneStatus("fs-rules", HARNESS_LANES["fs-rules"]).saved,
      to: lane.after.current,
      commit: head,
      kind: "scheme",
    },
  ]);
  // Without a commit to name, nothing is proposed; with a token change, nothing is either.
  assert.deepEqual(rewriteReport({ [`conformance/src/${file}`]: edited }, NO_GIT).proposedHops, []);
  const tokenChange = rewriteReport(
    { [`conformance/src/${file}`]: `${readSrc(file)}\nconst x = 1;\n` },
    { ...NO_GIT, proposeCommit: head },
  );
  assert.deepEqual(tokenChange.proposedHops, []);
  assert.match(tokenChange.problems.join("\n"), /fs-rules/);
});

test("a rewrite that changes a token of an input a lane is connected through is refused", () => {
  const file = "fs-rules/session.mjs";
  const edited = `${readSrc(file)}\nconst rewrittenByMistake = 1;\n`;
  const report = rewriteReport({ [`conformance/src/${file}`]: edited }, NO_GIT);
  const lane = laneReport(report, "fs-rules");
  assert.equal(lane.digestChanged, true);
  assert.equal(lane.after.state, "stale");
  assert.match(report.problems.join("\n"), /fs-rules: the rewrite disconnects/);
  // The same file is an input of the AUTH-FS-CROSS copy only through its own session; the lane
  // whose inputs the edit does not touch is left alone.
  assert.ok(!report.problems.join("\n").includes("auth-fs-cross:"));
});

test("a lane that is known unconnected stays so under a comment rewrite, and is refused under a token change", () => {
  const file = "auth-fs-cross/stage2-session.mjs";
  const comment = rewriteReport(
    { [`conformance/src/${file}`]: `// a comment\n${readSrc(file)}` },
    NO_GIT,
  );
  assert.equal(laneReport(comment, "auth-fs-cross-stage2").before.state, "stale");
  assert.deepEqual(comment.problems, []);
  const token = rewriteReport(
    { [`conformance/src/${file}`]: `${readSrc(file)}\nconst x = 1;\n` },
    NO_GIT,
  );
  assert.match(
    token.problems.join("\n"),
    /after the rewrite: auth-fs-cross-stage2: the known-unconnected entry is out of date/,
  );
});

test("a rewrite of a line break in the real stage-1 session is caught", () => {
  const file = "auth-fs-cross/session.mjs";
  const text = readSrc(file);
  assert.ok(text.includes("return id;"));
  const edited = text.replace("return id;", "return\n id;");
  const report = rewriteReport({ [`conformance/src/${file}`]: edited }, NO_GIT);
  assert.equal(laneReport(report, "auth-fs-cross").after.state, "stale");
  assert.match(report.problems.join("\n"), /auth-fs-cross: the rewrite disconnects/);
});

test("a rewrite of the fixture or of the lineage that disconnects a lane is refused", () => {
  const fixturePath = "conformance/auth-fs-cross-production.json";
  const fixture = JSON.parse(readFileSync(join(REPO_ROOT, fixturePath), "utf8"));
  for (const program of Object.values(fixture.programs)) program.harnessDigest = "7".repeat(64);
  const changedFixture = rewriteReport({ [fixturePath]: JSON.stringify(fixture) }, NO_GIT);
  assert.equal(laneReport(changedFixture, "auth-fs-cross").fixtureChanged, true);
  assert.match(changedFixture.problems.join("\n"), /auth-fs-cross: the rewrite disconnects/);
  const noHops = rewriteReport(
    { "conformance/harness-lineage.json": JSON.stringify({ version: 1, hops: [] }) },
    NO_GIT,
  );
  assert.match(noHops.problems.join("\n"), /auth-fs-cross: the rewrite disconnects/);
});

test("a rewritten lineage is verified as well, and a bad text is an error", () => {
  const hop = loadLineage().hops[0];
  const moved = JSON.stringify({ version: 1, hops: [{ ...hop, commit: "1".repeat(40) }] });
  const report = rewriteReport({ "conformance/harness-lineage.json": moved }, NO_GIT);
  assert.match(report.problems.join("\n"), /lineage after the rewrite: hop 0: the sources at/);
  assert.throws(() => rewriteReport({ "conformance/harness-lineage.json": "not json" }, NO_GIT));
  assert.throws(() => rewriteReport({ "conformance/src/x.mjs": 5 }, NO_GIT), /must be a string/);
});

test("a rewrite of a file no lane reads changes nothing", () => {
  const report = rewriteReport(
    { "conformance/src/auth-fs-cross/run.mjs": "// anything\n" },
    NO_GIT,
  );
  assert.deepEqual(report.problems, []);
  assert.ok(report.lanes.every((l) => l.changedInputs.length === 0 && !l.fixtureChanged));
});

test("a hop is never proposed for a lane that was connected through a hop", () => {
  const noHops = rewriteReport(
    { "conformance/harness-lineage.json": JSON.stringify({ version: 1, hops: [] }) },
    { ...NO_GIT, proposeCommit: "d".repeat(40) },
  );
  assert.match(noHops.problems.join("\n"), /auth-fs-cross: the rewrite disconnects/);
  assert.deepEqual(noHops.proposedHops, []);
});

test("a rewritten lineage is checked against the rewritten inputs", () => {
  const file = "auth-fs-cross/session.mjs";
  const report = rewriteReport(
    {
      "conformance/harness-lineage.json": JSON.stringify(loadLineage()),
      [`conformance/src/${file}`]: `${readSrc(file)}\nconst x = 1;\n`,
    },
    { reader: gitReader, shallow: false },
  );
  assert.match(
    report.problems.join("\n"),
    /lineage after the rewrite: hop 0: the scheme-2 digest of the current tree/,
  );
});

// ---- digest inputs the registry lists (review round 1) -------------------------------------

test("scheme 2 digests only JavaScript; data goes through extra", () => {
  const read = () => "{}";
  for (const file of ["a.json", "a.py", "a", "a.mjs.txt", "a.cjs"])
    assert.throws(
      () => scheme2Digest({ files: [file], extra: "" }, read),
      /only \.mjs and \.js/,
      file,
    );
  assert.doesNotThrow(() => scheme2Digest({ files: ["a.js"], extra: "" }, () => "a;"));
});

test("the waived fixtures are exactly these, so a new waiver is a visible edit here", () => {
  // Discovery sees only top-level `*-production.json` files that hold the key `"harnessDigest"`:
  // a fixture named otherwise, in a subdirectory or under another key is not found, so a new lane
  // must follow that convention.
  assert.deepEqual(WAIVED_FIXTURES.map((w) => w.fixture).toSorted(), [
    "auth-federation-followup-production.json",
    "auth-federation-production.json",
    "auth-federation-saml-production.json",
    "auth-tenant-blocking-production.json",
  ]);
  assert.deepEqual(Object.keys(HARNESS_LANES).toSorted(), [
    "auth-account",
    "auth-action",
    "auth-config-sdk",
    "auth-credential",
    "auth-fs-cross",
    "auth-fs-cross-stage2",
    "auth-mfa",
    "fs-config-lifecycle",
    "fs-data-write-list",
    "fs-query-index",
    "fs-rules",
  ]);
});

const literalsOf = (text, pattern) => [...text.matchAll(pattern)].map((m) => m[1]);
/** The file names a runner's private `harnessDigest` reads, from its source. */
const runnerDigestFiles = (runner) => {
  const text = readFileSync(join(CONFORMANCE_DIR, "src", runner), "utf8");
  const start = text.search(/function harnessDigest\(/);
  assert.ok(start >= 0, `${runner} has a harnessDigest`);
  const body = text.slice(start, text.indexOf("\n}\n", start));
  return literalsOf(body, /"([\w./-]+\.(?:mjs|js|json))"/g);
};

test("the registry lists the files each runner's own digest reads", () => {
  const runners = {
    "auth-account": "auth-account/run.mjs",
    "auth-action": "auth-action/run.mjs",
    "auth-config-sdk": "auth-config-sdk/run.mjs",
    "auth-credential": "auth-credential/run.mjs",
    "auth-mfa": "auth-mfa/run.mjs",
    "fs-query-index": "fs-query-index/run.mjs",
    "fs-data-write-list": "fs-query-index/run.mjs",
    "fs-config-lifecycle": "fs-config-lifecycle/run.mjs",
  };
  for (const [name, runner] of Object.entries(runners)) {
    const read = runnerDigestFiles(runner);
    const listed = HARNESS_LANES[name].files;
    // A runner may name a file relative to its own directory.
    for (const file of read)
      assert.ok(
        listed.some((f) => f.endsWith(file)),
        `${name}: ${file} is read but not listed`,
      );
    for (const file of listed)
      assert.ok(
        read.some((f) => file.endsWith(f)),
        `${name}: ${file} is listed but not read`,
      );
  }
});

test("the waived lanes list the files their digests read", () => {
  const federation = readFileSync(join(CONFORMANCE_DIR, "src/auth-federation/record.mjs"), "utf8");
  const region = federation.slice(
    federation.indexOf("export const SOURCES = ["),
    federation.indexOf("].map(", federation.indexOf("export const SOURCES = [")),
  );
  const sources = literalsOf(region, /"([\w./-]+\.mjs)"/g).map(
    (name) =>
      `conformance/src/${join("auth-federation", name).replace(/^auth-federation\/\.\.\//, "")}`,
  );
  for (const w of WAIVED_FIXTURES.filter((x) => x.fixture.startsWith("auth-federation")))
    assert.deepEqual(w.inputs.toSorted(), sources.toSorted(), w.fixture);
  const blocking = WAIVED_FIXTURES.find(
    (w) => w.fixture === "auth-tenant-blocking-production.json",
  );
  for (const file of runnerDigestFiles("auth-tenant-blocking/run.mjs"))
    assert.ok(
      blocking.inputs.some((input) => input.endsWith(`/${file}`)),
      `${file} is read by the runner but not listed`,
    );
});

test("every guarded and waived input exists, and is listed in `paths`", () => {
  const paths = new Set(registryPaths());
  for (const lane of Object.values(HARNESS_LANES))
    for (const path of lane.guarded ?? []) {
      assert.ok(existsSync(join(REPO_ROOT, path)), path);
      assert.ok(paths.has(path), path);
    }
  for (const waived of WAIVED_FIXTURES)
    for (const path of waived.inputs) {
      assert.ok(existsSync(join(REPO_ROOT, path)), path);
      assert.ok(paths.has(path), path);
    }
});

test("a rewrite of an input a waived lane shares is refused, even of a comment", () => {
  // auth-credential/tokens.mjs is an input of enrolled lanes and of the waived tenant-blocking lane.
  const file = "auth-credential/tokens.mjs";
  const report = rewriteReport(
    { [`conformance/src/${file}`]: `// a comment\n${readSrc(file)}` },
    NO_GIT,
  );
  assert.match(
    report.problems.join("\n"),
    /conformance\/src\/auth-credential\/tokens\.mjs: a rewrite changes an input the registry cannot follow: auth-tenant-blocking-production\.json/,
  );
  // An input only a waived lane reads, and a file that carries an enrolled lane's constants.
  for (const path of [
    "conformance/src/auth-tenant-blocking/session.mjs",
    "conformance/src/auth-federation/idp.mjs",
    "conformance/src/auth-mfa/run.mjs",
    "conformance/src/auth-account/corpus.mjs",
    "conformance/src/fs-rules/corpus.mjs",
    "conformance/fs-query-index.indexes.json",
  ]) {
    const text = readFileSync(join(REPO_ROOT, path), "utf8");
    const found = rewriteReport({ [path]: text.endsWith("\n") ? `${text} ` : `${text}\n` }, NO_GIT);
    assert.match(
      found.problems.join("\n"),
      new RegExp(`${path.replaceAll(".", "\\.")}: a rewrite changes`),
      path,
    );
  }
  // A file no lane reads is not affected.
  assert.deepEqual(rewriteReport({ "conformance/src/config.mjs": "// x\n" }, NO_GIT).problems, []);
});

test("the gate's binding problems include an unconnected lane, and a shallow clone by name", () => {
  const found = bindingProblems({ shallow: false, unconnected: () => ["x: not connected"] });
  assert.deepEqual(found, ["x: not connected"]);
  assert.deepEqual(bindingProblems({ shallow: false, unconnected: () => [] }), []);
  assert.match(
    bindingProblems({ shallow: true, unconnected: () => [] }).join("\n"),
    /shallow clone/,
  );
});

test("a real depth-1 clone is a shallow checkout and this one is not", () => {
  assert.equal(isShallowCheckout(), false);
  const dir = mkdtempSync(join(tmpdir(), "shallow-"));
  try {
    execFileSync("git", ["clone", "-q", "--depth", "1", `file://${REPO_ROOT}`, dir], {
      stdio: "ignore",
    });
    assert.equal(isShallowCheckout({ cwd: dir }), true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("verify prints the lanes and exits non-zero on any binding problem", () => {
  const report = {
    lanes: { lane: { state: "raw", saved: "s", current: "c" } },
    lineageProblems: [],
    enrollmentProblems: [],
  };
  const clean = verifyOutcome({ report, problems: [] });
  assert.equal(clean.exitCode, 0);
  assert.deepEqual(clean.lines, ["lane: raw (recorded s, current c)"]);
  assert.deepEqual(clean.errors, []);
  const bad = verifyOutcome({ report, problems: ["an entry is out of date"] });
  assert.equal(bad.exitCode, 1);
  assert.deepEqual(bad.errors, ["an entry is out of date"]);
  assert.equal(
    JSON.parse(verifyOutcome({ json: true, report, problems: [] }).lines[0]).lanes.lane.state,
    "raw",
  );
});

test("a waiver names inputs that exist", () => {
  const base = { fixture: "a-production.json", reason: "a reason long enough to count" };
  const problems = (waiver) =>
    enrollmentProblems({ fixtures: ["a-production.json"], lanes: {}, waived: [waiver] }).join("\n");
  assert.match(problems(base), /names no inputs to guard/);
  assert.match(problems({ ...base, inputs: [] }), /names no inputs to guard/);
  assert.match(
    problems({ ...base, inputs: ["conformance/src/no-such-file.mjs"] }),
    /the guarded input conformance\/src\/no-such-file\.mjs does not exist/,
  );
  assert.equal(problems({ ...base, inputs: ["conformance/src/config.mjs"] }), "");
});

test("the parser reports every real input's tokens already in source order", () => {
  // An inserted semicolon is reported at the end of the token before it, so the report order is
  // the position order and the sort is only a guard; this pins the property on the real inputs
  // and on the line-break cases.
  const ordered = (text, label) => {
    const at = tokensInReportOrder(text).map((token) => token.at);
    assert.deepEqual(
      at,
      at.toSorted((a, b) => a - b),
      label,
    );
  };
  for (const lane of Object.values(HARNESS_LANES))
    for (const file of lane.files) ordered(treeReader(file), file);
  for (const [joined, split] of ASI_PAIRS) {
    ordered(wrapAsi(joined), joined);
    ordered(wrapAsi(split), split);
  }
});
