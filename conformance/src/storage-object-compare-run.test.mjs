import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  compareCommand,
  compareReport,
  differenceKey,
  loadFixture,
  normalizeCommand,
  readReceipt,
  reportText,
} from "./storage-object-compare/run.mjs";
import {
  LOOPBACK_PROFILE,
  rehearsalPlan,
  standinSha256,
} from "./storage-object-compare/rehearse.mjs";

const RUN_JS = fileURLToPath(new URL("./storage-object-compare/run.mjs", import.meta.url));
const BUCKET = "prod-bucket.firebasestorage.app";
const PROJECT = "prod-bucket";
const RUN1 = "0123456789abcdef0123";
const RUN2 = "fedcba9876543210fedc";
const quiet = () => {};

const capture = (
  sequence,
  run,
  {
    url,
    status = 200,
    headers = { "content-type": "application/json; charset=UTF-8" },
    body = '{"kind":"storage#objects"}',
  } = {},
) => ({
  sequence,
  request: {
    method: "GET",
    url:
      url ??
      `https://storage.googleapis.com/storage/v1/b/${BUCKET}/o?prefix=storage-object%2F${run}%2F`,
  },
  response: { status, headers, bodyBase64: Buffer.from(body).toString("base64") },
});
const lines = (rows) => `${rows.map((row) => JSON.stringify(row)).join("\n")}\n`;

function productionDirectory(run, { outcome = "recorded", failedRecipes = [], bodies } = {}) {
  const directory = mkdtempSync(join(tmpdir(), "compare-run-"));
  writeFileSync(
    join(directory, "meta.json"),
    JSON.stringify({ runId: run, outcome, failedRecipes }),
  );
  writeFileSync(
    join(directory, "captures.jsonl"),
    lines([
      capture(2, run, { body: bodies?.[0] }),
      capture(3, run, {
        url: `https://firebasestorage.googleapis.com/v0/b/${BUCKET}/o/storage-object%2F${run}%2Fa.bin`,
        status: 404,
        body: '{"error":{"code":404,"message":"Not Found."}}',
        ...(bodies?.[1] ? { body: bodies[1] } : {}),
      }),
    ]),
  );
  writeFileSync(
    join(directory, "events.jsonl"),
    lines([
      {
        type: "recipe-finish",
        recipeId: "storage-object/gcs/a",
        firstSequence: 2,
        lastSequence: 3,
      },
    ]),
  );
  return directory;
}

const options = (runs, extra = {}) => ({
  run: runs,
  bucket: BUCKET,
  project: PROJECT,
  out: join(mkdtempSync(join(tmpdir(), "compare-out-")), "fx"),
  ...extra,
});

test("normalize writes an index and one file per recipe from equivalent recordings", () => {
  const opts = options([productionDirectory(RUN1), productionDirectory(RUN2)]);
  const messages = [];
  const index = normalizeCommand(opts, (text) => messages.push(text));
  assert.equal(index.equivalentRecordings, true);
  assert.deepEqual(index.runIds, [RUN1, RUN2]);
  assert.ok(existsSync(join(opts.out, "index.json")));
  assert.ok(existsSync(join(opts.out, "gcs--a.json")));
  assert.match(messages[0], /2 files in .*; 2 exchanges; equivalent recordings: true/);
  const fixture = loadFixture(opts.out);
  assert.equal(fixture.recipes.get("storage-object/gcs/a").length, 2);
  assert.equal(fixture.recipes.get("storage-object/gcs/a")[1].status, 404);
});

test("normalize needs its options and a recording", () => {
  for (const name of ["bucket", "project", "out"]) {
    const opts = options([productionDirectory(RUN1)]);
    delete opts[name];
    assert.throws(() => normalizeCommand(opts, quiet), new RegExp(`--${name} is required`));
  }
  assert.throws(() => normalizeCommand(options([]), quiet), /--run is required/);
});

test("normalize refuses a recording that is not complete", () => {
  assert.throws(
    () =>
      normalizeCommand(options([productionDirectory(RUN1, { outcome: "needs-recovery" })]), quiet),
    /not a complete recording/,
  );
  assert.throws(
    () =>
      normalizeCommand(
        options([productionDirectory(RUN1, { failedRecipes: [{ recipeId: "x" }] })]),
        quiet,
      ),
    /not a complete recording/,
  );
});

test("normalize refuses recordings that do not normalize to the same rows, unless told to allow it", () => {
  const different = [
    productionDirectory(RUN1),
    productionDirectory(RUN2, { bodies: ['{"kind":"storage#objects","items":[]}'] }),
  ];
  const opts = options(different);
  assert.throws(() => normalizeCommand(opts, quiet), /do not normalize to the same rows/);
  assert.equal(existsSync(opts.out), false);
  const allowed = normalizeCommand({ ...options(different), "allow-different": "yes" }, quiet);
  assert.equal(allowed.equivalentRecordings, false);
});

test("normalize writes nothing when the scan refuses something", () => {
  const leaking = productionDirectory(RUN1, {
    bodies: ['{"kind":"storage#objects","contact":"person@company.co.jp"}'],
  });
  const opts = options([leaking]);
  assert.throws(() => normalizeCommand(opts, quiet), /email outside example\.com/);
  assert.equal(existsSync(opts.out), false);
  const forbiddenFile = join(mkdtempSync(join(tmpdir(), "compare-forbidden-")), "forbidden.txt");
  writeFileSync(forbiddenFile, "SECRETWORD\n\n");
  const named = options([productionDirectory(RUN1, { bodies: ['{"kind":"SECRETWORD"}'] })], {
    "forbidden-file": forbiddenFile,
  });
  assert.throws(() => normalizeCommand(named, quiet), /private or unmasked/);
  assert.equal(existsSync(named.out), false);
});

test("the real bucket and project never survive into a fixture, even if a mask missed them", () => {
  const opts = options([productionDirectory(RUN1)]);
  normalizeCommand(opts, quiet);
  for (const name of ["index.json", "gcs--a.json"]) {
    const text = readFileSync(join(opts.out, name), "utf8");
    assert.equal(text.includes(BUCKET), false);
    assert.equal(text.includes(PROJECT), false);
  }
});

test("a fixture whose files do not match its index is refused", () => {
  const opts = options([productionDirectory(RUN1)]);
  normalizeCommand(opts, quiet);
  const file = join(opts.out, "gcs--a.json");
  const parsed = JSON.parse(readFileSync(file, "utf8"));
  writeFileSync(
    file,
    JSON.stringify({ ...parsed, rows: 1, exchanges: parsed.exchanges.slice(0, 1) }),
  );
  assert.throws(() => loadFixture(opts.out), /does not match the index/);
  writeFileSync(file, JSON.stringify({ ...parsed, recipeId: "storage-object/other" }));
  assert.throws(() => loadFixture(opts.out), /does not match the index/);
});

// ---- compare ---------------------------------------------------------------------------------

const LOCAL_BUCKET = "example.appspot.com";
const LOCAL_PROJECT = "example-project";
function localJournal(run, rows) {
  const directory = mkdtempSync(join(tmpdir(), "compare-local-"));
  const path = join(directory, "journal.jsonl");
  writeFileSync(
    path,
    lines([
      {
        type: "recipe-begin",
        recipeId: "storage-object/gcs/a",
        prefix: `storage-object/${run}/`,
        sequence: 1,
      },
      ...rows.map((row) => ({ type: "lean-capture", ...row })),
      {
        type: "recipe-finish",
        recipeId: "storage-object/gcs/a",
        firstSequence: 2,
        lastSequence: 2 + rows.length - 1,
      },
    ]),
  );
  return path;
}
const localRows = (run, over = {}) => [
  capture(2, run, {
    url: `https://storage.googleapis.com/storage/v1/b/${LOCAL_BUCKET}/o?prefix=storage-object%2F${run}%2F`,
    ...over,
  }),
  capture(3, run, {
    url: `https://firebasestorage.googleapis.com/v0/b/${LOCAL_BUCKET}/o/storage-object%2F${run}%2Fa.bin`,
    status: 404,
    body: '{"error":{"code":404,"message":"Not Found."}}',
  }),
];
function receiptFor(journal, fixture, over = {}) {
  const receipt = {
    fireemu: { binarySha256: "a".repeat(64), version: "fireemu 0.9.0", commit: "b".repeat(40) },
    recorder: { commit: "c".repeat(40), clean: true },
    standinSha256: standinSha256(),
    fixtureIndexSha256: createHash("sha256")
      .update(readFileSync(join(fixture, "index.json")))
      .digest("hex"),
    rulesSha256: "d".repeat(64),
    journalSha256: createHash("sha256").update(readFileSync(journal)).digest("hex"),
    result: { status: "LOCAL_COMPLETE", completedRecipes: [1, 0], requests: 2, exitCode: 0 },
    ...over,
  };
  const path = `${journal}.receipt.json`;
  writeFileSync(path, JSON.stringify(receipt));
  return path;
}
function fixtureDirectory() {
  const opts = options([productionDirectory(RUN1)]);
  normalizeCommand(opts, quiet);
  return opts.out;
}

test("compare reports a MATCH for identical exchanges (the content type, headers and body exact)", () => {
  const fixture = fixtureDirectory();
  const journal = localJournal("aaaabbbbccccdddd0001", localRows("aaaabbbbccccdddd0001"));
  const messages = [];
  const report = compareCommand(
    { fixture, journal, receipt: receiptFor(journal, fixture) },
    (text) => messages.push(text),
  );
  assert.deepEqual(report.total, {
    MATCH: 2,
    DIVERGENCE: 0,
    LOCAL_UNIMPLEMENTED: 0,
    TAINTED: 0,
    ONLY_PRODUCTION: 0,
    ONLY_LOCAL: 0,
    NOT_RUN: 0,
  });
  assert.deepEqual(report.fireemu, {
    binarySha256: "a".repeat(64),
    version: "fireemu 0.9.0",
    commit: "b".repeat(40),
  });
  assert.match(messages[0], /fireemu fireemu 0\.9\.0 commit b{40} binary sha256 a{64}/);
  assert.match(messages[0], /total: \{"MATCH":2/);
});

test("compare reports DIVERGENCE with its kinds, the most frequent differences, and a recipe that did not run", () => {
  const fixture = fixtureDirectory();
  const journal = localJournal(
    "aaaabbbbccccdddd0001",
    localRows("aaaabbbbccccdddd0001", {
      headers: { "content-type": "application/json; charset=utf-8" },
    }),
  );
  const reportPath = join(mkdtempSync(join(tmpdir(), "compare-report-")), "report.json");
  const report = compareCommand(
    { fixture, journal, receipt: receiptFor(journal, fixture), report: reportPath },
    quiet,
  );
  assert.equal(report.total.DIVERGENCE, 1);
  assert.equal(report.total.MATCH, 1);
  assert.deepEqual(report.differenceKinds, { contentType: 1 });
  assert.match(
    Object.keys(report.byDifference)[0],
    /^contentType "application\/json; charset=UTF-8" -> "application\/json; charset=utf-8"$/,
  );
  assert.deepEqual(JSON.parse(readFileSync(reportPath, "utf8")).total, report.total);
  const text = reportText(report);
  assert.match(text, /most frequent differences:\n  1  contentType/);
  assert.match(text, /storage-object\/gcs\/a: \{"MATCH":1,"DIVERGENCE":1/);
  assert.match(text, /#1 GET \/storage\/v1\/b\/<BUCKET>\/o: contentType/);
  // A recipe the journal does not have is reported as not run.
  const fixtureObject = loadFixture(fixture);
  fixtureObject.recipes.set(
    "storage-object/gcs/missing",
    fixtureObject.recipes.get("storage-object/gcs/a"),
  );
  const missing = compareReport({
    fixture: fixtureObject,
    journal,
    localBucket: LOCAL_BUCKET,
    localProject: LOCAL_PROJECT,
    receipt: JSON.parse(readFileSync(receiptFor(journal, fixture), "utf8")),
  });
  assert.equal(missing.recipes.at(-1).ran, false);
  assert.match(reportText(missing), /storage-object\/gcs\/missing: NOT RUN/);
});

test("compare needs a fixture, a journal and a receipt", () => {
  for (const name of ["fixture", "journal", "receipt"]) {
    const given = { fixture: "a", journal: "b", receipt: "c" };
    delete given[name];
    assert.throws(() => compareCommand(given, quiet), new RegExp(`--${name} is required`));
  }
});

test("a receipt that does not describe this journal, this fixture and the current stand-in is refused, field by field", () => {
  const fixture = fixtureDirectory();
  const journal = localJournal("aaaabbbbccccdddd0001", localRows("aaaabbbbccccdddd0001"));
  const indexSha256 = loadFixture(fixture).indexSha256;
  const read = (over, extra = {}) =>
    readReceipt(receiptFor(journal, fixture, over), journal, {
      fixtureIndexSha256: indexSha256,
      ...extra,
    });
  assert.equal(read({}).fireemu.commit, "b".repeat(40));
  assert.throws(() => read({ journalSha256: "0".repeat(64) }), /does not describe this journal/);
  assert.throws(() => read({ journalSha256: undefined }), /does not describe this journal/);
  const fireemuCases = [
    { binarySha256: "a".repeat(64), commit: "short" },
    { binarySha256: "a".repeat(64), commit: "B".repeat(40) },
    { binarySha256: "a", commit: "b".repeat(40) },
    { binarySha256: "A".repeat(64), commit: "b".repeat(40) },
    { commit: "b".repeat(40) },
    undefined,
  ];
  for (const fireemu of fireemuCases)
    assert.throws(() => read({ fireemu }), /does not bind a fireemu commit/);
  const recorderCases = [
    { commit: "", clean: true },
    { commit: "short", clean: true },
    { commit: "c".repeat(40), clean: false },
    { commit: "c".repeat(40) },
    { commit: "C".repeat(40), clean: true },
    undefined,
  ];
  for (const recorder of recorderCases)
    assert.throws(() => read({ recorder }), /does not bind a clean recorder commit/);
  assert.throws(() => read({ standinSha256: "0".repeat(64) }), /another stand-in/);
  assert.throws(() => read({ standinSha256: undefined }), /another stand-in/);
  assert.throws(() => read({ fixtureIndexSha256: "0".repeat(64) }), /another fixture/);
  assert.throws(() => read({ fixtureIndexSha256: undefined }), /another fixture/);
  assert.throws(
    () =>
      readReceipt(receiptFor(journal, fixture), journal, { fixtureIndexSha256: "0".repeat(64) }),
    /another fixture/,
  );
  assert.throws(() => readReceipt(receiptFor(journal, fixture), journal), /another fixture/);
  for (const rulesSha256 of [undefined, "short", "D".repeat(64)])
    assert.throws(() => read({ rulesSha256 }), /does not bind the Rules file/);
});

test("a receipt of a rehearsal that did not finish is refused, unless an incomplete rehearsal is allowed", () => {
  const fixture = fixtureDirectory();
  const journal = localJournal("aaaabbbbccccdddd0001", localRows("aaaabbbbccccdddd0001"));
  const indexSha256 = loadFixture(fixture).indexSha256;
  for (const result of [
    { status: "LOCAL_BLOCKED", exitCode: 0 },
    { status: "LOCAL_COMPLETE", exitCode: 2 },
    { status: "LOCAL_COMPLETE" },
    { exitCode: 0 },
    undefined,
  ]) {
    const path = receiptFor(journal, fixture, { result });
    assert.throws(
      () => readReceipt(path, journal, { fixtureIndexSha256: indexSha256 }),
      /did not finish/,
    );
    assert.deepEqual(
      readReceipt(path, journal, { fixtureIndexSha256: indexSha256, allowIncomplete: true }).result,
      result,
    );
  }
});

test("the rehearsal runs the recorder's local aggregate in the strict profile against the bound binary", () => {
  const plan = rehearsalPlan({
    fireemuBinary: "/bin/fireemu",
    recorderDir: "/rec",
    rulesFile: "/rules.rules",
    fixtureDir: "/fx",
    outDir: "/out",
    sandbox: true,
  });
  assert.equal(plan.cwd, "/rec/conformance");
  assert.deepEqual(plan.command.slice(0, 4), [
    "sandbox-exec",
    "-f",
    "/out/loopback.sb",
    "/bin/fireemu",
  ]);
  assert.deepEqual(plan.command.slice(4, 14), [
    "exec",
    "--project",
    "example-project",
    "--config",
    "/out/fireemu.config.json",
    "--firebase-json",
    "/out/firebase.json",
    "--only",
    "storage,auth",
    "--",
  ]);
  assert.match(
    plan.command.at(-1),
    /node --import .*rehearsal-standin\.mjs src\/storage-object\/local-aggregate\.mjs$/,
  );
  assert.deepEqual(JSON.parse(plan.files["/out/fireemu.config.json"]), {
    schemaVersion: 1,
    profile: "strict",
    auth: { idTokenSigning: "session-rsa" },
  });
  assert.deepEqual(JSON.parse(plan.files["/out/firebase.json"]), {
    storage: { rules: "/rules.rules" },
  });
  assert.equal(plan.files["/out/loopback.sb"], LOOPBACK_PROFILE);
  assert.deepEqual(plan.env, {
    STORAGE_OBJECT_RULES_SOURCE: "/rules.rules",
    STORAGE_OBJECT_LOCAL_WIRE: "lean",
    STORAGE_OBJECT_LOCAL_RECORDINGS: "1",
    STANDIN_FIXTURE: "/fx",
  });
  const open = rehearsalPlan({
    fireemuBinary: "/bin/fireemu",
    recorderDir: "/rec",
    rulesFile: "/r",
    fixtureDir: "/fx",
    outDir: "/out",
    sandbox: false,
  });
  assert.equal(open.command[0], "/bin/fireemu");
  assert.equal("/out/loopback.sb" in open.files, false);
  assert.match(LOOPBACK_PROFILE, /deny network-outbound \(remote ip\)/);
  assert.match(LOOPBACK_PROFILE, /allow network-outbound \(remote ip "localhost:\*"\)/);
});

test("the command line refuses a bad command or argument with a message and exit code 2", () => {
  for (const args of [
    [],
    ["unknown"],
    ["normalize", "--bucket"],
    ["normalize", "bucket", "x"],
    ["compare"],
  ]) {
    const result = spawnSync(process.execPath, [RUN_JS, ...args], { encoding: "utf8" });
    assert.equal(result.status, 2, args.join(" "));
    assert.ok(result.stderr.length > 0);
  }
  mkdirSync(join(tmpdir(), "compare-cli"), { recursive: true });
});

test("normalize creates the output directory and its missing parents", () => {
  const opts = options([productionDirectory(RUN1)]);
  opts.out = join(mkdtempSync(join(tmpdir(), "compare-nested-")), "a", "b", "fx");
  normalizeCommand(opts, quiet);
  assert.ok(existsSync(join(opts.out, "index.json")));
});

test("a difference is described by its kind and what identifies it, so that equal ones count together", () => {
  assert.equal(differenceKey({ kind: "status", production: 200, local: 404 }), "status 200 -> 404");
  assert.equal(
    differenceKey({ kind: "contentType", production: "a/b", local: null }),
    'contentType "a/b" -> null',
  );
  assert.equal(
    differenceKey({ kind: "bodyType", production: "json", local: "text" }),
    'bodyType "json" -> "text"',
  );
  assert.equal(
    differenceKey({ kind: "headerValue", header: "vary", production: "a", local: "b" }),
    "headerValue vary",
  );
  assert.equal(
    differenceKey({ kind: "missingHeader", header: "expires", production: "x" }),
    "missingHeader expires",
  );
  assert.equal(
    differenceKey({ kind: "extraHeader", header: "pragma", local: "x" }),
    "extraHeader pragma",
  );
  assert.equal(
    differenceKey({ kind: "body", path: "$.etag", production: "a", local: "b" }),
    "body $.etag",
  );
  assert.equal(differenceKey({ kind: "body", production: "a", local: "b" }), "body ");
  assert.equal(differenceKey({ kind: "requestQuery", production: [], local: [] }), "requestQuery");
  assert.equal(
    differenceKey({ kind: "status", production: "x".repeat(100), local: 1 }).length < 80,
    true,
  );
});

// ---- the command line, end to end ---------------------------------------------------------------

const cli = (...args) => spawnSync(process.execPath, [RUN_JS, ...args], { encoding: "utf8" });

test("the command line normalizes with several --run, and compares with a receipt and a report", () => {
  const out = join(mkdtempSync(join(tmpdir(), "compare-cli-")), "fx");
  const normalized = cli(
    "normalize",
    "--run",
    productionDirectory(RUN1),
    "--run",
    productionDirectory(RUN2),
    "--bucket",
    BUCKET,
    "--project",
    PROJECT,
    "--out",
    out,
  );
  assert.equal(normalized.status, 0, normalized.stderr);
  assert.match(normalized.stdout, /equivalent recordings: true/);
  assert.deepEqual(JSON.parse(readFileSync(join(out, "index.json"), "utf8")).runIds, [RUN1, RUN2]);
  const journal = localJournal("aaaabbbbccccdddd0001", localRows("aaaabbbbccccdddd0001"));
  const report = `${journal}.report.json`;
  const compared = cli(
    "compare",
    "--fixture",
    out,
    "--journal",
    journal,
    "--receipt",
    receiptFor(journal, out),
    "--report",
    report,
  );
  assert.equal(compared.status, 0, compared.stderr);
  assert.match(compared.stdout, /total: \{"MATCH":2/);
  assert.equal(JSON.parse(readFileSync(report, "utf8")).total.MATCH, 2);
  const bad = cli(
    "compare",
    "--fixture",
    out,
    "--journal",
    journal,
    "--receipt",
    receiptFor(journal, out, { journalSha256: "0".repeat(64) }),
  );
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /does not describe this journal/);
  const incomplete = receiptFor(journal, out, { result: { status: "LOCAL_BLOCKED", exitCode: 0 } });
  assert.equal(
    cli("compare", "--fixture", out, "--journal", journal, "--receipt", incomplete).status,
    2,
  );
  assert.equal(
    cli(
      "compare",
      "--fixture",
      out,
      "--journal",
      journal,
      "--receipt",
      incomplete,
      "--allow-incomplete",
      "yes",
    ).status,
    0,
  );
});

test("the command line passes every option of rehearse through", () => {
  const result = cli(
    "rehearse",
    "--fireemu",
    "/absent",
    "--fireemu-commit",
    "b".repeat(40),
    "--recorder",
    "/absent",
    "--rules",
    "/absent",
    "--fixture",
    "/absent",
    "--out",
    "/tmp/absent-out",
  );
  assert.equal(result.status, 2);
  assert.match(result.stderr, /fireemuBinary does not exist/);
  const noCommit = cli(
    "rehearse",
    "--fireemu",
    "/absent",
    "--recorder",
    "/absent",
    "--rules",
    "/absent",
    "--fixture",
    "/absent",
    "--out",
    "/tmp/absent-out",
  );
  assert.match(noCommit.stderr, /full commit SHA/);
});

test("an argument without a value, or without --, is refused with its name", () => {
  const dangling = cli("normalize", "--bucket", "b", "--project");
  assert.equal(dangling.status, 2);
  assert.match(dangling.stderr, /bad argument: --project/);
  const bare = cli("normalize", "bucket", "b");
  assert.match(bare.stderr, /bad argument: bucket/);
  assert.match(cli("unknown").stderr, /usage/);
});

test("the index records what the scan was given: whether a private list was used, how many entries, and its digest", () => {
  const file = join(mkdtempSync(join(tmpdir(), "compare-forbidden-")), "forbidden.txt");
  writeFileSync(file, "ALPHA\nBETA\n\n  GAMMA  \n");
  const used = options([productionDirectory(RUN1)], { "forbidden-file": file });
  const index = normalizeCommand(used, quiet);
  assert.deepEqual(index.scan, {
    forbiddenFileUsed: true,
    forbiddenEntries: 3,
    forbiddenListSha256: createHash("sha256").update("ALPHA\nBETA\nGAMMA").digest("hex"),
  });
  assert.deepEqual(JSON.parse(readFileSync(join(used.out, "index.json"), "utf8")).scan, index.scan);
  assert.equal(
    readFileSync(join(used.out, "index.json"), "utf8").includes(file),
    false,
    "the path is not recorded",
  );
  const none = normalizeCommand(options([productionDirectory(RUN1)]), quiet);
  assert.deepEqual(none.scan, {
    forbiddenFileUsed: false,
    forbiddenEntries: 0,
    forbiddenListSha256: createHash("sha256").update("").digest("hex"),
  });
});

test("normalize refuses what the real bucket or project leaves behind, wherever a mask does not reach", () => {
  for (const url of [
    `https://x.example/storage/v1/b/${BUCKET}/o?${BUCKET}=1`,
    `https://x.example/storage/v1/b/${BUCKET}/o?${PROJECT}=1`,
  ]) {
    const directory = productionDirectory(RUN1);
    writeFileSync(
      join(directory, "captures.jsonl"),
      lines([capture(2, RUN1, { url }), capture(3, RUN1)]),
    );
    const opts = options([directory]);
    assert.throws(() => normalizeCommand(opts, quiet), /private or unmasked identifier/);
    assert.equal(existsSync(opts.out), false);
  }
});

test("a fixture whose rows were edited without changing their number is refused by the digests", () => {
  const opts = options([productionDirectory(RUN1)]);
  normalizeCommand(opts, quiet);
  const file = join(opts.out, "gcs--a.json");
  const parsed = JSON.parse(readFileSync(file, "utf8"));
  parsed.exchanges[0].status = 500;
  writeFileSync(file, JSON.stringify(parsed));
  assert.throws(() => loadFixture(opts.out), /does not match the index digests/);
  // An index without digests for a recipe is refused too.
  const second = options([productionDirectory(RUN1)]);
  normalizeCommand(second, quiet);
  const index = JSON.parse(readFileSync(join(second.out, "index.json"), "utf8"));
  index.recipes[0].digests = { [RUN1]: "0".repeat(64) };
  writeFileSync(join(second.out, "index.json"), JSON.stringify(index));
  assert.throws(() => loadFixture(second.out), /does not match the index digests/);
});

test("a recipe that did not run is counted by its rows, and an incomplete comparison is never clean", () => {
  const fixture = fixtureDirectory();
  const journal = localJournal("aaaabbbbccccdddd0001", localRows("aaaabbbbccccdddd0001"));
  const fixtureObject = loadFixture(fixture);
  const rows = fixtureObject.recipes.get("storage-object/gcs/a");
  fixtureObject.recipes.set("storage-object/gcs/missing", rows);
  fixtureObject.recipes.set("storage-object/gcs/missing-too", rows.slice(0, 1));
  const report = compareReport({
    fixture: fixtureObject,
    journal,
    localBucket: LOCAL_BUCKET,
    localProject: LOCAL_PROJECT,
    receipt: JSON.parse(readFileSync(receiptFor(journal, fixture), "utf8")),
  });
  assert.equal(report.total.NOT_RUN, 3);
  assert.equal(report.total.MATCH, 2);
  assert.equal(
    report.recipes.find((recipe) => recipe.recipeId.endsWith("missing")).counts.NOT_RUN,
    2,
  );
  assert.match(reportText(report), /storage-object\/gcs\/missing: NOT RUN \(2 rows\)/);
  assert.equal(report.fixtureIndexSha256, fixtureObject.indexSha256);
});

test("the report says how many production rows have a body layout that cannot be judged, and the layout is judged where known", () => {
  const fixture = fixtureDirectory();
  const journal = localJournal("aaaabbbbccccdddd0001", localRows("aaaabbbbccccdddd0001"));
  const report = compareReport({
    fixture: loadFixture(fixture),
    journal,
    localBucket: LOCAL_BUCKET,
    localProject: LOCAL_PROJECT,
    receipt: JSON.parse(readFileSync(receiptFor(journal, fixture), "utf8")),
  });
  // The synthetic recording carries no byte count, so no layout is known.
  assert.equal(report.layoutUnjudgedProductionRows, 2);
  assert.match(reportText(report), /body layout cannot be judged: 2/);
  const known = loadFixture(fixture);
  known.recipes.get("storage-object/gcs/a").forEach((row) => (row.layout = 74));
  const judged = compareReport({
    fixture: known,
    journal,
    localBucket: LOCAL_BUCKET,
    localProject: LOCAL_PROJECT,
    receipt: JSON.parse(readFileSync(receiptFor(journal, fixture), "utf8")),
  });
  assert.equal(judged.layoutUnjudgedProductionRows, 0);
});

test("the report text lists at most 30 frequent differences, 5 divergences per recipe and 4 differences per divergence, with values cut short", () => {
  const long = "v".repeat(60);
  const diffs = Array.from({ length: 5 }, (_, i) => ({
    kind: "headerValue",
    header: `h${i}`,
    production: long,
    local: long,
  }));
  const report = {
    fixtureRunIds: ["r1", "r2"],
    fireemu: { version: "v", commit: "c", binarySha256: "s" },
    recorder: { commit: "rc" },
    rehearsalResult: { status: "LOCAL_COMPLETE" },
    total: {},
    layoutUnjudgedProductionRows: 0,
    differenceKinds: {},
    byDifference: Object.fromEntries(Array.from({ length: 35 }, (_, i) => [`key${i}`, 100 - i])),
    recipes: [
      {
        recipeId: "storage-object/gcs/a",
        ran: true,
        counts: { DIVERGENCE: 6 },
        results: Array.from({ length: 6 }, (_, i) => ({
          n: i + 1,
          outcome: "DIVERGENCE",
          route: "GET /x",
          differences: diffs,
        })),
      },
    ],
  };
  const text = reportText(report);
  assert.equal(text.split("\n").filter((line) => /^ {2}\d+ {2}key/.test(line)).length, 30);
  assert.match(text, /key29/);
  assert.doesNotMatch(text, /key30/);
  const shown = text.split("\n").filter((line) => line.startsWith("  #"));
  assert.equal(shown.length, 5);
  for (const line of shown) {
    const parts = line.split(" | ");
    assert.equal(parts.length, 4);
    assert.match(parts[0], /headerValue h0 "v{39} "v{39}$/);
    assert.doesNotMatch(line, /v{41}/);
  }
});

test("a difference key keeps the first 48 characters of each value", () => {
  const key = differenceKey({ kind: "status", production: "p".repeat(80), local: "l".repeat(80) });
  assert.equal(key, `status "${"p".repeat(47)} -> "${"l".repeat(47)}`);
});
