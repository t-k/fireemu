// The STORAGE-OBJECT comparison tool.
//
//   node src/storage-object-compare/run.mjs normalize --run <private run dir> [--run <dir>...]
//        --bucket <production bucket> --project <production project> --out <fixture dir>
//        [--forbidden-file <file of private identifiers, one per line>]
//     Normalize production recordings into the committed fixture and scan it. With several
//     --run, they must normalize to the same rows. Refuses to write anything that fails the scan.
//
//   node src/storage-object-compare/run.mjs compare --fixture <fixture dir> --journal <aggregate-events.jsonl>
//        [--receipt <receipt.json>] [--report <file>]
//     Compare a local rehearsal's journal with the fixture and report MATCH, DIVERGENCE,
//     LOCAL_UNIMPLEMENTED (fireemu answered 501, or the stand-in did) and the exchanges without a
//     counterpart. The receipt binds the comparison to the fireemu commit and binary digest.
//
//   node src/storage-object-compare/run.mjs rehearse --fireemu <binary> --fireemu-commit <sha>
//        --recorder <recorder checkout> --rules <fixed rules file> --fixture <fixture dir> --out <dir>
//     Run the recorder's local rehearsal against the binary and write <dir>/journal.jsonl and
//     <dir>/receipt.json.

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { compareRecipe, summarize } from "./compare.mjs";
import { buildFixture, indexText, normalizeRecipe, recipeFileText } from "./fixture.mjs";
import { readLocalJournal, readProductionRecording } from "./recording.mjs";
import { rehearse } from "./rehearse.mjs";
import { scanFixtureText } from "./scan.mjs";

function parseArguments(argv) {
  const options = { run: [] };
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!flag?.startsWith("--") || value === undefined) throw new Error(`bad argument: ${flag}`);
    const name = flag.slice(2);
    if (name === "run") options.run.push(value);
    else options[name] = value;
  }
  return options;
}

export function normalizeCommand(options, log = console.log) {
  for (const name of ["bucket", "project", "out"])
    if (!options[name]) throw new Error(`--${name} is required`);
  if (options.run.length === 0) throw new Error("--run is required");
  const forbidden = options["forbidden-file"]
    ? readFileSync(options["forbidden-file"], "utf8")
        .split("\n")
        .map((line) => line.trim())
        .filter(Boolean)
    : [];
  forbidden.push(options.bucket, options.project);
  const recordings = options.run.map((directory) => readProductionRecording(resolve(directory)));
  for (const recording of recordings)
    if (recording.outcome !== "recorded" || recording.failedRecipes.length > 0)
      throw new Error(`run ${recording.runId} is not a complete recording`);
  const fixture = buildFixture({
    recordings,
    bucket: options.bucket,
    project: options.project,
    source: "STORAGE-OBJECT production recordings (private run directories, not committed)",
  });
  if (!fixture.index.equivalentRecordings && options["allow-different"] !== "yes")
    throw new Error("the recordings do not normalize to the same rows");
  const files = [
    ["index.json", indexText(fixture.index)],
    ...fixture.recipes.map((recipe) => [
      fixture.index.recipes.find((row) => row.recipeId === recipe.recipeId).file,
      recipeFileText(recipe),
    ]),
  ];
  const runIds = fixture.index.runIds;
  // The index names the run IDs on purpose; the recipe files must not.
  for (const [name, text] of files)
    scanFixtureText(text, { runIds: name === "index.json" ? [] : runIds, forbidden });
  const out = resolve(options.out);
  mkdirSync(out, { recursive: true });
  for (const [name, text] of files) writeFileSync(join(out, name), text);
  log(
    `${files.length} files in ${out}; ${fixture.index.recipes.reduce((sum, row) => sum + row.rows, 0)} exchanges; equivalent recordings: ${fixture.index.equivalentRecordings}`,
  );
  return fixture.index;
}

/** Load a committed fixture directory: the index and each recipe's normalized exchanges. */
export function loadFixture(directory) {
  const index = JSON.parse(readFileSync(join(directory, "index.json"), "utf8"));
  const recipes = new Map();
  for (const entry of index.recipes) {
    const file = JSON.parse(readFileSync(join(directory, entry.file), "utf8"));
    if (file.recipeId !== entry.recipeId || file.exchanges.length !== entry.rows)
      throw new Error(`${entry.file} does not match the index`);
    recipes.set(entry.recipeId, file.exchanges);
  }
  return { index, recipes };
}

/** A short description of one difference, for counting: the kind, the header or path, the values. */
export function differenceKey(diff) {
  const show = (value) => JSON.stringify(value)?.slice(0, 48);
  if (diff.kind === "status" || diff.kind === "contentType" || diff.kind === "bodyType")
    return `${diff.kind} ${show(diff.production)} -> ${show(diff.local)}`;
  if (diff.kind === "headerValue") return `headerValue ${diff.header}`;
  if (diff.kind === "missingHeader" || diff.kind === "extraHeader")
    return `${diff.kind} ${diff.header}`;
  if (diff.kind === "body") return `body ${diff.path ?? ""}`;
  return diff.kind;
}

/** Compare a local journal with a fixture. Returns the report object. */
export function compareReport({ fixture, journal, localBucket, localProject, receipt }) {
  const local = readLocalJournal(journal);
  const recipes = [];
  for (const [recipeId, production] of fixture.recipes) {
    const localRecipe = local.recipes.find((candidate) => candidate.recipeId === recipeId);
    if (!localRecipe) {
      recipes.push({ recipeId, ran: false, counts: null, results: [] });
      continue;
    }
    const rows = normalizeRecipe(localRecipe, {
      runId: local.runId,
      bucket: localBucket,
      project: localProject,
    });
    const results = compareRecipe({ production, local: rows });
    recipes.push({ recipeId, ran: true, counts: summarize(results), results });
  }
  const total = {
    MATCH: 0,
    DIVERGENCE: 0,
    LOCAL_UNIMPLEMENTED: 0,
    ONLY_PRODUCTION: 0,
    ONLY_LOCAL: 0,
  };
  for (const recipe of recipes)
    for (const [name, count] of Object.entries(recipe.counts ?? {})) total[name] += count;
  const kinds = {};
  const byDifference = {};
  for (const recipe of recipes)
    for (const result of recipe.results)
      for (const diff of result.differences ?? []) {
        kinds[diff.kind] = (kinds[diff.kind] ?? 0) + 1;
        const key = differenceKey(diff);
        byDifference[key] = (byDifference[key] ?? 0) + 1;
      }
  return {
    fixtureRunIds: fixture.index.runIds,
    fireemu: receipt.fireemu,
    recorder: receipt.recorder,
    rehearsalResult: receipt.result,
    total,
    differenceKinds: kinds,
    byDifference: Object.fromEntries(
      Object.entries(byDifference).toSorted(([, a], [, b]) => b - a),
    ),
    recipes,
  };
}

export function reportText(report) {
  const lines = [
    `production recordings: ${report.fixtureRunIds.join(", ")}`,
    `fireemu ${report.fireemu.version} commit ${report.fireemu.commit} binary sha256 ${report.fireemu.binarySha256}`,
    `recorder commit ${report.recorder.commit}; rehearsal ${JSON.stringify(report.rehearsalResult)}`,
    `total: ${JSON.stringify(report.total)}`,
    `difference kinds: ${JSON.stringify(report.differenceKinds)}`,
    "most frequent differences:",
    ...Object.entries(report.byDifference)
      .slice(0, 30)
      .map(([key, count]) => `  ${count}  ${key}`),
    "",
  ];
  for (const recipe of report.recipes) {
    lines.push(
      recipe.ran
        ? `${recipe.recipeId}: ${JSON.stringify(recipe.counts)}`
        : `${recipe.recipeId}: NOT RUN`,
    );
    for (const result of recipe.results.filter((row) => row.outcome === "DIVERGENCE").slice(0, 5))
      lines.push(
        `  #${result.n} ${result.route}: ${result.differences
          .slice(0, 4)
          .map((diff) =>
            [
              diff.kind,
              diff.header ?? diff.path ?? "",
              JSON.stringify(diff.production)?.slice(0, 40),
              JSON.stringify(diff.local)?.slice(0, 40),
            ]
              .filter(Boolean)
              .join(" "),
          )
          .join(" | ")}`,
      );
  }
  return `${lines.join("\n")}\n`;
}

/** Check the receipt against the journal it names; a comparison without a matching receipt is refused. */
export function readReceipt(path, journal) {
  const receipt = JSON.parse(readFileSync(path, "utf8"));
  const digest = createHash("sha256").update(readFileSync(journal)).digest("hex");
  if (receipt.journalSha256 !== digest)
    throw new Error("the receipt does not describe this journal");
  if (
    !/^[0-9a-f]{64}$/.test(receipt.fireemu?.binarySha256 ?? "") ||
    !/^[0-9a-f]{40}$/.test(receipt.fireemu?.commit ?? "")
  )
    throw new Error("the receipt does not bind a fireemu commit and binary digest");
  if (receipt.recorder?.clean !== true)
    throw new Error("the receipt's recorder checkout was not clean");
  return receipt;
}

export function compareCommand(options, log = console.log) {
  for (const name of ["fixture", "journal", "receipt"])
    if (!options[name]) throw new Error(`--${name} is required`);
  const report = compareReport({
    fixture: loadFixture(resolve(options.fixture)),
    journal: resolve(options.journal),
    localBucket: options["local-bucket"] ?? "example.appspot.com",
    localProject: options["local-project"] ?? "example-project",
    receipt: readReceipt(resolve(options.receipt), resolve(options.journal)),
  });
  if (options.report)
    writeFileSync(resolve(options.report), `${JSON.stringify(report, null, 1)}\n`);
  log(reportText(report));
  return report;
}

export async function rehearseCommand(options) {
  const receipt = await rehearse({
    fireemuBinary: options.fireemu,
    fireemuCommit: options["fireemu-commit"],
    recorderDir: options.recorder,
    rulesFile: options.rules,
    fixtureDir: options.fixture,
    outDir: options.out,
  });
  console.log(JSON.stringify(receipt, null, 2));
  return receipt;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [command, ...rest] = process.argv.slice(2);
  try {
    const options = parseArguments(rest);
    if (command === "normalize") normalizeCommand(options);
    else if (command === "compare") compareCommand(options);
    else if (command === "rehearse") await rehearseCommand(options);
    else throw new Error("usage: run.mjs normalize|compare");
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 2;
  }
}
