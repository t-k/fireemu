import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";
import { fileURLToPath } from "node:url";
import { runCli, stableJson } from "./functions-events/compare/compare-cli.mjs";
import {
  LOCAL_BINARY,
  LOCAL_PROJECT,
  PRODUCTION_PROJECT,
  T0,
  firestoreFrame,
  frameEntry,
  localOp,
  localSession,
  op,
  productionRun,
} from "./functions-events/compare/fixtures/build.mjs";

const cliPath = fileURLToPath(
  new URL("./functions-events/compare/compare-cli.mjs", import.meta.url),
);
const corpusPath = fileURLToPath(new URL("../functions-events/corpus.json", import.meta.url));
const fixturePath = fileURLToPath(
  new URL("../functions-events/fixtures/index.js", import.meta.url),
);
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const ARTIFACT = "b".repeat(64);
const dirs = [];

afterEach(async () => {
  while (dirs.length > 0) await rm(dirs.pop(), { recursive: true, force: true });
});

async function inputs({ corpusDigest } = {}) {
  const dir = await mkdtemp(join(tmpdir(), "fe-compare-"));
  dirs.push(dir);
  const path = (n) => `fe_events_primary/e${String(n).padStart(32, "0")}`;
  const passes = [1, 2].map((pass) => {
    const start = T0 + pass * 3_600_000;
    const frames = [1, 2].map((generation) =>
      frameEntry(
        firestoreFrame({
          handler: `fsCreatedV${generation}`,
          generation,
          project: PRODUCTION_PROJECT,
          path: path(pass),
          eventId: `00000000-0000-4000-8000-00000000000${pass}`,
          timeMs: start + 500,
        }),
        start + 2000,
        `insert-${pass}-${generation}`,
      ),
    );
    return {
      ops: [
        op({ scenarioId: "fs-create", start, matchKey: { kind: "firestore", value: path(pass) } }),
      ],
      frames,
    };
  });
  const run = productionRun(
    passes[0].ops,
    passes[1].ops,
    [...passes[0].frames, ...passes[1].frames],
    {
      corpusDigest: corpusDigest ?? sha256(await readFile(corpusPath)),
    },
  );
  const session = localSession([
    {
      recipeId: "functions-events/firestore/create",
      operations: [
        localOp({
          scenarioId: "fs-create",
          matchKey: { kind: "firestore", value: path(9) },
          v1: [
            firestoreFrame({
              handler: "fsCreatedV1",
              generation: 1,
              project: LOCAL_PROJECT,
              path: path(9),
              eventId: "00000000-0000-4000-8000-000000000009",
              timeMs: T0 + 1,
            }),
          ],
          v2: [
            firestoreFrame({
              handler: "fsCreatedV2",
              generation: 2,
              project: LOCAL_PROJECT,
              path: path(9),
              eventId: "00000000-0000-4000-8000-000000000009",
              timeMs: T0 + 1,
            }),
          ],
        }),
      ],
    },
  ]);
  const files = {
    run: join(dir, "production-run.json"),
    emulator: join(dir, "emulator.json"),
    strict: join(dir, "strict.json"),
    out: join(dir, "comparison.json"),
  };
  await writeFile(files.run, JSON.stringify(run));
  await writeFile(files.emulator, JSON.stringify(session));
  await writeFile(files.strict, JSON.stringify(session));
  const argv = [
    "--production-run",
    files.run,
    "--emulator-session",
    files.emulator,
    "--strict-session",
    files.strict,
    "--local-project",
    LOCAL_PROJECT,
    "--artifact-sha256",
    ARTIFACT,
    "--execution",
    "local fireemu sessions vs production run (test)",
    "--out",
    files.out,
  ];
  return { files, argv };
}

test("stable JSON sorts keys at every depth, keeps array order and ends with a newline", () => {
  assert.equal(
    stableJson({ b: 1, a: [{ d: 1, c: 2 }, 3], c: { z: null, y: "x" } }),
    '{\n  "a": [\n    {\n      "c": 2,\n      "d": 1\n    },\n    3\n  ],\n  "b": 1,\n  "c": {\n    "y": "x",\n    "z": null\n  }\n}\n',
  );
});

test("the CLI writes the comparison in the record-schema.md shape, byte-identical on a rerun", async () => {
  const { files, argv } = await inputs();
  const document = await runCli(argv);
  const first = await readFile(files.out, "utf8");
  assert.equal(first, stableJson(document));
  assert.ok(first.endsWith("}\n"));
  assert.equal(document.kind, "functions-events-comparison");
  assert.equal(document.artifactSha256, ARTIFACT);
  assert.equal(document.execution, "local fireemu sessions vs production run (test)");
  assert.equal(document.fixtureSha256, sha256(await readFile(fixturePath)));
  assert.equal(document.corpusSha256, sha256(await readFile(corpusPath)));
  assert.deepEqual(document.productionRun, {
    project: PRODUCTION_PROJECT,
    recordedAt: new Date(T0).toISOString(),
    corpusDigest: document.corpusSha256,
    sha256: sha256(await readFile(files.run)),
  });
  assert.equal(document.comparator, undefined, "no comparator is named unless the caller gives it");
  assert.equal(document.summary.rows, 109);
  assert.equal(document.summary.match, 6);
  assert.equal(
    document.rows.find(({ row }) => row === "functions-events/firestore/create#new-document#v2")
      .status,
    "MATCH",
  );
  await runCli(argv);
  assert.equal(await readFile(files.out, "utf8"), first);
});

test("the CLI writes the binary the sessions ran, and refuses sessions that do not name the artifact", async () => {
  const { files, argv } = await inputs();
  const document = await runCli(argv);
  assert.deepEqual(document.localBinary, {
    sha256: ARTIFACT,
    sourceCommit: "c".repeat(40),
    dirty: false,
    runnerPath: LOCAL_BINARY.runnerPath,
    runnerSha256: LOCAL_BINARY.runnerSha256,
    runnerTree: LOCAL_BINARY.runnerTree,
  });
  // the two sessions must have run the same runner
  const withRunner = async (key, value) => {
    const session = JSON.parse(await readFile(files.emulator, "utf8"));
    const before = session.fireemu[key];
    session.fireemu[key] = value;
    await writeFile(files.emulator, JSON.stringify(session));
    await assert.rejects(runCli(argv), /different runners/);
    session.fireemu[key] = before;
    await writeFile(files.emulator, JSON.stringify(session));
  };
  await withRunner("runnerSha256", "8".repeat(64));
  await withRunner("runnerTree", "6".repeat(40));
  const sessionOf = async (file) => JSON.parse(await readFile(file, "utf8"));
  const rewrite = async (file, change) => {
    const session = await sessionOf(file);
    change(session);
    await writeFile(file, JSON.stringify(session));
  };
  const original = await sessionOf(files.strict);
  // no identity at all
  await rewrite(files.strict, (session) => delete session.fireemu);
  await assert.rejects(runCli(argv), /strict session names no binary/);
  await writeFile(files.strict, JSON.stringify(original));
  // the emulator session ran another binary
  await rewrite(files.emulator, (session) => (session.fireemu.binarySha256 = "d".repeat(64)));
  await assert.rejects(runCli(argv), /different binaries/);
  await writeFile(files.emulator, JSON.stringify(original));
  // both ran a binary that is not the artifact typed on the command line
  const other = [...argv];
  other[other.indexOf("--artifact-sha256") + 1] = "e".repeat(64);
  await assert.rejects(runCli(other), /not the artifact the comparison names/);
  // the harness commit differs
  await rewrite(files.emulator, (session) => (session.fireemu.sourceCommit = "f".repeat(40)));
  await assert.rejects(runCli(argv), /different harness commits/);
  await writeFile(files.emulator, JSON.stringify(original));
  await runCli(argv);
});

test("the CLI refuses a run recorded against another corpus and invalid arguments", async () => {
  const { argv } = await inputs({ corpusDigest: "c".repeat(64) });
  await assert.rejects(runCli(argv), /corpusDigest/);
  const valid = (await inputs()).argv;
  await assert.rejects(runCli(valid.filter((_, i) => i < 8 || i > 9)), /--artifact-sha256/);
  const badArtifact = [...valid];
  badArtifact[badArtifact.indexOf("--artifact-sha256") + 1] = "B".repeat(64);
  await assert.rejects(runCli(badArtifact), /--artifact-sha256/);
  await assert.rejects(runCli([...valid, "--unknown", "x"]), /unknown/i);
});

test("the CLI runs as a process: exit 0 with the file written, exit 1 with a message on bad input", async () => {
  const { files, argv } = await inputs();
  const ok = spawnSync(process.execPath, [cliPath, ...argv], { encoding: "utf8", timeout: 30_000 });
  assert.equal(ok.status, 0, ok.stderr);
  assert.match(await readFile(files.out, "utf8"), /"kind": "functions-events-comparison"/);
  const bad = spawnSync(process.execPath, [cliPath, "--out", files.out], {
    encoding: "utf8",
    timeout: 30_000,
  });
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /--production-run/);
});

test("the CLI pins the comparator when it is given its commit and tree, and refuses half of that or a malformed one", async () => {
  const { argv } = await inputs();
  const commit = "a".repeat(40);
  const tree = "b".repeat(40);
  const document = await runCli([
    ...argv,
    "--comparator-commit",
    commit,
    "--comparator-tree",
    tree,
  ]);
  assert.deepEqual(document.comparator, { commit, tree });
  // Digits and every hex letter are fine, zero included.
  const mixed = "0123456789abcdef0123456789abcdef01234567";
  assert.deepEqual(
    (await runCli([...argv, "--comparator-commit", mixed, "--comparator-tree", mixed])).comparator,
    { commit: mixed, tree: mixed },
  );
  const together = /--comparator-commit and --comparator-tree are given together/;
  await assert.rejects(runCli([...argv, "--comparator-commit", commit]), together);
  await assert.rejects(runCli([...argv, "--comparator-tree", tree]), together);
  for (const bad of [
    "",
    "A".repeat(40),
    "a".repeat(39),
    "a".repeat(41),
    `${commit} `,
    "g".repeat(40),
  ]) {
    await assert.rejects(
      runCli([...argv, "--comparator-commit", bad, "--comparator-tree", tree]),
      /^Error: --comparator-commit must be a 40-digit lowercase hex id$/,
      JSON.stringify(bad),
    );
    await assert.rejects(
      runCli([...argv, "--comparator-commit", commit, "--comparator-tree", bad]),
      /^Error: --comparator-tree must be a 40-digit lowercase hex id$/,
      JSON.stringify(bad),
    );
  }
});

test("the production run digest in the comparison is the digest of the file's bytes, whatever its formatting", async () => {
  const { files, argv } = await inputs();
  const before = (await runCli(argv)).productionRun.sha256;
  const text = await readFile(files.run, "utf8");
  await writeFile(files.run, `${JSON.stringify(JSON.parse(text), null, 1)}\n`);
  const after = (await runCli(argv)).productionRun.sha256;
  assert.notEqual(after, before);
  assert.equal(after, sha256(await readFile(files.run)));
});
