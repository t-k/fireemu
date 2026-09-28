import json
import os
import subprocess
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[3]
ARTIFACT_PATH = (
    REPOSITORY
    / "spec/compatibility/broad-runs/fs-batch-malformed-middle-8a0f205-current-comparison.json"
)
COMPARATOR_PATH = REPOSITORY / "conformance/src/fs-data-write-sandbox.mjs"


@pytest.fixture(scope="module")
def fresh_local_replay() -> dict:
    install = subprocess.run(
        ["pnpm", "-C", "conformance", "install", "--frozen-lockfile"],
        cwd=REPOSITORY,
        check=False,
        capture_output=True,
        text=True,
    )
    assert install.returncode == 0, install.stderr

    replay = subprocess.run(
        ["pnpm", "-C", "conformance", "fs-data-write:check"],
        cwd=REPOSITORY,
        check=False,
        capture_output=True,
        text=True,
    )
    records = []
    for line in replay.stdout.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and "runDir" in record:
            records.append(record)
    assert len(records) == 1, replay.stdout + replay.stderr
    run_path = Path(records[0]["runDir"]).resolve()
    runs_root = (REPOSITORY / "conformance/.runs").resolve()
    assert run_path.is_relative_to(runs_root)
    comparison_lines = []
    for line in replay.stdout.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and "corpusDigest" in record:
            comparison_lines.append(record)
    assert len(comparison_lines) == 1, replay.stdout + replay.stderr
    summary = comparison_lines[0]
    # The checker exits 1 while any row differs and 0 once every row matches.
    assert summary["mismatches"] == len(summary["differences"])
    assert replay.returncode == (1 if summary["mismatches"] else 0), replay.stdout + replay.stderr
    return {"path": run_path, "summary": summary}


def test_current_local_results_match_the_saved_production_subset_with_existing_comparator(
    fresh_local_replay,
):
    script = r"""
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const artifactPath = process.argv.at(-1);
const artifact = JSON.parse(await readFile(artifactPath, 'utf8'));
const localRunPath = process.env.FIREEMU_LOCAL_RUN_PATH;
const freshLocalResults = JSON.parse(await readFile(`${localRunPath}/rest-results.json`, 'utf8'));
const freshCorpus = JSON.parse(await readFile(`${localRunPath}/corpus.json`, 'utf8'));
const { compareSandboxArtifact } = await import(process.env.FIREEMU_COMPARATOR_URL);
const recipeIds = artifact.recipeIds;
const localPrograms = Object.fromEntries(recipeIds.map((id) => [id, freshLocalResults[id]]));
assert.deepEqual(Object.keys(artifact.productionPrograms).toSorted(), recipeIds.toSorted());
assert.deepEqual(Object.keys(localPrograms).toSorted(), recipeIds.toSorted());
assert.deepEqual(artifact.recipes.map(({ id }) => id).toSorted(), recipeIds.toSorted());
assert.equal(
  createHash('sha256')
    .update(`${JSON.stringify(artifact.localRunBinding, null, 2)}\n`)
    .digest('hex'),
  artifact.localRunBindingSha256,
);
for (const recipe of artifact.recipes) {
  const digest = createHash('sha256').update(JSON.stringify(recipe)).digest('hex');
  assert.equal(artifact.recipeDigests[recipe.id], digest);
}
const differences = compareSandboxArtifact(
  { programs: artifact.productionPrograms, streams: {} },
  localPrograms,
  {},
  { restPrograms: freshCorpus.restPrograms.filter(({ id }) => recipeIds.includes(id)) },
);
assert.deepEqual(differences, []);
assert.equal(
  createHash('sha256').update(JSON.stringify(localPrograms)).digest('hex'),
  artifact.localSelectedResultsSha256,
);
assert.deepEqual(localPrograms, artifact.localPrograms);
assert.equal(artifact.result.comparableRecipes, 7);
assert.equal(artifact.result.mismatchedRecipes, 0);
assert.deepEqual(artifact.result.pendingRelatedConditions, [
  'FS-WRITE-LIMITS-03/batch-undecodable-value',
]);
assert.equal(artifact.result.fullRun.knownMismatchRows, 9);
assert.equal(artifact.result.fullRunExitCode, 1);
"""
    result = subprocess.run(
        ["node", "--input-type=module", "-e", script, str(ARTIFACT_PATH)],
        cwd=REPOSITORY,
        env={
            **os.environ,
            "FIREEMU_COMPARATOR_URL": COMPARATOR_PATH.as_uri(),
            "FIREEMU_LOCAL_RUN_PATH": str(fresh_local_replay["path"]),
        },
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
