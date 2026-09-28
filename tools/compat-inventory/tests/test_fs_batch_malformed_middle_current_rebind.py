import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[3]
ARTIFACT_PATH = (
    REPOSITORY
    / "spec/compatibility/broad-runs/fs-batch-malformed-middle-8a0f205-current-comparison.json"
)
COMPARATOR_PATH = REPOSITORY / "conformance/src/fs-data-write-sandbox.mjs"
SAVED_PATH = (
    REPOSITORY
    / "spec/compatibility/broad-runs/fs-batch-malformed-middle-3d7ceabb8-saved-comparison.json"
)
HISTORY_REWRITE_PATH = REPOSITORY / "spec/compatibility/history-rewrite-2026-09-28.json"
REQUIRED_RUNTIME_INPUTS = {
    "Cargo.toml",
    "Cargo.lock",
    "conformance/src/fs-data-write-sandbox-run.mjs",
    "conformance/src/firestore-probe/sandbox-session.mjs",
}


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rewritten(commit: str) -> str:
    """The commit a recorded SHA has after the 2026-09-28 history rewrite, if the record exists."""
    if not HISTORY_REWRITE_PATH.exists():
        return commit
    for label in read_json(HISTORY_REWRITE_PATH)["labels"]:
        if commit.startswith(label["token"]):
            return label["new"]
    return commit


def source_blob_sha256(commit: str, path: str) -> str:
    result = subprocess.run(
        ["git", "show", f"{rewritten(commit)}:{path}"],
        cwd=REPOSITORY,
        check=True,
        capture_output=True,
    )
    return hashlib.sha256(result.stdout).hexdigest()


def test_the_rebind_is_bound_to_its_recorded_source_blobs_and_saved_provenance():
    """Static provenance of the f35f7b8 rebind: it no longer needs the tree to equal that commit."""
    artifact = read_json(ARTIFACT_PATH)
    assert artifact["schemaVersion"] == 1
    assert artifact["conditionId"] == "FS-WRITE-LIMITS-03/batch-malformed-middle"
    assert artifact["sourceCommit"] == "f35f7b83e8a17133817c533decf67e0f242550e2"
    assert artifact["savedComparison"] == {
        "path": "spec/compatibility/broad-runs/fs-batch-malformed-middle-3d7ceabb8-saved-comparison.json",
        "sha256": sha256(SAVED_PATH),
    }
    saved = read_json(SAVED_PATH)
    assert artifact["localIndexConfigSha256"] == saved["indexConfigSha256"]
    assert saved["productionFixtureSha256"] == artifact["productionFixtureSha256"]
    assert artifact["productionPrograms"] == saved["productionPrograms"]
    assert artifact["productionRecordingDigests"][0] == artifact["productionRecordingDigests"][1]
    assert artifact["localRunPath"] == "conformance/.runs/fs-data-write-local-DbrwFE"

    binding = artifact["localRunBinding"]
    assert binding["sourceHead"] == artifact["sourceCommit"]
    assert binding["executablePath"] == "target/debug/fireemu"
    assert binding["executableSha256"] == artifact["localExecutableSha256"]
    assert binding["executableSha256After"] == artifact["localExecutableSha256"]
    assert binding["config"] == "conformance/fs-data-write-sandbox.fireemu.json"
    assert binding["configSha256"] == artifact["localConfigSha256"]
    assert binding["runtimeInputs"] == artifact["localRuntimeInputs"]
    assert set(artifact["localRuntimeInputs"]) == REQUIRED_RUNTIME_INPUTS
    assert set(binding["commandVersions"]) == {"cargo", "node", "rustc"}
    assert re.fullmatch(r"[0-9a-f]{64}", artifact["localRunBindingSha256"])
    assert (
        hashlib.sha256(f"{json.dumps(binding, indent=2)}\n".encode()).hexdigest()
        == artifact["localRunBindingSha256"]
    )
    commit = artifact["sourceCommit"]
    runtime = artifact["comparisonRuntimeInput"]
    assert runtime["path"] == "conformance/src/fs-data-write-sandbox.mjs"
    assert source_blob_sha256(commit, runtime["path"]) == runtime["sha256"]
    assert source_blob_sha256(commit, binding["config"]) == binding["configSha256"]
    assert (
        source_blob_sha256(commit, "conformance/firestore.indexes.json")
        == artifact["localIndexConfigSha256"]
    )
    for path, expected_sha in artifact["localRuntimeInputs"].items():
        assert source_blob_sha256(commit, path) == expected_sha
    recipes = {recipe["id"]: recipe for recipe in artifact["recipes"]}
    assert sorted(recipes) == sorted(artifact["recipeIds"])
    for recipe_id, recipe in recipes.items():
        digest = hashlib.sha256(json.dumps(recipe, separators=(",", ":")).encode()).hexdigest()
        assert artifact["recipeDigests"][recipe_id] == digest




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
