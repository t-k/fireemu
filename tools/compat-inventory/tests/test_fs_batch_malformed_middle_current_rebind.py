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
SAVED_PATH = (
    REPOSITORY
    / "spec/compatibility/broad-runs/fs-batch-malformed-middle-3d7ceabb8-saved-comparison.json"
)
PRODUCTION_FIXTURE_PATH = REPOSITORY / "conformance/fs-data-write-production-matrix.json"
RECIPE_MANIFEST_PATH = REPOSITORY / "conformance/fs-data-write-recipe-digests.json"
COMPARATOR_PATH = REPOSITORY / "conformance/src/fs-data-write-sandbox.mjs"
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


def source_blob_sha256(commit: str, path: str) -> str:
    result = subprocess.run(
        ["git", "show", f"{commit}:{path}"],
        cwd=REPOSITORY,
        check=True,
        capture_output=True,
    )
    return hashlib.sha256(result.stdout).hexdigest()


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
    assert replay.returncode == 1, replay.stdout + replay.stderr
    comparison_lines = []
    for line in replay.stdout.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and "corpusDigest" in record:
            comparison_lines.append(record)
    assert len(comparison_lines) == 1, replay.stdout + replay.stderr
    return {"path": run_path, "summary": comparison_lines[0]}


def test_current_rebind_is_source_bound_and_keeps_saved_recording_provenance(fresh_local_replay):
    artifact = read_json(ARTIFACT_PATH)
    saved_bytes_sha = sha256(SAVED_PATH)
    saved = read_json(SAVED_PATH)
    fixture = read_json(PRODUCTION_FIXTURE_PATH)
    manifest = read_json(RECIPE_MANIFEST_PATH)

    assert artifact["schemaVersion"] == 1
    assert artifact["conditionId"] == "FS-WRITE-LIMITS-03/batch-malformed-middle"
    assert artifact["sourceCommit"] == "8a0f20599bab98bb094a74e00d6b2df9f6cd60e8"
    assert artifact["verificationCommand"].startswith(
        "pnpm -C conformance install --frozen-lockfile && uv run"
    )
    assert artifact["savedComparison"] == {
        "path": "spec/compatibility/broad-runs/fs-batch-malformed-middle-3d7ceabb8-saved-comparison.json",
        "sha256": saved_bytes_sha,
    }
    assert artifact["productionFixtureSha256"] == sha256(PRODUCTION_FIXTURE_PATH)
    assert artifact["recordedCorpusSha256"] == fixture["evidence"]["corpusSha256"]
    assert artifact["recordedCorpusSha256"] == manifest["corpusSha256"]
    assert artifact["recipeManifestSha256"] == sha256(RECIPE_MANIFEST_PATH)
    assert artifact["localIndexConfigSha256"] == saved["indexConfigSha256"]
    assert artifact["productionRecordingTimes"] == fixture["evidence"]["recordedAt"]
    assert len(set(artifact["productionRecordingTimes"])) == 2
    assert artifact["productionRecordingDigests"] == fixture["evidence"]["recordingDigests"]
    assert artifact["productionRecordingDigests"][0] == artifact["productionRecordingDigests"][1]
    assert saved["productionFixtureSha256"] == artifact["productionFixtureSha256"]
    assert artifact["productionPrograms"] == saved["productionPrograms"]
    assert all(
        artifact["recipeDigests"][recipe_id] == manifest["programs"][recipe_id]
        for recipe_id in artifact["recipeIds"]
    )
    assert artifact["localRunPath"] == "conformance/.runs/fs-data-write-local-DbrwFE"
    assert not Path(artifact["localRunPath"]).is_absolute()
    subprocess.run(
        ["git", "merge-base", "--is-ancestor", artifact["sourceCommit"], "HEAD"],
        cwd=REPOSITORY,
        check=True,
    )
    subprocess.run(
        [
            "git",
            "diff",
            "--quiet",
            artifact["sourceCommit"],
            "HEAD",
            "--",
            ".",
            ":(exclude)spec/compatibility/closure/FS-DATA-WRITE.json",
            ":(exclude)conformance/src/fs-data-write-closure.test.mjs",
            ":(exclude)spec/compatibility/broad-runs/fs-batch-malformed-middle-8a0f205-current-comparison.json",
            ":(exclude)tools/compat-inventory/tests/test_fs_batch_malformed_middle_current_rebind.py",
        ],
        cwd=REPOSITORY,
        check=True,
    )

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
    assert re.fullmatch(r"[0-9a-f]{64}", artifact["localExecutableSha256"])
    assert source_blob_sha256(
        artifact["sourceCommit"], artifact["comparisonRuntimeInput"]["path"]
    ) == artifact["comparisonRuntimeInput"]["sha256"]
    assert source_blob_sha256(artifact["sourceCommit"], binding["config"]) == binding[
        "configSha256"
    ]
    assert source_blob_sha256(artifact["sourceCommit"], "conformance/firestore.indexes.json") == artifact[
        "localIndexConfigSha256"
    ]
    for path, expected_sha in artifact["localRuntimeInputs"].items():
        assert source_blob_sha256(artifact["sourceCommit"], path) == expected_sha
    assert artifact["comparisonRuntimeInput"]["path"] == "conformance/src/fs-data-write-sandbox.mjs"
    assert sha256(REPOSITORY / artifact["comparisonRuntimeInput"]["path"]) == artifact[
        "comparisonRuntimeInput"
    ]["sha256"]
    assert sha256(REPOSITORY / binding["config"]) == binding["configSha256"]
    assert sha256(REPOSITORY / "conformance/firestore.indexes.json") == artifact[
        "localIndexConfigSha256"
    ]

    replay_binding = read_json(fresh_local_replay["path"] / "local-run-binding.json")
    replay_results = read_json(fresh_local_replay["path"] / "rest-results.json")
    replay_corpus = read_json(fresh_local_replay["path"] / "corpus.json")
    current_head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPOSITORY, check=True, capture_output=True, text=True
    ).stdout.strip()
    assert replay_binding["sourceHead"] == current_head
    assert replay_binding["runtimeInputs"] == artifact["localRuntimeInputs"]
    assert replay_binding["configSha256"] == artifact["localConfigSha256"]
    replay_binary = REPOSITORY / replay_binding["executablePath"]
    assert replay_binding["executableSha256"] == sha256(replay_binary)
    assert replay_binding["executableSha256After"] == replay_binding["executableSha256"]
    assert {
        program["id"]: program
        for program in replay_corpus["restPrograms"]
        if program["id"] in artifact["recipeIds"]
    } == {recipe["id"]: recipe for recipe in artifact["recipes"]}
    assert sha256(fresh_local_replay["path"] / "corpus.json") == artifact["localCorpusSha256"]
    assert replay_results["writes/batch-write-malformed/undecodable-value"]
    assert fresh_local_replay["summary"]["comparedPrograms"] == 39
    assert fresh_local_replay["summary"]["comparedStreams"] == 2
    assert fresh_local_replay["summary"]["mismatches"] == 9
    assert len(fresh_local_replay["summary"]["pendingRestIds"]) == 39
    assert len(fresh_local_replay["summary"]["pendingStreamIds"]) == 5


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
