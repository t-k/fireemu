"""Recompile non-authorizing FS-DATA-WRITE preparation; no network or execution.

A source-bound plan is not an observation, permission, invoice, final-artifact
attestation or independent review. Historical evidence is read, never rewritten.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
BOUND_SOURCES = (
    'tools/compat-broad/offline-closure/preparation.py',
    'tools/compat-broad/offline-closure/recovery_review.py',
    'tools/compat-broad/fs-commit-transform-limits/transform_compiler.py',
    'tools/compat-broad/fs-commit-transform-limits/local_collector.py',
    'tools/compat-broad/fs-commit-transform-limits/transform_comparator.py',
    'tools/compat-broad/fs-data-write-local/boundaries.py',
    'spec/limits/firestore-standard-2026-08-25.json',
    'crates/fireemu-core-firestore/src/size.rs',
    'crates/fireemu-core-firestore/tests/reference_size_namespaces.rs',
    'crates/fireemu-adapter-grpc/tests/write_boundary_corpus.rs',
)
HISTORICAL_REFERENCES = (
    'spec/compatibility/broad-runs/fs-commit-transform-limits-031c74bfe-production-result.json',
    'spec/compatibility/broad-runs/fs-commit-transform-limits-aa39de4b6-saved-result.json',
    'spec/compatibility/broad-runs/fs-write-limits-02-40dfc0da3-production-result.json',
    'spec/compatibility/broad-runs/fs-write-limits-02-8b33aac4d-saved-result.json',
    'spec/compatibility/broad-runs/fs-write-txn-dee737c14-production-result.json',
    'spec/compatibility/broad-runs/fs-write-txn-567565bdd-saved-result.json',
)


def encoded(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def digest(value: Any) -> str:
    return hashlib.sha256(encoded(value)).hexdigest()


def source_binding(root: Path, names: tuple[str, ...]) -> dict[str, str]:
    """Only fixed repo-relative regular inputs, without symlink traversal."""
    result = {}
    for name in names:
        path = root
        for part in Path(name).parts:
            if part in ('..', '.') or not part or Path(name).is_absolute():
                raise ValueError('invalid source path')
            path = path / part
            if path.is_symlink():
                raise ValueError('symlinked source input')
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 16 * 1024 * 1024:
            raise ValueError('invalid source input')
        payload = path.read_bytes()
        after = path.stat()
        if (info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
                after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('source changed during reading')
        result[name] = hashlib.sha256(payload).hexdigest()
    return result


def _module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError('compiler unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare(nonce: str, *, root: Path = ROOT) -> dict[str, Any]:
    if type(nonce) is not str or re.fullmatch('[0-9a-f]{32}', nonce) is None:
        raise ValueError('32 lowercase hexadecimal nonce required')
    bound = source_binding(root, BOUND_SOURCES)
    historical = source_binding(root, HISTORICAL_REFERENCES)
    historical_transform = json.loads((root / HISTORICAL_REFERENCES[0]).read_bytes())
    if (historical_transform.get('campaignId') != 'FS-DATA-WRITE-COMMIT-TRANSFORMS-03'
            or historical_transform.get('production', {}).get('productionExecuted') is not True
            or historical_transform.get('conditionObserved', {}).get('condition')
            != 'FS-LIMIT-FIELD-TRANSFORMS-PER-DOCUMENT'):
        raise ValueError('historical transform receipt identity mismatch')
    transform = _module(root / BOUND_SOURCES[2], '_offline_closure_transform')
    boundary = _module(root / 'tools/compat-broad/fs-data-write-local/boundaries.py',
                       '_offline_closure_boundaries')
    commit_plan = transform.compile_plan('demo-closure', '(default)', nonce)
    # Reuse the existing catalog checks and compiler. Compile one case at a
    # time so large index-sum fixtures are not all retained simultaneously.
    boundary.compile_suite(nonce, family='collection-id', position='below')
    cases = []
    for family in boundary.FAMILIES:
        for position in boundary.POSITIONS:
            case = boundary.compile_case(family, position, nonce)
            cases.append({key: case[key] for key in (
                'id', 'family', 'position', 'limitId', 'metric', 'overlappingLimits', 'expect')}
                | {'compiledInputSha256': digest(case), 'nativeExecuted': False})
    observed_transforms = []
    for operation in commit_plan['observation']:
        if operation['kind'] == 'commit-transform':
            writes = operation['body']['writes']
            observed_transforms.append({
                'writeCount': len(writes),
                'transformsPerWrite': [len(w['transform']['fieldTransforms']) for w in writes],
                'fieldTransformsOnOneDocument': sum(len(w['transform']['fieldTransforms']) for w in writes),
                'existingDocumentPrecondition': all(w['currentDocument'].get('exists') is True for w in writes),
            })
    if source_binding(root, BOUND_SOURCES) != bound or source_binding(root, HISTORICAL_REFERENCES) != historical:
        raise ValueError('inputs changed while preparing')
    report = {
        'schema': 'fireemu-five-area-offline-preparation-v1',
        'nonce': nonce, 'sourceBinding': bound, 'historicalReferences': historical,
        'kind': 'preparation-not-observation',
        'authorizesProduction': False, 'authorizesCleanup': False,
        'productionExecuted': False, 'nativeExecuted': False,
        'promotionReady': False, 'independentReviewCompleted': False,
        'fieldTransformBoundary': {
            'campaignId': commit_plan['campaignId'],
            'metric': 'sum of field transforms on one document in one Commit',
            'notMetric': 'number of writes in a Commit',
            'cases': observed_transforms,
            'historicalObservationExists': True,
            'historicalStatusBasis': 'stored receipt claim; not a new acquisition validation',
            'repeatProductionRequested': False,
            'historicalReference': HISTORICAL_REFERENCES[0],
        },
        'commitPlan': commit_plan, 'boundaryCases': cases,
        'recoveryContract': {
            'unknownAcknowledgement': 'retain responsibility; absence does not settle a delayed create',
            'knownDocument': 'same-instance owner marker + current version + conditional delete + typed absence',
            'knownAccount': 'confirmed current-run UID only; never infer ownership from requested UID',
            'restartExecutionImplemented': False,
        },
        'remainingNonProduction': [
            'native and fixed-SDK execution of compiled boundaries',
            'final artifact/source/config/collector/comparator binding',
            'saved-reference replay at the final artifact',
            'independent correctness and safety review',
            'current-instance and stopped-producer adapters for any recovery restart',
        ],
    }
    report['preparationDigest'] = digest(report)
    return report


def validate(report: Any, *, root: Path = ROOT) -> None:
    if type(report) is not dict:
        raise ValueError('object required')
    # A re-hashed forgery or flipped permission flag is not a compiled plan.
    if encoded(report) != encoded(prepare(report.get('nonce'), root=root)):
        raise ValueError('preparation differs from current compiled inputs')


def publish(value: dict[str, Any], path: Path) -> None:
    payload = encoded(value) + b'\n'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(payload)
        while view:
            n = os.write(fd, view)
            if n <= 0:
                raise OSError('no output progress')
            view = view[n:]
        os.fsync(fd)
    finally:
        os.close(fd)
    # A failed write can leave an incomplete file. It is never a valid package:
    # callers and the delivery gate must validate bytes and the full structure.


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nonce', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    report = prepare(args.nonce)
    publish(report, args.output)
    validate(json.loads(args.output.read_bytes()))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
